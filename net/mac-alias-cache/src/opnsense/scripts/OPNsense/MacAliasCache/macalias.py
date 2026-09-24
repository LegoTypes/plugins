#!/usr/local/bin/python3
"""
Copyright (C) 2026 cayossarian (Bill Flood)
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.

MAC alias cache: show what each mac alias resolves to (status) and rebuild
every mac alias, and every alias nesting one, from current host discovery
data (flush). Always prints one JSON object and exits 0 so configd returns
JSON rather than "Execute error".
"""
import fcntl
import json
import os
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import macaliascache_lib as lib  # noqa: E402

DEFAULTS = {
    "tables_conf": "/usr/local/etc/filter_tables.conf",
    "cache_file": "/tmp/alias_filter_arp.cache",
    "lock_file": "/tmp/filter_update_tables.lock",
    "last_file": "/tmp/macaliascache.last.json",
    "aliastables_dir": "/var/db/aliastables",
    "list_hosts": ["/usr/local/opnsense/scripts/interfaces/list_hosts.py", "-n"],
    "update_tables": "/usr/local/opnsense/scripts/filter/update_tables.py",
    "pfctl": "/sbin/pfctl",
    "lock_timeout": 15.0,
    "lock_retry": 0.25,
    "min_interval": 10.0,
    "update_timeout": 60,
}


def _read_json(path):
    try:
        with open(path) as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except (OSError, ValueError):
        return None


def _write_json_atomic(path, obj):
    """ write obj as JSON to a temp file beside path, then rename it over path """
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix=".%s." % os.path.basename(path), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:  # closes fd on every path out of the with block, chmod failure included
            os.fchmod(f.fileno(), 0o644)  # mkstemp creates 0600; match a plain open() under umask 022
            json.dump(obj, f)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _sweep_stale_temps(path, now, max_age=60):
    """ delete our own atomic-write temp files beside path (name .<basename>.<random>.tmp,
    see _write_json_atomic) older than max_age seconds; catches orphans left by a kill
    between mkstemp and os.replace
    """
    directory = os.path.dirname(path) or "."
    prefix = ".%s." % os.path.basename(path)
    try:
        names = os.listdir(directory)
    except FileNotFoundError:
        return
    for name in names:
        if not (name.startswith(prefix) and name.endswith(".tmp")):
            continue
        full = os.path.join(directory, name)
        try:
            if now - os.stat(full).st_mtime > max_age:
                os.unlink(full)
        except FileNotFoundError:
            pass


def seed_cache(rows, now):
    """ {mac: {"items": [ip, ...], "last_seen": now}} in core's ArpCache format; the
    MAC key is kept exactly as list_hosts returns it (core's current_cache does the same)
    """
    cache = {}
    for row in rows if isinstance(rows, list) else []:
        if isinstance(row, (list, tuple)) and len(row) >= 3:
            cache.setdefault(row[1], {"items": [], "last_seen": now})["items"].append(row[2])
    return cache


def read_tables(cfg):
    with open(cfg["tables_conf"]) as f:
        return lib.parse_tables(f.read())


def read_hosts(cfg):
    """ (source, rows) from list_hosts.py; (None, []) when it fails or prints non-JSON """
    try:
        proc = subprocess.run(cfg["list_hosts"], capture_output=True, text=True, timeout=30)
        data = json.loads(proc.stdout)
        return data.get("source"), data.get("rows", [])
    except (OSError, ValueError, subprocess.SubprocessError, AttributeError):
        return None, []


def pf_set(cfg, name):
    """ addresses currently in pf table <name>, or None when the table can't be read """
    try:
        proc = subprocess.run([cfg["pfctl"], "-t", name, "-T", "show"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return sorted(line.strip() for line in proc.stdout.splitlines() if line.strip())


def acquire_lock(cfg, sleep):
    """ core's update-tables lock (flock(2), same as util-linux flock(1)); None on timeout """
    handle = open(cfg["lock_file"], "a")
    deadline = cfg["lock_timeout"]
    waited = 0.0
    while True:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return handle
        except BlockingIOError:
            if waited >= deadline:
                handle.close()
                return None
            sleep(cfg["lock_retry"])
            waited += cfg["lock_retry"]


def _flush_emptied_tables(cfg, names):
    """ core's update_tables.py --aliases (targeted) mode forces cnt_alias_pf_content
    to the new content count, so it never runs PF.flush for an alias whose rebuilt
    content is now empty; pf keeps the stale addresses until the next non-targeted
    (cron) run. Flush pf ourselves for any such alias. A missing .txt means "not
    managed / unknown": do nothing. Errors are per-table and never abort the flush.
    """
    flushed = []
    for name in names:
        path = os.path.join(cfg["aliastables_dir"], "%s.txt" % name)
        try:
            with open(path) as f:
                lines = f.readlines()
        except OSError:
            continue
        if any(line.strip() for line in lines):
            continue
        if not pf_set(cfg, name):
            continue
        try:
            subprocess.run(
                [cfg["pfctl"], "-t", name, "-T", "flush"],
                capture_output=True, text=True, timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            continue
        flushed.append(name)
    return flushed


def cmd_status(cfg, now):
    tables = read_tables(cfg)
    source, hosts = read_hosts(cfg)
    cache = _read_json(cfg["cache_file"]) or {}
    names = list(lib.mac_aliases(tables))
    pf_counts = {}
    for name in names:
        members = pf_set(cfg, name)
        pf_counts[name] = len(members) if members is not None else None
    last = _read_json(cfg["last_file"])
    return {
        "source": source,
        "aliases": lib.alias_view(tables, cache, hosts, pf_counts, now),
        "last_flush": last if last and "at" in last else None,
    }


def cmd_flush(cfg, clock=time.time, sleep=time.sleep):
    lock = acquire_lock(cfg, sleep)
    if lock is None:
        return {"error": "busy", "detail": "alias update lock held for %ss" % cfg["lock_timeout"]}
    try:
        # rate limit checked under the lock, so a flush that finished while we waited wins
        last = _read_json(cfg["last_file"])
        now = clock()
        # lower bound: a backwards clock step must not lock flush out indefinitely
        if (last and isinstance(last.get("at"), (int, float))
                and 0 <= now - last["at"] < cfg["min_interval"]):
            return {"error": "too_soon", "detail": "last flush %.0fs ago" % (now - last["at"])}

        # sweep orphans from a prior kill between mkstemp and os.replace before writing again
        _sweep_stale_temps(cfg["cache_file"], now)
        _sweep_stale_temps(cfg["last_file"], now)

        tables = read_tables(cfg)
        names = lib.refresh_set(tables)
        if not names:
            return {"aliases": [], "note": "no mac aliases"}

        # Read the host list before any side effect. Core's ArpCache.current_cache()
        # turns a list_hosts failure into {} without raising; with the cache gone
        # that would empty every mac alias and every alias nesting one. Refuse
        # instead, change nothing and leave the rate limit unarmed.
        source, rows = read_hosts(cfg)
        seeded = seed_cache(rows, now) if source is not None else {}
        if not seeded:
            return {"error": "hosts_unavailable", "detail": "host list could not be read; nothing changed"}

        before = {name: pf_set(cfg, name) for name in names}

        # Replace the cache with current data only (core's exact format), so stale
        # MACs are dropped; if list_hosts fails again inside update_tables, core
        # then merges into this rather than into {}.
        _write_json_atomic(cfg["cache_file"], seeded)

        for name in lib.mac_aliases(tables):
            md5 = os.path.join(cfg["aliastables_dir"], "%s.md5.txt" % name)
            if os.path.isfile(md5):
                os.utime(md5, (0, 0))

        try:
            proc = subprocess.run(
                [cfg["update_tables"], "--aliases", ",".join(names)],
                capture_output=True, text=True, timeout=cfg["update_timeout"],
            )
            if proc.returncode == 0:
                output = proc.stdout.strip()
            else:
                # a crash's traceback is usually on stderr; keep both so it isn't lost
                output = "\n".join(part for part in (proc.stdout.strip(), proc.stderr.strip()) if part)
            update = {"rc": proc.returncode, "output": output}
        except subprocess.TimeoutExpired:
            update = {"rc": None, "output": "timeout after %ss" % cfg["update_timeout"]}
        except OSError as e:
            update = {"rc": None, "output": str(e)}

        # Core's update_tables.py --aliases mode never flushes pf for an alias whose
        # rebuild left it empty (see _flush_emptied_tables). Do it ourselves, still
        # under the lock, unless the child never ran to completion.
        emptied = _flush_emptied_tables(cfg, names) if update["rc"] is not None else []

        # Arm the rate limit before releasing the lock. Otherwise a flush queued
        # behind us acquires the lock the instant we release it below (while we're
        # still doing the post-release "after" pfctl reads), reads the last.json
        # from before this flush started, and runs a second full rebuild instead
        # of standing down.
        _write_json_atomic(cfg["last_file"], {"at": now, "summary": []})
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()

    after = {name: pf_set(cfg, name) for name in names}
    summary = lib.summarise(before, after)
    _write_json_atomic(cfg["last_file"], {"at": now, "summary": summary})
    return {"before": before, "after": after, "summary": summary, "update_tables": update, "emptied": emptied}


def main(argv):
    try:
        if argv == ["status"]:
            result = cmd_status(DEFAULTS, time.time())
        elif argv == ["flush"]:
            result = cmd_flush(DEFAULTS)
        else:
            result = {"error": "usage", "detail": "macalias.py status|flush"}
    except Exception as e:  # always answer configd with JSON
        result = {"error": "internal", "detail": "%s: %s" % (type(e).__name__, e)}
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
