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
        if last and isinstance(last.get("at"), (int, float)) and now - last["at"] < cfg["min_interval"]:
            return {"error": "too_soon", "detail": "last flush %.0fs ago" % (now - last["at"])}

        tables = read_tables(cfg)
        names = lib.refresh_set(tables)
        if not names:
            return {"aliases": [], "note": "no mac aliases"}

        before = {name: pf_set(cfg, name) for name in names}

        try:
            os.unlink(cfg["cache_file"])
        except FileNotFoundError:
            pass

        for name in lib.mac_aliases(tables):
            md5 = os.path.join(cfg["aliastables_dir"], "%s.md5.txt" % name)
            if os.path.isfile(md5):
                os.utime(md5, (0, 0))

        try:
            proc = subprocess.run(
                [cfg["update_tables"], "--aliases", ",".join(names)],
                capture_output=True, text=True, timeout=cfg["update_timeout"],
            )
            update = {"rc": proc.returncode, "output": proc.stdout.strip()}
        except subprocess.TimeoutExpired:
            update = {"rc": None, "output": "timeout after %ss" % cfg["update_timeout"]}
        except OSError as e:
            update = {"rc": None, "output": str(e)}
    finally:
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()

    after = {name: pf_set(cfg, name) for name in names}
    summary = lib.summarise(before, after)
    with open(cfg["last_file"], "w") as f:
        json.dump({"at": now, "summary": summary}, f)
    return {"before": before, "after": after, "summary": summary, "update_tables": update}


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
