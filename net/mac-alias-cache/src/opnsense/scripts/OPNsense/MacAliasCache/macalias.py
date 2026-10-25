#!/usr/local/bin/python3
"""
Copyright (C) 2026 cayossarian
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
import stat
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
    "state_dir": "/var/run/macaliascache",
    "aliastables_dir": "/var/db/aliastables",
    "list_hosts": ["/usr/local/opnsense/scripts/interfaces/list_hosts.py", "-n"],
    "update_tables": "/usr/local/opnsense/scripts/filter/update_tables.py",
    "pfctl": "/sbin/pfctl",
    "lock_timeout": 15.0,
    "lock_retry": 0.25,
    "min_interval": 10.0,
    "update_timeout": 60,
}

# the error code each blocking problem item refuses a flush with; when items of several
# codes block at once, the earliest code in _REFUSAL_ORDER wins
_REFUSAL_CODE = {
    "state_dir": "state_unusable",
    "last_file": "state_unusable",
    "cache_file": "state_unusable",
    "lock_file": "lock_unusable",
}
_REFUSAL_ORDER = ("state_unusable", "lock_unusable", "core_changed")


def state_paths(cfg):
    """ the plugin's own files, all inside its root-only state directory """
    return {
        "last_file": os.path.join(cfg["state_dir"], "last.json"),
        "plugin_lock": os.path.join(cfg["state_dir"], "flush.lock"),
    }


def _problem(item, text, blocks_flush):
    return {"item": item, "problem": text, "blocks_flush": blocks_flush}


def ensure_state_dir(cfg):
    """ create the state directory 0700 when missing and narrow a wider mode back to 0700;
    a blocking state_dir problem when it is not a directory owned by root, else None.
    The checks and the mode fix go through one descriptor opened without following a link.
    /var/run is root's alone, so this catches an operator's mistake more than an attacker
    """
    path = cfg["state_dir"]
    try:
        os.makedirs(path, 0o700, exist_ok=True)
    except FileExistsError:
        pass  # something other than a directory holds the path; the open below refuses it
    except OSError as e:
        return _problem("state_dir", "plugin state directory %s cannot be created (%s)" % (path, e.strerror), True)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except OSError:
        return _problem("state_dir", "plugin state directory %s is not a directory, or is a symbolic link" % path, True)
    try:
        st = os.fstat(fd)
        if not stat.S_ISDIR(st.st_mode):
            return _problem("state_dir", "plugin state directory %s is not a directory" % path, True)
        if st.st_uid != os.geteuid():
            return _problem("state_dir", "plugin state directory %s is not owned by root" % path, True)
        if st.st_mode & 0o077:
            os.fchmod(fd, 0o700)
    except OSError as e:
        return _problem("state_dir", "plugin state directory %s cannot be checked (%s)" % (path, e.strerror), True)
    finally:
        os.close(fd)
    return None


def _single_regular(st):
    """ a regular file with one link: a hard link passes the type and owner checks """
    return stat.S_ISREG(st.st_mode) and st.st_nlink == 1


def _last_file_problem(cfg):
    """ the flush writes its record over last.json with os.replace, which cannot replace a
    directory, so one there blocks the flush before it writes anything. Anything else that is
    not a regular file of ours is ignored on read, and the flush's own write replaces it.
    """
    path = state_paths(cfg)["last_file"]
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as e:
        return _problem("last_file", "plugin flush record at %s cannot be checked (%s)" % (path, e.strerror), True)
    if stat.S_ISDIR(st.st_mode):
        return _problem("last_file", "plugin flush record at %s is a directory" % path, True)
    if not _single_regular(st) or st.st_uid != os.geteuid():
        return _problem("last_file", "plugin flush record at %s is not a regular file owned by root; "
                        "it is ignored and the next flush replaces it" % path, False)
    return None


def _lock_file_problem(cfg):
    """ core's update-tables lock may be absent (core's flock(1) creates it on use) or a
    regular file with one link; anything else blocks, as the plugin will not open it
    """
    path = cfg["lock_file"]
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as e:
        return _problem("lock_file", "core's alias update lock at %s cannot be checked (%s)" % (path, e.strerror), True)
    if _single_regular(st):
        return None
    return _problem("lock_file", "core's alias update lock at %s is not a regular file with one link" % path, True)


def _cache_file_problem(cfg):
    """ core loads its MAC alias cache without checking it, so say when it is not a regular
    file owned by root. A flush replaces it atomically and is the remedy, so only a directory,
    which os.replace cannot replace, blocks one. Absent is normal after a boot.
    """
    path = cfg["cache_file"]
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as e:
        return _problem("cache_file", "core's MAC alias cache at %s cannot be checked (%s)" % (path, e.strerror), True)
    if stat.S_ISDIR(st.st_mode):
        return _problem("cache_file", "core's MAC alias cache at %s is a directory" % path, True)
    if not _single_regular(st) or st.st_uid != os.geteuid():
        return _problem("cache_file", "core's MAC alias cache at %s is not a regular file owned by root; "
                        "core may be loading forged content" % path, False)
    return None


def problems(cfg):
    """ what makes the plugin's state or core's files unsafe to use, for status and for a
    flush before it takes core's lock; ensure_state_dir puts the state directory in place
    """
    state = ensure_state_dir(cfg)
    # nothing inside a state directory that failed its check is looked at
    found = [state, None if state else _last_file_problem(cfg), _lock_file_problem(cfg), _cache_file_problem(cfg)]
    return [problem for problem in found if problem]


def refusal(found):
    """ the flush refusal for the blocking problems in found, or None when none blocks; the
    blocking texts make its detail and it carries every problem
    """
    blocking = [problem for problem in found if problem["blocks_flush"]]
    if not blocking:
        return None
    code = min((_REFUSAL_CODE[problem["item"]] for problem in blocking), key=_REFUSAL_ORDER.index)
    return {"error": code, "detail": "; ".join(problem["problem"] for problem in blocking), "problems": found}


def _fdopen(fd, *args, **kwargs):
    """ os.fdopen that closes fd when wrapping it fails, so no descriptor is left over """
    try:
        return os.fdopen(fd, *args, **kwargs)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass  # io.open closes the descriptor itself when it fails after creating the file object
        raise


def _open_regular(path):
    """ path opened to read as UTF-8 text when it is a regular file with one link, owned by
    the running user, else None. O_NOFOLLOW refuses a symlink and O_NONBLOCK keeps a FIFO
    from waiting for a writer; the link count refuses a hard link planted in /tmp to another
    root-owned file. Any OSError means absent: FreeBSD answers a symlink with EMLINK, not ELOOP.
    """
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
    except OSError:
        st = None
    if st is None or not _single_regular(st) or st.st_uid != os.geteuid():
        os.close(fd)
        return None
    return _fdopen(fd, encoding="utf-8")


def _read_json(path, schema):
    """ schema() of the JSON in path; None when path is not a regular file we own, holds no
    UTF-8 JSON, or fails the schema
    """
    f = _open_regular(path)
    if f is None:
        return None
    try:
        with f:
            data = json.load(f)
    # ValueError includes UnicodeDecodeError; RecursionError is nesting deeper than the parser goes
    except (OSError, ValueError, RecursionError):
        return None
    return schema(data)


def _write_json_atomic(path, obj, mode=0o644):
    """ write obj as JSON to a temp file beside path, then rename it over path; the default
    mode is the one core gives its cache file, the plugin's own files pass 0600
    """
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path) or ".", prefix=".%s." % os.path.basename(path), suffix=".tmp")
    try:
        # the with block closes fd on every path out of it, chmod failure included
        with _fdopen(fd, "w", encoding="utf-8") as f:
            os.fchmod(f.fileno(), mode)  # mkstemp creates 0600
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


def _open_lock(path, flags, mode):
    """ fd of the lock file at path, opened with flags that follow no symlink and never wait
    on a FIFO; None when it cannot be opened or is not a regular file with one link. Any
    OSError counts: FreeBSD answers a symlink with EMLINK, not ELOOP.
    """
    try:
        fd = os.open(path, flags, mode)
    except OSError:
        return None
    try:
        regular = _single_regular(os.fstat(fd))
    except OSError:
        regular = False
    if not regular:
        os.close(fd)
        return None
    return fd


def acquire_lock(cfg, sleep):
    """ core's update-tables lock (flock(2), same as util-linux flock(1)): the handle, None on
    timeout, or a lock_unusable reply when the path is not a regular file with one link that
    the plugin can open safely. Core's own flock(1) wrappers would follow a symlink there; the plugin does not.
    """
    path = cfg["lock_file"]
    fd = _open_lock(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o644)
    if fd is None:
        return {"error": "lock_unusable",
                "detail": "core's alias update lock at %s is not a regular file with one link "
                          "that the plugin can open safely" % path}
    handle = _fdopen(fd, "a")
    deadline = cfg["lock_timeout"]
    waited = 0.0
    try:
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
    except BaseException:
        handle.close()
        raise


def _flush_emptied_tables(cfg, names):
    """ core's update_tables.py --aliases (targeted) mode forces cnt_alias_pf_content
    to the new content count, so it never runs PF.flush for an alias whose rebuilt
    content is now empty; pf keeps the stale addresses until the next non-targeted
    (cron) run. Flush pf ourselves for any such alias. A missing .txt means "not
    managed / unknown": do nothing. Undecodable content is not provably empty:
    treat it as non-empty, do nothing. Errors are per-table and never abort the
    flush.
    """
    flushed = []
    for name in names:
        path = os.path.join(cfg["aliastables_dir"], "%s.txt" % name)
        try:
            with open(path) as f:
                lines = f.readlines()
        except (OSError, ValueError):  # ValueError includes UnicodeDecodeError
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
    found = problems(cfg)
    tables = read_tables(cfg)
    source, hosts = read_hosts(cfg)
    cache = _read_json(cfg["cache_file"], lib.cache_schema) or {}
    names = list(lib.mac_aliases(tables))
    pf_counts = {}
    for name in names:
        members = pf_set(cfg, name)
        pf_counts[name] = len(members) if members is not None else None
    # nothing inside a state directory that failed its check is read
    state_ok = not any(problem["item"] == "state_dir" for problem in found)
    last = _read_json(state_paths(cfg)["last_file"], lib.last_schema) if state_ok else None
    return {
        "source": source,
        "aliases": lib.alias_view(tables, cache, hosts, pf_counts, now),
        "last_flush": last,
        "problems": found,
    }


def acquire_plugin_lock(cfg):
    """ the plugin's own flush lock in the state directory: the handle, None when another flush
    holds it (no waiting), or a state_unusable reply when the path cannot be opened safely
    """
    path = state_paths(cfg)["plugin_lock"]
    fd = _open_lock(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600)
    if fd is None:
        return refusal([_problem(
            "state_dir", "the plugin's flush lock at %s is not a regular file with one link "
                         "that the plugin can open safely" % path, True)])
    handle = _fdopen(fd, "w")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        return None
    except BaseException:
        handle.close()
        raise
    return handle


def _unlock(handle):
    """ release a lock handle; closing it must happen even if the explicit unlock raises """
    try:
        fcntl.flock(handle, fcntl.LOCK_UN)
    finally:
        handle.close()


def cmd_flush(cfg, clock=time.time, sleep=time.sleep):
    # the plugin's own files live in the state directory, so it is made safe before any of
    # them is opened; every refusal below comes before any write
    problem = ensure_state_dir(cfg)
    if problem:
        return refusal([problem])
    # one flush at a time: a second request answers at once instead of queueing a root
    # process behind core's lock
    plugin_lock = acquire_plugin_lock(cfg)
    if isinstance(plugin_lock, dict):
        return plugin_lock
    if plugin_lock is None:
        return {"error": "busy", "detail": "another flush is running"}
    lock = None
    try:
        refused = refusal(problems(cfg))
        if refused:
            return refused
        last_file = state_paths(cfg)["last_file"]
        lock = acquire_lock(cfg, sleep)
        if isinstance(lock, dict):
            return lock
        if lock is None:
            return {"error": "busy", "detail": "alias update lock held for %ss" % cfg["lock_timeout"]}
    finally:
        if lock is None or isinstance(lock, dict):
            _unlock(plugin_lock)
    try:
        # rate limit checked under the lock, so a flush that finished while we waited wins
        last = _read_json(last_file, lib.last_schema)
        now = clock()
        # lower bound: a backwards clock step must not lock flush out indefinitely
        if last is not None and 0 <= now - last["at"] < cfg["min_interval"]:
            return {"error": "too_soon", "detail": "last flush %.0fs ago" % (now - last["at"])}

        # sweep orphans from a prior kill between mkstemp and os.replace before writing again
        _sweep_stale_temps(cfg["cache_file"], now)
        _sweep_stale_temps(last_file, now)

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
        _write_json_atomic(last_file, {"at": now, "summary": []}, mode=0o600)
    finally:
        try:
            _unlock(lock)
        finally:
            _unlock(plugin_lock)

    after = {name: pf_set(cfg, name) for name in names}
    summary = lib.summarise(before, after)
    _write_json_atomic(last_file, {"at": now, "summary": summary}, mode=0o600)
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
