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
import syslog
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import macaliascache_lib as lib  # noqa: E402

# item -> core's file, for each file the flush imitates or reads core's fixes from; the contract
# checks the programs it runs
_CORE_FILES = {row[0]: row[1] for row in lib.CORE_CONTRACT + lib.CORE_FIXES}

DEFAULTS = {
    "tables_conf": "/usr/local/etc/filter_tables.conf",
    "cache_file": lib.CACHE_FILE,
    "lock_file": lib.UPDATE_LOCK,
    "state_dir": "/var/run/macaliascache",
    "aliastables_dir": lib.ALIASTABLES_DIR,
    "list_hosts": list(lib.LIST_HOSTS_ARGV),
    "update_tables": _CORE_FILES["targeted_mode"],
    "core_files": _CORE_FILES,
    "pfctl": "/sbin/pfctl",
    "lock_timeout": 15.0,
    "lock_retry": 0.25,
    "min_interval": 10.0,
    "update_timeout": 60,
}

# every item problems() can list, with the error code it refuses a flush with when it blocks;
# when items of several codes block at once, the earliest code in _REFUSAL_ORDER wins. Every
# core-contract item is core_changed; core's fixes are notes, never problems
_REFUSAL_CODE = {
    "state_dir": "state_unusable",
    "last_file": "state_unusable",
    "plugin_lock": "state_unusable",
    "cache_file": "state_unusable",
    "lock_file": "lock_unusable",
    "alias_name": "core_changed",
}
_REFUSAL_CODE.update((item, "core_changed") for item, _path, _expected in lib.CORE_CONTRACT)
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
    The checks and the mode fix go through one descriptor opened without following a link
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
    """ a directory at last.json blocks, as os.replace cannot replace it; anything else that is
    not a regular file of ours is ignored on read and replaced by the flush's own write
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
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid():
        return _problem("last_file", "plugin flush record at %s is not a regular file owned by root; "
                        "it is ignored and the next flush replaces it" % path, False)
    if st.st_nlink != 1:
        return _problem("last_file", "plugin flush record at %s has more than one link; "
                        "it is ignored and the next flush replaces it" % path, False)
    return None


def _plugin_lock_problem(cfg):
    """ the plugin's flush lock may be absent (the flush creates it) or a regular file with one
    link; anything else blocks, as the flush will not open it
    """
    path = state_paths(cfg)["plugin_lock"]
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as e:
        return _problem("plugin_lock", "the plugin's flush lock at %s cannot be checked (%s)" % (path, e.strerror),
                        True)
    if _single_regular(st):
        return None
    return _problem("plugin_lock", "the plugin's flush lock at %s is not a regular file with one link" % path, True)


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
    """ core loads its MAC alias cache unchecked, so a file that is not a regular file owned by
    root with one link is reported; only a directory, which os.replace cannot replace, blocks.
    Absent is normal after a boot
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
        return _problem("cache_file", "core's MAC alias cache at %s is not a regular file owned by root with one link; "
                        "core may be loading forged content" % path, False)
    return None


def _alias_name_problem(tables):
    """ every name the flush refreshes must pass core's alias name pattern, as it becomes a path
    under the alias tables directory and a pfctl -t argument. Core's internal tables
    (__lan_network ...) fail the pattern and are never refreshed
    """
    bad = [name for name in lib.refresh_set(tables) if not lib.valid_alias_name(name)]
    if not bad:
        return None
    return _problem("alias_name", "alias names that do not match core's alias name pattern: %s; "
                    "the flush would use them in a file path and as a pfctl table name"
                    % ", ".join(repr(name) for name in bad), True)


def problems(cfg, tables=None, texts=None):
    """ what makes the plugin's state or core's files unsafe to use, for status and for a
    flush before it takes core's lock; ensure_state_dir puts the state directory in place.
    tables is filter_tables.conf as the caller parsed it, so the names checked are the names used;
    texts is read_core_texts as the caller read it, so status reads each core file once
    """
    state = ensure_state_dir(cfg)
    if tables is None:
        tables = read_tables(cfg)
    if texts is None:
        texts = read_core_texts(cfg)
    # nothing inside a state directory that failed its check is looked at
    found = [state, None if state else _last_file_problem(cfg), None if state else _plugin_lock_problem(cfg),
             _lock_file_problem(cfg), _cache_file_problem(cfg), _alias_name_problem(tables)]
    return [problem for problem in found if problem] + lib.core_contract(texts)


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


def _open_regular(path, errors="strict"):
    """ path opened to read as UTF-8 text (errors as open() takes them) when it is a regular
    file with one link, owned by the running user, else None. Any OSError means absent:
    FreeBSD answers O_NOFOLLOW on a symlink with EMLINK, not ELOOP
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
    return _fdopen(fd, encoding="utf-8", errors=errors)


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


def _read_text(path):
    """ the text of a core file, None when it is not a regular file of root's or cannot be
    read; a byte that is not UTF-8 does not hide the texts around it
    """
    f = _open_regular(path, errors="replace")
    if f is None:
        return None
    try:
        with f:
            return f.read()
    except OSError:
        return None


def _executable(path):
    """ path is a regular file with an execute bit, as subprocess needs to run it """
    try:
        st = os.stat(path)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and bool(st.st_mode & 0o111)


def read_core_texts(cfg):
    """ {item: text} of each core file the flush imitates or reads core's fixes from, read once
    per file: None for a file that is missing or unusable; list_hosts only has to be
    executable, so its text is "exists" or None
    """
    texts, read = {}, {}
    for item, path in cfg["core_files"].items():
        if item == "list_hosts":
            texts[item] = "exists" if _executable(path) else None
            continue
        if path not in read:
            read[path] = _read_text(path)
        texts[item] = read[path]
    return texts


def _write_json_atomic(path, obj, mode=lib.CORE_FILE_MODE):
    """ write obj as JSON to a temp file beside path, then rename it over path; the default
    mode is the one core creates its cache file with (fixed, so a wider one is narrowed), the
    plugin's own files pass 0600
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
    """ delete our own atomic-write temp files beside path (.<basename>.<random>.tmp) older than
    max_age seconds; only a regular file of ours with one link is removed, and an entry that
    cannot be looked at or removed is skipped
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
            st = os.lstat(full)
            if _single_regular(st) and st.st_uid == os.geteuid() and now - st.st_mtime > max_age:
                os.unlink(full)
        except OSError:
            pass  # gone already, or not ours to remove


def read_tables(cfg):
    with open(cfg["tables_conf"]) as f:
        return lib.parse_tables(f.read())


def read_hosts(cfg):
    """ (source, rows) from list_hosts.py; (None, []) when it fails or prints non-JSON, and no
    rows when its rows are not a list
    """
    try:
        proc = subprocess.run(cfg["list_hosts"], capture_output=True, text=True, timeout=30)
        data = json.loads(proc.stdout)
        rows = data.get("rows", [])
        return data.get("source"), rows if isinstance(rows, list) else []
    # RecursionError is nesting deeper than the parser goes
    except (OSError, ValueError, RecursionError, subprocess.SubprocessError, AttributeError):
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
    the plugin can open safely
    """
    path = cfg["lock_file"]
    fd = _open_lock(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, lib.CORE_FILE_MODE)
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
    """ flush pf for each alias in names whose rebuilt content is empty, and return those names:
    targeted mode never flushes an emptied table (core #10950). A missing or undecodable .txt
    is not provably empty and is left alone; an error skips that table only
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
    tables = read_tables(cfg)
    texts = read_core_texts(cfg)
    found = problems(cfg, tables, texts)
    source, hosts = read_hosts(cfg)
    good, _rejected = lib.validate_rows(hosts)
    cache = _read_json(cfg["cache_file"], lib.cache_schema) or {}
    names = list(lib.mac_aliases(tables))
    pf_counts = {}
    for name in names:
        # a name outside core's pattern is listed as a problem and never passed to pfctl
        members = pf_set(cfg, name) if lib.valid_alias_name(name) else None
        pf_counts[name] = len(members) if members is not None else None
    # nothing inside a state directory that failed its check is read
    state_ok = not any(problem["item"] == "state_dir" for problem in found)
    last = _read_json(state_paths(cfg)["last_file"], lib.last_schema) if state_ok else None
    return {
        "source": source,
        "aliases": lib.alias_view(tables, cache, good, pf_counts, now),
        "last_flush": last,
        "problems": found,
        "notes": lib.core_fixes(texts),
    }


def acquire_plugin_lock(cfg):
    """ the plugin's own flush lock in the state directory: the handle, None when another flush
    holds it (no waiting), or a state_unusable reply when the path cannot be opened safely
    """
    path = state_paths(cfg)["plugin_lock"]
    fd = _open_lock(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600)
    if fd is None:
        return refusal([_problem(
            "plugin_lock", "the plugin's flush lock at %s is not a regular file with one link "
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


_LOGGED_REFUSALS = ("core_changed", "state_unusable", "lock_unusable", "hosts_malformed")
_LOG_LIMIT = 400


def log_refusal(code, detail):
    """ one warning line in the system log """
    syslog.openlog("macaliascache")
    syslog.syslog(syslog.LOG_WARNING, ("%s: %s" % (code, detail))[:_LOG_LIMIT])


def _log_reply(reply):
    """ log the reply if it is a refusal that is a security event or a flush that dropped host rows;
    building the line is guarded with the writing, so logging never changes the reply
    """
    try:
        if reply.get("error") in _LOGGED_REFUSALS:
            log_refusal(reply["error"], reply.get("detail", ""))
        elif reply.get("rows_rejected"):
            log_refusal("rows_rejected", "%d host rows dropped, e.g. %s" % (reply["rows_rejected"],
                                                                             "; ".join(reply["rejected"])))
    except Exception:
        pass


def cmd_flush(cfg, clock=time.time, sleep=time.sleep):
    """ the flush reply; it is logged here so no refusal path logs twice or not at all """
    reply = _flush(cfg, clock, sleep)
    _log_reply(reply)
    return reply


def _flush(cfg, clock, sleep):
    # every refusal comes before any write
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
        # read once, so the names the problem list checks are the names the flush uses
        tables = read_tables(cfg)
        refused = refusal(problems(cfg, tables))
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

        names = lib.refresh_set(tables)
        if not names:
            return {"aliases": [], "note": "no mac aliases"}

        # the host list is read before any side effect: a failure refuses, changes nothing and
        # leaves the rate limit unarmed; only rows with a MAC and an address are written
        source, rows = read_hosts(cfg)
        if source is None or not rows:
            return {"error": "hosts_unavailable", "detail": "host list could not be read; nothing changed"}
        good, rejected = lib.validate_rows(rows)
        if not good:
            return {"error": "hosts_malformed",
                    "detail": "%d host rows, none with a MAC and an address in the expected columns; nothing changed"
                              % len(rows),
                    "rejected": rejected}
        seeded = lib.seed_cache(good, now)

        before = {name: pf_set(cfg, name) for name in names}

        # the cache is replaced with current data only, in core's format, so stale MACs are dropped
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

        # emptied tables are flushed under the lock, unless the child never ran to completion
        emptied = _flush_emptied_tables(cfg, names) if update["rc"] is not None else []

        # the rate limit is armed before the unlock, or a flush queued behind this one would
        # read the previous last.json and rebuild again
        _write_json_atomic(last_file, {"at": now, "summary": []}, mode=0o600)
    finally:
        try:
            _unlock(lock)
        finally:
            _unlock(plugin_lock)

    after = {name: pf_set(cfg, name) for name in names}
    summary = lib.summarise(before, after)
    _write_json_atomic(last_file, {"at": now, "summary": summary}, mode=0o600)
    return {"before": before, "after": after, "summary": summary, "update_tables": update, "emptied": emptied,
            "rows_rejected": len(rows) - len(good), "rejected": rejected}


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
