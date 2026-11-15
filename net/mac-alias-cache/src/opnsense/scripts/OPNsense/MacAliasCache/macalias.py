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

MAC alias cache: show what each mac alias resolves to (status), rebuild
every mac alias, and every alias nesting one, from current host discovery
data (flush), and add to core's MAC alias cache the IPv6 addresses the
kernel's neighbor table has for a listed MAC and host discovery lacks
(neighbors, run by cron each minute). Always prints one JSON object and
exits 0 so configd returns JSON rather than "Execute error".
"""
import fcntl
import json
import os
import selectors
import stat
import subprocess
import sys
import syslog
import tempfile
import time
from typing import TypedDict, final

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import macaliascache_lib as lib  # noqa: E402

# item -> core's file, for each file the flush imitates, reads core's fixes from or the neighbor keys rely
# on; the contract checks the programs it runs
_CORE_FILES = {row[0]: row[1] for row in lib.CORE_CONTRACT + lib.CORE_FIXES + lib.NEIGHBOR_CONTRACT}


class Config(TypedDict):
    """ the paths, programs and limits a status, a flush or a tick works with; DEFAULTS is the box's own """
    tables_conf: str
    cache_file: str
    lock_file: str
    state_dir: str
    aliastables_dir: str
    list_hosts: list[str]
    update_tables: str
    core_files: dict[str, str]
    pfctl: str
    ndp: list[str]
    ndp_timeout: float
    ndp_max_bytes: int
    settings_file: str
    lock_timeout: float
    lock_retry: float
    neighbors_lock_timeout: float
    min_interval: float
    update_timeout: int


class UpdateRun(TypedDict):
    """ one run of core's update_tables.py as the flush reply carries it (_run_update) """
    rc: int | None
    output: str
    status: str | None
    messages: list[str]
    complete: bool


DEFAULTS: Config = {
    "tables_conf": "/usr/local/etc/filter_tables.conf",
    "cache_file": lib.CACHE_FILE,
    "lock_file": lib.UPDATE_LOCK,
    "state_dir": "/var/run/macaliascache",
    "aliastables_dir": lib.ALIASTABLES_DIR,
    "list_hosts": list(lib.LIST_HOSTS_ARGV),
    "update_tables": _CORE_FILES["targeted_mode"],
    "core_files": _CORE_FILES,
    "pfctl": "/sbin/pfctl",
    "ndp": list(lib.NDP_ARGV),
    "ndp_timeout": 5.0,
    "ndp_max_bytes": lib.NDP_MAX_BYTES,
    "settings_file": "/usr/local/etc/macaliascache.conf",
    "lock_timeout": 15.0,
    "lock_retry": 0.25,
    # the tick runs at second 30, off core's own run at second 0, so core's lock is free when it asks
    "neighbors_lock_timeout": 5.0,
    "min_interval": 10.0,
    "update_timeout": 60,
}

# every item problems() can list that may block a flush, with the error code it refuses with when
# it does; when items of several codes block at once, the earliest code in _REFUSAL_ORDER wins.
# Every core-contract item is core_changed; core's fixes are notes, never problems
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
# the items problems() lists that never block a flush, so none has a refusal code
_ADVISORY_ITEMS = ("alias_ttl", "neighbor_merge", "ndp", "neighbors_setting", "neighbors_file")
# every item that stops the neighbor tick, whether or not it blocks a flush, with the code the tick refuses
# with; the earliest code in _NEIGHBORS_REFUSAL_ORDER wins. plugin_lock is either lock of the plugin's own.
# What only a flush uses (the expiry marker, the targeted update, the flush record, the alias names and
# lifetimes) does not stop the tick
_NEIGHBORS_REFUSAL_CODE = {
    "state_dir": "state_unusable",
    "plugin_lock": "state_unusable",
    "cache_file": "state_unusable",
    "neighbors_file": "state_unusable",
    "lock_file": "lock_unusable",
    "arpcache": "core_changed",
    "update_lock": "core_changed",
    "list_hosts": "core_changed",
    "neighbor_merge": "core_changed",
    "ndp": "core_changed",
    "neighbors_setting": "setting_unusable",
}
_NEIGHBORS_REFUSAL_ORDER = ("state_unusable", "lock_unusable", "core_changed", "setting_unusable")
# the items a removal of every key (neighbors remove) does not stop for: it reads neither the setting, the
# host list nor the neighbor table, and no longer needs core to merge the keys
_REMOVAL_UNUSED = ("neighbors_setting", "list_hosts", "ndp", "neighbor_merge")
# the tick's results that are no state: neither recorded nor logged. One is over within the minute; with
# the other the record itself may be what cannot be written, and status shows the problem
_UNRECORDED_RESULTS = ("busy", "state_unusable")
# the most of the settings file that is read; its template renders two short lines
_SETTING_MAX_CHARS = 4096


@final
class NeighborsError(TypedDict):
    """ the tick's reply when it changed nothing: one of its codes and the reason """
    error: str
    detail: str


@final
class NeighborsDone(TypedDict):
    """ the tick's reply when it ran: changed says whether core's cache was written, keys is how many keys of
    the plugin's own the cache holds now, samples at most five of the addresses added
    """
    result: str
    changed: bool
    added: int
    removed: int
    refreshed: int
    keys: int
    over_limit: int
    samples: list[str]


def state_paths(cfg):
    """ the plugin's own files, all inside its root-only state directory """
    return {
        "last_file": os.path.join(cfg["state_dir"], "last.json"),
        "plugin_lock": os.path.join(cfg["state_dir"], "flush.lock"),
        "neighbors_file": os.path.join(cfg["state_dir"], "neighbors.json"),
        "neighbors_lock": os.path.join(cfg["state_dir"], "neighbors.lock"),
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


def _state_lock_problem(path, name, blocks_flush):
    """ a lock of the plugin's own may be absent (its user creates it) or a regular file with one link;
    anything else is a problem, as its user will not open it
    """
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as e:
        return _problem("plugin_lock", "the plugin's %s lock at %s cannot be checked (%s)" % (name, path, e.strerror),
                        blocks_flush)
    if _single_regular(st):
        return None
    return _problem("plugin_lock", "the plugin's %s lock at %s is not a regular file with one link" % (name, path),
                    blocks_flush)


def _plugin_lock_problem(cfg):
    """ the flush lock; a problem with it blocks the flush """
    return _state_lock_problem(state_paths(cfg)["plugin_lock"], "flush", True)


def _neighbors_lock_problem(cfg):
    """ the neighbor tick's lock; a problem with it stops the tick and is no obstacle to a flush """
    return _state_lock_problem(state_paths(cfg)["neighbors_lock"], "neighbor", False)


def _neighbors_file_problem(cfg):
    """ a directory at neighbors.json stops the tick, as os.replace cannot replace it; anything else there is
    ignored on read and replaced by the tick's own write. It is no obstacle to a flush
    """
    path = state_paths(cfg)["neighbors_file"]
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return None
    except OSError as e:
        return _problem("neighbors_file", "plugin neighbor record at %s cannot be checked (%s)" % (path, e.strerror),
                        False)
    if stat.S_ISDIR(st.st_mode):
        return _problem("neighbors_file", "plugin neighbor record at %s is a directory" % path, False)
    return None


def _ndp_problem(cfg):
    """ the program the neighbor table is read with must be there to run """
    path = cfg["ndp"][0]
    if _executable(path):
        return None
    return _problem("ndp", "%s is missing or not executable, so the neighbor table cannot be read" % path, False)


def _setting_problem(cfg, setting):
    """ a settings file that is there and holds no clean setting reads as off; saving the setting renders it
    again
    """
    if setting[1] != "unusable":
        return None
    return _problem("neighbors_setting", "the plugin's settings file at %s holds no setting the plugin can read, so the "
                    "neighbor table is not used; save the setting on the plugin's page to write the file again"
                    % cfg["settings_file"], False)


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
    """ every name the flush refreshes must pass core's alias name pattern, because each becomes
    a path under the alias tables directory and a pfctl -t argument. Core's internal tables
    (__lan_network ...) fail the pattern and are never refreshed
    """
    bad = [name for name in lib.refresh_set(tables) if not lib.valid_alias_name(name)]
    if not bad:
        return None
    return _problem("alias_name", "alias names that do not match core's alias name pattern: %s; "
                    "the flush would use them in a file path and as a pfctl table name"
                    % ", ".join(repr(name) for name in bad), True)


def _alias_ttl_problems(cfg: Config, tables: dict[str, lib.Table]) -> list[dict[str, object]]:
    """ one problem per enabled MAC alias that core never rebuilds (lib.no_expiry), so a flush leaves it as
    it is; the other aliases are rebuilt all the same, so none blocks
    """
    return [_problem("alias_ttl", "MAC alias %s has no lifetime above 0 in core's alias table file (%s), so core "
                     "never rebuilds it and a flush cannot change it; clear the alias's update frequency"
                     % (name, cfg["tables_conf"]), False)
            for name in lib.no_expiry(tables)]


def problems(cfg, tables=None, texts=None, setting=None):
    """ what makes the plugin's state or core's files unsafe to use, for status, for a flush before it
    takes core's lock and for the neighbor tick; ensure_state_dir puts the state directory in place.
    tables is filter_tables.conf as the caller parsed it, so the names checked are the names used;
    texts is read_core_texts as the caller read it, so status reads each core file once; setting is
    read_setting as the caller read it. The problems of the neighbor addresses alone come last
    """
    state = ensure_state_dir(cfg)
    if tables is None:
        tables = read_tables(cfg)
    if texts is None:
        texts = read_core_texts(cfg)
    if setting is None:
        setting = read_setting(cfg)
    # nothing inside a state directory that failed its check is looked at
    found = [state, None if state else _last_file_problem(cfg), None if state else _plugin_lock_problem(cfg),
             _lock_file_problem(cfg), _cache_file_problem(cfg), _alias_name_problem(tables)]
    neighbors = [_ndp_problem(cfg), _setting_problem(cfg, setting), None if state else _neighbors_file_problem(cfg),
                 None if state else _neighbors_lock_problem(cfg)]
    return ([problem for problem in found if problem] + _alias_ttl_problems(cfg, tables) + lib.core_contract(texts)
            + lib.neighbor_contract(texts) + [problem for problem in neighbors if problem])


def refusal(found):
    """ the flush refusal for the blocking problems in found, or None when none blocks; the
    blocking texts make its detail and it carries every problem
    """
    blocking = [problem for problem in found if problem["blocks_flush"]]
    if not blocking:
        return None
    code = min((_REFUSAL_CODE[problem["item"]] for problem in blocking), key=_REFUSAL_ORDER.index)
    return {"error": code, "detail": "; ".join(problem["problem"] for problem in blocking), "problems": found}


def neighbors_refusal(found) -> NeighborsError | None:
    """ the tick's refusal for the problems in found that stop it, or None when none does; their texts make
    its detail. A problem stops the tick by its item, whether or not it blocks a flush
    """
    stopping = [problem for problem in found if problem["item"] in _NEIGHBORS_REFUSAL_CODE]
    if not stopping:
        return None
    code = min((_NEIGHBORS_REFUSAL_CODE[problem["item"]] for problem in stopping), key=_NEIGHBORS_REFUSAL_ORDER.index)
    return {"error": code, "detail": "; ".join(problem["problem"] for problem in stopping)}


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


def _run_hosts(cfg):
    """ list_hosts.py's exit status with the source and the rows it printed, each as printed and None when
    it printed none; three times None when it cannot be run, times out or prints no JSON object
    """
    try:
        proc = subprocess.run(cfg["list_hosts"], capture_output=True, text=True, timeout=30)
        data = json.loads(proc.stdout)
        return proc.returncode, data.get("source"), data.get("rows")
    # RecursionError is nesting deeper than the parser goes
    except (OSError, ValueError, RecursionError, subprocess.SubprocessError, AttributeError):
        return None, None, None


def read_hosts(cfg):
    """ (source, rows) from list_hosts.py; (None, []) when it fails or prints non-JSON, and no
    rows when its rows are not a list
    """
    _status, source, rows = _run_hosts(cfg)
    return source, rows if isinstance(rows, list) else []


def read_host_listing(cfg: Config) -> tuple[str, list[object]] | None:
    """ (source, rows) for the neighbor tick, which removes keys on what the host list says: None unless
    list_hosts.py ended with exit status 0 and printed one of its two sources with a list of rows, so a host
    list that could not be read is never taken for host discovery being off
    """
    status, source, rows = _run_hosts(cfg)
    if status != 0 or source not in ("discovery", "arp-ndp") or not isinstance(rows, list):
        return None
    return source, rows


def read_setting(cfg: Config) -> tuple[bool, str]:
    """ (whether the neighbor table is used, how the settings file read). "ok": the value the file holds.
    "absent": on, the model's default, for a file the template has not rendered. "unusable": off, for a
    file that is there and is not a regular file of root's with one clean setting
    """
    path = cfg["settings_file"]
    try:
        os.lstat(path)
    except FileNotFoundError:
        return True, "absent"
    except OSError:
        return False, "unusable"
    f = _open_regular(path)
    if f is None:
        return False, "unusable"
    try:
        with f:
            text = f.read(_SETTING_MAX_CHARS + 1)
    # ValueError includes UnicodeDecodeError
    except (OSError, ValueError):
        return False, "unusable"
    value = lib.parse_setting(text) if len(text) <= _SETTING_MAX_CHARS else None
    return (False, "unusable") if value is None else (value, "ok")


def _read_output(proc: subprocess.Popen[bytes], limit: int, timeout: float) -> bytes | None:
    """ what proc prints until it closes its output, when that is at most limit bytes within timeout seconds
    and it then ends with exit status 0; None otherwise. Never more than limit bytes and one read are held
    """
    if proc.stdout is None:
        return None
    deadline = time.monotonic() + timeout
    chunks: list[bytes] = []
    size = 0
    with selectors.DefaultSelector() as selector:
        selector.register(proc.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                return None
            chunk = os.read(proc.stdout.fileno(), 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > limit:
                return None
            chunks.append(chunk)
    try:
        status = proc.wait(max(deadline - time.monotonic(), 0))
    except subprocess.TimeoutExpired:
        return None
    return b"".join(chunks) if status == 0 else None


def read_neighbors(cfg: Config) -> list[lib.Pair] | None:
    """ the neighbor table's usable (MAC, address) pairs from ndp; None when it cannot be run, runs longer
    than its timeout, ends with another exit status than 0, prints more than ndp_max_bytes or prints
    anything but its JSON. An unreadable table is never an empty one
    """
    try:
        proc = subprocess.Popen(cfg["ndp"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)
    except OSError:
        return None
    try:
        output = _read_output(proc, cfg["ndp_max_bytes"], cfg["ndp_timeout"])
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait()
        if proc.stdout is not None:
            proc.stdout.close()
    if output is None:
        return None
    return lib.parse_neighbors(output.decode("utf-8", errors="replace"))


def _json_object(obj: object) -> dict[str, object] | None:
    return obj if isinstance(obj, dict) else None


def read_cache(cfg: Config) -> dict[str, object] | None:
    """ core's cache as the tick merges into it, with every entry as it is written: {} when the file is
    absent, which is normal after a boot; None when it exists and is not a regular file of root's holding a
    JSON object. Core's own run leaves it at 0 bytes from its first MAC alias until it ends, so such a file
    is never read as empty
    """
    path = cfg["cache_file"]
    try:
        os.lstat(path)
    except FileNotFoundError:
        return {}
    except OSError:
        return None
    cache = _read_json(path, _json_object)
    return cache if isinstance(cache, dict) else None


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


def acquire_lock(cfg, sleep, timeout=None):
    """ core's update-tables lock (flock(2), same as util-linux flock(1)): the handle, None on
    timeout (lock_timeout unless timeout gives another), or a lock_unusable reply when the path is
    not a regular file with one link that the plugin can open safely
    """
    path = cfg["lock_file"]
    fd = _open_lock(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, lib.CORE_FILE_MODE)
    if fd is None:
        return {"error": "lock_unusable",
                "detail": "core's alias update lock at %s is not a regular file with one link "
                          "that the plugin can open safely" % path}
    handle = _fdopen(fd, "a")
    deadline = cfg["lock_timeout"] if timeout is None else timeout
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


def _run_update(cfg: Config, names: list[str]) -> UpdateRun:
    """ core's targeted update of the aliases names, and what it answered: its exit status (None when it never
    started or was killed at the timeout), its output, and the status and messages of its reply, read once,
    after an exit status of 0. The run is complete when it ended with exit status 0 and a reply: only then are
    the alias files it left known to be whole
    """
    rc: int | None = None
    reply: lib.UpdateReply = {"status": None, "messages": []}
    try:
        proc = subprocess.run(
            [cfg["update_tables"], "--aliases", ",".join(names)],
            capture_output=True, text=True, timeout=cfg["update_timeout"],
        )
        rc = proc.returncode
        if rc == 0:
            output = proc.stdout.strip()
            reply = lib.parse_update_reply(output)
        else:
            # a crash's traceback is usually on stderr; keep both so it isn't lost
            output = "\n".join(part for part in (proc.stdout.strip(), proc.stderr.strip()) if part)
    except subprocess.TimeoutExpired:
        output = "timeout after %ss" % cfg["update_timeout"]
    except OSError as e:
        output = str(e)
    return {"rc": rc, "output": output, "status": reply["status"], "messages": reply["messages"],
            "complete": rc == 0 and reply["status"] is not None}


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


def _acquire_state_lock(path, name):
    """ a lock of the plugin's own in the state directory, never waited for: the handle, None when
    it is held, or a blocking plugin_lock problem when the path cannot be opened safely
    """
    fd = _open_lock(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o600)
    if fd is None:
        return _problem("plugin_lock", "the plugin's %s lock at %s is not a regular file with one link "
                                       "that the plugin can open safely" % (name, path), True)
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


def acquire_plugin_lock(cfg):
    """ the plugin's own flush lock in the state directory: the handle, None when another flush
    holds it (no waiting), or a state_unusable reply when the path cannot be opened safely
    """
    lock = _acquire_state_lock(state_paths(cfg)["plugin_lock"], "flush")
    return refusal([lock]) if isinstance(lock, dict) else lock


def acquire_neighbors_lock(cfg):
    """ the neighbor tick's own lock in the state directory, so ticks never pile up and the Flush button
    never answers busy because of one: the handle, None when another tick holds it (no waiting), or the
    tick's state_unusable reply when the path cannot be opened safely
    """
    lock = _acquire_state_lock(state_paths(cfg)["neighbors_lock"], "neighbor")
    return neighbors_refusal([lock]) if isinstance(lock, dict) else lock


def _unlock(handle):
    """ release a lock handle; closing it must happen even if the explicit unlock raises """
    try:
        fcntl.flock(handle, fcntl.LOCK_UN)
    finally:
        handle.close()


_LOGGED_REFUSALS = ("core_changed", "state_unusable", "lock_unusable", "hosts_malformed")
_LOG_LIMIT = 400


def _log(priority, text):
    """ one line in the system log """
    syslog.openlog("macaliascache")
    syslog.syslog(priority, text[:_LOG_LIMIT])


def log_refusal(code, detail):
    """ one warning line in the system log """
    _log(syslog.LOG_WARNING, "%s: %s" % (code, detail))


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

        update = _run_update(cfg, names)

        # emptied tables are flushed under the lock, and only after a complete update: one that crashed, was
        # killed or printed no reply may have left an alias file empty that it had not written yet
        emptied = _flush_emptied_tables(cfg, names) if update["complete"] else []

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
            "no_expiry": lib.no_expiry(tables), "rows_rejected": len(rows) - len(good), "rejected": rejected}


def _neighbors_done(plan: lib.NeighborPlan, cache: dict[str, object], over_limit: int, changed: bool) -> NeighborsDone:
    return {"result": "ok", "changed": changed, "added": len(plan["add"]), "removed": len(plan["remove"]),
            "refreshed": len(plan["refresh"]), "keys": lib.count_neighbor_keys(cache), "over_limit": over_limit,
            "samples": lib.neighbor_addresses(plan["add"])[:lib.NEIGHBOR_SAMPLES]}


def _neighbors(cfg: Config, now: float, sleep, remove_all: bool) -> NeighborsDone | NeighborsError:
    """ one tick under its own lock: what it answers, with core's cache written when the plan asked for it """
    setting = read_setting(cfg)
    tables = read_tables(cfg)
    found = problems(cfg, tables, read_core_texts(cfg), setting)
    if remove_all:
        found = [problem for problem in found if problem["item"] not in _REMOVAL_UNUSED]
    refused = neighbors_refusal(found)
    if refused:
        return refused

    # every key of ours is removed when the setting is off, no MAC alias is enabled or host discovery is
    # off (core then reads the neighbor table itself); only host discovery's own list merges
    merge = False
    hosts: set[lib.Pair] = set()
    neighbors: list[lib.Pair] = []
    if not remove_all and setting[0] and lib.mac_aliases(tables):
        listing = read_host_listing(cfg)
        if listing is None:
            return {"error": "hosts_unavailable", "detail": "host list could not be read; nothing changed"}
        source, rows = listing
        if source == "discovery":
            table = read_neighbors(cfg)
            if table is None:
                return {"error": "neighbors_unavailable", "detail": "neighbor table could not be read; nothing changed"}
            merge, hosts, neighbors = True, lib.host_pairs(rows), table

    def planned(cache: dict[str, object]) -> tuple[lib.NeighborPlan, int]:
        """ the plan for this cache and how many addresses the limits cut; the keys it holds come first """
        if not merge:
            return lib.neighbor_plan(cache, None, hosts, set(neighbors), now), 0
        wanted, over_limit = lib.wanted_neighbors(tables, hosts, neighbors, cache)
        return lib.neighbor_plan(cache, wanted, hosts, set(neighbors), now), over_limit

    # the normal minute ends here: a cache read without a lock that needs no change is left alone, with no
    # lock taken and nothing written. A cache that cannot be read says nothing, so it is read under the lock
    cache = read_cache(cfg)
    if cache is not None:
        plan, over_limit = planned(cache)
        if not (plan["add"] or plan["refresh"] or plan["remove"]):
            return _neighbors_done(plan, cache, over_limit, False)

    # sweep orphans from a prior kill between mkstemp and os.replace before writing again
    _sweep_stale_temps(cfg["cache_file"], now)
    lock = acquire_lock(cfg, sleep, cfg["neighbors_lock_timeout"])
    if isinstance(lock, dict):
        return {"error": lock["error"], "detail": lock["detail"]}
    if lock is None:
        return {"error": "busy", "detail": "alias update lock held for %ss" % cfg["neighbors_lock_timeout"]}
    try:
        # under core's lock only the cache is read and written: the host list and the neighbor table are
        # the ones read before it, and the plan is made again from this read
        cache = read_cache(cfg)
        if cache is None:
            return {"error": "cache_unreadable",
                    "detail": "core's MAC alias cache at %s holds no JSON object; nothing changed" % cfg["cache_file"]}
        plan, over_limit = planned(cache)
        changed = bool(plan["add"] or plan["refresh"] or plan["remove"])
        if changed:
            cache = lib.apply_neighbor_plan(cache, plan, now)
            _write_json_atomic(cfg["cache_file"], cache)
    finally:
        _unlock(lock)
    return _neighbors_done(plan, cache, over_limit, changed)


def _neighbors_record(reply: NeighborsDone | NeighborsError, now: float) -> lib.NeighborRecord:
    """ neighbors.json for a reply: a tick that changed nothing counts nothing """
    record: lib.NeighborRecord = {"at": now, "result": "ok", "added": 0, "removed": 0, "refreshed": 0, "keys": 0,
                                  "over_limit": 0, "samples": []}
    if "error" in reply:
        record["result"] = reply["error"]
        return record
    for name in ("added", "removed", "refreshed", "keys", "over_limit"):
        record[name] = reply[name]
    record["samples"] = reply["samples"]
    return record


def _log_neighbors(reply: NeighborsDone | NeighborsError, before: str, result: str) -> None:
    """ one line when addresses were added or removed, and one when the result changes between working and
    a refusal; building the line is guarded with the writing, so logging never changes the reply
    """
    try:
        if "error" in reply:
            if result != before:
                _log(syslog.LOG_WARNING, "neighbors: %s: %s" % (result, reply["detail"]))
            return
        if before != "ok":
            _log(syslog.LOG_NOTICE, "neighbors: working again after %s" % before)
        if reply["added"] or reply["removed"]:
            samples = " (%s)" % ", ".join(reply["samples"]) if reply["samples"] else ""
            _log(syslog.LOG_NOTICE, "neighbors: %d added%s, %d removed" % (reply["added"], samples, reply["removed"]))
    except Exception:
        pass


def _keep_neighbors_record(cfg: Config, reply: NeighborsDone | NeighborsError, previous: lib.NeighborRecord | None,
                           now: float) -> None:
    """ write neighbors.json when the tick wrote core's cache, when its result is another than the recorded
    one, and when the record is more than an hour old (or from the future), so the record's age says whether
    the tick runs; then log what changed. An unchanged minute writes and logs nothing
    """
    result = reply["error"] if "error" in reply else "ok"
    if result in _UNRECORDED_RESULTS:
        return
    wrote = "error" not in reply and reply["changed"]
    current = previous is not None and previous["result"] == result and 0 <= now - previous["at"] <= lib.NEIGHBOR_REFRESH
    if wrote or not current:
        path = state_paths(cfg)["neighbors_file"]
        _sweep_stale_temps(path, now)
        _write_json_atomic(path, _neighbors_record(reply, now), mode=0o600)
    _log_neighbors(reply, previous["result"] if previous else "ok", result)


def cmd_neighbors(cfg: Config, clock=time.time, sleep=time.sleep, remove_all: bool = False
                  ) -> NeighborsDone | NeighborsError:
    """ the neighbor tick: make core's cache hold, under keys of the plugin's own, the IPv6 addresses the
    neighbor table has for the MACs of the enabled MAC aliases and host discovery lacks; remove_all removes
    every such key whatever the setting, for the package's removal. Core's own minute run applies the cache
    """
    problem = ensure_state_dir(cfg)
    if problem:
        return {"error": "state_unusable", "detail": problem["problem"]}
    # one tick at a time, and never the flush lock: a second tick answers at once
    own_lock = acquire_neighbors_lock(cfg)
    if isinstance(own_lock, dict):
        return own_lock
    if own_lock is None:
        return {"error": "busy", "detail": "another neighbor tick is running"}
    try:
        now = clock()
        previous = _read_json(state_paths(cfg)["neighbors_file"], lib.neighbors_schema)
        reply = _neighbors(cfg, now, sleep, remove_all)
        _keep_neighbors_record(cfg, reply, previous, now)
    finally:
        _unlock(own_lock)
    return reply


def main(argv):
    try:
        if argv == ["status"]:
            result = cmd_status(DEFAULTS, time.time())
        elif argv == ["flush"]:
            result = cmd_flush(DEFAULTS)
        elif argv == ["neighbors"]:
            result = cmd_neighbors(DEFAULTS)
        elif argv == ["neighbors", "remove"]:
            result = cmd_neighbors(DEFAULTS, remove_all=True)
        else:
            result = {"error": "usage", "detail": "macalias.py status|flush|neighbors [remove]"}
    except Exception as e:  # always answer configd with JSON
        result = {"error": "internal", "detail": "%s: %s" % (type(e).__name__, e)}
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
