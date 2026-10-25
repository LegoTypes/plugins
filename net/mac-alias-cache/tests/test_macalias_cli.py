import contextlib
import errno
import fcntl
import json
import os
import pathlib
import shutil
import signal
import socket
import stat
import subprocess
import sys
import textwrap

import pytest

import macalias
import macaliascache_lib as lib

TABLES = """<?xml version="1.0"?>
<tabledef>
  <table><name>DevMacs</name><type>mac</type><address>aa:bb:cc:00:00:01</address><ttl>30</ttl></table>
  <table><name>Parent</name><type>host</type><address>DevMacs</address><ttl>300</ttl></table>
</tabledef>
"""

# the core files the flush imitates, relative to /usr/local/opnsense; the fixtures mirror them
CORE_FILES = {
    "arpcache": "scripts/filter/lib/alias/arpcache.py",
    "update_lock": "service/conf/actions.d/actions_filter.conf",
    "md5_marker": "scripts/filter/lib/alias/__init__.py",
    "targeted_mode": "scripts/filter/update_tables.py",
    "emptied_table": "scripts/filter/update_tables.py",
    "list_hosts": "scripts/interfaces/list_hosts.py",
}
FIXTURES = pathlib.Path(__file__).parent / "fixtures" / "core"


def _exe(path, body):
    path.write_text("#!/bin/sh\n" + textwrap.dedent(body))
    path.chmod(path.stat().st_mode | stat.S_IEXEC)
    return str(path)


@pytest.fixture
def env(tmp_path):
    pf = tmp_path / "pf"
    pf.mkdir()
    (pf / "DevMacs").write_text("192.0.2.50\n192.0.2.99\n")
    (pf / "Parent").write_text("192.0.2.50\n192.0.2.99\n")
    aliastables = tmp_path / "aliastables"
    aliastables.mkdir()
    (aliastables / "DevMacs.md5.txt").write_text("x")
    (aliastables / "Parent.md5.txt").write_text("y")
    (tmp_path / "filter_tables.conf").write_text(TABLES)
    (tmp_path / "arp.cache").write_text(json.dumps(
        {"aa:bb:cc:00:00:01": {"items": ["192.0.2.50", "192.0.2.99"], "last_seen": 1000.0}}))
    pfctl = _exe(tmp_path / "pfctl", f"""
        # pfctl -t NAME -T show|flush
        f="{pf}/$2"
        if [ "$4" = "flush" ]; then
            : > "$f"
            echo "$@" >> "{tmp_path}/pfctl_flush_args"
            exit 0
        fi
        [ -f "$f" ] || {{ echo "pfctl: Table does not exist." >&2; exit 1; }}
        cat "$f"
    """)
    update = _exe(tmp_path / "update_tables.py", f"""
        echo "$@" >> "{tmp_path}/update_args"
        printf '192.0.2.50\\n' > "{pf}/DevMacs"
        printf '192.0.2.50\\n' > "{pf}/Parent"
        echo '{{"status": "ok"}}'
    """)
    hosts = _exe(tmp_path / "list_hosts.py", """
        echo '{"source": "discovery", "rows": [["vlan0.120", "aa:bb:cc:00:00:01", "192.0.2.50"]]}'
    """)
    # a copy of the fixtures, so a case may change a core file
    shutil.copytree(FIXTURES, tmp_path / "core")
    cfg = dict(macalias.DEFAULTS)
    cfg.update(
        tables_conf=str(tmp_path / "filter_tables.conf"),
        cache_file=str(tmp_path / "arp.cache"),
        lock_file=str(tmp_path / "update.lock"),
        state_dir=str(tmp_path / "state"),
        aliastables_dir=str(aliastables),
        list_hosts=[hosts, "-n"],
        update_tables=update,
        pfctl=pfctl,
        lock_timeout=0.5,
        lock_retry=0.05,
        core_files={item: str(tmp_path / "core" / path) for item, path in CORE_FILES.items()},
    )
    return cfg, tmp_path


@pytest.fixture(autouse=True)
def problems_name_only_mapped_items():
    """ every problem any case here produces or refuses with names an item that has a refusal
    code, so an item added without one fails here instead of raising KeyError in a flush
    """
    real_problems, real_refusal = macalias.problems, macalias.refusal

    def check(found):
        unmapped = [problem["item"] for problem in found if problem["item"] not in macalias._REFUSAL_CODE]
        assert unmapped == [], found

    def problems(*args, **kwargs):
        found = real_problems(*args, **kwargs)
        check(found)
        return found

    def refusal(found):
        check(found)
        return real_refusal(found)

    # a separate MonkeyPatch, so a case's own monkeypatch.undo() leaves this in place
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(macalias, "problems", problems)
        patch.setattr(macalias, "refusal", refusal)
        yield


def _last(cfg):
    return pathlib.Path(macalias.state_paths(cfg)["last_file"])


def _write_last(cfg, obj):
    """ last.json as a flush leaves it: in a 0700 state dir, mode 0600 """
    os.makedirs(cfg["state_dir"], 0o700, exist_ok=True)
    _last(cfg).write_text(json.dumps(obj))
    _last(cfg).chmod(0o600)


def test_status_reports_source_rows_and_last_flush(env):
    cfg, tmp = env
    _write_last(cfg, {"at": 1050.0, "summary": []})
    out = macalias.cmd_status(cfg, now=1060.0)
    assert out["source"] == "discovery"
    row = out["aliases"][0]
    assert row["name"] == "DevMacs" and row["pf_count"] == 2 and row["nested_by"] == ["Parent"]
    assert row["macs"][0]["cache_items"] == ["192.0.2.50", "192.0.2.99"]
    assert row["macs"][0]["current_items"] == ["192.0.2.50"]
    assert out["last_flush"] == {"at": 1050.0, "summary": []}


def test_status_survives_corrupt_cache(env):
    cfg, tmp = env
    (tmp / "arp.cache").write_text('{"aa:bb:cc:00:00:01": {"items": [')
    out = macalias.cmd_status(cfg, now=0.0)
    assert out["aliases"][0]["macs"][0]["cache_items"] == []


def test_status_survives_list_hosts_failure(env):
    cfg, tmp = env
    cfg["list_hosts"] = [_exe(tmp / "broken_hosts", "echo not-json\n"), "-n"]
    out = macalias.cmd_status(cfg, now=0.0)
    assert out["source"] is None
    assert out["aliases"][0]["macs"][0]["current_items"] == []


def test_status_missing_pf_table_is_null(env):
    cfg, tmp = env
    (tmp / "pf" / "DevMacs").unlink()
    out = macalias.cmd_status(cfg, now=0.0)
    assert out["aliases"][0]["pf_count"] is None


def test_flush_seeds_cache_from_hosts_forces_expiry_runs_targeted_update(env):
    cfg, tmp = env
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert "error" not in out
    # seeded from the validated list_hosts rows only, in core's ArpCache format
    assert json.loads((tmp / "arp.cache").read_text()) == {
        "aa:bb:cc:00:00:01": {"items": ["192.0.2.50"], "last_seen": 5000.0}}
    assert os.stat(tmp / "aliastables" / "DevMacs.md5.txt").st_mtime == 0
    assert os.stat(tmp / "aliastables" / "Parent.md5.txt").st_mtime != 0   # parents follow via rel_alias.expired()
    assert (tmp / "update_args").read_text().split() == ["--aliases", "DevMacs,Parent"]
    by_name = {r["name"]: r for r in out["summary"]}
    assert by_name["DevMacs"]["removed"] == ["192.0.2.99"]
    assert by_name["Parent"]["removed"] == ["192.0.2.99"]
    assert out["update_tables"]["rc"] == 0
    assert json.loads(_last(cfg).read_text())["at"] == 5000.0


def test_flush_seeds_every_ip_per_mac_and_skips_short_rows(env):
    cfg, tmp = env
    listing = json.dumps({"source": "discovery", "rows": [
        ["vlan0.120", "aa:bb:cc:00:00:01", "192.0.2.50"],
        ["vlan0.120", "aa:bb:cc:00:00:01", "2001:db8::50"],
        ["vlan0.120", "aa:bb:cc:00:00:02"],
        ["vlan0.66", "AA:BB:CC:00:00:03", "192.0.2.77"],
    ]})
    cfg["list_hosts"] = [_exe(tmp / "multi_hosts", "echo '%s'\n" % listing), "-n"]
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert "error" not in out
    assert out["rows_rejected"] == 1 and out["rejected"] == [repr(["vlan0.120", "aa:bb:cc:00:00:02"])]
    # MAC keys kept exactly as list_hosts returns them, as core's ArpCache.current_cache does
    assert json.loads((tmp / "arp.cache").read_text()) == {
        "aa:bb:cc:00:00:01": {"items": ["192.0.2.50", "2001:db8::50"], "last_seen": 5000.0},
        "AA:BB:CC:00:00:03": {"items": ["192.0.2.77"], "last_seen": 5000.0},
    }


def test_flush_flushes_pf_table_left_empty_by_targeted_update(env):
    # core's update_tables.py never flushes pf for an alias whose targeted-mode
    # (--aliases) rebuild left its .txt empty (cnt_alias_pf_content is forced to
    # cnt_alias_content in that mode); the plugin must do it itself.
    cfg, tmp = env
    cfg["update_tables"] = _exe(tmp / "empty_update", f"""
        echo "$@" >> "{tmp}/update_args"
        : > "{tmp}/aliastables/DevMacs.txt"
        : > "{tmp}/aliastables/Parent.txt"
        echo '{{"status": "ok"}}'
    """)
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert "error" not in out
    assert out["emptied"] == ["DevMacs", "Parent"]
    assert (tmp / "pf" / "DevMacs").read_text() == ""
    assert (tmp / "pf" / "Parent").read_text() == ""
    by_name = {r["name"]: r for r in out["summary"]}
    assert sorted(by_name["DevMacs"]["removed"]) == ["192.0.2.50", "192.0.2.99"]
    assert sorted(by_name["Parent"]["removed"]) == ["192.0.2.50", "192.0.2.99"]


def test_flush_skips_pf_flush_when_rebuilt_txt_is_not_empty(env):
    cfg, tmp = env
    cfg["update_tables"] = _exe(tmp / "nonempty_update", f"""
        echo "$@" >> "{tmp}/update_args"
        printf '192.0.2.50\\n' > "{tmp}/aliastables/DevMacs.txt"
        printf '192.0.2.50\\n' > "{tmp}/aliastables/Parent.txt"
        printf '192.0.2.50\\n' > "{tmp}/pf/DevMacs"
        printf '192.0.2.50\\n' > "{tmp}/pf/Parent"
        echo '{{"status": "ok"}}'
    """)
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert "error" not in out
    assert out["emptied"] == []
    assert not (tmp / "pfctl_flush_args").exists()


def test_flush_skips_pf_flush_when_txt_missing(env):
    # the default fake update_tables (see env fixture) never writes aliastables/*.txt:
    # a missing .txt means "not managed / unknown"
    cfg, tmp = env
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert "error" not in out
    assert out["emptied"] == []
    assert not (tmp / "pfctl_flush_args").exists()


def test_flush_skips_pf_flush_when_update_tables_fails_to_start(env):
    cfg, tmp = env
    # pre-existing empty .txt: if rc weren't None this would qualify for a flush
    (tmp / "aliastables" / "DevMacs.txt").write_text("")
    (tmp / "aliastables" / "Parent.txt").write_text("")
    cfg["update_tables"] = str(tmp / "does-not-exist")
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert out["update_tables"]["rc"] is None
    assert out["emptied"] == []
    assert not (tmp / "pfctl_flush_args").exists()


def test_flush_skips_pf_flush_when_txt_is_undecodable(env):
    # not provably empty: treat as non-empty rather than let UnicodeDecodeError
    # (a ValueError) escape cmd_flush after update_tables already ran
    cfg, tmp = env
    (tmp / "aliastables" / "DevMacs.txt").write_bytes(b"\xff\xfe")
    (tmp / "aliastables" / "Parent.txt").write_bytes(b"\xff\xfe")
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert "error" not in out
    assert out["emptied"] == []
    assert not (tmp / "pfctl_flush_args").exists()


def _snapshot(tmp):
    return (
        (tmp / "arp.cache").read_bytes(),
        os.stat(tmp / "aliastables" / "DevMacs.md5.txt").st_mtime,
        os.stat(tmp / "aliastables" / "Parent.md5.txt").st_mtime,
    )


@pytest.mark.parametrize("body", [
    "echo not-json\n",
    "echo '{\"source\": \"discovery\", \"rows\": []}'\n",
    "exit 1\n",
    "echo '{\"rows\": [[\"vlan0.120\", \"aa:bb:cc:00:00:01\", \"192.0.2.50\"]]}'\n",
    "echo '{\"source\": \"discovery\", \"rows\": {\"vlan0.120\": [\"aa:bb:cc:00:00:01\", \"192.0.2.50\"]}}'\n",
    "echo '{\"source\": \"discovery\", \"rows\": \"aa:bb:cc:00:00:01 192.0.2.50\"}'\n",
    "echo '{\"source\": \"discovery\", \"rows\": null}'\n",
    "echo '[[\"vlan0.120\", \"aa:bb:cc:00:00:01\", \"192.0.2.50\"]]'\n",
    "head -c 200000 /dev/zero | tr '\\0' '['\n",
], ids=["non-json", "empty-rows", "no-output", "no-source", "rows-object", "rows-string", "rows-null",
        "top-level-list", "nested-beyond-the-parser"])
def test_flush_refuses_when_hosts_unavailable(env, body):
    cfg, tmp = env
    cfg["list_hosts"] = [_exe(tmp / "bad_hosts", body), "-n"]
    before = _snapshot(tmp)
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert out == {"error": "hosts_unavailable", "detail": "host list could not be read; nothing changed"}
    assert _snapshot(tmp) == before
    assert not (tmp / "update_args").exists()
    assert not _last(cfg).exists()   # rate limit not armed
    assert sorted(p.name for p in tmp.iterdir() if p.name.startswith((".", "tmp"))) == []


def test_flush_rate_limit_ignores_future_timestamp(env):
    # a backwards clock step must not lock flush out indefinitely
    cfg, tmp = env
    _write_last(cfg, {"at": 5100.0, "summary": []})
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert "error" not in out
    assert json.loads(_last(cfg).read_text())["at"] == 5000.0


def test_write_json_atomic_replaces_and_leaves_no_temp(tmp_path):
    target = tmp_path / "out.json"
    target.write_text("old")
    macalias._write_json_atomic(str(target), {"a": 1})
    assert json.loads(target.read_text()) == {"a": 1}
    assert [p.name for p in tmp_path.iterdir()] == ["out.json"]
    # same mode a plain open() gives under the usual 022 umask, not mkstemp's 0600
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o644


def test_write_json_atomic_failure_keeps_original(tmp_path):
    target = tmp_path / "out.json"
    target.write_text("old")
    with pytest.raises(TypeError):
        macalias._write_json_atomic(str(target), {"a": object()})
    assert target.read_text() == "old"
    assert [p.name for p in tmp_path.iterdir()] == ["out.json"]


def test_write_json_atomic_fchmod_failure_closes_fd_and_leaves_no_temp(tmp_path, monkeypatch):
    target = tmp_path / "out.json"
    recorded = {}
    real_mkstemp = macalias.tempfile.mkstemp

    def spy_mkstemp(*args, **kwargs):
        fd, tmp = real_mkstemp(*args, **kwargs)
        recorded["fd"] = fd
        return fd, tmp

    def boom(fd, mode):
        raise OSError("fchmod failed")

    monkeypatch.setattr(macalias.tempfile, "mkstemp", spy_mkstemp)
    monkeypatch.setattr(macalias.os, "fchmod", boom)

    with pytest.raises(OSError):
        macalias._write_json_atomic(str(target), {"a": 1})

    # immediately, before opening anything else that could reuse the fd number
    with pytest.raises(OSError):
        os.fstat(recorded["fd"])

    assert not target.exists()
    assert [p.name for p in tmp_path.iterdir()] == []


def test_flush_writes_state_files_atomically(env, monkeypatch):
    cfg, tmp = env
    replaced = []
    real_replace = os.replace

    def spy(src, dst):
        assert os.path.dirname(src) == os.path.dirname(dst)
        replaced.append(os.path.basename(dst))
        real_replace(src, dst)

    monkeypatch.setattr(macalias.os, "replace", spy)
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert "error" not in out
    assert replaced == ["arp.cache", "last.json", "last.json"]


def test_flush_sweeps_stale_temp_files_for_cache_file(env):
    # orphans from a kill between mkstemp and os.replace: stale ones are swept, fresh ones survive
    cfg, tmp = env
    old = tmp / ".arp.cache.oldrand.tmp"
    old.write_text("stale")
    os.utime(old, (5000.0 - 120, 5000.0 - 120))
    fresh = tmp / ".arp.cache.freshrand.tmp"
    fresh.write_text("fresh")
    os.utime(fresh, (5000.0, 5000.0))
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert "error" not in out
    assert not old.exists()
    assert fresh.exists()


def test_flush_sweeps_only_its_own_temp_files(env, monkeypatch):
    # core's cache is in /tmp, where any user can make a name of the temp pattern: a link
    # looping to itself, a directory, another user's file or a hard link must neither stop the
    # flush nor be removed; only a stale regular file of ours with one link is swept
    cfg, tmp = env
    stale = (5000.0 - 120, 5000.0 - 120)
    loop = tmp / ".arp.cache.loop.tmp"
    os.symlink(loop.name, loop)
    os.utime(loop, stale, follow_symlinks=False)
    directory = tmp / ".arp.cache.dir.tmp"
    directory.mkdir()
    foreign = tmp / ".arp.cache.foreign.tmp"
    foreign.write_text("theirs")
    elsewhere = tmp / "elsewhere"
    elsewhere.write_text("linked")
    linked = tmp / ".arp.cache.linked.tmp"
    os.link(elsewhere, linked)
    ours = tmp / ".arp.cache.ours.tmp"
    ours.write_text("stale")
    for path in (directory, foreign, linked, ours):
        os.utime(path, stale)
    _patch_stat(monkeypatch, "lstat", foreign, _UID, os.geteuid() + 1)
    out = _flush(cfg)
    assert "error" not in out
    assert os.path.islink(loop)
    assert directory.is_dir()
    assert foreign.read_text() == "theirs"
    assert linked.read_text() == "linked"
    assert not ours.exists()


def test_flush_too_soon_changes_nothing(env):
    cfg, tmp = env
    _write_last(cfg, {"at": 4995.0, "summary": []})
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert out["error"] == "too_soon"
    assert (tmp / "arp.cache").exists()


def test_flush_busy_when_lock_held(env):
    cfg, tmp = env
    with open(cfg["lock_file"], "a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert out["error"] == "busy"
    assert (tmp / "arp.cache").exists()


def test_flush_rate_limit_checked_after_lock(env):
    # a concurrent flush that finished while we waited for the lock must make us stand down
    cfg, tmp = env
    calls = {"n": 0}

    def sleep(_):
        calls["n"] += 1
        _write_last(cfg, {"at": 5000.0, "summary": []})
        fcntl.flock(holder, fcntl.LOCK_UN)

    with open(cfg["lock_file"], "a") as holder:
        fcntl.flock(holder, fcntl.LOCK_EX)
        out = macalias.cmd_flush(cfg, clock=lambda: 5001.0, sleep=sleep)
    assert calls["n"] >= 1
    assert out["error"] == "too_soon"


def test_flush_without_mac_aliases_is_noop(env):
    cfg, tmp = env
    (tmp / "filter_tables.conf").write_text("<tabledef/>")
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert out == {"aliases": [], "note": "no mac aliases"}
    assert (tmp / "arp.cache").exists()


def test_flush_reports_update_tables_failure_and_empty_output(env):
    cfg, tmp = env
    cfg["update_tables"] = _exe(tmp / "failing_update", "exit 3\n")
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert out["update_tables"] == {"rc": 3, "output": ""}
    assert json.loads((tmp / "arp.cache").read_text()) == {
        "aa:bb:cc:00:00:01": {"items": ["192.0.2.50"], "last_seen": 5000.0}}


def test_flush_reports_update_tables_stderr_in_output(env):
    # a crash's traceback usually lands on stderr; it must not be dropped
    cfg, tmp = env
    cfg["update_tables"] = _exe(tmp / "failing_update_stderr", """
        echo "boom" >&2
        exit 5
    """)
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert out["update_tables"]["rc"] == 5
    assert "boom" in out["update_tables"]["output"]


def test_flush_releases_lock_after_success(env):
    cfg, tmp = env
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert "error" not in out
    with open(cfg["lock_file"], "a") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)  # must not raise: lock was released


def test_flush_releases_lock_after_too_soon(env):
    cfg, tmp = env
    _write_last(cfg, {"at": 4995.0, "summary": []})
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert out["error"] == "too_soon"
    with open(cfg["lock_file"], "a") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)  # must not raise: lock was released


def test_flush_rate_limit_race_through_lock_handoff(env, monkeypatch):
    # Flush A's "after" pfctl reads happen once the lock is already released (see
    # cmd_flush). A second flush (B) queued on that same lock can therefore acquire
    # it *during* A's after-reads. B must see A's rate-limit marker already written
    # and stand down, rather than racing A into a second full rebuild.
    cfg, tmp = env
    real_pf_set = macalias.pf_set
    state = {"calls": 0, "nested": None}

    def fake_pf_set(cfg_, name):
        state["calls"] += 1
        # calls 1-2 are A's "before" reads (still holding the lock); call 3 is the
        # first "after" read, made right after A released the lock in its finally
        if state["calls"] == 3 and state["nested"] is None:
            state["nested"] = macalias.cmd_flush(cfg_, clock=lambda: 5001.0, sleep=lambda s: None)
        return real_pf_set(cfg_, name)

    monkeypatch.setattr(macalias, "pf_set", fake_pf_set)
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert "error" not in out
    assert state["nested"]["error"] == "too_soon"
    assert (tmp / "update_args").read_text().strip().splitlines() == ["--aliases DevMacs,Parent"]


def test_main_always_prints_json_and_exits_zero(capsys):
    assert macalias.main(["bogus"]) == 0
    assert json.loads(capsys.readouterr().out)["error"] == "usage"


def _flush(cfg):
    return macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)


_NLINK, _UID = 3, 4   # positions in an os.stat_result


def _patch_stat(monkeypatch, name, path, field, value):
    """ make os.<name> (fstat or lstat) report value in field for the file now at path, matched
    by device and inode; every other file keeps its real stat
    """
    target = os.lstat(path)
    real = getattr(os, name)

    def patched(arg, *args, **kwargs):
        st = real(arg, *args, **kwargs)
        if (st.st_dev, st.st_ino) != (target.st_dev, target.st_ino):
            return st
        fields = list(st)
        fields[field] = value
        return os.stat_result(fields)

    monkeypatch.setattr(macalias.os, name, patched)


class _Hung(Exception):
    """ raised by the alarm guard; not an OSError, so no except clause under test swallows it """


def _hung(signum, frame):
    raise _Hung()


@contextlib.contextmanager
def _within(seconds):
    previous = signal.signal(signal.SIGALRM, _hung)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


CACHE_FORGED = ("core's MAC alias cache at %s is not a regular file owned by root with one link; "
                "core may be loading forged content")
CACHE_DIRECTORY = "core's MAC alias cache at %s is a directory"
LOCK_NOT_REGULAR = "core's alias update lock at %s is not a regular file with one link"
LAST_DIRECTORY = "plugin flush record at %s is a directory"
LAST_IGNORED = ("plugin flush record at %s is not a regular file owned by root; "
                "it is ignored and the next flush replaces it")
LAST_LINKED = "plugin flush record at %s has more than one link; it is ignored and the next flush replaces it"
PLUGIN_LOCK_NOT_REGULAR = "the plugin's flush lock at %s is not a regular file with one link"
PLUGIN_LOCK_UNUSABLE = PLUGIN_LOCK_NOT_REGULAR + " that the plugin can open safely"
CANNOT_CHECK = {
    "last_file": "plugin flush record at %s cannot be checked (%s)",
    "plugin_lock": "the plugin's flush lock at %s cannot be checked (%s)",
    "lock_file": "core's alias update lock at %s cannot be checked (%s)",
    "cache_file": "core's MAC alias cache at %s cannot be checked (%s)",
}
EMPTIED_NOTE = ("core may now flush emptied tables itself (core #10950); "
                "the plugin's own flush is redundant but harmless")


def _items(out, item):
    return [p for p in out["problems"] if p["item"] == item]


def test_flush_creates_state_dir_0700_and_writes_last_json_0600(env):
    cfg, tmp = env
    assert "last_file" not in macalias.DEFAULTS
    assert macalias.DEFAULTS["state_dir"] == "/var/run/macaliascache"
    assert macalias.state_paths(macalias.DEFAULTS) == {
        "last_file": "/var/run/macaliascache/last.json",
        "plugin_lock": "/var/run/macaliascache/flush.lock",
    }
    assert not os.path.exists(cfg["state_dir"])
    out = _flush(cfg)
    assert "error" not in out
    assert stat.S_IMODE(os.lstat(cfg["state_dir"]).st_mode) == 0o700
    assert _last(cfg).parent == pathlib.Path(cfg["state_dir"])
    assert stat.S_IMODE(os.lstat(_last(cfg)).st_mode) == 0o600
    assert json.loads(_last(cfg).read_text())["at"] == 5000.0
    assert not (tmp / "last.json").exists()


def test_flush_refuses_when_state_dir_is_a_symlink(env):
    cfg, tmp = env
    elsewhere = tmp / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    os.symlink(elsewhere, cfg["state_dir"])
    before = _snapshot(tmp)
    out = _flush(cfg)
    assert out["error"] == "state_unusable"
    assert [p["item"] for p in out["problems"]] == ["state_dir"]
    assert out["problems"][0]["blocks_flush"] is True
    assert cfg["state_dir"] in out["detail"]
    assert _snapshot(tmp) == before
    assert not (tmp / "update_args").exists()
    assert list(elsewhere.iterdir()) == []


def test_flush_refuses_when_state_dir_is_a_regular_file(env):
    cfg, tmp = env
    pathlib.Path(cfg["state_dir"]).write_text("x")
    before = _snapshot(tmp)
    out = _flush(cfg)
    assert out["error"] == "state_unusable"
    assert [p["item"] for p in out["problems"]] == ["state_dir"]
    assert _snapshot(tmp) == before
    assert not (tmp / "update_args").exists()
    assert pathlib.Path(cfg["state_dir"]).read_text() == "x"


def test_flush_refuses_when_state_dir_is_not_ours(env, monkeypatch):
    cfg, tmp = env
    os.mkdir(cfg["state_dir"], 0o700)
    _patch_stat(monkeypatch, "fstat", cfg["state_dir"], _UID, os.geteuid() + 1)
    before = _snapshot(tmp)
    out = _flush(cfg)
    assert out["error"] == "state_unusable"
    assert [p["item"] for p in out["problems"]] == ["state_dir"]
    assert _snapshot(tmp) == before
    assert not (tmp / "update_args").exists()
    assert os.listdir(cfg["state_dir"]) == []


def test_flush_repairs_state_dir_mode(env):
    cfg, tmp = env
    os.mkdir(cfg["state_dir"])
    os.chmod(cfg["state_dir"], 0o755)
    out = _flush(cfg)
    assert "error" not in out
    assert stat.S_IMODE(os.lstat(cfg["state_dir"]).st_mode) == 0o700
    assert (tmp / "update_args").exists()


def test_read_json_ignores_symlink(env):
    cfg, tmp = env
    real = tmp / "elsewhere.json"
    real.write_text(json.dumps({"at": 4995.0, "summary": []}))
    real.chmod(0o600)
    os.mkdir(cfg["state_dir"], 0o700)
    os.symlink(real, _last(cfg))
    assert macalias.cmd_status(cfg, now=5000.0)["last_flush"] is None
    out = _flush(cfg)
    assert "error" not in out   # the rate limit did not fire
    assert json.loads(real.read_text())["at"] == 4995.0   # the link's target is not written through


def test_read_json_returns_at_once_on_fifo(env):
    cfg, tmp = env
    os.mkdir(cfg["state_dir"], 0o700)
    os.mkfifo(_last(cfg), 0o600)
    with _within(5):
        status = macalias.cmd_status(cfg, now=5000.0)
        out = _flush(cfg)
    assert status["last_flush"] is None
    assert "error" not in out
    assert stat.S_ISREG(os.lstat(_last(cfg)).st_mode)


def test_read_json_ignores_foreign_owner(env, monkeypatch):
    cfg, tmp = env
    _write_last(cfg, {"at": 4995.0, "summary": []})
    _patch_stat(monkeypatch, "fstat", _last(cfg), _UID, os.geteuid() + 1)
    assert macalias.cmd_status(cfg, now=5000.0)["last_flush"] is None
    out = _flush(cfg)
    assert "error" not in out   # the rate limit did not fire


def test_read_refuses_hard_linked_file(env, monkeypatch):
    # a hard link passes the type and owner checks, so the link count is checked too
    cfg, tmp = env
    _write_last(cfg, {"at": 4995.0, "summary": []})
    _patch_stat(monkeypatch, "fstat", cfg["cache_file"], _NLINK, 2)
    assert macalias.cmd_status(cfg, now=5000.0)["aliases"][0]["macs"][0]["cache_items"] == []
    monkeypatch.undo()
    _patch_stat(monkeypatch, "fstat", _last(cfg), _NLINK, 2)
    assert macalias.cmd_status(cfg, now=5000.0)["last_flush"] is None
    assert "error" not in _flush(cfg)   # the rate limit did not fire


def test_acquire_lock_refuses_hard_linked_lock_path(env, monkeypatch):
    cfg, tmp = env
    pathlib.Path(cfg["lock_file"]).write_text("")
    _patch_stat(monkeypatch, "fstat", cfg["lock_file"], _NLINK, 2)
    before = _snapshot(tmp)
    lock = macalias.acquire_lock(cfg, sleep=lambda s: None)
    assert isinstance(lock, dict) and lock["error"] == "lock_unusable"
    out = _flush(cfg)
    assert out["error"] == "lock_unusable"
    assert _snapshot(tmp) == before
    assert not (tmp / "update_args").exists()
    assert not _last(cfg).exists()
    # status names it too, so the problem list foretells the refusal
    _patch_stat(monkeypatch, "lstat", cfg["lock_file"], _NLINK, 2)
    assert _items(macalias.cmd_status(cfg, now=0.0), "lock_file") == [
        {"item": "lock_file", "problem": LOCK_NOT_REGULAR % cfg["lock_file"], "blocks_flush": True}]


@pytest.mark.parametrize("content", [
    {"at": "4995", "summary": []},
    {"at": 4995.0, "summary": {}},
    {"at": 4995.0, "summary": [{"name": "DevMacs", "before": 1, "after": 1, "added": [], "removed": "x"}]},
    [4995.0],
], ids=["at-string", "summary-dict", "removed-string", "top-level-list"])
def test_read_json_rejects_bad_schema(env, content):
    cfg, tmp = env
    _write_last(cfg, content)
    assert macalias.cmd_status(cfg, now=5000.0)["last_flush"] is None
    out = _flush(cfg)
    assert "error" not in out   # the rate limit did not fire


@pytest.mark.parametrize("at, now", [("NaN", 5000.0), ("Infinity", 5000.0), ("-Infinity", 5000.0), ("true", 5.0)],
                         ids=["nan", "infinity", "minus-infinity", "true"])
def test_last_json_with_non_finite_or_bool_at_neither_arms_nor_blocks_the_rate_limit(env, at, now):
    # (s7) Python's json reads NaN and Infinity as floats, and true is an int (1) in Python's
    # arithmetic: 5.0 - true would be 4 s ago and refuse as too_soon. None of them is a time.
    cfg, tmp = env
    os.mkdir(cfg["state_dir"], 0o700)
    _last(cfg).write_text('{"at": %s, "summary": []}' % at)
    _last(cfg).chmod(0o600)
    assert macalias.cmd_status(cfg, now=now)["last_flush"] is None
    out = macalias.cmd_flush(cfg, clock=lambda: now, sleep=lambda s: None)
    assert "error" not in out
    assert json.loads(_last(cfg).read_text())["at"] == now


def test_status_cache_schema_drops_malformed_entries(env):
    cfg, tmp = env
    (tmp / "arp.cache").write_text(json.dumps({"aa:bb:cc:00:00:01": {"items": "192.0.2.5"}}))
    out = macalias.cmd_status(cfg, now=0.0)
    assert out["aliases"][0]["macs"][0]["cache_items"] == []


def test_status_reports_cache_file_problem_for_fifo_and_symlink(env):
    cfg, tmp = env
    cache = tmp / "arp.cache"
    real = tmp / "real.cache"
    cache.rename(real)
    os.symlink(real, cache)
    forged = [{"item": "cache_file", "problem": CACHE_FORGED % cache, "blocks_flush": False}]
    out = macalias.cmd_status(cfg, now=0.0)
    assert _items(out, "cache_file") == forged
    assert out["aliases"][0]["macs"][0]["cache_items"] == []   # not followed

    cache.unlink()
    os.mkfifo(cache)
    with _within(5):
        out = macalias.cmd_status(cfg, now=0.0)
        flushed = _flush(cfg)
    assert _items(out, "cache_file") == forged
    assert "error" not in flushed   # a flush is the remedy, so it stays allowed
    assert stat.S_ISREG(os.lstat(cache).st_mode)

    cache.unlink()
    cache.mkdir()
    out = macalias.cmd_status(cfg, now=0.0)
    assert _items(out, "cache_file") == [
        {"item": "cache_file", "problem": CACHE_DIRECTORY % cache, "blocks_flush": True}]
    os.utime(tmp / "aliastables" / "DevMacs.md5.txt", (1.0, 1.0))
    (tmp / "update_args").unlink()
    refused = macalias.cmd_flush(cfg, clock=lambda: 6000.0, sleep=lambda s: None)
    assert refused["error"] == "state_unusable"
    assert refused["detail"] == CACHE_DIRECTORY % cache
    assert os.stat(tmp / "aliastables" / "DevMacs.md5.txt").st_mtime == 1.0
    assert not (tmp / "update_args").exists()


@pytest.mark.parametrize("field, value", [(_UID, os.geteuid() + 1), (_NLINK, 2)], ids=["foreign-owner", "hard-link"])
def test_status_reports_cache_file_problem_for_foreign_owner(env, monkeypatch, field, value):
    cfg, tmp = env
    _patch_stat(monkeypatch, "lstat", cfg["cache_file"], field, value)
    out = macalias.cmd_status(cfg, now=0.0)
    assert _items(out, "cache_file") == [
        {"item": "cache_file", "problem": CACHE_FORGED % cfg["cache_file"], "blocks_flush": False}]


def test_cache_file_problem_text_names_cores_path_by_default():
    assert CACHE_FORGED % macalias.DEFAULTS["cache_file"] == (
        "core's MAC alias cache at /tmp/alias_filter_arp.cache is not a regular file owned by root with one link; "
        "core may be loading forged content")


def test_flush_refuses_before_writing_when_last_json_is_a_directory(env):
    # os.replace cannot put the flush record over a directory; without the check the flush
    # would fail only after update_tables had run, with the rate limit unarmed
    cfg, tmp = env
    os.mkdir(cfg["state_dir"], 0o700)
    _last(cfg).mkdir()
    problem = {"item": "last_file", "problem": LAST_DIRECTORY % _last(cfg), "blocks_flush": True}
    assert _items(macalias.cmd_status(cfg, now=0.0), "last_file") == [problem]
    before = _snapshot(tmp)
    out = _flush(cfg)
    assert out == {"error": "state_unusable", "detail": LAST_DIRECTORY % _last(cfg), "problems": [problem]}
    assert _snapshot(tmp) == before
    assert not (tmp / "update_args").exists()
    assert _last(cfg).is_dir()


@pytest.mark.parametrize("kind", ["symlink", "fifo", "socket", "foreign-owner", "hard-link"])
def test_status_notes_non_file_last_json_and_flush_replaces_it(env, monkeypatch, kind):
    # unlike a directory these are no obstacle to os.replace, so the flush is the remedy
    cfg, tmp = env
    os.mkdir(cfg["state_dir"], 0o700)
    path = _last(cfg)
    if kind == "symlink":
        (tmp / "elsewhere.json").write_text(json.dumps({"at": 4995.0, "summary": []}))
        os.symlink(tmp / "elsewhere.json", path)
    elif kind == "fifo":
        os.mkfifo(path, 0o600)
    elif kind == "socket":
        monkeypatch.chdir(cfg["state_dir"])   # a socket path is limited to about 100 bytes
        listener = socket.socket(socket.AF_UNIX)
        listener.bind(path.name)
        listener.close()
    else:
        _write_last(cfg, {"at": 4995.0, "summary": []})
        field, value = (_UID, os.geteuid() + 1) if kind == "foreign-owner" else (_NLINK, 2)
        _patch_stat(monkeypatch, "lstat", path, field, value)
        _patch_stat(monkeypatch, "fstat", path, field, value)
    with _within(5):
        status = macalias.cmd_status(cfg, now=5000.0)
        out = _flush(cfg)
    text = (LAST_LINKED if kind == "hard-link" else LAST_IGNORED) % path
    assert _items(status, "last_file") == [{"item": "last_file", "problem": text, "blocks_flush": False}]
    assert status["last_flush"] is None
    assert "error" not in out
    st = os.lstat(path)
    assert stat.S_ISREG(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600
    assert _items(macalias.cmd_status(cfg, now=5000.0), "last_file") == []


def test_acquire_lock_refuses_symlink_lock_path(env):
    cfg, tmp = env
    target = tmp / "lock-target"
    target.write_text("")
    os.symlink(target, cfg["lock_file"])
    before = _snapshot(tmp)
    lock = macalias.acquire_lock(cfg, sleep=lambda s: None)
    assert isinstance(lock, dict) and lock["error"] == "lock_unusable" and cfg["lock_file"] in lock["detail"]
    out = _flush(cfg)
    assert out["error"] == "lock_unusable"
    assert _snapshot(tmp) == before
    assert not (tmp / "update_args").exists()
    assert not _last(cfg).exists()
    assert target.read_text() == ""


def test_write_json_atomic_sets_mode_0600_under_state_dir(env):
    cfg, tmp = env
    out = _flush(cfg)
    assert "error" not in out
    modes = {p.name: stat.S_IMODE(os.lstat(p).st_mode) for p in pathlib.Path(cfg["state_dir"]).iterdir()}
    assert "last.json" in modes and set(modes.values()) == {0o600}
    # core's cache file keeps the 0644 core creates it with
    assert stat.S_IMODE(os.lstat(tmp / "arp.cache").st_mode) == 0o644
    target = pathlib.Path(cfg["state_dir"]) / "other.json"
    macalias._write_json_atomic(str(target), {"a": 1}, mode=0o600)
    assert stat.S_IMODE(os.lstat(target).st_mode) == 0o600
    assert json.loads(target.read_text()) == {"a": 1}


def test_status_lists_state_dir_problem_when_state_dir_is_a_regular_file(env):
    # (s8) an unusable state directory is reported as a problem in one JSON object, never an internal error
    cfg, tmp = env
    pathlib.Path(cfg["state_dir"]).write_text("x")
    out = macalias.cmd_status(cfg, now=0.0)
    assert "error" not in out
    assert [p["item"] for p in out["problems"]] == ["state_dir"]
    assert out["problems"][0]["blocks_flush"] is True
    assert cfg["state_dir"] in out["problems"][0]["problem"]
    assert out["last_flush"] is None
    assert out["aliases"][0]["name"] == "DevMacs"


def test_status_creates_state_dir_0700(env):
    # (s9) status puts the state directory in place right after an upgrade, and writes nothing else there
    cfg, tmp = env
    assert not os.path.exists(cfg["state_dir"])
    out = macalias.cmd_status(cfg, now=0.0)
    assert out["problems"] == []
    st = os.lstat(cfg["state_dir"])
    assert stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o700
    assert os.listdir(cfg["state_dir"]) == []


@pytest.mark.parametrize("kind", ["absent", "regular", "fifo", "symlink"])
def test_status_lock_file_problem(env, kind):
    # (s10) core's flock(1) creates the lock on use, so absent is fine; only a regular file may be opened
    cfg, tmp = env
    path = cfg["lock_file"]
    if kind == "regular":
        pathlib.Path(path).write_text("")
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "symlink":
        (tmp / "lock-target").write_text("")
        os.symlink(tmp / "lock-target", path)
    out = macalias.cmd_status(cfg, now=0.0)
    if kind in ("absent", "regular"):
        assert _items(out, "lock_file") == []
        return
    assert _items(out, "lock_file") == [{"item": "lock_file", "problem": LOCK_NOT_REGULAR % path, "blocks_flush": True}]
    before = _snapshot(tmp)
    with _within(5):
        lock = macalias.acquire_lock(cfg, sleep=lambda s: None)
        out = _flush(cfg)
    assert isinstance(lock, dict) and lock["error"] == "lock_unusable"
    assert out["error"] == "lock_unusable"
    assert out["detail"] == LOCK_NOT_REGULAR % path
    assert _snapshot(tmp) == before
    assert not (tmp / "update_args").exists()


def test_emlink_from_open_reads_absent_and_refuses_cores_lock(env, monkeypatch):
    # (s11) FreeBSD's open(2) answers O_NOFOLLOW on a symlink with EMLINK, not ELOOP, so
    # any OSError from the open must read as absent, or refuse core's lock, never escape
    cfg, tmp = env
    _write_last(cfg, {"at": 4995.0, "summary": []})
    pathlib.Path(cfg["lock_file"]).write_text("")
    refused = {cfg["cache_file"], str(_last(cfg)), cfg["lock_file"]}
    real_open = os.open

    def emlink_open(path, flags, *args, **kwargs):
        if os.fspath(path) in refused:
            raise OSError(errno.EMLINK, os.strerror(errno.EMLINK), path)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(macalias.os, "open", emlink_open)
    status = macalias.cmd_status(cfg, now=5000.0)
    assert "error" not in status
    assert status["last_flush"] is None
    assert status["aliases"][0]["macs"][0]["cache_items"] == []
    before = _snapshot(tmp)
    out = _flush(cfg)
    assert out["error"] == "lock_unusable"
    assert _snapshot(tmp) == before
    assert not (tmp / "update_args").exists()


def test_status_without_cache_file_has_no_problem_and_flush_creates_it(env):
    # (s12) core's cache is absent after a boot until something writes it
    cfg, tmp = env
    (tmp / "arp.cache").unlink()
    out = macalias.cmd_status(cfg, now=0.0)
    assert out["problems"] == []
    assert out["aliases"][0]["macs"][0]["cache_items"] == []
    assert "error" not in _flush(cfg)
    assert stat.S_ISREG(os.lstat(tmp / "arp.cache").st_mode)
    assert json.loads((tmp / "arp.cache").read_text()) == {
        "aa:bb:cc:00:00:01": {"items": ["192.0.2.50"], "last_seen": 5000.0}}


@pytest.mark.parametrize("target", ["last", "cache"])
def test_undecodable_bytes_read_as_absent(env, target):
    # (s13) undecodable bytes read as absent, never an exception
    cfg, tmp = env
    if target == "last":
        os.mkdir(cfg["state_dir"], 0o700)
        _last(cfg).write_bytes(b'{"at": 4995.0, "summary": [{"name": "\xff"}]}')
        _last(cfg).chmod(0o600)
    else:
        (tmp / "arp.cache").write_bytes(b'{"aa:bb:cc:00:00:01": {"items": ["\xff"], "last_seen": 1000.0}}')
    out = macalias.cmd_status(cfg, now=5000.0)
    if target == "last":
        assert out["last_flush"] is None
    else:
        assert out["aliases"][0]["macs"][0]["cache_items"] == []
    assert "error" not in _flush(cfg)   # the rate limit did not fire


def test_reads_decode_utf8_whatever_the_locale(env):
    # (s13) the files are UTF-8 JSON; run status under a Latin-1 locale, where a default open() would misread them
    cfg, tmp = env
    row = {"name": "Café", "before": 1, "after": 1, "added": [], "removed": []}
    os.mkdir(cfg["state_dir"], 0o700)
    _last(cfg).write_bytes(json.dumps({"at": 1050.0, "summary": [row]}, ensure_ascii=False).encode("utf-8"))
    _last(cfg).chmod(0o600)
    child_env = dict(os.environ, LC_ALL="en_US.ISO8859-1", LANG="en_US.ISO8859-1",
                     PYTHONUTF8="0", PYTHONCOERCECLOCALE="0",
                     PYTHONPATH=os.path.dirname(macalias.__file__))
    code = ("import json, locale, sys, macalias; "
            "print(json.dumps({'encoding': locale.getencoding(), "
            "'status': macalias.cmd_status(json.loads(sys.argv[1]), 1060.0)}))")
    proc = subprocess.run([sys.executable, "-c", code, json.dumps(cfg)],
                          capture_output=True, text=True, env=child_env, timeout=30)
    assert proc.returncode == 0, proc.stderr
    reply = json.loads(proc.stdout)
    if reply["encoding"].lower().replace("-", "") == "utf8":
        pytest.skip("no Latin-1 locale on this host")
    assert reply["status"]["last_flush"]["summary"] == [row]


def test_refusal_takes_the_first_class_and_carries_every_problem(env):
    note = {"item": "cache_file", "problem": "n", "blocks_flush": False}
    lock = {"item": "lock_file", "problem": "a", "blocks_flush": True}
    state = {"item": "state_dir", "problem": "b", "blocks_flush": True}
    assert macalias.refusal([]) is None
    assert macalias.refusal([note]) is None
    assert macalias.refusal([lock, note]) == {"error": "lock_unusable", "detail": "a", "problems": [lock, note]}
    assert macalias.refusal([lock, note, state]) == {
        "error": "state_unusable", "detail": "a; b", "problems": [lock, note, state]}

    cfg, tmp = env
    (tmp / "lock-target").write_text("")
    os.symlink(tmp / "lock-target", cfg["lock_file"])
    (tmp / "arp.cache").unlink()
    (tmp / "arp.cache").mkdir()
    out = _flush(cfg)
    assert out["error"] == "state_unusable"
    assert [p["item"] for p in out["problems"]] == ["lock_file", "cache_file"]
    assert out["detail"] == "%s; %s" % (LOCK_NOT_REGULAR % cfg["lock_file"], CACHE_DIRECTORY % cfg["cache_file"])
    assert not (tmp / "update_args").exists()


def _plugin_lock_free(cfg):
    with open(macalias.state_paths(cfg)["plugin_lock"], "a") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)  # raises BlockingIOError while held


def test_flush_busy_at_once_when_plugin_lock_held(env):
    cfg, tmp = env
    os.makedirs(cfg["state_dir"], 0o700, exist_ok=True)
    slept = []
    before = _snapshot(tmp)
    with open(macalias.state_paths(cfg)["plugin_lock"], "a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=slept.append)
    assert out == {"error": "busy", "detail": "another flush is running"}
    assert slept == []
    assert _snapshot(tmp) == before
    assert not (tmp / "update_args").exists()


def test_concurrent_flush_runs_one_rebuild(env, monkeypatch):
    # the second request arrives while the first is rebuilding; update_tables is a shell
    # script and cannot call back, so the nested flush starts from the first pf_set read
    cfg, tmp = env
    real_pf_set = macalias.pf_set
    nested = []

    def fake_pf_set(cfg_, name):
        if not nested:
            nested.append(macalias.cmd_flush(cfg_, clock=lambda: 5000.0, sleep=lambda s: pytest.fail("waited")))
        return real_pf_set(cfg_, name)

    monkeypatch.setattr(macalias, "pf_set", fake_pf_set)
    out = _flush(cfg)
    assert "error" not in out
    assert nested == [{"error": "busy", "detail": "another flush is running"}]
    assert (tmp / "update_args").read_text().strip().splitlines() == ["--aliases DevMacs,Parent"]


@pytest.mark.parametrize("kind", ["directory", "symlink", "fifo", "hard-link"])
def test_flush_refuses_when_plugin_lock_is_not_a_regular_file(env, kind):
    # status names the flush lock too, so the page still shows why after the refusal's own text is gone
    cfg, tmp = env
    os.makedirs(cfg["state_dir"], 0o700, exist_ok=True)
    path = macalias.state_paths(cfg)["plugin_lock"]
    elsewhere = tmp / "elsewhere"
    elsewhere.write_text("")
    if kind == "directory":
        os.mkdir(path)
    elif kind == "symlink":
        os.symlink(elsewhere, path)
    elif kind == "fifo":
        os.mkfifo(path, 0o600)
    else:
        os.link(elsewhere, path)
    with _within(5):
        status = macalias.cmd_status(cfg, now=0.0)
        before = _snapshot(tmp)
        out = _flush(cfg)
    assert _items(status, "plugin_lock") == [
        {"item": "plugin_lock", "problem": PLUGIN_LOCK_NOT_REGULAR % path, "blocks_flush": True}]
    problem = {"item": "plugin_lock", "problem": PLUGIN_LOCK_UNUSABLE % path, "blocks_flush": True}
    assert out == {"error": "state_unusable", "detail": problem["problem"], "problems": [problem]}
    _unchanged(tmp, cfg, before)


def test_status_accepts_an_absent_or_regular_plugin_lock(env):
    cfg, tmp = env
    assert _items(macalias.cmd_status(cfg, now=0.0), "plugin_lock") == []
    assert "error" not in _flush(cfg)
    assert os.path.isfile(macalias.state_paths(cfg)["plugin_lock"])
    assert _items(macalias.cmd_status(cfg, now=0.0), "plugin_lock") == []


@pytest.mark.parametrize("case", ["success", "too_soon", "hosts_unavailable", "state_unusable", "update_oserror"])
def test_flush_releases_plugin_lock_after_every_exit(env, case):
    cfg, tmp = env
    if case == "too_soon":
        _write_last(cfg, {"at": 4995.0, "summary": []})
    elif case == "hosts_unavailable":
        cfg["list_hosts"] = [_exe(tmp / "broken_hosts", "exit 1\n"), "-n"]
    elif case == "state_unusable":
        os.makedirs(cfg["state_dir"], 0o700, exist_ok=True)
        os.mkdir(macalias.state_paths(cfg)["last_file"])
    elif case == "update_oserror":
        cfg["update_tables"] = str(tmp / "missing_update_tables")   # exec raises OSError
    out = _flush(cfg)
    if case == "success":
        assert "error" not in out
    elif case == "update_oserror":
        assert out["update_tables"]["rc"] is None
    else:
        assert out["error"] == case
    _plugin_lock_free(cfg)
    with open(cfg["lock_file"], "a") as fh:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)


def test_flush_releases_plugin_lock_when_a_read_raises(env, monkeypatch):
    cfg, tmp = env

    def broken_pf_set(cfg_, name):
        raise OSError("pfctl cannot start")

    monkeypatch.setattr(macalias, "pf_set", broken_pf_set)
    with pytest.raises(OSError):
        _flush(cfg)
    _plugin_lock_free(cfg)


def test_flush_releases_plugin_lock_when_core_lock_times_out(env):
    cfg, tmp = env
    with open(cfg["lock_file"], "a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        out = _flush(cfg)
    assert out["error"] == "busy" and "alias update lock held" in out["detail"]
    _plugin_lock_free(cfg)


def test_flush_frees_the_plugin_lock_when_core_lock_release_raises(env, monkeypatch):
    cfg, tmp = env
    real_flock = fcntl.flock
    unlocks = []

    def flock(handle, op):
        # the first release is core's lock; the plugin lock's must still happen
        if op == fcntl.LOCK_UN:
            unlocks.append(handle)
            if len(unlocks) == 1:
                raise OSError(errno.EIO, "unlock failed")
        return real_flock(handle, op)

    monkeypatch.setattr(macalias.fcntl, "flock", flock)
    with pytest.raises(OSError):
        _flush(cfg)
    monkeypatch.undo()
    assert len(unlocks) == 2
    _plugin_lock_free(cfg)


@pytest.mark.parametrize("which", ["plugin_lock", "lock_file"])
def test_lock_handle_is_closed_when_flock_fails_unexpectedly(env, monkeypatch, which):
    cfg, tmp = env
    os.makedirs(cfg["state_dir"], 0o700, exist_ok=True)
    opened = []
    real_fdopen = os.fdopen

    def fdopen(fd, mode):
        handle = real_fdopen(fd, mode)
        opened.append(handle)
        return handle

    def flock(handle, op):
        raise OSError(errno.EIO, "flock failed")

    monkeypatch.setattr(macalias.os, "fdopen", fdopen)
    monkeypatch.setattr(macalias.fcntl, "flock", flock)
    with pytest.raises(OSError):
        if which == "plugin_lock":
            macalias.acquire_plugin_lock(cfg)
        else:
            macalias.acquire_lock(cfg, lambda s: None)
    assert len(opened) == 1 and opened[0].closed


def test_core_lock_handle_is_closed_when_the_retry_sleep_raises(env, monkeypatch):
    cfg, tmp = env
    opened = []
    real_fdopen = os.fdopen

    def fdopen(fd, mode):
        handle = real_fdopen(fd, mode)
        opened.append(handle)
        return handle

    def sleep(_):
        raise KeyboardInterrupt

    monkeypatch.setattr(macalias.os, "fdopen", fdopen)
    with open(cfg["lock_file"], "a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        with pytest.raises(KeyboardInterrupt):
            macalias.acquire_lock(cfg, sleep)
    assert len(opened) == 1 and opened[0].closed


@pytest.mark.parametrize("which", ["plugin_lock", "lock_file", "read"])
def test_descriptor_is_closed_when_fdopen_fails(env, monkeypatch, which):
    cfg, tmp = env
    os.makedirs(cfg["state_dir"], 0o700, exist_ok=True)
    fds = []
    real_open = os.open

    def tracking_open(*args, **kwargs):
        fd = real_open(*args, **kwargs)
        fds.append(fd)
        return fd

    def failing_fdopen(*args, **kwargs):
        raise MemoryError

    monkeypatch.setattr(macalias.os, "open", tracking_open)
    monkeypatch.setattr(macalias.os, "fdopen", failing_fdopen)
    with pytest.raises(MemoryError):
        if which == "plugin_lock":
            macalias.acquire_plugin_lock(cfg)
        elif which == "lock_file":
            macalias.acquire_lock(cfg, lambda s: None)
        else:
            macalias._open_regular(cfg["tables_conf"])
    assert len(fds) == 1
    with pytest.raises(OSError):
        os.fstat(fds[0])   # EBADF: closed


def test_failed_fdopen_that_closed_the_descriptor_itself_surfaces_its_own_error(env, monkeypatch):
    cfg, tmp = env

    def self_closing_fdopen(fd, *args, **kwargs):
        os.close(fd)
        raise MemoryError

    monkeypatch.setattr(macalias.os, "fdopen", self_closing_fdopen)
    with pytest.raises(MemoryError):
        macalias._open_regular(cfg["tables_conf"])


def _list_hosts(cfg, tmp, rows):
    """ list_hosts prints rows from a file, so a row may hold any text """
    listing = tmp / "listing.json"
    listing.write_text(json.dumps({"source": "discovery", "rows": rows}))
    cfg["list_hosts"] = [_exe(tmp / "listed_hosts", 'cat "%s"\n' % listing), "-n"]


def _core(cfg, item):
    return pathlib.Path(cfg["core_files"][item])


def _unchanged(tmp, cfg, before):
    """ nothing a flush writes was written: core's cache, the .md5.txt marks, update_tables, last.json """
    assert _snapshot(tmp) == before
    assert not (tmp / "update_args").exists()
    assert not _last(cfg).exists()


@pytest.mark.parametrize("row", [
    ["vlan0.10", "laptop.lan", "aa:bb:cc:00:00:01"],
    ["vlan0.120", "aa:bb:cc:00:00:01"],
], ids=["columns-swapped", "only-short-rows"])
def test_flush_refuses_when_all_rows_malformed(env, row):
    cfg, tmp = env
    _list_hosts(cfg, tmp, [row])
    before = _snapshot(tmp)
    out = _flush(cfg)
    assert out == {
        "error": "hosts_malformed",
        "detail": "1 host rows, none with a MAC and an address in the expected columns; nothing changed",
        "rejected": [repr(row)],
    }
    _unchanged(tmp, cfg, before)


def test_flush_refuses_when_all_rows_malformed_counts_every_row(env):
    cfg, tmp = env
    rows = [["vlan0.10", "laptop-%d.lan" % n, "aa:bb:cc:00:00:01"] for n in range(7)]
    _list_hosts(cfg, tmp, rows)
    out = _flush(cfg)
    assert out["error"] == "hosts_malformed"
    assert out["detail"].startswith("7 host rows, none with")
    assert out["rejected"] == [repr(row) for row in rows[:5]]


def test_flush_drops_malformed_rows_and_reports_count(env):
    cfg, tmp = env
    hostname_row = ["vlan0.10", "aa:bb:cc:00:00:01", "laptop.lan"]
    _list_hosts(cfg, tmp, [["vlan0.10", "aa:bb:cc:00:00:01", "192.0.2.50"], hostname_row])
    out = _flush(cfg)
    assert "error" not in out
    assert json.loads((tmp / "arp.cache").read_text()) == {
        "aa:bb:cc:00:00:01": {"items": ["192.0.2.50"], "last_seen": 5000.0}}
    assert out["rows_rejected"] == 1
    assert out["rejected"] == [repr(hostname_row)]


def test_clean_flush_reports_no_rejected_rows(env):
    cfg, tmp = env
    out = _flush(cfg)
    assert out["rows_rejected"] == 0 and out["rejected"] == []


def test_flush_with_only_link_local_rows_seeds_them(env):
    # (r8) host discovery may be IPv6-heavy on a segment; unzoned link-local rows are real devices
    cfg, tmp = env
    _list_hosts(cfg, tmp, [["vlan0.10", "aa:bb:cc:00:00:01", "fe80::5"], ["vlan0.10", "aa:bb:cc:00:00:01", "fe80::6"]])
    out = _flush(cfg)
    assert "error" not in out
    assert out["rows_rejected"] == 0
    assert json.loads((tmp / "arp.cache").read_text()) == {
        "aa:bb:cc:00:00:01": {"items": ["fe80::5", "fe80::6"], "last_seen": 5000.0}}
    assert (tmp / "update_args").read_text().split() == ["--aliases", "DevMacs,Parent"]


def test_status_shows_only_checked_rows(env):
    cfg, tmp = env
    _list_hosts(cfg, tmp, [["vlan0.10", None, "192.0.2.60"], ["vlan0.10", "aa:bb:cc:00:00:01", "laptop.lan"],
                           ["vlan0.10", "aa:bb:cc:00:00:01", "192.0.2.50"]])
    out = macalias.cmd_status(cfg, now=0.0)
    assert out["aliases"][0]["macs"][0]["current_items"] == ["192.0.2.50"]


def test_core_files_are_the_files_the_flush_imitates_and_runs():
    core = macalias.DEFAULTS["core_files"]
    assert core == {item: "/usr/local/opnsense/" + path for item, path in CORE_FILES.items()}
    # the contract checks the very programs the flush runs
    assert macalias.DEFAULTS["list_hosts"] == [core["list_hosts"], "-n"]
    assert macalias.DEFAULTS["update_tables"] == core["targeted_mode"]
    # and core's texts it expects are the paths the plugin writes, locks and marks
    assert macalias.DEFAULTS["cache_file"] == "/tmp/alias_filter_arp.cache"
    assert macalias.DEFAULTS["lock_file"] == "/tmp/filter_update_tables.lock"
    assert macalias.DEFAULTS["aliastables_dir"] == "/var/db/aliastables"
    expected = {item: texts for item, _path, texts, _note in lib.CORE_CONTRACT}
    assert macalias.DEFAULTS["cache_file"] in expected["arpcache"]
    assert macalias.DEFAULTS["lock_file"] in expected["update_lock"]
    assert os.path.join(macalias.DEFAULTS["aliastables_dir"], "%s.md5.txt") in expected["md5_marker"]


def test_stock_core_files_give_no_problem(env):
    # (c7) the fixtures hold 26.7.7's own lines, so a stock box raises no problem
    cfg, tmp = env
    texts = macalias.read_core_texts(cfg)
    assert set(texts) == set(CORE_FILES)
    assert texts["list_hosts"] == "exists"
    assert None not in texts.values()
    assert lib.core_contract(texts) == []
    assert macalias.cmd_status(cfg, now=0.0)["problems"] == []


def test_read_core_texts_replaces_undecodable_bytes(env):
    cfg, tmp = env
    with open(_core(cfg, "targeted_mode"), "ab") as f:
        f.write(b"# \xff\xfe\n")
    texts = macalias.read_core_texts(cfg)
    assert "�" in texts["targeted_mode"] and "--aliases" in texts["targeted_mode"]
    assert macalias.cmd_status(cfg, now=0.0)["problems"] == []


@pytest.mark.parametrize("change", ["drift", "md5-directory-moved", "missing", "symlink", "not-executable", "directory"])
def test_flush_refuses_on_blocking_contract_problem(env, change):
    cfg, tmp = env
    item = {"not-executable": "list_hosts", "md5-directory-moved": "md5_marker"}.get(change, "arpcache")
    path = _core(cfg, item)
    if change == "drift":
        path.write_text(path.read_text().replace("/tmp/alias_filter_arp.cache", "/var/cache/alias_filter_arp.cache"))
    elif change == "md5-directory-moved":
        path.write_text(path.read_text().replace("/var/db/aliastables/", "/var/db/aliases/"))
    elif change == "missing":
        path.unlink()
    elif change == "symlink":
        path.rename(tmp / "arpcache.real")
        os.symlink(tmp / "arpcache.real", path)
    elif change == "not-executable":
        path.chmod(0o644)
    else:
        path.unlink()
        path.mkdir()
    before = _snapshot(tmp)
    out = _flush(cfg)
    assert out["error"] == "core_changed"
    assert [p["item"] for p in out["problems"]] == [item]
    assert out["problems"][0]["blocks_flush"] is True
    assert out["detail"] == out["problems"][0]["problem"]
    _unchanged(tmp, cfg, before)


def test_flush_refuses_when_update_tables_is_missing(env):
    # the same file holds the targeted-mode and the emptied-table texts: only the blocking item is listed
    cfg, tmp = env
    _core(cfg, "targeted_mode").unlink()
    before = _snapshot(tmp)
    out = _flush(cfg)
    assert out["error"] == "core_changed"
    assert [p["item"] for p in out["problems"]] == ["targeted_mode"]
    _unchanged(tmp, cfg, before)


def test_flush_runs_on_non_blocking_contract_note(env):
    cfg, tmp = env
    path = _core(cfg, "emptied_table")
    path.write_text(path.read_text().replace("else cnt_alias_content", "else alias.get_pf_addr_count()"))
    out = _flush(cfg)
    assert "error" not in out
    assert (tmp / "update_args").read_text().split() == ["--aliases", "DevMacs,Parent"]
    assert macalias.cmd_status(cfg, now=0.0)["problems"] == [
        {"item": "emptied_table", "problem": EMPTIED_NOTE, "blocks_flush": False}]


BAD_NAME_TABLES = """<?xml version="1.0"?>
<tabledef>
  <table><name>DevMacs</name><type>mac</type><address>aa:bb:cc:00:00:01</address><ttl>30</ttl></table>
  <table><name>Dev Macs</name><type>mac</type><address>aa:bb:cc:00:00:02</address><ttl>30</ttl></table>
  <table><name>Parent</name><type>host</type><address>DevMacs
Dev Macs</address><ttl>300</ttl></table>
</tabledef>
"""
ALIAS_NAME = ("alias names that do not match core's alias name pattern: %s; "
              "the flush would use them in a file path and as a pfctl table name")


def _record_pf_set(monkeypatch):
    names = []
    real_pf_set = macalias.pf_set

    def pf_set(cfg_, name):
        names.append(name)
        return real_pf_set(cfg_, name)

    monkeypatch.setattr(macalias, "pf_set", pf_set)
    return names


def test_flush_refuses_on_bad_alias_name(env, monkeypatch):
    cfg, tmp = env
    (tmp / "filter_tables.conf").write_text(BAD_NAME_TABLES)
    pf_names = _record_pf_set(monkeypatch)
    before = _snapshot(tmp)
    out = _flush(cfg)
    problem = {"item": "alias_name", "problem": ALIAS_NAME % "'Dev Macs'", "blocks_flush": True}
    assert out == {"error": "core_changed", "detail": problem["problem"], "problems": [problem]}
    assert pf_names == []
    _unchanged(tmp, cfg, before)


def test_status_never_passes_a_bad_alias_name_to_pfctl(env, monkeypatch):
    cfg, tmp = env
    (tmp / "filter_tables.conf").write_text(BAD_NAME_TABLES)
    pf_names = _record_pf_set(monkeypatch)
    out = macalias.cmd_status(cfg, now=0.0)
    assert pf_names == ["DevMacs"]
    assert {row["name"]: row["pf_count"] for row in out["aliases"]} == {"Dev Macs": None, "DevMacs": 2}
    assert _items(out, "alias_name") == [
        {"item": "alias_name", "problem": ALIAS_NAME % "'Dev Macs'", "blocks_flush": True}]


INTERNAL_TABLE = "<table><name>__lan_network</name><type>network</type><address>%s</address></table>"


def test_alias_name_checks_the_refresh_set_only(env):
    # (n3) core's own internal tables (__lan_network and the like) fail the pattern, and are no
    # concern of the flush until one nests a mac alias and so joins the refresh set
    cfg, tmp = env
    conf = tmp / "filter_tables.conf"
    conf.write_text(TABLES.replace("</tabledef>", INTERNAL_TABLE % "192.0.2.0/24" + "\n</tabledef>"))
    assert _items(macalias.cmd_status(cfg, now=0.0), "alias_name") == []
    assert "error" not in _flush(cfg)

    conf.write_text(TABLES.replace("</tabledef>", INTERNAL_TABLE % "DevMacs" + "\n</tabledef>"))
    problem = {"item": "alias_name", "problem": ALIAS_NAME % "'__lan_network'", "blocks_flush": True}
    assert _items(macalias.cmd_status(cfg, now=0.0), "alias_name") == [problem]
    refused = macalias.cmd_flush(cfg, clock=lambda: 6000.0, sleep=lambda s: None)
    assert refused == {"error": "core_changed", "detail": problem["problem"], "problems": [problem]}


def test_flush_reads_filter_tables_once(env, monkeypatch):
    # the names the problem list checks are the names the flush then uses
    cfg, tmp = env
    reads = []
    real_read_tables = macalias.read_tables

    def read_tables(cfg_):
        reads.append(cfg_["tables_conf"])
        return real_read_tables(cfg_)

    monkeypatch.setattr(macalias, "read_tables", read_tables)
    assert "error" not in _flush(cfg)
    assert reads == [cfg["tables_conf"]]


def test_status_lists_problems(env):
    cfg, tmp = env
    pathlib.Path(cfg["state_dir"]).write_text("x")
    os.mkfifo(cfg["lock_file"])
    (tmp / "arp.cache").rename(tmp / "real.cache")
    os.symlink(tmp / "real.cache", tmp / "arp.cache")
    (tmp / "filter_tables.conf").write_text(BAD_NAME_TABLES)
    arpcache = _core(cfg, "arpcache")
    arpcache.write_text(arpcache.read_text().replace("/tmp/alias_filter_arp.cache", "/var/cache/alias_filter_arp.cache"))
    update_tables = _core(cfg, "emptied_table")
    update_tables.write_text(update_tables.read_text().replace("else cnt_alias_content", "else alias.get_pf_addr_count()"))
    with _within(5):
        out = macalias.cmd_status(cfg, now=0.0)
    assert "error" not in out
    assert [(p["item"], p["blocks_flush"]) for p in out["problems"]] == [
        ("state_dir", True), ("lock_file", True), ("cache_file", False), ("alias_name", True), ("arpcache", True),
        ("emptied_table", False)]
    assert _items(out, "cache_file")[0]["problem"] == CACHE_FORGED % cfg["cache_file"]
    assert _items(out, "alias_name")[0]["problem"] == ALIAS_NAME % "'Dev Macs'"
    assert _items(out, "emptied_table")[0]["problem"] == EMPTIED_NOTE

    # with the state directory usable, what is inside it is listed too
    pathlib.Path(cfg["state_dir"]).unlink()
    os.mkdir(cfg["state_dir"], 0o700)
    os.mkdir(macalias.state_paths(cfg)["plugin_lock"])
    with _within(5):
        out = macalias.cmd_status(cfg, now=0.0)
    assert [(p["item"], p["blocks_flush"]) for p in out["problems"]] == [
        ("plugin_lock", True), ("lock_file", True), ("cache_file", False), ("alias_name", True), ("arpcache", True),
        ("emptied_table", False)]
    os.rmdir(macalias.state_paths(cfg)["plugin_lock"])

    # a flush refuses with the first class that blocks and carries every problem
    with _within(5):
        out = _flush(cfg)
    assert out["error"] == "lock_unusable"
    assert [p["item"] for p in out["problems"]] == ["lock_file", "cache_file", "alias_name", "arpcache", "emptied_table"]
    os.unlink(cfg["lock_file"])
    out = _flush(cfg)
    assert out["error"] == "core_changed"
    blocking = [p["problem"] for p in out["problems"] if p["blocks_flush"]]
    assert [p["item"] for p in out["problems"] if p["blocks_flush"]] == ["alias_name", "arpcache"]
    assert out["detail"] == "; ".join(blocking)
    assert not (tmp / "update_args").exists()


@pytest.mark.parametrize("item, code", [
    ("last_file", "state_unusable"), ("plugin_lock", "state_unusable"), ("lock_file", "lock_unusable"),
    ("cache_file", "state_unusable")])
def test_lstat_error_other_than_absent_blocks(env, monkeypatch, item, code):
    # a path that cannot even be looked at is not taken for absent
    cfg, tmp = env
    os.mkdir(cfg["state_dir"], 0o700)
    path = macalias.state_paths(cfg)[item] if item in ("last_file", "plugin_lock") else cfg[item]
    real_lstat = os.lstat

    def lstat(arg, *args, **kwargs):
        if os.fspath(arg) == path:
            raise OSError(errno.EACCES, os.strerror(errno.EACCES), arg)
        return real_lstat(arg, *args, **kwargs)

    monkeypatch.setattr(macalias.os, "lstat", lstat)
    problem = {"item": item, "problem": CANNOT_CHECK[item] % (path, os.strerror(errno.EACCES)), "blocks_flush": True}
    assert _items(macalias.cmd_status(cfg, now=0.0), item) == [problem]
    before = _snapshot(tmp)
    out = _flush(cfg)
    assert out == {"error": code, "detail": problem["problem"], "problems": [problem]}
    _unchanged(tmp, cfg, before)


def test_every_problem_item_has_a_refusal_code(env):
    # the items, driven from the module's one table of them, are each produced by some case
    # below and each has a code; the autouse check holds every other case to the same table
    cfg, tmp = env
    seen = set()
    os.mkdir(cfg["state_dir"], 0o700)
    _last(cfg).mkdir()
    os.mkdir(macalias.state_paths(cfg)["plugin_lock"])
    os.mkfifo(cfg["lock_file"])
    (tmp / "arp.cache").unlink()
    (tmp / "arp.cache").mkdir()
    (tmp / "filter_tables.conf").write_text(BAD_NAME_TABLES)
    shutil.rmtree(tmp / "core")
    with _within(5):
        seen.update(p["item"] for p in macalias.problems(cfg))
    _last(cfg).rmdir()
    os.rmdir(macalias.state_paths(cfg)["plugin_lock"])
    os.rmdir(cfg["state_dir"])
    pathlib.Path(cfg["state_dir"]).write_text("x")
    shutil.copytree(FIXTURES, tmp / "core")
    update_tables = _core(cfg, "emptied_table")
    update_tables.write_text(update_tables.read_text().replace("else cnt_alias_content", ""))
    with _within(5):
        seen.update(p["item"] for p in macalias.problems(cfg))
    assert seen == set(macalias._REFUSAL_CODE)
    for item, code in macalias._REFUSAL_CODE.items():
        assert code in ("state_unusable", "lock_unusable", "core_changed"), item
        assert macalias.refusal([{"item": item, "problem": "p", "blocks_flush": True}])["error"] == code
    assert {item for item, code in macalias._REFUSAL_CODE.items() if code == "state_unusable"} == {
        "state_dir", "last_file", "plugin_lock", "cache_file"}
    assert {item for item, code in macalias._REFUSAL_CODE.items() if code == "core_changed"} == {
        "alias_name", "arpcache", "update_lock", "md5_marker", "targeted_mode", "emptied_table", "list_hosts"}


@pytest.fixture
def logged(monkeypatch):
    """ the (priority, message) pairs passed to syslog, and the idents passed to openlog """
    lines, idents = [], []
    monkeypatch.setattr(macalias.syslog, "openlog", lambda ident, *args, **kwargs: idents.append(ident))
    monkeypatch.setattr(macalias.syslog, "syslog", lambda priority, message: lines.append((priority, message)))
    return lines, idents


def _refuse_state_unusable(cfg, tmp):
    elsewhere = tmp / "elsewhere"
    elsewhere.mkdir(mode=0o700)
    os.symlink(elsewhere, cfg["state_dir"])


def _refuse_lock_unusable(cfg, tmp):
    target = tmp / "lock-target"
    target.write_text("")
    os.symlink(target, cfg["lock_file"])


def _refuse_core_changed(cfg, tmp):
    _core(cfg, "targeted_mode").unlink()


def _refuse_hosts_malformed(cfg, tmp):
    _list_hosts(cfg, tmp, [["vlan0.10", "laptop.lan", "aa:bb:cc:00:00:01"]])


def _quiet_busy(cfg, tmp):
    held = open(cfg["lock_file"], "a")
    fcntl.flock(held, fcntl.LOCK_EX)
    return held


def _quiet_too_soon(cfg, tmp):
    _write_last(cfg, {"at": 4995.0, "summary": []})


def _quiet_hosts_unavailable(cfg, tmp):
    cfg["list_hosts"] = [_exe(tmp / "bad_hosts", "exit 1\n"), "-n"]


@pytest.mark.parametrize("setup, code", [
    (_refuse_state_unusable, "state_unusable"), (_refuse_lock_unusable, "lock_unusable"),
    (_refuse_core_changed, "core_changed"), (_refuse_hosts_malformed, "hosts_malformed")])
def test_refusal_logs_one_warning(env, logged, setup, code):
    cfg, tmp = env
    lines, idents = logged
    setup(cfg, tmp)
    out = _flush(cfg)
    assert out["error"] == code
    assert lines == [(macalias.syslog.LOG_WARNING, "%s: %s" % (code, out["detail"]))]
    assert idents == ["macaliascache"]


def test_refusal_logs_one_warning_for_a_flush_that_dropped_rows(env, logged):
    cfg, tmp = env
    lines, idents = logged
    short = ["vlan0.120", "aa:bb:cc:00:00:02"]
    _list_hosts(cfg, tmp, [["vlan0.120", "aa:bb:cc:00:00:01", "192.0.2.50"], short])
    out = _flush(cfg)
    assert "error" not in out and out["rows_rejected"] == 1
    assert [priority for priority, _ in lines] == [macalias.syslog.LOG_WARNING]
    assert lines[0][1].startswith("rows_rejected: 1 ") and repr(short) in lines[0][1]
    assert len(lines[0][1]) < 400
    assert idents == ["macaliascache"]


@pytest.mark.parametrize("setup", [_quiet_busy, _quiet_too_soon, _quiet_hosts_unavailable],
                         ids=["busy", "too_soon", "hosts_unavailable"])
def test_quiet_refusals_log_nothing(env, logged, setup):
    cfg, tmp = env
    held = setup(cfg, tmp)
    out = _flush(cfg)
    if held:
        held.close()
    assert out["error"] in ("busy", "too_soon", "hosts_unavailable")
    assert logged[0] == []


def test_clean_flush_logs_nothing(env, logged):
    cfg, tmp = env
    out = _flush(cfg)
    assert "error" not in out and out["rows_rejected"] == 0
    assert logged[0] == []


@pytest.mark.parametrize("failing", ["openlog", "syslog"])
def test_syslog_failure_never_changes_the_reply(env, monkeypatch, failing):
    cfg, tmp = env
    _refuse_core_changed(cfg, tmp)
    expected = _flush(cfg)

    def broken(*args, **kwargs):
        raise OSError("no syslog socket")

    monkeypatch.setattr(macalias.syslog, failing, broken)
    assert _flush(cfg) == expected
    assert expected["error"] == "core_changed"


def test_a_line_that_cannot_be_built_never_changes_the_reply(env, logged, monkeypatch):
    # the samples are joined into the line, which raises on an item that is not text
    cfg, tmp = env
    reply = {"summary": [], "rows_rejected": 1, "rejected": [("vlan0.120", "aa:bb:cc:00:00:02")]}
    monkeypatch.setattr(macalias, "_flush", lambda cfg_, clock, sleep: reply)
    assert _flush(cfg) is reply
    assert logged[0] == []


def test_status_never_logs_even_with_blocking_problems(env, logged):
    cfg, tmp = env
    pathlib.Path(cfg["state_dir"]).write_text("x")
    os.mkfifo(cfg["lock_file"])
    (tmp / "arp.cache").rename(tmp / "real.cache")
    os.symlink(tmp / "real.cache", tmp / "arp.cache")
    (tmp / "filter_tables.conf").write_text(BAD_NAME_TABLES)
    arpcache = _core(cfg, "arpcache")
    arpcache.write_text(arpcache.read_text().replace("/tmp/alias_filter_arp.cache", "/var/cache/alias_filter_arp.cache"))
    with _within(5):
        out = macalias.cmd_status(cfg, now=0.0)
    assert any(p["blocks_flush"] for p in out["problems"])
    assert logged == ([], [])
