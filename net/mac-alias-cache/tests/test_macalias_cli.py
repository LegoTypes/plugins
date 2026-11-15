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

# the core files the flush imitates, reads core's fixes from or the neighbor keys rely on, relative to
# /usr/local/opnsense; the fixtures mirror them
CORE_FILES = {
    "arpcache": "scripts/filter/lib/alias/arpcache.py",
    "cache_expiry": "scripts/filter/lib/alias/arpcache.py",
    "neighbor_merge": "scripts/filter/lib/alias/arpcache.py",
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
    # the neighbor table and the plugin's settings file are fixtures too, or a case would run the workstation's
    # own ndp and read its files: an empty table, and the setting as the template renders its default
    (tmp_path / "ndp.json").write_text(json.dumps({"ndp": {"neighbor-cache": []}}))
    ndp = _exe(tmp_path / "ndp", f"""
        echo "$@" >> "{tmp_path}/ndp_args"
        cat "{tmp_path}/ndp.json"
    """)
    (tmp_path / "macaliascache.conf").write_text("[general]\nneighbors=1\n")
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
        ndp=[ndp, "-an", "--libxo", "json"],
        settings_file=str(tmp_path / "macaliascache.conf"),
        lock_timeout=0.5,
        lock_retry=0.05,
        neighbors_lock_timeout=0.2,
        core_files={item: str(tmp_path / "core" / path) for item, path in CORE_FILES.items()},
    )
    return cfg, tmp_path


@pytest.fixture(autouse=True)
def problems_name_only_mapped_items():
    """ every problem any case here produces or refuses with names an item that has a refusal
    code, so an item added without one fails here instead of raising KeyError in a flush; or it
    names an advisory item, which has no code and must never block
    """
    real_problems, real_refusal = macalias.problems, macalias.refusal
    real_neighbors_refusal = getattr(macalias, "neighbors_refusal", None)
    # the previous release, which these cases also run against, has no advisory item
    advisory = getattr(macalias, "_ADVISORY_ITEMS", ())

    def check(found):
        unmapped = [problem["item"] for problem in found
                    if problem["item"] not in macalias._REFUSAL_CODE and problem["item"] not in advisory]
        assert unmapped == [], found
        assert [problem for problem in found if problem["item"] in advisory and problem["blocks_flush"]] == [], found

    def problems(*args, **kwargs):
        found = real_problems(*args, **kwargs)
        check(found)
        return found

    def refusal(found):
        check(found)
        return real_refusal(found)

    def neighbors_refusal(found, *args, **kwargs):
        check(found)
        return real_neighbors_refusal(found, *args, **kwargs)

    # a separate MonkeyPatch, so a case's own monkeypatch.undo() leaves this in place
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(macalias, "problems", problems)
        patch.setattr(macalias, "refusal", refusal)
        if real_neighbors_refusal is not None:
            patch.setattr(macalias, "neighbors_refusal", neighbors_refusal)
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


UPDATE_OK = {"rc": 0, "output": '{"status": "ok"}', "status": "ok", "messages": [], "complete": True}


def _emptying_update(tmp, name, last_line):
    """ an update_tables.py that leaves both alias files empty, as core does between opening a file
    and writing it, then runs last_line
    """
    return _exe(tmp / name, f"""
        echo "$@" >> "{tmp}/update_args"
        : > "{tmp}/aliastables/DevMacs.txt"
        : > "{tmp}/aliastables/Parent.txt"
        {last_line}
    """)


def _pf_untouched(tmp):
    """ no pf table was flushed, and both still hold what the fixture put there """
    return (not (tmp / "pfctl_flush_args").exists()
            and (tmp / "pf" / "DevMacs").read_text() == "192.0.2.50\n192.0.2.99\n"
            and (tmp / "pf" / "Parent").read_text() == "192.0.2.50\n192.0.2.99\n")


def test_flush_reply_carries_cores_status_and_messages(env):
    cfg, tmp = env
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert out["update_tables"] == UPDATE_OK


def test_flush_keeps_the_tables_an_update_that_crashed_left_empty(env):
    # core truncates an alias file when it opens it and writes it afterwards: a run that ends in
    # between leaves the file empty while the alias is not, so its pf table must keep its addresses
    cfg, tmp = env
    cfg["update_tables"] = _emptying_update(tmp, "crashing_update", "exit 3")
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert out["emptied"] == []
    assert _pf_untouched(tmp)
    assert out["update_tables"] == {"rc": 3, "output": "", "status": None, "messages": [], "complete": False}


def test_flush_keeps_the_tables_an_update_killed_at_the_timeout_left_empty(env):
    cfg, tmp = env
    cfg["update_tables"] = _emptying_update(tmp, "hanging_update", "exec sleep 30")
    cfg["update_timeout"] = 1
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert out["emptied"] == []
    assert _pf_untouched(tmp)
    assert out["update_tables"] == {
        "rc": None, "output": "timeout after 1s", "status": None, "messages": [], "complete": False}


@pytest.mark.parametrize("last_line, output", [
    (":", ""),
    ("echo done", "done"),
    ("echo '[\"ok\"]'", '["ok"]'),
    ("echo '{\"status\": 1}'", '{"status": 1}'),
    ("echo '{\"messages\": [\"x\"]}'", '{"messages": ["x"]}'),
], ids=["nothing", "text", "json-list", "status-not-a-string", "no-status"])
def test_flush_keeps_the_tables_an_update_without_a_reply_left_empty(env, last_line, output):
    # exit status 0 alone does not say the run reached its end: core exits 0 early, printing nothing,
    # when no alias is selected
    cfg, tmp = env
    cfg["update_tables"] = _emptying_update(tmp, "silent_update", last_line)
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert out["emptied"] == []
    assert _pf_untouched(tmp)
    assert out["update_tables"] == {"rc": 0, "output": output, "status": None, "messages": [], "complete": False}


def test_flush_carries_cores_error_and_still_flushes_the_emptied_tables(env):
    # the run reached its end and answered, so its files are whole and the emptied aliases are
    # truly empty; the error is about loading another alias's table
    cfg, tmp = env
    reply = '{"status": "error", "messages": ["Error loading alias [Other]: x"]}'
    cfg["update_tables"] = _emptying_update(tmp, "error_update", "echo '%s'" % reply)
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert out["update_tables"] == {"rc": 0, "output": reply, "status": "error",
                                    "messages": ["Error loading alias [Other]: x"], "complete": True}
    assert out["emptied"] == ["DevMacs", "Parent"]
    assert (tmp / "pfctl_flush_args").read_text().splitlines() == ["-t DevMacs -T flush", "-t Parent -T flush"]
    assert (tmp / "pf" / "DevMacs").read_text() == ""


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
    # core's creation mode for its files, not mkstemp's 0600
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o640


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


def test_flush_sweep_skips_a_temp_file_it_cannot_remove(env, monkeypatch):
    # the first orphan the sweep tries cannot be removed: it is skipped and the sweep goes on
    cfg, tmp = env
    orphans = [tmp / ".arp.cache.first.tmp", tmp / ".arp.cache.second.tmp"]
    for path in orphans:
        path.write_text("stale")
        os.utime(path, (5000.0 - 120, 5000.0 - 120))
    real_unlink = os.unlink
    refused = []

    def unlink(path, *args, **kwargs):
        if not refused and os.fspath(path) in map(str, orphans):
            refused.append(os.fspath(path))
            raise OSError(errno.EACCES, os.strerror(errno.EACCES), path)
        return real_unlink(path, *args, **kwargs)

    monkeypatch.setattr(macalias.os, "unlink", unlink)
    out = _flush(cfg)
    assert "error" not in out
    assert [str(path) for path in orphans if path.exists()] == refused


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
    assert out["update_tables"] == {"rc": 3, "output": "", "status": None, "messages": [], "complete": False}
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
    for argv in ([], ["neighbors", "remove", "x"], ["neighbors", "--remove"], ["remove"], ["status", "neighbors"]):
        assert macalias.main(argv) == 0
        assert json.loads(capsys.readouterr().out) == {
            "error": "usage", "detail": "macalias.py status|flush|neighbors [remove]"}


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
EXPIRY_NOTE = ("core's arpcache.py no longer holds the lines that add a fixed 12 h (core #10114); "
               "MAC aliases may now drop a vanished address on their own, and the neighbor-table addresses this plugin "
               "adds may no longer reach the aliases")


def _items(out, item):
    return [p for p in out["problems"] if p["item"] == item]


def test_flush_creates_state_dir_0700_and_writes_last_json_0600(env):
    cfg, tmp = env
    assert "last_file" not in macalias.DEFAULTS
    assert macalias.DEFAULTS["state_dir"] == "/var/run/macaliascache"
    assert macalias.state_paths(macalias.DEFAULTS) == {
        "last_file": "/var/run/macaliascache/last.json",
        "plugin_lock": "/var/run/macaliascache/flush.lock",
        "neighbors_file": "/var/run/macaliascache/neighbors.json",
        "neighbors_lock": "/var/run/macaliascache/neighbors.lock",
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
    # Python's json reads NaN and Infinity as floats, and true is an int (1) in Python's
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


def test_flush_writes_a_fresh_cache_at_core_mode(env):  # (e1)
    cfg, tmp = env
    (tmp / "arp.cache").unlink()
    out = _flush(cfg)
    assert "error" not in out
    assert stat.S_IMODE(os.lstat(tmp / "arp.cache").st_mode) == 0o640


def test_flush_narrows_a_cache_an_earlier_flush_widened(env):  # (e2)
    cfg, tmp = env
    (tmp / "arp.cache").chmod(0o644)
    out = _flush(cfg)
    assert "error" not in out
    assert stat.S_IMODE(os.lstat(tmp / "arp.cache").st_mode) == 0o640


def test_acquire_lock_creates_an_absent_core_lock_at_core_mode(env):  # (e3)
    cfg, tmp = env
    assert not os.path.lexists(cfg["lock_file"])
    # os.open applies the umask to the creation mode; pin core's usual one
    old_umask = os.umask(0o022)
    try:
        lock = macalias.acquire_lock(cfg, sleep=lambda s: None)
    finally:
        os.umask(old_umask)
    assert not isinstance(lock, dict) and lock is not None
    lock.close()
    assert stat.S_IMODE(os.lstat(cfg["lock_file"]).st_mode) == 0o640


def test_write_json_atomic_sets_mode_0600_under_state_dir(env):
    cfg, tmp = env
    out = _flush(cfg)
    assert "error" not in out
    modes = {p.name: stat.S_IMODE(os.lstat(p).st_mode) for p in pathlib.Path(cfg["state_dir"]).iterdir()}
    assert "last.json" in modes and set(modes.values()) == {0o600}
    # core's cache file keeps the 0640 core creates it with
    assert stat.S_IMODE(os.lstat(tmp / "arp.cache").st_mode) == 0o640
    target = pathlib.Path(cfg["state_dir"]) / "other.json"
    macalias._write_json_atomic(str(target), {"a": 1}, mode=0o600)
    assert stat.S_IMODE(os.lstat(target).st_mode) == 0o600
    assert json.loads(target.read_text()) == {"a": 1}


def test_status_lists_state_dir_problem_when_state_dir_is_a_regular_file(env):
    # an unusable state directory is reported as a problem in one JSON object, never an internal error
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
    # status puts the state directory in place right after an upgrade, and writes nothing else there
    cfg, tmp = env
    assert not os.path.exists(cfg["state_dir"])
    out = macalias.cmd_status(cfg, now=0.0)
    assert out["problems"] == []
    st = os.lstat(cfg["state_dir"])
    assert stat.S_ISDIR(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o700
    assert os.listdir(cfg["state_dir"]) == []


@pytest.mark.parametrize("kind", ["absent", "regular", "fifo", "symlink"])
def test_status_lock_file_problem(env, kind):
    # core's flock(1) creates the lock on use, so absent is fine; only a regular file may be opened
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
    # FreeBSD's open(2) answers O_NOFOLLOW on a symlink with EMLINK, not ELOOP, so
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
    # core's cache is absent after a boot until something writes it
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
    # undecodable bytes read as absent, never an exception
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
    # the files are UTF-8 JSON; run status under a Latin-1 locale, where a default open() would misread them
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
    # host discovery may be IPv6-heavy on a segment; unzoned link-local rows are real devices
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
    expected = {row[0]: row[2] for row in lib.CORE_CONTRACT}
    assert repr(macalias.DEFAULTS["list_hosts"]) in expected["arpcache"]
    assert macalias.DEFAULTS["cache_file"] in expected["arpcache"]
    assert macalias.DEFAULTS["lock_file"] in expected["update_lock"]
    assert os.path.join(macalias.DEFAULTS["aliastables_dir"], "%s.md5.txt") in expected["md5_marker"]


def test_stock_core_files_give_no_problem(env):
    # the fixtures hold 26.7.7's own lines, so a stock box raises no problem
    cfg, tmp = env
    texts = macalias.read_core_texts(cfg)
    assert set(texts) == set(CORE_FILES)
    assert texts["list_hosts"] == "exists"
    assert None not in texts.values()
    assert lib.core_contract(texts) == []
    out = macalias.cmd_status(cfg, now=0.0)
    assert out["problems"] == []
    assert out["notes"] == []


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


def test_flush_refuses_when_cores_host_row_line_changes(env):
    cfg, tmp = env
    path = _core(cfg, "arpcache")
    text = path.read_text()
    assert "item[2])" in text
    path.write_text(text.replace("item[2])", "item[0])"))
    before = _snapshot(tmp)
    out = _flush(cfg)
    assert out["error"] == "core_changed"
    assert [p["item"] for p in out["problems"]] == ["arpcache"]
    assert out["problems"][0]["blocks_flush"] is True
    assert out["detail"] == out["problems"][0]["problem"]
    _unchanged(tmp, cfg, before)


def test_flush_refuses_when_update_tables_is_missing(env):
    # the file also holds the text of core's emptied-table fix, which gives a note, never a problem:
    # only the blocking item is listed
    cfg, tmp = env
    _core(cfg, "targeted_mode").unlink()
    before = _snapshot(tmp)
    out = _flush(cfg)
    assert out["error"] == "core_changed"
    assert [p["item"] for p in out["problems"]] == ["targeted_mode"]
    _unchanged(tmp, cfg, before)


def _fix_core(cfg, item, text):
    path = _core(cfg, item)
    path.write_text(path.read_text().replace(text, ""))


def test_status_lists_core_fixes_as_notes(env):
    cfg, tmp = env
    _fix_core(cfg, "emptied_table", "else cnt_alias_content")
    out = macalias.cmd_status(cfg, now=0.0)
    assert out["problems"] == []
    assert out["notes"] == [{"item": "emptied_table", "note": EMPTIED_NOTE, "shown": False}]
    _fix_core(cfg, "cache_expiry", "_address_ttl = 43200")
    out = macalias.cmd_status(cfg, now=0.0)
    assert out["problems"] == []
    assert out["notes"] == [{"item": "cache_expiry", "note": EXPIRY_NOTE, "shown": True},
                            {"item": "emptied_table", "note": EMPTIED_NOTE, "shown": False}]
    out = _flush(cfg)
    assert "error" not in out and "notes" not in out
    assert (tmp / "update_args").read_text().split() == ["--aliases", "DevMacs,Parent"]


def test_refusal_never_carries_a_note(env):
    cfg, tmp = env
    arpcache = _core(cfg, "arpcache")
    arpcache.write_text(arpcache.read_text().replace("/tmp/alias_filter_arp.cache", "/var/cache/alias_filter_arp.cache"))
    _fix_core(cfg, "emptied_table", "else cnt_alias_content")
    before = _snapshot(tmp)
    out = _flush(cfg)
    assert out["error"] == "core_changed"
    assert [p["item"] for p in out["problems"]] == ["arpcache"]
    assert "notes" not in out
    _unchanged(tmp, cfg, before)
    assert macalias.cmd_status(cfg, now=0.0)["notes"] == [{"item": "emptied_table", "note": EMPTIED_NOTE, "shown": False}]


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


ALIAS_TTL = ("MAC alias %s has no lifetime above 0 in core's alias table file (%s), so core never rebuilds it and "
             "a flush cannot change it; clear the alias's update frequency")


def _devmacs_ttl(tmp, ttl):
    """ filter_tables.conf with DevMacs's <ttl> holding the text ttl, or left out for None """
    (tmp / "filter_tables.conf").write_text(
        TABLES.replace("<ttl>30</ttl>", "" if ttl is None else "<ttl>%s</ttl>" % ttl))


@pytest.mark.parametrize("ttl", ["0", "0.0", "0.5", "-1", None],
                         ids=["zero", "zero-float", "under-a-second", "not-digits", "absent"])
def test_status_names_a_mac_alias_core_never_rebuilds_and_the_flush_still_runs(env, ttl):
    # core expires an alias only while its lifetime is above 0, so setting the .md5.txt mark to 0 does
    # nothing for this one; the aliases beside it are rebuilt all the same
    cfg, tmp = env
    _devmacs_ttl(tmp, ttl)
    problem = {"item": "alias_ttl", "problem": ALIAS_TTL % ("DevMacs", cfg["tables_conf"]), "blocks_flush": False}
    assert macalias.cmd_status(cfg, now=0.0)["problems"] == [problem]
    out = _flush(cfg)
    assert "error" not in out
    assert out["no_expiry"] == ["DevMacs"]
    assert (tmp / "update_args").read_text().split() == ["--aliases", "DevMacs,Parent"]
    assert out["update_tables"] == UPDATE_OK


@pytest.mark.parametrize("ttl", ["30", "43200.0", "1"], ids=["stock", "update-frequency", "one-second"])
def test_a_mac_alias_with_a_lifetime_above_zero_is_no_problem(env, ttl):
    # 43200.0 is what core writes for an update frequency of half a day: a float
    cfg, tmp = env
    _devmacs_ttl(tmp, ttl)
    assert macalias.cmd_status(cfg, now=0.0)["problems"] == []
    out = _flush(cfg)
    assert "error" not in out
    assert out["no_expiry"] == []
    assert os.stat(tmp / "aliastables" / "DevMacs.md5.txt").st_mtime == 0


def test_a_refusal_carries_the_advisory_problem_and_is_decided_without_it(env):
    cfg, tmp = env
    _devmacs_ttl(tmp, "0")
    _core(cfg, "targeted_mode").unlink()
    before = _snapshot(tmp)
    out = _flush(cfg)
    assert out["error"] == "core_changed"
    assert [(p["item"], p["blocks_flush"]) for p in out["problems"]] == [("alias_ttl", False), ("targeted_mode", True)]
    assert out["detail"] == out["problems"][1]["problem"]
    _unchanged(tmp, cfg, before)


def test_the_advisory_items_have_no_refusal_code_and_refuse_nothing():
    assert macalias._ADVISORY_ITEMS == ("alias_ttl", "neighbor_merge", "ndp", "neighbors_setting", "neighbors_file",
                                        "neighbors_lock")
    assert set(macalias._ADVISORY_ITEMS) & set(macalias._REFUSAL_CODE) == set()
    for item in macalias._ADVISORY_ITEMS:
        assert macalias.refusal([{"item": item, "problem": "p", "blocks_flush": False}]) is None


INTERNAL_TABLE = "<table><name>__lan_network</name><type>network</type><address>%s</address></table>"


def test_alias_name_checks_the_refresh_set_only(env):
    # core's own internal tables (__lan_network and the like) fail the pattern, and are no
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
        ("state_dir", True), ("lock_file", True), ("cache_file", False), ("alias_name", True), ("arpcache", True)]
    assert _items(out, "cache_file")[0]["problem"] == CACHE_FORGED % cfg["cache_file"]
    assert _items(out, "alias_name")[0]["problem"] == ALIAS_NAME % "'Dev Macs'"
    assert out["notes"] == [{"item": "emptied_table", "note": EMPTIED_NOTE, "shown": False}]

    # with the state directory usable, what is inside it is listed too
    pathlib.Path(cfg["state_dir"]).unlink()
    os.mkdir(cfg["state_dir"], 0o700)
    os.mkdir(macalias.state_paths(cfg)["plugin_lock"])
    with _within(5):
        out = macalias.cmd_status(cfg, now=0.0)
    assert [(p["item"], p["blocks_flush"]) for p in out["problems"]] == [
        ("plugin_lock", True), ("lock_file", True), ("cache_file", False), ("alias_name", True), ("arpcache", True)]
    os.rmdir(macalias.state_paths(cfg)["plugin_lock"])

    # a flush refuses with the first class that blocks and carries every problem
    with _within(5):
        out = _flush(cfg)
    assert out["error"] == "lock_unusable"
    assert [p["item"] for p in out["problems"]] == ["lock_file", "cache_file", "alias_name", "arpcache"]
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
    with _within(5):
        seen.update(p["item"] for p in macalias.problems(cfg))
    assert seen == set(macalias._REFUSAL_CODE)
    for item, code in macalias._REFUSAL_CODE.items():
        assert code in ("state_unusable", "lock_unusable", "core_changed"), item
        assert macalias.refusal([{"item": item, "problem": "p", "blocks_flush": True}])["error"] == code
    assert {item for item, code in macalias._REFUSAL_CODE.items() if code == "state_unusable"} == {
        "state_dir", "last_file", "plugin_lock", "cache_file"}
    assert {item for item, code in macalias._REFUSAL_CODE.items() if code == "core_changed"} == {
        "alias_name", "arpcache", "update_lock", "md5_marker", "targeted_mode", "list_hosts"}


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


# the neighbor tick: macalias.py neighbors

NMAC = "aa:bb:cc:00:00:01"
# what env's cache holds before a case changes it: the MAC's own entry, which is core's to write
OWN = {NMAC: {"items": ["192.0.2.50", "192.0.2.99"], "last_seen": 1000.0}}
HOSTS_UNAVAILABLE = {"error": "hosts_unavailable", "detail": "host list could not be read; nothing changed"}
NEIGHBORS_UNAVAILABLE = {"error": "neighbors_unavailable",
                         "detail": "neighbor table could not be read; nothing changed"}
CACHE_UNREADABLE = "core's MAC alias cache at %s holds no JSON object; nothing changed"
TICK_BUSY = {"error": "busy", "detail": "another neighbor tick is running"}
NDP_MISSING = "%s is missing or not executable, so the neighbor table cannot be read"
SETTING_UNUSABLE = ("the plugin's settings file at %s holds no setting the plugin can read, so the neighbor table is "
                    "not used; save the setting on the plugin's page to write the file again")
NEIGHBORS_DIRECTORY = "plugin neighbor record at %s is a directory"
NEIGHBORS_LOCK_NOT_REGULAR = "the plugin's neighbor lock at %s is not a regular file with one link"
NEIGHBOR_DRIFT = ("core's %s no longer contains %s; the addresses from the neighbor table rely on it, "
                  "so none is added or removed")


def _nkey(ip, mac=NMAC):
    return "%s#%s" % (mac, ip)


def _nentry(ip, last_seen):
    return {"items": [ip], "last_seen": last_seen}


def _neighbor_table(tmp, pairs):
    """ the fake ndp prints one row per (MAC, address) """
    (tmp / "ndp.json").write_text(json.dumps({"ndp": {"neighbor-cache": [
        {"address": ip, "mac-address": mac, "interface": "vlan0.120"} for mac, ip in pairs]}}))


def _tick(cfg, now=5000.0, **kwargs):
    return macalias.cmd_neighbors(cfg, clock=lambda: now, sleep=lambda s: None, **kwargs)


def _ok(**counts):
    reply = {"result": "ok", "changed": False, "added": 0, "removed": 0, "refreshed": 0, "keys": 0, "over_limit": 0,
             "samples": []}
    reply.update(counts)
    return reply


def _cache(tmp):
    return json.loads((tmp / "arp.cache").read_text())


def _seed(tmp, extra):
    """ core's cache with the MAC's own entry and extra """
    (tmp / "arp.cache").write_text(json.dumps(dict(OWN, **extra)))


def _neighbors_file(cfg):
    return pathlib.Path(macalias.state_paths(cfg)["neighbors_file"])


def _neighbors_record(cfg):
    return json.loads(_neighbors_file(cfg).read_text())


def _state(cfg):
    """ the record's result, when it began and whether it was reported """
    record = _neighbors_record(cfg)
    return record["result"], record["since"], record["reported"]


def _file_id(path):
    st = os.stat(path)
    return st.st_ino, st.st_mtime_ns, st.st_size


def _no_temps(cfg, tmp):
    names = [p.name for p in tmp.iterdir()] + os.listdir(cfg["state_dir"])
    return [name for name in names if name.endswith(".tmp")] == []


def _locks_free(cfg):
    for path in (cfg["lock_file"], macalias.state_paths(cfg)["neighbors_lock"]):
        if os.path.exists(path):
            with open(path, "a") as fh:
                fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)   # raises BlockingIOError while held


def _no_core_lock(monkeypatch):
    monkeypatch.setattr(macalias, "acquire_lock", lambda *args, **kwargs: pytest.fail("core's lock was asked for"))


def test_neighbors_defaults_are_the_box_and_the_specified_limits():
    defaults = macalias.DEFAULTS
    assert defaults["ndp"] == ["/usr/sbin/ndp", "-an", "--libxo", "json"]
    assert (defaults["ndp_timeout"], defaults["ndp_max_bytes"]) == (5.0, 1048576)
    assert defaults["settings_file"] == "/usr/local/etc/macaliascache.conf"
    assert defaults["neighbors_lock_timeout"] == 5.0
    # ndp is a program of its own, not one of core's files
    assert "ndp" not in defaults["core_files"]


def test_neighbors_adds_keys_under_core_lock(env, monkeypatch):
    cfg, tmp = env
    _neighbor_table(tmp, [("AA:BB:CC:00:00:01", "2001:DB8::0007"), (NMAC, "fe80::7%vlan0.120"),
                          ("dd:ee:ff:00:00:03", "2001:db8::3"), (NMAC, "192.0.2.50")])
    locked = []
    real_write = macalias._write_json_atomic

    def write(path, obj, *args, **kwargs):
        if path == cfg["cache_file"]:
            with open(cfg["lock_file"], "a") as probe:
                try:
                    fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    locked.append(False)
                except BlockingIOError:
                    locked.append(True)
        return real_write(path, obj, *args, **kwargs)

    monkeypatch.setattr(macalias, "_write_json_atomic", write)
    out = _tick(cfg)
    assert out == _ok(changed=True, added=2, keys=2, samples=["2001:db8::7", "fe80::7"])
    assert locked == [True]
    # the MAC's own entry is as core wrote it; each key holds its one address, seen now
    assert _cache(tmp) == dict(OWN, **{_nkey("2001:db8::7"): _nentry("2001:db8::7", 5000.0),
                                       _nkey("fe80::7"): _nentry("fe80::7", 5000.0)})
    assert stat.S_IMODE(os.lstat(tmp / "arp.cache").st_mode) == 0o640
    assert (tmp / "ndp_args").read_text().splitlines() == ["-an --libxo json"]
    _locks_free(cfg)
    assert _no_temps(cfg, tmp)
    # core is not run and no alias is marked: its own next run applies the cache
    assert not (tmp / "update_args").exists()
    assert os.stat(tmp / "aliastables" / "DevMacs.md5.txt").st_mtime != 0


def test_neighbors_unchanged_minute_takes_no_core_lock_and_writes_nothing(env, monkeypatch, logged):
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    assert _tick(cfg, now=5000.0) == _ok(changed=True, added=1, keys=1, samples=["2001:db8::7"])
    before = _file_id(tmp / "arp.cache"), _file_id(_neighbors_file(cfg)), (tmp / "arp.cache").read_bytes()
    del logged[0][:]
    _no_core_lock(monkeypatch)
    # something else holds core's lock the whole minute: the tick neither waits for it nor answers busy
    with open(cfg["lock_file"], "a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        out = _tick(cfg, now=5060.0)
    assert out == _ok(keys=1)
    assert (_file_id(tmp / "arp.cache"), _file_id(_neighbors_file(cfg)), (tmp / "arp.cache").read_bytes()) == before
    assert logged[0] == []
    assert _no_temps(cfg, tmp)


def test_neighbors_nothing_wanted_writes_nothing(env, monkeypatch):
    # the stock case of a network whose host discovery misses nothing: no key, no lock, no cache write
    cfg, tmp = env
    before = _file_id(tmp / "arp.cache")
    _no_core_lock(monkeypatch)
    assert _tick(cfg) == _ok()
    assert _file_id(tmp / "arp.cache") == before


def test_neighbors_busy_on_own_lock(env, logged):
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    os.makedirs(cfg["state_dir"], 0o700, exist_ok=True)
    before = (tmp / "arp.cache").read_bytes()
    slept = []
    with open(macalias.state_paths(cfg)["neighbors_lock"], "a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        out = macalias.cmd_neighbors(cfg, clock=lambda: 5000.0, sleep=slept.append)
    assert out == TICK_BUSY
    assert slept == []
    assert (tmp / "arp.cache").read_bytes() == before
    assert not (tmp / "ndp_args").exists()
    assert not _neighbors_file(cfg).exists()
    assert logged[0] == []


def test_neighbors_tick_and_flush_do_not_share_a_lock(env):
    # the Flush button never answers busy because of a tick, and a tick runs beside a waiting flush
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    os.makedirs(cfg["state_dir"], 0o700, exist_ok=True)
    with open(macalias.state_paths(cfg)["neighbors_lock"], "a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        assert "error" not in _flush(cfg)
    with open(macalias.state_paths(cfg)["plugin_lock"], "a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        assert _tick(cfg, now=6000.0)["result"] == "ok"


def test_neighbors_busy_on_core_lock_not_logged(env, logged):
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    before = _file_id(tmp / "arp.cache")
    with open(cfg["lock_file"], "a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        out = _tick(cfg)
    assert out == {"error": "busy", "detail": "alias update lock held for 0.2s"}
    assert _file_id(tmp / "arp.cache") == before
    # one busy minute is recorded as the tick's result and is no state yet: nothing is logged, now or when the
    # next tick works
    assert logged[0] == []
    assert _state(cfg) == ("busy", 5000.0, False)
    assert _tick(cfg, now=5060.0) == _ok(changed=True, added=1, keys=1, samples=["2001:db8::7"])
    assert [message for _priority, message in logged[0]] == ["neighbors: 1 added (2001:db8::7), 0 removed"]
    assert _state(cfg) == ("ok", 5060.0, False)
    _locks_free(cfg)


def _whole_cache_at_the_lock(monkeypatch, tmp, cache):
    """ core's cache is whole again by the time its lock is free, as after a run of core's that had truncated it """
    real_acquire = macalias.acquire_lock

    def acquire(*args, **kwargs):
        lock = real_acquire(*args, **kwargs)
        (tmp / "arp.cache").write_text(json.dumps(cache))
        return lock

    monkeypatch.setattr(macalias, "acquire_lock", acquire)


def test_neighbors_unparseable_cache_unlocked_goes_to_locked_path(env, monkeypatch):
    # core truncates its cache and writes it when its run ends: 0 bytes is not "no key of ours"
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    (tmp / "arp.cache").write_text("")
    held = dict(OWN, **{_nkey("2001:db8::8"): _nentry("2001:db8::8", 4000.0)})
    _whole_cache_at_the_lock(monkeypatch, tmp, held)
    assert _tick(cfg) == _ok(changed=True, added=1, keys=2, samples=["2001:db8::7"])
    assert _cache(tmp) == dict(held, **{_nkey("2001:db8::7"): _nentry("2001:db8::7", 5000.0)})


def test_neighbors_unparseable_cache_unlocked_then_nothing_to_change_writes_nothing(env, monkeypatch, logged):
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    (tmp / "arp.cache").write_text("")
    _whole_cache_at_the_lock(monkeypatch, tmp, dict(OWN, **{_nkey("2001:db8::7"): _nentry("2001:db8::7", 4990.0)}))
    writes = []
    real_write = macalias._write_json_atomic
    monkeypatch.setattr(macalias, "_write_json_atomic",
                        lambda path, *args, **kwargs: (writes.append(path), real_write(path, *args, **kwargs)))
    assert _tick(cfg) == _ok(keys=1)
    assert cfg["cache_file"] not in writes
    assert logged[0] == []
    _locks_free(cfg)


@pytest.mark.parametrize("content", ["", "not json", "[]", '"text"', '{"aa:bb:cc:00:00:01": {"items": ['],
                         ids=["empty", "not-json", "list", "string", "cut-short"])
def test_neighbors_unparseable_cache_under_lock_writes_nothing(env, logged, content):
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    (tmp / "arp.cache").write_text(content)
    before = _file_id(tmp / "arp.cache")
    out = _tick(cfg)
    assert out == {"error": "cache_unreadable", "detail": CACHE_UNREADABLE % cfg["cache_file"]}
    assert _file_id(tmp / "arp.cache") == before and (tmp / "arp.cache").read_text() == content
    assert _no_temps(cfg, tmp)
    _locks_free(cfg)
    # the next minute, with the cache whole, works
    _seed(tmp, {})
    assert _tick(cfg, now=5060.0) == _ok(changed=True, added=1, keys=1, samples=["2001:db8::7"])


def test_neighbors_absent_cache_is_empty(env):
    # absent is normal after a boot: an empty cache, and no reason to create one
    cfg, tmp = env
    (tmp / "arp.cache").unlink()
    with pytest.MonkeyPatch.context() as patch:
        _no_core_lock(patch)
        assert _tick(cfg) == _ok()
    assert not (tmp / "arp.cache").exists()
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    assert _tick(cfg, now=5060.0) == _ok(changed=True, added=1, keys=1, samples=["2001:db8::7"])
    assert _cache(tmp) == {_nkey("2001:db8::7"): _nentry("2001:db8::7", 5060.0)}
    assert stat.S_IMODE(os.lstat(tmp / "arp.cache").st_mode) == 0o640


@pytest.mark.parametrize("body", [
    "exit 1\n",
    "echo not-json\n",
    "echo '{\"source\": \"discovery\", \"rows\": [[\"vlan0.120\", \"aa:bb:cc:00:00:01\", \"192.0.2.50\"]]}'\nexit 3\n",
    "echo '{\"rows\": [[\"vlan0.120\", \"aa:bb:cc:00:00:01\", \"192.0.2.50\"]]}'\n",
    "echo '{\"source\": null, \"rows\": []}'\n",
    "echo '{\"source\": \"discovery\", \"rows\": {\"vlan0.120\": [\"aa:bb:cc:00:00:01\", \"192.0.2.50\"]}}'\n",
    "echo '{\"source\": \"discovery\", \"rows\": null}'\n",
    "echo '{\"source\": \"discovery\"}'\n",
    "echo '{\"source\": \"other\", \"rows\": []}'\n",
    "echo '{\"source\": [\"arp-ndp\"], \"rows\": []}'\n",
    "echo '[[\"vlan0.120\", \"aa:bb:cc:00:00:01\", \"192.0.2.50\"]]'\n",
    None,
], ids=["fails", "non-json", "json-then-fails", "no-source", "null-source", "rows-object", "rows-null", "no-rows",
        "unknown-source", "source-not-text", "top-level-list", "times-out"])
def test_neighbors_hosts_unreadable_changes_nothing(env, monkeypatch, body):
    # an unreadable host list is not "host discovery is off": the keys stay, or every alias would lose its
    # neighbor addresses for the minutes host discovery restarts in
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    _seed(tmp, {_nkey("2001:db8::8"): _nentry("2001:db8::8", 4000.0)})
    if body is None:
        real_run = subprocess.run

        def run(argv, *args, **kwargs):
            if argv == cfg["list_hosts"]:
                raise subprocess.TimeoutExpired(argv, kwargs.get("timeout"))
            return real_run(argv, *args, **kwargs)

        monkeypatch.setattr(macalias.subprocess, "run", run)
    else:
        cfg["list_hosts"] = [_exe(tmp / "bad_hosts", body), "-n"]
    before = _file_id(tmp / "arp.cache")
    _no_core_lock(monkeypatch)
    assert _tick(cfg) == HOSTS_UNAVAILABLE
    assert _file_id(tmp / "arp.cache") == before
    assert not (tmp / "ndp_args").exists()


def test_neighbors_empty_discovery_list_is_a_list(env):
    # host discovery on with no row yet lists nothing for any MAC: every neighbor address is wanted
    cfg, tmp = env
    _list_hosts(cfg, tmp, [])
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    assert _tick(cfg) == _ok(changed=True, added=1, keys=1, samples=["2001:db8::7"])


def _arp_ndp_hosts(cfg, tmp):
    listing = tmp / "arp_ndp.json"
    listing.write_text(json.dumps({"source": "arp-ndp", "rows": [["vlan0.120", NMAC, "192.0.2.50"],
                                                                  ["vlan0.120", NMAC, "2001:db8::7"]]}))
    cfg["list_hosts"] = [_exe(tmp / "arp_ndp_hosts", 'cat "%s"\n' % listing), "-n"]


def test_neighbors_source_arp_ndp_removes_ours(env):
    # host discovery is off: core reads the neighbor table itself, so the plugin's keys go
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    _seed(tmp, {_nkey("2001:db8::7"): _nentry("2001:db8::7", 4000.0), _nkey("fe80::2", "aa:bb:cc:00:00:02"):
                _nentry("fe80::2", 4000.0)})
    _arp_ndp_hosts(cfg, tmp)
    assert _tick(cfg) == _ok(changed=True, removed=2)
    assert _cache(tmp) == OWN
    assert not (tmp / "ndp_args").exists()
    assert _tick(cfg, now=5060.0) == _ok()


def test_neighbors_setting_off_removes_ours(env):
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    assert _tick(cfg)["added"] == 1
    (tmp / "macaliascache.conf").write_text("[general]\nneighbors=0\n")
    (tmp / "ndp_args").unlink()
    cfg["list_hosts"] = [str(tmp / "never-run"), "-n"]
    assert _tick(cfg, now=5060.0) == _ok(changed=True, removed=1)
    assert _cache(tmp) == OWN
    assert not (tmp / "ndp_args").exists()
    assert _tick(cfg, now=5120.0) == _ok()


def test_neighbors_no_mac_alias_removes_ours(env):
    cfg, tmp = env
    _seed(tmp, {_nkey("2001:db8::7"): _nentry("2001:db8::7", 4000.0)})
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    (tmp / "filter_tables.conf").write_text(TABLES.replace("aa:bb:cc:00:00:01", ""))
    assert _tick(cfg) == _ok(changed=True, removed=1)
    assert _cache(tmp) == OWN


def test_neighbors_setting_absent_is_on(env):
    # a file the template never rendered: the model's default, on
    cfg, tmp = env
    (tmp / "macaliascache.conf").unlink()
    assert macalias.read_setting(cfg) == (True, "absent")
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    assert _tick(cfg) == _ok(changed=True, added=1, keys=1, samples=["2001:db8::7"])


def test_read_setting_reads_the_rendered_file(env):
    cfg, tmp = env
    assert macalias.read_setting(cfg) == (True, "ok")
    (tmp / "macaliascache.conf").write_text("[general]\nneighbors=0\n")
    assert macalias.read_setting(cfg) == (False, "ok")
    cfg["settings_file"] = str(tmp / "no-such-directory" / "macaliascache.conf")
    assert macalias.read_setting(cfg) == (True, "absent")


@pytest.mark.parametrize("kind", ["two", "garbage", "empty", "oversized", "undecodable", "symlink", "directory", "fifo",
                                  "hard-link", "under-a-file"])
def test_neighbors_setting_unusable_refuses(env, kind):
    # present and not a clean setting reads as off, and the tick refuses: it adds nothing and removes nothing
    cfg, tmp = env
    conf = tmp / "macaliascache.conf"
    good = "[general]\nneighbors=1\n"
    if kind == "two":
        conf.write_text("[general]\nneighbors=2\n")
    elif kind == "garbage":
        conf.write_text("neighbors on\n")
    elif kind == "empty":
        conf.write_text("")
    elif kind == "oversized":
        conf.write_text(good + "\n" * 5000)
    elif kind == "undecodable":
        conf.write_bytes(b"[general]\nneighbors=1\n\xff\n")
    elif kind == "under-a-file":
        cfg["settings_file"] = str(conf / "macaliascache.conf")
    else:
        conf.rename(tmp / "real.conf")
        if kind == "symlink":
            os.symlink(tmp / "real.conf", conf)
        elif kind == "directory":
            conf.mkdir()
        elif kind == "fifo":
            os.mkfifo(conf)
        else:
            os.link(tmp / "real.conf", conf)
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    _seed(tmp, {_nkey("2001:db8::8"): _nentry("2001:db8::8", 4000.0)})
    before = _file_id(tmp / "arp.cache")
    problem = {"item": "neighbors_setting", "problem": SETTING_UNUSABLE % cfg["settings_file"], "blocks_flush": False}
    with _within(5):
        assert macalias.read_setting(cfg) == (False, "unusable")
        assert _items(macalias.cmd_status(cfg, now=0.0), "neighbors_setting") == [problem]
        assert _tick(cfg) == {"error": "setting_unusable", "detail": problem["problem"]}
    assert _file_id(tmp / "arp.cache") == before
    assert not (tmp / "ndp_args").exists()


def test_neighbors_remove_argument(env, monkeypatch, capsys):
    # package removal: every key of ours goes whatever the setting says, and whatever the removal does not use
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    assert _tick(cfg)["added"] == 1
    (tmp / "ndp_args").unlink()
    cfg["list_hosts"] = [str(tmp / "never-run"), "-n"]
    assert _tick(cfg, now=5060.0, remove_all=True) == _ok(changed=True, removed=1)
    assert _cache(tmp) == OWN
    assert not (tmp / "ndp_args").exists()

    # neither the settings file, the neighbor table's program, the host list's, the merge contract, the alias
    # table file nor the record's own path is the removal's to need
    _seed(tmp, {_nkey("2001:db8::7"): _nentry("2001:db8::7", 4000.0)})
    (tmp / "macaliascache.conf").write_text("neighbors on\n")
    pathlib.Path(cfg["ndp"][0]).chmod(0o644)
    _core(cfg, "list_hosts").chmod(0o644)
    _fix_core(cfg, "neighbor_merge", "if macaddr.startswith(pattern.lower()):")
    assert _tick(cfg, now=5120.0)["error"] == "core_changed"
    (tmp / "filter_tables.conf").write_text("<tabledef><table>")
    _neighbors_file(cfg).unlink()
    _neighbors_file(cfg).mkdir()
    reads = []
    monkeypatch.setattr(macalias, "read_tables", lambda cfg_: reads.append(cfg_) or pytest.fail("the alias table read"))
    monkeypatch.setattr(macalias, "read_setting", lambda cfg_: pytest.fail("the setting read"))
    assert _tick(cfg, now=5120.0, remove_all=True) == _ok(changed=True, removed=1)
    assert _cache(tmp) == OWN
    monkeypatch.undo()
    _neighbors_file(cfg).rmdir()
    (tmp / "filter_tables.conf").write_text(TABLES)

    # what the removal writes through still refuses it
    _seed(tmp, {_nkey("2001:db8::7"): _nentry("2001:db8::7", 4000.0)})
    _core(cfg, "update_lock").unlink()
    assert _tick(cfg, now=5180.0, remove_all=True)["error"] == "core_changed"
    assert _nkey("2001:db8::7") in _cache(tmp)

    calls = []
    monkeypatch.setattr(macalias, "cmd_neighbors",
                        lambda cfg_, **kwargs: calls.append((cfg_, kwargs)) or {"result": "ok"})
    assert macalias.main(["neighbors"]) == 0 and macalias.main(["neighbors", "remove"]) == 0
    assert calls == [(macalias.DEFAULTS, {}), (macalias.DEFAULTS, {"remove_all": True})]
    assert capsys.readouterr().out == '{"result": "ok"}\n{"result": "ok"}\n'


@pytest.mark.parametrize("kind", ["fails", "fails-after-json", "non-json", "other-shape", "over-the-limit", "times-out",
                                  "cannot-start"])
def test_neighbors_ndp_unreadable(env, monkeypatch, kind):
    cfg, tmp = env
    good = json.dumps({"ndp": {"neighbor-cache": [{"address": "2001:db8::7", "mac-address": NMAC}]}})
    body = {
        "fails": "exit 1\n",
        "fails-after-json": "echo '%s'\nexit 1\n" % good,
        "non-json": "echo 'Neighbor Linklayer Address Netif Expire S Flags'\n",
        "other-shape": "echo '{\"ndp\": {\"neighbor-cache\": {}}}'\n",
        "over-the-limit": "echo '%s'\nhead -c 4096 /dev/zero | tr '\\0' ' '\n" % good,
        "times-out": "echo '%s'\nexec sleep 30\n" % good,
        "cannot-start": "exit 0\n",
    }[kind]
    cfg["ndp"] = [_exe(tmp / "bad_ndp", body), "-an", "--libxo", "json"]
    cfg["ndp_max_bytes"] = 1024
    cfg["ndp_timeout"] = 0.5
    if kind == "cannot-start":
        real_popen = subprocess.Popen

        def popen(argv, *args, **kwargs):
            if argv == cfg["ndp"]:
                raise OSError(errno.ENOEXEC, os.strerror(errno.ENOEXEC))
            return real_popen(argv, *args, **kwargs)

        monkeypatch.setattr(macalias.subprocess, "Popen", popen)
    _seed(tmp, {_nkey("2001:db8::8"): _nentry("2001:db8::8", 4000.0)})
    before = _file_id(tmp / "arp.cache")
    _no_core_lock(monkeypatch)
    with _within(10):
        assert macalias.read_neighbors(cfg) is None
        assert _tick(cfg) == NEIGHBORS_UNAVAILABLE
    assert _file_id(tmp / "arp.cache") == before


def test_read_neighbors_reads_the_table_up_to_the_limit(env):
    cfg, tmp = env
    _neighbor_table(tmp, [("AA:BB:CC:00:00:01", "fe80::7%vlan0.120"), (NMAC, "2001:db8::7")])
    assert macalias.read_neighbors(cfg) == [(NMAC, "2001:db8::7"), (NMAC, "fe80::7")]
    cfg["ndp_max_bytes"] = len((tmp / "ndp.json").read_bytes())
    assert macalias.read_neighbors(cfg) == [(NMAC, "2001:db8::7"), (NMAC, "fe80::7")]
    cfg["ndp_max_bytes"] -= 1
    assert macalias.read_neighbors(cfg) is None


def test_neighbors_table_without_a_row_is_an_empty_table(env):
    # ndp's reply with no neighbor at all is read, not unreadable: nothing is wanted, and a key whose address
    # left the table is left to core's 12 h as with any other table
    cfg, tmp = env
    (tmp / "ndp.json").write_text('{"ndp": {}}')
    _seed(tmp, {_nkey("2001:db8::8"): _nentry("2001:db8::8", 4000.0)})
    assert macalias.read_neighbors(cfg) == []
    assert _tick(cfg) == _ok(keys=1)
    assert _flush(cfg)["neighbors"] == {"added": 0, "over_limit": 0}


def test_neighbors_never_writes_an_address_no_host_can_have(env):
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "::"), (NMAC, "::1"), (NMAC, "ff02::1"), (NMAC, "::ffff:192.0.2.1"),
                          (NMAC, "2001:db8::7")])
    assert _tick(cfg) == _ok(changed=True, added=1, keys=1, samples=["2001:db8::7"])
    assert _cache(tmp) == dict(OWN, **{_nkey("2001:db8::7"): _nentry("2001:db8::7", 5000.0)})


def test_neighbors_limit_bounds_what_the_cache_holds_over_time(env):
    # 32 fresh addresses of the listed MAC each minute, the minute before's gone from the table: the cache never
    # holds more than 32 keys of the MAC, and the tick says what it removed for them
    cfg, tmp = env
    for minute in range(4):
        _neighbor_table(tmp, [(NMAC, "2001:db8:%x::%x" % (minute + 1, n)) for n in range(1, 33)])
        out = _tick(cfg, now=5000.0 + 60 * minute)
        assert (out["added"], out["removed"], out["keys"], out["over_limit"]) == (32, 32 if minute else 0, 32, 0)
        assert sorted(_cache(tmp)) == sorted(
            [NMAC] + [_nkey("2001:db8:%x::%x" % (minute + 1, n)) for n in range(1, 33)])
    # a table that shrinks keeps the newest of the old keys in the room left
    _neighbor_table(tmp, [(NMAC, "2001:db8:9::%x" % n) for n in range(1, 31)])
    out = _tick(cfg, now=5300.0)
    assert (out["added"], out["removed"], out["keys"]) == (30, 30, 32)


def test_neighbors_ndp_not_executable_is_a_problem_and_refuses(env):
    cfg, tmp = env
    pathlib.Path(cfg["ndp"][0]).chmod(0o644)
    _seed(tmp, {_nkey("2001:db8::8"): _nentry("2001:db8::8", 4000.0)})
    before = _file_id(tmp / "arp.cache")
    problem = {"item": "ndp", "problem": NDP_MISSING % cfg["ndp"][0], "blocks_flush": False}
    assert macalias.cmd_status(cfg, now=0.0)["problems"] == [problem]
    assert _tick(cfg) == {"error": "core_changed", "detail": problem["problem"]}
    assert _file_id(tmp / "arp.cache") == before
    cfg["ndp"] = [str(tmp / "no-such-ndp"), "-an"]
    assert _tick(cfg) == {"error": "core_changed", "detail": NDP_MISSING % cfg["ndp"][0]}
    # a flush is not the neighbor table's business
    assert "error" not in _flush(cfg)


def _refuses(item, blocks, removing=False):
    return macalias.neighbors_refusal([{"item": item, "problem": "p", "blocks_flush": blocks}], removing)


def test_neighbors_refusal_table():
    table = macalias._NEIGHBORS_REFUSAL_CODE
    assert table == {
        "state_dir": "state_unusable", "neighbors_lock": "state_unusable", "cache_file": "state_unusable",
        "neighbors_file": "state_unusable",
        "lock_file": "lock_unusable",
        "arpcache": "core_changed", "update_lock": "core_changed", "list_hosts": "core_changed",
        "neighbor_merge": "core_changed", "ndp": "core_changed",
        "neighbors_setting": "setting_unusable",
    }
    assert macalias._NEIGHBORS_REFUSAL_ORDER == ("state_unusable", "lock_unusable", "core_changed", "setting_unusable")
    assert set(table.values()) == set(macalias._NEIGHBORS_REFUSAL_ORDER)
    # a tick that only removes (the setting off, neighbors remove) stops for what a removal uses, and nothing else
    assert macalias._REMOVAL_ITEMS == ("state_dir", "neighbors_lock", "cache_file", "lock_file", "arpcache",
                                       "update_lock")
    assert set(macalias._REMOVAL_ITEMS) < set(table)
    # every item is one problems() can list
    assert set(table) <= set(macalias._REFUSAL_CODE) | set(macalias._ADVISORY_ITEMS)
    # these never stop the tick: what only a flush uses, the flush's own lock among it
    for item in ("md5_marker", "targeted_mode", "last_file", "plugin_lock", "alias_name", "alias_ttl"):
        assert item not in table
        for removing in (False, True):
            assert _refuses(item, item not in macalias._ADVISORY_ITEMS, removing) is None
    for item, code in table.items():
        own = item in macalias._ADVISORY_ITEMS
        # an item of the neighbor addresses' own stops the tick as it is; one of the flush's only in the form that
        # blocks a flush, so a cache that is merely not root's regular file is left for the tick to find unreadable
        assert _refuses(item, not own) == {"error": code, "detail": "p"}
        if not own:
            assert _refuses(item, False) is None
        assert _refuses(item, not own, True) == ({"error": code, "detail": "p"} if item in macalias._REMOVAL_ITEMS
                                                else None)
    assert macalias.neighbors_refusal([]) is None
    found = [
        {"item": "neighbors_setting", "problem": "a", "blocks_flush": False},
        {"item": "alias_ttl", "problem": "b", "blocks_flush": False},
        {"item": "ndp", "problem": "c", "blocks_flush": False},
        {"item": "lock_file", "problem": "d", "blocks_flush": True},
        {"item": "cache_file", "problem": "e", "blocks_flush": False},
    ]
    # the first class wins and every stopping text is carried
    assert macalias.neighbors_refusal(found) == {"error": "lock_unusable", "detail": "a; c; d"}
    assert macalias.neighbors_refusal(found, True) == {"error": "lock_unusable", "detail": "d"}


CONTRACT_CHANGES = [
    ("neighbor_merge", "cls._data.update(cls.current_cache())"),
    ("neighbor_merge", "if cls._now - cls._data[macaddr]['last_seen'] > cls._address_ttl:"),
    ("neighbor_merge", "if macaddr.startswith(pattern.lower()):"),
    ("neighbor_merge", "for item in self._data[macaddr]['items']:"),
    ("arpcache", "/tmp/alias_filter_arp.cache"),
    ("update_lock", "/tmp/filter_update_tables.lock"),
    ("list_hosts", None),
]
CONTRACT_IDS = ["replace", "expiry", "prefix-match", "items", "cache-path", "lock-path", "list-hosts"]


def _change_core(cfg, item, change):
    if change is None:
        _core(cfg, item).chmod(0o644)
    else:
        _fix_core(cfg, item, change)


@pytest.mark.parametrize("item, change", CONTRACT_CHANGES, ids=CONTRACT_IDS)
def test_neighbors_contract_failure_removes_nothing(env, item, change):
    # with the setting on a refused tick adds nothing and removes nothing
    cfg, tmp = env
    _change_core(cfg, item, change)
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    _seed(tmp, {_nkey("2001:db8::8"): _nentry("2001:db8::8", 4000.0)})
    before = _file_id(tmp / "arp.cache")
    out = _tick(cfg)
    assert out["error"] == "core_changed"
    if item == "neighbor_merge":
        path = "/usr/local/opnsense/" + CORE_FILES[item]
        problem = {"item": item, "problem": NEIGHBOR_DRIFT % (path, repr(change)), "blocks_flush": False}
        assert out == {"error": "core_changed", "detail": problem["problem"]}
        assert _items(macalias.cmd_status(cfg, now=0.0), item) == [problem]
        # the neighbor contract is advisory for a flush
        assert macalias.refusal(macalias.problems(cfg)) is None
    assert _file_id(tmp / "arp.cache") == before
    assert not (tmp / "ndp_args").exists()


@pytest.mark.parametrize("item, change", CONTRACT_CHANGES, ids=CONTRACT_IDS)
def test_neighbors_off_removes_whatever_the_merge_is_refused_for(env, item, change):
    # the switch works when the user is most likely to reach for it, after core changed: off removes the keys
    # unless core changed what the removal itself writes through (its cache's path and format, its lock)
    cfg, tmp = env
    (tmp / "macaliascache.conf").write_text("[general]\nneighbors=0\n")
    _change_core(cfg, item, change)
    _seed(tmp, {_nkey("2001:db8::8"): _nentry("2001:db8::8", 4000.0)})
    before = _file_id(tmp / "arp.cache")
    out = _tick(cfg)
    if item in ("arpcache", "update_lock"):
        assert out["error"] == "core_changed"
        assert _file_id(tmp / "arp.cache") == before
    else:
        assert out == _ok(changed=True, removed=1)
        assert _cache(tmp) == OWN
    assert not (tmp / "ndp_args").exists()


def test_neighbors_off_removes_without_the_neighbor_table_the_alias_table_or_the_record(env, monkeypatch):
    cfg, tmp = env
    (tmp / "macaliascache.conf").write_text("[general]\nneighbors=0\n")
    _seed(tmp, {_nkey("2001:db8::8"): _nentry("2001:db8::8", 4000.0)})
    pathlib.Path(cfg["ndp"][0]).chmod(0o644)
    (tmp / "filter_tables.conf").write_text("<tabledef><table>")
    os.mkdir(cfg["state_dir"], 0o700)
    _neighbors_file(cfg).mkdir()
    os.mkdir(macalias.state_paths(cfg)["plugin_lock"])
    monkeypatch.setattr(macalias, "read_tables", lambda cfg_: pytest.fail("the alias table read"))
    assert _tick(cfg) == _ok(changed=True, removed=1)
    assert _cache(tmp) == OWN


@pytest.mark.parametrize("item", ["md5_marker", "targeted_mode", "last_file", "plugin_lock", "alias_name", "alias_ttl"])
def test_neighbors_tick_runs_with_a_problem_that_is_the_flushs_alone(env, item):
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    if item in ("md5_marker", "targeted_mode"):
        _core(cfg, item).unlink()
    elif item == "last_file":
        os.mkdir(cfg["state_dir"], 0o700)
        _last(cfg).mkdir()
    elif item == "plugin_lock":
        os.mkdir(cfg["state_dir"], 0o700)
        os.mkfifo(macalias.state_paths(cfg)["plugin_lock"])
    elif item == "alias_name":
        (tmp / "filter_tables.conf").write_text(BAD_NAME_TABLES)
    else:
        _devmacs_ttl(tmp, "0")
    assert [p["item"] for p in macalias.problems(cfg)] == [item]
    assert _tick(cfg) == _ok(changed=True, added=1, keys=1, samples=["2001:db8::7"])


def test_neighbors_logs_only_on_change(env, logged):
    cfg, tmp = env
    lines, idents = logged
    notice, warning = macalias.syslog.LOG_NOTICE, macalias.syslog.LOG_WARNING
    addresses = ["2001:db8::%x" % n for n in range(1, 8)]
    _neighbor_table(tmp, [(NMAC, ip) for ip in addresses])
    now = 5000.0
    assert _tick(cfg, now=now)["added"] == 7
    assert lines == [(notice, "neighbors: 7 added (%s), 0 removed" % ", ".join(addresses[:5]))]
    assert idents == ["macaliascache"]
    del lines[:]
    # the unchanged minutes, and the hourly write that keeps the keys alive: nothing
    for now in (5060.0, 5120.0, 5000.0 + 3601):
        assert _tick(cfg, now=now)["result"] == "ok"
    assert _cache(tmp)[_nkey(addresses[0])] == _nentry(addresses[0], 8601.0)
    assert lines == []
    # a result other than ok that is over within ten minutes is no state: recorded, never logged
    good_hosts = cfg["list_hosts"]
    cfg["list_hosts"] = [_exe(tmp / "bad_hosts", "exit 1\n"), "-n"]
    for now in (8700.0, 8760.0, 8700.0 + 599):
        assert _tick(cfg, now=now) == HOSTS_UNAVAILABLE
    assert _state(cfg) == ("hosts_unavailable", 8700.0, False)
    cfg["list_hosts"] = good_hosts
    assert _tick(cfg, now=9300.0) == _ok(keys=7)
    assert _state(cfg) == ("ok", 9300.0, False)
    assert lines == []
    # one that lasts ten minutes is logged once, whatever codes it passes through, and its end once
    cfg["list_hosts"] = [_exe(tmp / "bad_hosts", "exit 1\n"), "-n"]
    assert _tick(cfg, now=10000.0) == HOSTS_UNAVAILABLE
    pathlib.Path(cfg["ndp"][0]).chmod(0o644)
    assert _tick(cfg, now=10300.0)["error"] == "core_changed"
    assert _state(cfg) == ("core_changed", 10000.0, False)
    assert lines == []
    assert _tick(cfg, now=10600.0)["error"] == "core_changed"
    assert lines == [(warning, "neighbors: core_changed for 600 s: " + NDP_MISSING % cfg["ndp"][0])]
    assert _state(cfg) == ("core_changed", 10000.0, True)
    del lines[:]
    pathlib.Path(cfg["ndp"][0]).chmod(0o755)
    for now in (10660.0, 14000.0, 17000.0):
        assert _tick(cfg, now=now) == HOSTS_UNAVAILABLE
    assert _state(cfg) == ("hosts_unavailable", 10000.0, True)
    assert lines == []
    cfg["list_hosts"] = good_hosts
    # the keys were last written at 8601, more than an hour before: the first working tick writes them again
    assert _tick(cfg, now=17060.0) == _ok(changed=True, refreshed=7, keys=7)
    assert _tick(cfg, now=17120.0) == _ok(keys=7)
    assert lines == [(notice, "neighbors: working again after hosts_unavailable")]
    assert _state(cfg) == ("ok", 17060.0, False)
    del lines[:]
    # an address host discovery now lists itself leaves, and one arrives
    _list_hosts(cfg, tmp, [["vlan0.120", NMAC, "192.0.2.50"], ["vlan0.120", NMAC, addresses[0]]])
    _neighbor_table(tmp, [(NMAC, ip) for ip in addresses + ["2001:db8::99"]])
    assert _tick(cfg, now=17180.0) == _ok(changed=True, added=1, removed=1, keys=7, samples=["2001:db8::99"])
    assert lines == [(notice, "neighbors: 1 added (2001:db8::99), 1 removed")]
    del lines[:]
    (tmp / "macaliascache.conf").write_text("[general]\nneighbors=0\n")
    assert _tick(cfg, now=17240.0) == _ok(changed=True, removed=7)
    assert lines == [(notice, "neighbors: 0 added, 7 removed")]
    assert all(len(message) < 400 for _priority, message in lines)


def test_neighbors_a_failure_that_cannot_be_recorded_is_never_logged(env, logged):
    # the record is what says a line was written: with none, the tick stays quiet rather than log each minute
    cfg, tmp = env
    os.mkdir(cfg["state_dir"], 0o700)
    _neighbors_file(cfg).mkdir()
    for now in (5000.0, 5600.0, 6200.0, 9000.0):
        assert _tick(cfg, now=now)["error"] == "state_unusable"
    assert logged[0] == []


def test_neighbors_clock_step_back_restarts_the_ten_minutes(env, logged):
    cfg, tmp = env
    cfg["list_hosts"] = [_exe(tmp / "bad_hosts", "exit 1\n"), "-n"]
    assert _tick(cfg, now=5000.0) == HOSTS_UNAVAILABLE
    assert _tick(cfg, now=1000.0) == HOSTS_UNAVAILABLE
    assert _state(cfg) == ("hosts_unavailable", 1000.0, False)
    assert _tick(cfg, now=1599.0) == HOSTS_UNAVAILABLE
    assert logged[0] == []
    assert _tick(cfg, now=1600.0) == HOSTS_UNAVAILABLE
    assert len(logged[0]) == 1


@pytest.mark.parametrize("failing", ["openlog", "syslog"])
def test_neighbors_syslog_failure_never_changes_the_reply(env, monkeypatch, failing):
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])

    def broken(*args, **kwargs):
        raise OSError("no syslog socket")

    monkeypatch.setattr(macalias.syslog, failing, broken)
    assert _tick(cfg) == _ok(changed=True, added=1, keys=1, samples=["2001:db8::7"])
    assert _neighbors_record(cfg)["added"] == 1
    _locks_free(cfg)


def test_neighbors_record_schema_and_mode(env):
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7"), (NMAC, "2001:db8::8")])
    assert _tick(cfg, now=5000.0)["added"] == 2
    record = {"at": 5000.0, "result": "ok", "since": 5000.0, "reported": False, "added": 2, "removed": 0,
              "refreshed": 0, "keys": 2, "over_limit": 0, "samples": ["2001:db8::7", "2001:db8::8"]}
    assert _neighbors_record(cfg) == record == lib.neighbors_schema(record)
    modes = {p.name: stat.S_IMODE(os.lstat(p).st_mode) for p in pathlib.Path(cfg["state_dir"]).iterdir()}
    assert modes == {"neighbors.json": 0o600, "neighbors.lock": 0o600}
    # an unchanged minute leaves the record; the first tick after an hour writes it again, so its age says
    # whether the tick runs, with or without a key to refresh
    kept = _file_id(_neighbors_file(cfg))
    assert _tick(cfg, now=5000.0 + 3600) == _ok(keys=2)
    assert _file_id(_neighbors_file(cfg)) == kept
    (tmp / "macaliascache.conf").write_text("[general]\nneighbors=0\n")
    assert _tick(cfg, now=6000.0) == _ok(changed=True, removed=2)
    assert _neighbors_record(cfg) == dict(record, at=6000.0, added=0, removed=2, keys=0, samples=[])
    assert _tick(cfg, now=6000.0 + 3600) == _ok()
    assert _neighbors_record(cfg)["at"] == 6000.0
    assert _tick(cfg, now=6000.0 + 3601) == _ok()
    assert _neighbors_record(cfg) == dict(record, at=9601.0, added=0, keys=0, samples=[])
    # a record from the future (a clock step) is replaced
    assert _tick(cfg, now=100.0) == _ok()
    assert (_neighbors_record(cfg)["at"], _neighbors_record(cfg)["since"]) == (100.0, 100.0)
    assert stat.S_IMODE(os.lstat(_neighbors_file(cfg)).st_mode) == 0o600
    assert _no_temps(cfg, tmp)


def test_neighbors_first_tick_with_nothing_to_do_records_that_it_ran(env):
    cfg, tmp = env
    assert _tick(cfg, now=5000.0) == _ok()
    assert _neighbors_record(cfg) == {"at": 5000.0, "result": "ok", "since": 5000.0, "reported": False, "added": 0,
                                      "removed": 0, "refreshed": 0, "keys": 0, "over_limit": 0, "samples": []}


def test_neighbors_record_of_a_refusal(env):
    cfg, tmp = env
    _seed(tmp, {_nkey("2001:db8::8"): _nentry("2001:db8::8", 4000.0)})
    cfg["list_hosts"] = [_exe(tmp / "bad_hosts", "exit 1\n"), "-n"]
    assert _tick(cfg, now=5000.0) == HOSTS_UNAVAILABLE
    assert _neighbors_record(cfg) == {"at": 5000.0, "result": "hosts_unavailable", "since": 5000.0, "reported": False,
                                      "added": 0, "removed": 0, "refreshed": 0, "keys": 0, "over_limit": 0,
                                      "samples": []}
    kept = _file_id(_neighbors_file(cfg))
    assert _tick(cfg, now=5060.0) == HOSTS_UNAVAILABLE
    assert _file_id(_neighbors_file(cfg)) == kept


def test_neighbors_record_follows_the_count_the_limit_cut(env):
    # status reads the count from the record, so a minute in which only that count changes writes it
    cfg, tmp = env
    addresses = ["2001:db8::%x" % n for n in range(1, 41)]
    _neighbor_table(tmp, [(NMAC, ip) for ip in addresses[:32]])
    assert _tick(cfg, now=5000.0) == _ok(changed=True, added=32, keys=32, samples=addresses[:5])
    _neighbor_table(tmp, [(NMAC, ip) for ip in addresses])
    assert _tick(cfg, now=5060.0) == _ok(keys=32, over_limit=8)
    assert (_neighbors_record(cfg)["at"], _neighbors_record(cfg)["over_limit"]) == (5060.0, 8)
    assert macalias.cmd_status(cfg, now=5090.0)["neighbors"]["over_limit"] == 8
    kept = _file_id(_neighbors_file(cfg))
    assert _tick(cfg, now=5120.0) == _ok(keys=32, over_limit=8)
    assert _file_id(_neighbors_file(cfg)) == kept
    _neighbor_table(tmp, [(NMAC, ip) for ip in addresses[:32]])
    assert _tick(cfg, now=5180.0) == _ok(keys=32)
    assert macalias.cmd_status(cfg, now=5190.0)["neighbors"]["over_limit"] == 0


def test_neighbors_an_unexpected_error_is_a_recorded_result_and_never_raised(env, monkeypatch, logged):
    # cron mails what a job prints on stderr, and configd wants JSON: an alias table file that cannot be parsed,
    # or anything else unforeseen, is the result "internal"
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    (tmp / "filter_tables.conf").write_text("<tabledef><table>")
    before = _file_id(tmp / "arp.cache")
    out = _tick(cfg, now=5000.0)
    assert out["error"] == "internal" and out["detail"].startswith("ParseError: ") and set(out) == {"error", "detail"}
    assert _state(cfg) == ("internal", 5000.0, False)
    assert _file_id(tmp / "arp.cache") == before
    (tmp / "filter_tables.conf").unlink()
    out = _tick(cfg, now=5600.0)
    assert out["error"] == "internal" and out["detail"].startswith("FileNotFoundError: ")
    assert len(logged[0]) == 1
    assert logged[0][0][1].startswith("neighbors: internal for 600 s: FileNotFoundError: ")
    _locks_free(cfg)
    (tmp / "filter_tables.conf").write_text(TABLES)

    # an error before the tick has its lock is answered the same way
    def broken(cfg_):
        raise RuntimeError("no state")

    monkeypatch.setattr(macalias, "ensure_state_dir", broken)
    assert _tick(cfg, now=5660.0) == {"error": "internal", "detail": "RuntimeError: no state"}


def test_neighbors_record_that_cannot_be_written_leaves_the_reply_and_the_log_line(env, monkeypatch, logged):
    # core's cache is written by then: the reply says so and the line is logged, with no record to show for it
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    real_write = macalias._write_json_atomic

    def write(path, *args, **kwargs):
        if path == str(_neighbors_file(cfg)):
            raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC), path)
        return real_write(path, *args, **kwargs)

    monkeypatch.setattr(macalias, "_write_json_atomic", write)
    assert _tick(cfg) == _ok(changed=True, added=1, keys=1, samples=["2001:db8::7"])
    assert not _neighbors_file(cfg).exists()
    assert [message for _priority, message in logged[0]] == ["neighbors: 1 added (2001:db8::7), 0 removed"]
    _locks_free(cfg)


@pytest.mark.parametrize("content", ["{", "[]", '{"at": "5000", "result": "ok"}',
                                     '{"at": 4000.0, "result": "ok", "added": 1, "removed": 0, "refreshed": 0, '
                                     '"keys": 1, "over_limit": 0, "samples": "2001:db8::1"}'],
                         ids=["cut-short", "list", "at-string", "samples-string"])
def test_neighbors_record_of_another_shape_is_ignored_and_replaced(env, logged, content):
    cfg, tmp = env
    os.mkdir(cfg["state_dir"], 0o700)
    _neighbors_file(cfg).write_text(content)
    _neighbors_file(cfg).chmod(0o600)
    assert _tick(cfg, now=5000.0) == _ok()
    assert _neighbors_record(cfg)["at"] == 5000.0
    assert logged[0] == []


def test_neighbors_sweeps_its_stale_temp_files(env):
    # orphans of a tick killed between mkstemp and os.replace: the cache's when the cache is written, the record's
    # when the record is
    cfg, tmp = env
    os.mkdir(cfg["state_dir"], 0o700)
    stale = [tmp / ".arp.cache.old.tmp", pathlib.Path(cfg["state_dir"]) / ".neighbors.json.old.tmp"]
    fresh = [tmp / ".arp.cache.new.tmp", pathlib.Path(cfg["state_dir"]) / ".neighbors.json.new.tmp"]
    for path in stale + fresh:
        path.write_text("x")
    for path in stale:
        os.utime(path, (5000.0 - 120, 5000.0 - 120))
    for path in fresh:
        os.utime(path, (5000.0, 5000.0))
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    assert _tick(cfg, now=5000.0)["added"] == 1
    assert [path.exists() for path in stale] == [False, False]
    assert [path.exists() for path in fresh] == [True, True]


@pytest.mark.parametrize("kind", ["directory", "cannot-check"])
def test_neighbors_record_that_cannot_be_replaced_refuses(env, monkeypatch, logged, kind):
    cfg, tmp = env
    os.mkdir(cfg["state_dir"], 0o700)
    path = _neighbors_file(cfg)
    if kind == "directory":
        path.mkdir()
        text = NEIGHBORS_DIRECTORY % path
    else:
        real_lstat = os.lstat

        def lstat(arg, *args, **kwargs):
            if os.fspath(arg) == str(path):
                raise OSError(errno.EACCES, os.strerror(errno.EACCES), arg)
            return real_lstat(arg, *args, **kwargs)

        monkeypatch.setattr(macalias.os, "lstat", lstat)
        text = "plugin neighbor record at %s cannot be checked (%s)" % (path, os.strerror(errno.EACCES))
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    before = _file_id(tmp / "arp.cache")
    problem = {"item": "neighbors_file", "problem": text, "blocks_flush": False}
    assert _items(macalias.cmd_status(cfg, now=0.0), "neighbors_file") == [problem]
    assert _tick(cfg) == {"error": "state_unusable", "detail": text}
    assert _file_id(tmp / "arp.cache") == before
    # the tick cannot record its state, so it never logs it: status shows the problem
    assert logged[0] == []
    assert "error" not in _flush(cfg)


@pytest.mark.parametrize("kind", ["symlink", "regular-file", "foreign-owner"])
def test_neighbors_state_dir_unusable_refuses_and_logs_nothing(env, monkeypatch, logged, kind):
    cfg, tmp = env
    if kind == "symlink":
        (tmp / "elsewhere").mkdir(mode=0o700)
        os.symlink(tmp / "elsewhere", cfg["state_dir"])
    elif kind == "regular-file":
        pathlib.Path(cfg["state_dir"]).write_text("x")
    else:
        os.mkdir(cfg["state_dir"], 0o700)
        _patch_stat(monkeypatch, "fstat", cfg["state_dir"], _UID, os.geteuid() + 1)
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    before = _file_id(tmp / "arp.cache")
    for now in (5000.0, 5060.0):
        out = _tick(cfg, now=now)
        assert out["error"] == "state_unusable" and cfg["state_dir"] in out["detail"]
        assert set(out) == {"error", "detail"}
    assert _file_id(tmp / "arp.cache") == before
    assert not (tmp / "ndp_args").exists()
    assert logged[0] == []
    if kind == "symlink":
        assert list((tmp / "elsewhere").iterdir()) == []


@pytest.mark.parametrize("kind", ["directory", "symlink", "fifo", "hard-link"])
def test_neighbors_refuses_when_its_lock_is_not_a_regular_file(env, logged, kind):
    cfg, tmp = env
    os.makedirs(cfg["state_dir"], 0o700, exist_ok=True)
    path = macalias.state_paths(cfg)["neighbors_lock"]
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
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    before = _file_id(tmp / "arp.cache")
    with _within(5):
        status = macalias.cmd_status(cfg, now=0.0)
        out = _tick(cfg)
        unchanged = _file_id(tmp / "arp.cache") == before
        flushed = _flush(cfg)
    # status names the tick's lock under an item of its own, and it is no obstacle to a flush
    assert status["problems"] == [
        {"item": "neighbors_lock", "problem": NEIGHBORS_LOCK_NOT_REGULAR % path, "blocks_flush": False}]
    assert out == {"error": "state_unusable",
                   "detail": NEIGHBORS_LOCK_NOT_REGULAR % path + " that the plugin can open safely"}
    assert unchanged
    assert "error" not in flushed
    # the state directory itself is usable, so the result is recorded
    assert _state(cfg) == ("state_unusable", 5000.0, False)
    assert logged[0] == []
    assert elsewhere.read_text() == ""


def test_neighbors_refuses_on_what_the_flush_refuses_for_the_state_and_the_lock(env):
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    os.mkfifo(cfg["lock_file"])
    with _within(5):
        assert _tick(cfg) == {"error": "lock_unusable", "detail": LOCK_NOT_REGULAR % cfg["lock_file"]}
    os.unlink(cfg["lock_file"])
    (tmp / "arp.cache").unlink()
    (tmp / "arp.cache").mkdir()
    assert _tick(cfg) == {"error": "state_unusable", "detail": CACHE_DIRECTORY % cfg["cache_file"]}
    (tmp / "arp.cache").rmdir()
    _seed(tmp, {})
    assert _tick(cfg, now=5060.0)["added"] == 1


def test_neighbors_flush_lock_is_not_the_ticks(env):
    # two locks, two items: a flush lock that cannot be used stops the flush and not the tick
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    os.mkdir(cfg["state_dir"], 0o700)
    os.mkdir(macalias.state_paths(cfg)["plugin_lock"])
    assert [(p["item"], p["blocks_flush"]) for p in macalias.problems(cfg)] == [("plugin_lock", True)]
    assert _flush(cfg)["error"] == "state_unusable"
    assert _tick(cfg) == _ok(changed=True, added=1, keys=1, samples=["2001:db8::7"])
    assert macalias.cmd_status(cfg, now=5030.0)["neighbors"]["active"] is True


@pytest.mark.parametrize("kind", ["symlink", "hard-link", "foreign-owner", "fifo"])
def test_neighbors_cache_it_cannot_read_safely_is_cache_unreadable(env, monkeypatch, logged, kind):
    # a second link to core's cache is one command for any local account: it must not turn the tick off with no
    # trace. The tick does not merge into such a cache, says so as a result that is recorded and reported like
    # any other, and a flush, which replaces the file, is the remedy
    cfg, tmp = env
    cache = tmp / "arp.cache"
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    if kind == "symlink":
        cache.rename(tmp / "real.cache")
        os.symlink(tmp / "real.cache", cache)
    elif kind == "fifo":
        cache.unlink()
        os.mkfifo(cache)
    else:
        field, value = (_NLINK, 2) if kind == "hard-link" else (_UID, os.geteuid() + 1)
        _patch_stat(monkeypatch, "lstat", cache, field, value)
        _patch_stat(monkeypatch, "fstat", cache, field, value)
    with _within(10):
        assert [(p["item"], p["blocks_flush"]) for p in macalias.problems(cfg)] == [("cache_file", False)]
        for now in (5000.0, 5300.0, 5600.0):
            assert _tick(cfg, now=now) == {"error": "cache_unreadable", "detail": CACHE_UNREADABLE % cfg["cache_file"]}
    assert _state(cfg) == ("cache_unreadable", 5000.0, True)
    assert [message for _priority, message in logged[0]] == [
        "neighbors: cache_unreadable for 600 s: " + CACHE_UNREADABLE % cfg["cache_file"]]
    if kind == "symlink":
        assert json.loads((tmp / "real.cache").read_text()) == OWN
    with _within(10):
        assert "error" not in macalias.cmd_flush(cfg, clock=lambda: 5700.0, sleep=lambda s: None)
    assert stat.S_ISREG(os.lstat(cache).st_mode)
    assert _tick(cfg, now=5760.0)["result"] == "ok"
    assert logged[0][-1][1] == "neighbors: working again after cache_unreadable"
    _locks_free(cfg)


def test_neighbors_core_lock_that_turns_unusable_after_the_check_refuses(env, monkeypatch):
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    pathlib.Path(cfg["lock_file"]).write_text("")
    _patch_stat(monkeypatch, "fstat", cfg["lock_file"], _NLINK, 2)
    before = _file_id(tmp / "arp.cache")
    out = _tick(cfg)
    assert out["error"] == "lock_unusable" and set(out) == {"error", "detail"}
    assert _file_id(tmp / "arp.cache") == before
    _locks_free(cfg)


def test_neighbors_foreign_keys_untouched(env):
    # everything in core's cache that is not a key of ours is written back as it was read, whatever its shape
    cfg, tmp = env
    foreign = {
        "dd:ee:ff:00:00:03": {"items": ["192.0.2.77", "2001:db8::77"], "last_seen": 4321.5},
        NMAC: {"items": ["192.0.2.50", "2001:db8::50"], "last_seen": 1000.0},
        "AA:BB:CC:00:00:01": {"items": ["192.0.2.51"], "last_seen": 1000},
        "AA:BB:CC:00:00:01#2001:db8::9": {"items": ["2001:db8::9"], "last_seen": 1000.0},
        "aa:bb:cc:00:00:01#2001:DB8::9": {"items": ["2001:db8::9"], "last_seen": 1000.0},
        "aa:bb:cc:00:00:01#192.0.2.9": {"items": ["192.0.2.9"], "last_seen": 1000.0},
        "odd": {"items": "192.0.2.5", "extra": [1, None, {"a": True}]},
        "": 5,
    }
    cache = dict(foreign)
    cache[_nkey("2001:db8::50")] = _nentry("2001:db8::50", 4000.0)
    cache[_nkey("2001:db8::8")] = _nentry("2001:db8::8", 1000.0)
    (tmp / "arp.cache").write_text(json.dumps(cache))
    _list_hosts(cfg, tmp, [["vlan0.120", NMAC, "192.0.2.50"], ["vlan0.120", NMAC, "2001:db8::50"]])
    _neighbor_table(tmp, [(NMAC, "2001:db8::7"), (NMAC, "2001:db8::8"), (NMAC, "2001:db8::50")])
    assert _tick(cfg) == _ok(changed=True, added=1, removed=1, refreshed=1, keys=2, samples=["2001:db8::7"])
    after = _cache(tmp)
    assert {name: after[name] for name in foreign} == foreign
    assert list(after)[:len(foreign)] == list(foreign)
    assert {name: value for name, value in after.items() if name not in foreign} == {
        _nkey("2001:db8::7"): _nentry("2001:db8::7", 5000.0), _nkey("2001:db8::8"): _nentry("2001:db8::8", 5000.0)}


def test_neighbors_moved_address_is_removed(env):
    cfg, tmp = env
    _seed(tmp, {_nkey("2001:db8::7"): _nentry("2001:db8::7", 4990.0),
                _nkey("2001:db8::8"): _nentry("2001:db8::8", 4990.0)})
    _neighbor_table(tmp, [("dd:ee:ff:00:00:03", "2001:db8::7")])
    assert _tick(cfg) == _ok(changed=True, removed=1, keys=1)
    assert _cache(tmp) == dict(OWN, **{_nkey("2001:db8::8"): _nentry("2001:db8::8", 4990.0)})


def test_neighbors_limits_reach_the_reply_and_the_record(env):
    cfg, tmp = env
    addresses = ["2001:db8::%x" % n for n in range(1, 41)]
    _neighbor_table(tmp, [(NMAC, ip) for ip in addresses])
    out = _tick(cfg)
    assert out == _ok(changed=True, added=32, keys=32, over_limit=8, samples=addresses[:5])
    assert sorted(_cache(tmp)) == sorted([NMAC] + [_nkey(ip) for ip in addresses[:32]])
    assert _neighbors_record(cfg)["over_limit"] == 8
    # the same choice the next minute: nothing to write
    assert _tick(cfg, now=5060.0) == _ok(keys=32, over_limit=8)


def test_neighbors_nothing_run_under_core_lock(env, monkeypatch):
    # hosts and neighbors are the ones read before the lock: under core's lock the tick reads the cache and
    # writes it, and runs no program
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    events = []
    real_popen = subprocess.Popen
    real_acquire, real_unlock = macalias.acquire_lock, macalias._unlock
    core_locks = []

    class Popen(real_popen):
        def __init__(self, argv, *args, **kwargs):
            events.append("run " + os.path.basename(argv[0]))
            super().__init__(argv, *args, **kwargs)

    def acquire(*args, **kwargs):
        lock = real_acquire(*args, **kwargs)
        core_locks.append(lock)
        events.append("lock")
        return lock

    def unlock(handle):
        if handle in core_locks:
            events.append("unlock")
        return real_unlock(handle)

    monkeypatch.setattr(macalias.subprocess, "Popen", Popen)
    monkeypatch.setattr(macalias, "acquire_lock", acquire)
    monkeypatch.setattr(macalias, "_unlock", unlock)
    assert _tick(cfg)["added"] == 1
    assert events == ["run list_hosts.py", "run ndp", "lock", "unlock"]


@pytest.mark.parametrize("case", ["added", "unchanged", "busy", "hosts_unavailable", "neighbors_unavailable",
                                  "cache_unreadable", "core_changed", "raises"])
def test_neighbors_releases_its_locks_after_every_exit(env, monkeypatch, case):
    cfg, tmp = env
    held = None
    if case != "unchanged":
        _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    if case == "busy":
        held = open(cfg["lock_file"], "a")
        fcntl.flock(held, fcntl.LOCK_EX)
    elif case == "hosts_unavailable":
        cfg["list_hosts"] = [_exe(tmp / "bad_hosts", "exit 1\n"), "-n"]
    elif case == "neighbors_unavailable":
        (tmp / "ndp.json").write_text("x")
    elif case == "cache_unreadable":
        (tmp / "arp.cache").write_text("")
    elif case == "core_changed":
        _core(cfg, "arpcache").unlink()
    elif case == "raises":
        def broken(path, *args, **kwargs):
            raise OSError(errno.ENOSPC, os.strerror(errno.ENOSPC), path)

        monkeypatch.setattr(macalias, "_write_json_atomic", broken)
    out = _tick(cfg)
    assert out.get("error", "ok") == {"added": "ok", "unchanged": "ok", "raises": "internal"}.get(case, case)
    if held:
        held.close()
    _locks_free(cfg)


def test_neighbors_problems_and_core_files_join_the_tables(env):
    cfg, tmp = env
    assert macalias.DEFAULTS["core_files"]["neighbor_merge"] == macalias.DEFAULTS["core_files"]["arpcache"]
    # the file is read once for its three items
    reads = []
    real_read_text = macalias._read_text

    def read_text(path):
        reads.append(path)
        return real_read_text(path)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(macalias, "_read_text", read_text)
        texts = macalias.read_core_texts(cfg)
    assert texts["neighbor_merge"] == texts["arpcache"] == texts["cache_expiry"]
    assert reads.count(cfg["core_files"]["arpcache"]) == 1
    # a missing arpcache.py is arpcache's problem alone, and stops the tick as core_changed
    _core(cfg, "arpcache").unlink()
    assert [p["item"] for p in macalias.problems(cfg)] == ["arpcache"]
    assert _tick(cfg)["error"] == "core_changed"


# the neighbor table in a flush and in status

SEEDED = {NMAC: {"items": ["192.0.2.50"], "last_seen": 5000.0}}
SETTING_ABSENT_NOTE = "the plugin's settings file at %s is absent, so the default is used: the neighbor table is on"


def test_flush_keeps_wanted_neighbors(env):
    # a flush rebuilds from current data, and the neighbor table is current data: an address it lists for a
    # listed MAC stays, with the choice the tick would make; a key no table lists any more goes like every
    # stale entry
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7"), (NMAC, "fe80::7"), ("dd:ee:ff:00:00:03", "2001:db8::3")])
    _seed(tmp, {_nkey("2001:db8::7"): _nentry("2001:db8::7", 1000.0),
                _nkey("2001:db8::9"): _nentry("2001:db8::9", 4990.0)})
    out = _flush(cfg)
    assert "error" not in out
    assert out["neighbors"] == {"added": 2, "over_limit": 0}
    assert _cache(tmp) == dict(SEEDED, **{_nkey("2001:db8::7"): _nentry("2001:db8::7", 5000.0),
                                          _nkey("fe80::7"): _nentry("fe80::7", 5000.0)})
    assert (tmp / "update_args").read_text().split() == ["--aliases", "DevMacs,Parent"]
    # nothing is left for the tick to do, and the flush wrote no record of the tick's
    assert not _neighbors_file(cfg).exists()
    assert _tick(cfg, now=5060.0) == _ok(keys=2)


def test_flush_skips_a_neighbor_address_host_discovery_lists(env):
    cfg, tmp = env
    _list_hosts(cfg, tmp, [["vlan0.120", NMAC, "192.0.2.50"], ["vlan0.120", NMAC, "2001:DB8::7"]])
    _neighbor_table(tmp, [(NMAC, "2001:db8::7"), (NMAC, "2001:db8::8")])
    out = _flush(cfg)
    assert out["neighbors"] == {"added": 1, "over_limit": 0}
    assert _cache(tmp) == {NMAC: {"items": ["192.0.2.50", "2001:DB8::7"], "last_seen": 5000.0},
                           _nkey("2001:db8::8"): _nentry("2001:db8::8", 5000.0)}


def test_flush_keeps_the_held_keys_over_the_limit(env):
    cfg, tmp = env
    addresses = ["2001:db8::%x" % n for n in range(1, 41)]
    _neighbor_table(tmp, [(NMAC, ip) for ip in addresses])
    _seed(tmp, {_nkey(ip): _nentry(ip, 4000.0) for ip in addresses[37:]})
    out = _flush(cfg)
    assert out["neighbors"] == {"added": 32, "over_limit": 8}
    assert sorted(_cache(tmp)) == sorted([NMAC] + [_nkey(ip) for ip in addresses[:29] + addresses[37:]])


def test_flush_reads_neighbors_before_core_lock(env, monkeypatch):
    # and before any side effect: the cache write, the expiry marks and core's update all come after
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    events = []
    real_popen = subprocess.Popen
    real_acquire, real_write = macalias.acquire_lock, macalias._write_json_atomic

    class Popen(real_popen):
        def __init__(self, argv, *args, **kwargs):
            events.append("run " + os.path.basename(argv[0]))
            super().__init__(argv, *args, **kwargs)

    def acquire(*args, **kwargs):
        events.append("lock")
        return real_acquire(*args, **kwargs)

    def write(path, *args, **kwargs):
        events.append("write " + os.path.basename(path))
        return real_write(path, *args, **kwargs)

    monkeypatch.setattr(macalias.subprocess, "Popen", Popen)
    monkeypatch.setattr(macalias, "acquire_lock", acquire)
    monkeypatch.setattr(macalias, "_write_json_atomic", write)
    out = _flush(cfg)
    assert out["neighbors"] == {"added": 1, "over_limit": 0}
    assert events[:3] == ["run ndp", "lock", "run list_hosts.py"]
    assert events.count("run ndp") == 1
    assert events.index("write arp.cache") > events.index("lock")


@pytest.mark.parametrize("body", ["exit 1\n", "echo not-json\n", "echo '{\"ndp\": []}'\n"],
                         ids=["fails", "non-json", "other-shape"])
def test_flush_neighbors_unreadable_flushes_as_before(env, body):
    cfg, tmp = env
    cfg["ndp"] = [_exe(tmp / "bad_ndp", body), "-an", "--libxo", "json"]
    _seed(tmp, {_nkey("2001:db8::7"): _nentry("2001:db8::7", 4990.0)})
    out = _flush(cfg)
    assert "error" not in out
    assert out["neighbors"] == {"skipped": "neighbors_unavailable"}
    assert _cache(tmp) == SEEDED
    assert out["update_tables"] == UPDATE_OK


def test_flush_setting_off_drops_our_keys(env):
    cfg, tmp = env
    (tmp / "macaliascache.conf").write_text("[general]\nneighbors=0\n")
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    _seed(tmp, {_nkey("2001:db8::7"): _nentry("2001:db8::7", 4990.0)})
    out = _flush(cfg)
    assert "error" not in out
    assert out["neighbors"] == {"skipped": "off"}
    assert _cache(tmp) == SEEDED
    assert not (tmp / "ndp_args").exists()


def test_flush_setting_absent_is_on(env):
    cfg, tmp = env
    (tmp / "macaliascache.conf").unlink()
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    assert _flush(cfg)["neighbors"] == {"added": 1, "over_limit": 0}


def test_flush_host_discovery_off_adds_no_neighbor_key(env):
    # core reads the neighbor table itself then, and the flush seeds its rows as before
    cfg, tmp = env
    _arp_ndp_hosts(cfg, tmp)
    _neighbor_table(tmp, [(NMAC, "2001:db8::7"), (NMAC, "2001:db8::8")])
    out = _flush(cfg)
    assert out["neighbors"] == {"skipped": "not_discovery"}
    assert _cache(tmp) == {NMAC: {"items": ["192.0.2.50", "2001:db8::7"], "last_seen": 5000.0}}


@pytest.mark.parametrize("kind, reason", [
    ("contract", "core_changed"), ("ndp", "core_changed"), ("setting", "setting_unusable"),
    ("record", "state_unusable"),
])
def test_flush_adds_no_neighbor_key_when_the_tick_would_refuse(env, kind, reason):
    # what stops the tick is advisory for the flush: it runs, and leaves the neighbor addresses to the tick
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    if kind == "contract":
        _fix_core(cfg, "neighbor_merge", "if macaddr.startswith(pattern.lower()):")
    elif kind == "ndp":
        pathlib.Path(cfg["ndp"][0]).chmod(0o644)
    elif kind == "setting":
        (tmp / "macaliascache.conf").write_text("neighbors on\n")
    else:
        os.mkdir(cfg["state_dir"], 0o700)
        _neighbors_file(cfg).mkdir()
    out = _flush(cfg)
    assert "error" not in out
    assert out["neighbors"] == {"skipped": reason}
    assert _cache(tmp) == SEEDED
    assert not (tmp / "ndp_args").exists()


def test_flush_without_mac_aliases_reads_no_neighbor_table(env):
    cfg, tmp = env
    (tmp / "filter_tables.conf").write_text("<tabledef/>")
    assert _flush(cfg) == {"aliases": [], "note": "no mac aliases"}
    assert not (tmp / "ndp_args").exists()


def test_status_neighbors_block(env):
    cfg, tmp = env
    idle = {"enabled": True, "active": True, "keys": 0, "over_limit": 0, "last": None, "stale": False,
            "failing": None, "setting": "ok"}
    out = macalias.cmd_status(cfg, now=5000.0)
    assert out["neighbors"] == idle
    assert out["aliases"][0]["macs"][0]["neighbor_items"] == []
    # status runs no ndp and writes nothing of the tick's
    assert not (tmp / "ndp_args").exists()
    assert os.listdir(cfg["state_dir"]) == []

    addresses = ["2001:db8::%x" % n for n in range(1, 41)]
    _neighbor_table(tmp, [(NMAC, ip) for ip in addresses])
    assert _tick(cfg, now=5000.0)["added"] == 32
    out = macalias.cmd_status(cfg, now=5030.0)
    assert out["neighbors"] == dict(idle, keys=32, over_limit=8, last=_neighbors_record(cfg))
    assert out["neighbors"]["last"]["at"] == 5000.0
    mac = out["aliases"][0]["macs"][0]
    # the MAC's own entry and the plugin's keys apart; the keys are no MACs of their own
    assert [row["mac"] for row in out["aliases"][0]["macs"]] == [NMAC]
    assert mac["cache_items"] == ["192.0.2.50", "192.0.2.99"]
    assert mac["neighbor_items"] == sorted(({"ip": ip, "age_s": 30} for ip in addresses[:32]),
                                           key=lambda item: item["ip"])
    assert out["problems"] == [] and out["notes"] == []


def test_status_neighbors_off_and_not_active(env):
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    assert _tick(cfg, now=5000.0)["added"] == 1
    record = _neighbors_record(cfg)
    on = {"enabled": True, "active": True, "keys": 1, "over_limit": 0, "last": record, "stale": False,
          "failing": None, "setting": "ok"}
    assert macalias.cmd_status(cfg, now=5030.0)["neighbors"] == on
    # host discovery off, the host list unreadable, a tick refusal: on, and not active
    good_hosts = cfg["list_hosts"]
    _arp_ndp_hosts(cfg, tmp)
    assert macalias.cmd_status(cfg, now=5030.0)["neighbors"] == dict(on, active=False)
    cfg["list_hosts"] = [_exe(tmp / "bad_hosts", "exit 1\n"), "-n"]
    assert macalias.cmd_status(cfg, now=5030.0)["neighbors"] == dict(on, active=False)
    cfg["list_hosts"] = good_hosts
    pathlib.Path(cfg["ndp"][0]).chmod(0o644)
    assert macalias.cmd_status(cfg, now=5030.0)["neighbors"] == dict(on, active=False)
    pathlib.Path(cfg["ndp"][0]).chmod(0o755)
    (tmp / "macaliascache.conf").write_text("[general]\nneighbors=0\n")
    assert macalias.cmd_status(cfg, now=5030.0)["neighbors"] == dict(on, enabled=False, active=False)
    (tmp / "macaliascache.conf").write_text("neighbors on\n")
    assert macalias.cmd_status(cfg, now=5030.0)["neighbors"] == dict(on, enabled=False, active=False,
                                                                     setting="unusable")


def test_status_over_limit_comes_from_a_working_tick_only(env):
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::%x" % n) for n in range(1, 41)])
    assert _tick(cfg, now=5000.0)["over_limit"] == 8
    cfg["list_hosts"] = [_exe(tmp / "bad_hosts", "exit 1\n"), "-n"]
    assert _tick(cfg, now=5060.0) == HOSTS_UNAVAILABLE
    block = macalias.cmd_status(cfg, now=5090.0)["neighbors"]
    assert (block["keys"], block["over_limit"], block["last"]["result"]) == (32, 0, "hosts_unavailable")


def test_status_stale_after_7200s(env):
    # a tick that runs writes its record at least every hour, so a record older than two hours beside keys of
    # ours says the cron job is not running
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    assert _tick(cfg, now=5000.0)["added"] == 1
    assert macalias.cmd_status(cfg, now=5000.0 + 7200)["neighbors"]["stale"] is False
    assert macalias.cmd_status(cfg, now=5000.0 + 7201)["neighbors"]["stale"] is True
    # a clock that stepped back is no evidence
    assert macalias.cmd_status(cfg, now=100.0)["neighbors"]["stale"] is False
    # not active: nothing to warn about
    (tmp / "macaliascache.conf").write_text("[general]\nneighbors=0\n")
    assert macalias.cmd_status(cfg, now=5000.0 + 7201)["neighbors"]["stale"] is False
    (tmp / "macaliascache.conf").write_text("[general]\nneighbors=1\n")
    # no key of ours: nothing a dead tick would let expire
    _seed(tmp, {})
    block = macalias.cmd_status(cfg, now=5000.0 + 7201)["neighbors"]
    assert (block["active"], block["keys"], block["stale"]) == (True, 0, False)
    # keys and no record at all: a flush put them there and the first tick is still to come
    _seed(tmp, {_nkey("2001:db8::7"): _nentry("2001:db8::7", 4000.0)})
    _neighbors_file(cfg).unlink()
    block = macalias.cmd_status(cfg, now=5000.0 + 7201)["neighbors"]
    assert (block["keys"], block["last"], block["stale"]) == (1, None, False)


def test_status_a_running_tick_is_never_stale(env):
    # keys no table lists any more are not written again, and the record still stays young
    cfg, tmp = env
    _seed(tmp, {_nkey("2001:db8::7"): _nentry("2001:db8::7", 4000.0)})
    now = 5000.0
    while now <= 5000.0 + 3 * 3600:
        assert _tick(cfg, now=now) == _ok(keys=1)
        assert macalias.cmd_status(cfg, now=now + 899)["neighbors"]["stale"] is False
        now += 900


def test_status_setting_absent_note(env):
    # the default is used; a note of status, not shown on the page and no problem
    cfg, tmp = env
    (tmp / "macaliascache.conf").unlink()
    out = macalias.cmd_status(cfg, now=0.0)
    assert out["neighbors"] == {"enabled": True, "active": True, "keys": 0, "over_limit": 0, "last": None,
                                "stale": False, "failing": None, "setting": "absent"}
    assert out["notes"] == [{"item": "neighbors_setting", "note": SETTING_ABSENT_NOTE % cfg["settings_file"],
                             "shown": False}]
    assert out["problems"] == []


def test_status_neighbors_record_is_not_read_from_an_unusable_state_dir(env):
    cfg, tmp = env
    pathlib.Path(cfg["state_dir"]).write_text("x")
    out = macalias.cmd_status(cfg, now=0.0)
    assert out["neighbors"] == {"enabled": True, "active": False, "keys": 0, "over_limit": 0, "last": None,
                                "stale": False, "failing": None, "setting": "ok"}


def test_status_ignores_a_neighbors_record_of_another_shape(env):
    cfg, tmp = env
    os.mkdir(cfg["state_dir"], 0o700)
    _neighbors_file(cfg).write_text('{"at": "5000", "result": "ok"}')
    _neighbors_file(cfg).chmod(0o600)
    assert macalias.cmd_status(cfg, now=5000.0)["neighbors"]["last"] is None


def test_status_failing_after_600s(env):
    # a tick that fails every minute must show: its result is a state once it has lasted ten minutes, whether or
    # not a tick has run since to say so in the log
    cfg, tmp = env
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    assert _tick(cfg, now=5000.0)["added"] == 1
    assert macalias.cmd_status(cfg, now=9000.0)["neighbors"]["failing"] is None
    (tmp / "ndp.json").write_text("x" * 100)
    assert _tick(cfg, now=5060.0) == NEIGHBORS_UNAVAILABLE
    block = macalias.cmd_status(cfg, now=5060.0 + 599)["neighbors"]
    assert (block["failing"], block["active"], block["keys"], block["last"]["result"]) == (
        None, True, 1, "neighbors_unavailable")
    assert macalias.cmd_status(cfg, now=5660.0)["neighbors"]["failing"] == {
        "result": "neighbors_unavailable", "since": 5060.0}
    # it lasts while the result does, through the hourly rewrites of the record, and is never stale meanwhile
    for now in (5720.0, 9000.0, 12700.0, 48300.0):
        assert _tick(cfg, now=now) == NEIGHBORS_UNAVAILABLE
        block = macalias.cmd_status(cfg, now=now + 30)["neighbors"]
        assert (block["failing"], block["stale"]) == ({"result": "neighbors_unavailable", "since": 5060.0}, False)
    _neighbor_table(tmp, [(NMAC, "2001:db8::7")])
    assert _tick(cfg, now=48360.0)["result"] == "ok"
    assert macalias.cmd_status(cfg, now=48390.0)["neighbors"]["failing"] is None


def test_status_failing_names_the_latest_result_of_the_run(env):
    cfg, tmp = env
    cfg["list_hosts"] = [_exe(tmp / "bad_hosts", "exit 1\n"), "-n"]
    assert _tick(cfg, now=5000.0) == HOSTS_UNAVAILABLE
    with open(cfg["lock_file"], "a") as held:
        fcntl.flock(held, fcntl.LOCK_EX)
        (tmp / "arp.cache").write_text("")
        (tmp / "macaliascache.conf").write_text("[general]\nneighbors=0\n")
        assert _tick(cfg, now=5300.0)["error"] == "busy"
    assert macalias.cmd_status(cfg, now=5700.0)["neighbors"]["failing"] == {"result": "busy", "since": 5000.0}
