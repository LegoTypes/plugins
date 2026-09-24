import fcntl
import json
import os
import stat
import textwrap

import pytest

import macalias

TABLES = """<?xml version="1.0"?>
<tabledef>
  <table><name>DevMacs</name><type>mac</type><address>aa:bb:cc:00:00:01</address><ttl>30</ttl></table>
  <table><name>Parent</name><type>host</type><address>DevMacs</address><ttl>300</ttl></table>
</tabledef>
"""


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
        echo '{"source": "discovery", "rows": [["vlan0.65", "aa:bb:cc:00:00:01", "192.0.2.50"]]}'
    """)
    cfg = dict(macalias.DEFAULTS)
    cfg.update(
        tables_conf=str(tmp_path / "filter_tables.conf"),
        cache_file=str(tmp_path / "arp.cache"),
        lock_file=str(tmp_path / "update.lock"),
        last_file=str(tmp_path / "last.json"),
        aliastables_dir=str(aliastables),
        list_hosts=[hosts, "-n"],
        update_tables=update,
        pfctl=pfctl,
        lock_timeout=0.5,
        lock_retry=0.05,
    )
    return cfg, tmp_path


def test_status_reports_source_rows_and_last_flush(env):
    cfg, tmp = env
    (tmp / "last.json").write_text(json.dumps({"at": 1050.0, "summary": []}))
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
    assert json.loads((tmp / "last.json").read_text())["at"] == 5000.0


def test_flush_seeds_every_ip_per_mac_and_skips_short_rows(env):
    cfg, tmp = env
    listing = json.dumps({"source": "discovery", "rows": [
        ["vlan0.65", "aa:bb:cc:00:00:01", "192.0.2.50"],
        ["vlan0.65", "aa:bb:cc:00:00:01", "2001:db8::50"],
        ["vlan0.65", "aa:bb:cc:00:00:02"],
        ["vlan0.66", "AA:BB:CC:00:00:03", "192.0.2.77"],
    ]})
    cfg["list_hosts"] = [_exe(tmp / "multi_hosts", "echo '%s'\n" % listing), "-n"]
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert "error" not in out
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


def _snapshot(tmp):
    return (
        (tmp / "arp.cache").read_bytes(),
        os.stat(tmp / "aliastables" / "DevMacs.md5.txt").st_mtime,
        os.stat(tmp / "aliastables" / "Parent.md5.txt").st_mtime,
    )


@pytest.mark.parametrize("body", [
    "echo not-json\n",
    "echo '{\"source\": \"discovery\", \"rows\": []}'\n",
    "echo '{\"source\": \"discovery\", \"rows\": [[\"vlan0.65\", \"aa:bb:cc:00:00:01\"]]}'\n",
    "exit 1\n",
], ids=["non-json", "empty-rows", "only-short-rows", "no-output"])
def test_flush_refuses_when_hosts_unavailable(env, body):
    cfg, tmp = env
    cfg["list_hosts"] = [_exe(tmp / "bad_hosts", body), "-n"]
    before = _snapshot(tmp)
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert out == {"error": "hosts_unavailable", "detail": "host list could not be read; nothing changed"}
    assert _snapshot(tmp) == before
    assert not (tmp / "update_args").exists()
    assert not (tmp / "last.json").exists()   # rate limit not armed
    assert sorted(p.name for p in tmp.iterdir() if p.name.startswith((".", "tmp"))) == []


def test_flush_rate_limit_ignores_future_timestamp(env):
    # a backwards clock step must not lock flush out indefinitely
    cfg, tmp = env
    (tmp / "last.json").write_text(json.dumps({"at": 5100.0, "summary": []}))
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert "error" not in out
    assert json.loads((tmp / "last.json").read_text())["at"] == 5000.0


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


def test_flush_too_soon_changes_nothing(env):
    cfg, tmp = env
    (tmp / "last.json").write_text(json.dumps({"at": 4995.0, "summary": []}))
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
        (tmp / "last.json").write_text(json.dumps({"at": 5000.0, "summary": []}))
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
    (tmp / "last.json").write_text(json.dumps({"at": 4995.0, "summary": []}))
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
