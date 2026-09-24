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
        # pfctl -t NAME -T show
        f="{pf}/$2"
        [ -f "$f" ] || {{ echo "pfctl: Table does not exist." >&2; exit 1; }}
        cat "$f"
    """)
    update = _exe(tmp_path / "update_tables.py", f"""
        echo "$@" > "{tmp_path}/update_args"
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


def test_flush_deletes_cache_forces_expiry_runs_targeted_update(env):
    cfg, tmp = env
    out = macalias.cmd_flush(cfg, clock=lambda: 5000.0, sleep=lambda s: None)
    assert "error" not in out
    assert not (tmp / "arp.cache").exists()
    assert os.stat(tmp / "aliastables" / "DevMacs.md5.txt").st_mtime == 0
    assert os.stat(tmp / "aliastables" / "Parent.md5.txt").st_mtime != 0   # parents follow via rel_alias.expired()
    assert (tmp / "update_args").read_text().split() == ["--aliases", "DevMacs,Parent"]
    by_name = {r["name"]: r for r in out["summary"]}
    assert by_name["DevMacs"]["removed"] == ["192.0.2.99"]
    assert by_name["Parent"]["removed"] == ["192.0.2.99"]
    assert out["update_tables"]["rc"] == 0
    assert json.loads((tmp / "last.json").read_text())["at"] == 5000.0


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
    assert not (tmp / "arp.cache").exists()


def test_main_always_prints_json_and_exits_zero(capsys):
    assert macalias.main(["bogus"]) == 0
    assert json.loads(capsys.readouterr().out)["error"] == "usage"
