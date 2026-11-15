import copy
import json
import os

import pytest

import macaliascache_lib as lib

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "core")

TABLES_XML = """<?xml version="1.0"?>
<tabledef>
  <general><ttl>0</ttl></general>
  <table><name>HubMacs</name><type>mac</type>
    <address>AA:BB:CC:00:00:01,aa:bb:cc:00:00:02</address><ttl>30</ttl></table>
  <table><name>VendorPrefix</name><type>mac</type>
    <address>aa:bb:cc</address><ttl>30</ttl></table>
  <table><name>DisabledMac</name><type>mac</type><address></address><ttl>30</ttl></table>
  <table><name>Hubs</name><type>host</type>
    <address>HubMacs
192.0.2.10</address><ttl>300</ttl></table>
  <table><name>NoTtl</name><type>network</type><address>198.51.100.0/24</address></table>
</tabledef>
"""


def test_parse_tables_splits_addresses_and_reads_ttl():
    t = lib.parse_tables(TABLES_XML)
    assert t["HubMacs"] == {"type": "mac", "address": ["AA:BB:CC:00:00:01", "aa:bb:cc:00:00:02"], "ttl": 30}
    assert t["Hubs"]["address"] == ["HubMacs", "192.0.2.10"]
    assert t["DisabledMac"]["address"] == []
    assert t["NoTtl"]["ttl"] is None


@pytest.mark.parametrize("text, ttl", [
    ("30", 30), ("43200.0", 43200), ("0", 0), ("0.5", 0), ("-1", None), ("1.2.3", None), ("", None),
    (" 30\n", 30), ("5.", 5), (".5", 0), (".", None), ("30s", None), ("1e3", None), ("\u00b2", None),
    ("9" * 400, None),
], ids=["digits", "float", "zero", "fraction", "negative", "two-dots", "absent", "padded", "trailing-dot",
        "leading-dot", "dot-alone", "unit", "exponent", "superscript", "beyond-a-float"])
def test_alias_ttl_reads_a_ttl_as_core_reads_it(text, ttl):
    # core's Alias: digits with at most one dot become int(float(text)); anything else leaves its
    # default of -1, which is None here. The last two would raise in core, and read as None
    assert lib.alias_ttl(text) == ttl


TTL_XML = """<?xml version="1.0"?>
<tabledef>
  <table><name>Daily</name><type>mac</type><address>aa:bb:cc:00:00:01</address><ttl>43200.0</ttl></table>
  <table><name>Never</name><type>mac</type><address>aa:bb:cc:00:00:02</address><ttl>0.0</ttl></table>
  <table><name>Fraction</name><type>mac</type><address>aa:bb:cc:00:00:03</address><ttl>0.5</ttl></table>
  <table><name>Unset</name><type>mac</type><address>aa:bb:cc:00:00:04</address></table>
  <table><name>Stock</name><type>mac</type><address>aa:bb:cc:00:00:05</address><ttl>30</ttl></table>
  <table><name>DisabledNever</name><type>mac</type><address></address><ttl>0</ttl></table>
  <table><name>HostNever</name><type>host</type><address>192.0.2.1</address><ttl>0</ttl></table>
</tabledef>
"""


def test_parse_tables_reads_the_float_ttl_core_writes_for_an_update_frequency():
    t = lib.parse_tables(TTL_XML)
    assert {name: table["ttl"] for name, table in t.items()} == {
        "Daily": 43200, "Never": 0, "Fraction": 0, "Unset": None, "Stock": 30, "DisabledNever": 0, "HostNever": 0}


def test_no_expiry_names_the_enabled_mac_aliases_without_a_lifetime_above_zero():
    # a disabled alias and an alias of another type are not the flush's to expire
    assert lib.no_expiry(lib.parse_tables(TTL_XML)) == ["Fraction", "Never", "Unset"]
    assert lib.no_expiry(lib.parse_tables(TABLES_XML)) == []


@pytest.mark.parametrize("text, reply", [
    ('{"status": "ok"}', {"status": "ok", "messages": []}),
    ('{"status": "error", "messages": ["Error loading alias [A]: x", "Error loading alias [B]: y"]}',
     {"status": "error", "messages": ["Error loading alias [A]: x", "Error loading alias [B]: y"]}),
    ("", {"status": None, "messages": []}),
    ("Traceback (most recent call last):", {"status": None, "messages": []}),
    ('["ok"]', {"status": None, "messages": []}),
    ('{"status": 1, "messages": ["x"]}', {"status": None, "messages": []}),
    ('{"messages": ["x"]}', {"status": None, "messages": []}),
    ('{"status": "error", "messages": "x"}', {"status": "error", "messages": []}),
    ('{"status": "error", "messages": ["x", 1, null]}', {"status": "error", "messages": ["x"]}),
    ("[" * 200000, {"status": None, "messages": []}),
], ids=["ok", "error-with-messages", "empty", "not-json", "json-list", "status-not-a-string", "no-status",
        "messages-not-a-list", "messages-not-all-strings", "nested-beyond-the-parser"])
def test_parse_update_reply(text, reply):
    assert lib.parse_update_reply(text) == reply


def test_mac_aliases_lowercases_and_skips_empty():
    m = lib.mac_aliases(lib.parse_tables(TABLES_XML))
    assert m == {
        "HubMacs": ["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"],
        "VendorPrefix": ["aa:bb:cc"],
    }


def test_expand_entries_prefix_and_case_insensitive():
    macs = ["AA:BB:CC:00:00:01", "aa:bb:cc:00:00:02", "dd:ee:ff:00:00:03"]
    assert lib.expand_entries(["aa:bb:cc"], macs) == {"aa:bb:cc": ["aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02"]}
    assert lib.expand_entries(["AA:BB:CC:00:00:01"], macs) == {"AA:BB:CC:00:00:01": ["aa:bb:cc:00:00:01"]}


def test_expand_entries_unmatched_entry_maps_to_empty_list():
    assert lib.expand_entries(["00:00:5e:00:53:01"], ["aa:bb:cc:00:00:01"]) == {"00:00:5e:00:53:01": []}


NEST_XML = """<?xml version="1.0"?>
<tabledef>
  <table><name>DevMacs</name><type>mac</type><address>aa:bb:cc:00:00:01</address><ttl>30</ttl></table>
  <table><name>DevMacsExtra</name><type>host</type><address>198.51.100.7</address></table>
  <table><name>Parent</name><type>host</type><address>DevMacs,192.0.2.1</address></table>
  <table><name>GrandParent</name><type>host</type><address>Parent</address></table>
  <table><name>NetGroup</name><type>networkgroup</type><address>DevMacs</address></table>
  <table><name>CycleA</name><type>host</type><address>CycleB,GrandParent</address></table>
  <table><name>CycleB</name><type>host</type><address>CycleA</address></table>
  <table><name>DisabledParent</name><type>host</type><address></address></table>
  <table><name>Unrelated</name><type>host</type><address>DevMacsExtra</address></table>
</tabledef>
"""


def test_nesting_closure_transitive_cycle_safe_token_match():
    t = lib.parse_tables(NEST_XML)
    assert lib.nesting_closure(t, ["DevMacs"]) == ["CycleA", "CycleB", "GrandParent", "NetGroup", "Parent"]


def test_nesting_closure_excludes_targets_and_unrelated():
    t = lib.parse_tables(NEST_XML)
    closure = lib.nesting_closure(t, ["DevMacs"])
    assert "DevMacs" not in closure
    assert "Unrelated" not in closure      # references DevMacsExtra, a name that merely starts with DevMacs
    assert "DisabledParent" not in closure


def test_refresh_set_is_mac_aliases_plus_closure_sorted():
    t = lib.parse_tables(NEST_XML)
    assert lib.refresh_set(t) == ["CycleA", "CycleB", "DevMacs", "GrandParent", "NetGroup", "Parent"]


def test_refresh_set_empty_without_mac_aliases():
    t = lib.parse_tables("<tabledef><table><name>H</name><type>host</type><address>192.0.2.1</address></table></tabledef>")
    assert lib.refresh_set(t) == []


def test_alias_view_combines_cache_hosts_and_pf():
    t = lib.parse_tables(NEST_XML)
    cache = {"aa:bb:cc:00:00:01": {"items": ["192.0.2.50", "192.0.2.51"], "last_seen": 1000.0}}
    hosts = [["vlan0.120", "AA:BB:CC:00:00:01", "192.0.2.50"], ["vlan0.140", "aa:bb:cc:00:00:01", "2001:db8::1"]]
    rows = lib.alias_view(t, cache, hosts, {"DevMacs": 2}, now=1060.0)
    assert rows == [{
        "name": "DevMacs",
        "entries": ["aa:bb:cc:00:00:01"],
        "macs": [{
            "mac": "aa:bb:cc:00:00:01",
            "cache_items": ["192.0.2.50", "192.0.2.51"],
            "cache_age_s": 60,
            "current_items": ["192.0.2.50", "2001:db8::1"],
            "neighbor_items": [],
        }],
        "nested_by": ["CycleA", "CycleB", "GrandParent", "NetGroup", "Parent"],
        "pf_count": 2,
    }]


def test_alias_view_mac_only_in_hosts_has_no_cache_age():
    t = lib.parse_tables(NEST_XML)
    rows = lib.alias_view(t, {}, [["vlan0.120", "aa:bb:cc:00:00:01", "192.0.2.50"]], {}, now=0.0)
    assert rows[0]["macs"][0]["cache_items"] == []
    assert rows[0]["macs"][0]["cache_age_s"] is None
    assert rows[0]["pf_count"] is None


def test_summarise_counts_and_differences():
    before = {"A": ["192.0.2.1", "192.0.2.2"], "B": None}
    after = {"A": ["192.0.2.1", "192.0.2.3"], "B": ["192.0.2.9"]}
    assert lib.summarise(before, after) == [
        {"name": "A", "before": 2, "after": 2, "added": ["192.0.2.3"], "removed": ["192.0.2.2"]},
        {"name": "B", "before": None, "after": 1, "added": [], "removed": []},
    ]


GOOD_ROW = {"name": "DevMacs", "before": 2, "after": None, "added": ["192.0.2.1"], "removed": []}


def test_last_schema_and_cache_schema():
    assert lib.last_schema({"at": 5000.0, "summary": [GOOD_ROW]}) == {"at": 5000.0, "summary": [GOOD_ROW]}
    assert lib.last_schema({"at": 5000, "summary": []}) == {"at": 5000, "summary": []}
    for bad in (
        [],
        "x",
        None,
        {"summary": []},
        {"at": "5000", "summary": []},
        {"at": 5000.0},
        {"at": 5000.0, "summary": {}},
        {"at": 5000.0, "summary": ["x"]},
        {"at": 5000.0, "summary": [dict(GOOD_ROW, name=1)]},
        {"at": 5000.0, "summary": [dict(GOOD_ROW, before="2")]},
        {"at": 5000.0, "summary": [dict(GOOD_ROW, after=1.5)]},
        {"at": 5000.0, "summary": [dict(GOOD_ROW, added="192.0.2.1")]},
        {"at": 5000.0, "summary": [dict(GOOD_ROW, removed=[1])]},
        {"at": 5000.0, "summary": [{"name": "DevMacs"}]},
    ):
        assert lib.last_schema(bad) is None, bad

    good = {"items": ["192.0.2.50", "2001:db8::50"], "last_seen": 1000.0}
    assert lib.cache_schema({"aa:bb:cc:00:00:01": good}) == {"aa:bb:cc:00:00:01": good}
    assert lib.cache_schema({}) == {}
    assert lib.cache_schema({
        "aa:bb:cc:00:00:01": good,
        "aa:bb:cc:00:00:02": {"items": "192.0.2.5", "last_seen": 1000.0},
        "aa:bb:cc:00:00:03": {"items": [5], "last_seen": 1000.0},
        "aa:bb:cc:00:00:04": {"items": ["192.0.2.6"], "last_seen": "1000"},
        "aa:bb:cc:00:00:05": {"items": ["192.0.2.7"]},
        "aa:bb:cc:00:00:06": ["192.0.2.8"],
        "aa:bb:cc:00:00:07": {"items": ["192.0.2.9"], "last_seen": True},
        "aa:bb:cc:00:00:08": {"items": ["192.0.2.10"], "last_seen": float("nan")},
    }) == {"aa:bb:cc:00:00:01": good}
    for bad in ([], "x", None, 5):
        assert lib.cache_schema(bad) is None, bad


@pytest.mark.parametrize("at", [float("nan"), float("inf"), float("-inf"), True, False, 10 ** 400],
                         ids=["nan", "infinity", "minus-infinity", "true", "false", "int-beyond-float"])
def test_last_schema_refuses_non_finite_and_bool_at(at):
    # Python's json reads NaN and Infinity, and a bool is an int in Python; none of
    # them is a time, and an int beyond a float's range would raise in the rate limit's
    # arithmetic
    assert lib.last_schema({"at": at, "summary": []}) is None


def test_validate_rows_keeps_mac_case_and_both_families():
    rows = [["vlan0.10", "AA:BB:CC:00:00:03", "192.0.2.77"], ["vlan0.10", "aa:bb:cc:00:00:04", "2001:db8::50"]]
    good, rejected = lib.validate_rows(rows)
    assert good == rows and good[0] is rows[0]
    assert rejected == []


def test_validate_rows_keeps_unzoned_link_local():
    # host discovery and NDP list unzoned fe80:: rows (core strips the zone itself); they must stay
    rows = [["vlan0.10", "aa:bb:cc:00:00:05", "fe80::5"]]
    assert lib.validate_rows(rows) == (rows, [])


@pytest.mark.parametrize("row", [
    ["vlan0.10", "aa:bb:cc:00:00:01", "laptop.lan"],
    ["vlan0.10", "aa:bb:cc:00:00:01", "fe80::1%vlan0.10"],
    ["vlan0.10", "(incomplete)", "192.0.2.5"],
    ["vlan0.10", None, "192.0.2.5"],
    ["vlan0.10", "aa:bb:cc:00:00:01"],
    ["vlan0.10", "aa:bb:cc:00:01", "192.0.2.5"],
], ids=["hostname", "zone", "incomplete", "none-mac", "two-columns", "five-octets"])
def test_validate_rows_rejects_hostname_zone_incomplete_and_none(row):
    # the zone case: ipaddress accepts a scoped address, the row check must not
    kept = ["vlan0.10", "aa:bb:cc:00:00:02", "192.0.2.6"]
    assert lib.validate_rows([kept, row]) == ([kept], [repr(row)])


@pytest.mark.parametrize("row", [
    ["vlan0.10", "aa:bb:cc:00:00:01:02", "192.0.2.5"],
    ["vlan0.10", "aa-bb-cc-00-00-01", "192.0.2.5"],
    ["vlan0.10", "aa:bb:cc:00:00:0g", "192.0.2.5"],
    ["vlan0.10", "aa:bb:cc:00:00:01\n", "192.0.2.5"],
    ["vlan0.10", "aa:bb:cc:00:00:01", "192.0.2.5\n"],
    ["vlan0.10", "aa:bb:cc:00:00:01", 1],
    ["vlan0.10", "aa:bb:cc:00:00:01", True],
    ["vlan0.10", "aa:bb:cc:00:00:01", None],
    "vlan0.10 aa:bb:cc:00:00:01 192.0.2.5",
    {"mac": "aa:bb:cc:00:00:01", "ip": "192.0.2.5"},
    None,
], ids=["seven-octets", "dashes", "not-hex", "mac-newline", "ip-newline", "ip-int", "ip-bool", "ip-none",
        "string-row", "object-row", "null-row"])
def test_validate_rows_rejects_other_shapes(row):
    assert lib.validate_rows([row]) == ([], [repr(row)])


def test_validate_rows_keeps_five_samples_of_at_most_60_characters():
    rows = [["vlan0.10", "laptop-%d.lan" % n, "192.0.2.%d" % n, "x" * 200] for n in range(7)]
    good, rejected = lib.validate_rows(rows)
    assert good == []
    assert len(rejected) == 5
    assert all(len(sample) <= 60 for sample in rejected)
    assert rejected[0].startswith("['vlan0.10', 'laptop-0.lan', '192.0.2.0'")


@pytest.mark.parametrize("value", [1, True, None, b"192.0.2.5", "fe80::1%vlan0.10", "192.0.2.5%1", "laptop.lan",
                                   " 192.0.2.5", "192.0.2.5\n", ""])
def test_valid_ip_refuses_non_strings_zones_and_names(value):
    # ipaddress.ip_address itself accepts an int, a bool and a scoped address
    assert not lib.valid_ip(value)


def test_valid_ip_accepts_both_families_and_unzoned_link_local():
    for value in ("192.0.2.5", "2001:db8::50", "fe80::5", "::ffff:192.0.2.5"):
        assert lib.valid_ip(value), value


def test_valid_mac_is_six_hex_octets_in_either_case():
    for value in ("aa:bb:cc:00:00:01", "AA:BB:CC:00:00:01", "Aa:bB:cc:00:00:01", "00:00:5e:00:53:01"):
        assert lib.valid_mac(value), value
    for value in ("aa:bb:cc:00:00", "aa:bb:cc:00:00:01:02", "aa:bb:cc:00:00:1", "aabbcc000001", "aa:bb:cc:00:00:01\n",
                  "ａa:bb:cc:00:00:01", "(incomplete)", "", None, 1):
        assert not lib.valid_mac(value), value


def test_seed_cache_groups_by_mac_and_writes_only_checked_rows():
    rows = [
        ["vlan0.10", "aa:bb:cc:00:00:01", "192.0.2.50"],
        ["vlan0.10", "aa:bb:cc:00:00:01", "fe80::5"],
        ["vlan0.11", "AA:BB:CC:00:00:03", "2001:db8::3"],
        ["vlan0.10", "aa:bb:cc:00:00:01", "laptop.lan"],
        ["vlan0.10", "laptop.lan", "aa:bb:cc:00:00:04"],
    ]
    assert lib.seed_cache(rows, 5000.0) == {
        "aa:bb:cc:00:00:01": {"items": ["192.0.2.50", "fe80::5"], "last_seen": 5000.0},
        "AA:BB:CC:00:00:03": {"items": ["2001:db8::3"], "last_seen": 5000.0},
    }


def test_alias_view_ignores_rejected_rows_without_raising():
    t = lib.parse_tables(NEST_XML)
    hosts = [
        ["vlan0.10", None, "192.0.2.60"],
        ["vlan0.10", "aa:bb:cc:00:00:01", "laptop.lan"],
        ["vlan0.10", "aa:bb:cc:00:00:01", "192.0.2.50"],
    ]
    rows = lib.alias_view(t, {}, hosts, {}, now=0.0)
    assert rows[0]["macs"] == [
        {"mac": "aa:bb:cc:00:00:01", "cache_items": [], "cache_age_s": None, "current_items": ["192.0.2.50"],
         "neighbor_items": []}]


CORE_ROOT = "/usr/local/opnsense/"
ARGV_TEXT = "['/usr/local/opnsense/scripts/interfaces/list_hosts.py', '-n']"
EMPTIED_NOTE = ("core may now flush emptied tables itself (core #10950); "
                "the plugin's own flush is redundant but harmless")
EXPIRY_NOTE = ("core's arpcache.py no longer holds the lines that add a fixed 12 h (core #10114); "
               "MAC aliases may now drop a vanished address on their own, and the neighbor-table addresses this plugin "
               "adds may no longer reach the aliases")


def core_rows():
    """ the contract's rows, core's fixes and the neighbor contract's rows, read by index; the previous
    release's lib, which these cases also run against, may lack CORE_FIXES and NEIGHBOR_CONTRACT and carry
    4-column contract rows
    """
    return lib.CORE_CONTRACT + getattr(lib, "CORE_FIXES", ()) + getattr(lib, "NEIGHBOR_CONTRACT", ())


def core_paths():
    return {row[0]: row[1] for row in core_rows()}


def fixture_texts():
    """ the texts macalias reads from a stock 26.7.7 box, taken from the fixture copies of its lines """
    texts = {}
    for row in core_rows():
        local = os.path.join(FIXTURES, row[1][len(CORE_ROOT):])
        if row[2] is None:
            texts[row[0]] = "exists" if os.access(local, os.X_OK) else None
        else:
            with open(local, encoding="utf-8") as f:
                texts[row[0]] = f.read()
    return texts


def without(texts, path, text):
    """ texts with text removed from every item read from core's file at path """
    paths = core_paths()
    return {item: value.replace(text, "") if paths[item] == path and value is not None else value
            for item, value in texts.items()}


def test_core_contract_is_the_table_of_cores_files():
    assert lib.CORE_CONTRACT == (
        ("arpcache", CORE_ROOT + "scripts/filter/lib/alias/arpcache.py",
         ("/tmp/alias_filter_arp.cache", "last_seen", ARGV_TEXT, "hosts.get('rows', [])",
          "current_macs[item[1]]['items'].append(item[2])")),
        ("update_lock", CORE_ROOT + "service/conf/actions.d/actions_filter.conf", ("/tmp/filter_update_tables.lock",)),
        ("md5_marker", CORE_ROOT + "scripts/filter/lib/alias/__init__.py",
         ("/var/db/aliastables/%s.md5.txt", "if self._ttl > 0 and os.path.isfile(self._filename_alias_hash):",
          "fstat = os.stat(self._filename_alias_hash)",
          "self._has_expired = fstat.st_mtime > now or now - fstat.st_mtime > self._ttl")),
        ("targeted_mode", CORE_ROOT + "scripts/filter/update_tables.py", ("--aliases",)),
        ("list_hosts", CORE_ROOT + "scripts/interfaces/list_hosts.py", None),
    )


def test_core_contract_matches_fixture_copies():
    # the fixtures hold 26.7.7's own lines, so a stock box raises no problem
    texts = fixture_texts()
    assert None not in texts.values()
    assert lib.core_contract(texts) == []


@pytest.mark.parametrize("item, text", [
    ("arpcache", "/tmp/alias_filter_arp.cache"),
    ("arpcache", "last_seen"),
    ("arpcache", ARGV_TEXT),
    ("arpcache", "hosts.get('rows', [])"),
    ("arpcache", "current_macs[item[1]]['items'].append(item[2])"),
    ("update_lock", "/tmp/filter_update_tables.lock"),
    ("md5_marker", "/var/db/aliastables/%s.md5.txt"),
    ("md5_marker", "if self._ttl > 0 and os.path.isfile(self._filename_alias_hash):"),
    ("md5_marker", "fstat = os.stat(self._filename_alias_hash)"),
    ("md5_marker", "self._has_expired = fstat.st_mtime > now or now - fstat.st_mtime > self._ttl"),
    ("targeted_mode", "--aliases"),
    ("list_hosts", None),
], ids=["cache-file", "last-seen", "argv", "rows-key", "column-line", "lock-file", "md5-file", "md5-guard",
        "md5-stat", "md5-expiry", "aliases-flag", "list-hosts-missing"])
def test_core_contract_each_drift_blocks(item, text):
    texts = fixture_texts()
    texts[item] = None if text is None else texts[item].replace(text, "")
    found = lib.core_contract(texts)
    assert [(p["item"], p["blocks_flush"]) for p in found] == [(item, True)]
    path = core_paths()[item]
    if text is None:
        assert found[0]["problem"] == "core's %s is missing or not executable" % path
    else:
        assert found[0]["problem"] == "core's %s no longer contains %r; the flush imitates it, so it refuses" % (
            path, text)


def test_core_contract_names_every_missing_text():
    texts = fixture_texts()
    texts["arpcache"] = "_cache_filename = None"
    assert lib.core_contract(texts)[0]["problem"].endswith(
        "no longer contains '/tmp/alias_filter_arp.cache', 'last_seen', \"%s\", \"hosts.get('rows', [])\", "
        "\"current_macs[item[1]]['items'].append(item[2])\"; the flush imitates it, so it refuses" % ARGV_TEXT)


def test_core_contract_blocks_when_the_md5_marker_moves_directory():
    # the flush forces expiry through <aliastables dir>/<name>.md5.txt, so the suffix alone is not enough
    texts = fixture_texts()
    texts["md5_marker"] = texts["md5_marker"].replace("/var/db/aliastables/", "/var/db/aliases/")
    assert ".md5.txt" in texts["md5_marker"]
    found = lib.core_contract(texts)
    assert [(p["item"], p["blocks_flush"]) for p in found] == [("md5_marker", True)]
    assert "'/var/db/aliastables/%s.md5.txt'" in found[0]["problem"]


@pytest.mark.parametrize("item", ["arpcache", "update_lock", "md5_marker", "targeted_mode", "list_hosts"])
def test_core_contract_missing_file_blocks(item):
    texts = fixture_texts()
    texts[item] = None
    found = lib.core_contract(texts)
    assert [(p["item"], p["blocks_flush"]) for p in found] == [(item, True)]
    path = core_paths()[item]
    absent = "not executable" if item == "list_hosts" else "cannot be read"
    assert found[0]["problem"] == "core's %s is missing or %s" % (path, absent)


def test_core_contract_with_nothing_read_blocks_on_every_file():
    found = lib.core_contract({})
    assert [(p["item"], p["blocks_flush"]) for p in found] == [
        ("arpcache", True), ("update_lock", True), ("md5_marker", True), ("targeted_mode", True), ("list_hosts", True)]


def test_core_fixes_is_the_table_of_cores_fixes():
    assert lib.CORE_FIXES == (
        ("cache_expiry", CORE_ROOT + "scripts/filter/lib/alias/arpcache.py",
         ("_address_ttl = 43200", "cls._data.update(cls.current_cache())"), EXPIRY_NOTE, True),
        ("emptied_table", CORE_ROOT + "scripts/filter/update_tables.py", ("else cnt_alias_content",), EMPTIED_NOTE, False),
    )


def test_core_fixes_stock_core_gives_no_note():
    assert lib.core_fixes(fixture_texts()) == []


@pytest.mark.parametrize("item, text, note, shown", [
    ("cache_expiry", "_address_ttl = 43200", EXPIRY_NOTE, True),
    ("cache_expiry", "cls._data.update(cls.current_cache())", EXPIRY_NOTE, True),
    ("emptied_table", "else cnt_alias_content", EMPTIED_NOTE, False),
])
def test_core_fixes_each_fix_is_a_note(item, text, note, shown):
    # the text leaves every item read from that file, so it is no contract text; only a note that
    # changes what the user may do is shown on the page
    texts = without(fixture_texts(), core_paths()[item], text)
    assert lib.core_fixes(texts) == [{"item": item, "note": note, "shown": shown}]
    assert lib.core_contract(texts) == []


def test_core_fixes_both_notes_never_block():
    paths = core_paths()
    texts = fixture_texts()
    texts = without(texts, paths["cache_expiry"], "_address_ttl = 43200")
    texts = without(texts, paths["cache_expiry"], "cls._data.update(cls.current_cache())")
    texts = without(texts, paths["emptied_table"], "else cnt_alias_content")
    assert lib.core_fixes(texts) == [{"item": "cache_expiry", "note": EXPIRY_NOTE, "shown": True},
                                     {"item": "emptied_table", "note": EMPTIED_NOTE, "shown": False}]
    assert lib.core_contract(texts) == []


def test_core_fixes_contract_drift_in_update_tables_gives_no_note():
    # the other direction: each contract text gone from update_tables.py blocks and gives no note
    path = core_paths()["emptied_table"]
    drifts = [(row[0], text) for row in lib.CORE_CONTRACT if row[1] == path for text in row[2]]
    assert drifts
    for item, text in drifts:
        texts = without(fixture_texts(), path, text)
        assert [(p["item"], p["blocks_flush"]) for p in lib.core_contract(texts)] == [(item, True)], text
        assert lib.core_fixes(texts) == [], text


def test_core_fixes_unreadable_file_gives_no_note():
    # a fix's file is a contract file, whose absence already blocks
    texts = fixture_texts()
    texts["cache_expiry"] = texts["emptied_table"] = None
    assert lib.core_fixes(texts) == []
    assert lib.core_fixes({}) == []


def test_core_fixes_files_are_contract_files():
    contract = {row[1] for row in lib.CORE_CONTRACT}
    assert [row[1] for row in lib.CORE_FIXES if row[1] not in contract] == []


def test_valid_alias_name_accepts_core_mask_and_rejects_slash_space_long():
    # core's AliasNameField pattern, 26.7.7, copied verbatim
    assert lib._ALIAS_NAME.pattern == "([a-zA-Z]|(([_a-zA-Z][a-zA-Z0-9]|[a-zA-Z][_a-zA-Z0-9])[_a-zA-Z0-9]{0,29}))"
    for name in ("a", "Z", "DevMacs", "_a", "_1", "a_", "a1", "Dev_Macs_2", "a" * 31, "_" + "a" * 30):
        assert lib.valid_alias_name(name), name
    for name in ("Dev/Macs", "Dev Macs", "../DevMacs", "a" * 32, "", "_", "1a", "__lan_network", "Dev.Macs",
                 "Dev-Macs", "DevMacs\n", "DévMacs", None, 5):
        assert not lib.valid_alias_name(name), name


@pytest.mark.parametrize("value, expected", [
    ("2001:DB8::0050", "2001:db8::50"),
    ("2001:db8:0:0:0:0:0:77", "2001:db8::77"),
    ("FE80::5", "fe80::5"),
    ("192.0.2.5", "192.0.2.5"),
])
def test_canonical_ip_both_families_and_two_ways(value, expected):
    assert lib.canonical_ip(value) == expected


def test_canonical_ip_gives_one_form_to_an_ipv4_mapped_address():
    assert lib.canonical_ip("::FFFF:192.0.2.5") == lib.canonical_ip("::ffff:192.0.2.5")
    assert lib.canonical_ip("::FFFF:192.0.2.5") is not None


@pytest.mark.parametrize("value", ["fe80::1%hn0", 1, True, None, b"192.0.2.5", "laptop.lan", "192.0.2.05", ""])
def test_canonical_ip_refuses_zones_non_strings_and_names(value):
    assert lib.canonical_ip(value) is None


def test_alias_view_compares_addresses_in_canonical_form():
    t = lib.parse_tables(NEST_XML)
    cache = {"aa:bb:cc:00:00:01": {"items": ["2001:DB8::0050", "2001:db8::50", "192.0.2.50"], "last_seen": 1000.0}}
    hosts = [["vlan0.140", "aa:bb:cc:00:00:01", "2001:db8::50"], ["vlan0.120", "aa:bb:cc:00:00:01", "192.0.2.50"]]
    mac = lib.alias_view(t, cache, hosts, {}, now=1060.0)[0]["macs"][0]
    assert mac["cache_items"] == mac["current_items"] == ["192.0.2.50", "2001:db8::50"]


def test_alias_view_keeps_an_unparsed_cached_item_as_written():
    t = lib.parse_tables(NEST_XML)
    cache = {"aa:bb:cc:00:00:01": {"items": ["fe80::1%hn0", "laptop.lan", "192.0.2.05", "192.0.2.50"], "last_seen": 1000.0}}
    hosts = [["vlan0.120", "aa:bb:cc:00:00:01", "192.0.2.50"]]
    mac = lib.alias_view(t, cache, hosts, {}, now=1060.0)[0]["macs"][0]
    assert mac["cache_items"] == ["192.0.2.05", "192.0.2.50", "fe80::1%hn0", "laptop.lan"]
    assert mac["current_items"] == ["192.0.2.50"]


def test_summarise_both_families():
    before = {"C": ["192.0.2.1", "2001:db8::1"]}
    after = {"C": ["192.0.2.1", "2001:db8::2"]}
    assert lib.summarise(before, after) == [
        {"name": "C", "before": 2, "after": 2, "added": ["2001:db8::2"], "removed": ["2001:db8::1"]}]


# the neighbor table's addresses: rows, keys, the wanted set, the plan, the contract, the record and the setting

MAC1, MAC2, MAC3 = "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:02", "dd:ee:ff:00:00:03"
NEIGHBOR_TEXTS = (
    "cls._data.update(cls.current_cache())",
    "if cls._now - cls._data[macaddr]['last_seen'] > cls._address_ttl:",
    "if macaddr.startswith(pattern.lower()):",
    "for item in self._data[macaddr]['items']:",
)
NEIGHBOR_DRIFT = ("core's %s no longer contains %s; the addresses from the neighbor table rely on it, "
                  "so none is added or removed")
ONE_MAC_XML = """<?xml version="1.0"?>
<tabledef>
  <table><name>DevMacs</name><type>mac</type><address>AA:BB:CC:00:00:01</address><ttl>30</ttl></table>
</tabledef>
"""
PREFIX_XML = """<?xml version="1.0"?>
<tabledef>
  <table><name>Vendor</name><type>mac</type><address>AA:BB:CC</address><ttl>30</ttl></table>
</tabledef>
"""


def ndp_text(rows):
    return json.dumps({"ndp": {"neighbor-cache": rows}})


def ndp_row(address, mac, **more):
    return dict({"address": address, "mac-address": mac, "interface": "vlan0.10"}, **more)


def key(mac, ip):
    return "%s#%s" % (mac, ip)


def entry(ip, last_seen):
    return {"items": [ip], "last_seen": last_seen}


def test_neighbor_constants_are_the_specified_ones():
    assert lib.NDP_ARGV == ("/usr/sbin/ndp", "-an", "--libxo", "json") and lib.NDP == lib.NDP_ARGV[0]
    assert (lib.NDP_MAX_BYTES, lib.NEIGHBOR_MAX_PER_MAC, lib.NEIGHBOR_MAX_TOTAL) == (1048576, 32, 1024)
    assert (lib.NEIGHBOR_REFRESH, lib.NEIGHBOR_STALE) == (3600, 7200)
    # a key is refreshed long before core's own 12 h would drop it
    assert lib.NEIGHBOR_STALE == 2 * lib.NEIGHBOR_REFRESH < 43200


def test_parse_neighbors_rows():
    text = ndp_text([
        ndp_row("2001:db8::2", "AA:BB:CC:00:00:01", permanent=True),
        ndp_row("fe80::1%vlan0.10", MAC1),
        ndp_row("2001:DB8:0:0::0001", MAC2, expires_sec=5),
        ndp_row("2001:db8::2", MAC1),
        ndp_row("2001:db8::9", "(incomplete)"),
        ndp_row("192.0.2.5", MAC1),
        ndp_row("laptop.lan", MAC1),
        ndp_row("%vlan0.10", MAC1),
        ndp_row(5, MAC1), ndp_row(True, MAC1), ndp_row(None, MAC1), ndp_row(["2001:db8::7"], MAC1),
        ndp_row("2001:db8::7", 5), ndp_row("2001:db8::7", True), ndp_row("2001:db8::7", None),
        ndp_row("2001:db8::7", "aa:bb:cc:00:00"), ndp_row("2001:db8::7", "aa:bb:cc:00:00:01\n"),
        {"address": "2001:db8::8"}, {"mac-address": MAC1},
        ["2001:db8::8", MAC1], "2001:db8::8 " + MAC1, None, 7, True,
    ])
    # a static row is used, the MAC is lowered, the zone is cut, the address is canonical, a pair is listed once;
    # an incomplete row, an IPv4 row and every row of another shape are skipped
    assert lib.parse_neighbors(text) == [(MAC1, "2001:db8::2"), (MAC1, "fe80::1"), (MAC2, "2001:db8::1")]
    assert lib.parse_neighbors(ndp_text([])) == []


@pytest.mark.parametrize("text", [
    "", "not-json", "[]", "5", "null", '"ndp"', '{"ndp": []}', '{"ndp": {}}', '{"ndp": {"neighbor-cache": {}}}',
    '{"ndp": {"neighbor-cache": "x"}}', '{"neighbor-cache": []}', "[" * 200000,
], ids=["empty", "not-json", "list", "number", "null", "string", "ndp-list", "no-cache", "cache-object", "cache-string",
        "no-ndp", "nested-beyond-the-parser"])
def test_parse_neighbors_refuses_text_of_another_shape(text):
    assert lib.parse_neighbors(text) is None


def test_host_pairs_are_lower_case_and_canonical():
    rows = [["vlan0.10", "AA:BB:CC:00:00:01", "2001:DB8::0001"], ["vlan0.10", MAC1, "192.0.2.5"],
            ["vlan0.10", MAC2, "fe80::2"], ["vlan0.10", "laptop.lan", "2001:db8::9"], ["vlan0.10", MAC2], None]
    assert lib.host_pairs(rows) == {(MAC1, "2001:db8::1"), (MAC1, "192.0.2.5"), (MAC2, "fe80::2")}
    assert lib.host_pairs([]) == set()


def test_neighbor_key_round_trip():
    assert lib.neighbor_key(MAC1, "2001:db8::2") == "aa:bb:cc:00:00:01#2001:db8::2"
    assert lib.parse_neighbor_key("aa:bb:cc:00:00:01#2001:db8::2") == (MAC1, "2001:db8::2")
    pairs = lib.parse_neighbors(ndp_text([
        ndp_row("2001:DB8::00A2", "AA:BB:CC:00:00:01"), ndp_row("fe80::1%vlan0.10", MAC2), ndp_row("::1", MAC3)]))
    assert len(pairs) == 3
    for pair in pairs:
        assert lib.parse_neighbor_key(lib.neighbor_key(*pair)) == pair


@pytest.mark.parametrize("value", [
    "AA:BB:CC:00:00:01#2001:db8::1", "aa:bb:cc:00:00:01#2001:DB8::1", "aa:bb:cc:00:00:01#2001:db8:0::1",
    "aa:bb:cc:00:00:01#192.0.2.5", "aa:bb:cc:00:00:01", "aa:bb:cc:00:00:0#2001:db8::1",
    "aa:bb:cc:00:00:01:02#2001:db8::1", "aa:bb:cc:00:00:01 2001:db8::1", "aa:bb:cc:00:00:01#2001:db8::1#2001:db8::2",
    "aa:bb:cc:00:00:01#fe80::1%hn0", "aa:bb:cc:00:00:01#", "#2001:db8::1", "aa:bb:cc:00:00:01#2001:db8::1\n",
    "aa:bb:cc:00:00:01#laptop.lan", "", None, 5, True, b"aa:bb:cc:00:00:01#2001:db8::1", (MAC1, "2001:db8::1"),
], ids=["upper-case-mac", "upper-case-address", "address-not-shortest", "ipv4", "no-separator", "mac-of-16",
        "mac-of-20", "space", "two-separators", "zone", "no-address", "no-mac", "newline", "name", "empty", "none",
        "int", "bool", "bytes", "pair"])
def test_parse_neighbor_key_refuses(value):
    # a key called ours is one neighbor_key could have written
    assert lib.parse_neighbor_key(value) is None


def test_wanted_prefix_entry():
    tables = lib.parse_tables(PREFIX_XML)
    neighbors = [(MAC1, "2001:db8::1"), ("aa:bb:cc:00:00:09", "fe80::9"), (MAC3, "2001:db8::3")]
    assert lib.wanted_neighbors(tables, set(), neighbors, set()) == (
        [key(MAC1, "2001:db8::1"), key("aa:bb:cc:00:00:09", "fe80::9")], 0)


def test_wanted_full_mac_entries_of_several_aliases():
    # HubMacs lists two MACs in either case, VendorPrefix their prefix: each address is wanted once
    tables = lib.parse_tables(TABLES_XML)
    neighbors = [(MAC1, "2001:db8::1"), (MAC2, "2001:db8::2"), (MAC3, "2001:db8::3")]
    assert lib.wanted_neighbors(tables, set(), neighbors + neighbors, set()) == (
        [key(MAC1, "2001:db8::1"), key(MAC2, "2001:db8::2")], 0)


def test_wanted_skips_address_discovery_has_for_that_mac():
    tables = lib.parse_tables(ONE_MAC_XML)
    hosts = lib.host_pairs([["vlan0.10", "AA:BB:CC:00:00:01", "2001:DB8::0001"], ["vlan0.10", MAC1, "fe80::1"]])
    neighbors = [(MAC1, "2001:db8::1"), (MAC1, "2001:db8::2"), (MAC1, "fe80::1")]
    assert lib.wanted_neighbors(tables, hosts, neighbors, set()) == ([key(MAC1, "2001:db8::2")], 0)


def test_wanted_keeps_address_discovery_has_for_other_mac():
    tables = lib.parse_tables(ONE_MAC_XML)
    hosts = lib.host_pairs([["vlan0.10", MAC2, "2001:db8::1"], ["vlan0.11", MAC3, "fe80::1"]])
    neighbors = [(MAC1, "2001:db8::1"), (MAC1, "fe80::1")]
    assert lib.wanted_neighbors(tables, hosts, neighbors, set()) == (
        [key(MAC1, "2001:db8::1"), key(MAC1, "fe80::1")], 0)


def test_wanted_disabled_alias():
    # a disabled alias has no address; an alias of another type lists no MAC
    tables = lib.parse_tables("""<tabledef>
      <table><name>DisabledMac</name><type>mac</type><address></address><ttl>30</ttl></table>
      <table><name>Hosts</name><type>host</type><address>aa:bb:cc:00:00:01</address></table>
    </tabledef>""")
    assert lib.wanted_neighbors(tables, set(), [(MAC1, "2001:db8::1")], set()) == ([], 0)
    assert lib.wanted_neighbors({}, set(), [(MAC1, "2001:db8::1")], set()) == ([], 0)


def test_wanted_ignores_a_neighbor_that_is_not_ipv6():
    tables = lib.parse_tables(ONE_MAC_XML)
    assert lib.wanted_neighbors(tables, set(), [(MAC1, "192.0.2.5"), (MAC1, "laptop.lan"), (MAC1, "2001:db8::1")],
                                set()) == ([key(MAC1, "2001:db8::1")], 0)


def test_wanted_limits_stable():
    # 40 addresses of one listed MAC: the 3 already held, though the highest, then the 29 lowest by value
    # ("2001:db8::10" sorts before "2001:db8::2" as text); the same choice once those are the held ones
    tables = lib.parse_tables(ONE_MAC_XML)
    addresses = ["2001:db8::%x" % n for n in range(1, 41)]
    neighbors = [(MAC1, ip) for ip in reversed(addresses)]
    held = {key(MAC1, ip) for ip in addresses[37:]}
    expected = sorted(key(MAC1, ip) for ip in addresses[:29] + addresses[37:])
    assert lib.wanted_neighbors(tables, set(), neighbors, held) == (expected, 8)
    assert lib.wanted_neighbors(tables, set(), neighbors, set(expected)) == (expected, 8)
    # a held key that is no candidate takes no place
    assert lib.wanted_neighbors(tables, set(), neighbors, held | {key(MAC1, "2001:db8::ffff"), key(MAC2, "fe80::2")}
                                ) == (expected, 8)
    # more held than the limit: the lowest held
    everything = {key(MAC1, ip) for ip in addresses}
    assert lib.wanted_neighbors(tables, set(), neighbors, everything) == (
        sorted(key(MAC1, ip) for ip in addresses[:32]), 8)


def test_wanted_total_limit():
    tables = lib.parse_tables(PREFIX_XML)
    neighbors = [(mac, "2001:db8::%x" % n) for mac in (MAC2, MAC1) for n in (3, 2, 1)]
    # no key held: the MACs in sorted order, the lowest addresses of the last one that fits
    first = [key(MAC1, "2001:db8::1"), key(MAC1, "2001:db8::2"), key(MAC1, "2001:db8::3"), key(MAC2, "2001:db8::1")]
    assert lib.wanted_neighbors(tables, set(), neighbors, set(), total=4) == (first, 2)
    assert lib.wanted_neighbors(tables, set(), neighbors, set(first), total=4) == (first, 2)
    # held keys come first whatever their MAC, then the lowest of the first MAC
    held = {key(MAC2, "2001:db8::2"), key(MAC2, "2001:db8::3")}
    second = [key(MAC1, "2001:db8::1"), key(MAC1, "2001:db8::2"), key(MAC2, "2001:db8::2"), key(MAC2, "2001:db8::3")]
    assert lib.wanted_neighbors(tables, set(), neighbors, held, total=4) == (second, 2)
    assert lib.wanted_neighbors(tables, set(), neighbors, set(second), total=4) == (second, 2)
    # the limit per MAC is applied first: what it cut cannot fill the total
    assert lib.wanted_neighbors(tables, set(), neighbors, set(), per_mac=1, total=4) == (
        [key(MAC1, "2001:db8::1"), key(MAC2, "2001:db8::1")], 4)
    assert lib.wanted_neighbors(tables, set(), neighbors, set()) == (
        sorted(key(mac, ip) for mac, ip in neighbors), 0)


def test_plan_add_refresh_boundary():
    now = 100000.0
    ips = ["2001:db8::%x" % n for n in range(1, 10)]
    keys = [key(MAC1, ip) for ip in ips]
    cache = {
        keys[0]: entry(ips[0], now - 3600),
        keys[1]: entry(ips[1], now - 3601),
        keys[2]: entry(ips[2], now + 1),
        # keys[3] is absent
        keys[4]: entry(ips[4], "99000"),
        keys[5]: entry(ips[5], True),
        keys[6]: {"items": [ips[6]]},
        keys[7]: {"items": ["2001:db8::bad"], "last_seen": now},
        keys[8]: [ips[8]],
    }
    neighbors = {(MAC1, ip) for ip in ips}
    assert lib.neighbor_plan(cache, keys, set(), neighbors, now) == {
        "add": [keys[3]], "refresh": [keys[1], keys[2], keys[4], keys[5], keys[6], keys[7], keys[8]], "remove": []}
    assert lib.neighbor_plan(cache, keys[:2], set(), neighbors, now, refresh_after=3601) == {
        "add": [], "refresh": [], "remove": []}
    assert lib.neighbor_plan({}, [], set(), set(), now) == {"add": [], "refresh": [], "remove": []}


def test_plan_remove_covered_by_discovery():
    # rule (a): host discovery now lists the address for that MAC, so the MAC's own entry carries it
    now = 5000.0
    covered, other = key(MAC1, "2001:db8::1"), key(MAC1, "2001:db8::2")
    cache = {MAC1: {"items": ["192.0.2.50"], "last_seen": now}, covered: entry("2001:db8::1", now),
             other: entry("2001:db8::2", now)}
    hosts = {(MAC1, "2001:db8::1"), (MAC1, "192.0.2.50")}
    neighbors = {(MAC1, "2001:db8::1"), (MAC1, "2001:db8::2")}
    assert lib.neighbor_plan(cache, [other], hosts, neighbors, now) == {"add": [], "refresh": [], "remove": [covered]}


@pytest.mark.parametrize("hosts, neighbors", [
    (set(), {(MAC2, "2001:db8::1")}),
    ({(MAC2, "2001:db8::1")}, set()),
    ({(MAC3, "2001:db8::1")}, {(MAC2, "2001:db8::1")}),
], ids=["neighbor-table", "host-discovery", "both"])
def test_plan_remove_moved_address(hosts, neighbors):
    # rule (b): the tables list the address, and under no row with that MAC
    moved = key(MAC1, "2001:db8::1")
    cache = {moved: entry("2001:db8::1", 5000.0)}
    assert lib.neighbor_plan(cache, [], hosts, neighbors, 5000.0) == {"add": [], "refresh": [], "remove": [moved]}


def test_plan_link_local_under_several_macs_kept():
    # with the zone cut, one link-local address is rightly under several MACs on several interfaces: rule (b)
    # removes a key only when no row lists the address with the key's own MAC
    now = 5000.0
    first, second, third = key(MAC1, "fe80::1"), key(MAC2, "fe80::1"), key(MAC3, "fe80::1")
    cache = {first: entry("fe80::1", now), second: entry("fe80::1", now), third: entry("fe80::1", now)}
    neighbors = {(MAC1, "fe80::1"), (MAC2, "fe80::1")}
    assert lib.neighbor_plan(cache, [first, second], set(), neighbors, now) == {
        "add": [], "refresh": [], "remove": [third]}
    # host discovery lists it for the second MAC: that key goes by rule (a), the first one stays
    assert lib.neighbor_plan(cache, [first], {(MAC2, "fe80::1")}, neighbors, now) == {
        "add": [], "refresh": [], "remove": [second, third]}


def test_plan_remove_all():
    now = 5000.0
    ours = [key(MAC1, "2001:db8::1"), key(MAC2, "fe80::2")]
    cache = {MAC1: {"items": ["192.0.2.50"], "last_seen": now}, ours[1]: entry("fe80::2", now),
             ours[0]: entry("2001:db8::1", now - 99999), "AA:BB:CC:00:00:01#2001:db8::1": entry("2001:db8::1", now)}
    assert lib.neighbor_plan(cache, None, set(), set(), now) == {"add": [], "refresh": [], "remove": ours}
    # nothing the tables say matters in this mode
    assert lib.neighbor_plan(cache, None, {(MAC1, "2001:db8::1")}, {(MAC1, "2001:db8::1")}, now) == {
        "add": [], "refresh": [], "remove": ours}
    assert lib.neighbor_plan({MAC1: cache[MAC1]}, None, set(), set(), now) == {"add": [], "refresh": [], "remove": []}
    # the keys counted as ours are the keys this mode removes
    assert lib.count_neighbor_keys(cache) == 2 and lib.count_neighbor_keys({MAC1: cache[MAC1]}) == 0


def test_plan_absent_from_tables_left():
    # a key whose address no table lists any more is neither removed nor refreshed: core's own 12 h ends it
    now = 100000.0
    gone = key(MAC1, "2001:db8::1")
    cache = {gone: entry("2001:db8::1", now - 40000)}
    assert lib.neighbor_plan(cache, [], {(MAC1, "192.0.2.50")}, {(MAC1, "2001:db8::2")}, now) == {
        "add": [], "refresh": [], "remove": []}


def test_apply_plan_leaves_foreign_keys():
    now = 6000.0
    added, refreshed, removed = key(MAC1, "2001:db8::1"), key(MAC1, "2001:db8::2"), key(MAC2, "2001:db8::3")
    foreign = {
        MAC1: {"items": ["192.0.2.50", "2001:db8::50"], "last_seen": 5000.0},
        "AA:BB:CC:00:00:03": {"items": ["192.0.2.77"], "last_seen": 100.0},
        "AA:BB:CC:00:00:01#2001:db8::9": {"items": ["2001:db8::9"], "last_seen": 100.0},
        "aa:bb:cc:00:00:01#192.0.2.9": {"items": ["192.0.2.9"], "last_seen": 100.0},
        "odd": "value",
    }
    cache = dict(foreign)
    cache[refreshed] = entry("2001:db8::2", 100.0)
    cache[removed] = entry("2001:db8::3", 5000.0)
    before = copy.deepcopy(cache)
    plan = {"add": [added], "refresh": [refreshed], "remove": [removed, MAC1, "odd", "AA:BB:CC:00:00:01#2001:db8::9"]}
    result = lib.apply_neighbor_plan(cache, plan, now)
    assert result == dict(foreign, **{added: entry("2001:db8::1", now), refreshed: entry("2001:db8::2", now)})
    assert all(result[name] is cache[name] for name in foreign)
    assert cache == before and result is not cache
    assert lib.apply_neighbor_plan(cache, {"add": [], "refresh": [], "remove": []}, now) == cache
    # a key that is not ours is never written either
    assert lib.apply_neighbor_plan({}, {"add": ["odd", MAC1], "refresh": ["AA:BB:CC:00:00:01#2001:db8::9"],
                                        "remove": []}, now) == {}


def test_neighbor_contract_is_the_table_of_the_merge_texts():
    assert lib.NEIGHBOR_CONTRACT == (
        ("neighbor_merge", CORE_ROOT + "scripts/filter/lib/alias/arpcache.py", NEIGHBOR_TEXTS),)
    # its file is a contract file, whose absence already blocks
    assert {row[1] for row in lib.NEIGHBOR_CONTRACT} <= {row[1] for row in lib.CORE_CONTRACT}
    assert lib.neighbor_contract(fixture_texts()) == []


@pytest.mark.parametrize("text", NEIGHBOR_TEXTS, ids=["replace", "expiry", "prefix-match", "items"])
def test_neighbor_contract_texts(text):
    # each text gone is an advisory problem of the neighbor addresses alone; a flush is not blocked by it
    path = core_paths()["neighbor_merge"]
    texts = without(fixture_texts(), path, text)
    assert lib.neighbor_contract(texts) == [
        {"item": "neighbor_merge", "problem": NEIGHBOR_DRIFT % (path, repr(text)), "blocks_flush": False}]
    assert lib.core_contract(texts) == []


def test_neighbor_contract_names_every_missing_text_and_none_for_a_missing_file():
    texts = fixture_texts()
    texts["neighbor_merge"] = "class ArpCache:"
    assert lib.neighbor_contract(texts) == [{
        "item": "neighbor_merge", "blocks_flush": False,
        "problem": NEIGHBOR_DRIFT % (core_paths()["neighbor_merge"], ", ".join(repr(text) for text in NEIGHBOR_TEXTS))}]
    # the file is arpcache's, whose absence is that item's problem
    texts["neighbor_merge"] = None
    assert lib.neighbor_contract(texts) == []
    assert lib.neighbor_contract({}) == []


def test_alias_view_folds_neighbor_keys():
    t = lib.parse_tables(NEST_XML)
    cache = {
        MAC1: {"items": ["192.0.2.50", "2001:db8::50"], "last_seen": 1000.0},
        key(MAC1, "2001:db8::b"): entry("2001:db8::b", 1030.0),
        key(MAC1, "2001:db8::a"): entry("2001:db8::a", "x"),
        key(MAC2, "2001:db8::c"): entry("2001:db8::c", 1000.0),
    }
    hosts = [["vlan0.120", MAC1, "192.0.2.50"]]
    rows = lib.alias_view(t, cache, hosts, {}, now=1060.0)
    # the keys are no MACs of their own: one row for the MAC, its own entry apart from the plugin's keys
    assert rows[0]["macs"] == [{
        "mac": MAC1,
        "cache_items": ["192.0.2.50", "2001:db8::50"],
        "cache_age_s": 60,
        "current_items": ["192.0.2.50"],
        "neighbor_items": [{"ip": "2001:db8::a", "age_s": None}, {"ip": "2001:db8::b", "age_s": 30}],
    }]


def test_alias_view_mac_with_only_neighbor_keys():
    # no entry of its own and no current row: the MAC still gets a row, and a prefix entry finds it
    cache = {key(MAC1, "fe80::1"): entry("fe80::1", 1000.0)}
    for xml in (NEST_XML, PREFIX_XML):
        rows = lib.alias_view(lib.parse_tables(xml), cache, [], {}, now=1060.0)
        assert rows[0]["macs"] == [{"mac": MAC1, "cache_items": [], "cache_age_s": None, "current_items": [],
                                    "neighbor_items": [{"ip": "fe80::1", "age_s": 60}]}]


NEIGHBOR_RECORD = {"at": 5000.0, "result": "ok", "added": 2, "removed": 0, "refreshed": 1, "keys": 3, "over_limit": 0,
                   "samples": ["2001:db8::1", "2001:db8::2"]}


def test_neighbors_schema():
    assert lib.neighbors_schema(NEIGHBOR_RECORD) == NEIGHBOR_RECORD
    assert lib.neighbors_schema(dict(NEIGHBOR_RECORD, extra=1, samples=[])) == dict(NEIGHBOR_RECORD, samples=[])
    assert lib.neighbors_schema(dict(NEIGHBOR_RECORD, at=5000, result="core_changed")) == dict(
        NEIGHBOR_RECORD, at=5000, result="core_changed")
    for bad in (
        [], "x", None, 5,
        {name: value for name, value in NEIGHBOR_RECORD.items() if name != "at"},
        {name: value for name, value in NEIGHBOR_RECORD.items() if name != "result"},
        {name: value for name, value in NEIGHBOR_RECORD.items() if name != "keys"},
        {name: value for name, value in NEIGHBOR_RECORD.items() if name != "samples"},
        dict(NEIGHBOR_RECORD, at="5000"), dict(NEIGHBOR_RECORD, at=True), dict(NEIGHBOR_RECORD, at=float("nan")),
        dict(NEIGHBOR_RECORD, result=None), dict(NEIGHBOR_RECORD, result=1),
        dict(NEIGHBOR_RECORD, added="2"), dict(NEIGHBOR_RECORD, removed=1.0), dict(NEIGHBOR_RECORD, refreshed=True),
        dict(NEIGHBOR_RECORD, keys=-1), dict(NEIGHBOR_RECORD, over_limit=None),
        dict(NEIGHBOR_RECORD, samples="2001:db8::1"), dict(NEIGHBOR_RECORD, samples=[1]),
        dict(NEIGHBOR_RECORD, samples=["2001:db8::%x" % n for n in range(6)]),
    ):
        assert lib.neighbors_schema(bad) is None, bad


@pytest.mark.parametrize("text, value", [
    ("[general]\nneighbors=1\n", True),
    ("[general]\nneighbors=0\n", False),
    ("[general]\nneighbors=1", True),
    ("\n[general]\n\nneighbors = 0\n\n", False),
    ("[general]\nneighbors=2\n", None),
    ("[general]\nneighbors=\n", None),
    ("[general]\nneighbors=yes\n", None),
    ("[general]\nneighbors=01\n", None),
    ("[general]\n", None),
    ("[general]\nother=1\n", None),
    ("neighbors=1\n", None),
    ("[other]\nneighbors=1\n", None),
    ("[general]\nneighbors=1\nneighbors=0\n", None),
    ("[general]\nneighbors=1\n[general]\nneighbors=1\n", None),
    ("[general]\nneighbors=1\nnoise\n", None),
    ("", None),
    ("neighbors", None),
    ("{\"general\": {\"neighbors\": 1}}", None),
], ids=["on", "off", "no-final-newline", "spaced", "two", "empty-value", "word", "padded-digit", "missing-key",
        "other-key", "missing-section", "other-section", "key-twice", "section-twice", "stray-line", "empty", "garbage",
        "json"])
def test_parse_setting(text, value):
    assert lib.parse_setting(text) is value


def test_neighbor_addresses_are_the_keys_addresses_lowest_first():
    keys = [key(MAC1, "2001:db8::10"), key(MAC2, "2001:db8::2"), key(MAC1, "fe80::1"), key(MAC1, "2001:db8::2"),
            "odd", MAC1, "AA:BB:CC:00:00:01#2001:db8::1"]
    assert lib.neighbor_addresses(keys) == ["2001:db8::2", "2001:db8::10", "fe80::1"]
    assert lib.neighbor_addresses([]) == []
