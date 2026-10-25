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
    # (s7) Python's json reads NaN and Infinity, and a bool is an int in Python; none of
    # them is a time, and an int beyond a float's range would raise in the rate limit's
    # arithmetic
    assert lib.last_schema({"at": at, "summary": []}) is None


def test_validate_rows_keeps_mac_case_and_both_families():
    rows = [["vlan0.10", "AA:BB:CC:00:00:03", "192.0.2.77"], ["vlan0.10", "aa:bb:cc:00:00:04", "2001:db8::50"]]
    good, rejected = lib.validate_rows(rows)
    assert good == rows and good[0] is rows[0]
    assert rejected == []


def test_validate_rows_keeps_unzoned_link_local():
    # (r6) host discovery and NDP list unzoned fe80:: rows (core strips the zone itself); they must stay
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
    # (r7) the zone case: ipaddress accepts a scoped address, the row check must not
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
    # (r9) ipaddress.ip_address itself accepts an int, a bool and a scoped address
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
        {"mac": "aa:bb:cc:00:00:01", "cache_items": [], "cache_age_s": None, "current_items": ["192.0.2.50"]}]


CORE_ROOT = "/usr/local/opnsense/"
EMPTIED_NOTE = ("core may now flush emptied tables itself (core #10950); "
                "the plugin's own flush is redundant but harmless")


def fixture_texts():
    """ the texts macalias reads from a stock 26.7.7 box, taken from the fixture copies of its lines """
    texts = {}
    for item, path, expected, note in lib.CORE_CONTRACT:
        local = os.path.join(FIXTURES, path[len(CORE_ROOT):])
        if expected is None:
            texts[item] = "exists" if os.access(local, os.X_OK) else None
        else:
            with open(local, encoding="utf-8") as f:
                texts[item] = f.read()
    return texts


def test_core_contract_is_the_table_of_cores_files():
    assert lib.CORE_CONTRACT == (
        ("arpcache", CORE_ROOT + "scripts/filter/lib/alias/arpcache.py",
         ("/tmp/alias_filter_arp.cache", "items", "last_seen"), None),
        ("update_lock", CORE_ROOT + "service/conf/actions.d/actions_filter.conf",
         ("/tmp/filter_update_tables.lock",), None),
        ("md5_marker", CORE_ROOT + "scripts/filter/lib/alias/__init__.py", ("/var/db/aliastables/%s.md5.txt",), None),
        ("targeted_mode", CORE_ROOT + "scripts/filter/update_tables.py", ("--aliases",), None),
        ("emptied_table", CORE_ROOT + "scripts/filter/update_tables.py", ("else cnt_alias_content",), EMPTIED_NOTE),
        ("list_hosts", CORE_ROOT + "scripts/interfaces/list_hosts.py", None, None),
    )


def test_core_contract_matches_fixture_copies():
    # (c7) the fixtures hold 26.7.7's own lines, so a stock box raises no problem
    texts = fixture_texts()
    assert None not in texts.values()
    assert lib.core_contract(texts) == []


@pytest.mark.parametrize("item, text", [
    ("arpcache", "/tmp/alias_filter_arp.cache"),
    ("arpcache", "items"),
    ("arpcache", "last_seen"),
    ("update_lock", "/tmp/filter_update_tables.lock"),
    ("md5_marker", "/var/db/aliastables/%s.md5.txt"),
    ("targeted_mode", "--aliases"),
    ("list_hosts", None),
])
def test_core_contract_each_drift_blocks(item, text):
    texts = fixture_texts()
    texts[item] = None if text is None else texts[item].replace(text, "")
    found = lib.core_contract(texts)
    assert [(p["item"], p["blocks_flush"]) for p in found] == [(item, True)]
    path = dict((i, p) for i, p, _e, _n in lib.CORE_CONTRACT)[item]
    if text is None:
        assert found[0]["problem"] == "core's %s is missing or not executable" % path
    else:
        assert found[0]["problem"] == "core's %s no longer contains %r; the flush imitates it, so it refuses" % (
            path, text)


def test_core_contract_names_every_missing_text():
    texts = fixture_texts()
    texts["arpcache"] = "_cache_filename = None"
    assert lib.core_contract(texts)[0]["problem"].endswith(
        "no longer contains '/tmp/alias_filter_arp.cache', 'items', 'last_seen'; the flush imitates it, so it refuses")


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
    if item == "targeted_mode":
        texts["emptied_table"] = None   # the same file: its note gives way to the blocking problem
    found = lib.core_contract(texts)
    assert [(p["item"], p["blocks_flush"]) for p in found] == [(item, True)]
    path = dict((i, p) for i, p, _e, _n in lib.CORE_CONTRACT)[item]
    absent = "not executable" if item == "list_hosts" else "cannot be read"
    assert found[0]["problem"] == "core's %s is missing or %s" % (path, absent)


def test_core_contract_with_nothing_read_blocks_on_every_file():
    found = lib.core_contract({})
    assert [(p["item"], p["blocks_flush"]) for p in found] == [
        ("arpcache", True), ("update_lock", True), ("md5_marker", True), ("targeted_mode", True), ("list_hosts", True)]


def test_core_contract_emptied_table_fix_is_non_blocking_note():
    texts = fixture_texts()
    fixed = texts["emptied_table"].replace("else cnt_alias_content", "else alias.get_pf_addr_count()")
    texts["targeted_mode"] = texts["emptied_table"] = fixed
    assert lib.core_contract(texts) == [{"item": "emptied_table", "problem": EMPTIED_NOTE, "blocks_flush": False}]


def test_valid_alias_name_accepts_core_mask_and_rejects_slash_space_long():
    # core's AliasNameField pattern, 26.7.7, copied verbatim
    assert lib._ALIAS_NAME.pattern == "([a-zA-Z]|(([_a-zA-Z][a-zA-Z0-9]|[a-zA-Z][_a-zA-Z0-9])[_a-zA-Z0-9]{0,29}))"
    for name in ("a", "Z", "DevMacs", "_a", "_1", "a_", "a1", "Dev_Macs_2", "a" * 31, "_" + "a" * 30):
        assert lib.valid_alias_name(name), name
    for name in ("Dev/Macs", "Dev Macs", "../DevMacs", "a" * 32, "", "_", "1a", "__lan_network", "Dev.Macs",
                 "Dev-Macs", "DevMacs\n", "DévMacs", None, 5):
        assert not lib.valid_alias_name(name), name
