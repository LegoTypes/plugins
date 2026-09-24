import macaliascache_lib as lib

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
