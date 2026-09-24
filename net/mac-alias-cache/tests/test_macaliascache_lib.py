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
