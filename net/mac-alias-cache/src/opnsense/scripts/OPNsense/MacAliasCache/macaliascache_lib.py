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

Pure logic for the MAC alias cache plugin: no I/O, no subprocesses.
Inputs mirror what core uses: /usr/local/etc/filter_tables.conf (applied
alias definitions), list_hosts.py rows, the ArpCache JSON file and the
kernel's neighbor table as ndp prints it.
"""
import ipaddress
import json
import math
import re
import xml.etree.ElementTree as ET
from collections.abc import Iterable, Mapping
from typing import TypedDict, TypeGuard

_SPLIT = re.compile(r"[,\n]")
_MAC = re.compile(r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}")
# core's AliasNameField pattern (26.7.7), verbatim, without its reserved words
_ALIAS_NAME = re.compile(r"([a-zA-Z]|(([_a-zA-Z][a-zA-Z0-9]|[a-zA-Z][_a-zA-Z0-9])[_a-zA-Z0-9]{0,29}))")
_SAMPLES = 5
# the most addresses a tick's reply, record and log line name
NEIGHBOR_SAMPLES = _SAMPLES
_SAMPLE_LENGTH = 60

# the paths of core's that the flush writes, locks and marks, as core 26.7.7 names them; the
# plugin's defaults and the contract below both take them from here
CACHE_FILE = "/tmp/alias_filter_arp.cache"
UPDATE_LOCK = "/tmp/filter_update_tables.lock"
# core creates both files root:wheel 0640; the plugin writes and creates them with that mode too
CORE_FILE_MODE = 0o640
ALIASTABLES_DIR = "/var/db/aliastables"

_CORE = "/usr/local/opnsense/"
ARPCACHE_PY = _CORE + "scripts/filter/lib/alias/arpcache.py"
UPDATE_TABLES_PY = _CORE + "scripts/filter/update_tables.py"
LIST_HOSTS = _CORE + "scripts/interfaces/list_hosts.py"
LIST_HOSTS_ARGV = (LIST_HOSTS, "-n")
# what the flush imitates in core: item, file and the texts it must still hold (None: only an
# executable file); any drift blocks a flush
CORE_CONTRACT = (
    ("arpcache", ARPCACHE_PY, (CACHE_FILE, "last_seen", repr(list(LIST_HOSTS_ARGV)), "hosts.get('rows', [])",
                               "current_macs[item[1]]['items'].append(item[2])")),
    ("update_lock", _CORE + "service/conf/actions.d/actions_filter.conf", (UPDATE_LOCK,)),
    ("md5_marker", _CORE + "scripts/filter/lib/alias/__init__.py",
     (ALIASTABLES_DIR + "/%s.md5.txt", "if self._ttl > 0 and os.path.isfile(self._filename_alias_hash):",
      "fstat = os.stat(self._filename_alias_hash)",
      "self._has_expired = fstat.st_mtime > now or now - fstat.st_mtime > self._ttl")),
    ("targeted_mode", UPDATE_TABLES_PY, ("--aliases",)),
    ("list_hosts", LIST_HOSTS, None),
)
# Core's bugs the plugin works around: the item, core's file, the texts it holds while the bug
# stands, the note once any of them is gone, and whether the page shows it. Status lists every
# note; the page shows only a note that changes what the user may do. A note never blocks
CORE_FIXES = (
    ("cache_expiry", ARPCACHE_PY, ("_address_ttl = 43200", "cls._data.update(cls.current_cache())"),
     "core's arpcache.py no longer holds the lines that add a fixed 12 h (core #10114); "
     "MAC aliases may now drop a vanished address on their own, and the neighbor-table addresses this plugin adds "
     "may no longer reach the aliases", True),
    ("emptied_table", UPDATE_TABLES_PY, ("else cnt_alias_content",),
     "core may now flush emptied tables itself (core #10950); the plugin's own flush is redundant but harmless", False),
)

# the kernel's neighbor table, read as libxo JSON; a longer output than NDP_MAX_BYTES counts as unreadable
NDP = "/usr/sbin/ndp"
NDP_ARGV = (NDP, "-an", "--libxo", "json")
NDP_MAX_BYTES = 1048576
# the most keys of the plugin's own in core's cache: for one MAC, and in all
NEIGHBOR_MAX_PER_MAC = 32
NEIGHBOR_MAX_TOTAL = 1024
# a key still wanted is written again once its last_seen is this old, well inside core's 12 h; a record of the
# tick older than twice that, while keys exist, says the tick is not running
NEIGHBOR_REFRESH = 3600
NEIGHBOR_STALE = 7200
# what the plugin's own cache keys rely on in core: every key the host list does not name is kept until it is
# 12 h old, and an alias entry takes the items of every key that starts with it. Drift is a problem of the
# neighbor addresses alone and never blocks a flush
NEIGHBOR_CONTRACT = (
    ("neighbor_merge", ARPCACHE_PY, ("cls._data.update(cls.current_cache())",
                                     "if cls._now - cls._data[macaddr]['last_seen'] > cls._address_ttl:",
                                     "if macaddr.startswith(pattern.lower()):",
                                     "for item in self._data[macaddr]['items']:")),
)
_KEY_SEPARATOR = "#"
_MAC_LENGTH = 17

# a lower-case MAC and an address in canonical form
Pair = tuple[str, str]


class Table(TypedDict):
    """ one alias of filter_tables.conf as parse_tables reads it; a disabled alias has no address """
    type: str
    address: list[str]
    ttl: int | None


class UpdateReply(TypedDict):
    """ what a flush reads from update_tables.py's reply: status is None when it printed no reply """
    status: str | None
    messages: list[str]


class NeighborPlan(TypedDict):
    """ what a tick does to core's cache: the keys of the plugin's own to write, to write again and to delete """
    add: list[str]
    refresh: list[str]
    remove: list[str]


class NeighborRecord(TypedDict):
    """ neighbors.json, the tick's record of its last write or change of result (neighbors_schema) """
    at: float
    result: str
    added: int
    removed: int
    refreshed: int
    keys: int
    over_limit: int
    samples: list[str]


def alias_ttl(text: str) -> int | None:
    """ an alias's lifetime in seconds as core's Alias reads a <ttl>: digits with at most one dot, cut to
    an int (core writes update frequency * 86400 as a float); None for any other text, which core leaves at
    its default of -1, never expiring
    """
    text = text.strip()
    if len(text.split(".")) > 2 or not text.replace(".", "").isdigit():
        return None
    try:
        return int(float(text))
    # str.isdigit takes digits float() does not read (a superscript), and a long run of digits is infinite
    except (ValueError, OverflowError):
        return None


def parse_tables(xml_text: str) -> dict[str, Table]:
    """ filter_tables.conf text -> {name: {type, address: [str], ttl: int|None}}; ttl as alias_ttl reads it """
    result: dict[str, Table] = {}
    root = ET.fromstring(xml_text)
    for table in root.iter("table"):
        name = (table.findtext("name") or "").strip()
        if not name:
            continue
        address = [a.strip() for a in _SPLIT.split(table.findtext("address") or "") if a.strip()]
        result[name] = {
            "type": (table.findtext("type") or "").strip(),
            "address": address,
            "ttl": alias_ttl(table.findtext("ttl") or ""),
        }
    return result


def mac_aliases(tables):
    """ enabled mac aliases (a disabled alias has an empty address) -> lower-cased entries """
    return {
        name: [entry.lower() for entry in table["address"]]
        for name, table in tables.items()
        if table["type"] == "mac" and table["address"]
    }


def no_expiry(tables: dict[str, Table]) -> list[str]:
    """ the enabled mac aliases core never rebuilds, sorted: core expires an alias only while its lifetime is
    above 0, and forcing that expiry is how a flush makes core rebuild one
    """
    lifetimes = {name: tables[name]["ttl"] for name in mac_aliases(tables)}
    return sorted(name for name, ttl in lifetimes.items() if ttl is None or ttl <= 0)


def expand_entries(entries, macs):
    """ each entry -> every known MAC starting with it, the rule ArpCache.iter_addresses applies """
    known = sorted({mac.lower() for mac in macs})
    return {entry: [mac for mac in known if mac.startswith(entry.lower())] for entry in entries}


def nesting_closure(tables, targets):
    """ every alias that nests a target, directly or through other aliases, matched on whole
    address tokens; computed here because core's get_affected_aliases reuses its dependency lists
    across iterations and can skip a parent
    """
    targets = set(targets)
    found = set()
    frontier = set(targets)
    while frontier:
        nxt = set()
        for name, table in tables.items():
            if name in found or name in targets:
                continue
            if frontier.intersection(table["address"]):
                nxt.add(name)
        found |= nxt
        frontier = nxt
    return sorted(found)


def refresh_set(tables):
    """ the --aliases argument for update_tables.py: mac aliases plus everything nesting them """
    macs = set(mac_aliases(tables))
    return sorted(macs | set(nesting_closure(tables, macs)))


def valid_mac(s):
    """ a full six-octet MAC, as core's host discovery reports them, in either case """
    return type(s) is str and _MAC.fullmatch(s) is not None


def valid_ip(s):
    """ a plain IPv4 or IPv6 address; an unzoned link-local address is kept """
    # ipaddress.ip_address takes more than core writes: an int or a bool (1 and True are
    # 0.0.0.1) and, since Python 3.9, a scoped address such as fe80::1%vlan0.10
    if type(s) is not str or "%" in s:
        return False
    try:
        ipaddress.ip_address(s)
    except ValueError:
        return False
    return True


def canonical_ip(s):
    """ the address in the one form the status view compares, or None where valid_ip refuses it """
    if not valid_ip(s):
        return None
    return str(ipaddress.ip_address(s))


def _valid_row(row):
    """ a list_hosts row with a MAC and an address in the columns core's cache takes them from """
    return isinstance(row, (list, tuple)) and len(row) >= 3 and valid_mac(row[1]) and valid_ip(row[2])


def validate_rows(rows):
    """ (good, rejected): the rows core's cache may be written from, each kept as returned,
    and short samples of up to five of the others for the reply and the log
    """
    good, rejected = [], []
    for row in rows:
        if _valid_row(row):
            good.append(row)
        elif len(rejected) < _SAMPLES:
            rejected.append(repr(row)[:_SAMPLE_LENGTH])
    return good, rejected


def seed_cache(good, now):
    """ {mac: {"items": [ip, ...], "last_seen": now}} in core's ArpCache format, from the rows
    validate_rows kept, skipping any that fails the row check; the MAC key is kept as list_hosts
    returns it
    """
    cache = {}
    for row in good:
        if _valid_row(row):
            cache.setdefault(row[1], {"items": [], "last_seen": now})["items"].append(row[2])
    return cache


def _ipv6(text: str) -> ipaddress.IPv6Address | None:
    """ text as an IPv6 address, None for anything else valid_ip takes or refuses """
    if not valid_ip(text):
        return None
    address = ipaddress.ip_address(text)
    return address if isinstance(address, ipaddress.IPv6Address) else None


def parse_neighbors(text: str) -> list[Pair] | None:
    """ `ndp -an --libxo json` text -> the sorted pairs of its usable rows: a full MAC, lowered here because
    core compares its cache keys as written, and an IPv6 address in canonical form with its %zone cut as
    list_hosts.py cuts it. A static row is used, as core's own reading of the table uses it; an incomplete
    row and a row of any other shape are skipped. None when the text is not {"ndp": {"neighbor-cache": [...]}}
    """
    try:
        data = json.loads(text)
    # ValueError is no JSON; RecursionError is nesting deeper than the parser goes
    except (ValueError, RecursionError):
        return None
    table = data.get("ndp") if isinstance(data, dict) else None
    rows = table.get("neighbor-cache") if isinstance(table, dict) else None
    if not isinstance(rows, list):
        return None
    pairs: set[Pair] = set()
    for row in rows:
        if not isinstance(row, dict):
            continue
        mac, address = row.get("mac-address"), row.get("address")
        if not isinstance(mac, str) or not valid_mac(mac) or type(address) is not str:
            continue
        ip = _ipv6(address.split("%", 1)[0])
        if ip is not None:
            pairs.add((mac.lower(), str(ip)))
    return sorted(pairs)


def host_pairs(rows: Iterable[object]) -> set[Pair]:
    """ the (MAC, address) pairs host discovery lists, from the rows that pass the row check, in the form the
    neighbor pairs have
    """
    pairs: set[Pair] = set()
    for row in rows:
        if not isinstance(row, (list, tuple)) or not _valid_row(row):
            continue
        mac, ip = row[1], canonical_ip(row[2])
        if isinstance(mac, str) and isinstance(ip, str):
            pairs.add((mac.lower(), ip))
    return pairs


def neighbor_key(mac: str, ip: str) -> str:
    """ the plugin's own key in core's cache for one address of one MAC: it starts with the MAC, so every
    alias entry that matches the MAC takes its item, and host discovery never reports it, so core keeps it
    """
    return mac.lower() + _KEY_SEPARATOR + ip


def parse_neighbor_key(key: object) -> Pair | None:
    """ the pair of a key neighbor_key could have written, a lower-case full MAC, the separator and an IPv6
    address in canonical form; None for any other key, so a key called ours is one the plugin could have written
    """
    if type(key) is not str or key.count(_KEY_SEPARATOR) != 1:
        return None
    mac, _separator, ip = key.partition(_KEY_SEPARATOR)
    if len(mac) != _MAC_LENGTH or not valid_mac(mac) or mac != mac.lower():
        return None
    address = _ipv6(ip)
    if address is None or str(address) != ip:
        return None
    return mac, ip


def wanted_neighbors(tables: Mapping[str, Table], hosts: set[Pair], neighbors: Iterable[Pair], held: Iterable[str],
                     per_mac: int = NEIGHBOR_MAX_PER_MAC, total: int = NEIGHBOR_MAX_TOTAL) -> tuple[list[str], int]:
    """ (the sorted keys the cache should hold, how many more the limits cut): for every neighbor MAC an entry
    of an enabled mac alias matches by core's prefix rule, each IPv6 address of the neighbor table that host
    discovery does not list for that MAC. At most per_mac for one MAC, then at most total in all; over a limit
    the keys already held come first, then the lowest addresses, the MACs in sorted order, so the same tables
    and the cache this choice made give the same choice again
    """
    entries = {entry for listed in mac_aliases(tables).values() for entry in listed}
    held = set(held)
    by_mac: dict[str, list[tuple[bool, ipaddress.IPv6Address, str]]] = {}
    for mac, ip in set(neighbors):
        address = _ipv6(ip)
        if address is None or (mac, ip) in hosts or not any(mac.startswith(entry) for entry in entries):
            continue
        by_mac.setdefault(mac, []).append((neighbor_key(mac, ip) not in held, address, ip))
    candidates = sum(len(found) for found in by_mac.values())
    chosen = sorted((not_held, mac, address, ip)
                    for mac, found in by_mac.items() for not_held, address, ip in sorted(found)[:max(per_mac, 0)])
    wanted = sorted(neighbor_key(mac, ip) for _not_held, mac, _address, ip in chosen[:max(total, 0)])
    return wanted, candidates - len(wanted)


def _own_keys(cache: Mapping[str, object]) -> dict[str, Pair]:
    """ the keys of the plugin's own in a cache, each with its pair """
    found: dict[str, Pair] = {}
    for key in cache:
        pair = parse_neighbor_key(key)
        if pair is not None:
            found[key] = pair
    return found


def count_neighbor_keys(cache: Mapping[str, object]) -> int:
    """ how many keys of the plugin's own a cache holds """
    return len(_own_keys(cache))


def neighbor_addresses(keys: Iterable[str]) -> list[str]:
    """ the addresses of the keys of the plugin's own among keys, each once, the lowest first """
    found = {pair[1] for pair in map(parse_neighbor_key, keys) if pair is not None}
    return sorted(found, key=ipaddress.ip_address)


def _entry_due(entry: object, ip: str, now: float, refresh_after: int) -> bool:
    """ a key's value is to be written again: it is not the value the plugin writes, its last_seen is no
    number or lies in the future (a clock step), or it is older than refresh_after
    """
    if not isinstance(entry, dict) or entry.get("items") != [ip]:
        return True
    last_seen = entry.get("last_seen")
    if not _is_number(last_seen):
        return True
    return last_seen > now or now - last_seen > refresh_after


def neighbor_plan(cache: Mapping[str, object], wanted: list[str] | None, hosts: set[Pair], neighbors: set[Pair],
                  now: float, refresh_after: int = NEIGHBOR_REFRESH) -> NeighborPlan:
    """ what to change in cache so that it holds the wanted keys; wanted None removes every key of the
    plugin's own and adds none. Otherwise a key of ours is removed (a) when host discovery lists its address
    for its MAC, whose own entry then carries it, and (b) when host discovery or the neighbor table lists its
    address and neither lists it with its MAC: the address moved. A key whose address no table lists is left
    to core's 12 h. A wanted key is added when absent and written again when its value is due (_entry_due)
    """
    ours = _own_keys(cache)
    if wanted is None:
        return {"add": [], "refresh": [], "remove": sorted(ours)}
    listed = hosts | neighbors
    addresses = {ip for _mac, ip in listed}
    remove = sorted(key for key, pair in ours.items()
                    if pair in hosts or (pair[1] in addresses and pair not in listed))
    add, refresh = [], []
    for key in sorted(set(wanted) - set(remove)):
        pair = parse_neighbor_key(key)
        if pair is None:
            continue
        if key not in cache:
            add.append(key)
        elif _entry_due(cache[key], pair[1], now, refresh_after):
            refresh.append(key)
    return {"add": add, "refresh": refresh, "remove": remove}


def apply_neighbor_plan(cache: Mapping[str, object], plan: NeighborPlan, now: float) -> dict[str, object]:
    """ a new cache with the plan applied: the keys to add and to write again hold their one address with
    last_seen now. Only a key of the plugin's own is written or deleted; every other key keeps its value
    """
    removed = {key for key in plan["remove"] if parse_neighbor_key(key) is not None}
    result = {key: value for key, value in cache.items() if key not in removed}
    for key in plan["add"] + plan["refresh"]:
        pair = parse_neighbor_key(key)
        if pair is not None:
            result[key] = {"items": [pair[1]], "last_seen": now}
    return result


def parse_setting(text: str) -> bool | None:
    """ the plugin's settings file as its template renders it, "[general]" and "neighbors=0" or
    "neighbors=1": the setting, or None for a text without exactly one such value or with any line that is
    neither a section, a key with a value, nor empty
    """
    section = None
    values = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        name, separator, value = line.partition("=")
        if not separator or section is None:
            return None
        if section == "general" and name.strip() == "neighbors":
            values.append(value.strip())
    if values == ["1"]:
        return True
    if values == ["0"]:
        return False
    return None


def valid_alias_name(name):
    """ name passes core's own alias name pattern, so it is safe in a file path and as a pfctl table name """
    return type(name) is str and _ALIAS_NAME.fullmatch(name) is not None


def core_contract(texts):
    """ blocking problems with the core files the flush imitates; texts maps each item to its
    file's text, None when missing or unreadable ("exists" or None for list_hosts)
    """
    found = []
    for item, path, expected in CORE_CONTRACT:
        text = texts.get(item)
        if text is None:
            absent = "not executable" if expected is None else "cannot be read"
            found.append({"item": item, "problem": "core's %s is missing or %s" % (path, absent), "blocks_flush": True})
            continue
        missing = [part for part in expected or () if part not in text]
        if missing:
            found.append({"item": item, "problem": "core's %s no longer contains %s; the flush imitates it, so it refuses"
                          % (path, ", ".join(repr(part) for part in missing)), "blocks_flush": True})
    return found


def neighbor_contract(texts):
    """ advisory problems with what the plugin's own cache keys rely on in core, from the texts
    core_contract reads; none blocks a flush. A missing file gives none: it is a contract file, whose
    absence is already a problem
    """
    found = []
    for item, path, expected in NEIGHBOR_CONTRACT:
        text = texts.get(item)
        if text is None:
            continue
        missing = [part for part in expected if part not in text]
        if missing:
            found.append({"item": item, "problem": "core's %s no longer contains %s; the addresses from the neighbor "
                          "table rely on it, so none is added or removed"
                          % (path, ", ".join(repr(part) for part in missing)), "blocks_flush": False})
    return found


def core_fixes(texts):
    """ notes for core's fixes that have landed, from the texts core_contract reads: a fix whose
    file no longer holds one of its texts gives its note, with whether the page shows it. A missing
    file gives none, since it is a contract file whose absence already blocks
    """
    found = []
    for item, _path, expected, note, shown in CORE_FIXES:
        text = texts.get(item)
        if text is not None and any(part not in text for part in expected):
            found.append({"item": item, "note": note, "shown": shown})
    return found


def alias_view(tables, cache, hosts, pf_counts, now):
    """ status rows, one per mac alias, from the host rows that pass the row check. A key of the plugin's own
    in the cache is no MAC of its own: its address is listed under its MAC as a neighbor item, and a MAC that
    has only such keys still gets a row
    """
    current = {}
    for row in hosts:
        if _valid_row(row):
            current.setdefault(row[1].lower(), set()).add(canonical_ip(row[2]))
    neighbor_items = {}
    for key, value in cache.items():
        pair = parse_neighbor_key(key)
        if pair is not None:
            last_seen = value.get("last_seen") if isinstance(value, dict) else None
            neighbor_items.setdefault(pair[0], []).append(
                {"ip": pair[1], "age_s": int(now - last_seen) if _is_number(last_seen) else None})
    cache = {mac.lower(): value for mac, value in cache.items() if parse_neighbor_key(mac) is None}
    known = set(current) | set(cache) | set(neighbor_items)
    rows = []
    for name, entries in sorted(mac_aliases(tables).items()):
        macs = sorted({mac for matched in expand_entries(entries, known).values() for mac in matched})
        mac_rows = []
        for mac in macs:
            cached = cache.get(mac) or {}
            last_seen = cached.get("last_seen")
            mac_rows.append({
                "mac": mac,
                "cache_items": sorted({canonical_ip(ip) or ip for ip in cached.get("items", [])}),
                "cache_age_s": int(now - last_seen) if isinstance(last_seen, (int, float)) else None,
                "current_items": sorted(current.get(mac, set())),
                "neighbor_items": sorted(neighbor_items.get(mac, []), key=lambda item: item["ip"]),
            })
        rows.append({
            "name": name,
            "entries": entries,
            "macs": mac_rows,
            "nested_by": nesting_closure(tables, [name]),
            "pf_count": pf_counts.get(name),
        })
    return rows


def summarise(before, after):
    """ per alias: pf set sizes before/after a flush and the addresses added/removed """
    result = []
    for name in sorted(set(before) | set(after)):
        b, a = before.get(name), after.get(name)
        both = b is not None and a is not None
        result.append({
            "name": name,
            "before": len(b) if b is not None else None,
            "after": len(a) if a is not None else None,
            "added": sorted(set(a) - set(b)) if both else [],
            "removed": sorted(set(b) - set(a)) if both else [],
        })
    return result


def parse_update_reply(text: str) -> UpdateReply:
    """ update_tables.py's reply: the status and the messages of a JSON object whose status is a string;
    no status and no messages for any other text, and only the messages that are strings
    """
    try:
        reply = json.loads(text)
    # ValueError is no JSON; RecursionError is nesting deeper than the parser goes
    except (ValueError, RecursionError):
        return {"status": None, "messages": []}
    if not isinstance(reply, dict) or not isinstance(reply.get("status"), str):
        return {"status": None, "messages": []}
    messages = reply.get("messages")
    if not isinstance(messages, list):
        messages = []
    return {"status": reply["status"], "messages": [message for message in messages if isinstance(message, str)]}


def _is_number(value: object) -> TypeGuard[float]:
    """ an int or a finite float; a bool and an int too large to convert are refused """
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(value)
    except OverflowError:
        return False


def _is_count(value):
    return value is None or (isinstance(value, int) and not isinstance(value, bool))


def _is_strings(value):
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


_SUMMARY_KEYS = ("name", "before", "after", "added", "removed")


def _summary_row(row):
    """ one summarise() row with only its own keys, or None """
    if not isinstance(row, dict) or not all(key in row for key in _SUMMARY_KEYS):
        return None
    if not (isinstance(row["name"], str) and _is_count(row["before"]) and _is_count(row["after"])
            and _is_strings(row["added"]) and _is_strings(row["removed"])):
        return None
    return {key: row[key] for key in _SUMMARY_KEYS}


def last_schema(obj):
    """ last.json as cmd_flush writes it, {"at": time, "summary": [summarise() row]}, with only
    those keys; None for anything else
    """
    if not isinstance(obj, dict) or not _is_number(obj.get("at")) or not isinstance(obj.get("summary"), list):
        return None
    summary = [_summary_row(row) for row in obj["summary"]]
    if None in summary:
        return None
    return {"at": obj["at"], "summary": summary}


def cache_schema(obj):
    """ core's ArpCache file, {mac: {"items": [ip], "last_seen": time}}; entries of any other
    shape are dropped, as the file is only displayed. None when it is not an object at all
    """
    if not isinstance(obj, dict):
        return None
    return {
        mac: {"items": entry["items"], "last_seen": entry["last_seen"]}
        for mac, entry in obj.items()
        if isinstance(entry, dict) and _is_strings(entry.get("items")) and _is_number(entry.get("last_seen"))
    }


def _is_tally(value: object) -> bool:
    """ a count that is known: an int of 0 or more, never a bool """
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


_NEIGHBOR_TALLIES = ("added", "removed", "refreshed", "keys", "over_limit")


def neighbors_schema(obj: object) -> NeighborRecord | None:
    """ neighbors.json as a tick writes it, with only its own keys: the time, the result ("ok" or the code
    the tick answered with), the counts and at most five sample addresses; None for anything else
    """
    if not isinstance(obj, dict) or not _is_number(obj.get("at")) or not isinstance(obj.get("result"), str):
        return None
    samples = obj.get("samples")
    if not all(_is_tally(obj.get(name)) for name in _NEIGHBOR_TALLIES):
        return None
    if not isinstance(samples, list) or len(samples) > _SAMPLES or not _is_strings(samples):
        return None
    return {"at": obj["at"], "result": obj["result"], "added": obj["added"], "removed": obj["removed"],
            "refreshed": obj["refreshed"], "keys": obj["keys"], "over_limit": obj["over_limit"], "samples": samples}
