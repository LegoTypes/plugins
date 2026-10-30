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
alias definitions), list_hosts.py rows and the ArpCache JSON file.
"""
import ipaddress
import math
import re
import xml.etree.ElementTree as ET

_SPLIT = re.compile(r"[,\n]")
_MAC = re.compile(r"[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}")
# core's AliasNameField pattern (26.7.7), verbatim, without its reserved words
_ALIAS_NAME = re.compile(r"([a-zA-Z]|(([_a-zA-Z][a-zA-Z0-9]|[a-zA-Z][_a-zA-Z0-9])[_a-zA-Z0-9]{0,29}))")
_SAMPLES = 5
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
     "MAC aliases may now drop a vanished address on their own, which would make this plugin unnecessary", True),
    ("emptied_table", UPDATE_TABLES_PY, ("else cnt_alias_content",),
     "core may now flush emptied tables itself (core #10950); the plugin's own flush is redundant but harmless", False),
)


def parse_tables(xml_text):
    """ filter_tables.conf text -> {name: {type, address: [str], ttl: int|None}} """
    result = {}
    root = ET.fromstring(xml_text)
    for table in root.iter("table"):
        name = (table.findtext("name") or "").strip()
        if not name:
            continue
        address = [a.strip() for a in _SPLIT.split(table.findtext("address") or "") if a.strip()]
        ttl_text = (table.findtext("ttl") or "").strip()
        result[name] = {
            "type": (table.findtext("type") or "").strip(),
            "address": address,
            "ttl": int(ttl_text) if ttl_text.isdigit() else None,
        }
    return result


def mac_aliases(tables):
    """ enabled mac aliases (a disabled alias has an empty address) -> lower-cased entries """
    return {
        name: [entry.lower() for entry in table["address"]]
        for name, table in tables.items()
        if table["type"] == "mac" and table["address"]
    }


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
    """ status rows, one per mac alias, from the host rows that pass the row check """
    current = {}
    for row in hosts:
        if _valid_row(row):
            current.setdefault(row[1].lower(), set()).add(canonical_ip(row[2]))
    cache = {mac.lower(): value for mac, value in cache.items()}
    known = set(current) | set(cache)
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


def _is_number(value):
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
