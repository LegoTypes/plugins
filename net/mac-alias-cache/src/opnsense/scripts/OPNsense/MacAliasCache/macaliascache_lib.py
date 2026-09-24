"""
Copyright (C) 2026 cayossarian (Bill Flood)
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
import re
import xml.etree.ElementTree as ET

_SPLIT = re.compile(r"[,\n]")


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
    """
    Every alias that nests a target, directly or through other aliases. Matching is on
    whole address tokens (a nested alias is listed by exact name). Computed here rather
    than via core's get_affected_aliases, which reuses dep_lists across iterations and
    can skip a parent.
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


def alias_view(tables, cache, hosts, pf_counts, now):
    """ status rows, one per mac alias """
    current = {}
    for row in hosts:
        if len(row) >= 3:
            current.setdefault(row[1].lower(), set()).add(row[2])
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
                "cache_items": sorted(cached.get("items", [])),
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
