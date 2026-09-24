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
