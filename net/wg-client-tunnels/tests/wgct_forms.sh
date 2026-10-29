#!/bin/sh

# Copyright (C) 2026 cayossarian
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Forms test: the forms and the page are built from core parts. Every <help> is plain text, as core shows it (no
# markup, entity, quote or CDATA, printable ASCII only), and states no default and no range (the refusals state
# the ranges); no grid column has a fixed width; labels are in sentence case. The page has no inline style block
# and no width style, and uses core's apply button with its service controls, core's grids and core's help. It
# reads the plugin tree directly, with POSIX sh and grep, so it runs on the Mac, like the header test.
#
# Usage: wgct_forms.sh /path/to/net/wg-client-tunnels

set -u
D="$1"
F="$D/src/opnsense/mvc/app/controllers/OPNsense/WGClientTunnels/forms"
V="$D/src/opnsense/mvc/app/views/OPNsense/WGClientTunnels/index.volt"
pass=0
fail=0

# report DESC BAD: PASS when BAD (the offending lines, evidence) is empty
report() {
    if [ -z "$2" ]; then
        pass=$((pass + 1)); echo "[PASS] $1"
    else
        fail=$((fail + 1)); echo "[FAIL] $1"
        printf '%s\n' "$2" | sed 's/^/      | /'
    fi
}

# forms PATTERN: the forms' lines matching PATTERN, as FILE:LINE:TEXT with the file's name only
forms() {
    grep -n -H -e "$1" "$F"/*.xml | sed "s|^$F/||"
}

# every <help> as FILE:LINE:TEXT; a <help> that does not close on its own line cannot be read, and is evidence itself
helps=$(forms '^[[:space:]]*<help>')
[ -n "$helps" ] || helps="no <help> in $F"
texts=$(printf '%s\n' "$helps" | sed -n 's|^\([^:]*:[0-9]*:\).*<help>\(.*\)</help>.*$|\1\2|p')
unclosed=$(printf '%s\n' "$helps" | grep -v '</help>')

bad=$(printf '%s\n' "$unclosed"; printf '%s\n' "$texts" | grep -e '[<>&"]'; printf '%s\n' "$texts" | LC_ALL=C grep -e '[^ -~]')
report "forms: help text is plain" "$(printf '%s\n' "$bad" | grep -v '^$')"

report "forms: no fixed column width" "$(forms '<width>')"

report "forms: no help states a default" "$(forms 'Normally')"

report "forms: no range in help" "$(printf '%s\n' "$texts" | grep -E -e '1 to 27|1280 to 1420|from 1280')"

# sentence case: after a label's first word, no word is one capital and lower case only (WAN, IPv6 and WireGuard
# are not)
labels=$(forms '^[[:space:]]*<label>' | sed -n 's|^\([^:]*:[0-9]*:\).*<label>\(.*\)</label>.*$|\1\2|p')
bad=$(forms 'Tunnel References'; printf '%s\n' "$labels" \
    | sed 's|^\([^:]*:[0-9]*:\)[^ ]*|\1|' | grep -E -e ' [A-Z][a-z]+( |$)')
report "forms: headings in sentence case" "$(printf '%s\n' "$bad" | grep -v '^$')"

report "forms: the Enable help says Apply with the plugin disabled stops it" \
    "$(grep -A4 -F '<id>wgclienttunnels.enabled</id>' "$F/general.xml" | grep -q -F 'Apply with the plugin disabled stops it' \
        || echo "general.xml: the Enable help does not say it")"

report "page: no inline style block and no width style" "$(grep -n -e '<style' -e 'style="[^"]*width' "$V")"

report "page: no brief beside core's help" "$(grep -n -e 'brief' "$V"; forms '<brief>')"

bad=""
grep -q -F "partial('layout_partials/base_apply_button', {'data_endpoint': '/api/wgclienttunnels/service/reconfigure', 'data_service_widget': 'wgclienttunnels'" "$V" \
    || bad="no base_apply_button for service/reconfigure with the service widget"
[ -z "$(grep -n -e 'id="reconfigureAct"' "$V")" ] || bad="$bad${bad:+
}a hand-made reconfigureAct button is left"
grep -q -F "updateServiceControlUI('wgclienttunnels');" "$V" || bad="$bad${bad:+
}the service controls are not loaded with the page"
report "page: Apply is core's apply button, with core's service controls" "$bad"

bad=""
grep -q -F "partial('layout_partials/base_bootgrid_table', formGridUnmanaged" "$V" || bad="no base_bootgrid_table over formGridUnmanaged"
grep -q -F "search: '/api/wgclienttunnels/tunnels/search_unmanaged'" "$V" || bad="$bad${bad:+
}the grid does not search tunnels/search_unmanaged"
[ -z "$(grep -n -e 'unmanaged-table' "$V")" ] || bad="$bad${bad:+
}the hand-made unmanaged table is left"
report "page: the unmanaged instances are core's grid over search_unmanaged" "$bad"

echo "forms: $pass/$((pass + fail)) passed"
[ "$fail" = 0 ]
