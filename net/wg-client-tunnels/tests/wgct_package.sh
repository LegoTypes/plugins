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
# Package test: what the plugin registers with core. Cron and configd enter only through wgct.sh (or, for the
# alarm replay, core's own flock), no configd action is left that nothing calls, pkg-descr says the plugin is
# per node, and neither the description nor the installed tree names a provider. It reads the plugin tree directly
# (cron.d, actions.d and pkg-descr never reach the VM's suite uploads), with POSIX sh and grep, so it runs on the
# Mac, like the header test.
#
# Usage: wgct_package.sh /path/to/net/wg-client-tunnels

set -u
D="$1"
CRON="$D/src/etc/cron.d/wgclienttunnels"
ACTIONS="$D/src/opnsense/service/conf/actions.d/actions_wgclienttunnels.conf"
DESCR="$D/pkg-descr"
pass=0
fail=0

# report DESC BAD: PASS when BAD (the offending lines, evidence) is empty
report() {
    if [ -z "$2" ]; then
        pass=$((pass + 1)); echo "[PASS] package: $1"
    else
        fail=$((fail + 1)); echo "[FAIL] package: $1"
        printf '%s\n' "$2" | sed 's/^/      | /'
    fi
}

# every cron line: five time fields, root, then wgct.sh and its plain words only, after an optional `sleep N && `
lines=$(grep -v -E '^[[:space:]]*(#|$)' "$CRON" 2>&1)
bad=$(printf '%s\n' "$lines" | grep -v -E '^([^[:space:]]+[[:space:]]+){5}root[[:space:]]+(sleep [0-9]+ && )?/usr/local/opnsense/scripts/OPNsense/WGClientTunnels/wgct[.]sh( [a-z_-]+)*$')
[ -n "$lines" ] || bad="no cron line in $CRON"
report "cron runs only wgct.sh" "$bad"

commands=$(grep '^command:' "$ACTIONS" 2>&1)
bad=$(printf '%s\n' "$commands" | grep -v -E '^command:(/usr/local/opnsense/scripts/OPNsense/WGClientTunnels/wgct[.]sh |/usr/local/bin/flock -o -w 120 /tmp/filter_reload_gateway[.]lock )')
[ -n "$commands" ] || bad="no command line in $ACTIONS"
report "every configd action runs wgct.sh or core's flock" "$bad"

report "no action without a caller" "$(grep -E '^\[(health_mirror|list|tunnel_status|configure_routes)\]$' "$ACTIONS" 2>&1)"

# the description wraps its lines, so it is read as one line with single spaces
tr -s '\n ' '  ' < "$DESCR" | grep -q -F -e '- Per node: not synchronised to a CARP peer; each firewall manages its own tunnels' \
    && bad="" || bad="no Per node line in $DESCR"
report "pkg-descr says the plugin is per node" "$bad"

# the description above its changelog, and everything the package installs, name no provider and no "this site"
names='proton|this site'
descr_hits=$(sed '/^Plugin Changelog$/,$d' "$DESCR" | grep -n -i -E "$names" | sed 's|^|pkg-descr:|')
src_hits=$(grep -r -n -i -E "$names" "$D/src" 2>&1)
bad=$(printf '%s\n%s\n' "$descr_hits" "$src_hits" | sed '/^$/d')
report "no provider or site name" "$bad"

echo "package: $pass/$((pass + fail)) passed"
[ "$fail" = 0 ]
