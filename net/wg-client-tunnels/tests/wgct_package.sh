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
# per node, and neither the description nor the installed tree names a provider. Every configd action names the
# groups configd admits and none has a description line (core's cron page would offer it to nobody's crontab), and
# one that runs tunnel.php puts its options before the command; the service API's four
# stock actions refuse a read-only user first; the self-tests keep no file under the system's temporary directory;
# every end-anchored pattern carries /D; the health mirror's saves take no history entry and its failures are
# warnings; the privilege and the description say what the privilege grants. It reads the plugin tree directly
# (cron.d, actions.d and pkg-descr never reach the VM's suite uploads), with POSIX sh, grep, sed and awk, so it runs
# on the Mac, like the header test.
#
# Usage: wgct_package.sh /path/to/net/wg-client-tunnels

set -u
D="$1"
CRON="$D/src/etc/cron.d/wgclienttunnels"
ACTIONS="$D/src/opnsense/service/conf/actions.d/actions_wgclienttunnels.conf"
DESCR="$D/pkg-descr"
SCRIPTS="$D/src/opnsense/scripts/OPNsense/WGClientTunnels"
MIRROR="$SCRIPTS/health_mirror.php"
SERVICE="$D/src/opnsense/mvc/app/controllers/OPNsense/WGClientTunnels/Api/ServiceController.php"
ACL="$D/src/opnsense/mvc/app/models/OPNsense/WGClientTunnels/ACL/ACL.xml"
# the groups every action names, and the number of actions
GROUPS_LINE='allowed_groups:wheel,wwwonly'
SECTIONS=19
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

# the last line of every section is the groups line, each section has one, and there are as many sections as known
bad=$(awk -v want="$GROUPS_LINE" '
    function close_section() { if (name != "" && last != want) print name " ends with: " last }
    /^\[/ { close_section(); name = $0; last = ""; next }
    /^[[:space:]]*(#|$)/ { next }
    { last = $0 }
    END { close_section() }' "$ACTIONS" 2>&1)
n=$(grep -c '^\[' "$ACTIONS" 2> /dev/null)
g=$(grep -c -x -F -e "$GROUPS_LINE" "$ACTIONS" 2> /dev/null)
[ "$n" = "$SECTIONS" ] && [ "$g" = "$SECTIONS" ] || bad=$(printf '%s\n%s\n' "$bad" "${n:-no} sections and ${g:-no} '$GROUPS_LINE' lines in $ACTIONS, not $SECTIONS of each" | sed '/^$/d')
report "every one of the $SECTIONS configd actions ends with $GROUPS_LINE" "$bad"

# core's cron page (System > Settings > Cron) offers every action that has a description line and runs its jobs
# from nobody's crontab: an account in neither group, which every action here refuses
report "no configd action has a description line, so core's cron page offers none of them" "$(grep -n '^description:' "$ACTIONS" 2>&1)"

# a caller's value comes after the command, where tunnel.php reads no option
tunnel=$(printf '%s\n' "$commands" | grep -F '/wgct.sh tunnel')
bad=$(printf '%s\n' "$tunnel" | grep -v -E '^command:/usr/local/opnsense/scripts/OPNsense/WGClientTunnels/wgct[.]sh tunnel --json( --dry)? [a-z-]+$')
[ -n "$tunnel" ] || bad="no action runs wgct.sh tunnel in $ACTIONS"
report "every configd action that runs tunnel.php puts --json, and --dry where it previews, before the command and nothing after it" "$bad"

# the service API: each stock action that starts, stops or reloads refuses a read-only user before its parent runs
bad=""
for a in start stop restart reconfigure; do
    awk -v a="$a" '
        index($0, "public function " a "Action()") { at = NR }
        at && NR == at + 2 && index($0, "$this->throwReadOnly();") { guarded = 1 }
        at && NR == at + 3 && guarded && index($0, "return parent::" a "Action();") { ok = 1 }
        END { exit ok ? 0 : 1 }' "$SERVICE" 2> /dev/null || bad="$bad${a}Action "
done
report "the service controller's start, stop, restart and reconfigure call throwReadOnly() first, then their parent" "$bad"

# the self-tests' files: one helper and a root of its own, never the system's temporary directory
temp=$(grep -r -n -F 'sys_get_temp_dir' "$D/src" 2>&1 \
    | grep -v -E "/lib/render[.]php:[0-9]+:[[:space:]]*[$]errFile = tempnam[(]sys_get_temp_dir[(][)], 'wgct_pfctl'[)];\$")
globs=$(grep -r -n -F "array_map('unlink', glob(" "$D/src" 2>&1)
consts=$(grep -n -E '^[[:space:]]*(const[[:space:]]|define[[:space:]]*[(])' "$SCRIPTS/lib/selftest.php" 2>&1)
bad=$(printf '%s\n%s\n%s\n' "$temp" "$globs" "$consts" | sed '/^$/d')
report "no file under sys_get_temp_dir() but pfctl's stderr, no unlink over a glob, and no constant in lib/selftest.php" "$bad"

# a pattern that ends in "$", a delimiter (/, # or ~) and flags without D lets a trailing line break pass. The two
# multi-line patterns, whose "$" is the end of a line by intent, are named here
bad=$(grep -r -n -E --include='*.php' --include='*.inc' -e "[$][/#~][a-zA-CE-Z]*['\"]" "$D/src" 2>&1 \
    | grep -v -F -e "'/^command:(.*)\$/m'" -e "'/^type:script\$/m'")
report "every end-anchored pattern carries /D (none ends in \$, a delimiter and flags without D), the two multi-line patterns aside" "$bad"

# the mirror's two saves take no configuration history entry; the page's actions and the removal's release-holds do
calls() {
    grep -c -E 'wgct_locked_commit[(][^)]' "$1" 2> /dev/null
}
got="mirror $(calls "$MIRROR") calls, $(grep -c -E '^[[:space:]]*[}], null, false[)];$' "$MIRROR" 2> /dev/null) without history"
got="$got; writer $(calls "$SCRIPTS/lib/writer.php") calls, $(grep -c -F "wgct_locked_commit(\$guarded, 'wg upstream tunnels: ' . \$description);" "$SCRIPTS/lib/writer.php" 2> /dev/null) with a description alone"
got="$got; cli $(calls "$SCRIPTS/lib/cli.php") calls, $(grep -c -E "^[[:space:]]*[}], 'wg upstream tunnels: release holds [(]package removal[)]'[)];$" "$SCRIPTS/lib/cli.php" 2> /dev/null) with a description alone"
want="mirror 2 calls, 2 without history; writer 1 calls, 1 with a description alone; cli 1 calls, 1 with a description alone"
[ "$got" = "$want" ] && bad="" || bad="$got"
report "health_mirror.php passes false as the third argument of both commits; lib/writer.php and lib/cli.php pass none" "$bad"

# the mirror's skips, one call a line (a call ends with ");"): a failure is a warning, the lock another run holds a
# notice
notes=$(tr -s '\n ' '  ' < "$MIRROR" 2> /dev/null | sed 's/); /);\
/g' | grep -F 'wgct_note_lock(')
bad=""
for text in 'tick skipped: health.lock cannot be opened' 'gateway change left for the next tick' 'kern.boot_id cannot be read'; do
    printf '%s\n' "$notes" | grep -F -e "$text" | grep -q -F ', $logTag, LOG_WARNING);' || bad=$(printf '%s\n%s\n' "$bad" "not a warning: $text" | sed '/^$/d')
done
n=$(printf '%s\n' "$notes" | grep -c -F 'LOG_WARNING')
[ "$n" = 3 ] || bad=$(printf '%s\n%s\n' "$bad" "$n wgct_note_lock() statements name LOG_WARNING, not 3" | sed '/^$/d')
quiet=$(printf '%s\n' "$notes" | grep -F '$tickMsg' | grep -F -e 'LOG_' -e '$logTag')
[ "$(printf '%s\n' "$notes" | grep -c -F ', true, $tickMsg,')" = 1 ] || quiet="no skip of \$tickMsg in $MIRROR"
bad=$(printf '%s\n%s\n' "$bad" "$quiet" | sed '/^$/d')
report "of the mirror's four skips three are warnings; the tick another run holds the lock for names no priority" "$bad"

# the description wraps its lines, so it is read as one line with single spaces
tr -s '\n ' '  ' < "$DESCR" | grep -q -F -e '- Per node: not synchronised to a CARP peer; each firewall manages its own tunnels' \
    && bad="" || bad="no Per node line in $DESCR"
report "pkg-descr says the plugin is per node" "$bad"

# the privilege says what it grants, in its name and in the description's feature list
PRIV_NAME='VPN: WireGuard: Upstream tunnels (creates and removes WireGuard instances, gateways, routes and outbound NAT)'
bad=""
grep -q -F -e "<name>$PRIV_NAME</name>" "$ACL" 2> /dev/null || bad="the privilege's name in $ACL"
grep -q -F -e '<page-vpn-wgclienttunnels>' "$ACL" 2> /dev/null || bad=$(printf '%s\n%s\n' "$bad" "the privilege's key page-vpn-wgclienttunnels in $ACL" | sed '/^$/d')
sed '/^Plugin Changelog$/,$d' "$DESCR" | tr -s '\n ' '  ' | grep -q -F -e '- One privilege for the page and its API. Its holder can create, change and remove WireGuard instances and peers, interface assignments, gateways, static routes and outbound NAT rules through the plugin, and send sized pings from a WAN, without the privileges of those core pages - Per node' \
    || bad=$(printf '%s\n%s\n' "$bad" "no privilege line before the Per node line in $DESCR" | sed '/^$/d')
report "the privilege's name and pkg-descr say what the privilege grants" "$bad"

# the description above its changelog, and everything the package installs, name no provider and no "this site"
names='proton|this site'
descr_hits=$(sed '/^Plugin Changelog$/,$d' "$DESCR" | grep -n -i -E "$names" | sed 's|^|pkg-descr:|')
src_hits=$(grep -r -n -i -E "$names" "$D/src" 2>&1)
bad=$(printf '%s\n%s\n' "$descr_hits" "$src_hits" | sed '/^$/d')
report "no provider or site name" "$bad"

echo "package: $pass/$((pass + fail)) passed"
[ "$fail" = 0 ]
