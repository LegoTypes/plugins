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
# VM tests for the plugin's API guards and the one-at-a-time MTU measurement. Root on the disposable test VM only
# (vm_selftest.sh), never on a firewall.
#
# It creates two throw-away users through core's own User model and gives each an API key: one with access
# to the plugin page plus core's user-config-readonly privilege (what throwReadOnly() checks), and a control
# with the page privilege only. It calls the installed plugin's API with curl against the GUI on this
# machine, so the controllers under test are the ones the GUI serves (vm_overlay.sh puts the working tree
# there); the CLI case runs the copy of the scripts vm_selftest.sh puts in /tmp/wgct. At exit, even on
# failure, it removes both users, and with them their keys.
#
# Case 1: the read-only user's measure_mtu POST is refused. core's throwReadOnly() raises a UserException, which
#         core's API front controller answers as HTTP 500 with the message "User NAME denied for write access
#         (user-config-readonly set)" (UserBaseException::getHttpCode() is 500), so "refused" means that pair.
# Case 2: its dry=1 POSTs to edit, remove, adopt and the sentinel are refused, and configd's log shows no plugin
#         action in that window. The control user's dry sentinel preview answers 200 and does appear in the log, so
#         the check can see what it looks for. (core's reconfigure flow writes no config, so it has no read-only
#         guard; the service's Apply is case 7.)
# Case 2b: every request the plugin refuses answers status failed: a GET to create, an empty create form, edit
#         with a value that is not a uuid, edit with dry=yes, remove with a value that is not a uuid, measure_mtu
#         without a WAN and the sentinel with dry=yes.
# Case 3: two concurrent measure-mtu runs give one measurement and one refusal.
# Case 4: the control user's settings/set POST naming `managed` and `held` is
#         saved with no validation message and changes neither the settings node (its persisted_at stamp aside,
#         which every save rewrites) nor the engine node: the settings model has no such fields. Should a change
#         get through, the old values are posted back so the VM keeps its managed list.
# Case 4b: while the installed lib/mirror.php cannot be read (pkg's rename window), the control user's settings/set
#         POST is refused with core's UserException (HTTP 500, "The plugin is being installed or upgraded") and
#         PHP's error log does not grow: no fatal reaches core's crash reporter. cron is stopped meanwhile, so no
#         tick runs without its library, and the file is put back at once (and at exit).
#
# Case 5: an unmanaged WireGuard instance: apply refuses it and does nothing. The instance
#         is created through core's Server model with a synthetic key, a documentation-range address and
#         enabled=0, so it has no device; the observables are configd's log (an apply would log its
#         `wireguard restart UUID`) and `wg show all latest-handshakes`. It is removed at exit.
#
# Case 6: the tunnel list's banners. This core carries the fix for opnsense/core#10951, so the core contract gives
#         only the no_dad note: tunnels/lists's global findings hold it as a core-fixed finding at level info and no
#         core-contract finding. The installed page takes each banner's class from its finding's level, so a note is
#         never shown as a warning.
#
# Case 7: the service's Apply (service/reconfigure) runs core's reconfigure flow, with the soft reload. The base has
#         IPv6 routes off and no IPv6 on rehearse, so nothing would be watched: the cases turn IPv6 routes on in the
#         settings, and each case that watches rehearse's line turns rehearse's IPv6 on through the plugin's Edit
#         and off again at its end. cron is stopped meanwhile, so no tick saves config under the reads.
#         - Enabled and running, the Apply reloads the route set: configd logs the reload and no stop; the enabled
#           marker (stop removes it, start creates it) and footprint.json keep their inodes, footprint.json its at,
#           and every record line's address, next-hop route and monitor route stay on its device, with no
#           `removed` or `stopped` line in the plugin's log.
#         - Disabled, the Apply stops the plugin: not running, and no record.
#         - Enabled again and stopped (the save's queued reconcile has already run the route set), a hook and a
#           reconcile add nothing back and the plugin stays stopped, with one log line saying so; the Apply starts
#           it: configd logs the start, and it runs with rehearse's line in the record.
#         - IPv6 routes off on the enabled plugin, a start leaves it running as core's service status reads it, so
#           the Apply reloads it: configd logs the reload, and no start or stop.
#         At the end the settings are put back, stop and start rebuild the route set they give, and a filter reload
#         records the footprint again (also at exit, should the suite end inside the case).
# Case 8: tunnels/lists and tunnels/choices answer; tunnels/search and tunnels/options are gone. The unmanaged
#         instances grid's tunnels/search_unmanaged finds case 5's instance, still there, by its name, with its uuid
#         and as disabled, and searches only its text columns: its uuid finds nothing.
#
# The dummy tunnel `rehearse` (bound to the second VM WAN, endpoint 192.0.2.10) provides the uuid; the first
# VM WAN is never touched.
#
# Usage: wgct_api.sh /path/to/wgct.sh   (tunnel.php beside it)

set -u
SRC="$1"
TUNNEL="$(dirname "$SRC")/tunnel.php"
PHP="/usr/local/bin/php -d log_errors=0"
API=https://127.0.0.1/api/wgclienttunnels
PAGE_PRIV=page-vpn-wgclienttunnels
RO_USER=wgct-api-readonly
CTL_USER=wgct-api-control
WAN=WAN_B
ENDPOINT=192.0.2.10
T=$(mktemp -d /tmp/wgct-api.XXXXXX)
PASS=0
FAIL=0

check() {
    if [ "$2" = "$3" ]; then
        PASS=$((PASS + 1))
        echo "[PASS] $1"
    else
        FAIL=$((FAIL + 1))
        echo "[FAIL] $1 (expected '$3', got '$2')"
    fi
}

. "$(dirname "$0")/wgct_marks.sh"
. "$(dirname "$0")/wgct_settle.sh"
. "$(dirname "$0")/wgct_exact.sh"
MIRROR_LIB=/usr/local/opnsense/scripts/OPNsense/WGClientTunnels/lib/mirror.php
RECORD=/var/run/wgclienttunnels/active_gateways
FOOTPRINT=/var/db/wgclienttunnels/footprint.json
# rehearse's IPv6 tunnel address and monitor while case 7 turns its IPv6 on
R6=2001:db8:0:99::2
M6=2001:db8:ffff::99

USERS="$(dirname "$0")/wgct_user.php"
EDIT_REQUEST="$(dirname "$0")/wgct_edit_request.php"

UNMANAGED_NAME=wgct-api-unmanaged

cat > "$T/instance.php" <<'PHPEOF'
<?php
require_once 'config.inc';
require_once '/usr/local/opnsense/mvc/script/load_phalcon.php';

use OPNsense\Core\Config;
use OPNsense\Wireguard\Server;

/* instance.php create NAME PRIVKEY => its uuid; instance.php delete NAME */
[, $mode, $name] = $argv;
Config::getInstance()->lock();
$model = new Server();
if ($mode === 'create') {
    $server = $model->servers->server->Add();
    $uuid = $server->getAttribute('uuid');
    $server->enabled = '0';
    $server->name = $name;
    $server->instance = '9';
    $server->privkey = $argv[3];
    $server->port = '51899';
    $server->tunneladdress = '198.51.100.9/32';
    foreach ($model->performValidation() as $msg) {
        fwrite(STDERR, $msg->getMessage() . "\n");
        Config::getInstance()->unlock();
        exit(1);
    }
    $model->serializeToConfig(false, true);
    Config::getInstance()->save();
    echo $uuid, "\n";
    exit(0);
}
foreach ($model->servers->server->iterateItems() as $uuid => $node) {
    if ((string)$node->name === $name) {
        $model->servers->server->del($uuid);
    }
}
$model->serializeToConfig(false, true);
Config::getInstance()->save();
PHPEOF

remove_instance() {
    $PHP "$T/instance.php" delete "$UNMANAGED_NAME" > /dev/null 2>&1
}

remove_users() {
    for u in "$RO_USER" "$CTL_USER"; do
        $PHP "$USERS" delete "$u" > /dev/null 2>&1
        configctl auth sync user "$u" > /dev/null 2>&1
    done
}

cleanup() {
    [ -f "$T/mirror.php.off" ] && mv "$T/mirror.php.off" "$MIRROR_LIB"
    [ -f "$T/svc.settings" ] && svc_restore > /dev/null
    service cron status > /dev/null 2>&1 || service cron start > /dev/null 2>&1
    remove_users
    remove_instance
    rm -rf "$T"
}
trap cleanup EXIT

# a leftover from an interrupted run goes first
remove_users

make_user() {
    $PHP "$USERS" create "$1" "$2" || return 1
    configctl auth sync user "$1" > /dev/null 2>&1
}

RO_CRED=$(make_user "$RO_USER" "$PAGE_PRIV,user-config-readonly")
CTL_CRED=$(make_user "$CTL_USER" "$PAGE_PRIV")
[ -n "$RO_CRED" ] && [ -n "$CTL_CRED" ] || { echo "[FAIL] the test users could not be created"; exit 1; }

UUID=$($PHP "$TUNNEL" --json list | $PHP -r '
    $j = json_decode(stream_get_contents(STDIN), true);
    foreach ($j["tunnels"] as $t) { if ($t["name"] === "rehearse") { echo $t["uuid"]; } }')
[ -n "$UUID" ] || { echo "[FAIL] the rehearse tunnel is missing (vm_base.sh)"; exit 1; }

# call CREDENTIALS PATH [CURL ARGS]: prints the HTTP status, the body goes to $T/body
call() {
    cred="$1"; path="$2"; shift 2
    curl -sk -m 150 -o "$T/body" -w '%{http_code}' -u "$cred" -X POST "$@" "$API/$path"
}

# refused CREDENTIALS PATH [CURL ARGS]: "refused" when core's throwReadOnly() answered (core's UserException is
# HTTP 500 with the message "User NAME denied for write access (user-config-readonly set)"), else "answered HTTP n"
refused() {
    code=$(call "$@")
    if [ "$code" = 500 ] && grep -q 'denied for write access (user-config-readonly set)' "$T/body"; then
        echo refused
    else
        echo "answered HTTP $code"
    fi
}

# plugin actions configd logged after MARK (wgct_marks.sh): the lines that name one of the actions with a side
# effect or a preview
ACTIONS='previewing the (removal|adoption|no-default)|ensuring the no-default|removing WireGuard upstream|adopting WireGuard instance|measuring the tunnel MTU|applying WireGuard upstream tunnel [0-9a-f]|rebinding WireGuard|(reconfiguring|reloading|starting|stopping) WireGuard upstream tunnel IPv6 routes'
actions() {
    lcount configd "$1" -E -e "$ACTIONS"
}

# the control user may preview, and the preview shows in configd's log
mark=$(lmark configd)
check "control user (page privilege only): dry sentinel preview answers 200" \
    "$(call "$CTL_CRED" service/sentinel -d dry=1)" 200
check "control user: that preview is in configd's log" "$(actions "$mark")" 1

# case 1
check "read-only user: measure_mtu POST is refused" \
    "$(refused "$RO_CRED" tunnels/measure_mtu -d "wan=$WAN" -d "endpoint=$ENDPOINT")" refused

# case 2
mark=$(lmark configd)
for what in "tunnels/edit/$UUID" "tunnels/remove/$UUID" "tunnels/adopt/$UUID" service/sentinel; do
    check "read-only user: dry=1 POST to $(echo "$what" | sed "s/$UUID/<uuid>/") is refused" \
        "$(refused "$RO_CRED" "$what" -d dry=1)" refused
done
check "read-only user: no plugin action in configd's log" "$(actions "$mark")" 0

# case 2b: the reply's status, of the body the last request left
status_of() {
    $PHP -r '$j = json_decode((string)file_get_contents($argv[1]), true); echo is_array($j) ? ($j["status"] ?? "none") : "not-json";' "$T/body"
}
curl -sk -m 150 -o "$T/body" -u "$CTL_CRED" "$API/tunnels/create" > /dev/null
statuses="get-create=$(status_of)"
call "$CTL_CRED" tunnels/create > /dev/null
statuses="$statuses empty-create=$(status_of)"
call "$CTL_CRED" tunnels/edit/not-a-uuid > /dev/null
statuses="$statuses edit-not-a-uuid=$(status_of)"
call "$CTL_CRED" "tunnels/edit/$UUID" -d dry=yes > /dev/null
statuses="$statuses edit-dry-yes=$(status_of)"
call "$CTL_CRED" tunnels/remove/not-a-uuid > /dev/null
statuses="$statuses remove-not-a-uuid=$(status_of)"
call "$CTL_CRED" tunnels/measure_mtu -d "endpoint=$ENDPOINT" > /dev/null
statuses="$statuses measure-no-wan=$(status_of)"
call "$CTL_CRED" service/sentinel -d dry=yes > /dev/null
statuses="$statuses sentinel-dry-yes=$(status_of)"
check "api: every refused request answers status failed" "$statuses" \
    "get-create=failed empty-create=failed edit-not-a-uuid=failed edit-dry-yes=failed remove-not-a-uuid=failed measure-no-wan=failed sentinel-dry-yes=failed"

# case 3: two measurements at once; the loser is refused while the winner pings (about 3 s)
$PHP "$TUNNEL" --json measure-mtu "$WAN" "$ENDPOINT" > "$T/m1" &
P1=$!
$PHP "$TUNNEL" --json measure-mtu "$WAN" "$ENDPOINT" > "$T/m2" &
P2=$!
wait "$P1" "$P2"
oks=0
refusals=0
for f in "$T/m1" "$T/m2"; do
    case "$(cat "$f")" in
        *'"ok":true'*) oks=$((oks + 1)) ;;
        *'another MTU measurement is running'*) refusals=$((refusals + 1)) ;;
    esac
done
check "two concurrent measure-mtu: one measurement" "$oks" 1
check "two concurrent measure-mtu: one refusal" "$refusals" 1
# the lock is free again afterwards
$PHP "$TUNNEL" --json measure-mtu "$WAN" "$ENDPOINT" > "$T/m3"
check "a measurement after both: runs" "$(grep -c '"ok":true' "$T/m3")" 1

# case 4: the plugin's two config nodes, the settings node without its persisted_at stamp
nodes() {
    $PHP -r '
        $x = simplexml_load_file("/conf/config.xml");
        $s = $x->OPNsense->WGClientTunnels;
        unset($s["persisted_at"]);
        echo $s->asXML(), "\n", (string)$x->OPNsense->WGClientTunnelsEngine->asXML(), "\n";'
}
# the settings node's raw value of FIELD, as a 3.7_1 config holds it
raw_field() {
    $PHP -r 'echo (string)simplexml_load_file("/conf/config.xml")->OPNsense->WGClientTunnels->{$argv[1]};' "$1"
}
FOREIGN=00000000-0000-4000-8000-0000000000f5
OLD_MANAGED=$(raw_field managed)
OLD_HELD=$(raw_field held)
nodes > "$T/nodes.before"
check "control user: a settings/set POST naming managed and held answers 200" \
    "$(call "$CTL_CRED" settings/set -d "wgclienttunnels[managed]=$FOREIGN" -d "wgclienttunnels[held]=$FOREIGN")" 200
check "control user: that POST is saved with no validation message" "$(cat "$T/body")" '{"result":"saved"}'
nodes > "$T/nodes.after"
if cmp -s "$T/nodes.before" "$T/nodes.after"; then
    same=unchanged
else
    same=changed
    call "$CTL_CRED" settings/set -d "wgclienttunnels[managed]=$OLD_MANAGED" -d "wgclienttunnels[held]=$OLD_HELD" > /dev/null
fi
check "control user: that POST leaves the settings node and the engine node as they were" "$same" unchanged

# case 4b (PHP's error log as core's GUI crash reporter reads it)
PHPLOG=/var/lib/php/tmp/PHP_errors.log
log0=$(stat -f %z "$PHPLOG" 2> /dev/null || echo 0)
cq=$(cron_quiesce) && cq=cron-quiet
mv "$MIRROR_LIB" "$T/mirror.php.off"
code=$(call "$CTL_CRED" settings/set -d 'wgclienttunnels[enabled]=1')
mv "$T/mirror.php.off" "$MIRROR_LIB"
service cron start > /dev/null 2>&1
check "control user: a settings/set POST while lib/mirror.php cannot be read is refused (HTTP 500: the plugin is being installed or upgraded) and PHP's error log does not grow" \
    "$code $(grep -c 'The plugin is being installed or upgraded' "$T/body") $(stat -f %z "$PHPLOG" 2> /dev/null || echo 0) $cq" "500 1 $log0 cron-quiet"

# case 7: the service's Apply
svc_status() {
    configctl wgclienttunnels status
}
# settings FIELD=VALUE...: the control user's settings/set of those fields; prints the reply
settings() {
    for f in "$@"; do
        set -- "$@" -d "wgclienttunnels[${f%%=*}]=${f#*=}"
        shift
    done
    call "$CTL_CRED" settings/set "$@" > /dev/null
    cat "$T/body"
}
# reconfigure: the page's Apply; prints the reply's status
reconfigure() {
    call "$CTL_CRED" service/reconfigure > /dev/null
    status_of
}
# quiet: the reconcile a save queues has run, and the gateways are quiet
quiet() {
    reconcile_drained 150 && gw_quiet 120
}
# rehearse_ipv6 on|off: the plugin's Edit turns rehearse's IPv6 on or off; prints "ok" or what the reply said. "on" does
# nothing when rehearse already has an IPv6 address, and "off" turns off only what "on" turned on ($T/r6.set, a file
# so that a call in a command substitution keeps it).
rehearse_ipv6() {
    if [ "$1" = on ]; then
        if $PHP -r 'foreach (simplexml_load_file("/conf/config.xml")->OPNsense->wireguard->server->servers->server as $s) {
                if ((string)$s->name === "rehearse" && str_contains((string)$s->tunneladdress, ":")) { exit(0); } } exit(1);'; then
            echo ok
            return
        fi
        : > "$T/r6.set"
    elif [ ! -f "$T/r6.set" ]; then
        echo ok
        return
    else
        rm -f "$T/r6.set"
    fi
    $PHP "$EDIT_REQUEST" rehearse "$1" "$R6/128" "$M6" | $PHP "$TUNNEL" --json edit > "$T/edit.out"
    $PHP -r '$j = json_decode((string)file_get_contents($argv[1]), true);
        echo is_array($j) && ($j["ok"] ?? false) === true ? "ok" : "failed: " . json_encode($j);' "$T/edit.out"
}
# rehearse_routes: "in place" when the record holds rehearse's line, and its address is on its device and its
# next-hop and monitor routes leave by it; else what was read
rehearse_routes() {
    rr_line=$(awk -F'|' -v a="$R6" '{ split($2, p, "/") } p[1] == a' "$RECORD" 2> /dev/null)
    rr_dev=$(echo "$rr_line" | cut -d'|' -f1)
    rr_nh=$(echo "$rr_line" | cut -d'|' -f3)
    rr_mon=$(echo "$rr_line" | cut -d'|' -f5)
    if [ -n "$rr_dev" ] && [ -n "$rr_mon" ] && inet6_on "$rr_dev" "$R6" && [ "$(dev_of "$rr_nh")" = "$rr_dev" ] \
        && [ "$(dev_of "$rr_mon")" = "$rr_dev" ]; then
        echo "in place"
    else
        echo "not in place (record line '$rr_line': next hop via '$(dev_of "$rr_nh")', monitor via '$(dev_of "$rr_mon")')"
    fi
}
# route_state: what an Apply on an enabled plugin must leave as it is: the enabled marker's inode, footprint.json's
# inode and at, and for each record line whether its address is on its device and which devices its next-hop and
# monitor routes leave by
route_state() {
    echo "enabled marker inode $(stat -f %i /var/run/wgclienttunnels/enabled 2> /dev/null || echo absent)"
    echo "footprint.json inode $(stat -f %i "$FOOTPRINT" 2> /dev/null || echo absent) at $($PHP -r '
        $f = is_file($argv[1]) ? json_decode((string)file_get_contents($argv[1]), true) : null; echo $f["at"] ?? "absent";' "$FOOTPRINT")"
    [ -f "$RECORD" ] || { echo "no record"; return; }
    while IFS='|' read -r rs_dev rs_addr rs_nh rs_gw4 rs_mon; do
        [ -n "$rs_dev" ] || continue
        inet6_on "$rs_dev" "${rs_addr%/*}" && rs_on=on || rs_on=off
        echo "$rs_dev ($rs_gw4): $rs_addr $rs_on; next hop $rs_nh via '$(dev_of "$rs_nh")'; monitor '$rs_mon' via '$([ -n "$rs_mon" ] && dev_of "$rs_mon")'"
    done < "$RECORD"
}
# config_shape: the gateways' names and rehearse's tunnel addresses, which case 7's Edits change
config_shape() {
    $PHP -r '$x = simplexml_load_file("/conf/config.xml"); $n = [];
        foreach ($x->OPNsense->Gateways->gateway_item as $g) { $n[] = (string)$g->name; }
        foreach ($x->OPNsense->wireguard->server->servers->server as $s) {
            if ((string)$s->name === "rehearse") { echo "gateways ", implode(",", $n), "; rehearse ", (string)$s->tunneladdress; } }'
}
# svc_restore: the settings case 7 found ($T/svc.settings, removed once they are back), rehearse's IPv6 off, the
# route set and the footprint they give; prints "restored" or what was not
svc_restore() {
    sr_edit=$(rehearse_ipv6 off)
    sr_set=$(settings $(cat "$T/svc.settings"))
    quiet > /dev/null
    configctl wgclienttunnels stop > /dev/null
    configctl wgclienttunnels start > /dev/null
    configctl filter reload > /dev/null
    quiet > /dev/null
    rm -f "$T/svc.settings"
    if [ "$sr_edit $sr_set" = 'ok {"result":"saved"}' ]; then
        echo restored
    else
        echo "Edit: $sr_edit; settings/set: $sr_set"
    fi
}

svc0=$(svc_status)
shape0=$(config_shape)
settings0="enabled=$(raw_field enabled) ipv6_routes=$(raw_field ipv6_routes)"
echo "$settings0" > "$T/svc.settings"
cq=$(cron_quiesce) && cq=cron-quiet
check "service: cron is stopped for the case" "$cq" cron-quiet
check "service: the settings take the plugin and IPv6 routes on" "$(settings enabled=1 ipv6_routes=1)" '{"result":"saved"}'

# enabled and running: the Apply reloads the route set in place
check "service (in place): Edit turns rehearse's IPv6 on" "$(rehearse_ipv6 on)" ok
quiet
check "service (in place): before the Apply the plugin is running, and rehearse's address and routes are in place" \
    "$(svc_status); $(rehearse_routes)" "wgclienttunnels is running; in place"
route_state > "$T/state.before"
mark=$(lmark configd)
wmark=$(lmark wireguard)
check "api: reconfigure with the plugin enabled answers status ok" "$(reconfigure)" ok
settle 90
route_state > "$T/state.after"
check "api: reconfigure with the plugin enabled reloads the route set" \
    "reload $(lcount configd "$mark" -F -e 'reloading WireGuard upstream tunnel IPv6 routes') stop $(lcount configd "$mark" -F -e 'stopping WireGuard upstream tunnel IPv6 routes')" \
    "reload 1 stop 0"
if cmp -s "$T/state.before" "$T/state.after"; then
    moved=unchanged
else
    moved="changed: before [$(tr '\n' ' ' < "$T/state.before")] after [$(tr '\n' ' ' < "$T/state.after")]"
fi
check "api: an Apply on an enabled plugin leaves the tunnels in place (the enabled marker, footprint.json, each record line's address and routes; no removed or stopped line)" \
    "$moved; removed or stopped lines $(lcount wireguard "$wmark" -E -e '\[wgct-routes\] (removed|stopped)')" \
    "unchanged; removed or stopped lines 0"
check "service (in place): Edit turns rehearse's IPv6 off" "$(rehearse_ipv6 off)" ok

# disabled: the Apply stops it
check "service (disabled): the settings take the plugin off" "$(settings enabled=0)" '{"result":"saved"}'
quiet
check "service (disabled): before the Apply the plugin is running" "$(svc_status)" "wgclienttunnels is running"
check "api: reconfigure with the plugin disabled answers status ok" "$(reconfigure)" ok
check "api: reconfigure with the plugin disabled stops it" \
    "$(svc_status); record $([ -e "$RECORD" ] && echo present || echo absent)" "wgclienttunnels is not running; record absent"

# enabled again: the Apply leaves it running, with rehearse's line
check "service (enabled again): Edit turns rehearse's IPv6 on" "$(rehearse_ipv6 on)" ok
check "service (enabled again): the settings take the plugin on" "$(settings enabled=1)" '{"result":"saved"}'
quiet
# the save's queued reconcile has run the route set; stopped again, only the Apply can start it
configctl wgclienttunnels stop > /dev/null
check "service (enabled again): after a stop the plugin is not running" "$(svc_status)" "wgclienttunnels is not running"
# the stop holds against core's hooks and the reconcile, said once
wmark=$(lmark wireguard)
"$SRC" hook
configctl wgclienttunnels reconcile > /dev/null
quiet
stopped_routes=$(rehearse_routes)
check "service (stopped): a hook and a reconcile add nothing back, the plugin stays stopped, and that is logged once" \
    "$(svc_status); ${stopped_routes%% (*}; skipped lines $(lcount wireguard "$wmark" -F -e '[wgct-routes] route set skipped: the service is stopped')" \
    "wgclienttunnels is not running; not in place; skipped lines 1"
mark=$(lmark configd)
check "api: reconfigure after enabling answers status ok" "$(reconfigure)" ok
check "api: reconfigure after enabling starts it" \
    "start $(lcount configd "$mark" -F -e 'starting WireGuard upstream tunnel IPv6 routes'); $(svc_status); $(rehearse_routes)" \
    "start 1; wgclienttunnels is running; in place"
check "service (enabled again): Edit turns rehearse's IPv6 off" "$(rehearse_ipv6 off)" ok

# IPv6 routes off on the enabled plugin: it runs with no route set, so the Apply reloads it
check "service (IPv6 routes off): the settings take IPv6 routes off" "$(settings ipv6_routes=0)" '{"result":"saved"}'
quiet
configctl wgclienttunnels stop > /dev/null
configctl wgclienttunnels start > /dev/null
call "$CTL_CRED" service/status > /dev/null
check "service (IPv6 routes off): after a start the plugin is running, as core's service status reads it" \
    "$(svc_status); $(status_of)" "wgclienttunnels is running; running"
mark=$(lmark configd)
check "api: reconfigure with IPv6 routes off answers status ok" "$(reconfigure)" ok
check "api: reconfigure with IPv6 routes off reloads, and neither starts nor stops" \
    "reload $(lcount configd "$mark" -F -e 'reloading WireGuard upstream tunnel IPv6 routes') start $(lcount configd "$mark" -F -e 'starting WireGuard upstream tunnel IPv6 routes') stop $(lcount configd "$mark" -F -e 'stopping WireGuard upstream tunnel IPv6 routes')" \
    "reload 1 start 0 stop 0"

svc_restore > "$T/restore.out"
check "service: the settings, rehearse's IPv6, the route set and the footprint are put back" "$(cat "$T/restore.out")" restored
service cron start > /dev/null 2>&1
check "service: the plugin's status, its settings, the gateways and rehearse's addresses are as the case found them, and footprint.json is recorded" \
    "$(svc_status); enabled=$(raw_field enabled) ipv6_routes=$(raw_field ipv6_routes); $(config_shape); footprint.json $([ -f "$FOOTPRINT" ] && echo present || echo absent)" \
    "$svc0; $settings0; $shape0; footprint.json present"

# case 5
remove_instance
UNMANAGED=$($PHP "$T/instance.php" create "$UNMANAGED_NAME" "$(wg genkey)")
[ -n "$UNMANAGED" ] || { echo "[FAIL] the unmanaged instance could not be created"; exit 1; }
check "the throw-away instance is not on the managed list" \
    "$($PHP -r '$n = 0; foreach (simplexml_load_file("/conf/config.xml")->OPNsense->WGClientTunnelsEngine->tunnels as $r) { $n += (string)$r->instance === $argv[1] ? 1 : 0; } echo $n;' "$UNMANAGED")" 0
handshakes=$(wg show all latest-handshakes)
mark=$(lmark configd)
$PHP "$TUNNEL" --json apply "$UNMANAGED" > "$T/apply"
check "apply of an unmanaged instance: refused as not a managed tunnel" \
    "$($PHP -r '$j = json_decode(file_get_contents($argv[1]), true); echo $j["ok"] === false ? implode("|", $j["errors"]) : "ok";' "$T/apply")" \
    "not a managed tunnel"
check "apply of an unmanaged instance: configd's log never names it" \
    "$(lcount configd "$mark" -F -e "$UNMANAGED")" 0
check "apply of an unmanaged instance: every latest handshake is unchanged" "$(wg show all latest-handshakes)" "$handshakes"
$PHP "$TUNNEL" --json apply "$UNMANAGED" first > /dev/null
check "apply of an unmanaged instance with a mode: configd's log still never names it" \
    "$(lcount configd "$mark" -F -e "$UNMANAGED")" 0

# case 8
check "api: lists and choices answer; search and options are gone" \
    "lists $(call "$CTL_CRED" tunnels/lists) $(status_of), choices $(call "$CTL_CRED" tunnels/choices) $(status_of), search $(call "$CTL_CRED" tunnels/search), options $(call "$CTL_CRED" tunnels/options)" \
    "lists 200 ok, choices 200 ok, search 404, options 404"
check "api: search_unmanaged finds the unmanaged instance by name, with its uuid, as disabled" \
    "$(call "$CTL_CRED" tunnels/search_unmanaged -d "searchPhrase=$UNMANAGED_NAME") $($PHP -r '$j = json_decode((string)file_get_contents($argv[1]), true); $o = [];
        foreach ($j["rows"] ?? [] as $r) { $o[] = $r["name"] . " " . ($r["uuid"] === $argv[2] ? "uuid" : "another uuid") . " " . var_export($r["enabled"], true); }
        echo implode(", ", $o);' "$T/body" "$UNMANAGED")" \
    "200 $UNMANAGED_NAME uuid false"
check "api: search_unmanaged searches only the text columns: the instance's uuid finds nothing" \
    "$(call "$CTL_CRED" tunnels/search_unmanaged -d "searchPhrase=$UNMANAGED") $($PHP -r '$j = json_decode((string)file_get_contents($argv[1]), true);
        echo "rows ", is_array($j["rows"] ?? null) ? count($j["rows"]) : "none";' "$T/body")" \
    "200 rows 0"

# the banners: what tunnels/lists gives the page, and how the installed page renders it
check "control user: tunnels/lists answers 200" "$(call "$CTL_CRED" tunnels/lists)" 200
check "tunnels/lists: the core contract's findings on this core are one core-fixed note at level info" \
    "$($PHP -r '$j = json_decode(file_get_contents($argv[1]), true); $o = [];
        foreach ($j["global"] ?? [] as $f) { if (str_starts_with($f["code"], "core-")) { $o[] = $f["code"] . "=" . ($f["level"] ?? "none"); } }
        echo implode(" ", $o);' "$T/body")" "core-fixed=info"
PAGE=/usr/local/opnsense/mvc/app/views/OPNsense/WGClientTunnels/index.volt
check "page: a global finding's banner takes its class from the finding's level, never a fixed warning" \
    "$(grep -c -F "banners.push(\$('<div class=\"alert\"/>').addClass(f.level === 'info' ? 'alert-info' : 'alert-warning')" "$PAGE") $(grep -c -F "banners.push(\$('<div class=\"alert alert-warning\"/>')" "$PAGE")" "1 0"

echo "api: $PASS/$((PASS + FAIL)) passed"
[ "$FAIL" -eq 0 ]
