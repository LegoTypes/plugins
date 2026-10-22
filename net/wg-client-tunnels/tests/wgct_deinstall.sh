#!/bin/sh

# Copyright (C) 2026 cayossarian
# All rights reserved.
# BSD 2-Clause License
#
# VM test of what a package removal does (spec 2026-10-20 section 3.11, convention C6): `tunnel.php --json
# release-holds` and the plugin's +PRE_DEINSTALL.pre, run against the plugin vm_overlay.sh put onto the installed
# package. Root on the disposable test VM only, never on a firewall. The real `pkg delete` and `pkg add -f` halves
# run on the CI-built package (spec section 6 step 2), not here.
#
# The VM's tunnel `rehearse` is bound to WAN_B, the second VM WAN. A hold is taken the way the mirror takes one:
# WAN_B's gateway forced down in its settings, then one mirror tick. Only WAN_B's gateway is ever forced down; the
# first VM WAN is never touched. cron is stopped for the whole run, and the ticks a cron round started before the
# stop are waited out, so no tick re-takes a hold the test released and no minute reconcile rebuilds what the .pre
# removed; the ticks the test needs run by hand.
#   a. release-holds with rehearse held: exit 0, rehearse force_down=0, no hold record, routing re-synced through
#      configd, the alarm replayed for rehearse, one "deinstall: released rehearse" line in the WireGuard log;
#      run again with nothing held: "deinstall: nothing held", nothing saved.
#   d. only with --configd-down: release-holds with rehearse held and configd stopped once the hold's own apply has
#      finished: the same release, routing re-synced by running rc.routing_configure directly, the alarm replayed
#      directly. Opt-in because core's routing configure then waits on configd for every configd call it makes in
#      process (10 s each), which takes minutes.
#   b. sh +PRE_DEINSTALL.pre with PKG_UPGRADE set and rehearse held: nothing changes (the hold and its record, the
#      state directory with the footprint, the MSS anchor, the pin labels in pf).
#   c. sh +PRE_DEINSTALL.pre with rehearse held: rehearse force_down=0, no hold record, both state directories
#      gone, the MSS anchor empty.
# At exit, even on failure: configd running, config.xml put back as it was at the start through core's
# Config::restoreBackup(), routing re-synced, the state rebuilt (wgct.sh reconcile, a filter reload, one mirror
# tick) and cron started.
#
# Usage: wgct_deinstall.sh /path/to/+PRE_DEINSTALL.pre [--configd-down]

set -u
PRE="$1"
CONFIGD_DOWN="${2:-}"
PHP="/usr/local/bin/php -d log_errors=0"
S=/usr/local/opnsense/scripts/OPNsense/WGClientTunnels
TUNNEL="$S/tunnel.php"
MIRROR="$S/health_mirror.php"
ACTIONS=/usr/local/opnsense/service/conf/actions.d/actions_wgclienttunnels.conf
DB=/var/db/wgclienttunnels
RUN=/var/run/wgclienttunnels
ANCHOR=wgclienttunnels_mss
WGLOG=/var/log/wireguard/latest.log
PHPLOG=/var/lib/php/tmp/PHP_errors.log
T=$(mktemp -d /tmp/wgct-deinstall.XXXXXX)
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

cp -p /conf/config.xml "$T/config.xml"
cat > "$T/restore.php" <<'PHPEOF'
<?php
require_once '/usr/local/opnsense/mvc/script/load_phalcon.php';
exit(\OPNsense\Core\Config::getInstance()->restoreBackup($argv[1]) ? 0 : 1);
PHPEOF
cleanup() {
    service configd status > /dev/null 2>&1 || service configd start > /dev/null 2>&1
    $PHP "$T/restore.php" "$T/config.xml" || echo "[FAIL] config.xml could not be restored from $T/config.xml"
    /usr/local/sbin/configctl interface routes configure > /dev/null
    "$S/wgct.sh" reconcile > /dev/null 2>&1
    /usr/local/sbin/configctl filter reload > /dev/null
    $PHP "$MIRROR" > /dev/null 2>&1
    service cron start > /dev/null 2>&1
    rm -rf "$T"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

# gw.php set NAME 0|1: a gateway's force_down in its settings, as System > Gateways saves it
cat > "$T/gw.php" <<'PHPEOF'
<?php
require_once '/usr/local/opnsense/mvc/script/load_phalcon.php';
[, $name, $value] = $argv;
$cfg = \OPNsense\Core\Config::getInstance();
$cfg->lock();
$m = new \OPNsense\Routing\Gateways();
$found = false;
foreach ($m->gateway_item->iterateItems() as $g) {
    if ((string)$g->name === $name) {
        $g->force_down = $value;
        $found = true;
    }
}
if ($found) {
    $m->serializeToConfig();
    $cfg->save();
}
$cfg->unlock();
exit($found ? 0 : 1);
PHPEOF

# fact.php WHAT [NAME]: one fact about /conf/config.xml as it is on disk
cat > "$T/fact.php" <<'PHPEOF'
<?php
$x = simplexml_load_file('/conf/config.xml');
switch ($argv[1]) {
    case 'rows':
        echo count($x->xpath('/opnsense/OPNsense/WGClientTunnelsEngine/holds'));
        break;
    case 'row_gateway':
        echo (string)($x->xpath('/opnsense/OPNsense/WGClientTunnelsEngine/holds/gateway')[0] ?? '');
        break;
    case 'force_down':
    case 'uuid':
        foreach ($x->OPNsense->Gateways->gateway_item as $g) {
            if ((string)$g->name === $argv[2]) {
                echo $argv[1] === 'uuid' ? (string)$g['uuid'] : (string)$g->force_down;
            }
        }
        break;
}
PHPEOF

# json.php KEY: one key of the JSON object on stdin, a list joined by commas
cat > "$T/json.php" <<'PHPEOF'
<?php
$r = json_decode((string)stream_get_contents(STDIN), true);
$v = is_array($r) ? ($r[$argv[1]] ?? null) : null;
echo is_array($v) ? implode(',', $v) : (is_bool($v) ? ($v ? 'true' : 'false') : (string)$v);
PHPEOF

status_of() {
    /usr/local/opnsense/scripts/routes/gateway_status.php | $PHP -r '$d = json_decode(stream_get_contents(STDIN), true); echo $d[$argv[1]]["status"] ?? "absent";' "$1"
}
deinstall_lines() {
    tail -n +"$(($1 + 1))" "$WGLOG" | grep -F '[wgct-action] deinstall:' | sed 's/.*\[wgct-action\] //'
}
# hold: WAN_B forced down in its settings and applied, then one mirror tick takes the hold on rehearse
hold() {
    $PHP "$T/gw.php" WAN_B 1 && /usr/local/sbin/configctl interface routes configure > /dev/null
    $PHP "$MIRROR" > /dev/null 2>&1
}
release_wan_b() {
    $PHP "$T/gw.php" WAN_B 0 && /usr/local/sbin/configctl interface routes configure > /dev/null
}

service cron stop > /dev/null 2>&1
# a cron round started before the stop keeps its `sleep N && health_mirror.php` children: let them end first
n=0
while [ "$n" -lt 90 ] && pgrep -f 'WGClientTunnels/(health_mirror|prime)[.]php|wgct[.]sh (reconcile|_reconcile)' > /dev/null; do
    sleep 1
    n=$((n + 1))
done
RGW=$($PHP "$T/fact.php" uuid rehearse)
[ -n "$RGW" ] && [ -n "$($PHP "$T/fact.php" uuid WAN_B)" ] || { echo "[FAIL] rehearse or WAN_B is missing (vm_base.sh)"; exit 1; }
check "start: rehearse and WAN_B are not forced down, no hold record, WAN_DHCP not forced down" \
    "$($PHP "$T/fact.php" force_down rehearse) $($PHP "$T/fact.php" force_down WAN_B) $($PHP "$T/fact.php" rows) $($PHP "$T/fact.php" force_down WAN_DHCP)" "0 0 0 0"
check "start: no tick or reconcile started by cron is still pending" \
    "$(pgrep -f 'WGClientTunnels/(health_mirror|prime)[.]php|wgct[.]sh (reconcile|_reconcile)' > /dev/null && echo pending || echo none)" none
check "the [replay_alarm] action's command is the one release-holds runs directly" \
    "$(sed -n '/^\[replay_alarm\]/,/^\[/p' "$ACTIONS" | sed -n 's/^command://p')" \
    "$($PHP -r 'require "/usr/local/opnsense/mvc/script/load_phalcon.php"; require "'"$S"'/lib/apply.php"; echo WGCT_REPLAY_ALARM_COMMAND;')"
phplog=$(stat -f %z "$PHPLOG")

# a. release-holds with rehearse held
hold
check "a: one mirror tick holds rehearse: force_down=1 and one hold record for its gateway" \
    "$($PHP "$T/fact.php" force_down rehearse) $($PHP "$T/fact.php" rows) $($PHP "$T/fact.php" row_gateway)" "1 1 $RGW"
check "a: gateway status shows rehearse force_down" "$(status_of rehearse)" force_down
mark=$(wc -l < "$WGLOG")
$PHP "$TUNNEL" --json release-holds > "$T/a.json"
rc=$?
sleep 1
check "a: release-holds exits 0" "$rc" 0
check "a: it reports ok, saved, rehearse released, nothing pruned, routing through configd, rehearse replayed" \
    "$($PHP "$T/json.php" ok < "$T/a.json") $($PHP "$T/json.php" saved < "$T/a.json") $($PHP "$T/json.php" released < "$T/a.json") [$($PHP "$T/json.php" pruned < "$T/a.json")] $($PHP "$T/json.php" routing < "$T/a.json") $($PHP "$T/json.php" replayed < "$T/a.json")" \
    "true true rehearse [] configd rehearse"
check "a: rehearse force_down=0 and no hold record; WAN_B still forced down, WAN_DHCP untouched" \
    "$($PHP "$T/fact.php" force_down rehearse) $($PHP "$T/fact.php" rows) $($PHP "$T/fact.php" force_down WAN_B) $($PHP "$T/fact.php" force_down WAN_DHCP)" "0 0 1 0"
check "a: routing re-synced: gateway status no longer shows rehearse force_down" \
    "$([ "$(status_of rehearse)" != force_down ] && echo yes || echo no)" yes
check "a: one line in the WireGuard log: deinstall: released rehearse" "$(deinstall_lines "$mark")" "deinstall: released rehearse"
mark=$(wc -l < "$WGLOG")
$PHP "$TUNNEL" --json release-holds > "$T/a2.json"
rc=$?
sleep 1
check "a: again with nothing held: exit 0, ok, nothing saved, nothing released, no routing re-sync" \
    "$rc $($PHP "$T/json.php" ok < "$T/a2.json") $($PHP "$T/json.php" saved < "$T/a2.json") [$($PHP "$T/json.php" released < "$T/a2.json")] [$($PHP "$T/json.php" routing < "$T/a2.json")]" \
    "0 true false [] []"
check "a: one line: deinstall: nothing held" "$(deinstall_lines "$mark")" "deinstall: nothing held"
release_wan_b

# d. release-holds with configd not answering
if [ "$CONFIGD_DOWN" = --configd-down ]; then
    hold
    check "d: rehearse held again" "$($PHP "$T/fact.php" force_down rehearse) $($PHP "$T/fact.php" rows)" "1 1"
    # the hold's apply (configd's routes configure and alarm replay, and the monitor hook's reconcile) ends first
    n=0
    while [ "$n" -lt 60 ] && pgrep -f 'rc.routing_configure|wgct.sh reconcile' > /dev/null; do
        sleep 1
        n=$((n + 1))
    done
    check "d: the hold's own apply has finished" "$(pgrep -f 'rc.routing_configure|wgct.sh reconcile' > /dev/null && echo running || echo done)" done
    service configd stop > /dev/null 2>&1
    check "d: configd is stopped: no socket" "$([ -S /var/run/configd.socket ] && echo socket || echo none)" none
    mark=$(wc -l < "$WGLOG")
    $PHP "$TUNNEL" --json release-holds > "$T/d.json"
    rc=$?
    sleep 1
    check "d: release-holds exits 0, ok, rehearse released, routing run directly, rehearse replayed directly" \
        "$rc $($PHP "$T/json.php" ok < "$T/d.json") $($PHP "$T/json.php" released < "$T/d.json") $($PHP "$T/json.php" routing < "$T/d.json") $($PHP "$T/json.php" replayed < "$T/d.json")" \
        "0 true rehearse direct rehearse"
    check "d: rehearse force_down=0, no hold record, gateway status no longer force_down" \
        "$($PHP "$T/fact.php" force_down rehearse) $($PHP "$T/fact.php" rows) $([ "$(status_of rehearse)" != force_down ] && echo resynced || echo stale)" "0 0 resynced"
    check "d: one line in the WireGuard log: deinstall: released rehearse" "$(deinstall_lines "$mark")" "deinstall: released rehearse"
    service configd start > /dev/null 2>&1
    release_wan_b
fi

# b. the .pre on an upgrade changes nothing
hold
labels=$($PHP -r '$f = json_decode((string)file_get_contents("/var/db/wgclienttunnels/footprint.json"), true); echo implode(" ", array_unique(array_column($f["rules"] ?? [], "label")));')
pins() {
    n=0
    for l in $labels; do
        pfctl -sr 2> /dev/null | grep -q "label \"$l\"" && n=$((n + 1))
    done
    echo "$n"
}
pfctl -a "$ANCHOR" -sr 2> /dev/null > "$T/anchor.before"
pins_before=$(pins)
check "b: rehearse held, the footprint names its pins and pf holds them, the MSS anchor has rules" \
    "$($PHP "$T/fact.php" force_down rehearse) $($PHP "$T/fact.php" rows) $([ -n "$labels" ] && echo labels) $pins_before $([ -s "$T/anchor.before" ] && echo anchor)" \
    "1 1 labels $(echo $labels | wc -w | tr -d ' ') anchor"
mark=$(wc -l < "$WGLOG")
PKG_UPGRADE=true sh "$PRE"
rc=$?
sleep 1
check "b: PKG_UPGRADE=true sh +PRE_DEINSTALL.pre exits 0" "$rc" 0
check "b: the hold and its record stay" "$($PHP "$T/fact.php" force_down rehearse) $($PHP "$T/fact.php" rows) $($PHP "$T/fact.php" row_gateway)" "1 1 $RGW"
check "b: /var/db/wgclienttunnels stays with footprint.json and boot.json, /var/run/wgclienttunnels stays" \
    "$([ -s "$DB/footprint.json" ] && [ -s "$DB/boot.json" ] && [ -d "$RUN" ] && echo kept || echo gone)" kept
pfctl -a "$ANCHOR" -sr 2> /dev/null > "$T/anchor.after"
check "b: the MSS anchor is unchanged" "$(cmp -s "$T/anchor.before" "$T/anchor.after" && echo same || echo changed)" same
check "b: every pin label is still in pf" "$(pins)" "$pins_before"
check "b: nothing logged by release-holds" "$(deinstall_lines "$mark")" ""

# c. the .pre on a real removal, rehearse still held
mark=$(wc -l < "$WGLOG")
env -u PKG_UPGRADE sh "$PRE"
rc=$?
sleep 1
check "c: sh +PRE_DEINSTALL.pre exits 0" "$rc" 0
check "c: rehearse force_down=0 and no hold record; WAN_B still forced down, WAN_DHCP untouched" \
    "$($PHP "$T/fact.php" force_down rehearse) $($PHP "$T/fact.php" rows) $($PHP "$T/fact.php" force_down WAN_B) $($PHP "$T/fact.php" force_down WAN_DHCP)" "0 0 1 0"
check "c: /var/db/wgclienttunnels and /var/run/wgclienttunnels are gone" \
    "$([ -e "$DB" ] || [ -e "$RUN" ] && echo present || echo gone)" gone
check "c: the MSS anchor is empty" "$(pfctl -a "$ANCHOR" -sr 2> /dev/null | wc -l | tr -d ' ')" 0
check "c: one line in the WireGuard log: deinstall: released rehearse" "$(deinstall_lines "$mark")" "deinstall: released rehearse"
check "PHP's error log did not grow" "$(stat -f %z "$PHPLOG")" "$phplog"
release_wan_b

echo "deinstall: $PASS/$((PASS + FAIL)) passed"
[ "$FAIL" -eq 0 ]
