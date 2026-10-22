#!/bin/sh

# Copyright (C) 2026 cayossarian
# All rights reserved.
# BSD 2-Clause License
#
# VM test of what a package removal does (spec 2026-10-20 section 3.11, convention C6, rulings R29-R31):
# `tunnel.php --json release-holds` and the plugin's +PRE_DEINSTALL.pre, +POST_DEINSTALL.post and
# +POST_INSTALL.post, run against the plugin vm_overlay.sh put onto the installed package. Root on the disposable
# test VM only, never on a firewall. The real `pkg delete` and `pkg add -f` halves run on the CI-built package
# (spec section 6 step 2), not here.
#
# The VM's tunnel `rehearse` is bound to WAN_B, the second VM WAN. A hold is taken the way the mirror takes one:
# WAN_B's gateway forced down in its settings, then one mirror tick. Only WAN_B's gateway is ever forced down; the
# first VM WAN is never touched. cron is stopped for the whole run, and the ticks a cron round started before the
# stop are waited out, so only the ticks the test runs by hand act.
#   a. release-holds with rehearse held: exit 0, rehearse force_down=0, no hold record, routing re-synced through
#      configd, the alarm replayed for rehearse, one "deinstall: released rehearse" line in the WireGuard log;
#      run again with nothing held: "deinstall: nothing held", nothing saved.
#   d. release-holds with rehearse held and configd stopped (R29): it ends well within its bound, force_down=0 and
#      no hold record are saved, routing is skipped and one line says configd is not answering.
#  d2. release-holds with nothing held and configd still stopped: it ends well within its bound, makes no configd
#      call and logs "nothing held" alone.
#   f. A mirror tick that needs a change waits for the gateway lock (held by flock for 70 s, WAN_B forced down and
#      no hold taken yet) while it holds health.lock; the .pre meanwhile gives up on health.lock after 60 s, writes
#      the marker and runs release-holds. Once the gateway lock is free the tick stops at the marker: no hold record,
#      rehearse not forced down (R30, review fix I2).
#   b. With PKG_UPGRADE set: +PRE_DEINSTALL.pre with rehearse held changes nothing (the hold and its record, the
#      state directories with the footprint, the MSS anchor, the pin labels in pf, no removal marker), and
#      +POST_DEINSTALL.post keeps both state directories.
#   c. A real removal with rehearse held, mirror ticks running back to back all the while (R30): +PRE_DEINSTALL.pre
#      releases rehearse and no tick re-takes the hold; the removal marker stays, the MSS anchor is empty; with the
#      marker wgct.sh reconcile, request_reconcile and a filter reload rebuild nothing; +POST_DEINSTALL.post then
#      removes both state directories.
#   e. +POST_INSTALL.post deletes a removal marker.
# At exit, even on failure: configd running, the removal marker gone, config.xml put back as it was at the start
# through core's Config::restoreBackup(), routing re-synced, the state rebuilt (wgct.sh reconcile, a filter reload,
# one mirror tick) and cron started.
#
# Usage: wgct_deinstall.sh DIR   (DIR holds +PRE_DEINSTALL.pre, +POST_DEINSTALL.post and +POST_INSTALL.post)

set -u
DIR="$1"
PHP="/usr/local/bin/php -d log_errors=0"
S=/usr/local/opnsense/scripts/OPNsense/WGClientTunnels
TUNNEL="$S/tunnel.php"
MIRROR="$S/health_mirror.php"
DB=/var/db/wgclienttunnels
RUN=/var/run/wgclienttunnels
MARKER="$RUN/removing"
ANCHOR=wgclienttunnels_mss
WGLOG=/var/log/wireguard/latest.log
PHPLOG=/var/lib/php/tmp/PHP_errors.log
PENDING='WGClientTunnels/(health_mirror|prime)[.]php|wgct[.]sh (reconcile|_reconcile)'
T=$(mktemp -d /tmp/wgct-deinstall.XXXXXX)
LOOP=""
HOLDER=""
TICK=""
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
stop_loop() {
    if [ -n "$LOOP" ]; then
        : > "$T/stop"
        wait "$LOOP" 2> /dev/null
        LOOP=""
    fi
}
cleanup() {
    stop_loop
    for p in $HOLDER $TICK; do
        kill "$p" 2> /dev/null
        wait "$p" 2> /dev/null
    done
    service configd status > /dev/null 2>&1 || service configd start > /dev/null 2>&1
    rm -f "$MARKER"
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
facts() {
    echo "$($PHP "$T/fact.php" force_down rehearse) $($PHP "$T/fact.php" rows) $($PHP "$T/fact.php" force_down WAN_B) $($PHP "$T/fact.php" force_down WAN_DHCP)"
}
# hold: WAN_B forced down in its settings and applied, then one mirror tick takes the hold on rehearse
hold() {
    $PHP "$T/gw.php" WAN_B 1 && /usr/local/sbin/configctl interface routes configure > /dev/null
    $PHP "$MIRROR" > /dev/null 2>&1
}
release_wan_b() {
    $PHP "$T/gw.php" WAN_B 0 && /usr/local/sbin/configctl interface routes configure > /dev/null
}
# settle: wait (at most 90 s) until no tick, prime, reconcile or routing configure is running
settle() {
    n=0
    while [ "$n" -lt 90 ] && pgrep -f "$PENDING|rc[.]routing_configure" > /dev/null; do
        sleep 1
        n=$((n + 1))
    done
}

service cron stop > /dev/null 2>&1
# a cron round started before the stop keeps its `sleep N && health_mirror.php` children: let them end first
settle
RGW=$($PHP "$T/fact.php" uuid rehearse)
[ -n "$RGW" ] && [ -n "$($PHP "$T/fact.php" uuid WAN_B)" ] || { echo "[FAIL] rehearse or WAN_B is missing (vm_base.sh)"; exit 1; }
check "start: rehearse and WAN_B are not forced down, no hold record, WAN_DHCP not forced down, no removal marker" \
    "$(facts) $([ -e "$MARKER" ] && echo marker || echo none)" "0 0 0 0 none"
check "start: no tick or reconcile started by cron is still pending" \
    "$(pgrep -f "$PENDING" > /dev/null && echo pending || echo none)" none
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
check "a: it reports ok, saved, rehearse released, nothing pruned or left down, routing through configd, rehearse replayed" \
    "$($PHP "$T/json.php" ok < "$T/a.json") $($PHP "$T/json.php" saved < "$T/a.json") $($PHP "$T/json.php" released < "$T/a.json") [$($PHP "$T/json.php" pruned < "$T/a.json")] [$($PHP "$T/json.php" left_down < "$T/a.json")] $($PHP "$T/json.php" routing < "$T/a.json") $($PHP "$T/json.php" replayed < "$T/a.json")" \
    "true true rehearse [] [] configd rehearse"
check "a: rehearse force_down=0 and no hold record; WAN_B still forced down, WAN_DHCP untouched" "$(facts)" "0 0 1 0"
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

# d. release-holds with configd not answering (R29)
hold
check "d: rehearse held again" "$($PHP "$T/fact.php" force_down rehearse) $($PHP "$T/fact.php" rows)" "1 1"
settle
check "d: the hold's own apply has finished" "$(pgrep -f "$PENDING|rc[.]routing_configure" > /dev/null && echo running || echo done)" done
service configd stop > /dev/null 2>&1
check "d: configd is stopped: no socket" "$([ -S /var/run/configd.socket ] && echo socket || echo none)" none
mark=$(wc -l < "$WGLOG")
start=$(date +%s)
$PHP "$TUNNEL" --json release-holds > "$T/d.json"
rc=$?
took=$(($(date +%s) - start))
sleep 1
bound=$($PHP -r 'require "/usr/local/opnsense/mvc/script/load_phalcon.php"; require "'"$S"'/lib/apply.php"; echo WGCT_REMOVAL_CONFIGD_SECONDS;')
echo "    d: release-holds took ${took} s with configd stopped (one configd call is bounded at ${bound} s)"
check "d: release-holds ends well within one bound" "$([ "$took" -lt "$bound" ] && echo within || echo "over (${took} s)")" within
check "d: exit 0, ok, saved, rehearse released, routing skipped, nothing replayed" \
    "$rc $($PHP "$T/json.php" ok < "$T/d.json") $($PHP "$T/json.php" saved < "$T/d.json") $($PHP "$T/json.php" released < "$T/d.json") $($PHP "$T/json.php" routing < "$T/d.json") [$($PHP "$T/json.php" replayed < "$T/d.json")]" \
    "0 true true rehearse skipped []"
check "d: rehearse force_down=0 and no hold record saved; WAN_B still forced down, WAN_DHCP untouched" "$(facts)" "0 0 1 0"
check "d: two lines: the release, then configd not answering" "$(deinstall_lines "$mark" | tr '\n' '|')" \
    "deinstall: released rehearse|deinstall: configd not answering; routing applies the release at its next configure|"

# d2. nothing held, configd still stopped (review fix I1)
mark=$(wc -l < "$WGLOG")
start=$(date +%s)
$PHP "$TUNNEL" --json release-holds > "$T/d2.json"
rc=$?
took=$(($(date +%s) - start))
sleep 1
echo "    d2: release-holds with nothing held took ${took} s with configd stopped"
check "d2: release-holds with nothing held ends well within one bound" "$([ "$took" -lt "$bound" ] && echo within || echo "over (${took} s)")" within
check "d2: exit 0, ok, nothing saved or released, no configd call (routing empty), nothing replayed" \
    "$rc $($PHP "$T/json.php" ok < "$T/d2.json") $($PHP "$T/json.php" saved < "$T/d2.json") [$($PHP "$T/json.php" released < "$T/d2.json")] [$($PHP "$T/json.php" routing < "$T/d2.json")] [$($PHP "$T/json.php" replayed < "$T/d2.json")]" \
    "0 true false [] [] []"
check "d2: one line: deinstall: nothing held" "$(deinstall_lines "$mark")" "deinstall: nothing held"
service configd start > /dev/null 2>&1
release_wan_b

# f. a tick waiting on the gateway lock while the .pre runs (review fix I2)
$PHP "$T/gw.php" WAN_B 1 && /usr/local/sbin/configctl interface routes configure > /dev/null
settle
check "f: WAN_B forced down, no hold taken yet" "$(facts)" "0 0 1 0"
/usr/local/bin/flock -o /tmp/filter_reload_gateway.lock sleep 70 &
HOLDER=$!
sleep 1
mark=$(wc -l < "$WGLOG")
$PHP "$MIRROR" > "$T/f.tick" 2>&1 &
TICK=$!
sleep 5
check "f: the tick is waiting for the gateway lock, holding health.lock" \
    "$(kill -0 "$TICK" 2> /dev/null && echo waiting || echo ended) $(/usr/local/bin/flock -n "$RUN/health.lock" true && echo free || echo held)" "waiting held"
start=$(date +%s)
env -u PKG_UPGRADE sh "$DIR/+PRE_DEINSTALL.pre"
rc=$?
took=$(($(date +%s) - start))
wait "$TICK"
wait "$HOLDER" 2> /dev/null
sleep 1
echo "    f: the .pre took ${took} s (60 s for health.lock, then release-holds behind the gateway lock)"
check "f: the .pre exits 0 and leaves the marker" "$rc $([ -f "$MARKER" ] && echo marker || echo none)" "0 marker"
check "f: after the tick got the gateway lock: no hold record, rehearse not forced down; WAN_B still forced down, WAN_DHCP untouched" \
    "$(facts)" "0 0 1 0"
check "f: no tick took a hold" "$(tail -n +"$((mark + 1))" "$WGLOG" | grep -c '\[wgct-health\] rehearse: force_down')" 0
check "f: release-holds found nothing held" "$(deinstall_lines "$mark")" "deinstall: nothing held"
# an install after this removal: the marker goes, the state is rendered again
sh "$DIR/+POST_INSTALL.post"
"$S/wgct.sh" reconcile > /dev/null 2>&1
/usr/local/sbin/configctl filter reload > /dev/null
sleep 2
release_wan_b

# b. an upgrade: the .pre and the .post of the deinstall change nothing
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
PKG_UPGRADE=true sh "$DIR/+PRE_DEINSTALL.pre"
rc=$?
sleep 1
check "b: PKG_UPGRADE=true sh +PRE_DEINSTALL.pre exits 0 and writes no removal marker" \
    "$rc $([ -e "$MARKER" ] && echo marker || echo none)" "0 none"
check "b: the hold and its record stay" "$($PHP "$T/fact.php" force_down rehearse) $($PHP "$T/fact.php" rows) $($PHP "$T/fact.php" row_gateway)" "1 1 $RGW"
check "b: /var/db/wgclienttunnels stays with footprint.json and boot.json, /var/run/wgclienttunnels stays" \
    "$([ -s "$DB/footprint.json" ] && [ -s "$DB/boot.json" ] && [ -d "$RUN" ] && echo kept || echo gone)" kept
pfctl -a "$ANCHOR" -sr 2> /dev/null > "$T/anchor.after"
check "b: the MSS anchor is unchanged" "$(cmp -s "$T/anchor.before" "$T/anchor.after" && echo same || echo changed)" same
check "b: every pin label is still in pf" "$(pins)" "$pins_before"
check "b: nothing logged by release-holds" "$(deinstall_lines "$mark")" ""
PKG_UPGRADE=true sh "$DIR/+POST_DEINSTALL.post"
check "b: PKG_UPGRADE=true sh +POST_DEINSTALL.post exits 0 and keeps both state directories with the footprint" \
    "$? $([ -s "$DB/footprint.json" ] && [ -d "$RUN" ] && echo kept || echo gone)" "0 kept"

# c. a real removal, rehearse still held, with mirror ticks running back to back from before the .pre to after it
rm -f "$T/stop" "$T/ticks"
(
    while [ ! -e "$T/stop" ]; do
        $PHP "$MIRROR" > /dev/null 2>&1
        echo tick >> "$T/ticks"
    done
) &
LOOP=$!
sleep 2
mark=$(wc -l < "$WGLOG")
ticks_before=$(wc -l < "$T/ticks" | tr -d ' ')
env -u PKG_UPGRADE sh "$DIR/+PRE_DEINSTALL.pre"
rc=$?
ticks_during=$(($(wc -l < "$T/ticks" | tr -d ' ') - ticks_before))
sleep 3
stop_loop
$PHP "$MIRROR" > /dev/null 2>&1
check "c: sh +PRE_DEINSTALL.pre exits 0, with mirror ticks running all the while" \
    "$rc $([ "$ticks_before" -gt 0 ] && [ "$ticks_during" -gt 0 ] && echo ticking || echo "no ticks ($ticks_before, $ticks_during)")" "0 ticking"
check "c: rehearse force_down=0 and no hold record after every tick; WAN_B still forced down, WAN_DHCP untouched" "$(facts)" "0 0 1 0"
check "c: no tick took a hold after the release" \
    "$(tail -n +"$((mark + 1))" "$WGLOG" | grep -c '\[wgct-health\] rehearse: force_down')" 0
check "c: one line in the WireGuard log: deinstall: released rehearse" "$(deinstall_lines "$mark")" "deinstall: released rehearse"
check "c: the removal marker is there, both state directories still are (the .post removes them), the MSS anchor is empty" \
    "$([ -f "$MARKER" ] && echo marker) $([ -d "$RUN" ] && [ -d "$DB" ] && echo dirs) $(pfctl -a "$ANCHOR" -sr 2> /dev/null | wc -l | tr -d ' ')" "marker dirs 0"
mark=$(wc -l < "$WGLOG")
rm -f "$RUN/reconcile.pending"
"$S/wgct.sh" request_reconcile
"$S/wgct.sh" configure_routes
"$S/wgct.sh" reconcile --repair
/usr/local/sbin/configctl filter reload > /dev/null
sleep 3
check "c: with the marker, request_reconcile queues nothing, and reconcile and a filter reload render no anchor or footprint" \
    "$([ -e "$RUN/reconcile.pending" ] && echo queued || echo none) $(pfctl -a "$ANCHOR" -sr 2> /dev/null | wc -l | tr -d ' ') $([ -e "$DB/footprint.json" ] && echo footprint || echo none)" "none 0 none"
check "c: the minute reconcile says the package is being removed, once per run" \
    "$(tail -n +"$((mark + 1))" "$WGLOG" | grep -c 'the package is being removed')" 1
sh "$DIR/+POST_DEINSTALL.post"
check "c: sh +POST_DEINSTALL.post exits 0 and removes both state directories, the marker with them" \
    "$? $([ -e "$DB" ] || [ -e "$RUN" ] && echo present || echo gone)" "0 gone"
check "PHP's error log did not grow" "$(stat -f %z "$PHPLOG")" "$phplog"
release_wan_b

# e. an install after a removal that stopped partway
mkdir -p -m 700 "$RUN"
: > "$MARKER"
sh "$DIR/+POST_INSTALL.post"
check "e: sh +POST_INSTALL.post exits 0 and deletes the removal marker" "$? $([ -e "$MARKER" ] && echo marker || echo none)" "0 none"

echo "deinstall: $PASS/$((PASS + FAIL)) passed"
[ "$FAIL" -eq 0 ]
