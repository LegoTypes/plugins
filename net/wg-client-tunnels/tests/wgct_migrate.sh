#!/bin/sh

# Copyright (C) 2026 cayossarian
# All rights reserved.
# BSD 2-Clause License
#
# VM test of the settings model's 3.0.0 -> 3.1.0 migration (spec 2026-10-20 section 3.5, convention C1): the
# managed list and the mirror's holds move from the settings model into the engine model. Root on the disposable
# test VM only, never on a firewall, after vm_overlay.sh has put the 3.8 tree onto the installed package.
#
# It rewrites /conf/config.xml for a few seconds, so vm_selftest.sh runs it last, after every suite that reads
# config. config.xml is backed up first and put back through core's Config::restoreBackup() at exit, even on
# failure or a dropped session. The whole run holds the mirror's health.lock, so no mirror tick acts on a
# 3.7_1-shaped config or releases the carried hold before it is checked.
#
# Each scenario writes the config 3.7_1 leaves, through core's Config, around the VM's own tunnel `rehearse`:
#   - the settings node at version 3.0.0, `managed` = rehearse's instance and a synthetic upper-case uuid, in that
#     order (case m1: a value the 3.7_1 mask accepted), `held` = rehearse's IPv4 gateway, set force_down=1 as the
#     3.7_1 mirror leaves a hold, and WAN_B's gateway (force_down=0, and no tunnel's gateway);
#   - an IPv6 gateway `rehearse-ipv6` on rehearse's interface (a synthetic uuid, monitoring off), force_down=1 as
#     the 3.7_1 mirror's pass 2 leaves it while the IPv4 tunnel is unhealthy, and in no `held` list (spec 3.5a);
#   - no engine node (scenarios A, B and D, a box that never ran 3.8), or an empty one at 1.0.0 (scenario C);
#   - the plugin and its health mirror on, as the 3.7_1 mirror runs (A to C), or the health mirror off (D).
# The 3.7_1 tunnel.php, from the 3.7_1 package in pkg's cache, lists the tunnels on that config. Then:
#   A: run_migrations.php OPNsense/WGClientTunnels, as the package's +POST_INSTALL runs it (both models);
#   B: run_migrations.php OPNsense/WGClientTunnels/WGClientTunnels, the settings model alone: its migration first
#      brings the engine model to its own version, so the order core runs the two in does not matter;
#   C: as A, with the engine model already migrated;
#   D: as A, with the health mirror off (ruling R35): the 3.7_1 mirror never ran, so the forced IPv6 gateway is not
#      the plugin's.
# Each scenario then asserts: the settings node is at 3.1.0 with neither field; the engine node is at 1.0.0 with
# the managed list byte for byte and its holds rows, each with the live kern.boot_id and taken during the run:
# rehearse's gateway on WAN_B, and (A to C) rehearse-ipv6 following rehearse; in D one line names rehearse-ipv6 as
# left forced down as manual; force_down is as it was; one "not held by this plugin" line names WAN_B's gateway in
# core's WireGuard log; the installed tunnel.php lists the same tunnels, findings and unmanaged instances as 3.7_1
# did (beside the pins fields 3.8 adds), and its `held` keeps rehearse's gateways with a row (WAN_B's was dropped);
# boot.json, removed before the run, names the live boot (M3: a reboot before the mirror's first tick still finds
# the carried rows its own). A second run changes nothing (A). boot.json is backed up first and put back at exit.
#
# Before scenario A's migration runs, the window between pkg installing 3.8's files and the migration (M1, ruling
# R37), with cron stopped from then on (started again at exit) and the runs it already started waited out, so none
# of them logs a refusal before the checks look: the 3.8 list shows the tunnels and findings 3.7_1 lists, and the
# listing writes nothing (config.xml as it was, no marker, no log line); a mirror tick, apply, an action (adopt, and
# a dry remove), release-holds, the route set, the monitor repair and the settings API's set each refuse, change
# nothing, and log the refusal once (each run twice where it repeats; --dry only says so). After the migration the
# first action logs that it runs again. The set runs as a temporary API user with the plugin's page privilege
# (tests/wgct_user.php), deleted again.
#
# The first VM WAN is never touched, and WAN_B's gateway is only named in `held`. Case m3 (kern.boot_id
# unreadable) is a unit case of M3_1_0::plan() in tunnel.php --selftest (ruling R12).
#
# Usage: wgct_migrate.sh

set -u
LOCK=/var/run/wgclienttunnels/health.lock
if [ "${1:-}" != --locked ]; then
    exec /usr/bin/lockf -k -t 60 "$LOCK" /bin/sh "$0" --locked
fi

PHP="/usr/local/bin/php -d log_errors=0"
MIGRATE=/usr/local/opnsense/mvc/script/run_migrations.php
TUNNEL=/usr/local/opnsense/scripts/OPNsense/WGClientTunnels/tunnel.php
PKG371=/var/cache/pkg/os-wg-client-tunnels-3.7_1.pkg
UPPER=ABCDEF00-0000-4000-8000-0000000000AB
GW6=0000a5a5-0000-4000-8000-00000000a5a5
T=$(mktemp -d /tmp/wgct-migrate.XXXXXX)
PASS=0
FAIL=0

. "$(dirname "$0")/wgct_marks.sh"

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
BOOTJSON=/var/db/wgclienttunnels/boot.json
[ -f "$BOOTJSON" ] && cp -p "$BOOTJSON" "$T/boot.json"
cat > "$T/restore.php" <<'PHPEOF'
<?php
require_once '/usr/local/opnsense/mvc/script/load_phalcon.php';
exit(\OPNsense\Core\Config::getInstance()->restoreBackup($argv[1]) ? 0 : 1);
PHPEOF
remove_set_user() {
    $PHP "$(dirname "$0")/wgct_user.php" delete wgct-migrate-set > /dev/null 2>&1
    configctl auth sync user wgct-migrate-set > /dev/null 2>&1
}
cleanup() {
    $PHP "$T/restore.php" "$T/config.xml" || echo "[FAIL] config.xml could not be restored from $T/config.xml"
    remove_set_user
    rm -f /var/run/wgclienttunnels/*.pending
    service cron status > /dev/null 2>&1 || service cron start > /dev/null
    if [ -f "$T/boot.json" ]; then cp -p "$T/boot.json" "$BOOTJSON"; else rm -f "$BOOTJSON"; fi
    rm -rf "$T/pkg"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

# shape.php ENGINE UPPER GW6 MIRROR: the config 3.7_1 leaves (see the header); ENGINE is none or empty, MIRROR on or
# off (the 3.0.0 health_mirror switch). Prints the uuids.
cat > "$T/shape.php" <<'PHPEOF'
<?php
require_once '/usr/local/opnsense/mvc/script/load_phalcon.php';

use OPNsense\Core\Config;

[, $engineMode, $upper, $gw6, $mirror] = $argv;
$cfg = Config::getInstance();
$cfg->lock();
$root = $cfg->object();
$ids = ['instance' => '', 'gw_rehearse' => '', 'gw_wanb' => ''];
foreach ($root->OPNsense->wireguard->server->servers->server as $s) {
    if ((string)$s->name === 'rehearse') {
        $ids['instance'] = (string)$s['uuid'];
    }
}
$opt = '';
$other6 = false;
foreach ($root->OPNsense->Gateways->gateway_item as $g) {
    if ((string)$g->name === 'rehearse') {
        $ids['gw_rehearse'] = (string)$g['uuid'];
        $g->force_down = '1';
        $opt = (string)$g->interface;
    } elseif ((string)$g->name === 'WAN_B') {
        $ids['gw_wanb'] = (string)$g['uuid'];
    } elseif ((string)$g->name === 'rehearse-ipv6' && (string)$g['uuid'] !== $gw6) {
        $other6 = true;
    }
}
if (in_array('', $ids, true) || $opt === '' || $other6) {
    $cfg->unlock();
    fwrite(STDERR, "rehearse or WAN_B is missing (vm_base.sh), or rehearse already has an IPv6 gateway of its own\n");
    exit(1);
}
/* the earlier scenario's staged IPv6 gateway goes; this scenario writes it again */
foreach ($root->xpath("//OPNsense/Gateways/gateway_item[@uuid='{$gw6}']") as $old6) {
    unset($old6[0]);
}
$g6 = $root->OPNsense->Gateways->addChild('gateway_item');
$g6->addAttribute('uuid', $gw6);
foreach (['disabled' => '0', 'name' => 'rehearse-ipv6', 'descr' => 'rehearse-ipv6 (IPv6 tunnel)', 'interface' => $opt,
          'ipprotocol' => 'inet6', 'gateway' => 'fd00::1:2', 'defaultgw' => '0', 'fargw' => '1', 'monitor_disable' => '1',
          'force_down' => '1', 'priority' => '255', 'weight' => '1'] as $field => $value) {
    $g6->addChild($field, $value);
}
$n = $root->OPNsense->WGClientTunnels;
$n['version'] = '3.0.0';
$n->enabled = '1';
$n->health_mirror = $mirror === 'on' ? '1' : '0';
$n->managed = "{$ids['instance']},{$upper}";
$n->held = "{$ids['gw_rehearse']},{$ids['gw_wanb']}";
unset($root->OPNsense->WGClientTunnelsEngine);
if ($engineMode === 'empty') {
    $e = $root->OPNsense->addChild('WGClientTunnelsEngine');
    $e->addAttribute('version', '1.0.0');
    $e->addChild('managed');
}
$cfg->save();
$cfg->unlock();
echo $ids['instance'], ' ', $ids['gw_rehearse'], ' ', $ids['gw_wanb'], "\n";
PHPEOF

# fact.php WHAT [ARG]: one fact about /conf/config.xml as it is on disk
cat > "$T/fact.php" <<'PHPEOF'
<?php
$x = simplexml_load_file('/conf/config.xml');
$s = $x->OPNsense->WGClientTunnels;
$e = $x->OPNsense->WGClientTunnelsEngine;
$rows = [];
foreach ($e->holds as $h) {
    $rows[] = [(string)$h->gateway, (string)$h->boot, (string)$h->underlay, (string)$h->taken_at];
}
switch ($argv[1]) {
    case 'settings':
        echo (string)$s['version'], ' managed:', isset($s->managed) ? 'yes' : 'no', ' held:', isset($s->held) ? 'yes' : 'no';
        break;
    case 'engine_version':
        echo count($x->xpath('/opnsense/OPNsense/WGClientTunnelsEngine')) === 1 ? (string)$e['version'] : 'no engine node';
        break;
    case 'engine_managed':
        echo (string)$e->managed;
        break;
    case 'rows':
        echo count($rows);
        break;
    case 'row':
        foreach ($rows as $r) {
            if ($r[0] === $argv[2]) {
                echo implode(' ', $r);
            }
        }
        break;
    case 'force_down':
        foreach ($x->OPNsense->Gateways->gateway_item as $g) {
            if ((string)$g->name === $argv[2]) {
                echo (string)$g->force_down;
            }
        }
        break;
}
PHPEOF

# lists.php BEFORE AFTER: "same" when both lists match once `held` and the per-tunnel fields 3.8 adds (`pins`,
# `pinned`: spec 2026-10-20 section 3.1 part C) are set aside, then each `held`
cat > "$T/lists.php" <<'PHPEOF'
<?php
$a = json_decode((string)file_get_contents($argv[1]), true);
$b = json_decode((string)file_get_contents($argv[2]), true);
if (!is_array($a) || !is_array($b)) {
    echo "unreadable\n";
    exit;
}
$ha = $a['held'] ?? null;
$hb = $b['held'] ?? null;
unset($a['held'], $b['held']);
$strip = function (array $list): array {
    foreach (array_keys($list['tunnels'] ?? []) as $i) {
        unset($list['tunnels'][$i]['pins'], $list['tunnels'][$i]['pinned']);
    }
    return $list;
};
$a = $strip($a);
$b = $strip($b);
echo $a === $b && $a['tunnels'] !== [] ? 'same' : 'different', "\n", json_encode($ha), "\n", json_encode($hb), "\n";
PHPEOF

# the 3.7_1 package's own tunnel.php, its settings model loaded in place of the installed one
mkdir -p "$T/pkg"
tar -xf "$PKG371" -C "$T/pkg" 2> /dev/null
OLD="$T/pkg/usr/local/opnsense"
[ -f "$OLD/scripts/OPNsense/WGClientTunnels/tunnel.php" ] || { echo "[FAIL] the 3.7_1 package is not in pkg's cache"; exit 1; }
cat > "$T/list371.php" <<PHPEOF
<?php
require_once 'config.inc';
require_once 'util.inc';
require_once 'interfaces.inc';
require_once '/usr/local/opnsense/mvc/script/load_phalcon.php';
require_once '$OLD/mvc/app/models/OPNsense/WGClientTunnels/WGClientTunnels.php';
\$argv = ['tunnel.php', '--json', 'list'];
require '$OLD/scripts/OPNsense/WGClientTunnels/tunnel.php';
PHPEOF

BOOT=$(/sbin/sysctl -x -n kern.boot_id | sed -n 's/.*Dump:0x\([0-9a-fA-F]*\).*/\1/p' | tr 'A-F' 'a-f')
[ -n "$BOOT" ] || { echo "[FAIL] kern.boot_id cannot be read on this VM"; exit 1; }

S=/usr/local/opnsense/scripts/OPNsense/WGClientTunnels
RUN=/var/run/wgclienttunnels
USERS="$(dirname "$0")/wgct_user.php"
SET_USER=wgct-migrate-set
REFUSED='the plugin settings are not migrated to 3.1.0 yet'

# pending INST: the checks of the window before the migration (see the header); config.xml is 3.7_1's
pending() {
    service cron stop > /dev/null
    # the ticks and the reconcile cron started before it stopped (a `sleep 45 && …` shell runs on): each would run
    # the route set or the mirror, and log its one refusal before the checks below mark the log
    n=0
    while [ "$n" -lt 90 ] && pgrep -f 'WGClientTunnels/((health_mirror|prime)[.]php|wgct[.]sh)|rc[.]routing_configure' > /dev/null; do
        sleep 1
        n=$((n + 1))
    done
    echo "    waited ${n} s for the runs cron started"
    check "pending: no run cron started is left" "$([ "$n" -lt 90 ] && echo none || echo running)" none
    rm -f "$RUN"/*.pending
    cp /conf/config.xml "$T/pending.xml"
    mark=$(lmark wireguard)
    $PHP "$TUNNEL" --json list > "$T/pending-list.json"
    check "pending: (M1) the 3.8 list shows the tunnels, findings and unmanaged instances 3.7_1 lists (the managed list 3.7_1 stored)" \
        "$($PHP "$T/lists.php" "$T/before.json" "$T/pending-list.json" | sed -n 1p)" same
    $PHP "$S/health_mirror.php" --dry > "$T/dry.out" 2>&1
    check "pending: (M1) health_mirror.php --dry says the tick refuses" "$(grep -c "the tick refuses: $REFUSED" "$T/dry.out")" 1
    check "pending: (M1) the listing and --dry write nothing: config.xml as it was, no marker, no log line" \
        "$(cmp -s /conf/config.xml "$T/pending.xml" && echo same || echo changed) $(ls "$RUN" | grep -c '[.]pending$') $(lcount wireguard "$mark" -e '\[wgct-')" "same 0 0"
    mark=$(lmark wireguard)
    $PHP "$S/health_mirror.php"; t1=$?
    $PHP "$S/health_mirror.php"; t2=$?
    check "pending: (M1) two mirror ticks exit 0 and log one refusal" \
        "$t1 $t2 $(lcount wireguard "$mark" -e "wgct-health. tick refused: $REFUSED")" "0 0 1"
    mark=$(lmark wireguard)
    a1=$($PHP "$TUNNEL" --json apply "$1" filter)
    $PHP "$TUNNEL" --json apply "$1" filter > /dev/null
    check "pending: (M1) apply refuses with the reason, before any step, and logs it once" \
        "$(echo "$a1" | grep -c "\"errors\":\[\"$REFUSED") $(echo "$a1" | grep -c '"apply":\[\]') $(lcount wireguard "$mark" -e "apply refused: $REFUSED")" "1 1 1"
    mark=$(lmark wireguard)
    d1=$($PHP "$TUNNEL" --json adopt "$UPPER")
    d2=$($PHP "$TUNNEL" --json --dry remove "$1")
    check "pending: (M1) an action (adopt) and a dry remove refuse with the reason; one line" \
        "$(echo "$d1" | grep -c "$REFUSED") $(echo "$d2" | grep -c "$REFUSED") $(lcount wireguard "$mark" -e "action refused: $REFUSED")" "1 1 1"
    mark=$(lmark wireguard)
    r1=$($PHP "$TUNNEL" --json release-holds)
    $PHP "$TUNNEL" --json release-holds > /dev/null
    check "pending: (M1) release-holds refuses, releases nothing (rehearse stays force_down=1) and logs it once" \
        "$(echo "$r1" | grep -c "$REFUSED") $($PHP "$T/fact.php" force_down rehearse) $(lcount wireguard "$mark" -e "release-holds refused: $REFUSED")" "1 1 1"
    mark=$(lmark wireguard)
    "$S/wgct.sh" configure_routes; "$S/wgct.sh" configure_routes
    $PHP "$S/monitor_repair.php"; $PHP "$S/monitor_repair.php"
    check "pending: (M1) the route set and the monitor repair refuse, each logged once" \
        "$(lcount wireguard "$mark" -e "wgct-routes. route set refused: $REFUSED") $(lcount wireguard "$mark" -e "wgct-monitor. monitor-repair refused: $REFUSED")" "1 1"
    check "pending: (M1) nothing refused changed config.xml" "$(cmp -s /conf/config.xml "$T/pending.xml" && echo same || echo changed)" same
    cred=$($PHP "$USERS" create "$SET_USER" page-vpn-wgclienttunnels) && configctl auth sync user "$SET_USER" > /dev/null 2>&1
    mark=$(lmark wireguard)
    code=$(curl -sk -m 60 -o "$T/set.body" -w '%{http_code}' -u "$cred" -X POST -d 'wgclienttunnels[enabled]=1' \
        https://127.0.0.1/api/wgclienttunnels/settings/set)
    curl -sk -m 60 -o /dev/null -u "$cred" -X POST -d 'wgclienttunnels[enabled]=1' https://127.0.0.1/api/wgclienttunnels/settings/set
    check "pending: (M1) the settings API's set refuses (core's UserException: HTTP 500 with the reason) and logs it once" \
        "$code $(grep -c "$REFUSED" "$T/set.body") $(lcount wireguard "$mark" -e "settings refused: $REFUSED")" "500 1 1"
    check "pending: (M1) the settings node keeps 3.7_1's managed list and holds for the migration" "$($PHP "$T/fact.php" settings)" "3.0.0 managed:yes held:yes"
    remove_set_user
    pend_mark=$(lmark wireguard)
}

# scenario NAME ENGINE PREFIX MIRROR [pending]
scenario() {
    name="$1"
    prefix="$3"
    mirror="$4"
    pend="${5:-}"
    ids=$($PHP "$T/shape.php" "$2" "$UPPER" "$GW6" "$mirror") || { echo "[FAIL] $name: the 3.7_1 config could not be written"; FAIL=$((FAIL + 1)); return; }
    set -- $ids
    inst="$1"; gwr="$2"; gwb="$3"
    if [ "$mirror" = on ]; then
        rows=2
        held38=$($PHP -r '$h = [$argv[1], $argv[2]]; sort($h); echo json_encode($h);' "$gwr" "$GW6")
    else
        rows=1
        held38="[\"$gwr\"]"
    fi
    $PHP "$T/list371.php" > "$T/before.json"
    [ "$pend" = pending ] && pending "$inst"
    rm -f "$BOOTJSON"
    mark=$(lmark wireguard)
    start=$(date +%s)
    $PHP "$MIGRATE" "$prefix" > "$T/migrate.out" 2>&1
    end=$(date +%s)
    echo "    $name: run_migrations.php said: $(tr '\n' ';' < "$T/migrate.out")"
    sleep 1
    $PHP "$TUNNEL" --json list > "$T/after.json"

    check "$name: the settings node is at 3.1.0 with neither managed nor held" "$($PHP "$T/fact.php" settings)" "3.1.0 managed:no held:no"
    check "$name: the engine node is at 1.0.0" "$($PHP "$T/fact.php" engine_version)" 1.0.0
    check "$name: the engine holds the managed list byte for byte (m1: order and upper case kept)" \
        "$($PHP "$T/fact.php" engine_managed)" "$inst,$UPPER"
    check "$name: exactly $rows holds rows" "$($PHP "$T/fact.php" rows)" "$rows"
    row=$($PHP "$T/fact.php" row "$gwr")
    check "$name: one row is rehearse's gateway, the live boot id, WAN_B" "${row% *}" "$gwr $BOOT WAN_B"
    taken="${row##* }"
    check "$name: that row was taken during the migration" \
        "$([ "$taken" -ge "$start" ] 2> /dev/null && [ "$taken" -le "$end" ] && echo yes || echo "no ($taken, run $start-$end)")" yes
    row6=$($PHP "$T/fact.php" row "$GW6")
    if [ "$mirror" = on ]; then
        check "$name: (3.5a) the other is rehearse-ipv6, forced down by the 3.7_1 pass 2: the live boot id, following rehearse" \
            "${row6% *}" "$GW6 $BOOT rehearse"
        taken="${row6##* }"
        check "$name: that row was taken during the migration" \
            "$([ "$taken" -ge "$start" ] 2> /dev/null && [ "$taken" -le "$end" ] && echo yes || echo "no ($taken, run $start-$end)")" yes
    else
        check "$name: (R35) rehearse-ipv6 has no row: the 3.7_1 mirror never ran, so its force_down is not the plugin's" "[$row6]" "[]"
        check "$name: (R35) one line names rehearse-ipv6 as left forced down as manual" \
            "$(lcount wireguard "$mark" -e "rehearse-ipv6 ($GW6) left forced down as manual: the 3.7_1 health mirror was off")" 1
    fi
    check "$name: (M3) boot.json, removed before the run, names the live boot" \
        "$($PHP -r '$r = json_decode((string)@file_get_contents($argv[1]), true); echo is_array($r) ? ($r["boot_id"] ?? "no boot_id") : "absent";' "$BOOTJSON")" "$BOOT"
    check "$name: rehearse and rehearse-ipv6 stay force_down=1, WAN_B force_down=0" \
        "$($PHP "$T/fact.php" force_down rehearse) $($PHP "$T/fact.php" force_down rehearse-ipv6) $($PHP "$T/fact.php" force_down WAN_B)" "1 1 0"
    check "$name: one 'not held by this plugin' line names WAN_B's gateway" \
        "$(lcount wireguard "$mark" -e "$gwb.*not held by this plugin" -e "not held by this plugin.*$gwb")" 1
    lists=$($PHP "$T/lists.php" "$T/before.json" "$T/after.json")
    check "$name: tunnel.php --json list shows the same tunnels, findings and unmanaged instances as 3.7_1" \
        "$(echo "$lists" | sed -n 1p)" same
    check "$name: 3.7_1 listed both held uuids" "$(echo "$lists" | sed -n 2p)" "[\"$gwr\",\"$gwb\"]"
    check "$name: 3.8 lists rehearse's gateways with a row as held, and only them" "$(echo "$lists" | sed -n 3p)" "$held38"
    if [ "$pend" = pending ]; then
        $PHP "$TUNNEL" --json adopt "$UPPER" > /dev/null
        check "pending: (M1) after the migration the first action logs that it runs again, and nothing refuses since" \
            "$(lcount wireguard "$pend_mark" -e 'action runs again: the plugin settings are migrated to 3.1.0') $(lcount wireguard "$mark" -e "refused: $REFUSED")" "1 0"
    fi
}

scenario "A (+POST_INSTALL, no engine node)" none OPNsense/WGClientTunnels on pending
cp /conf/config.xml "$T/after-a.xml"
$PHP "$MIGRATE" OPNsense/WGClientTunnels > "$T/again.out" 2>&1
check "A: a second run_migrations.php prints nothing" "$(cat "$T/again.out")" ""
check "A: a second run_migrations.php leaves config.xml as it was" \
    "$(cmp -s /conf/config.xml "$T/after-a.xml" && echo unchanged || echo changed)" unchanged
scenario "B (the settings model alone)" none OPNsense/WGClientTunnels/WGClientTunnels on
scenario "C (the engine model already at 1.0.0)" empty OPNsense/WGClientTunnels on
scenario "D (the health mirror off, R35)" none OPNsense/WGClientTunnels off

echo "migrate: $PASS/$((PASS + FAIL)) passed"
[ "$FAIL" -eq 0 ]
