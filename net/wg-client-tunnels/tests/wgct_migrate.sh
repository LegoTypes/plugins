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
#   - no engine node (scenarios A and B, a box that never ran 3.8), or an empty one at 1.0.0 (scenario C).
# The 3.7_1 tunnel.php, from the 3.7_1 package in pkg's cache, lists the tunnels on that config. Then:
#   A: run_migrations.php OPNsense/WGClientTunnels, as the package's +POST_INSTALL runs it (both models);
#   B: run_migrations.php OPNsense/WGClientTunnels/WGClientTunnels, the settings model alone: its migration first
#      brings the engine model to its own version, so the order core runs the two in does not matter;
#   C: as A, with the engine model already migrated.
# Each scenario then asserts: the settings node is at 3.1.0 with neither field; the engine node is at 1.0.0 with
# the managed list byte for byte and exactly one holds row (rehearse's gateway, the live kern.boot_id, WAN_B,
# taken during the run); force_down is as it was; one "not held by this plugin" line names WAN_B's gateway in
# core's WireGuard log; the installed tunnel.php lists the same tunnels, findings and unmanaged instances as 3.7_1
# did, and its `held` keeps only rehearse's gateway (the other was dropped). A second run changes nothing (A).
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
WGLOG=/var/log/wireguard/latest.log
UPPER=ABCDEF00-0000-4000-8000-0000000000AB
T=$(mktemp -d /tmp/wgct-migrate.XXXXXX)
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
    $PHP "$T/restore.php" "$T/config.xml" || echo "[FAIL] config.xml could not be restored from $T/config.xml"
    rm -rf "$T/pkg"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

# shape.php ENGINE UPPER: the config 3.7_1 leaves (see the header); ENGINE is none or empty. Prints the uuids.
cat > "$T/shape.php" <<'PHPEOF'
<?php
require_once '/usr/local/opnsense/mvc/script/load_phalcon.php';

use OPNsense\Core\Config;

[, $engineMode, $upper] = $argv;
$cfg = Config::getInstance();
$cfg->lock();
$root = $cfg->object();
$ids = ['instance' => '', 'gw_rehearse' => '', 'gw_wanb' => ''];
foreach ($root->OPNsense->wireguard->server->servers->server as $s) {
    if ((string)$s->name === 'rehearse') {
        $ids['instance'] = (string)$s['uuid'];
    }
}
foreach ($root->OPNsense->Gateways->gateway_item as $g) {
    if ((string)$g->name === 'rehearse') {
        $ids['gw_rehearse'] = (string)$g['uuid'];
        $g->force_down = '1';
    } elseif ((string)$g->name === 'WAN_B') {
        $ids['gw_wanb'] = (string)$g['uuid'];
    }
}
if (in_array('', $ids, true)) {
    $cfg->unlock();
    fwrite(STDERR, "rehearse or WAN_B is missing (vm_base.sh)\n");
    exit(1);
}
$n = $root->OPNsense->WGClientTunnels;
$n['version'] = '3.0.0';
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
        echo implode(' ', $rows[0] ?? []);
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

# lists.php BEFORE AFTER: "same" when both lists match once `held` is set aside, then each `held`
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

# scenario NAME ENGINE PREFIX
scenario() {
    name="$1"
    ids=$($PHP "$T/shape.php" "$2" "$UPPER") || { echo "[FAIL] $name: the 3.7_1 config could not be written"; FAIL=$((FAIL + 1)); return; }
    set -- "$@" $ids
    inst="$4"; gwr="$5"; gwb="$6"
    $PHP "$T/list371.php" > "$T/before.json"
    lines=$(wc -l < "$WGLOG")
    start=$(date +%s)
    $PHP "$MIGRATE" "$3" > "$T/migrate.out" 2>&1
    end=$(date +%s)
    echo "    $name: run_migrations.php said: $(tr '\n' ';' < "$T/migrate.out")"
    sleep 1
    $PHP "$TUNNEL" --json list > "$T/after.json"

    check "$name: the settings node is at 3.1.0 with neither managed nor held" "$($PHP "$T/fact.php" settings)" "3.1.0 managed:no held:no"
    check "$name: the engine node is at 1.0.0" "$($PHP "$T/fact.php" engine_version)" 1.0.0
    check "$name: the engine holds the managed list byte for byte (m1: order and upper case kept)" \
        "$($PHP "$T/fact.php" engine_managed)" "$inst,$UPPER"
    check "$name: exactly one holds row" "$($PHP "$T/fact.php" rows)" 1
    row=$($PHP "$T/fact.php" row)
    check "$name: the row is rehearse's gateway, the live boot id, WAN_B" "${row% *}" "$gwr $BOOT WAN_B"
    taken="${row##* }"
    check "$name: the row was taken during the migration" \
        "$([ "$taken" -ge "$start" ] 2> /dev/null && [ "$taken" -le "$end" ] && echo yes || echo "no ($taken, run $start-$end)")" yes
    check "$name: rehearse stays force_down=1, WAN_B force_down=0" \
        "$($PHP "$T/fact.php" force_down rehearse) $($PHP "$T/fact.php" force_down WAN_B)" "1 0"
    check "$name: one 'not held by this plugin' line names WAN_B's gateway" \
        "$(tail -n +"$((lines + 1))" "$WGLOG" | grep -F "$gwb" | grep -c 'not held by this plugin')" 1
    lists=$($PHP "$T/lists.php" "$T/before.json" "$T/after.json")
    check "$name: tunnel.php --json list shows the same tunnels, findings and unmanaged instances as 3.7_1" \
        "$(echo "$lists" | sed -n 1p)" same
    check "$name: 3.7_1 listed both held uuids" "$(echo "$lists" | sed -n 2p)" "[\"$gwr\",\"$gwb\"]"
    check "$name: 3.8 lists rehearse's gateway as held, and only it" "$(echo "$lists" | sed -n 3p)" "[\"$gwr\"]"
}

scenario "A (+POST_INSTALL, no engine node)" none OPNsense/WGClientTunnels
cp /conf/config.xml "$T/after-a.xml"
$PHP "$MIGRATE" OPNsense/WGClientTunnels > "$T/again.out" 2>&1
check "A: a second run_migrations.php prints nothing" "$(cat "$T/again.out")" ""
check "A: a second run_migrations.php leaves config.xml as it was" \
    "$(cmp -s /conf/config.xml "$T/after-a.xml" && echo unchanged || echo changed)" unchanged
scenario "B (the settings model alone)" none OPNsense/WGClientTunnels/WGClientTunnels
scenario "C (the engine model already at 1.0.0)" empty OPNsense/WGClientTunnels

echo "migrate: $PASS/$((PASS + FAIL)) passed"
[ "$FAIL" -eq 0 ]
