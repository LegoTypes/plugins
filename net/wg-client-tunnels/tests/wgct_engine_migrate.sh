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
# VM test of the engine model's 1.0.0 -> 1.1.0 migration (Migrations/ENG1_1_0.php): 3.8's comma list `managed`
# becomes one `tunnels` row per instance, in order. Root on the disposable test VM only, never on a firewall, after
# vm_overlay.sh has put the tree onto the installed package.
#
# It rewrites /conf/config.xml for a few seconds, so vm_selftest.sh runs it after every suite that reads config.
# config.xml is copied aside first and put back through core's Config::restoreBackup() at exit, even on failure or a
# dropped session, as wgct_migrate.sh does; boot.json, which the settings model's migration writes, is copied aside
# and put back too. The whole run holds the mirror's health.lock, so no mirror tick writes config.xml under a case.
#
# Each case writes its engine node into config.xml through core's Config (SimpleXML), waits out the reconcile that
# save queues, then runs run_migrations.php OPNsense/WGClientTunnels as the package's +POST_INSTALL runs it:
#   - 3.8_1 values: the engine node at 1.0.0, `managed` = the VM's tunnel `rehearse`'s instance and a synthetic
#     upper-case uuid, and one hold record => 1.1.0, two `tunnels` rows in that order, no `managed` element, the hold
#     record and the settings node as they were;
#   - an empty list => 1.1.0 and no row;
#   - rehearse's instance named twice => two rows naming it, as 3.8's list held it twice;
#   - a list that is not one text value => not migrated: the node stays at 1.0.0 and config.xml is as it was, byte
#     for byte (core saves nothing when a migration throws);
#   - a 3.7_1 settings node (3.0.0, with `managed` and `held`, rehearse's gateway forced down as the 3.7_1 mirror
#     leaves a hold, no engine node) => both models migrate: settings 3.1.0 without either field, engine 1.1.0 with
#     the rows in order, and the one hold record M3_1_0 plans (rehearse's gateway, the live boot, WAN_B; WAN_B's
#     own gateway, also in `held`, is not the plugin's and is dropped).
# The facts are read from a copy of config.xml taken as run_migrations.php exits.
#
# Usage: wgct_engine_migrate.sh

set -u
LOCK=/var/run/wgclienttunnels/health.lock
if [ "${1:-}" != --locked ]; then
    /usr/bin/lockf -k -t 60 "$LOCK" /bin/sh "$0" --locked
    rc=$?
    # lockf exits 75 when the lock stays held for its 60 s: no case ran, so say who holds it
    if [ "$rc" -eq 75 ]; then
        echo "[FAIL] engine_migrate: $LOCK was still held after 60 s, so no case ran; it is open in:"
        fstat "$LOCK" | sed 's/^/      | /'
        pgrep -lf 'WGClientTunnels/' | sed 's/^/      |   running: /'
        echo "engine_migrate: 0/1 passed"
    fi
    exit "$rc"
fi

PHP="/usr/local/bin/php -d log_errors=0"
MIGRATE=/usr/local/opnsense/mvc/script/run_migrations.php
UPPER=ABCDEF00-0000-4000-8000-0000000000AB
HOLD=0000e2e2-0000-4000-8000-00000000e2e2
HOLD_GW=0000e1e1-0000-4000-8000-00000000e1e1
T=$(mktemp -d /tmp/wgct-engine-migrate.XXXXXX)
PASS=0
FAIL=0

. "$(dirname "$0")/wgct_settle.sh"

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
cleanup() {
    $PHP "$T/restore.php" "$T/config.xml" || echo "[FAIL] config.xml could not be restored from $T/config.xml"
    reconcile_drained 150 || echo "[FAIL] the reconcile the restore queued was still queued or running 150 s later"
    rm -f /var/run/wgclienttunnels/*.awaiting-migration
    if [ -f "$T/boot.json" ]; then cp -p "$T/boot.json" "$BOOTJSON"; else rm -f "$BOOTJSON"; fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

# write.php MODE UPPER HOLD HOLD_GW BOOT: the engine node MODE names, through core's Config. values, empty and
# unreadable write a 1.0.0 engine node (see the header); legacy writes 3.7_1's settings node and no engine node.
# Prints rehearse's instance uuid, its gateway's and WAN_B's.
cat > "$T/write.php" <<'PHPEOF'
<?php
require_once '/usr/local/opnsense/mvc/script/load_phalcon.php';

use OPNsense\Core\Config;

[, $mode, $upper, $hold, $holdGw, $boot] = $argv;
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
        if ($mode === 'legacy') {
            $g->force_down = '1';
        }
    } elseif ((string)$g->name === 'WAN_B') {
        $ids['gw_wanb'] = (string)$g['uuid'];
    }
}
if (in_array('', $ids, true)) {
    $cfg->unlock();
    fwrite(STDERR, "rehearse or WAN_B is missing (vm_base.sh)\n");
    exit(1);
}
unset($root->OPNsense->WGClientTunnelsEngine);
if ($mode === 'legacy') {
    $n = $root->OPNsense->WGClientTunnels;
    $n['version'] = '3.0.0';
    $n->enabled = '1';
    $n->health_mirror = '1';
    $n->managed = "{$ids['instance']},{$upper}";
    $n->held = "{$ids['gw_rehearse']},{$ids['gw_wanb']}";
} else {
    $e = $root->OPNsense->addChild('WGClientTunnelsEngine');
    $e->addAttribute('version', '1.0.0');
    if ($mode === 'values') {
        $e->addChild('managed', "{$ids['instance']},{$upper}");
        $h = $e->addChild('holds');
        $h->addAttribute('uuid', $hold);
        foreach (['gateway' => $holdGw, 'boot' => $boot, 'underlay' => 'WAN_B', 'taken_at' => '1760000000'] as $field => $value) {
            $h->addChild($field, $value);
        }
    } elseif ($mode === 'twice') {
        $e->addChild('managed', "{$ids['instance']},{$ids['instance']}");
    } elseif ($mode === 'empty') {
        $e->addChild('managed');
    } else {
        $e->addChild('managed')->addChild('item', 'x');
    }
}
$cfg->save();
$cfg->unlock();
echo $ids['instance'], ' ', $ids['gw_rehearse'], ' ', $ids['gw_wanb'], "\n";
PHPEOF

# fact.php FILE WHAT [ARG]: one fact about the config file FILE, read with whitespace-only text left out, so a node
# reads the same before and after core's pretty-printing save
cat > "$T/fact.php" <<'PHPEOF'
<?php
$d = new DOMDocument();
$d->preserveWhiteSpace = false;
if (!$d->load($argv[1])) {
    echo "unreadable\n";
    exit(1);
}
$x = new DOMXPath($d);
$engine = '/opnsense/OPNsense/WGClientTunnelsEngine';
$one = function (string $path) use ($x): ?DOMElement {
    $l = $x->query($path);
    return $l !== false && $l->length === 1 && $l->item(0) instanceof DOMElement ? $l->item(0) : null;
};
switch ($argv[2]) {
    case 'engine_version':
        $e = $one($engine);
        echo $e === null ? 'no engine node' : $e->getAttribute('version');
        break;
    case 'rows':
        $instances = [];
        $uuids = [];
        foreach ($x->query("{$engine}/tunnels") as $r) {
            $instances[] = $x->evaluate('string(instance)', $r);
            if (preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/', $r->getAttribute('uuid')) === 1) {
                $uuids[] = $r->getAttribute('uuid');
            }
        }
        echo '[', implode(',', $instances), '] uuids=', count($uuids), ' distinct=', count(array_unique($uuids));
        break;
    case 'managed_elements':
        echo $x->query("{$engine}/managed")->length;
        break;
    case 'holds':
        echo $x->query("{$engine}/holds")->length;
        break;
    case 'hold':
        $h = $one("{$engine}/holds[@uuid='{$argv[3]}']");
        echo $h === null ? 'no such hold record' : $h->C14N();
        break;
    case 'hold_of':
        foreach ($x->query("{$engine}/holds") as $h) {
            if ($x->evaluate('string(gateway)', $h) === $argv[3]) {
                echo $x->evaluate('string(gateway)', $h), ' ', $x->evaluate('string(boot)', $h), ' ',
                    $x->evaluate('string(underlay)', $h);
            }
        }
        break;
    case 'settings':
        $s = $one('/opnsense/OPNsense/WGClientTunnels');
        echo $s === null ? 'no settings node' : $s->getAttribute('version') . ' managed:'
            . ($x->query('managed', $s)->length > 0 ? 'yes' : 'no') . ' held:' . ($x->query('held', $s)->length > 0 ? 'yes' : 'no');
        break;
    case 'settings_xml':
        $s = $one('/opnsense/OPNsense/WGClientTunnels');
        echo $s === null ? 'no settings node' : $s->C14N();
        break;
    case 'engine_xml':
        $e = $one($engine);
        echo $e === null ? 'no engine node' : $d->saveXML($e);
        break;
    case 'force_down':
        foreach ($x->query('/opnsense/OPNsense/Gateways/gateway_item') as $g) {
            if ($x->evaluate('string(name)', $g) === $argv[3]) {
                echo $x->evaluate('string(force_down)', $g);
            }
        }
        break;
}
PHPEOF

BOOT=$(/sbin/sysctl -x -n kern.boot_id | sed -n 's/.*Dump:0x\([0-9a-fA-F]*\).*/\1/p' | tr 'A-F' 'a-f')
[ -n "$BOOT" ] || { echo "[FAIL] kern.boot_id cannot be read on this VM"; exit 1; }

# stage NAME MODE: write MODE's config (write.php), wait out the reconcile its save queued, and keep a copy of
# config.xml as it then is in $T/before.xml; sets INST, GWR and GWB. Returns 1 when the config cannot be written.
stage() {
    ids=$($PHP "$T/write.php" "$2" "$UPPER" "$HOLD" "$HOLD_GW" "$BOOT") || { FAIL=$((FAIL + 1)); echo "[FAIL] $1: the config could not be written"; return 1; }
    set -- "$1" $ids
    INST="$2"; GWR="$3"; GWB="$4"
    reconcile_drained 150 || { FAIL=$((FAIL + 1)); echo "[FAIL] $1: the reconcile the write queued was still queued or running 150 s later"; }
    cp -p /conf/config.xml "$T/before.xml"
}

# migrate NAME: run_migrations.php as +POST_INSTALL runs it, config.xml copied to $T/after.xml as it exits, then the
# reconcile its save queued waited out; the case's first FAIL count is kept for evidence()
migrate() {
    fails0=$FAIL
    $PHP "$MIGRATE" OPNsense/WGClientTunnels > "$T/migrate.out" 2>&1
    cp -p /conf/config.xml "$T/after.xml"
    echo "    $1: run_migrations.php said: $(tr '\n' ';' < "$T/migrate.out")"
    reconcile_drained 150 || { FAIL=$((FAIL + 1)); echo "[FAIL] $1: the reconcile the migration queued was still queued or running 150 s later"; }
}

# evidence: after a case with a FAIL, the engine node before and after the run
evidence() {
    [ "$FAIL" -eq "$fails0" ] && return
    echo "      | before: $($PHP "$T/fact.php" "$T/before.xml" engine_xml | tr -s ' \n' ' ')"
    echo "      | after:  $($PHP "$T/fact.php" "$T/after.xml" engine_xml | tr -s ' \n' ' ')"
}

fact() {
    $PHP "$T/fact.php" "$T/after.xml" "$@"
}

# each case: version, rows ([instances] uuids=<rows with a uuid> distinct=<different uuids among them>), managed
# elements left, and what else it names
if stage "engine: 3.8_1 values" values; then
    hold0=$($PHP "$T/fact.php" "$T/before.xml" hold "$HOLD")
    settings0=$($PHP "$T/fact.php" "$T/before.xml" settings_xml)
    migrate "engine: 3.8_1 values"
    check "engine: 3.8_1 values become rows in order" \
        "$(fact engine_version) $(fact rows) $(fact managed_elements) holds=$(fact holds) hold:$([ "$(fact hold "$HOLD")" = "$hold0" ] && echo same || echo changed) settings:$([ "$(fact settings_xml)" = "$settings0" ] && echo same || echo changed)" \
        "1.1.0 [$INST,$UPPER] uuids=2 distinct=2 0 holds=1 hold:same settings:same"
    evidence
fi

if stage "engine: an empty list" empty; then
    migrate "engine: an empty list"
    check "engine: an empty list becomes no row" "$(fact engine_version) $(fact rows) $(fact managed_elements)" "1.1.0 [] uuids=0 distinct=0 0"
    evidence
fi

if stage "engine: a list naming one uuid twice" twice; then
    migrate "engine: a list naming one uuid twice"
    check "engine: a list naming one uuid twice keeps both rows" "$(fact engine_version) $(fact rows) $(fact managed_elements)" \
        "1.1.0 [$INST,$INST] uuids=2 distinct=2 0"
    evidence
fi

if stage "engine: a list that is not one text value" unreadable; then
    migrate "engine: a list that is not one text value"
    check "engine: a list that is not one text value is not migrated" \
        "$(fact engine_version) $(cmp -s "$T/after.xml" "$T/before.xml" && echo same || echo changed)" "1.0.0 same"
    evidence
fi

if stage "engine: a 3.7_1 settings node" legacy; then
    migrate "engine: a 3.7_1 settings node"
    check "engine: a 3.7_1 settings node migrates both models" \
        "$(fact settings) $(fact engine_version) $(fact rows) $(fact managed_elements) holds=$(fact holds) [$(fact hold_of "$GWR")] [$(fact hold_of "$GWB")] force_down=$(fact force_down rehearse)$(fact force_down WAN_B)" \
        "3.1.0 managed:no held:no 1.1.0 [$INST,$UPPER] uuids=2 distinct=2 0 holds=1 [$GWR $BOOT WAN_B] [] force_down=10"
    evidence
fi

echo "engine_migrate: $PASS/$((PASS + FAIL)) passed"
[ "$FAIL" -eq 0 ]
