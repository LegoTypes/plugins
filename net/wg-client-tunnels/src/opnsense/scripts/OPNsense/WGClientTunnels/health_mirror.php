#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Health mirror for the WireGuard tunnel gateways. Two passes, one save:
 *
 * 1. Underlay: a tunnel is bound to exactly one WAN -- the gateway of the /32
 *    or /128 static route to its peer's endpoint -- and is forced down whenever
 *    that WAN is not up: disabled, force_down, absent from gateway status, or in
 *    a state a downloss gateway group treats as down (down, loss, delay+loss).
 *    A tunnel never migrates to the other WAN. Only a force_down this pass set
 *    itself is ever released, so an operator's manual force_down on a tunnel is
 *    left alone.
 *
 * 2. IPv6: each IPv6 tunnel gateway follows its own IPv4 tunnel and nothing
 *    else. IPv6 rides inside the IPv4 tunnel and Proton NATs it server-side, so
 *    it depends on no native IPv6 upstream. It is forced down when its IPv4
 *    tunnel's loss crosses that gateway's losshigh (recovering at losslow,
 *    holding in between, exactly as dpinger does), when its dpinger socket is
 *    missing, or when the IPv4 gateway itself is force_down (pass 1, or by hand).
 *
 * Keeping tunnel gateways out of the default-gateway election is NOT this
 * script's job: the sentinel gateways and default_guard.php do that.
 *
 * Tunnels come from the plugin's managed list, not a fixed naming convention:
 * lib/tunnels.php derives each one (WireGuard instance, peer, interface
 * assignment, WAN binding, gateways) from core config every time it is
 * needed. The held set -- which IPv4 tunnels this pass 1 is holding down --
 * lives in the plugin model's `held` field as gateway UUIDs, and is saved in
 * the same Config::lock()/save() write as the force_down values it explains.
 *
 * Settle guard: a dpinger that has just started has no samples yet, so what it
 * reports -- 0% or 100% loss, a gateway status of down or up -- says nothing about
 * the path. Every routing reconfigure restarts all dpingers -- any gateway Apply,
 * and the reconfigure this script itself triggers when it changes a gateway -- so
 * without this the mirror releases gateways in the middle of an outage, or holds a
 * healthy WAN's tunnels down (seen on the firewall 2026-10-06: a gateway Apply
 * took WAN2's tunnels down for 1 min 45 s), and each change restarts the dpingers
 * again. While a gateway's dpinger socket is younger than the settle window, or
 * absent, its reading changes nothing: the previous decision stands. A WAN that
 * is disabled or forced down in configuration still holds its tunnels at once;
 * that is not a reading. A real outage that coincides with a restart is acted on
 * once the window has passed. The window is the gateway's own time_period
 * (SETTLE_FALLBACK_SECONDS if unset); --settle=N overrides it and --settle=0
 * disables the guard. It applies to the WAN reading in pass 1 and the tunnel
 * reading in pass 2. A bound WAN gateway with monitoring disabled counts as
 * settled at once: it has no dpinger to wait for.
 *
 * --dry reports every decision against live config and live gateway status
 * without writing or reconfiguring anything. --selftest exercises the decision
 * logic without touching config. --snapshot prints the decision input
 * (config, live status, held tunnels) as JSON and writes nothing; --plan-from=FILE
 * decides from a snapshot saved that way and prints what --dry would.
 *
 * Runs from /etc/cron.d/wgclienttunnels four times a minute (offsets 0/15/30/45s).
 */

require "/usr/local/opnsense/mvc/script/load_phalcon.php";
require_once __DIR__ . '/lib/mirror.php';

$logTag = 'wgct-health';

// Self-test: validate the decision logic in isolation, no config access.
if (in_array('--selftest', $argv ?? [], true)) {
    exit(wgct_selftest());
}

$settleOverride = null;
$dryRun = false;
$snapshotOut = false;
$planFrom = null;
foreach ($argv ?? [] as $arg) {
    if (strpos($arg, '--settle=') === 0) {
        $settleOverride = max(0, (int)substr($arg, strlen('--settle=')));
    } elseif ($arg === '--dry') {
        $dryRun = true;
    } elseif ($arg === '--snapshot') {
        $snapshotOut = true;
    } elseif (strpos($arg, '--plan-from=') === 0) {
        $planFrom = substr($arg, strlen('--plan-from='));
    }
}

/* --plan-from=FILE: decide from a saved snapshot, print what --dry would. */
if ($planFrom !== null) {
    $snap = json_decode((string)@file_get_contents($planFrom), true);
    if (!is_array($snap) || !isset($snap['config'], $snap['live'], $snap['held'])) {
        fwrite(STDERR, "not a snapshot: {$planFrom}\n");
        exit(1);
    }
    $plan = wgct_plan($snap['config'], $snap['live'], array_fill_keys($snap['held'], true), $settleOverride);
    foreach ($plan['report'] as $line) {
        echo $line, "\n";
    }
    exit(0);
}

/* --snapshot: print the decision input as JSON, write nothing. */
if ($snapshotOut) {
    $snapConfig = wgct_collect_config();
    echo json_encode([
        'config' => $snapConfig,
        'live' => wgct_collect_live(),
        'held' => $snapConfig['held'],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
    exit(0);
}

/*
 * Single-instance guard. Cron fires this script four times a minute
 * (0/15/30/45s). A tick that changes a gateway blocks below until a full
 * routing reconfigure completes (dpinger torn down and rebuilt), which can
 * outlast the 15s spacing. Two overlapping runs would issue overlapping
 * reconfigures, and those race dpinger's teardown against another's rebuild
 * and leave it dead -- at which point every gateway reads a false "down".
 * If another run holds the lock, skip this tick; the next one catches up.
 */
$selfLock = fopen('/tmp/wgct_health.lock', 'ce');
if ($selfLock === false || !flock($selfLock, LOCK_EX | LOCK_NB)) {
    exit(0);
}

$config = wgct_collect_config();
if (!$config['enabled']) {
    if ($dryRun) {
        echo "health mirror is off in the plugin settings\n";
    }
    exit(0);
}
$held = array_fill_keys($config['held'], true);
$plan = wgct_plan($config, wgct_collect_live(), $held, $settleOverride);

if ($dryRun) {
    foreach ($plan['report'] as $line) {
        echo $line, "\n";
    }
    exit(0);
}

if (empty($plan['changes'])) {
    foreach ($plan['log'] as $msg) {
        logMsg($logTag, $msg);
    }
    if (wgct_held_uuids($plan['held'], $config['gateways']) !== $config['held_raw']) {
        /*
         * Held-set only (a tunnel that no longer exists, or a stale entry):
         * a config write with no routing change, so no gateway lock. Re-plan
         * under the config lock; if config changed meanwhile and the re-plan
         * now wants a force_down change, save nothing -- that needs the
         * gateway lock and an apply, which the next tick does.
         */
        $live = wgct_collect_live();
        wgct_locked_commit(function () use ($live, $settleOverride) {
            $now = wgct_collect_config();
            $replan = wgct_plan($now, $live, array_fill_keys($now['held'], true), $settleOverride);
            if (!empty($replan['changes'])) {
                return ['save' => false];
            }
            return ['save' => wgct_commit_held($replan['held'], $now)];
        });
    }
    exit(0);
}

/*
 * A change is needed. Commit it in the order every config writer follows
 * (spec 2026-09-24 section 4.6):
 *
 *   1. /tmp/filter_reload_gateway.lock -- applying force_down is a full
 *      routing reconfigure, which restarts every dpinger; overlapping
 *      reconfigures leave dpinger dead. Same lock routes.alarm uses.
 *   2. Live readings, collected again: the wait for the lock can be long, and
 *      gateway_status.php reads config, so it must never run inside the
 *      config lock taken in step 3.
 *   3. Config::lock(), which re-reads config.xml; the decisions are planned
 *      again from fresh models, including the held set, so a GUI save made
 *      while this run waited is kept. The force_down values and the held set
 *      are saved together, once.
 *   4. Unlock, then apply and replay the alarms the hold dropped: our own
 *      and any other gateway's whose status changed meanwhile.
 *
 * If the gateway lock itself cannot be taken, leave the change for the next
 * tick rather than save a force_down we would not apply.
 */
/* status before the lock, so an alarm routes.alarm drops while we hold it can be replayed after */
$before = wgct_gateway_status();
$gwLock = fopen('/tmp/filter_reload_gateway.lock', 'ce');
if ($gwLock === false || !flock($gwLock, LOCK_EX)) {
    if ($gwLock !== false) {
        fclose($gwLock);
    }
    exit(0);
}
$live = wgct_collect_live();
$commit = wgct_locked_commit(function () use ($live, $settleOverride) {
    $now = wgct_collect_config();
    $plan = wgct_plan($now, $live, array_fill_keys($now['held'], true), $settleOverride);
    $save = false;
    if (!empty($plan['changes'])) {
        $routingMdl = new OPNsense\Routing\Gateways();
        wgct_apply_changes($routingMdl, $plan['changes']);
        $routingMdl->serializeToConfig();
        $save = true;
    }
    $save = wgct_commit_held($plan['held'], $now) || $save;
    return ['save' => $save, 'plan' => $plan];
});
$plan = $commit['plan'];
foreach ($plan['log'] as $msg) {
    logMsg($logTag, $msg);
}
if (!empty($plan['changes'])) {
    (new OPNsense\Core\Backend())->configdRun('interface routes configure');
}
flock($gwLock, LOCK_UN);
fclose($gwLock);
if (!empty($plan['changes'])) {
    wgct_mirror_replay($plan['changes'], $before, $logTag);
}
