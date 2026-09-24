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
 *    static route to its peer's endpoint -- and is forced down whenever that WAN
 *    is not up: disabled, force_down, absent from gateway status, or in a state
 *    a downloss gateway group treats as down (down, loss, delay+loss). A tunnel
 *    never migrates to the other WAN. Only a force_down this pass set itself is
 *    ever released, so an operator's manual force_down on a tunnel is left alone.
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
 * Settle guard: a dpinger that has just started reports 0% loss because it has
 * no samples yet, not because the path is healthy. Every routing reconfigure
 * restarts all dpingers -- including the reconfigure this script itself triggers
 * when it changes a gateway -- so without this the mirror releases gateways in
 * the middle of an outage and forces them down again on the next tick. While a
 * gateway's dpinger socket is younger than the settle window, a healthy reading
 * is ignored: it can still trip a gateway DOWN, never bring one back UP. The
 * window is the gateway's own time_period (SETTLE_FALLBACK_SECONDS if unset);
 * --settle=N overrides it and --settle=0 disables the guard. It applies to the
 * WAN reading in pass 1 and the tunnel reading in pass 2.
 *
 * --dry reports every decision against live config and live gateway status
 * without writing or reconfiguring anything. --selftest exercises the decision
 * logic without touching config.
 *
 * Runs from /etc/cron.d/wgipv6gateway four times a minute (offsets 0/15/30/45s).
 */

require "/usr/local/opnsense/mvc/script/load_phalcon.php";
require_once __DIR__ . '/lib/mirror.php';

$logTag = 'wgipv6gw-health';

// Self-test: validate the decision logic in isolation, no config access.
if (in_array('--selftest', $argv ?? [], true)) {
    exit(wgipv6_selftest());
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
    $plan = wgipv6_plan($snap['config'], $snap['live'], array_fill_keys($snap['held'], true), $settleOverride);
    foreach ($plan['report'] as $line) {
        echo $line, "\n";
    }
    exit(0);
}

/* --snapshot: print the decision input as JSON, write nothing. */
if ($snapshotOut) {
    echo json_encode([
        'config' => wgipv6_collect_config(),
        'live' => wgipv6_collect_live(),
        'held' => array_keys(wgipv6_load_held()),
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
$selfLock = fopen('/tmp/wgipv6gw_health.lock', 'c');
if ($selfLock === false || !flock($selfLock, LOCK_EX | LOCK_NB)) {
    exit(0);
}

$config = wgipv6_collect_config();
if (!$config['enabled']) {
    exit(0);
}
$held = wgipv6_load_held();
$plan = wgipv6_plan($config, wgipv6_collect_live(), $held, $settleOverride);

if ($dryRun) {
    foreach ($plan['report'] as $line) {
        echo $line, "\n";
    }
    exit(0);
}

foreach ($plan['log'] as $msg) {
    logMsg($logTag, $msg);
}
if (empty($plan['changes'])) {
    if ($plan['held_changed']) {
        wgipv6_save_held($plan['held']);
    }
    exit(0);
}

/*
 * Applying a gateway change means a full routing reconfigure, which
 * restarts every dpinger on the box. It must not run concurrently with
 * another routing reconfigure: overlapping reconfigures race dpinger's
 * teardown against another's rebuild and leave it dead, showing every
 * gateway as a false "down". Serialize on the same lock OPNsense's own
 * gateway-alarm reconfigure uses (interface routes alarm ->
 * flock /tmp/filter_reload_gateway.lock). configdRun is synchronous, so
 * the lock covers the whole reconfigure.
 *
 * Acquire the lock BEFORE persisting so config and applied state stay
 * consistent: if we cannot serialize, leave the change for the next tick
 * rather than saving a force_down we would not apply. The held set is
 * written only once the config it describes has been saved.
 */
$gwLock = fopen('/tmp/filter_reload_gateway.lock', 'c');
if ($gwLock !== false && flock($gwLock, LOCK_EX)) {
    $routingMdl = new OPNsense\Routing\Gateways();
    wgipv6_apply_changes($routingMdl, $plan['changes']);
    $routingMdl->serializeToConfig();
    OPNsense\Core\Config::getInstance()->save();
    if ($plan['held_changed']) {
        wgipv6_save_held($plan['held']);
    }
    (new OPNsense\Core\Backend())->configdRun('interface routes configure');
    flock($gwLock, LOCK_UN);
    fclose($gwLock);
    wgipv6_replay_alarm($plan['changes'], $logTag);
} elseif ($gwLock !== false) {
    fclose($gwLock);
}
