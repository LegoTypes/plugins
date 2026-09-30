#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Restart a missing IPv6 tunnel monitor (spec 2026-09-28 section 3.4.3). Run only by the minute cron, as the
 * last step of `wgct.sh reconcile --repair` (after the route set has released routes.lock, and after
 * default_guard.php and freshness.php): never from a hook, the config syshook or an apply. At hook time the
 * tunnel's inner address is almost always still tentative, and under routes.alarm or replay_alarm the gateway
 * lock is held by the parent flock. The decisions are lib/repair.php's; this file reads, starts and logs.
 * Every lock is opened close-on-exec (wgct_poll_lock), and dpinger is started through pluginctl as a child,
 * so no lock can reach a daemon.
 */

require_once 'config.inc';
require_once 'util.inc';
require_once 'interfaces.inc';
require_once '/usr/local/opnsense/mvc/script/load_phalcon.php';
require_once __DIR__ . '/lib/apply.php';
require_once __DIR__ . '/lib/repair.php';
openlog('wgct', LOG_PID, LOG_USER);

$stateDir = getenv('WGCT_STATE_DIR') ?: '/var/run/wgclienttunnels';
$mdl = new \OPNsense\WGClientTunnels\WGClientTunnels();
if (!$mdl->enabled->isEqual('1')) {
    exit(0);
}
$log = fn (string $msg): bool => syslog(LOG_NOTICE, "[wgct-monitor] {$msg}");
/* one tick at a time: a tick whose replay runs long must not overlap the next on the state file */
try {
    $self = wgct_poll_lock("{$stateDir}/monitor_repair.lock", 0, 50);
} catch (\Throwable $e) {
    $log('cannot open the single-instance lock: ' . $e->getMessage());
    exit(0);
}
if ($self === null) {
    exit(0);
}
$stateFile = "{$stateDir}/monitor_repair.json";
$state = json_decode((string)@file_get_contents($stateFile), true);
$state = (is_array($state) ? $state : []) + ['attempts' => [], 'noted' => [], 'duplicated' => []];
$now = time();

$core = wgct_core_snapshot();
$candidates = [];
foreach (wgct_repair_watch(wgct_derive($core, wgct_split_csv((string)$mdl->managed)), $core) as $w) {
    $ifconfig = [];
    exec('/sbin/ifconfig ' . escapeshellarg($w['device']) . ' inet6 2>/dev/null', $ifconfig);
    $route = [];
    exec('/sbin/route -n get -inet6 ' . escapeshellarg($w['monitor']) . ' 2>/dev/null', $route);
    $routed = interfaces_routed_address6($w['interface'])[0] ?? null;
    $duplicated = wgct_repair_is_duplicated($ifconfig, $w['address']);
    if ($duplicated && ($state['duplicated'][$w['gw6']] ?? '') !== $w['address']) {
        $log("{$w['address']} on {$w['device']} is duplicated; {$w['gw6']} cannot be monitored");
        $state['duplicated'][$w['gw6']] = $w['address'];
    } elseif (!$duplicated) {
        unset($state['duplicated'][$w['gw6']]);
    }
    $judged = wgct_repair_judge($w, [
        'pid_live' => isvalidpid("/var/run/dpinger_{$w['gw6']}.pid"),
        'routed' => is_string($routed) && $routed !== '' ? $routed : null,
        'duplicated' => $duplicated,
        'route_dev' => wgct_repair_route_dev($route, $w['monitor']),
    ], wgct_repair_allows($state, $w['gw6'], $now));
    if ($judged['candidate']) {
        $candidates[] = $w['gw6'];
    } elseif ($judged['why'] === 'back-off' && wgct_repair_note_due($state, $w['gw6'], $now)) {
        $log("{$w['gw6']} has no dpinger and " . WGCT_REPAIR_MAX . ' starts in ' . (WGCT_REPAIR_WINDOW / 60)
            . ' minutes did not keep one running; the next attempt waits for that window');
        $state['noted'][$w['gw6']] = $now;
    }
}

$lock = null;
$result = wgct_repair_run($candidates, [
    'status' => fn (): ?array => wgct_gateway_status(),
    'lock' => function () use (&$lock, $log): bool {
        try {
            $lock = wgct_poll_lock(WGCT_GATEWAY_LOCK_FILE, 0, 50);
        } catch (\Throwable $e) {
            $log('cannot open the gateway lock: ' . $e->getMessage());
            return false;
        }
        return $lock !== null;
    },
    'unlock' => function () use (&$lock): void {
        $lock?->flock(LOCK_UN);
        $lock = null;
    },
    'live' => fn (string $gw): bool => isvalidpid("/var/run/dpinger_{$gw}.pid"),
    'start' => function (string $gw): string {
        $out = [];
        exec('/usr/local/sbin/pluginctl -s dpinger start ' . escapeshellarg($gw) . ' 2>&1', $out);
        return implode("\n", $out);
    },
    'sleep' => function (int $usec): void {
        usleep($usec);
    },
    'clock' => fn (): float => microtime(true),
    'started' => function (array $started) use (&$state, $now, $stateFile): void {
        /* recorded and written before the replay: a replay that throws must not skip the back-off */
        foreach ($started as $gw) {
            $state = wgct_repair_record($state, $gw, $now);
        }
        wgct_write_file_atomic($stateFile, json_encode($state) . "\n");
    },
    'replay' => function (array $ours, ?array $before): void {
        wgct_replay_after_hold($ours, $before);
    },
]);
foreach ($result['lines'] as $line) {
    $log($line);
}
wgct_write_file_atomic($stateFile, json_encode($state) . "\n");
