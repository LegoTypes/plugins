#!/usr/local/bin/php
<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * wan-failover entry point (spec 2026-10-05 section 3.9):
 *   evaluate.php                       one evaluation (cron, configd, syshooks)
 *   evaluate.php --dry                 snapshot + plan as JSON; writes nothing
 *   evaluate.php --snapshot FILE       write the live snapshot (with pf) to FILE
 *   evaluate.php --plan-from FILE [S]  plan from a saved snapshot (and state)
 *   evaluate.php holds                 JSON status for the page
 *   evaluate.php status                the running line ApiMutableServiceControllerBase expects
 *   evaluate.php release               release every held gateway
 *   evaluate.php start|stop            regenerate cron (the minute job exists only while enabled), then evaluate | release
 */

const WF_STATE = '/var/db/wanfailover/state.json';
const WF_LOCK_DIR = '/var/run/wanfailover';
const WF_EVENT = '/var/run/wanfailover/event';
const WF_TRACE = '/var/log/wanfailover/trace';

require_once __DIR__ . '/lib/planner.php';
require_once __DIR__ . '/lib/state.php';
require_once __DIR__ . '/lib/log.php';
require_once __DIR__ . '/lib/contract.php';

$args = array_slice($argv, 1);
$mode = $args[0] ?? 'evaluate';

if ($mode === '--plan-from') {
    $snap = json_decode((string)file_get_contents($args[1] ?? ''), true, 64, JSON_THROW_ON_ERROR);
    $state = isset($args[2]) ? wf_state_load($args[2], (int)$snap['boot_time'])['state'] : wf_state_new((int)$snap['boot_time']);
    echo json_encode(wf_plan($snap, $state)['plan'], JSON_PRETTY_PRINT), "\n";
    exit(0);
}

require_once 'script/load_phalcon.php';
require_once __DIR__ . '/lib/snapshot.php';
require_once __DIR__ . '/lib/apply.php';

if ($mode === 'status') {
    $on = (new \OPNsense\WanFailover\WanFailover())->enabled->isEqual('1');
    echo $on ? "wanfailover is running\n" : "wanfailover is not running\n";
    exit(0);
}
if ($mode === 'start' || $mode === 'stop') {
    (new \OPNsense\Core\Backend())->configdRun('cron restart');
    $mode = $mode === 'stop' ? 'release' : 'evaluate';
}
if ($mode === '--snapshot') {
    $snap = wf_snapshot();
    $snap['pf'] = wf_snapshot_pf(array_map(fn (array $w): string => $w['gateway_ip'], $snap['wans']));
    file_put_contents($args[1] ?? '/tmp/wanfailover.snapshot.json', json_encode($snap, JSON_PRETTY_PRINT) . "\n");
    exit(0);
}
if ($mode === '--dry') {
    $snap = wf_snapshot();
    $state = wf_state_load(WF_STATE, $snap['boot_time'])['state'];
    echo json_encode(['snapshot' => $snap, 'plan' => wf_plan($snap, $state)['plan']], JSON_PRETTY_PRINT), "\n";
    exit(0);
}
if ($mode === 'holds') {
    $snap = wf_snapshot();
    $loaded = wf_state_load(WF_STATE, $snap['boot_time']);
    $s = $loaded['state'];
    $rows = [];
    foreach ($snap['wans'] as $n => $w) {
        $j = $s['judgements'][$n] ?? null;
        $rows[] = ['name' => $n, 'held' => in_array($n, $snap['held'], true), 'force_down' => $w['force_down'],
                   'status' => $w['status'], 'loss' => $w['loss'], 'judgement' => $j['value'] ?? null,
                   'since' => $j['since'] ?? null, 'failback_pending' => isset($s['pending_failbacks'][$n])];
    }
    echo json_encode(['enabled' => $snap['enabled'], 'dry' => $snap['dry'], 'wans' => $rows,
                      'unresolved' => $snap['unresolved'], 'contract' => $snap['contract'],
                      'tailscale' => ['default_gw' => $s['ts']['default_gw'], 'restarted_at' => $s['ts']['restarted_at']],
                      'state_corrupt' => $loaded['corrupt']]), "\n";
    exit(0);
}

if (!is_dir(WF_LOCK_DIR)) {
    mkdir(WF_LOCK_DIR, 0750, true);
}
$lock = fopen(WF_LOCK_DIR . '/evaluate.lock', 'ce');
if ($lock === false || !flock($lock, LOCK_EX | LOCK_NB)) {
    exit(0);
}
if (wf_booting()) {
    exit(0);
}

$snap = wf_snapshot();
$loaded = wf_state_load(WF_STATE, $snap['boot_time']);
if ($loaded['corrupt']) {
    wf_log('state file unreadable; starting from a fresh state', LOG_WARNING);
    $loaded['state']['boot_time'] = -1;
}
$state = $loaded['state'];
$cl = wf_contract_log($snap['contract'], $state['contract_last']);
if ($cl['line'] !== null) {
    wf_log($cl['line'], $cl['prio']);
}
$state['contract_last'] = $cl['last'];
$wanGwIp = array_map(fn (array $w): string => $w['gateway_ip'], $snap['wans']);

if ($mode === 'release') {
    $snap['enabled'] = false;
}
if (!$snap['enabled']) {
    $snap['tailscale_restart'] = false;
}

$r = wf_plan($snap, $state);
$plan = $r['plan'];
$state = $r['state'];
foreach (array_merge($plan['log'], $plan['alerts']) as $line) {
    wf_log(($snap['dry'] && $snap['enabled'] ? '[dry] ' : '') . $line);
}

if ($snap['dry'] && $snap['enabled']) {
    foreach ($plan['failback'] as $n => $fb) {
        $pf = wf_snapshot_pf($wanGwIp);
        $g = wf_failback_gate($n, $pf['flows'], $pf['rule_pref'], $pf['renderings'], $wanGwIp, $pf['default'], $fb['top'], $pf['pinned']);
        wf_log(sprintf('[dry] failback %s would kill %d states, spare %d flows%s', $n, count($g['kills']), $g['spared'],
            $g['ready'] ? '' : ' (not ready)'));
        unset($state['pending_failbacks'][$n]);
    }
    $d = wf_tailscale_decide(array_merge($state['ts'], ['expected_default' => $plan['expected_default'] ?? $state['ts']['expected_default']]),
        wf_live_default(), $snap['now'], WF_TS_STABLE_SECONDS, WF_TS_COOLDOWN_SECONDS);
    $state['ts'] = $d['ts'];
    if ($d['restart']) {
        wf_log('[dry] would restart tailscaled: default now ' . $d['ts']['default_gw']);
    }
    $state['last_held'] = $snap['held'];
    wf_state_save(WF_STATE, $state);
} else {
    $state = wf_apply($plan, $state, $snap, wf_live_io(WF_STATE, $wanGwIp, $snap['uuid_by_name']))['state'];
}

if ($plan['hold'] !== [] || $plan['release'] !== [] || $plan['alerts'] !== [] || $cl['line'] !== null) {
    wf_event(WF_EVENT, ['time' => date('c'), 'dry' => $snap['dry'], 'hold' => $plan['hold'], 'release' => $plan['release'],
                        'alerts' => array_merge($plan['alerts'], $cl['line'] !== null ? [$cl['line']] : [])]);
}
if ($snap['enabled'] && $snap['now'] - (int)($state['installed_at'] ?? $snap['now']) < WF_TRACE_DAYS * 86400) {
    $record = ['snap' => $snap, 'plan' => $plan, 'judgements' => $state['judgements']];
    if ($plan['acting']) {
        $pf = wf_snapshot_pf($wanGwIp);
        $record['pf'] = ['raw_states' => $pf['raw_states'], 'raw_rules' => $pf['raw_rules'], 'default' => $pf['default']];
    }
    wf_trace(WF_TRACE, $record);
}
exit(0);
