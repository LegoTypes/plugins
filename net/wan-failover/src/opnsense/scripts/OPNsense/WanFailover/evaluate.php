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
 *   evaluate.php status                the running line ApiMutableServiceControllerBase expects: running while
 *                                      the minute job is installed
 *   evaluate.php release               release every held gateway (the page's button); waits for a running
 *                                      evaluation and fails if it cannot
 *   evaluate.php failback-now          end the failback delay for every pending failback, then evaluate; waits for
 *                                      a running evaluation like release
 *   evaluate.php start|stop            regenerate cron (the minute job exists only while enabled), then evaluate | release
 * Every failure is logged to the plugin's log and exits non-zero; nothing is thrown into configd or core.
 */

const WF_STATE = '/var/db/wanfailover/state.json';
const WF_LOCK_DIR = '/var/run/wanfailover';
const WF_EVENT = '/var/run/wanfailover/event';
const WF_TRACE = '/var/log/wanfailover/trace';
const WF_RELEASE_WAIT_SECONDS = 60;

require_once __DIR__ . '/lib/planner.php';
require_once __DIR__ . '/lib/state.php';
require_once __DIR__ . '/lib/log.php';
require_once __DIR__ . '/lib/contract.php';
require_once 'script/load_phalcon.php';
require_once __DIR__ . '/lib/snapshot.php';
require_once __DIR__ . '/lib/apply.php';

$args = array_slice($argv, 1);
try {
    exit(wf_main($args[0] ?? 'evaluate', $args));
} catch (Throwable $e) {
    wf_log('evaluation failed: ' . $e->getMessage() . ' (' . basename($e->getFile()) . ':' . $e->getLine() . ')', LOG_ERR);
    exit(1);
}

/**
 * @param list<string> $args
 */
function wf_main(string $mode, array $args): int
{
    if ($mode === '--plan-from') {
        $snap = json_decode((string)file_get_contents($args[1] ?? ''), true, 64, JSON_THROW_ON_ERROR);
        $snap += ['release' => null, 'failback_now' => false, 'failback_delay' => 0];
        $state = isset($args[2]) ? wf_state_load($args[2], (string)$snap['boot_id'])['state'] : wf_state_new((string)$snap['boot_id']);
        echo json_encode(wf_plan($snap, $state)['plan'], JSON_PRETTY_PRINT), "\n";
        return 0;
    }

    if ($mode === 'status') {
        $cron = (string)shell_exec('/usr/bin/crontab -l 2>/dev/null');
        echo str_contains($cron, 'configctl wanfailover evaluate') ? "wanfailover is running\n" : "wanfailover is not running\n";
        return 0;
    }
    $stopping = $mode === 'stop';
    if ($mode === 'start' || $mode === 'stop') {
        (new \OPNsense\Core\Backend())->configdRun('cron restart');
        $mode = $stopping ? 'release' : 'evaluate';
    }
    if ($mode === '--snapshot') {
        $snap = wf_snapshot();
        $snap['pf'] = wf_snapshot_pf(array_map(fn (array $w): string => $w['route_target'], $snap['wans']));
        file_put_contents($args[1] ?? '/tmp/wanfailover.snapshot.json', json_encode($snap, JSON_PRETTY_PRINT) . "\n");
        return 0;
    }
    if ($mode === '--dry') {
        $snap = wf_snapshot();
        $state = wf_state_load(WF_STATE, $snap['boot_id'])['state'];
        echo json_encode(['snapshot' => $snap, 'plan' => wf_plan($snap, $state)['plan']], JSON_PRETTY_PRINT), "\n";
        return 0;
    }
    if ($mode === 'holds') {
        $snap = wf_snapshot();
        $loaded = wf_state_load(WF_STATE, $snap['boot_id']);
        $s = $loaded['state'];
        $rows = [];
        foreach ($snap['wans'] as $n => $w) {
            $j = $s['judgements'][$n] ?? null;
            $rows[] = ['name' => $n, 'held' => in_array($n, $snap['held'], true), 'simulated' => in_array($n, $s['dry_held'], true),
                       'force_down' => $w['force_down'],
                       'status' => $w['status'], 'loss' => $w['loss'], 'judgement' => $j['value'] ?? null,
                       'since' => $j['since'] ?? null, 'failback_pending' => isset($s['pending_failbacks'][$n]),
                       'failback' => isset($s['pending_failbacks'][$n])
                           ? wf_failback_wait($s['pending_failbacks'][$n], $snap['now'], $snap['failback_delay']) : null];
        }
        echo json_encode(['enabled' => $snap['enabled'], 'dry' => $snap['dry'], 'wans' => $rows,
                          'unresolved' => $snap['unresolved'], 'contract' => $snap['contract'],
                          'tailscale' => ['default_gw' => $s['ts']['default_gw'], 'restarted_at' => $s['ts']['restarted_at']],
                          'state_corrupt' => $loaded['corrupt']]), "\n";
        return 0;
    }

    if (!is_dir(WF_LOCK_DIR)) {
        mkdir(WF_LOCK_DIR, 0750, true);
    }
    $lock = fopen(WF_LOCK_DIR . '/evaluate.lock', 'ce');
    $locked = $lock !== false && flock($lock, LOCK_EX | LOCK_NB);
    /* a release (the page's button, or stop on disable) and fail back now wait for an evaluation in
     * flight instead of silently doing nothing; a routine evaluation just leaves it to the one running */
    $waits = $mode === 'release' || $mode === 'failback-now';
    for ($i = 0; !$locked && $lock !== false && $waits && $i < WF_RELEASE_WAIT_SECONDS; $i++) {
        sleep(1);
        $locked = flock($lock, LOCK_EX | LOCK_NB);
    }
    if (!$locked) {
        if ($waits) {
            wf_log("{$mode}: an evaluation kept the lock for " . WF_RELEASE_WAIT_SECONDS . ' s; nothing done', LOG_WARNING);
            return 1;
        }
        return 0;
    }
    if (wf_booting()) {
        return 0;
    }
    wf_trace_prune(WF_TRACE, time(), WF_TRACE_KEEP_DAYS);

    $snap = wf_snapshot();
    $loaded = wf_state_load(WF_STATE, $snap['boot_id']);
    if ($loaded['corrupt']) {
        wf_log('state file unreadable; starting from a fresh state', LOG_WARNING);
        $loaded['state']['boot_id'] = 'corrupt';
    }
    $state = $loaded['state'];
    $cl = wf_contract_log($snap['contract'], $state['contract_last']);
    if ($cl['line'] !== null) {
        wf_log($cl['line'], $cl['prio']);
    }
    $state['contract_last'] = $cl['last'];
    $wanTargets = array_map(fn (array $w): string => $w['route_target'], $snap['wans']);

    if ($stopping) {
        $snap['enabled'] = false;
    } elseif ($mode === 'release') {
        $snap['release'] = 'requested';
    } elseif ($mode === 'failback-now') {
        $snap['failback_now'] = true;
    }
    if (!$snap['enabled']) {
        $snap['tailscale_restart'] = false;
    }
    /* dry run never keeps a real hold: one it finds (dry was just turned on) is released for real first */
    $dry = $snap['dry'] && $snap['enabled'] && $snap['release'] === null;
    if ($dry && $snap['held'] !== []) {
        $snap['release'] = 'dry';
        $dry = false;
    }

    $r = $dry ? wf_plan(wf_dry_view($snap, $state['dry_held']), $state) : wf_plan($snap, wf_dry_exit($state, $snap));
    $plan = $r['plan'];
    $state = $r['state'];
    foreach (array_merge($plan['log'], $plan['alerts']) as $line) {
        wf_log(($dry ? '[dry] ' : '') . $line);
    }

    if ($dry) {
        foreach ($plan['failback'] as $n => $fb) {
            $pf = wf_snapshot_pf($wanTargets);
            $g = wf_failback_gate($n, $pf['flows'], $pf['rule_pref'], $pf['renderings'], $wanTargets, $pf['default'], $fb['top'], $pf['pinned']);
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
        wf_state_save(WF_STATE, wf_dry_after($state, $plan));
    } else {
        $state = wf_apply($plan, $state, $snap, wf_live_io(WF_STATE, $wanTargets, $snap['uuid_by_name']))['state'];
    }

    if ($plan['hold'] !== [] || $plan['release'] !== [] || $plan['alerts'] !== [] || $cl['line'] !== null) {
        wf_event(WF_EVENT, ['time' => date('c'), 'dry' => $snap['dry'], 'hold' => $plan['hold'], 'release' => $plan['release'],
                            'alerts' => array_merge($plan['alerts'], $cl['line'] !== null ? [$cl['line']] : [])]);
    }
    if ($snap['enabled'] && $snap['now'] - (int)($state['installed_at'] ?? $snap['now']) < WF_TRACE_DAYS * 86400) {
        $record = ['snap' => $snap, 'plan' => $plan, 'judgements' => $state['judgements']];
        if ($plan['acting']) {
            $pf = wf_snapshot_pf($wanTargets);
            $record['pf'] = ['raw_states' => $pf['raw_states'], 'raw_rules' => $pf['raw_rules'], 'default' => $pf['default']];
        }
        wf_trace(WF_TRACE, $record);
    }
    return 0;
}
