#!/usr/local/bin/php
<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
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
 *   evaluate.php kill-states TARGET    kill the states routed via TARGET (gateway@interface) by state id; a hold's
 *                                      evaluation calls it through configd while it holds the lock, so it takes none
 *   evaluate.php deinstall             the package removal's release (+PRE_DEINSTALL.pre, not on an upgrade): every
 *                                      hold the plugin took released, routing re-synced through core; always exits 0
 * While the package removal's marker exists, every mode but --plan-from, kill-states, status, holds and deinstall logs
 * that it was skipped and exits 0.
 * Every failure is logged to the plugin's log and exits non-zero; nothing is thrown into configd or core.
 */

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
        $snap += ['release' => null, 'failback_now' => false, 'failback_delay' => 0, 'holds' => [], 'holds_stale' => [],
                  'holds_dupes' => [], 'legacy_held' => []];
        $state = isset($args[2]) ? wf_state_load($args[2], (string)$snap['boot_id'])['state'] : wf_state_new((string)$snap['boot_id']);
        echo json_encode(wf_plan($snap, $state)['plan'], JSON_PRETTY_PRINT), "\n";
        return 0;
    }

    if ($mode === 'kill-states') {
        $r = wf_kill_states_run($args[1] ?? '', function (string $cmd): array {
            $lines = [];
            $rc = 0;
            exec($cmd . ' 2>/dev/null', $lines, $rc);
            return ['out' => implode("\n", $lines), 'rc' => $rc];
        });
        /* a hold logs the answer as its kill line too; a rejected target, which no hold sends, and a listing that failed
         * are logged here as well, so a kill run by hand leaves its failure in the log */
        if ($r['line'] === 'rejected target') {
            wf_log('kill-states: the target is not gateway@interface; nothing killed', LOG_WARNING);
        } elseif (str_starts_with($r['line'], 'listing failed')) {
            wf_log("kill-states {$args[1]}: {$r['line']}; nothing killed", LOG_WARNING);
        }
        echo $r['line'], "\n";
        return $r['rc'];
    }

    if ($mode === 'status') {
        $cron = (string)shell_exec('/usr/bin/crontab -l 2>/dev/null');
        echo str_contains($cron, 'configctl wanfailover evaluate') ? "wanfailover is running\n" : "wanfailover is not running\n";
        return 0;
    }
    if ($mode === 'holds') {
        $snap = wf_snapshot();
        $loaded = wf_state_load(WF_STATE, $snap['boot_id']);
        $s = $loaded['state'];
        /* held only where a record of this boot proves it; foreign counts the records pruned as not the plugin's */
        $owned = wf_reconcile($snap['holds'], $snap['force_down'], [], [], $snap['boot_id'])['owned'];
        $rows = [];
        foreach ($snap['wans'] as $n => $w) {
            $j = $s['judgements'][$n] ?? null;
            $rows[] = ['name' => $n, 'held' => in_array($n, $owned, true), 'simulated' => in_array($n, $s['dry_held'], true),
                       'force_down' => $w['force_down'],
                       'status' => $w['status'], 'loss' => $w['loss'], 'judgement' => $j['value'] ?? null,
                       'since' => $j['since'] ?? null, 'failback_pending' => isset($s['pending_failbacks'][$n]),
                       'failback' => isset($s['pending_failbacks'][$n])
                           ? wf_failback_wait($s['pending_failbacks'][$n], $snap['now'], $snap['failback_delay']) : null];
        }
        echo json_encode(['enabled' => $snap['enabled'], 'dry' => $snap['dry'], 'wans' => $rows,
                          'unresolved' => $snap['unresolved'], 'contract' => $snap['contract'],
                          'tailscale' => ['default_gw' => $s['ts']['default_gw'], 'restarted_at' => $s['ts']['restarted_at']],
                          'state_corrupt' => $loaded['corrupt'], 'foreign' => count($s['foreign_pruned'])]), "\n";
        return 0;
    }
    if ($mode === 'deinstall') {
        return wf_deinstall();
    }
    /* the package is being removed: its own release ran or runs (deinstall), and the alarms its routing re-sync raises
     * queue evaluations that must not re-hold a WAN before pkg removes the files; the modes above read only, or are
     * the removal itself, or (kill-states) are called by an evaluation that holds the lock */
    if (wf_removing()) {
        wf_log("the package is being removed; {$mode} skipped");
        return 0;
    }
    $stopping = $mode === 'stop';
    if ($mode === 'start' || $mode === 'stop') {
        (new \OPNsense\Core\Backend())->configdRun('cron restart');
        $mode = $stopping ? 'release' : 'evaluate';
    }
    if ($mode === '--snapshot') {
        /* no default path: a fixed name in /tmp is one any local user can plant a link at */
        if (($args[1] ?? '') === '') {
            fwrite(STDERR, "usage: evaluate.php --snapshot FILE\n");
            return 1;
        }
        $snap = wf_snapshot();
        $snap['pf'] = wf_snapshot_pf(array_map(fn (array $w): string => $w['route_target'], $snap['wans']));
        file_put_contents($args[1], json_encode($snap, JSON_PRETTY_PRINT) . "\n");
        return 0;
    }
    if ($mode === '--dry') {
        $snap = wf_snapshot();
        $state = wf_state_load(WF_STATE, $snap['boot_id'])['state'];
        echo json_encode(['snapshot' => $snap, 'plan' => wf_plan($snap, $state)['plan']], JSON_PRETTY_PRINT), "\n";
        return 0;
    }

    wf_private_dir(WF_RUN_DIR);
    $lock = wf_lock_open(WF_RUN_DIR . '/evaluate.lock');
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

    /* 1.3_1's held list still in the config: an upgrade whose migration has not run yet (or failed) is imported here,
     * before the snapshot, so a hold the plugin's state proves it took before the upgrade reads as this plugin's and
     * not as a foreign force_down; an entry it does not prove (a restored backup's) is dropped, its gateway left as it
     * is. With kern.boot_id unreadable the list waits, and the snapshot names its gateways (legacy_held) */
    $bootId = wf_boot_id();
    if ($bootId !== '' && wf_holds_legacy_csv() !== null) {
        wf_holds_import_legacy($bootId, wf_state_proof(wf_state_load(WF_STATE, '')));
    }
    $snap = wf_snapshot();
    $loaded = wf_state_load(WF_STATE, $snap['boot_id']);
    if ($loaded['corrupt']) {
        wf_log('state file unreadable (' . wf_state_problem($loaded) . '); starting from a fresh state', LOG_WARNING);
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
    if ($dry && wf_dry_must_release($snap, $state)) {
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
        $applied = wf_apply($plan, $state, $snap, wf_live_io(WF_STATE, $wanTargets));
        $state = $applied['state'];
        /* the next tick plans again from the config as it then is; a removal under way leaves no next tick */
        if ($applied['problem'] !== null) {
            wf_log($applied['problem'] . (wf_removing() ? '' : '; the change waits for the next tick'), $applied['prio']);
        }
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

/**
 * The package removal's release. +PRE_DEINSTALL.pre runs it on a real removal only, after writing the removal's marker,
 * which stops every other evaluation and its writes from then on: the dpinger alarms this re-sync raises queue
 * evaluations that would otherwise re-hold a lossy WAN before pkg removes the files. It waits for an evaluation in
 * flight, then goes on regardless: one already writing holds Config::lock(), and this write builds its models after
 * taking it. The release is tried until it lands, each try from a fresh snapshot (wf_deinstall_run()); the wait and
 * the tries share WF_DEINSTALL_WAIT_SECONDS from the start of this mode. It always returns 0, so pkg delete completes;
 * every failure is logged.
 */
function wf_deinstall(): int
{
    $startedAt = time();
    try {
        wf_private_dir(WF_RUN_DIR);
        $lock = wf_lock_open(WF_RUN_DIR . '/evaluate.lock');
        $locked = $lock !== false && flock($lock, LOCK_EX | LOCK_NB);
        while (!$locked && $lock !== false && time() - $startedAt < WF_DEINSTALL_WAIT_SECONDS) {
            sleep(1);
            $locked = flock($lock, LOCK_EX | LOCK_NB);
        }
        if ($lock === false) {
            wf_log('deinstall: the evaluate lock could not be opened; releasing anyway', LOG_WARNING);
        } elseif (!$locked) {
            wf_log('deinstall: an evaluation kept the lock for ' . WF_DEINSTALL_WAIT_SECONDS . ' s; releasing anyway', LOG_WARNING);
        }
        $read = function (): array {
            $snap = wf_snapshot();
            return ['snap' => $snap, 'loaded' => wf_state_load(WF_STATE, $snap['boot_id'])];
        };
        $ioFor = fn (array $snap): array => wf_deinstall_io(wf_live_io(WF_STATE,
            array_map(fn (array $w): string => $w['route_target'], $snap['wans'])), 'wf_core_shell', $snap['contract']['removal'] === []);
        wf_deinstall_run($startedAt, $read, $ioFor, 'time', function (int $s): void {
            sleep($s);
        }, 'wf_log');
    } catch (Throwable $e) {
        wf_log('deinstall: failed: ' . $e->getMessage() . ' (' . basename($e->getFile()) . ':' . $e->getLine()
            . '); any gateway the plugin held stays forced down: untick its Force down under System: Gateways: Configuration',
            LOG_ERR);
    }
    return 0;
}
