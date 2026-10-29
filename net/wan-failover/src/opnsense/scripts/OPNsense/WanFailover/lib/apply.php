<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Apply a plan in the planned order, through injected I/O so order and failure handling are testable. wf_live_io()
 * binds the real I/O: configd for every reconfigure, kill and restart (never exec of an rc script), close-on-exec
 * locks, and the config writer wf_write_holds(); wf_deinstall_io() binds the package removal's. The functions here call
 * snapshot.php, which evaluate.php loads first; it is not required here, so the pure tests can load this file without
 * OPNsense's includes.
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/failback.php';
require_once __DIR__ . '/parsers.php';
require_once __DIR__ . '/tailscale.php';
require_once __DIR__ . '/state.php';
require_once __DIR__ . '/log.php';
require_once __DIR__ . '/planner.php';

/**
 * @param array{hold: list<string>, release: list<string>, held_after: list<string>,
 *               records_after: array<string, array{boot: string, since: int}>, expected: array<string, bool>,
 *               held_now: list<string>, write: bool,
 *               redo_apply: list<string>, redo_replay: list<string>, foreign: list<string>, kill_targets: list<string>,
 *               failback: array<string, array{top: bool}>, expected_default: ?string, alerts: list<string>, log: list<string>,
 *               acting: bool, stopped: bool, legacy_held: list<string>} $plan wf_plan()
 * @param array $state the shape returned by wf_state_new()
 * @param array{now: int, release: ?string, tailscale_restart: bool, wans: array<string, array{route_target: string}>} $snap
 * @param array{configd: callable(string, list<string>): string,
 *             write: callable(array<string, bool>, array<string, bool>, array<string, array{boot: string, since: int}>, bool=): array{ok: bool, skipped: list<string>, problem: ?string, prio: int},
 *             gw_lock: callable(): bool, gw_unlock: callable(): void, status: callable(): array<string, string>,
 *             pf: callable(): array, live_default: callable(): ?string, save_state: callable(array): void,
 *             sleep: callable(int): int, log: callable(string, int=): void, crash_point: callable(string): void} $io
 * @return array{state: array, ok: bool, problem: ?string, prio: int, resynced: bool} problem: why the config change did
 *     not land (the gateway lock busy, a force_down moved since the snapshot, the write refused or failed), and the
 *     priority to log it at, for the caller to log as it goes on; null otherwise. resynced: false when the routing
 *     reconfigure answered "failed" (the removal's core command, wf_deinstall_io()) or the alarm replay failed
 */
function wf_apply(array $plan, array $state, array $snap, array $io): array
{
    $log = $io['log'];
    /* the package removal has no next tick to resume a replay in */
    $removal = $snap['release'] === 'removal';
    $resynced = true;
    $changes = [];
    foreach ($plan['hold'] as $n) {
        $changes[$n] = true;
    }
    foreach ($plan['release'] as $n) {
        $changes[$n] = false;
    }
    $replay = array_values(array_unique(array_merge($plan['redo_apply'], $plan['redo_replay'])));
    /* the names go into one command argument: only plain gateway names may, and a dropped one is said once */
    $skipped = false;
    $plain = function (array $names) use ($log, &$skipped): array {
        $ok = array_values(array_filter($names, fn (string $n): bool => wf_name_ok($n)));
        if (count($ok) !== count($names) && !$skipped) {
            $skipped = true;
            $log('replay skipped for an invalid gateway name');
        }
        return $ok;
    };

    if ($plan['write'] || $plan['foreign'] !== []) {
        foreach ($changes as $n => $down) {
            $state['apply_pending'][$n] = $down ? 'hold' : 'release';
        }
        ($io['save_state'])($state);
        ($io['crash_point'])('after-pending');
        $before = ($io['status'])();
        if (!($io['gw_lock'])()) {
            return ['state' => $state, 'ok' => false, 'problem' => 'gateway lock busy for 30 s', 'prio' => LOG_NOTICE,
                    'resynced' => false];
        }
        $written = ['ok' => true, 'skipped' => [], 'problem' => null, 'prio' => LOG_NOTICE];
        try {
            if ($plan['write']) {
                $written = ($io['write'])($changes, $plan['expected'], $plan['records_after']);
                ($io['crash_point'])('after-save');
            }
            /* a write that only prunes hold records changes no gateway: no reconfigure, no dpinger restarts */
            if ($written['ok'] && ($changes !== [] || $plan['foreign'] !== [])) {
                $resynced = trim(($io['configd'])('interface routes configure', [])) !== 'failed';
            }
        } finally {
            ($io['gw_unlock'])();
        }
        /* the caller plans again from the config as it then is */
        if (!$written['ok']) {
            return ['state' => $state, 'ok' => false, 'problem' => $written['problem'], 'prio' => $written['prio'],
                    'resynced' => false];
        }
        $after = ($io['status'])();
        $changedDuringHold = [];
        foreach ($after as $n => $st) {
            if (($before[$n] ?? null) !== $st) {
                $changedDuringHold[] = $n;
            }
        }
        $replay = array_values(array_unique(array_merge($replay, array_keys($changes), $plan['foreign'], $changedDuringHold)));
        $state['last_held'] = wf_last_held($plan['write'] ? $plan['held_after'] : $plan['held_now'], $state, $plan['legacy_held']);
    }

    $replayOk = true;
    $replay = $plain($replay);
    if ($replay !== []) {
        sort($replay);
        $want = [];
        foreach ($replay as $n) {
            if (isset($changes[$n])) {
                $want[$n] = $changes[$n];
            }
        }
        for ($i = 0; $i < 20 && $want !== []; $i++) {
            $st = ($io['status'])();
            $pending = array_filter($want, fn (bool $down, string $n): bool => isset($st[$n]) && (($st[$n] === 'force_down') !== $down),
                ARRAY_FILTER_USE_BOTH);
            if ($pending === []) {
                break;
            }
            ($io['sleep'])(1);
        }
        $replayOk = trim(($io['configd'])('wanfailover replay_alarm', [implode(',', $replay)])) === 'OK';
        if (!$replayOk) {
            $resynced = false;
            $log('alarm replay failed for ' . implode(',', $replay) . ($removal ? '' : '; resuming next tick'));
        }
    }
    if ($replayOk) {
        /* a kill that did not run in full is a warning; the hold stands either way */
        foreach ($plan['kill_targets'] as $target) {
            $out = trim(($io['configd'])('wanfailover kill_states', [$target]));
            $log("kill states via {$target}: {$out}", wf_kill_answer_clean($out) ? LOG_NOTICE : LOG_WARNING);
        }
        /* what this apply wrote or resumed is finished; a pending apply kept while nothing can be proven (an unreadable
         * kern.boot_id, wf_reconcile()) waits for the boot id */
        foreach (array_merge(array_keys($changes), $plan['redo_apply'], $plan['redo_replay']) as $n) {
            unset($state['apply_pending'][$n]);
        }
    }

    $wanTargets = array_map(fn (array $w): string => $w['route_target'], $snap['wans']);
    foreach ($plan['failback'] as $n => $fb) {
        $before = ($io['status'])();
        if (!($io['gw_lock'])()) {
            $log("failback {$n}: gateway lock busy; still pending");
            continue;
        }
        ($io['gw_unlock'])();
        /* a suspended failback kills nothing and stays pending */
        $pf = ($io['pf'])();
        $suspended = wf_failback_suspended($n, $pf);
        if ($suspended !== null) {
            $log($suspended);
            continue;
        }
        $g = wf_failback_gate($n, $pf['flows'], $pf['rule_pref'], $pf['renderings'], $wanTargets, $pf['default'], $fb['top'], $pf['pinned']);
        if (!$g['ready']) {
            $extra = array_keys(array_diff_assoc(($io['status'])(), $before));
            ($io['configd'])('wanfailover replay_alarm', [implode(',', $plain(array_values(array_unique(array_merge([$n], $extra)))))]);
            $pf = ($io['pf'])();
            $suspended = wf_failback_suspended($n, $pf);
            if ($suspended !== null) {
                $log($suspended);
                continue;
            }
            $g = wf_failback_gate($n, $pf['flows'], $pf['rule_pref'], $pf['renderings'], $wanTargets, $pf['default'], $fb['top'], $pf['pinned']);
        }
        $killed = 0;
        $failed = 0;
        foreach ($g['kills'] as $k) {
            $out = ($io['configd'])('filter kill state', [$k['id'], $k['creatorid']]);
            if (preg_match('/killed (\d+) states?/', $out, $m) === 1) {
                $killed += (int)$m[1];
            } else {
                $failed++;
            }
        }
        $log(sprintf('failback-kill %s: %d states killed%s, %d flows spared%s', $n, $killed,
            $failed > 0 ? " ({$failed} of " . count($g['kills']) . ' kills failed)' : '', $g['spared'],
            $g['ready'] ? '' : '; still pending (stale: ' . implode(',', $g['stale_labels'])
                . ($g['default_ok'] ? '' : '; default not yet moved') . ')'));
        if ($g['ready']) {
            unset($state['pending_failbacks'][$n]);
        }
    }

    if ($snap['tailscale_restart']) {
        if ($plan['expected_default'] !== null) {
            $state['ts']['expected_default'] = $plan['expected_default'];
        }
        $d = wf_tailscale_decide($state['ts'], ($io['live_default'])(), $snap['now'], WF_TS_STABLE_SECONDS, WF_TS_COOLDOWN_SECONDS);
        $state['ts'] = $d['ts'];
        if ($d['restart']) {
            $log("tailscale-restart: default now {$d['ts']['default_gw']}: " . trim(($io['configd'])('tailscale restart', [])));
        }
        $line = wf_once($state['said'], 'ts_defer', str_starts_with($d['reason'], 'defer') ? "tailscale {$d['reason']}" : null);
        if ($line !== null) {
            $log($line);
        }
    }
    ($io['save_state'])($state);
    return ['state' => $state, 'ok' => true, 'problem' => null, 'prio' => LOG_NOTICE, 'resynced' => $resynced];
}

/** Whether the package removal's marker exists (+PRE_DEINSTALL.pre writes it; +POST_INSTALL.pre deletes it). */
function wf_removing(): bool
{
    clearstatcache(true, WF_REMOVING);
    return is_file(WF_REMOVING);
}

/**
 * The config writer: force_down on the changed gateways and exactly the plan's hold records after the write
 * (wf_holds_rows()), every other row removed, in one save without a config backup. The caller holds core's gateway
 * lock; this takes Config::lock() and builds both models after it, so they read the config as it is now. Nothing is
 * written when a changed gateway's force_down moved since the snapshot (wf_write_guard(); those gateways come back as
 * skipped), or, unless this is the removal's own write, when the removal's marker exists, read under Config::lock(). A
 * write that only releases skips model validation, so a gateway field that fails validation can never pin a hold. It
 * never throws and logs nothing: a write that did not land returns why, and the priority, for its caller to log.
 *
 * The read-only guard (throwReadOnly()) protects a GUI session's privileges; this writer runs as root from cron,
 * configd or a syshook, with no session, and the page buttons that lead here call the guard in ServiceController.
 *
 * @param array<string, bool> $changes gateway name => force_down
 * @param array<string, bool> $expected gateway name => the force_down the snapshot read, for each changed gateway
 * @param array<string, array{boot: string, since: int}> $recordsAfter every hold record after the write, by gateway name
 * @param bool $removal true for the package removal's own write, the one write the removal's marker lets through
 * @param bool $dropLegacy true to remove 1.3_1's held list from the raw config in the same save
 * @return array{ok: bool, skipped: list<string>, problem: ?string, prio: int} skipped: the changed gateways whose
 *     force_down moved or that no longer exist (wf_write_guard()); problem: why nothing was written, when ok is false
 */
function wf_write_holds(array $changes, array $expected, array $recordsAfter, bool $removal = false, bool $dropLegacy = false): array
{
    $releaseOnly = !in_array(true, $changes, true);
    $failed = fn (string $problem, int $prio, array $skipped = []): array
        => ['ok' => false, 'skipped' => $skipped, 'problem' => $problem, 'prio' => $prio];
    try {
        $cfg = \OPNsense\Core\Config::getInstance();
        $cfg->lock();
        try {
            if (!$removal && wf_removing()) {
                return $failed('config write skipped: the package is being removed', LOG_NOTICE);
            }
            $gateways = new \OPNsense\Routing\Gateways();
            $items = [];
            $current = [];
            $uuidByName = [];
            foreach ($gateways->gateway_item->iterateItems() as $uuid => $gw) {
                $name = $gw->name->getValue();
                $items[$name] = $gw;
                $current[$name] = $gw->force_down->isEqual('1');
                $uuidByName[$name] = (string)$uuid;
            }
            $skipped = wf_write_guard($changes, $expected, $current);
            if ($skipped !== []) {
                return $failed(wf_write_guard_problem($skipped, $current), LOG_NOTICE, $skipped);
            }
            $rows = wf_holds_rows($recordsAfter, $uuidByName);
            if ($rows['missing'] !== []) {
                return $failed('config write skipped: the hold record for ' . implode(',', $rows['missing'])
                    . ' names a gateway the config no longer has', LOG_WARNING);
            }
            foreach ($changes as $name => $down) {
                $items[$name]->force_down = $down ? '1' : '0';
            }
            $holds = new \OPNsense\WanFailover\Holds();
            foreach (array_keys($holds->records()) as $item) {
                $holds->hold->del($item);
            }
            foreach ($rows['rows'] as $row) {
                $holds->hold->Add()->setNodes(['gateway' => $row['gateway'], 'boot' => $row['boot'], 'since' => (string)$row['since']]);
            }
            $gateways->serializeToConfig(false, $releaseOnly);
            $holds->serializeToConfig(false, $releaseOnly);
            if ($dropLegacy) {
                wf_holds_drop_legacy();
            }
            $cfg->save(null, false);
            return ['ok' => true, 'skipped' => [], 'problem' => null, 'prio' => LOG_NOTICE];
        } finally {
            $cfg->unlock();
        }
    } catch (\Throwable $e) {
        return $failed('config write failed: ' . $e->getMessage(), LOG_ERR);
    }
}

/**
 * Core's gateway lock, the one its routing reconfigure takes, tried each second for 30 s; opened close-on-exec.
 *
 * @return resource|null the lock held, or null when it stayed busy or could not be opened
 */
function wf_gateway_lock(): mixed
{
    $lock = fopen('/tmp/filter_reload_gateway.lock', 'ce');
    if ($lock === false) {
        return null;
    }
    for ($i = 0; $i < 30; $i++) {
        if (flock($lock, LOCK_EX | LOCK_NB)) {
            return $lock;
        }
        sleep(1);
    }
    fclose($lock);
    return null;
}

/**
 * @param resource|null $lock wf_gateway_lock()'s
 */
function wf_gateway_unlock(mixed $lock): void
{
    if (is_resource($lock)) {
        flock($lock, LOCK_UN);
        fclose($lock);
    }
}

/**
 * 1.3_1's held list ($csv, the raw node's text; null when the config has none) added to $holds as hold records, as
 * wf_legacy_import_plan() decides against the gateways configured now and the plugin's own state ($proof). It changes
 * the model only: the caller saves it and only then removes the raw list (wf_holds_drop_legacy()), so a save that
 * fails leaves the list for the next try.
 *
 * @param array{boot: string, held: list<string>} $proof wf_state_proof()
 * @return array{import: bool, lines: list<array{0: int, 1: string}>} import: the list is to be removed once saved;
 *     lines: what to log (priority, text), when imported once saved
 */
function wf_holds_import_into(\OPNsense\WanFailover\Holds $holds, ?string $csv, string $bootId, int $now, array $proof): array
{
    $nameByUuid = [];
    if ($csv !== null) {
        foreach ((new \OPNsense\Routing\Gateways())->gateway_item->iterateItems() as $uuid => $gw) {
            $nameByUuid[(string)$uuid] = $gw->name->getValue();
        }
    }
    $plan = wf_legacy_import_plan($csv, $nameByUuid, $bootId, $now, $proof);
    if ($plan['import']) {
        foreach ($plan['records'] as $r) {
            $holds->hold->Add()->setNodes(['gateway' => $r['gateway'], 'boot' => $r['boot'], 'since' => (string)$r['since']]);
        }
    }
    return ['import' => $plan['import'], 'lines' => $plan['lines']];
}

/**
 * One run of the migration's import of 1.3_1's held list (wf_holds_import_into() bound to its model): imported only
 * when the import decided to import and completed. One that found no list, could not read kern.boot_id, or threw
 * part way through, is not, and the caller then keeps the raw list for the next evaluation to import.
 *
 * @param callable(): array{import: bool, lines: list<array{0: int, 1: string}>} $import
 * @return array{imported: bool, lines: list<array{0: int, 1: string}>, error: ?string}
 */
function wf_legacy_import_attempt(callable $import): array
{
    try {
        $r = $import();
    } catch (\Throwable $e) {
        return ['imported' => false, 'lines' => [], 'error' => $e->getMessage()];
    }
    return ['imported' => $r['import'], 'lines' => $r['lines'], 'error' => null];
}

/** 1.3_1's held list removed from the raw config, so the settings model's next save cannot bring it back; the caller saves. */
function wf_holds_drop_legacy(): void
{
    unset(\OPNsense\Core\Config::getInstance()->object()->OPNsense->WanFailover->held);
}

/**
 * An evaluation's import of 1.3_1's held list, for a config that still carries it: under core's gateway lock and
 * Config::lock(), with the model built after it, the records the plugin's state proves added ($proof), the raw list
 * removed, and one save without a backup. Nothing is imported while the removal's marker exists, read under
 * Config::lock(). It never throws: a failure is logged and the list stays for the next evaluation, whose snapshot
 * names the list's gateways (legacy_held).
 *
 * The read-only guard (throwReadOnly()) protects a GUI session's privileges; this writer runs as root from cron,
 * configd or a syshook, with no session, and the page buttons that lead here call the guard in ServiceController.
 *
 * @param array{boot: string, held: list<string>} $proof wf_state_proof()
 */
function wf_holds_import_legacy(string $bootId, array $proof): void
{
    $gw = wf_gateway_lock();
    if ($gw === null) {
        wf_log('held list import: gateway lock busy for 30 s; the list waits for the next evaluation', LOG_WARNING);
        return;
    }
    try {
        $cfg = \OPNsense\Core\Config::getInstance();
        $cfg->lock();
        try {
            if (wf_removing()) {
                wf_log('held list import: the package is being removed; nothing imported');
                return;
            }
            $holds = new \OPNsense\WanFailover\Holds();
            $r = wf_holds_import_into($holds, wf_holds_legacy_csv(), $bootId, time(), $proof);
            if ($r['import']) {
                $holds->serializeToConfig();
                wf_holds_drop_legacy();
                $cfg->save(null, false);
            }
        } finally {
            $cfg->unlock();
        }
    } catch (\Throwable $e) {
        wf_log('held list import failed: ' . $e->getMessage() . '; the list waits for the next evaluation', LOG_ERR);
        return;
    } finally {
        wf_gateway_unlock($gw);
    }
    if ($r['import']) {
        wf_log("held list import: 1.3_1's held list was still in the config (an upgrade whose migration had not run, or a "
            . "restored backup); each entry is carried over only where this plugin's state proves the hold");
    }
    foreach ($r['lines'] as [$priority, $line]) {
        wf_log("held list import: {$line}", $priority);
    }
}

/**
 * @param array<string, string> $wanTargets WAN name => route target
 * @return array{configd: callable(string, list<string>): string,
 *                 write: callable(array<string, bool>, array<string, bool>, array<string, array{boot: string, since: int}>, bool=): array{ok: bool, skipped: list<string>, problem: ?string, prio: int},
 *                 gw_lock: callable(): bool, gw_unlock: callable(): void, status: callable(): array<string, string>,
 *                 pf: callable(): array, live_default: callable(): ?string, save_state: callable(array): void,
 *                 sleep: callable(int): int, log: callable(string, int=): void, crash_point: callable(string): void}
 */
function wf_live_io(string $statePath, array $wanTargets): array
{
    $lock = null;
    return [
        'configd' => fn (string $a, array $p): string => (string)(new \OPNsense\Core\Backend())->configdpRun($a, $p),
        'write' => fn (array $c, array $expected, array $recordsAfter, bool $removal = false): array
            => wf_write_holds($c, $expected, $recordsAfter, $removal),
        'gw_lock' => function () use (&$lock): bool {
            $lock = wf_gateway_lock();
            return $lock !== null;
        },
        'gw_unlock' => function () use (&$lock): void {
            wf_gateway_unlock($lock);
            $lock = null;
        },
        'status' => fn (): array => array_map(fn (array $s): string => (string)$s['status'], dpinger_status()),
        'pf' => fn (): array => wf_snapshot_pf($wanTargets),
        'live_default' => fn (): ?string => wf_live_default(),
        'save_state' => function (array $s) use ($statePath): void {
            wf_state_save($statePath, $s);
        },
        'sleep' => fn (int $s): int => sleep($s),
        'log' => function (string $m, int $prio = LOG_NOTICE): void {
            wf_log($m, $prio);
        },
        /* the VM's crash tests name the point in a root-only flag file; the point consumes it */
        'crash_point' => function (string $p): void {
            if (wf_crash_due(WF_CRASH_FLAG, $p)) {
                wf_log("test crash at {$p}", LOG_WARNING);
                exit(70);
            }
        },
    ];
}

/**
 * One of core's configd actions, or core's own command for it when configd does not answer, so a configd that is down,
 * hung or failing never leaves routing out of step with the config. configd has run a script action only when it
 * replies OK: configctl also exits 0 on no reply and on an error reply ("Execute error", "Action not found"), so the
 * configctl line exits 0 only on that reply. That line is bounded by WF_CONFIGD_TIMEOUT_SECONDS; core's own command is
 * not, and its output is discarded, so a daemon it starts cannot hold the runner's pipe open.
 *
 * @param string $action the configd action, words as configctl takes them ("interface routes configure")
 * @param string $direct the command core's action runs (a WF_CORE_* constant)
 * @param callable(string): int $run runs a shell command line and returns its exit status (wf_core_shell())
 * @param bool $fallback false when the core contract reports that core's action no longer runs $direct: then $direct
 *     is never run, as it may be a command core no longer uses
 * @return string configd, direct, failed when core's command exited non-zero too, or skipped when configd did not
 *     answer OK and $direct was not run
 */
function wf_core_command(string $action, string $direct, callable $run, bool $fallback = true): string
{
    $ctl = '/usr/bin/timeout ' . WF_CONFIGD_TIMEOUT_SECONDS . ' /usr/local/sbin/configctl ' . $action
        . ' 2> /dev/null | /usr/bin/grep -qx OK';
    if ($run($ctl) === 0) {
        return 'configd';
    }
    if (!$fallback) {
        return 'skipped';
    }
    return $run($direct . ' > /dev/null 2>&1') === 0 ? 'direct' : 'failed';
}

/** The production runner: the command line through sh, as written (its redirections and pipes included); its exit status. */
function wf_core_shell(string $cmdline): int
{
    $out = [];
    $rc = 0;
    exec($cmdline, $out, $rc);
    return $rc;
}

/**
 * The package removal's I/O: $io (wf_live_io()'s) with the removal's own write, which its marker lets through, inert
 * crash points, and a configd of its own, since the plugin's configd actions go with the package. The routing
 * reconfigure runs through wf_core_command(), which does not fall back to core's own command when $fallback is false
 * (one error then names the fix); the alarm replay runs WF_REPLAY_ALARM_CMD directly, the names its one argument; any
 * other action is refused with one line and never run. Every line apply logs through it starts "deinstall: ".
 *
 * @param array $io the shape returned by wf_live_io()
 * @param callable(string): int $run runs a shell command line and returns its exit status (wf_core_shell())
 * @param bool $fallback whether core's own routing command may run when configd does not answer (the snapshot's
 *     contract reports no [routes.configure] drift: wf_contract_routes_fallback())
 * @return array the same shape, as wf_apply() takes it
 */
function wf_deinstall_io(array $io, callable $run, bool $fallback): array
{
    $base = $io;
    $log = function (string $m, int $prio = LOG_NOTICE) use ($base): void {
        ($base['log'])("deinstall: {$m}", $prio);
    };
    $io['log'] = $log;
    /* a removal always runs to its end: nothing would resume one a test crash stopped */
    $io['crash_point'] = function (string $p): void {
    };
    $io['write'] = fn (array $c, array $expected, array $recordsAfter): array => ($base['write'])($c, $expected, $recordsAfter, true);
    $io['configd'] = function (string $action, array $params) use ($run, $log, $fallback): string {
        if ($action === 'interface routes configure' && $params === []) {
            $path = wf_core_command($action, WF_CORE_ROUTES_CONFIGURE, $run, $fallback);
            if ($path === 'configd') {
                $log('routing reconfigured through configd');
            } elseif ($path === 'direct') {
                $log('configd did not answer OK, so core\'s ' . WF_CORE_ROUTES_CONFIGURE . ' ran directly', LOG_WARNING);
            } elseif ($path === 'skipped') {
                $log('routing reconfigure failed: configd did not answer OK, and core\'s [routes.configure] no longer runs '
                    . WF_CORE_ROUTES_CONFIGURE . ', so that was not run either: apply System: Gateways: Configuration to '
                    . 're-sync routing', LOG_ERR);
            } else {
                $log('routing reconfigure failed: configd did not answer OK, and core\'s ' . WF_CORE_ROUTES_CONFIGURE
                    . ' exited non-zero', LOG_ERR);
            }
            return $path === 'failed' || $path === 'skipped' ? 'failed' : 'OK';
        }
        if ($action === 'wanfailover replay_alarm' && count($params) === 1) {
            $rc = $run(WF_REPLAY_ALARM_CMD . ' ' . escapeshellarg($params[0]) . ' > /dev/null 2>&1');
            return $rc === 0 ? 'OK' : "exit {$rc}";
        }
        $log("configd {$action} refused: the plugin's own actions go with the package", LOG_WARNING);
        return 'refused';
    };
    return $io;
}

/**
 * Whether the package removal goes on after a try: done once the release landed; another try while one more,
 * WF_DEINSTALL_RETRY_SECONDS on, still starts within WF_DEINSTALL_WAIT_SECONDS of the removal's start (the wait for
 * an evaluation's lock counts too); else it gives up.
 *
 * @return string done, retry or give_up
 */
function wf_deinstall_retry(int $startedAt, int $now, bool $ok): string
{
    if ($ok) {
        return 'done';
    }
    return $now + WF_DEINSTALL_RETRY_SECONDS - $startedAt <= WF_DEINSTALL_WAIT_SECONDS ? 'retry' : 'give_up';
}

/**
 * The package removal's release, tried until it lands or its time is up (wf_deinstall_retry()). Each try plans a fresh
 * snapshot and state as with the plugin disabled and the cause "package removal" (every hold the plugin proves it took
 * released, every other record pruned, its gateway left as it is) and applies the plan through the removal's I/O. A
 * try that did not land says why once for each new reason; the plan's own lines are logged only when they changed.
 * The last line names what the release left undone, each with the fix, since no plugin is left afterwards to say it:
 * a routing re-sync that did not complete, and any gateway left forced down that the plugin may have held but cannot
 * prove. Giving up leaves one error naming the gateways the plugin still holds and the fix.
 *
 * @param callable(): array{snap: array, loaded: array{state: array, corrupt: bool, problem: ?string}} $read a fresh
 *     snapshot (wf_snapshot()) and the state loaded for its boot id (wf_state_load())
 * @param callable(array): array $ioFor the removal's I/O for a snapshot (wf_deinstall_io())
 * @param callable(): int $clock the time now
 * @param callable(int): void $sleep waits that many seconds
 * @param callable(string, int=): void $log
 * @return bool whether the release landed
 */
function wf_deinstall_run(int $startedAt, callable $read, callable $ioFor, callable $clock, callable $sleep, callable $log): bool
{
    $said = null;
    $retrySaid = null;
    $corruptSaid = false;
    while (true) {
        $r = $read();
        $snap = $r['snap'];
        $loaded = $r['loaded'];
        if ($loaded['corrupt']) {
            if (!$corruptSaid) {
                $log('deinstall: state file unreadable (' . wf_state_problem($loaded) . '); starting from a fresh state', LOG_WARNING);
                $corruptSaid = true;
            }
            $loaded['state']['boot_id'] = 'corrupt';
        }
        $snap['enabled'] = false;
        $snap['tailscale_restart'] = false;
        $snap['release'] = 'removal';
        $p = wf_plan($snap, wf_dry_exit($loaded['state'], $snap));
        $plan = $p['plan'];
        $lines = array_merge($plan['log'], $plan['alerts']);
        if ($lines !== $said) {
            foreach ($lines as $line) {
                $log("deinstall: {$line}");
            }
            $said = $lines;
        }
        $applied = wf_apply($plan, $p['state'], $snap, $ioFor($snap));
        $next = wf_deinstall_retry($startedAt, $clock(), $applied['ok']);
        if ($next === 'done') {
            if ($plan['release'] === []) {
                $log('deinstall: nothing held');
            } elseif ($applied['resynced']) {
                $log('deinstall: released ' . implode(',', $plan['release']));
            } else {
                $log('deinstall: released ' . implode(',', $plan['release']) . ', but the routing re-sync did not complete '
                    . '(see above): apply System: Gateways: Configuration to re-sync routing', LOG_WARNING);
            }
            $left = array_values(array_filter(array_unique(array_merge($plan['unproven'], $plan['legacy_held'])),
                fn (string $n): bool => $snap['force_down'][$n] ?? false));
            if ($left !== []) {
                $one = count($left) === 1;
                $log('deinstall: ' . implode(',', $left) . ($one ? ' stays' : ' stay') . ' forced down: the plugin cannot prove '
                    . 'whether it took ' . ($one ? 'that hold' : 'those holds') . " (kern.boot_id unreadable, or 1.3_1's held "
                    . 'list not yet carried over): untick Force down on each under System: Gateways: Configuration if it should '
                    . 'carry traffic', LOG_ERR);
            }
            return true;
        }
        if ($next === 'give_up') {
            $elapsed = $clock() - $startedAt;
            if ($plan['release'] === []) {
                $log("deinstall: nothing held; the hold records stay in the config after {$elapsed} s ({$applied['problem']})");
            } else {
                $log('deinstall: ' . implode(',', $plan['release']) . " still forced down by the plugin after {$elapsed} s "
                    . "({$applied['problem']}): untick Force down on each under System: Gateways: Configuration", LOG_ERR);
            }
            return false;
        }
        if ($applied['problem'] !== $retrySaid) {
            $log("deinstall: the release did not land ({$applied['problem']}); retrying every " . WF_DEINSTALL_RETRY_SECONDS
                . ' s for up to ' . WF_DEINSTALL_WAIT_SECONDS . ' s', $applied['prio']);
            $retrySaid = $applied['problem'];
        }
        $sleep(WF_DEINSTALL_RETRY_SECONDS);
    }
}
