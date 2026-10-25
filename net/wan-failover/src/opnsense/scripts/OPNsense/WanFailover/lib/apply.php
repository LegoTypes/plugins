<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Apply a plan in the order of spec 2026-10-05 section 3.7, through injected I/O so order and failure
 * handling are testable. wf_live_io() binds the real I/O: configd for every reconfigure, kill and restart
 * (never exec of an rc script), close-on-exec locks, and wf_write_holds() -- the evaluation's config writer, which
 * saves force_down and exactly the plan's hold records together without a config backup (the owner's decision), and
 * writes nothing when a changed gateway's force_down moved since the snapshot the plan decided on. The one other
 * writer imports 1.3_1's held list when an upgrade's migration has not (wf_holds_import_legacy()); the migration
 * shares its import (wf_holds_import_into()). While the package removal's marker exists, neither writes, except the
 * removal's own write. wf_deinstall_io() is the removal's I/O: wf_live_io()'s, re-syncing routing through core's
 * commands only (wf_core_command()), since the plugin's own configd actions go with the package. wf_live_io()'s
 * closures and wf_write_holds() call snapshot.php functions; evaluate.php loads snapshot.php first. They are not
 * required here so the pure tests can load this file without OPNsense's includes.
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/failback.php';
require_once __DIR__ . '/parsers.php';
require_once __DIR__ . '/tailscale.php';
require_once __DIR__ . '/state.php';
require_once __DIR__ . '/log.php';

/**
 * @param array{hold: list<string>, release: list<string>, held_after: list<string>,
 *               records_after: array<string, array{boot: string, since: int}>, expected: array<string, bool>,
 *               held_now: list<string>, write: bool,
 *               redo_apply: list<string>, redo_replay: list<string>, foreign: list<string>, kill_targets: list<string>,
 *               failback: array<string, array{top: bool}>, expected_default: ?string, alerts: list<string>, log: list<string>,
 *               acting: bool, stopped: bool} $plan wf_plan()
 * @param array $state the shape returned by wf_state_new()
 * @param array{now: int, tailscale_restart: bool, wans: array<string, array{route_target: string}>} $snap
 * @param array{configd: callable(string, list<string>): string,
 *             write: callable(array<string, bool>, array<string, bool>, array<string, array{boot: string, since: int}>, bool=): array{ok: bool, skipped: list<string>},
 *             gw_lock: callable(): bool, gw_unlock: callable(): void, status: callable(): array<string, string>,
 *             pf: callable(): array, live_default: callable(): ?string, save_state: callable(array): void,
 *             sleep: callable(int): int, log: callable(string, int=): void, crash_point: callable(string): void} $io
 * @return array{state: array, ok: bool}
 */
function wf_apply(array $plan, array $state, array $snap, array $io): array
{
    $log = $io['log'];
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
            $log('gateway lock busy for 30 s; the change waits for the next tick');
            return ['state' => $state, 'ok' => false];
        }
        $written = ['ok' => true, 'skipped' => []];
        try {
            if ($plan['write']) {
                $written = ($io['write'])($changes, $plan['expected'], $plan['records_after']);
                ($io['crash_point'])('after-save');
            }
            /* a write that only prunes the held list changes no gateway: no reconfigure, no dpinger restarts */
            if ($written['ok'] && ($changes !== [] || $plan['foreign'] !== [])) {
                ($io['configd'])('interface routes configure', []);
            }
        } finally {
            ($io['gw_unlock'])();
        }
        /* the next tick plans again from the config as it now is */
        if ($written['skipped'] !== []) {
            $log('force_down on ' . implode(',', $written['skipped']) . ' changed since the snapshot; write skipped');
            return ['state' => $state, 'ok' => false];
        }
        if (!$written['ok']) {
            $log('config write failed; the change waits for the next tick');
            return ['state' => $state, 'ok' => false];
        }
        $after = ($io['status'])();
        $changedDuringHold = [];
        foreach ($after as $n => $st) {
            if (($before[$n] ?? null) !== $st) {
                $changedDuringHold[] = $n;
            }
        }
        $replay = array_values(array_unique(array_merge($replay, array_keys($changes), $plan['foreign'], $changedDuringHold)));
        $state['last_held'] = $plan['write'] ? $plan['held_after'] : $plan['held_now'];
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
            $log('alarm replay failed for ' . implode(',', $replay) . '; resuming next tick');
        }
    }
    if ($replayOk) {
        /* a kill that did not run in full is a warning; the hold stands either way */
        foreach ($plan['kill_targets'] as $target) {
            $out = trim(($io['configd'])('wanfailover kill_states', [$target]));
            $log("kill states via {$target}: {$out}", preg_match('/^killed \d+ states \(0 failed\)\z/', $out) === 1 ? LOG_NOTICE : LOG_WARNING);
        }
        $state['apply_pending'] = [];
    }

    $wanTargets = array_map(fn (array $w): string => $w['route_target'], $snap['wans']);
    foreach ($plan['failback'] as $n => $fb) {
        $before = ($io['status'])();
        if (!($io['gw_lock'])()) {
            $log("failback {$n}: gateway lock busy; still pending");
            continue;
        }
        ($io['gw_unlock'])();
        $pf = ($io['pf'])();
        if (!$pf['selfcheck']) {
            $log("failback {$n}: pf state format did not parse (core contract); failback suspended");
            continue;
        }
        $g = wf_failback_gate($n, $pf['flows'], $pf['rule_pref'], $pf['renderings'], $wanTargets, $pf['default'], $fb['top'], $pf['pinned']);
        if (!$g['ready']) {
            $extra = array_keys(array_diff_assoc(($io['status'])(), $before));
            ($io['configd'])('wanfailover replay_alarm', [implode(',', $plain(array_values(array_unique(array_merge([$n], $extra)))))]);
            $pf = ($io['pf'])();
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
    return ['state' => $state, 'ok' => true];
}

/** Whether the package removal's marker exists (+PRE_DEINSTALL.pre writes it; +POST_INSTALL.pre deletes it). */
function wf_removing(): bool
{
    clearstatcache(true, WF_REMOVING);
    return is_file(WF_REMOVING);
}

/**
 * The one config writer: force_down on the changed gateways and the plugin's hold records, in one locked save without
 * a config backup. An evaluation calls it under core's gateway lock; Config::lock() comes next, and both models are
 * built after it, so they read the config as it is now. Each changed gateway's force_down there is compared with the
 * value the plan decided on (wf_write_guard()): when one moved under it (a settings save, a restored config), nothing
 * is written and those gateways come back as skipped. Otherwise the hold records become exactly the plan's records
 * after the write (wf_holds_rows()), every other row removed, so a record the plan proved is never left behind for one
 * it did not. It never throws: a failure is logged and the change waits for the next tick. A write that only releases
 * skips model validation, so a gateway field that fails validation (after a firmware update tightened a rule, say) can
 * never pin a hold; the plugin itself only touches force_down and its hold records. While the package removal's marker
 * exists, only the removal's own write lands: the marker is read once Config::lock() is held, and the removal writes it
 * before anything else, so an evaluation that was waiting for the lock cannot re-take a hold the removal releases.
 *
 * @param array<string, bool> $changes gateway name => force_down
 * @param array<string, bool> $expected gateway name => the force_down the snapshot read, for each changed gateway
 * @param array<string, array{boot: string, since: int}> $recordsAfter every hold record after the write, by gateway name
 * @param bool $removal true for the package removal's own write, the one write the removal's marker lets through
 * @return array{ok: bool, skipped: list<string>} skipped: the changed gateways whose force_down moved, when ok is false
 */
function wf_write_holds(array $changes, array $expected, array $recordsAfter, bool $removal = false): array
{
    $releaseOnly = !in_array(true, $changes, true);
    try {
        $cfg = \OPNsense\Core\Config::getInstance();
        $cfg->lock();
        try {
            if (!$removal && wf_removing()) {
                wf_log('config write: the package is being removed; nothing written');
                return ['ok' => false, 'skipped' => []];
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
                return ['ok' => false, 'skipped' => $skipped];
            }
            $rows = wf_holds_rows($recordsAfter, $uuidByName);
            if ($rows['missing'] !== []) {
                wf_log('config write: the hold record for ' . implode(',', $rows['missing'])
                    . ' names a gateway the config no longer has; nothing written', LOG_WARNING);
                return ['ok' => false, 'skipped' => []];
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
            $cfg->save(null, false);
            return ['ok' => true, 'skipped' => []];
        } finally {
            $cfg->unlock();
        }
    } catch (\Throwable $e) {
        wf_log('config write failed: ' . $e->getMessage(), LOG_ERR);
        return ['ok' => false, 'skipped' => []];
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

/** Whether 1.3_1's held list is still in the config, read from the raw config: the settings model no longer has it. */
function wf_holds_legacy_present(): bool
{
    return isset(\OPNsense\Core\Config::getInstance()->object()->OPNsense->WanFailover->held);
}

/**
 * 1.3_1's held list added to $holds as hold records, as wf_legacy_import_plan() decides, against the gateways in the
 * config as it now is. It changes the model only. The caller saves it, and only then removes the raw list
 * (wf_holds_drop_legacy()), so a save that fails leaves the list for the next try. The migration runs this on the model
 * core hands it, which core then saves; an evaluation runs it under its own locks (wf_holds_import_legacy()).
 *
 * @return ?list<array{0: int, 1: string}> the lines to log once saved (priority, text), or null when there is no list
 */
function wf_holds_import_into(\OPNsense\WanFailover\Holds $holds, string $bootId, int $now): ?array
{
    $root = \OPNsense\Core\Config::getInstance()->object();
    $csv = isset($root->OPNsense->WanFailover->held) ? (string)$root->OPNsense->WanFailover->held : null;
    $nameByUuid = [];
    if ($csv !== null) {
        foreach ((new \OPNsense\Routing\Gateways())->gateway_item->iterateItems() as $uuid => $gw) {
            $nameByUuid[(string)$uuid] = $gw->name->getValue();
        }
    }
    $plan = wf_legacy_import_plan($csv, $nameByUuid, $bootId, $now);
    if (!$plan['import']) {
        return null;
    }
    foreach ($plan['records'] as $r) {
        $holds->hold->Add()->setNodes(['gateway' => $r['gateway'], 'boot' => $r['boot'], 'since' => (string)$r['since']]);
    }
    return $plan['lines'];
}

/**
 * One run of an import (wf_holds_import_into() bound to its model), for the migration: imported only when the import
 * returned its lines. One that found no list, or threw part way through, is not, and the caller then keeps the raw
 * list for the next evaluation to import.
 *
 * @param callable(): ?list<array{0: int, 1: string}> $import
 * @return array{imported: bool, lines: list<array{0: int, 1: string}>, error: ?string}
 */
function wf_import_attempt(callable $import): array
{
    try {
        $lines = $import();
    } catch (\Throwable $e) {
        return ['imported' => false, 'lines' => [], 'error' => $e->getMessage()];
    }
    return ['imported' => $lines !== null, 'lines' => $lines ?? [], 'error' => null];
}

/** 1.3_1's held list removed from the raw config, so the settings model's next save cannot bring it back; the caller saves. */
function wf_holds_drop_legacy(): void
{
    unset(\OPNsense\Core\Config::getInstance()->object()->OPNsense->WanFailover->held);
}

/**
 * An evaluation's import of 1.3_1's held list, when the upgrade's migration has not run yet or failed: the gateway
 * lock, then Config::lock() (which reloads the config), the models built after it, the records added, the raw list
 * removed, one save without a backup, then the unlocks. It never throws: a failure is logged and the list stays for
 * the next evaluation. A package removal under way imports nothing: the marker is read once Config::lock() is held.
 *
 * @return string imported, none (no list once locked), removing (the removal's marker exists) or failed
 */
function wf_holds_import_legacy(string $bootId): string
{
    $gw = wf_gateway_lock();
    if ($gw === null) {
        wf_log('held list import: gateway lock busy for 30 s; the list waits for the next evaluation', LOG_WARNING);
        return 'failed';
    }
    try {
        $cfg = \OPNsense\Core\Config::getInstance();
        $cfg->lock();
        try {
            if (wf_removing()) {
                wf_log('held list import: the package is being removed; nothing imported');
                return 'removing';
            }
            $holds = new \OPNsense\WanFailover\Holds();
            $lines = wf_holds_import_into($holds, $bootId, time());
            if ($lines === null) {
                return 'none';
            }
            $holds->serializeToConfig();
            wf_holds_drop_legacy();
            $cfg->save(null, false);
        } finally {
            $cfg->unlock();
        }
    } catch (\Throwable $e) {
        wf_log('held list import failed: ' . $e->getMessage() . '; the list waits for the next evaluation', LOG_ERR);
        return 'failed';
    } finally {
        wf_gateway_unlock($gw);
    }
    wf_log("held list import: 1.3_1's held list was still in the config, as the upgrade's migration had not run; imported");
    foreach ($lines as [$priority, $line]) {
        wf_log("held list import: {$line}", $priority);
    }
    return 'imported';
}

/**
 * @param array<string, string> $wanTargets WAN name => route target
 * @return array{configd: callable(string, list<string>): string,
 *                 write: callable(array<string, bool>, array<string, bool>, array<string, array{boot: string, since: int}>, bool=): array{ok: bool, skipped: list<string>},
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
 * @return string configd, direct, or failed when core's command exited non-zero too
 */
function wf_core_command(string $action, string $direct, callable $run): string
{
    $ctl = '/usr/bin/timeout ' . WF_CONFIGD_TIMEOUT_SECONDS . ' /usr/local/sbin/configctl ' . $action
        . ' 2> /dev/null | /usr/bin/grep -qx OK';
    if ($run($ctl) === 0) {
        return 'configd';
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
 * The package removal's I/O: $io (wf_live_io()'s) with its write made the removal's own, which the removal's marker
 * lets through, its crash points inert, and its configd replaced, since the plugin's own configd actions go with the
 * package. Core's routing reconfigure runs through core's configd action, else core's own command (wf_core_command());
 * the alarm replay runs the command the plugin's [replay_alarm] action wraps (WF_REPLAY_ALARM_CMD), directly, with
 * the names as its one argument; any other action is refused with one line and never run. Every line apply logs
 * through it starts "deinstall: ".
 *
 * @param array $io the shape returned by wf_live_io()
 * @param callable(string): int $run runs a shell command line and returns its exit status (wf_core_shell())
 * @return array the same shape, as wf_apply() takes it
 */
function wf_deinstall_io(array $io, callable $run): array
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
    $io['configd'] = function (string $action, array $params) use ($run, $log): string {
        if ($action === 'interface routes configure' && $params === []) {
            $path = wf_core_command($action, WF_CORE_ROUTES_CONFIGURE, $run);
            if ($path === 'configd') {
                $log('routing reconfigured through configd');
            } elseif ($path === 'direct') {
                $log('configd did not answer OK, so core\'s ' . WF_CORE_ROUTES_CONFIGURE . ' ran directly', LOG_WARNING);
            } else {
                $log('routing reconfigure failed: configd did not answer OK, and core\'s ' . WF_CORE_ROUTES_CONFIGURE
                    . ' exited non-zero', LOG_ERR);
            }
            return $path === 'failed' ? 'failed' : 'OK';
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
