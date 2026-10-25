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
 * saves force_down and the hold records together without a config backup (the owner's decision). The one other
 * writer imports 1.3_1's held list when an upgrade's migration has not (wf_holds_import_legacy()); the migration
 * shares its import (wf_holds_import_into()). wf_live_io()'s closures and wf_write_holds() call snapshot.php
 * functions; evaluate.php loads snapshot.php first. They are not required here so the pure tests can load this file
 * without OPNsense's includes.
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/failback.php';
require_once __DIR__ . '/parsers.php';
require_once __DIR__ . '/tailscale.php';
require_once __DIR__ . '/state.php';
require_once __DIR__ . '/log.php';

/**
 * @param array{hold: list<string>, release: list<string>, held_after: list<string>, held_now: list<string>, write: bool,
 *               redo_apply: list<string>, redo_replay: list<string>, foreign: list<string>, kill_targets: list<string>,
 *               failback: array<string, array{top: bool}>, expected_default: ?string, alerts: list<string>, log: list<string>,
 *               acting: bool, stopped: bool} $plan wf_plan()
 * @param array $state the shape returned by wf_state_new()
 * @param array{now: int, tailscale_restart: bool, wans: array<string, array{route_target: string}>} $snap
 * @param array{configd: callable(string, list<string>): string, write: callable(array<string, bool>, list<string>): bool,
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
        $written = true;
        try {
            if ($plan['write']) {
                $written = ($io['write'])($changes, $plan['held_after']);
                ($io['crash_point'])('after-save');
            }
            /* a write that only prunes the held list changes no gateway: no reconfigure, no dpinger restarts */
            if ($written && ($changes !== [] || $plan['foreign'] !== [])) {
                ($io['configd'])('interface routes configure', []);
            }
        } finally {
            ($io['gw_unlock'])();
        }
        if (!$written) {
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

/**
 * The one config writer: force_down on the changed gateways and the plugin's hold records, in one locked
 * save without a config backup. A gateway held after the write keeps its record; one held anew gets a record
 * stamped with this boot and now; every other record goes. It never throws: a failure is logged and the change
 * waits for the next tick. A write that only releases skips model validation, so a gateway field that fails
 * validation (after a firmware update tightened a rule, say) can never pin a hold; the plugin itself only
 * touches force_down and its hold records.
 *
 * @param array<string, bool> $changes gateway name => force_down
 * @param list<string> $heldAfterUuids gateway UUIDs the plugin holds after this write
 */
function wf_write_holds(array $changes, array $heldAfterUuids): bool
{
    $releaseOnly = !in_array(true, $changes, true);
    try {
        $cfg = \OPNsense\Core\Config::getInstance();
        $cfg->lock();
        try {
            $gateways = new \OPNsense\Routing\Gateways();
            $found = 0;
            foreach ($gateways->gateway_item->iterateItems() as $gw) {
                $name = $gw->name->getValue();
                if (array_key_exists($name, $changes)) {
                    $gw->force_down = $changes[$name] ? '1' : '0';
                    $found++;
                }
            }
            if ($found !== count($changes)) {
                wf_log('config write: ' . (count($changes) - $found) . ' gateway(s) to change no longer exist', LOG_WARNING);
                return false;
            }
            $holds = new \OPNsense\WanFailover\Holds();
            $kept = [];
            foreach ($holds->records() as $item => $row) {
                if (in_array($row['gateway'], $heldAfterUuids, true) && !isset($kept[$row['gateway']])) {
                    $kept[$row['gateway']] = true;
                } else {
                    $holds->hold->del($item);
                }
            }
            foreach ($heldAfterUuids as $uuid) {
                if (!isset($kept[$uuid])) {
                    $holds->hold->Add()->setNodes(['gateway' => $uuid, 'boot' => wf_boot_id(), 'since' => (string)time()]);
                    $kept[$uuid] = true;
                }
            }
            $gateways->serializeToConfig(false, $releaseOnly);
            $holds->serializeToConfig(false, $releaseOnly);
            $cfg->save(null, false);
            return true;
        } finally {
            $cfg->unlock();
        }
    } catch (\Throwable $e) {
        wf_log('config write failed: ' . $e->getMessage(), LOG_ERR);
        return false;
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
 * the next evaluation.
 *
 * @return string imported, none (no list once locked) or failed
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
 * @param array<string, string> $uuidByName gateway name => UUID
 * @return array{configd: callable(string, list<string>): string, write: callable(array<string, bool>, list<string>): bool,
 *                 gw_lock: callable(): bool, gw_unlock: callable(): void, status: callable(): array<string, string>,
 *                 pf: callable(): array, live_default: callable(): ?string, save_state: callable(array): void,
 *                 sleep: callable(int): int, log: callable(string, int=): void, crash_point: callable(string): void}
 */
function wf_live_io(string $statePath, array $wanTargets, array $uuidByName): array
{
    $lock = null;
    return [
        'configd' => fn (string $a, array $p): string => (string)(new \OPNsense\Core\Backend())->configdpRun($a, $p),
        'write' => fn (array $c, array $heldAfter): bool => wf_write_holds($c,
            array_values(array_filter(array_map(fn (string $n): string => $uuidByName[$n] ?? '', $heldAfter)))),
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
