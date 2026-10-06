<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Apply a plan in the order of spec 2026-10-05 section 3.7, through injected I/O so order and failure
 * handling are testable. wf_live_io() binds the real I/O: configd for every reconfigure, kill and restart
 * (never exec of an rc script), close-on-exec locks, and wf_write_holds() -- the one config writer, which
 * saves force_down and the held list together without a config backup (user decision, R3-11).
 * wf_live_io()'s closures call snapshot.php functions; evaluate.php loads snapshot.php first. They are not
 * required here so the pure tests can load this file without OPNsense's includes.
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/failback.php';
require_once __DIR__ . '/tailscale.php';
require_once __DIR__ . '/state.php';
require_once __DIR__ . '/log.php';

/**
 * @param array{hold: list<string>, release: list<string>, held_after: list<string>, held_now: list<string>, write: bool,
 *               redo_apply: list<string>, redo_replay: list<string>, foreign: list<string>, kill_gateways: list<string>,
 *               failback: array<string, array{top: bool}>, expected_default: ?string, alerts: list<string>, log: list<string>,
 *               acting: bool, stopped: bool} $plan wf_plan()
 * @param array $state the shape returned by wf_state_new()
 * @param array{now: int, tailscale_restart: bool, wans: array<string, array{route_target: string}>} $snap
 * @param array{configd: callable(string, list<string>): string, write: callable(array<string, bool>, list<string>): bool,
 *             gw_lock: callable(): bool, gw_unlock: callable(): void, status: callable(): array<string, string>,
 *             pf: callable(): array, live_default: callable(): ?string, save_state: callable(array): void,
 *             sleep: callable(int): int, log: callable(string): void, crash_point: callable(string): void} $io
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
        foreach ($plan['kill_gateways'] as $gw) {
            $log("kill states via {$gw}: " . trim(($io['configd'])('filter kill gateway_states', [$gw])));
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
            ($io['configd'])('wanfailover replay_alarm', [implode(',', array_values(array_unique(array_merge([$n], $extra))))]);
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
 * The one config writer: force_down on the changed gateways and the plugin's held list, in one locked
 * save without a config backup. It never throws: a failure is logged and the change waits for the next
 * tick. A write that only releases skips model validation, so a gateway field that fails validation
 * (after a firmware update tightened a rule, say) can never pin a hold; the plugin itself only touches
 * force_down and its held list.
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
            $mdl = new \OPNsense\WanFailover\WanFailover();
            $mdl->held = implode(',', $heldAfterUuids);
            $gateways->serializeToConfig(false, $releaseOnly);
            $mdl->serializeToConfig(false, $releaseOnly);
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
 * @param array<string, string> $wanTargets WAN name => route target
 * @param array<string, string> $uuidByName gateway name => UUID
 * @return array{configd: callable(string, list<string>): string, write: callable(array<string, bool>, list<string>): bool,
 *                 gw_lock: callable(): bool, gw_unlock: callable(): void, status: callable(): array<string, string>,
 *                 pf: callable(): array, live_default: callable(): ?string, save_state: callable(array): void,
 *                 sleep: callable(int): int, log: callable(string): void, crash_point: callable(string): void}
 */
function wf_live_io(string $statePath, array $wanTargets, array $uuidByName): array
{
    $lock = null;
    return [
        'configd' => fn (string $a, array $p): string => (string)(new \OPNsense\Core\Backend())->configdpRun($a, $p),
        'write' => fn (array $c, array $heldAfter): bool => wf_write_holds($c,
            array_values(array_filter(array_map(fn (string $n): string => $uuidByName[$n] ?? '', $heldAfter)))),
        'gw_lock' => function () use (&$lock): bool {
            $lock = fopen('/tmp/filter_reload_gateway.lock', 'ce');
            if ($lock === false) {
                return false;
            }
            for ($i = 0; $i < 30; $i++) {
                if (flock($lock, LOCK_EX | LOCK_NB)) {
                    return true;
                }
                sleep(1);
            }
            fclose($lock);
            $lock = null;
            return false;
        },
        'gw_unlock' => function () use (&$lock): void {
            if (is_resource($lock)) {
                flock($lock, LOCK_UN);
                fclose($lock);
            }
            $lock = null;
        },
        'status' => fn (): array => array_map(fn (array $s): string => (string)$s['status'], dpinger_status()),
        'pf' => fn (): array => wf_snapshot_pf($wanTargets),
        'live_default' => fn (): ?string => wf_live_default(),
        'save_state' => function (array $s) use ($statePath): void {
            wf_state_save($statePath, $s);
        },
        'sleep' => fn (int $s): int => sleep($s),
        'log' => function (string $m): void {
            wf_log($m);
        },
        'crash_point' => function (string $p): void {
            if (getenv('WF_TEST_CRASH_AT') === $p) {
                wf_log("test crash at {$p}", LOG_WARNING);
                exit(70);
            }
        },
    ];
}
