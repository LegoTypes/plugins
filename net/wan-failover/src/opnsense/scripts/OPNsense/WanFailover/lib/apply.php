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
 * @param array $plan  see the Task 9 interface
 * @param array $state the shape returned by wf_state_new()
 * @param array{now: int, tailscale_restart: bool, wans: array<string, array{gateway_ip: string}>} $snap
 * @param array $io    see the Task 11 interface
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
            if ($written) {
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

    $wanGwIp = array_map(fn (array $w): string => $w['gateway_ip'], $snap['wans']);
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
        $g = wf_failback_gate($n, $pf['flows'], $pf['rule_pref'], $pf['renderings'], $wanGwIp, $pf['default'], $fb['top'], $pf['pinned']);
        if (!$g['ready']) {
            $extra = array_keys(array_diff_assoc(($io['status'])(), $before));
            ($io['configd'])('wanfailover replay_alarm', [implode(',', array_values(array_unique(array_merge([$n], $extra))))]);
            $pf = ($io['pf'])();
            $g = wf_failback_gate($n, $pf['flows'], $pf['rule_pref'], $pf['renderings'], $wanGwIp, $pf['default'], $fb['top'], $pf['pinned']);
        }
        foreach ($g['kills'] as $k) {
            ($io['configd'])('filter kill state', [$k['id'], $k['creatorid']]);
        }
        $log(sprintf('failback-kill %s: %d states killed, %d flows spared%s', $n, count($g['kills']), $g['spared'],
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
        } elseif (str_starts_with($d['reason'], 'defer')) {
            $log("tailscale {$d['reason']}");
        }
    }
    ($io['save_state'])($state);
    return ['state' => $state, 'ok' => true];
}

/**
 * The one config writer: force_down on the changed gateways and the plugin's held list, in one locked
 * save without a config backup.
 *
 * @param array<string, bool> $changes gateway name => force_down
 * @param list<string> $heldAfterUuids gateway UUIDs the plugin holds after this write
 */
function wf_write_holds(array $changes, array $heldAfterUuids): bool
{
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
            return false;
        }
        $mdl = new \OPNsense\WanFailover\WanFailover();
        $mdl->held = implode(',', $heldAfterUuids);
        $gateways->serializeToConfig();
        $mdl->serializeToConfig();
        $cfg->save(null, false);
        return true;
    } finally {
        $cfg->unlock();
    }
}

/**
 * @param array<string, string> $wanGwIp WAN name => gateway ip
 * @param array<string, string> $uuidByName gateway name => UUID
 * @return array the Task 11 $io shape
 */
function wf_live_io(string $statePath, array $wanGwIp, array $uuidByName): array
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
        'pf' => fn (): array => wf_snapshot_pf($wanGwIp),
        'live_default' => fn (): ?string => wf_live_default(),
        'save_state' => fn (array $s) => wf_state_save($statePath, $s),
        'sleep' => fn (int $s): int => sleep($s),
        'log' => fn (string $m) => wf_log($m),
        'crash_point' => function (string $p): void {
            if (getenv('WF_TEST_CRASH_AT') === $p) {
                wf_log("test crash at {$p}", LOG_WARNING);
                exit(70);
            }
        },
    ];
}
