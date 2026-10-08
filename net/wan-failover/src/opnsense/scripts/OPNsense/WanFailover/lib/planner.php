<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The planner (spec 2026-10-05). Pure: (snapshot, runtime state) -> plan and new state. Ownership comes
 * from the snapshot's held list (the model); the plan's held_after is what apply writes back, with
 * force_down, in one config save. Failback kills and the Tailscale restart are decided in apply against
 * live data, from the plan's failback and expected_default entries.
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/judge.php';
require_once __DIR__ . '/holds.php';
require_once __DIR__ . '/state.php';

/**
 * @param array $snap  the shape returned by wf_snapshot() (snapshot.php)
 * @param array $state the shape returned by wf_state_new()
 * @return array{plan: array, state: array}
 */
function wf_plan(array $snap, array $state): array
{
    $now = $snap['now'];
    $log = [];
    $alerts = [];

    if ($state['last_now'] !== null && $now < $state['last_now'] - 60) {
        $log[] = sprintf('clock moved back %d s; time-based fields reset', $state['last_now'] - $now);
        foreach ($state['judgements'] as $n => $j) {
            $state['judgements'][$n]['since'] = $now;
            $state['judgements'][$n]['last_settled_at'] = null;
            $state['judgements'][$n]['unknown_since'] = $j['unknown_since'] === null ? null : $now;
        }
        foreach ($state['pending_failbacks'] as $n => $p) {
            $state['pending_failbacks'][$n] = ['since' => $now, 'clean_since' => ($p['clean_since'] ?? null) === null ? null : $now,
                                               'due' => ($p['due'] ?? null) === null ? null : $now];
        }
        $state['ts']['cur_since'] = $state['ts']['cur_since'] === null ? null : $now;
        $state['ts']['restarted_at'] = null;
        $state['unowned_alerted_at'] = [];
    }
    $state['last_now'] = $now;
    $state['installed_at'] = $state['installed_at'] ?? $now;
    foreach ($snap['wans'] as $n => $w) {
        if (filter_var($w['gateway_ip'], FILTER_VALIDATE_IP) !== false) {
            $state['gateway_ips'][$n] = $w['gateway_ip'];
        }
    }
    /* the early hook runs before syslog starts, so it leaves its outcome here */
    if (($state['boot_note'] ?? null) !== null) {
        $log[] = $state['boot_note'];
        $state['boot_note'] = null;
    }

    /* an unreadable boot id (reported as a command drift) proves nothing either way */
    $releaseAll = null;
    if ($snap['boot_id'] !== '' && $state['boot_id'] === '') {
        $state['boot_id'] = $snap['boot_id'];
    } elseif ($snap['boot_id'] !== '' && $state['boot_id'] !== $snap['boot_id']) {
        $state = wf_boot_reset($state, $snap['boot_id']);
        $state['last_now'] = $now;
        $state['last_held'] = $snap['held'];
        $releaseAll = 'boot the early hook did not handle';
    }

    $rec = wf_reconcile($snap['held'], $snap['force_down'], $state['apply_pending'], $state['last_held']);
    $state['apply_pending'] = $rec['apply_pending'];
    $log = array_merge($log, $rec['log']);
    foreach ($rec['manual_released'] as $n) {
        $state['no_rehold'][$n] = true;
    }
    $line = wf_once($state['said'], 'unresolved', $snap['unresolved'] === [] ? null
        : 'wans entries ' . implode(', ', $snap['unresolved']) . ' reference no saved IPv4 gateway; ignored');
    if ($line !== null) {
        $log[] = $line;
    }
    foreach (array_keys($state['judgements']) as $n) {
        if (!isset($snap['wans'][$n])) {
            unset($state['judgements'][$n]);
        }
    }
    foreach (array_keys($state['pending_failbacks']) as $n) {
        if (!isset($snap['wans'][$n])) {
            unset($state['pending_failbacks'][$n]);
            $log[] = "pending failback for {$n} dropped: no longer a configured WAN";
        }
    }

    /* A judging drift counts only once it has persisted: a reconfigure in flight briefly removes dpinger
     * sockets and the default route, and the engine's own holds cause reconfigures. Until then it only
     * blocks new holds, like a command drift. */
    $judgingDrift = $snap['contract']['judging'] !== [];
    if ($judgingDrift) {
        $state['contract_judging_since'] = $state['contract_judging_since'] ?? $now;
    } else {
        $state['contract_judging_since'] = null;
    }
    if (!$snap['enabled']) {
        $releaseAll = 'plugin disabled';
    } elseif ($snap['release'] === 'requested') {
        $releaseAll = 'release requested';
        /* like a manual release: not re-held until the WAN reads clean or marginal */
        foreach ($rec['owned'] as $n) {
            $state['no_rehold'][$n] = true;
        }
    } elseif ($snap['release'] === 'dry') {
        $releaseAll = 'dry run turned on; holds are only simulated from now on';
    } elseif ($judgingDrift && $now - $state['contract_judging_since'] >= WF_UNKNOWN_MAX_SECONDS) {
        $releaseAll = 'core contract broken: WANs cannot be read';
    }

    $owned = $rec['owned'];
    $prune = $rec['manual_released'] !== [] || $snap['held_stale'] !== [];
    $notInWans = array_values(array_diff($owned, array_keys($snap['wans'])));
    if ($releaseAll !== null) {
        if ($owned !== []) {
            $log[] = "releasing every held gateway: {$releaseAll}";
        }
        return wf_plan_result([], $owned, [], $prune, $rec, [], null, $alerts, $log, true, $state, $snap);
    }

    $wans = [];
    foreach ($snap['wans'] as $name => $w) {
        $held = in_array($name, $owned, true);
        $manual = $w['force_down'] && !in_array($name, $snap['held'], true);
        $input = $w + ['manual_down' => $manual];
        $reading = wf_reading($input, WF_DEAD_MIN_SECONDS);
        $settled = wf_settled($input);
        $loss = wf_effective_loss($input);
        $j = wf_judge($state['judgements'][$name] ?? wf_judgement_new($now), $reading, $settled, $loss, $now, WF_UNKNOWN_MAX_SECONDS);
        if ($held) {
            $j['recovering'] = true;
        }
        $state['judgements'][$name] = $j;
        if ($manual) {
            $last = $state['unowned_alerted_at'][$name] ?? null;
            if ($last === null || $now - $last >= 3600) {
                $alerts[] = "unowned-force-down {$name}: force_down is set but not by wan-failover; left alone";
                $state['unowned_alerted_at'][$name] = $now;
            }
        } else {
            unset($state['unowned_alerted_at'][$name]);
        }
        if ($reading === WF_CLEAN || $reading === WF_MARGINAL) {
            unset($state['no_rehold'][$name]);
        }
        $wans[$name] = ['reading' => $reading, 'judgement' => $j, 'held' => $held, 'manual_down' => $manual,
                        'disabled' => $w['disabled'], 'core_down' => $w['status'] === 'down' && $settled,
                        'raw_loss' => $loss, 'losslow' => $w['losslow'], 'rank' => $w['rank'],
                        'no_rehold' => isset($state['no_rehold'][$name])];
    }

    $h = wf_plan_holds($wans, $now, WF_FRESH_SECONDS);
    $log = array_merge($log, $h['log']);
    $hold = $h['hold'];
    $blocked = ($snap['contract']['command'] !== [] || $judgingDrift) && $hold !== [];
    $line = wf_once($state['said'], 'drift_block', $blocked ? 'core contract drift: not starting holds on ' . implode(',', $hold) : null);
    if ($line !== null) {
        $log[] = $line;
    }
    if ($blocked) {
        $hold = [];
    }
    $release = array_values(array_unique(array_merge($h['release'], $notInWans)));
    $heldAfter = array_values(array_unique(array_merge(array_diff($owned, $release), $hold)));

    if (!$snap['failback'] && $state['pending_failbacks'] !== []) {
        $log[] = 'move connections back is off: pending failbacks dropped (' . implode(',', array_keys($state['pending_failbacks'])) . ')';
        $state['pending_failbacks'] = [];
    }
    if ($snap['failback']) {
        foreach ($wans as $n => $w) {
            $j = $state['judgements'][$n];
            if ($j['value'] === WF_CLEAN && $j['recovering'] && wf_usable($w, in_array($n, $heldAfter, true))) {
                $state['pending_failbacks'][$n] = ['since' => $now, 'clean_since' => $now,
                                                   'due' => $snap['failback_delay'] === 0 ? $now : null];
                $state['judgements'][$n]['recovering'] = false;
                $log[] = "failback-pending {$n}" . ($snap['failback_delay'] === 0 ? '' : sprintf(' (after %d min of clean readings)', intdiv($snap['failback_delay'], 60)));
            }
        }
    }
    if ($snap['failback_now']) {
        if ($state['pending_failbacks'] === []) {
            $log[] = 'failback-now: no failback is pending';
        }
        foreach ($state['pending_failbacks'] as $n => $p) {
            if (($p['due'] ?? null) === null) {
                $state['pending_failbacks'][$n]['due'] = $now;
                $log[] = "failback-now: the delay ended for {$n}";
            }
        }
    }
    foreach ($state['pending_failbacks'] as $n => $p) {
        /* a failback queued by 1.1 records only since: it was due at once */
        $p += ['clean_since' => $p['since'], 'due' => $p['since']];
        if (!wf_usable($wans[$n], in_array($n, $heldAfter, true))) {
            unset($state['pending_failbacks'][$n]);
            $log[] = "failback for {$n} dropped: no longer usable";
            continue;
        }
        if ($p['due'] === null) {
            /* the countdown runs only while every reading is clean; anything else restarts it */
            if ($state['judgements'][$n]['value'] !== WF_CLEAN) {
                if ($p['clean_since'] !== null) {
                    $log[] = "failback-delay {$n} restarted: reading {$wans[$n]['reading']}";
                }
                $p['clean_since'] = null;
            } else {
                $p['clean_since'] = $p['clean_since'] ?? $now;
                if ($now - $p['clean_since'] >= $snap['failback_delay']) {
                    $p['due'] = $now;
                    $log[] = "failback-due {$n}: clean for " . intdiv($snap['failback_delay'], 60) . ' min';
                }
            }
        }
        if ($p['due'] !== null && $now - $p['due'] > WF_FAILBACK_MAX_SECONDS) {
            unset($state['pending_failbacks'][$n]);
            $log[] = "failback-expired {$n}";
            continue;
        }
        $state['pending_failbacks'][$n] = $p;
    }
    $failback = [];
    foreach ($state['pending_failbacks'] as $n => $p) {
        if ($p['due'] === null) {
            continue;
        }
        $top = true;
        foreach ($wans as $o => $ow) {
            if ($o !== $n && wf_usable($ow, in_array($o, $heldAfter, true)) && $ow['rank'] < $wans[$n]['rank']) {
                $top = false;
            }
        }
        $failback[$n] = ['top' => $top];
    }

    $expected = null;
    if ($hold !== [] || $release !== []) {
        $best = null;
        foreach ($snap['wans'] as $n => $w) {
            if (in_array($n, $heldAfter, true) || $wans[$n]['manual_down'] || $w['disabled'] || $wans[$n]['core_down']
                || $wans[$n]['reading'] === WF_UNAVAILABLE) {
                continue;
            }
            if ($best === null || $w['rank'] < $snap['wans'][$best]['rank']) {
                $best = $n;
            }
        }
        $expected = $best === null ? null : $snap['wans'][$best]['route_target'];
    }
    return wf_plan_result($hold, $release, $heldAfter, $prune, $rec, $failback, $expected, $alerts, $log, false, $state, $snap);
}

/**
 * Where a pending failback stands, for the status page: moving (due), counting (clean, with the seconds
 * left) or waiting (for a clean reading to start the countdown, which then takes the whole delay).
 *
 * @param array{since: int, clean_since?: ?int, due?: ?int} $p
 * @return array{state: string, left: int}
 */
function wf_failback_wait(array $p, int $now, int $delay): array
{
    $p += ['clean_since' => $p['since'], 'due' => $p['since']];
    if ($p['due'] !== null) {
        return ['state' => 'moving', 'left' => 0];
    }
    if ($p['clean_since'] === null) {
        return ['state' => 'waiting', 'left' => $delay];
    }
    return ['state' => 'counting', 'left' => max(0, $delay - ($now - $p['clean_since']))];
}

/**
 * Dry run simulates ownership: the planner sees the simulated holds as held and force_down, exactly as
 * a live hold would look, so a dry run decides each change once and rehearses hysteresis and failback.
 *
 * @param list<string> $dryHeld the state's simulated holds
 */
function wf_dry_view(array $snap, array $dryHeld): array
{
    $held = array_values(array_filter($dryHeld, fn (string $n): bool => isset($snap['wans'][$n])));
    $snap['held'] = $held;
    $snap['held_stale'] = [];
    foreach ($held as $n) {
        $snap['force_down'][$n] = true;
        $snap['wans'][$n]['force_down'] = true;
        $snap['wans'][$n]['status'] = 'force_down';
    }
    return $snap;
}

/**
 * Record a dry plan as if it had been applied.
 *
 * @param array{held_after: list<string>} $plan
 */
function wf_dry_after(array $state, array $plan): array
{
    $state['dry_held'] = $plan['held_after'];
    $state['last_held'] = $plan['held_after'];
    $state['apply_pending'] = [];
    return $state;
}

/**
 * Leave dry run: drop the simulated holds and take the real held list as the last one written, so the
 * first live plan does not read the difference as a foreign config change.
 *
 * @param array{held: list<string>} $snap the live snapshot
 */
function wf_dry_exit(array $state, array $snap): array
{
    if ($state['dry_held'] !== []) {
        $state['last_held'] = $snap['held'];
        $state['dry_held'] = [];
    }
    return $state;
}

/**
 * @param list<string> $hold
 * @param list<string> $release
 * @param list<string> $heldAfter
 * @param array{redo_apply: list<string>, redo_replay: list<string>, foreign: list<string>} $rec
 * @param array<string, array{top: bool}> $failback
 * @param list<string> $alerts
 * @param list<string> $log
 * @return array{plan: array, state: array}
 */
function wf_plan_result(array $hold, array $release, array $heldAfter, bool $prune, array $rec, array $failback,
                        ?string $expected, array $alerts, array $log, bool $stopped, array $state, array $snap): array
{
    $killGateways = [];
    foreach (array_values(array_unique(array_merge($hold, $rec['redo_apply']))) as $n) {
        if (!isset($snap['wans'][$n])) {
            continue;
        }
        /* a DHCP WAN that lost its link has no address now; its states still route to the last one */
        $gw = filter_var($snap['wans'][$n]['gateway_ip'], FILTER_VALIDATE_IP) !== false
            ? $snap['wans'][$n]['gateway_ip'] : ($state['gateway_ips'][$n] ?? '');
        if ($gw === '') {
            $log[] = "kill states for {$n} skipped: no gateway address known";
            continue;
        }
        $killGateways[] = $gw;
    }
    $write = $hold !== [] || $release !== [] || $prune;
    $plan = ['hold' => $hold, 'release' => $release, 'held_after' => $heldAfter, 'held_now' => $snap['held'], 'write' => $write,
             'redo_apply' => $rec['redo_apply'], 'redo_replay' => $rec['redo_replay'], 'foreign' => $rec['foreign'],
             'kill_gateways' => $killGateways, 'failback' => $failback, 'expected_default' => $expected,
             'alerts' => $alerts, 'log' => $log, 'stopped' => $stopped];
    $plan['acting'] = $write || $rec['redo_apply'] !== [] || $rec['redo_replay'] !== [] || $rec['foreign'] !== [] || $failback !== [];
    return ['plan' => $plan, 'state' => $state];
}
