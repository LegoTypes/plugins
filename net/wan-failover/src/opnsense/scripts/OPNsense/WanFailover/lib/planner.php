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
 * @param array $snap  see the Task 9 interface (built by snapshot.php)
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
        foreach (array_keys($state['pending_failbacks']) as $n) {
            $state['pending_failbacks'][$n]['since'] = $now;
        }
        $state['ts']['cur_since'] = $state['ts']['cur_since'] === null ? null : $now;
        $state['ts']['restarted_at'] = null;
    }
    $state['last_now'] = $now;
    $state['installed_at'] = $state['installed_at'] ?? $now;

    $releaseAll = null;
    if ($state['boot_time'] !== $snap['boot_time']) {
        $state = wf_boot_reset($state, $snap['boot_time']);
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
    foreach ($snap['unresolved'] as $uuid) {
        $log[] = "wans entry {$uuid} references no saved IPv4 gateway; ignored";
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

    if (!$snap['enabled']) {
        $releaseAll = 'plugin disabled';
    } elseif ($snap['contract']['judging'] !== []) {
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
                        'raw_loss' => $loss, 'losslow' => $w['losslow'], 'priority' => $w['priority'],
                        'no_rehold' => isset($state['no_rehold'][$name])];
    }

    $h = wf_plan_holds($wans, $now, WF_FRESH_SECONDS);
    $log = array_merge($log, $h['log']);
    $hold = $h['hold'];
    if ($snap['contract']['command'] !== [] && $hold !== []) {
        $log[] = 'core contract drift: not starting holds on ' . implode(',', $hold);
        $hold = [];
    }
    $release = array_values(array_unique(array_merge($h['release'], $notInWans)));
    $heldAfter = array_values(array_unique(array_merge(array_diff($owned, $release), $hold)));

    if ($snap['failback']) {
        foreach ($wans as $n => $w) {
            $j = $state['judgements'][$n];
            if ($j['value'] === WF_CLEAN && $j['recovering'] && wf_usable($w, in_array($n, $heldAfter, true))) {
                $state['pending_failbacks'][$n] = ['since' => $now];
                $state['judgements'][$n]['recovering'] = false;
                $log[] = "failback-pending {$n}";
            }
        }
    }
    foreach ($state['pending_failbacks'] as $n => $p) {
        if (!wf_usable($wans[$n], in_array($n, $heldAfter, true))) {
            unset($state['pending_failbacks'][$n]);
            $log[] = "failback for {$n} dropped: no longer usable";
        } elseif ($now - $p['since'] > WF_FAILBACK_MAX_SECONDS) {
            unset($state['pending_failbacks'][$n]);
            $log[] = "failback-expired {$n}";
        }
    }
    $failback = [];
    foreach (array_keys($state['pending_failbacks']) as $n) {
        $top = true;
        foreach ($wans as $o => $ow) {
            if ($o !== $n && wf_usable($ow, in_array($o, $heldAfter, true)) && $ow['priority'] < $wans[$n]['priority']) {
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
            if ($best === null || $w['priority'] < $snap['wans'][$best]['priority']) {
                $best = $n;
            }
        }
        $expected = $best === null ? null : $snap['wans'][$best]['gateway_ip'];
    }
    return wf_plan_result($hold, $release, $heldAfter, $prune, $rec, $failback, $expected, $alerts, $log, false, $state, $snap);
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
        if (isset($snap['wans'][$n])) {
            $killGateways[] = $snap['wans'][$n]['gateway_ip'];
        }
    }
    $write = $hold !== [] || $release !== [] || $prune;
    $plan = ['hold' => $hold, 'release' => $release, 'held_after' => $heldAfter, 'held_now' => $snap['held'], 'write' => $write,
             'redo_apply' => $rec['redo_apply'], 'redo_replay' => $rec['redo_replay'], 'foreign' => $rec['foreign'],
             'kill_gateways' => $killGateways, 'failback' => $failback, 'expected_default' => $expected,
             'alerts' => $alerts, 'log' => $log, 'stopped' => $stopped];
    $plan['acting'] = $write || $rec['redo_apply'] !== [] || $rec['redo_replay'] !== [] || $rec['foreign'] !== [] || $failback !== [];
    return ['plan' => $plan, 'state' => $state];
}
