<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Apply order and failure handling with fake I/O, spec section 3.7.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/apply.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/pfstate.php';

/**
 * @param array<string, string> $configd action => result
 * @param list<array<string, string>> $statusSeq successive status() results; the last repeats
 * @return array{io: array, calls: ArrayObject}
 */
function wf_t_io(array $configd = [], bool $lock = true, bool $write = true, array $pfs = [], ?string $default = '203.0.113.1', array $statusSeq = []): array
{
    $calls = new ArrayObject();
    $pfQueue = new ArrayObject($pfs);
    $stQueue = new ArrayObject($statusSeq !== [] ? $statusSeq : [['WAN2' => 'force_down', 'PRIMARY_WAN' => 'none']]);
    $next = function (ArrayObject $q): array {
        $a = $q->getArrayCopy();
        $v = $a[0];
        if (count($a) > 1) {
            array_shift($a);
            $q->exchangeArray($a);
        }
        return $v;
    };
    $io = [
        'configd' => function (string $a, array $p) use ($calls, $configd): string {
            $calls[] = trim("configd {$a} " . implode(' ', $p));
            return $configd[$a] ?? 'OK';
        },
        'write' => function (array $c, array $heldAfter) use ($calls, $write): bool {
            $calls[] = 'write ' . json_encode($c) . ' held=' . implode(',', $heldAfter);
            return $write;
        },
        'gw_lock' => function () use ($calls, $lock): bool {
            $calls[] = 'lock';
            return $lock;
        },
        'gw_unlock' => function () use ($calls): void {
            $calls[] = 'unlock';
        },
        'status' => fn (): array => $next($stQueue),
        'pf' => fn (): array => $next($pfQueue),
        'live_default' => fn (): ?string => $default,
        'save_state' => function (array $s) use ($calls): void {
            $calls[] = 'save';
        },
        'sleep' => fn (int $s): int => 0,
        'log' => function (string $m) use ($calls): void {
            $calls[] = "log {$m}";
        },
        'crash_point' => fn (string $p): int => 0,
    ];
    return ['io' => $io, 'calls' => $calls];
}

/** @return array<string, mixed> */
function wf_t_plan(array $over = []): array
{
    return array_merge(['hold' => [], 'release' => [], 'held_after' => [], 'held_now' => [], 'write' => false, 'redo_apply' => [],
                        'redo_replay' => [], 'foreign' => [], 'kill_gateways' => [], 'failback' => [],
                        'expected_default' => null, 'alerts' => [], 'log' => [], 'acting' => true, 'stopped' => false], $over);
}

wf_register_suite('apply', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $snap = ['now' => 1000, 'tailscale_restart' => false,
             'wans' => ['PRIMARY_WAN' => ['gateway_ip' => '203.0.113.1'], 'WAN2' => ['gateway_ip' => '192.168.12.1']]];
    $state = wf_state_new(1);
    $plan = wf_t_plan(['hold' => ['WAN2'], 'held_after' => ['WAN2'], 'write' => true, 'kill_gateways' => ['192.168.12.1']]);

    $f = wf_t_io();
    $r = wf_apply($plan, $state, $snap, $f['io']);
    $c = $f['calls']->getArrayCopy();
    wf_check($t, 'hold: save pending, lock, one write with held, routes configure, unlock, replay, kill', array_slice($c, 0, 7) === [
        'save', 'lock', 'write {"WAN2":true} held=WAN2', 'configd interface routes configure', 'unlock',
        'configd wanfailover replay_alarm WAN2', 'configd filter kill gateway_states 192.168.12.1']);
    wf_check($t, 'hold: apply_pending cleared, last_held set', $r['ok'] && $r['state']['apply_pending'] === [] && $r['state']['last_held'] === ['WAN2']);

    $f = wf_t_io([], true, true, [], '203.0.113.1', [['WAN2' => 'none', 'PRIMARY_WAN' => 'none'], ['WAN2' => 'force_down', 'PRIMARY_WAN' => 'down']]);
    wf_apply($plan, $state, $snap, $f['io']);
    wf_check($t, 'R3-2: a gateway whose status changed during our hold is replayed with ours',
        in_array('configd wanfailover replay_alarm PRIMARY_WAN,WAN2', $f['calls']->getArrayCopy(), true));

    $f = wf_t_io(['wanfailover replay_alarm' => 'Execute error']);
    $r = wf_apply($plan, $state, $snap, $f['io']);
    wf_check($t, 'RF4: replay fails -> apply_pending kept, no kill', $r['state']['apply_pending'] === ['WAN2' => 'hold']
        && !in_array('configd filter kill gateway_states 192.168.12.1', $f['calls']->getArrayCopy(), true));

    $f = wf_t_io([], false);
    $r = wf_apply($plan, $state, $snap, $f['io']);
    wf_check($t, 'gateway lock busy -> not ok, nothing written, pending kept for next tick', !$r['ok']
        && count(array_filter($f['calls']->getArrayCopy(), fn (string $x): bool => str_starts_with($x, 'write'))) === 0
        && $r['state']['apply_pending'] === ['WAN2' => 'hold']);

    $f = wf_t_io([], true, false);
    $r = wf_apply($plan, $state, $snap, $f['io']);
    wf_check($t, 'write fails -> not ok, unlock still called', !$r['ok'] && in_array('unlock', $f['calls']->getArrayCopy(), true));

    $f = wf_t_io();
    $r = wf_apply(wf_t_plan(['release' => ['WAN2'], 'write' => true]), $state, $snap, $f['io']);
    wf_check($t, 'release: write with empty held, then replay, pending cleared', in_array('write {"WAN2":false} held=', $f['calls']->getArrayCopy(), true)
        && $r['state']['apply_pending'] === []);

    $f = wf_t_io();
    $r = wf_apply(wf_t_plan(['foreign' => ['WAN2'], 'held_now' => ['WAN2']]), $state, $snap, $f['io']);
    $c = $f['calls']->getArrayCopy();
    wf_check($t, 'R3-8: foreign change -> routes configure under the lock, then replay; no write; last_held follows config',
        in_array('configd interface routes configure', $c, true) && in_array('configd wanfailover replay_alarm WAN2', $c, true)
        && count(array_filter($c, fn (string $x): bool => str_starts_with($x, 'write'))) === 0 && $r['state']['last_held'] === ['WAN2']);

    $states = wf_parse_states((string)file_get_contents(__DIR__ . '/fixtures/states.txt'));
    $rules = wf_parse_rules((string)file_get_contents(__DIR__ . '/fixtures/rules.txt'));
    $flows = wf_flows($states, ['203.0.113.1' => 'PRIMARY_WAN', '192.168.12.1' => 'WAN2']);
    $pref = ['22222222-2222-4222-8222-222222222222' => ['WAN2'], '33333333-3333-4333-8333-333333333333' => []];
    $pfStale = ['flows' => $flows, 'renderings' => $rules, 'pinned' => ['198.51.100.200' => true], 'rule_pref' => $pref,
                'default' => 'WAN2', 'selfcheck' => true, 'raw_states' => '', 'raw_rules' => ''];
    $pfMoved = array_merge($pfStale, ['default' => 'PRIMARY_WAN']);
    $fb = wf_state_new(1);
    $fb['pending_failbacks']['PRIMARY_WAN'] = ['since' => 990];
    $f = wf_t_io([], true, true, [$pfStale, $pfMoved]);
    $r = wf_apply(wf_t_plan(['failback' => ['PRIMARY_WAN' => ['top' => true]]]), $fb, $snap, $f['io']);
    $c = $f['calls']->getArrayCopy();
    wf_check($t, 'failback: stale default -> replay, recheck, kill once moved, pending cleared',
        in_array('configd wanfailover replay_alarm PRIMARY_WAN', $c, true)
        && in_array('configd filter kill state 33f6d16a00000000 4a28027f', $c, true)
        && !isset($r['state']['pending_failbacks']['PRIMARY_WAN']));
    $f = wf_t_io([], true, true, [array_merge($pfMoved, ['selfcheck' => false])]);
    $r = wf_apply(wf_t_plan(['failback' => ['PRIMARY_WAN' => ['top' => true]]]), $fb, $snap, $f['io']);
    wf_check($t, 'failback: pf self-check failed -> suspended, nothing killed, still pending',
        count(array_filter($f['calls']->getArrayCopy(), fn (string $x): bool => str_starts_with($x, 'configd filter kill state'))) === 0
        && isset($r['state']['pending_failbacks']['PRIMARY_WAN']));

    $ts = wf_state_new(1);
    $ts['ts'] = ['default_gw' => '192.168.12.1', 'restarted_at' => null, 'cur_default' => '192.168.12.1', 'cur_since' => 1,
                 'lost' => false, 'expected_default' => null];
    $f = wf_t_io([], true, true, [], '203.0.113.1');
    $r = wf_apply(wf_t_plan(['expected_default' => '203.0.113.1', 'acting' => false]), $ts, array_merge($snap, ['tailscale_restart' => true]), $f['io']);
    wf_check($t, 'tailscale: planned default change restarts through configd', in_array('configd tailscale restart', $f['calls']->getArrayCopy(), true)
        && $r['state']['ts']['default_gw'] === '203.0.113.1');
    return wf_tally_report('apply', $t);
});
