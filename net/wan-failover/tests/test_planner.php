<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Planner scenarios: spec section 6, round-3 fixes and the Review Focus list.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/planner.php';

/** @return array<string, string|int|float|bool|null> */
function wf_t_wan(string $uuid, string $gw, int $prio, array $over = []): array
{
    return array_merge([
        'uuid' => $uuid, 'gateway_ip' => $gw, 'priority' => $prio, 'disabled' => false, 'force_down' => false,
        'status' => 'none', 'present' => true, 'tilde' => false, 'carrier' => true, 'has_ipv4' => true,
        'loss' => 0.0, 'sock_age' => 300, 'losslow' => 10.0, 'losshigh' => 20.0, 'time_period' => 60,
        'interval' => 1, 'loss_interval' => 4,
    ], $over);
}

/** @return array<string, mixed> */
function wf_t_snap(int $now, array $primary, array $wan2, array $extra = []): array
{
    $wans = ['PRIMARY_WAN' => wf_t_wan('aaaaaaaa-0000-4000-8000-000000000001', '203.0.113.1', 1, $primary),
             'WAN2' => wf_t_wan('aaaaaaaa-0000-4000-8000-000000000002', '192.168.12.1', 2, $wan2)];
    return array_merge(['now' => $now, 'boot_time' => 1, 'enabled' => true, 'failback' => true,
        'default_gw' => '203.0.113.1', 'wans' => $wans, 'unresolved' => [], 'held' => [], 'held_stale' => [],
        'force_down' => array_map(fn (array $w): bool => $w['force_down'], $wans),
        'contract' => ['judging' => [], 'command' => []]], $extra);
}

/** What apply leaves behind when every step succeeds. */
function wf_t_applied(array $state, array $plan): array
{
    $state['last_held'] = $plan['held_after'];
    $state['apply_pending'] = [];
    return $state;
}

wf_register_suite('planner', function (): int {
    $t = ['fail' => 0, 'total' => 0];

    $r = wf_plan(wf_t_snap(1000, [], ['loss' => 30.0]), wf_state_new(1));
    wf_check($t, '1: hold WAN2, kill its gateway, default expected on PRIMARY', $r['plan']['hold'] === ['WAN2']
        && $r['plan']['held_after'] === ['WAN2'] && $r['plan']['write'] && $r['plan']['kill_gateways'] === ['192.168.12.1']
        && $r['plan']['expected_default'] === '203.0.113.1');
    $s = wf_t_applied($r['state'], $r['plan']);

    $held = ['held' => ['WAN2']];
    $r = wf_plan(wf_t_snap(1015, ['loss' => null, 'sock_age' => 3], ['loss' => null, 'sock_age' => 3, 'force_down' => true, 'status' => 'force_down'], $held), $s);
    wf_check($t, '2: restart after the hold changes nothing (B1)', $r['plan']['hold'] === [] && $r['plan']['release'] === [] && !$r['plan']['write']);
    $s = $r['state'];

    $r = wf_plan(wf_t_snap(1080, [], ['loss' => 5.0, 'force_down' => true, 'status' => 'force_down'], $held), $s);
    wf_check($t, '4: held WAN2 at 5% (marginal) stays held', $r['plan']['release'] === []);
    $r = wf_plan(wf_t_snap(1140, [], ['loss' => 0.0, 'force_down' => true, 'status' => 'force_down'], $held), $r['state']);
    wf_check($t, '4: loss-free -> released, held emptied, failback pending (not top)', $r['plan']['release'] === ['WAN2']
        && $r['plan']['held_after'] === [] && $r['plan']['failback'] === ['WAN2' => ['top' => false]]);

    $down = ['carrier' => false, 'present' => false, 'loss' => null];
    $r = wf_plan(wf_t_snap(2000, $down, $down), wf_state_new(1));
    wf_check($t, '6a: both down -> nothing held', $r['plan']['hold'] === []);
    $r2 = wf_plan(wf_t_snap(2100, [], ['loss' => null, 'sock_age' => 5]), $r['state']);
    wf_check($t, '6a: PRIMARY back, WAN2 unmeasured -> not held; PRIMARY failback pending as top',
        $r2['plan']['hold'] === [] && $r2['plan']['failback'] === ['PRIMARY_WAN' => ['top' => true]]);
    $r3 = wf_plan(wf_t_snap(2100, [], $down), $r['state']);
    wf_check($t, '6a variant: WAN2 still hard down -> held (decision 3)', $r3['plan']['hold'] === ['WAN2']);

    $s = wf_state_new(1);
    $r = wf_plan(wf_t_snap(3000, ['loss' => null, 'sock_age' => 2], ['loss' => null, 'sock_age' => 2, 'force_down' => true, 'status' => 'force_down'],
        ['boot_time' => 2, 'held' => ['WAN2']]), $s);
    wf_check($t, '12c: boot the hook missed -> every held gateway released, judgements reset', $r['plan']['release'] === ['WAN2']
        && $r['plan']['held_after'] === [] && $r['state']['boot_time'] === 2 && $r['state']['judgements'] === []);

    $r = wf_plan(wf_t_snap(4000, ['loss' => 30.0], ['force_down' => true, 'status' => 'force_down']), wf_state_new(1));
    wf_check($t, 'manual force_down: one alert, nothing released or held', count($r['plan']['alerts']) === 1
        && $r['plan']['release'] === [] && $r['plan']['hold'] === []);
    $r = wf_plan(wf_t_snap(4060, ['loss' => 30.0], ['force_down' => true, 'status' => 'force_down']), $r['state']);
    wf_check($t, 'manual force_down: no repeat alert within the hour', $r['plan']['alerts'] === []);

    $s = wf_state_new(1);
    $s['last_held'] = ['WAN2'];
    $r = wf_plan(wf_t_snap(5000, [], ['loss' => 30.0], ['held' => ['WAN2']]), $s);
    wf_check($t, '11: held but force_down=0 -> pruned from held, no re-hold yet', $r['plan']['hold'] === []
        && $r['plan']['held_after'] === [] && $r['plan']['write'] && isset($r['state']['no_rehold']['WAN2']));
    $s = wf_t_applied($r['state'], $r['plan']);
    $r = wf_plan(wf_t_snap(5060, [], ['loss' => 3.0]), $s);
    $r = wf_plan(wf_t_snap(5120, [], ['loss' => 30.0]), wf_t_applied($r['state'], $r['plan']));
    wf_check($t, '11: after reading up then over threshold, held again', $r['plan']['hold'] === ['WAN2']);

    $r = wf_plan(wf_t_snap(6000, [], ['loss' => 8.0]), wf_state_new(1));
    $r = wf_plan(wf_t_snap(6015, ['sock_age' => 12, 'loss' => 0.0], ['sock_age' => 40, 'loss' => 35.0]), $r['state']);
    wf_check($t, '3: the 10-05 pattern -- hold starts while PRIMARY is unsettled but fresh', $r['plan']['hold'] === ['WAN2']);

    $r = wf_plan(wf_t_snap(7000, [], [], ['unresolved' => ['bbbbbbbb-0000-4000-8000-00000000000f'], 'held_stale' => ['cccccccc-0000-4000-8000-00000000000e']]), wf_state_new(1));
    wf_check($t, 'RF1: unresolvable wans entry and stale held UUID -> prune write, logged', $r['plan']['write']
        && count(array_filter($r['plan']['log'], fn (string $l): bool => str_contains($l, 'bbbbbbbb'))) === 1);

    $r = wf_plan(wf_t_snap(8000, [], []), wf_state_new(1));
    $r = wf_plan(wf_t_snap(8100, [], ['loss' => null, 'sock_age' => 3]), $r['state']);
    $r = wf_plan(wf_t_snap(4500, [], ['loss' => null, 'sock_age' => 3]), $r['state']);
    wf_check($t, 'RF5: clock back an hour keeps WAN2 clean and logs it', $r['state']['judgements']['WAN2']['value'] === WF_CLEAN
        && count(array_filter($r['plan']['log'], fn (string $l): bool => str_starts_with($l, 'clock moved back'))) === 1);

    $s = wf_state_new(1);
    $s['last_held'] = ['WAN2'];
    $r = wf_plan(wf_t_snap(9000, [], ['loss' => 30.0, 'force_down' => true, 'status' => 'force_down'], ['held' => ['WAN2'], 'enabled' => false]), $s);
    wf_check($t, '12b: disabled -> every held gateway released, nothing planned', $r['plan']['release'] === ['WAN2']
        && $r['plan']['hold'] === [] && $r['plan']['stopped']);

    $r = wf_plan(wf_t_snap(9050, [], [], ['enabled' => false]), wf_state_new(1));
    wf_check($t, 'disabled with nothing held logs nothing and plans nothing', $r['plan']['log'] === [] && !$r['plan']['acting']);

    $drift = ['held' => ['WAN2'], 'contract' => ['judging' => ['dpinger_instances() rows lack current_losslow'], 'command' => []]];
    $r = wf_plan(wf_t_snap(9100, [], ['loss' => 30.0, 'force_down' => true, 'status' => 'force_down'], $drift), $s);
    wf_check($t, '12e: a judging drift that has not persisted (a reconfigure in flight) releases nothing', $r['plan']['release'] === [] && !$r['plan']['stopped']);
    $r = wf_plan(wf_t_snap(9281, [], ['loss' => 30.0, 'force_down' => true, 'status' => 'force_down'], $drift), $r['state']);
    wf_check($t, '12e: a judging drift persisting past unknown_max_seconds -> release all and stop', $r['plan']['release'] === ['WAN2'] && $r['plan']['stopped']);
    $r2 = wf_plan(wf_t_snap(9300, [], ['loss' => 30.0], ['contract' => ['judging' => ['x'], 'command' => []]]), wf_state_new(1));
    wf_check($t, '12e: a fresh judging drift blocks new holds', $r2['plan']['hold'] === []);
    $r = wf_plan(wf_t_snap(9200, [], ['loss' => 30.0], ['contract' => ['judging' => [], 'command' => ['[kill.state] changed']]]), wf_state_new(1));
    wf_check($t, '12e: command drift -> no new hold', $r['plan']['hold'] === [] && !$r['plan']['stopped']);

    $r = wf_plan(wf_t_snap(9300, [], ['force_down' => true, 'status' => 'force_down'], ['held' => ['WAN2']]), wf_state_new(1));
    wf_check($t, '12f: held appeared outside the engine -> foreign re-sync', $r['plan']['foreign'] === ['WAN2']);

    $r = wf_plan(['wans' => ['PRIMARY_WAN' => wf_t_wan('aaaaaaaa-0000-4000-8000-000000000001', '203.0.113.1', 1)]]
        + wf_t_snap(9400, [], ['force_down' => true, 'status' => 'force_down'], ['held' => ['WAN2'], 'force_down' => ['PRIMARY_WAN' => false, 'WAN2' => true]]), $s);
    wf_check($t, 'a held gateway removed from wans is released', $r['plan']['release'] === ['WAN2'] && $r['plan']['held_after'] === []);
    return wf_tally_report('planner', $t);
});
