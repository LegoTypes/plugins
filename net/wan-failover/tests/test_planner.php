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
function wf_t_wan(string $uuid, string $gw, int $rank, array $over = []): array
{
    return array_merge([
        'uuid' => $uuid, 'gateway_ip' => $gw, 'rank' => $rank, 'disabled' => false, 'force_down' => false,
        'status' => 'none', 'present' => true, 'tilde' => false, 'carrier' => true, 'has_ipv4' => true,
        'loss' => 0.0, 'sock_age' => 300, 'losslow' => 10.0, 'losshigh' => 20.0, 'time_period' => 60,
        'interval' => 1, 'loss_interval' => 4,
    ], $over);
}

/** @return array{now: int, boot_id: string, release: ?string, enabled: bool, dry: bool, failback: bool, default_gw: ?string, wans: array<string, array>, unresolved: list<string>, held: list<string>, held_stale: list<string>, force_down: array<string, bool>, contract: array{judging: list<string>, command: list<string>}} */
function wf_t_snap(int $now, array $primary, array $wan2, array $extra = []): array
{
    $wans = ['PRIMARY_WAN' => wf_t_wan('aaaaaaaa-0000-4000-8000-000000000001', '203.0.113.1', 1, $primary + ['route_target' => '203.0.113.1@igc1']),
             'WAN2' => wf_t_wan('aaaaaaaa-0000-4000-8000-000000000002', '172.16.12.1', 2, $wan2 + ['route_target' => '172.16.12.1@igc2'])];
    return array_merge(['now' => $now, 'boot_id' => 'b1', 'enabled' => true, 'failback' => true,
        'default_gw' => '203.0.113.1@igc1', 'wans' => $wans, 'unresolved' => [], 'held' => [], 'held_stale' => [],
        'force_down' => array_map(fn (array $w): bool => $w['force_down'], $wans),
        'contract' => ['judging' => [], 'command' => []], 'dry' => false, 'release' => null,
        'failback_delay' => 0, 'failback_now' => false], $extra);
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

    $r = wf_plan(wf_t_snap(1000, [], ['loss' => 30.0]), wf_state_new('b1'));
    wf_check($t, '1: hold WAN2, kill its gateway, default expected on PRIMARY', $r['plan']['hold'] === ['WAN2']
        && $r['plan']['held_after'] === ['WAN2'] && $r['plan']['write'] && $r['plan']['kill_gateways'] === ['172.16.12.1']
        && $r['plan']['expected_default'] === '203.0.113.1@igc1');
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
    $r = wf_plan(wf_t_snap(2000, $down, $down), wf_state_new('b1'));
    wf_check($t, '6a: both down -> nothing held', $r['plan']['hold'] === []);
    $r2 = wf_plan(wf_t_snap(2100, [], ['loss' => null, 'sock_age' => 5]), $r['state']);
    wf_check($t, '6a: PRIMARY back, WAN2 unmeasured -> not held; PRIMARY failback pending as top',
        $r2['plan']['hold'] === [] && $r2['plan']['failback'] === ['PRIMARY_WAN' => ['top' => true]]);
    $r3 = wf_plan(wf_t_snap(2100, [], $down), $r['state']);
    wf_check($t, '6a variant: WAN2 still hard down -> held (decision 3)', $r3['plan']['hold'] === ['WAN2']);

    $s = wf_state_new('b1');
    $r = wf_plan(wf_t_snap(3000, ['loss' => null, 'sock_age' => 2], ['loss' => null, 'sock_age' => 2, 'force_down' => true, 'status' => 'force_down'],
        ['boot_id' => 'b2', 'held' => ['WAN2']]), $s);
    wf_check($t, '12c: boot the hook missed -> every held gateway released, judgements reset', $r['plan']['release'] === ['WAN2']
        && $r['plan']['held_after'] === [] && $r['state']['boot_id'] === 'b2' && $r['state']['judgements'] === []);
    $s = wf_state_new('b1');
    $s['last_held'] = ['WAN2'];
    $r = wf_plan(wf_t_snap(3000, [], ['loss' => 30.0, 'force_down' => true, 'status' => 'force_down'],
        ['boot_time' => 1791270671, 'held' => ['WAN2']]), $s);
    wf_check($t, 'same boot id, kern.boottime moved by a clock step: not a boot, the hold stays', $r['plan']['release'] === []
        && $r['plan']['held_after'] === ['WAN2'] && $r['state']['boot_id'] === 'b1');

    $r = wf_plan(wf_t_snap(4000, ['loss' => 30.0], ['force_down' => true, 'status' => 'force_down']), wf_state_new('b1'));
    wf_check($t, 'manual force_down: one alert, nothing released or held', count($r['plan']['alerts']) === 1
        && $r['plan']['release'] === [] && $r['plan']['hold'] === []);
    $r = wf_plan(wf_t_snap(4060, ['loss' => 30.0], ['force_down' => true, 'status' => 'force_down']), $r['state']);
    wf_check($t, 'manual force_down: no repeat alert within the hour', $r['plan']['alerts'] === []);

    $s = wf_state_new('b1');
    $s['last_held'] = ['WAN2'];
    $r = wf_plan(wf_t_snap(5000, [], ['loss' => 30.0], ['held' => ['WAN2']]), $s);
    wf_check($t, '11: held but force_down=0 -> pruned from held, no re-hold yet', $r['plan']['hold'] === []
        && $r['plan']['held_after'] === [] && $r['plan']['write'] && isset($r['state']['no_rehold']['WAN2']));
    $s = wf_t_applied($r['state'], $r['plan']);
    $r = wf_plan(wf_t_snap(5060, [], ['loss' => 3.0]), $s);
    $r = wf_plan(wf_t_snap(5120, [], ['loss' => 30.0]), wf_t_applied($r['state'], $r['plan']));
    wf_check($t, '11: after reading up then over threshold, held again', $r['plan']['hold'] === ['WAN2']);

    $r = wf_plan(wf_t_snap(6000, [], ['loss' => 8.0]), wf_state_new('b1'));
    $r = wf_plan(wf_t_snap(6015, ['sock_age' => 12, 'loss' => 0.0], ['sock_age' => 40, 'loss' => 35.0]), $r['state']);
    wf_check($t, '3: the 10-05 pattern -- hold starts while PRIMARY is unsettled but fresh', $r['plan']['hold'] === ['WAN2']);

    $r = wf_plan(wf_t_snap(7000, [], [], ['unresolved' => ['bbbbbbbb-0000-4000-8000-00000000000f'], 'held_stale' => ['cccccccc-0000-4000-8000-00000000000e']]), wf_state_new('b1'));
    wf_check($t, 'RF1: unresolvable wans entry and stale held UUID -> prune write, logged', $r['plan']['write']
        && count(array_filter($r['plan']['log'], fn (string $l): bool => str_contains($l, 'bbbbbbbb'))) === 1);

    $r = wf_plan(wf_t_snap(8000, [], []), wf_state_new('b1'));
    $r = wf_plan(wf_t_snap(8100, [], ['loss' => null, 'sock_age' => 3]), $r['state']);
    $r = wf_plan(wf_t_snap(4500, [], ['loss' => null, 'sock_age' => 3]), $r['state']);
    wf_check($t, 'RF5: clock back an hour keeps WAN2 clean and logs it', $r['state']['judgements']['WAN2']['value'] === WF_CLEAN
        && count(array_filter($r['plan']['log'], fn (string $l): bool => str_starts_with($l, 'clock moved back'))) === 1);

    $s = wf_state_new('b1');
    $s['last_held'] = ['WAN2'];
    $r = wf_plan(wf_t_snap(9000, [], ['loss' => 30.0, 'force_down' => true, 'status' => 'force_down'], ['held' => ['WAN2'], 'enabled' => false]), $s);
    wf_check($t, '12b: disabled -> every held gateway released, nothing planned', $r['plan']['release'] === ['WAN2']
        && $r['plan']['hold'] === [] && $r['plan']['stopped']);

    $r = wf_plan(wf_t_snap(9050, [], [], ['enabled' => false]), wf_state_new('b1'));
    wf_check($t, 'disabled with nothing held logs nothing and plans nothing', $r['plan']['log'] === [] && !$r['plan']['acting']);

    $drift = ['held' => ['WAN2'], 'contract' => ['judging' => ['dpinger_instances() rows lack current_losslow'], 'command' => []]];
    $r = wf_plan(wf_t_snap(9100, [], ['loss' => 30.0, 'force_down' => true, 'status' => 'force_down'], $drift), $s);
    wf_check($t, '12e: a judging drift that has not persisted (a reconfigure in flight) releases nothing', $r['plan']['release'] === [] && !$r['plan']['stopped']);
    $r = wf_plan(wf_t_snap(9281, [], ['loss' => 30.0, 'force_down' => true, 'status' => 'force_down'], $drift), $r['state']);
    wf_check($t, '12e: a judging drift persisting past unknown_max_seconds -> release all and stop', $r['plan']['release'] === ['WAN2'] && $r['plan']['stopped']);
    $r2 = wf_plan(wf_t_snap(9300, [], ['loss' => 30.0], ['contract' => ['judging' => ['x'], 'command' => []]]), wf_state_new('b1'));
    wf_check($t, '12e: a fresh judging drift blocks new holds', $r2['plan']['hold'] === []);
    $r = wf_plan(wf_t_snap(9200, [], ['loss' => 30.0], ['contract' => ['judging' => [], 'command' => ['[kill.state] changed']]]), wf_state_new('b1'));
    wf_check($t, '12e: command drift -> no new hold', $r['plan']['hold'] === [] && !$r['plan']['stopped']);

    $r = wf_plan(wf_t_snap(9300, [], ['force_down' => true, 'status' => 'force_down'], ['held' => ['WAN2']]), wf_state_new('b1'));
    wf_check($t, '12f: held appeared outside the engine -> foreign re-sync', $r['plan']['foreign'] === ['WAN2']);

    $r = wf_plan(['wans' => ['PRIMARY_WAN' => wf_t_wan('aaaaaaaa-0000-4000-8000-000000000001', '203.0.113.1', 1)]]
        + wf_t_snap(9400, [], ['force_down' => true, 'status' => 'force_down'], ['held' => ['WAN2'], 'force_down' => ['PRIMARY_WAN' => false, 'WAN2' => true]]), $s);
    wf_check($t, 'a held gateway removed from wans is released', $r['plan']['release'] === ['WAN2'] && $r['plan']['held_after'] === []);
    $s = wf_state_new('b1');
    $s['boot_note'] = 'boot: released WAN2';
    $r = wf_plan(wf_t_snap(9500, [], []), $s);
    wf_check($t, 'the early hook\'s note (syslog is not running yet at that point) is logged once by the first evaluation',
        in_array('boot: released WAN2', $r['plan']['log'], true) && $r['state']['boot_note'] === null);
    $s = wf_state_new('b1');
    $s['last_held'] = ['WAN2'];
    $r = wf_plan(wf_t_snap(9400, [], ['loss' => 30.0, 'force_down' => true, 'status' => 'force_down'], ['held' => ['WAN2'], 'boot_id' => '']), $s);
    wf_check($t, 'an unreadable boot id is not a boot: the hold stays', $r['plan']['release'] === [] && $r['plan']['held_after'] === ['WAN2']
        && $r['state']['boot_id'] === 'b1');

    $s = wf_state_new('b1');
    $s['last_held'] = ['WAN2'];
    $r = wf_plan(wf_t_snap(9500, [], ['loss' => 30.0, 'force_down' => true, 'status' => 'force_down'], ['held' => ['WAN2'], 'release' => 'requested']), $s);
    wf_check($t, 'release from the page: released and not re-held while still bad', $r['plan']['release'] === ['WAN2']
        && isset($r['state']['no_rehold']['WAN2']));
    $r = wf_plan(wf_t_snap(9560, [], ['loss' => 30.0]), wf_t_applied($r['state'], $r['plan']));
    wf_check($t, 'release from the page: the next tick does not re-hold', $r['plan']['hold'] === []);

    $s = wf_state_new('b1');
    $s['pending_failbacks']['WAN2'] = ['since' => 9600];
    $r = wf_plan(wf_t_snap(9610, [], [], ['failback' => false]), $s);
    wf_check($t, 'move-connections-back off: pending failbacks dropped, none planned', $r['plan']['failback'] === [] && $r['state']['pending_failbacks'] === []);

    $s = wf_state_new('b1');
    $s['last_now'] = 20000;
    $s['unowned_alerted_at']['WAN2'] = 19990;
    $r = wf_plan(wf_t_snap(10000, [], ['force_down' => true, 'status' => 'force_down']), $s);
    wf_check($t, 'clock moved back: the unowned alert is not silenced for the size of the jump', count($r['plan']['alerts']) === 1);

    $s = wf_state_new('b1');
    $u = ['unresolved' => ['bbbbbbbb-0000-4000-8000-00000000000f']];
    $r = wf_plan(wf_t_snap(11000, [], [], $u), $s);
    $r2 = wf_plan(wf_t_snap(11060, [], [], $u), $r['state']);
    wf_check($t, 'an ignored wans entry is logged once, not every tick', count(array_filter($r['plan']['log'], fn (string $l): bool => str_contains($l, 'ignored'))) === 1
        && array_filter($r2['plan']['log'], fn (string $l): bool => str_contains($l, 'ignored')) === []);
    $c = ['contract' => ['judging' => [], 'command' => ['[kill.state] changed']]];
    $r = wf_plan(wf_t_snap(11100, [], ['loss' => 30.0], $c), wf_state_new('b1'));
    $r2 = wf_plan(wf_t_snap(11160, [], ['loss' => 30.0], $c), $r['state']);
    wf_check($t, '"not starting holds" is logged once while the drift lasts', count(array_filter($r['plan']['log'], fn (string $l): bool => str_contains($l, 'not starting holds'))) === 1
        && array_filter($r2['plan']['log'], fn (string $l): bool => str_contains($l, 'not starting holds')) === []);

    /* dry run simulates ownership: it holds once, stays quiet while held, releases once clean */
    $s = wf_state_new('b1');
    $snap = wf_t_snap(12000, [], ['loss' => 30.0], ['dry' => true]);
    $r = wf_plan(wf_dry_view($snap, $s['dry_held']), $s);
    $s = wf_dry_after($r['state'], $r['plan']);
    wf_check($t, 'dry: a bad WAN2 is held in the simulation', $r['plan']['hold'] === ['WAN2'] && $s['dry_held'] === ['WAN2']);
    $snap = wf_t_snap(12060, [], ['loss' => 30.0], ['dry' => true]);
    $r = wf_plan(wf_dry_view($snap, $s['dry_held']), $s);
    $s = wf_dry_after($r['state'], $r['plan']);
    wf_check($t, 'dry: still bad -> no repeated hold, still held', $r['plan']['hold'] === [] && $r['plan']['acting'] === false && $s['dry_held'] === ['WAN2']);
    $snap = wf_t_snap(12120, [], ['loss' => 3.0], ['dry' => true]);
    $r = wf_plan(wf_dry_view($snap, $s['dry_held']), $s);
    $s = wf_dry_after($r['state'], $r['plan']);
    wf_check($t, 'dry: marginal while held -> stays held (hysteresis rehearsed)', $r['plan']['release'] === [] && $s['dry_held'] === ['WAN2']);
    $snap = wf_t_snap(12180, [], [], ['dry' => true]);
    $r = wf_plan(wf_dry_view($snap, $s['dry_held']), $s);
    $s = wf_dry_after($r['state'], $r['plan']);
    wf_check($t, 'dry: loss-free -> released, failback rehearsed', $r['plan']['release'] === ['WAN2'] && $s['dry_held'] === []
        && isset($r['plan']['failback']['WAN2']));
    $s = wf_state_new('b1');
    $s['dry_held'] = ['WAN2'];
    $s['last_held'] = ['WAN2'];
    $snap = wf_t_snap(12240, [], ['loss' => 30.0]);
    $r = wf_plan($snap, wf_dry_exit($s, $snap));
    wf_check($t, 'dry turned off: the simulated holds are dropped, not taken for a foreign config change; a bad WAN2 is held for real',
        $r['plan']['foreign'] === [] && $r['plan']['hold'] === ['WAN2'] && $r['state']['dry_held'] === []
        && array_filter($r['plan']['log'], fn (string $l): bool => str_contains($l, 'outside the engine')) === []);
    $s = wf_state_new('b1');
    $s['last_held'] = ['WAN2'];
    $r = wf_plan(wf_t_snap(12300, [], ['loss' => 30.0, 'force_down' => true, 'status' => 'force_down'], ['held' => ['WAN2'], 'release' => 'dry']), $s);
    wf_check($t, 'dry turned on while really holding: the real hold is released', $r['plan']['release'] === ['WAN2'] && $r['plan']['held_after'] === []);
    /* failback delay: the recovered WAN must read clean for failback_delay seconds before its flows move back */
    $d = ['failback_delay' => 600];
    $s = wf_state_new('b1');
    $s['last_held'] = ['WAN2'];
    $r = wf_plan(wf_t_snap(13000, [], ['loss' => 0.0, 'force_down' => true, 'status' => 'force_down'], $d + ['held' => ['WAN2']]), $s);
    wf_check($t, 'delay: the release queues the failback without running it', $r['plan']['release'] === ['WAN2']
        && $r['plan']['failback'] === [] && isset($r['state']['pending_failbacks']['WAN2']));
    $s0 = wf_t_applied($r['state'], $r['plan']);
    $r = wf_plan(wf_t_snap(13300, [], [], $d), $s0);
    wf_check($t, 'delay: 300 s of clean readings is not enough', $r['plan']['failback'] === []);
    wf_check($t, 'delay: the status shows 300 s left', wf_failback_wait($r['state']['pending_failbacks']['WAN2'], 13300, 600)
        === ['state' => 'counting', 'left' => 300]);
    $r = wf_plan(wf_t_snap(13600, [], [], $d), $r['state']);
    wf_check($t, 'delay: 600 s of clean readings runs the failback', isset($r['plan']['failback']['WAN2']));
    wf_check($t, 'delay: the status shows it moving', wf_failback_wait($r['state']['pending_failbacks']['WAN2'], 13600, 600)['state'] === 'moving');
    $r = wf_plan(wf_t_snap(14201, [], [], $d), $r['state']);
    wf_check($t, 'delay: a due failback expires 600 s after it became due, not after it was queued',
        $r['plan']['failback'] === [] && in_array('failback-expired WAN2', $r['plan']['log'], true));

    $r = wf_plan(wf_t_snap(13300, [], ['loss' => 3.0], $d), $s0);
    wf_check($t, 'delay: a marginal reading restarts the countdown', $r['plan']['failback'] === []
        && wf_failback_wait($r['state']['pending_failbacks']['WAN2'], 13300, 600) === ['state' => 'waiting', 'left' => 600]);
    $r = wf_plan(wf_t_snap(13400, [], [], $d), $r['state']);
    $r = wf_plan(wf_t_snap(13900, [], [], $d), $r['state']);
    wf_check($t, 'delay: the restarted countdown is not done after 500 s', $r['plan']['failback'] === []);
    $r = wf_plan(wf_t_snap(14000, [], [], $d), $r['state']);
    wf_check($t, 'delay: done 600 s after the restart', isset($r['plan']['failback']['WAN2']));

    $r = wf_plan(wf_t_snap(13300, [], ['loss' => 30.0], $d), $s0);
    wf_check($t, 'delay: held again during the delay drops the failback', $r['plan']['hold'] === ['WAN2']
        && $r['state']['pending_failbacks'] === [] && $r['plan']['failback'] === []);

    $r = wf_plan(wf_t_snap(13100, [], [], $d + ['failback_now' => true]), $s0);
    wf_check($t, 'fail back now ends the delay', isset($r['plan']['failback']['WAN2'])
        && in_array('failback-now: the delay ended for WAN2', $r['plan']['log'], true));
    $r = wf_plan(wf_t_snap(13100, [], [], $d + ['failback_now' => true]), wf_state_new('b1'));
    wf_check($t, 'fail back now with nothing pending says so', in_array('failback-now: no failback is pending', $r['plan']['log'], true));

    $s = wf_state_new('b1');
    $s['pending_failbacks']['WAN2'] = ['since' => 13000];
    $r = wf_plan(wf_t_snap(13010, [], [], $d), $s);
    wf_check($t, 'a failback queued by 1.1 (no countdown recorded) runs as it would have', isset($r['plan']['failback']['WAN2']));
    return wf_tally_report('planner', $t);
});
