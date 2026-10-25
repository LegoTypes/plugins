<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
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

/** @return array{now: int, boot_id: string, release: ?string, enabled: bool, dry: bool, failback: bool, default_gw: ?string, wans: array<string, array>, unresolved: list<string>, holds: array<string, array{boot: string, since: int}>, holds_stale: list<string>, holds_dupes: list<string>, force_down: array<string, bool>, contract: array{judging: list<string>, command: list<string>}} */
function wf_t_snap(int $now, array $primary, array $wan2, array $extra = []): array
{
    $wans = ['PRIMARY_WAN' => wf_t_wan('aaaaaaaa-0000-4000-8000-000000000001', '203.0.113.1', 1, $primary + ['if' => 'igc1', 'route_target' => '203.0.113.1@igc1']),
             'WAN2' => wf_t_wan('aaaaaaaa-0000-4000-8000-000000000002', '172.16.12.1', 2, $wan2 + ['if' => 'igc2', 'route_target' => '172.16.12.1@igc2'])];
    return array_merge(['now' => $now, 'boot_id' => 'b1', 'enabled' => true, 'failback' => true,
        'default_gw' => '203.0.113.1@igc1', 'wans' => $wans, 'unresolved' => [], 'holds' => [], 'holds_stale' => [], 'holds_dupes' => [],
        'legacy_held' => [], 'force_down' => array_map(fn (array $w): bool => $w['force_down'], $wans),
        'contract' => ['judging' => [], 'command' => []], 'dry' => false, 'release' => null,
        'failback_delay' => 0, 'failback_now' => false], $extra);
}

/**
 * One hold record as the snapshot resolves it; the default boot is wf_t_snap()'s live one.
 *
 * @return array<string, array{boot: string, since: int}>
 */
function wf_t_rec(string $name, string $boot = 'b1', int $since = 900): array
{
    return [$name => ['boot' => $boot, 'since' => $since]];
}

/** Two WANs with synthetic names on documentation addresses, in a snapshot whose live boot is b500. */
function wf_t_ab(int $now, array $a, array $b, array $extra = []): array
{
    $wans = ['WAN_A' => wf_t_wan('aaaaaaaa-0000-4000-8000-00000000000a', '192.0.2.1', 1, $a + ['if' => 'vtnet1', 'route_target' => '192.0.2.1@vtnet1']),
             'WAN_B' => wf_t_wan('aaaaaaaa-0000-4000-8000-00000000000b', '198.51.100.1', 2, $b + ['if' => 'vtnet2', 'route_target' => '198.51.100.1@vtnet2'])];
    return wf_t_snap($now, [], [], array_merge(['wans' => $wans, 'boot_id' => 'b500', 'default_gw' => '192.0.2.1@vtnet1',
        'force_down' => array_map(fn (array $w): bool => $w['force_down'], $wans)], $extra));
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
    wf_check($t, '1: hold WAN2, kill the states via its gateway and interface, default expected on PRIMARY', $r['plan']['hold'] === ['WAN2']
        && $r['plan']['held_after'] === ['WAN2'] && $r['plan']['write'] && $r['plan']['kill_targets'] === ['172.16.12.1@igc2']
        && $r['plan']['expected_default'] === '203.0.113.1@igc1');
    $s = wf_t_applied($r['state'], $r['plan']);

    $held = ['holds' => wf_t_rec('WAN2')];
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
        ['boot_id' => 'b2', 'holds' => wf_t_rec('WAN2')]), $s);
    wf_check($t, '12c: boot the hook missed -> every held gateway released, judgements reset', $r['plan']['release'] === ['WAN2']
        && $r['plan']['held_after'] === [] && $r['state']['boot_id'] === 'b2' && $r['state']['judgements'] === []);
    $s = wf_state_new('b1');
    $s['last_held'] = ['WAN2'];
    $r = wf_plan(wf_t_snap(3000, [], ['loss' => 30.0, 'force_down' => true, 'status' => 'force_down'],
        ['boot_time' => 1791270671, 'holds' => wf_t_rec('WAN2')]), $s);
    wf_check($t, 'same boot id, kern.boottime moved by a clock step: not a boot, the hold stays', $r['plan']['release'] === []
        && $r['plan']['held_after'] === ['WAN2'] && $r['state']['boot_id'] === 'b1');

    $r = wf_plan(wf_t_snap(4000, ['loss' => 30.0], ['force_down' => true, 'status' => 'force_down']), wf_state_new('b1'));
    wf_check($t, 'manual force_down: one alert, nothing released or held', count($r['plan']['alerts']) === 1
        && $r['plan']['release'] === [] && $r['plan']['hold'] === []);
    $r = wf_plan(wf_t_snap(4060, ['loss' => 30.0], ['force_down' => true, 'status' => 'force_down']), $r['state']);
    wf_check($t, 'manual force_down: no repeat alert within the hour', $r['plan']['alerts'] === []);

    $s = wf_state_new('b1');
    $s['last_held'] = ['WAN2'];
    $r = wf_plan(wf_t_snap(5000, [], ['loss' => 30.0], ['holds' => wf_t_rec('WAN2')]), $s);
    wf_check($t, '11: held but force_down=0 -> pruned from held, no re-hold yet', $r['plan']['hold'] === []
        && $r['plan']['held_after'] === [] && $r['plan']['write'] && isset($r['state']['no_rehold']['WAN2']));
    $s = wf_t_applied($r['state'], $r['plan']);
    $r = wf_plan(wf_t_snap(5060, [], ['loss' => 3.0]), $s);
    $r = wf_plan(wf_t_snap(5120, [], ['loss' => 30.0]), wf_t_applied($r['state'], $r['plan']));
    wf_check($t, '11: after reading up then over threshold, held again', $r['plan']['hold'] === ['WAN2']);

    $r = wf_plan(wf_t_snap(6000, [], ['loss' => 8.0]), wf_state_new('b1'));
    $r = wf_plan(wf_t_snap(6015, ['sock_age' => 12, 'loss' => 0.0], ['sock_age' => 40, 'loss' => 35.0]), $r['state']);
    wf_check($t, '3: the 10-05 pattern -- hold starts while PRIMARY is unsettled but fresh', $r['plan']['hold'] === ['WAN2']);

    $r = wf_plan(wf_t_snap(7000, [], [], ['unresolved' => ['bbbbbbbb-0000-4000-8000-00000000000f'], 'holds_stale' => ['cccccccc-0000-4000-8000-00000000000e']]), wf_state_new('b1'));
    wf_check($t, 'RF1: unresolvable wans entry and stale held UUID -> prune write, logged', $r['plan']['write']
        && count(array_filter($r['plan']['log'], fn (string $l): bool => str_contains($l, 'bbbbbbbb'))) === 1);

    $r = wf_plan(wf_t_snap(8000, [], []), wf_state_new('b1'));
    $r = wf_plan(wf_t_snap(8100, [], ['loss' => null, 'sock_age' => 3]), $r['state']);
    $r = wf_plan(wf_t_snap(4500, [], ['loss' => null, 'sock_age' => 3]), $r['state']);
    wf_check($t, 'RF5: clock back an hour keeps WAN2 clean and logs it', $r['state']['judgements']['WAN2']['value'] === WF_CLEAN
        && count(array_filter($r['plan']['log'], fn (string $l): bool => str_starts_with($l, 'clock moved back'))) === 1);

    $s = wf_state_new('b1');
    $s['last_held'] = ['WAN2'];
    $r = wf_plan(wf_t_snap(9000, [], ['loss' => 30.0, 'force_down' => true, 'status' => 'force_down'], ['holds' => wf_t_rec('WAN2'), 'enabled' => false]), $s);
    wf_check($t, '12b: disabled -> every held gateway released, nothing planned', $r['plan']['release'] === ['WAN2']
        && $r['plan']['hold'] === [] && $r['plan']['stopped']);

    $r = wf_plan(wf_t_snap(9050, [], [], ['enabled' => false]), wf_state_new('b1'));
    wf_check($t, 'disabled with nothing held logs nothing and plans nothing', $r['plan']['log'] === [] && !$r['plan']['acting']);

    $drift = ['holds' => wf_t_rec('WAN2'), 'contract' => ['judging' => ['dpinger_instances() rows lack current_losslow'], 'command' => []]];
    $r = wf_plan(wf_t_snap(9100, [], ['loss' => 30.0, 'force_down' => true, 'status' => 'force_down'], $drift), $s);
    wf_check($t, '12e: a judging drift that has not persisted (a reconfigure in flight) releases nothing', $r['plan']['release'] === [] && !$r['plan']['stopped']);
    $r = wf_plan(wf_t_snap(9281, [], ['loss' => 30.0, 'force_down' => true, 'status' => 'force_down'], $drift), $r['state']);
    wf_check($t, '12e: a judging drift persisting past unknown_max_seconds -> release all and stop', $r['plan']['release'] === ['WAN2'] && $r['plan']['stopped']);
    $r2 = wf_plan(wf_t_snap(9300, [], ['loss' => 30.0], ['contract' => ['judging' => ['x'], 'command' => []]]), wf_state_new('b1'));
    wf_check($t, '12e: a fresh judging drift blocks new holds', $r2['plan']['hold'] === []);
    $r = wf_plan(wf_t_snap(9200, [], ['loss' => 30.0], ['contract' => ['judging' => [], 'command' => ['[kill.state] changed']]]), wf_state_new('b1'));
    wf_check($t, '12e: command drift -> no new hold', $r['plan']['hold'] === [] && !$r['plan']['stopped']);

    $r = wf_plan(wf_t_snap(9300, [], ['force_down' => true, 'status' => 'force_down'], ['holds' => wf_t_rec('WAN2')]), wf_state_new('b1'));
    wf_check($t, '12f: held appeared outside the engine -> foreign re-sync', $r['plan']['foreign'] === ['WAN2']);

    $r = wf_plan(['wans' => ['PRIMARY_WAN' => wf_t_wan('aaaaaaaa-0000-4000-8000-000000000001', '203.0.113.1', 1)]]
        + wf_t_snap(9400, [], ['force_down' => true, 'status' => 'force_down'], ['holds' => wf_t_rec('WAN2'), 'force_down' => ['PRIMARY_WAN' => false, 'WAN2' => true]]), $s);
    wf_check($t, 'a held gateway removed from wans is released', $r['plan']['release'] === ['WAN2'] && $r['plan']['held_after'] === []);
    $s = wf_state_new('b1');
    $s['boot_note'] = 'boot: released WAN2';
    $r = wf_plan(wf_t_snap(9500, [], []), $s);
    wf_check($t, 'the early hook\'s note (syslog is not running yet at that point) is logged once by the first evaluation',
        in_array('boot: released WAN2', $r['plan']['log'], true) && $r['state']['boot_note'] === null);
    $s = wf_state_new('b1');
    $s['last_held'] = ['WAN2'];
    $r = wf_plan(wf_t_snap(9400, [], ['loss' => 30.0, 'force_down' => true, 'status' => 'force_down'], ['holds' => wf_t_rec('WAN2'), 'boot_id' => '']), $s);
    wf_check($t, 'an unreadable boot id is not a boot: the hold stays', $r['plan']['release'] === [] && $r['plan']['held_after'] === ['WAN2']
        && $r['state']['boot_id'] === 'b1');

    $s = wf_state_new('b1');
    $s['last_held'] = ['WAN2'];
    $r = wf_plan(wf_t_snap(9500, [], ['loss' => 30.0, 'force_down' => true, 'status' => 'force_down'], ['holds' => wf_t_rec('WAN2'), 'release' => 'requested']), $s);
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
    $r = wf_plan(wf_t_snap(12300, [], ['loss' => 30.0, 'force_down' => true, 'status' => 'force_down'], ['holds' => wf_t_rec('WAN2'), 'release' => 'dry']), $s);
    wf_check($t, 'dry turned on while really holding: the real hold is released', $r['plan']['release'] === ['WAN2'] && $r['plan']['held_after'] === []);
    /* failback delay: the recovered WAN must read clean for failback_delay seconds before its flows move back */
    $d = ['failback_delay' => 600];
    $s = wf_state_new('b1');
    $s['last_held'] = ['WAN2'];
    $r = wf_plan(wf_t_snap(13000, [], ['loss' => 0.0, 'force_down' => true, 'status' => 'force_down'], $d + ['holds' => wf_t_rec('WAN2')]), $s);
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

    /* a DHCP WAN that loses its link loses its gateway address with it (VM 2026-10-08: the hold ran
     * "filter kill gateway_states" with an empty address); its states still route-to the old address */
    $lost = ['carrier' => false, 'has_ipv4' => false, 'present' => false, 'loss' => null, 'sock_age' => null, 'gateway_ip' => ''];
    $r = wf_plan(wf_t_snap(14000, [], []), wf_state_new('b1'));
    $r = wf_plan(wf_t_snap(14060, $lost, []), $r['state']);
    wf_check($t, 'a WAN that lost its gateway address is held and its states killed by the last address it had, on its interface',
        $r['plan']['hold'] === ['PRIMARY_WAN'] && $r['plan']['kill_targets'] === ['203.0.113.1@igc1']);
    $r = wf_plan(wf_t_snap(14000, $lost, []), wf_state_new('b1'));
    wf_check($t, 'with no address ever seen, the kill is skipped and logged, never run without an address',
        $r['plan']['hold'] === ['PRIMARY_WAN'] && $r['plan']['kill_targets'] === []
        && in_array('kill states for PRIMARY_WAN skipped: no gateway address known', $r['plan']['log'], true));
    $r = wf_plan(wf_t_snap(14000, ['gateway_ip' => 'dynamic'] + $lost, []), wf_state_new('b1'));
    wf_check($t, 'a gateway value that is no address (an unresolved dynamic gateway) is neither learned nor used for a kill',
        $r['plan']['kill_targets'] === [] && !isset($r['state']['gateway_ips']['PRIMARY_WAN']));

    $s = wf_state_new('b1');
    $s['gateway_ips']['WAN2'] = '198.51.100.1';
    $r = wf_plan(wf_t_snap(14100, [], ['if' => 'vtnet2', 'route_target' => '@vtnet2'] + $lost), $s);
    wf_check($t, '(q1) a held WAN with no gateway address now is killed by its last address on its interface',
        $r['plan']['hold'] === ['WAN2'] && $r['plan']['kill_targets'] === ['198.51.100.1@vtnet2']);
    $shared = fn (string $uuid, int $rank, string $if): array => wf_t_wan($uuid, '192.0.2.1', $rank,
        ['if' => $if, 'route_target' => "192.0.2.1@{$if}", 'loss' => 30.0]);
    $three = ['WAN_A' => $shared('aaaaaaaa-0000-4000-8000-00000000000a', 1, 'vtnet1'),
              'WAN_B' => $shared('aaaaaaaa-0000-4000-8000-00000000000b', 2, 'vtnet2'),
              'WAN_C' => wf_t_wan('aaaaaaaa-0000-4000-8000-00000000000c', '198.51.100.1', 3,
                  ['if' => 'vtnet3', 'route_target' => '198.51.100.1@vtnet3'])];
    $r = wf_plan(wf_t_snap(14200, [], [], ['wans' => $three, 'default_gw' => '192.0.2.1@vtnet1',
        'force_down' => ['WAN_A' => false, 'WAN_B' => false, 'WAN_C' => false]]), wf_state_new('b1'));
    wf_check($t, '(q2) two held WANs that share a gateway address get one kill target each, told apart by interface',
        $r['plan']['hold'] === ['WAN_A', 'WAN_B'] && $r['plan']['kill_targets'] === ['192.0.2.1@vtnet1', '192.0.2.1@vtnet2']);
    $r = wf_plan(wf_t_snap(14300, [], ['loss' => 30.0, 'if' => 'vt;1', 'route_target' => '172.16.12.1@vt;1']), wf_state_new('b1'));
    $skips = array_filter($r['plan']['log'], fn (string $l): bool => str_starts_with($l, 'kill states for WAN2'));
    wf_check($t, '(q3) a kill target whose interface is not a plain name is skipped with one line',
        $r['plan']['hold'] === ['WAN2'] && $r['plan']['kill_targets'] === [] && count($skips) === 1);

    /* ownership: a record proves a hold only by the boot that took it; b500 is the live boot, b400 the one before */
    $fdB = ['force_down' => true, 'status' => 'force_down'];
    $foreignLine = 'hold record for WAN_B from another boot or box; not ours, left alone';
    $lines = fn (array $plan, string $part): int => count(array_filter($plan['log'], fn (string $l): bool => str_contains($l, $part)));

    $s = wf_state_new('b500');
    $s['last_held'] = ['WAN_A', 'WAN_B'];
    $unread = ['boot_id' => '', 'holds' => wf_t_rec('WAN_A', 'deadbeef') + wf_t_rec('WAN_B', 'b500')];
    $r = wf_plan(wf_t_ab(30000, [], $fdB, $unread), $s);
    $r2 = wf_plan(wf_t_ab(30060, [], $fdB, $unread), $r['state']);
    wf_check($t, '(o7) with the live boot id unreadable a loss-free record of this boot is not released, one released by hand '
        . 'and one of another boot are not pruned, nothing is written, no alert; one line, not repeated next tick',
        $r['plan']['release'] === [] && !$r['plan']['write'] && $r['plan']['kill_targets'] === [] && $r['plan']['alerts'] === []
        && $r['plan']['records_after'] === $unread['holds'] && $lines($r['plan'], 'kern.boot_id') === 1
        && $lines($r2['plan'], 'kern.boot_id') === 0 && !$r2['plan']['write']);

    $s = wf_state_new('corrupt');
    $r = wf_plan(wf_t_ab(30100, [], ['loss' => 30.0] + $fdB, ['holds' => wf_t_rec('WAN_B', 'b500')]), $s);
    wf_check($t, '(o8) with the state unreadable a record of the live boot is released, never pruned as foreign',
        $r['plan']['release'] === ['WAN_B'] && $r['plan']['stopped'] && $r['plan']['expected'] === ['WAN_B' => true]
        && $lines($r['plan'], 'another boot') === 0 && $r['state']['foreign_pruned'] === [] && $r['state']['boot_id'] === 'b500');

    $s = wf_state_new('b500');
    $s['last_held'] = ['WAN_B'];
    $r = wf_plan(wf_t_ab(30200, [], ['loss' => 30.0] + $fdB, ['holds' => wf_t_rec('WAN_B', 'b500', 200), 'holds_dupes' => ['WAN_B']]), $s);
    wf_check($t, '(o9) a duplicate record is pruned with one line, the hold kept, no gateway changed',
        $r['plan']['write'] && $r['plan']['release'] === [] && $r['plan']['hold'] === [] && $r['plan']['expected'] === []
        && $r['plan']['records_after'] === wf_t_rec('WAN_B', 'b500', 200) && $lines($r['plan'], 'WAN_B') === 1
        && $lines($r['plan'], 'second hold record for WAN_B') === 1);

    $s = wf_state_new('b500');
    $r = wf_plan(wf_t_ab(30300, [], $fdB, ['holds' => wf_t_rec('WAN_B', 'deadbeef')]), $s);
    $s2 = wf_t_applied($r['state'], $r['plan']);
    $r2 = wf_plan(wf_t_ab(30360, [], $fdB), $s2);
    wf_check($t, '(p1) a loss-free gateway with a foreign record is not released: the record is pruned, nothing killed, '
        . 'force_down left; the next tick writes nothing',
        $r['plan']['release'] === [] && $r['plan']['hold'] === [] && $r['plan']['write'] && $r['plan']['kill_targets'] === []
        && $r['plan']['records_after'] === [] && $r['plan']['expected'] === [] && in_array($foreignLine, $r['plan']['log'], true)
        && $r2['plan']['release'] === [] && !$r2['plan']['write'] && $r2['plan']['kill_targets'] === []);

    $snap = wf_t_ab(30400, [], ['loss' => 30.0] + $fdB, ['holds' => wf_t_rec('WAN_B', 'b500')]);
    unset($snap['wans']['WAN_B']);
    $s = wf_state_new('b500');
    $s['last_held'] = ['WAN_B'];
    $r = wf_plan($snap, $s);
    wf_check($t, '(p2) an owned hold whose WAN left the managed WANs is still released',
        $r['plan']['release'] === ['WAN_B'] && $r['plan']['records_after'] === [] && $r['plan']['expected'] === ['WAN_B' => true]);

    $s = wf_state_new('b500');
    $s['last_held'] = ['WAN_A', 'WAN_B'];
    $r = wf_plan(wf_t_ab(30500, ['loss' => 30.0] + $fdB, $fdB, ['enabled' => false,
        'holds' => wf_t_rec('WAN_A', 'b500') + wf_t_rec('WAN_B', 'deadbeef')]), $s);
    wf_check($t, '(p3) the plugin disabled releases its own hold only, and prunes the foreign record',
        $r['plan']['release'] === ['WAN_A'] && $r['plan']['stopped'] && $r['plan']['write'] && $r['plan']['records_after'] === []
        && $r['plan']['expected'] === ['WAN_A' => true] && in_array($foreignLine, $r['plan']['log'], true));

    $s = wf_state_new('b500');
    $s['last_held'] = ['WAN_A', 'WAN_B'];
    $r = wf_plan(wf_t_ab(30550, ['loss' => 30.0] + $fdB, $fdB, ['enabled' => false, 'release' => 'removal',
        'holds' => wf_t_rec('WAN_A', 'b500') + wf_t_rec('WAN_B', 'deadbeef')]), $s);
    wf_check($t, '(d3) the package removal\'s stopped plan releases its own hold only, prunes the foreign record, kills '
        . 'nothing, and says why',
        $r['plan']['release'] === ['WAN_A'] && $r['plan']['hold'] === [] && $r['plan']['stopped'] && $r['plan']['write']
        && $r['plan']['records_after'] === [] && $r['plan']['expected'] === ['WAN_A' => true] && $r['plan']['kill_targets'] === []
        && $r['plan']['failback'] === [] && in_array($foreignLine, $r['plan']['log'], true)
        && in_array('releasing every held gateway: package removal', $r['plan']['log'], true));

    $s = wf_state_new('b400');
    $s['last_held'] = ['WAN_A', 'WAN_B'];
    $r = wf_plan(wf_t_ab(30600, ['loss' => 30.0] + $fdB, $fdB, ['holds' => wf_t_rec('WAN_A', 'b400') + wf_t_rec('WAN_B', 'deadbeef')]), $s);
    wf_check($t, '(p4) the boot detector releases the previous boot\'s records and prunes the others',
        $r['plan']['release'] === ['WAN_A'] && $r['plan']['records_after'] === [] && $r['state']['boot_id'] === 'b500'
        && in_array($foreignLine, $r['plan']['log'], true) && $r['plan']['foreign'] === []);

    $r = wf_plan(wf_t_ab(30700, [], ['loss' => 30.0]), wf_state_new('b500'));
    wf_check($t, '(p5) a new hold\'s record is stamped with the live boot and now, and its expected force_down is 0',
        $r['plan']['hold'] === ['WAN_B'] && $r['plan']['records_after'] === wf_t_rec('WAN_B', 'b500', 30700)
        && $r['plan']['expected'] === ['WAN_B' => false] && $r['plan']['held_after'] === ['WAN_B']);
    $s = wf_state_new('b500');
    $s['last_held'] = ['WAN_B'];
    $r = wf_plan(wf_t_ab(30760, [], ['loss' => 5.0] + $fdB, ['holds' => wf_t_rec('WAN_B', 'b500', 777)]), $s);
    wf_check($t, '(p5) an owned hold that stays keeps its record\'s boot and since', $r['plan']['records_after'] === wf_t_rec('WAN_B', 'b500', 777)
        && !$r['plan']['write']);

    $r = wf_plan(wf_t_ab(31000, [], $fdB, ['holds' => wf_t_rec('WAN_B', 'deadbeef')]), wf_state_new('b500'));
    $s0 = wf_t_applied($r['state'], $r['plan']);
    $kept = wf_plan(wf_t_ab(34599, [], $fdB), $s0)['state']['foreign_pruned'];
    $gone = wf_plan(wf_t_ab(34600, [], $fdB), $s0)['state']['foreign_pruned'];
    $up = wf_plan(wf_t_ab(31060, [], []), $s0)['state']['foreign_pruned'];
    wf_check($t, '(p6) a pruned foreign record is shown for 3599 s, not at 3600 s, and not once its gateway reads force_down 0',
        $s0['foreign_pruned'] === ['WAN_B' => 31000] && $kept === ['WAN_B' => 31000] && $gone === [] && $up === []);

    /* the rows the writer leaves are the plan's records_after, so a third tick over them still owns the hold: rows as
     * Holds::records() gives them (in config order), resolved, planned, written, resolved and planned again */
    $byUuid = ['aaaaaaaa-0000-4000-8000-00000000000a' => 'WAN_A', 'aaaaaaaa-0000-4000-8000-00000000000b' => 'WAN_B'];
    $uuidB = 'aaaaaaaa-0000-4000-8000-00000000000b';
    $item = fn (int $i): string => sprintf('cccccccc-0000-4000-8000-%012d', $i);
    $tick = function (int $now, array $wanB, array $rows, array $state) use ($byUuid): array {
        $res = wf_resolve_records($rows, $byUuid);
        return wf_plan(wf_t_ab($now, [], $wanB, ['holds' => $res['holds'], 'holds_stale' => $res['stale'],
            'holds_dupes' => $res['dupes']]), $state);
    };
    $written = function (array $plan) use ($byUuid, $item): array {
        $rows = [];
        foreach (wf_holds_rows($plan['records_after'], array_flip($byUuid))['rows'] as $i => $row) {
            $rows[$item(100 + $i)] = $row;
        }
        return $rows;
    };
    $owns = fn (array $rows): array => wf_reconcile(wf_resolve_records($rows, $byUuid)['holds'], ['WAN_A' => false, 'WAN_B' => true],
        [], ['WAN_B'], 'b500');

    $s = wf_state_new('b500');
    $s['last_held'] = ['WAN_B'];
    $planted = [$item(1) => ['gateway' => $uuidB, 'boot' => 'deadbeef', 'since' => 100],
                $item(2) => ['gateway' => $uuidB, 'boot' => 'b500', 'since' => 200]];
    $r = $tick(32000, ['loss' => 30.0] + $fdB, $planted, $s);
    $rows = $written($r['plan']);
    $r3 = $tick(32060, ['loss' => 30.0] + $fdB, $rows, wf_t_applied($r['state'], $r['plan']));
    $own = $owns($rows);
    wf_check($t, '(r1) two rows for one held gateway, the older foreign one first: the write leaves only the plan\'s own '
        . 'record (boot and since), and a third tick still owns the hold, prunes nothing and logs no foreign record',
        $r['plan']['write'] && $r['plan']['records_after'] === wf_t_rec('WAN_B', 'b500', 200)
        && array_values($rows) === [['gateway' => $uuidB, 'boot' => 'b500', 'since' => 200]]
        && $own['owned'] === ['WAN_B'] && $own['foreign_records'] === []
        && !$r3['plan']['write'] && $r3['plan']['release'] === [] && $lines($r3['plan'], 'another boot') === 0);

    $planted = [$item(3) => ['gateway' => $uuidB, 'boot' => 'deadbeef', 'since' => 100]];
    $r = $tick(32100, ['loss' => 30.0], $planted, wf_state_new('b500'));
    $rows = $written($r['plan']);
    $r3 = $tick(32160, ['loss' => 30.0] + $fdB, $rows, wf_t_applied($r['state'], $r['plan']));
    $own = $owns($rows);
    wf_check($t, '(r2) a foreign record pruned and its lossy gateway held anew in one plan: the write leaves only the new '
        . 'record (the live boot, now), and a third tick still owns the hold, prunes nothing and logs no foreign record',
        $r['plan']['hold'] === ['WAN_B'] && $r['plan']['expected'] === ['WAN_B' => false]
        && $r['plan']['records_after'] === wf_t_rec('WAN_B', 'b500', 32100) && in_array($foreignLine, $r['plan']['log'], true)
        && wf_write_guard(['WAN_B' => true], $r['plan']['expected'], ['WAN_A' => false, 'WAN_B' => false]) === []
        && array_values($rows) === [['gateway' => $uuidB, 'boot' => 'b500', 'since' => 32100]]
        && $own['owned'] === ['WAN_B'] && $own['foreign_records'] === []
        && !$r3['plan']['write'] && $r3['plan']['hold'] === [] && $r3['plan']['release'] === [] && $lines($r3['plan'], 'another boot') === 0);

    $view = wf_dry_view(wf_t_ab(31100, [], []), ['WAN_B']);
    $exit = wf_dry_exit(['dry_held' => ['WAN_B']] + wf_state_new('b500'), wf_t_ab(31100, [], [], ['holds' => wf_t_rec('WAN_A', 'deadbeef')]));
    wf_check($t, '(d1) a dry run simulates its holds as records of the live boot; leaving it takes the real records\' names',
        $view['holds'] === wf_t_rec('WAN_B', 'b500', 31100) && $view['force_down']['WAN_B'] && $exit['last_held'] === ['WAN_A']
        && $exit['dry_held'] === []);

    /* 1.3_1's held list still in the config after the evaluation's import (it failed, or waits for kern.boot_id): WAN_B
     * forced down with no record, as the upgrade window leaves it, and last_held from 1.3_1 naming it */
    $s = wf_state_new('b500');
    $s['last_held'] = ['WAN_B'];
    $pending = ['legacy_held' => ['WAN_B']];
    $r = wf_plan(wf_t_ab(31200, [], ['loss' => 30.0] + $fdB, $pending), $s);
    $r2 = wf_plan(wf_t_ab(31260, [], ['loss' => 30.0] + $fdB, $pending), $r['state']);
    wf_check($t, '(u1) a forced-down gateway 1.3_1\'s held list still names raises no unowned alert and no re-sync, though '
        . 'last_held names it; nothing is released, held or written; one line, not repeated next tick',
        $r['plan']['alerts'] === [] && $r['plan']['foreign'] === [] && $r['plan']['release'] === [] && $r['plan']['hold'] === []
        && !$r['plan']['write'] && $lines($r['plan'], "1.3_1's held list is still in the config for WAN_B") === 1
        && $lines($r['plan'], 'outside the engine') === 0
        && $r2['plan']['alerts'] === [] && $lines($r2['plan'], "1.3_1's held list") === 0);
    $r3 = wf_plan(wf_t_ab(31320, [], ['loss' => 30.0] + $fdB), $r2['state']);
    wf_check($t, '(u1) once the list is gone with no record made, the gateway forced down is alerted on',
        count($r3['plan']['alerts']) === 1 && str_starts_with($r3['plan']['alerts'][0], 'unowned-force-down WAN_B'));
    $r = wf_plan(wf_t_ab(31400, [], ['loss' => 30.0], ['legacy_held' => ['WAN_B']]), wf_state_new('b500'));
    wf_check($t, '(u2) a gateway the list names but that is not forced down is planned as any other: a lossy one is held',
        $r['plan']['hold'] === ['WAN_B'] && $r['plan']['legacy_held'] === ['WAN_B']);
    wf_check($t, '(u3) a write while the list waits keeps the proof of its entries in last_held, and never adds one',
        wf_last_held(['WAN_A'], ['WAN_B', 'WAN_C'], ['WAN_B', 'WAN_D']) === ['WAN_A', 'WAN_B']
        && wf_last_held([], [], ['WAN_B']) === [] && wf_last_held(['WAN_A'], ['WAN_B'], []) === ['WAN_A']);

    /* every state the planner and apply write loads back as saved: a state wrongly found corrupt releases every hold */
    $b = ['gateway_ip' => '198.51.100.1', 'route_target' => '198.51.100.1@igc2'];
    $at = fn (int $now, array $a, array $wanB, array $extra = []): array => wf_t_snap($now, $a, $wanB + $b, $extra);
    $fd = ['force_down' => true, 'status' => 'force_down'];
    $held = ['holds' => wf_t_rec('WAN2')];
    $produced = [];
    $r = wf_plan($at(20000, [], ['loss' => 30.0], ['unresolved' => ['bbbbbbbb-0000-4000-8000-00000000000f']]), wf_state_new('b1'));
    $produced['a hold, as apply saves it before its config write'] = array_merge($r['state'], ['apply_pending' => ['WAN2' => 'hold']]);
    $s = wf_t_applied($r['state'], $r['plan']);
    $s['ts'] = wf_tailscale_decide($s['ts'], '203.0.113.1@igc1', 20000, WF_TS_STABLE_SECONDS, WF_TS_COOLDOWN_SECONDS)['ts'];
    $produced['held, with a Tailscale default'] = $s;
    $r = wf_plan($at(20060, [], ['loss' => 5.0] + $fd, $held), $s);
    $produced['held at a marginal loss'] = $r['state'];
    $r = wf_plan($at(20120, [], ['loss' => 0.0] + $fd, $held + ['failback_delay' => 600]), $r['state']);
    $produced['released, its failback counting down'] = $s = wf_t_applied($r['state'], $r['plan']);
    $r = wf_plan($at(20180, [], [], ['failback_delay' => 600, 'failback_now' => true]), $s);
    $produced['its failback due'] = $r['state'];
    $produced['force_down set by hand'] = wf_plan($at(20300, ['loss' => 30.0], $fd), wf_state_new('b1'))['state'];
    $s = wf_state_new('b1');
    $s['last_held'] = ['WAN2'];
    $r = wf_plan($at(20400, [], ['loss' => 30.0], $held), $s);
    $produced['released by hand, not re-held'] = wf_t_applied($r['state'], $r['plan']);
    $r = wf_plan(wf_dry_view($at(20500, [], ['loss' => 30.0], ['dry' => true]), []), wf_state_new('b1'));
    $produced['a simulated hold'] = wf_dry_after($r['state'], $r['plan']);
    $produced['a foreign record pruned'] = wf_plan(wf_t_ab(20600, [], $fd, ['holds' => wf_t_rec('WAN_B', 'deadbeef')]), wf_state_new('b500'))['state'];
    $all = array_values($produced);
    $any = fn (callable $f): bool => array_filter($all, $f) !== [];
    wf_check($t, 'the round-trip states cover every nested field: apply_pending, ts, a failback counting and one due, '
        . 'an unowned alert, no_rehold, dry_held, said, a fractional settled loss, a foreign record pruned',
        $any(fn (array $x): bool => $x['foreign_pruned'] !== []) &&
        $any(fn (array $x): bool => $x['apply_pending'] !== []) && $any(fn (array $x): bool => $x['ts']['default_gw'] !== null)
        && $any(fn (array $x): bool => isset($x['pending_failbacks']['WAN2']) && $x['pending_failbacks']['WAN2']['due'] === null)
        && $any(fn (array $x): bool => is_int($x['pending_failbacks']['WAN2']['due'] ?? null))
        && $any(fn (array $x): bool => $x['unowned_alerted_at'] !== []) && $any(fn (array $x): bool => $x['no_rehold'] !== [])
        && $any(fn (array $x): bool => $x['dry_held'] !== []) && $any(fn (array $x): bool => $x['said'] !== [])
        && $any(fn (array $x): bool => ($x['judgements']['WAN2']['last_settled_loss'] ?? null) === 5.0));
    $dir = rtrim(sys_get_temp_dir(), '/') . '/wf-test-roundtrip-' . getmypid();
    foreach ($produced as $what => $state) {
        wf_state_save("{$dir}/state.json", $state);
        $l = wf_state_load("{$dir}/state.json", 'b9');
        wf_check($t, "a state the planner writes loads back as saved, not corrupt: {$what}",
            !$l['corrupt'] && json_encode($l['state']) === json_encode($state));
    }
    @unlink("{$dir}/state.json");
    @rmdir($dir);
    return wf_tally_report('planner', $t);
});
