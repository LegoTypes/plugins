<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The planner (spec sections 3.2 to 3.4, 3.10 and the section 5 planner list; Review Focus 2 to 4).
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/planner.php';
require_once __DIR__ . '/test_verdict.php';
require_once __DIR__ . '/test_zone.php';
require_once __DIR__ . '/test_choose.php';
require_once __DIR__ . '/test_contract.php';

/**
 * Two members, wg-a tier 1 and wg-b tier 2, both settled with no loss; Unbound running on the configured DoT
 * root; no resolver route. Cases override fields directly.
 *
 * @return array{now: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, failback_delay: int,
 *         probe_name: string},
 *     trigger: string, tiers: list<list<string>>,
 *     members: array<string, array{name: string, interface: string, if: string, next_hop: string, disabled: bool,
 *         force_down: bool, monitor_disable: bool, monitor: string, time_period: int, interval: int,
 *         loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool},
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, resolver_is_monitor: list<string>, resolver_in_static: list<string>,
 *         unmonitored_members: list<string>, foreign_route: bool,
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int}}
 */
function uu_test_snapshot(): array
{
    $a = uu_test_member();
    $a['monitor'] = '192.0.2.1';
    $b = uu_test_member();
    $b['name'] = 'wg-b';
    $b['interface'] = 'opt2';
    $b['if'] = 'wg2';
    $b['next_hop'] = '10.2.0.6';
    $b['monitor'] = '192.0.2.2';
    $zone = uu_root_zone([uu_test_fixture('dot_dot.conf')]);
    $contract = uu_test_contract_input();
    $contract['zone'] = $zone;
    $contract['fib_sync_ms'] = 1000;
    return [
        'now' => 10000,
        'settings' => ['enabled' => true, 'dry_run' => false, 'group' => 'grp_test', 'resolver' => '10.2.0.1',
                       'failback_delay' => 120, 'probe_name' => '.'],
        'trigger' => 'downloss',
        'tiers' => [['wg-a'], ['wg-b']],
        'members' => ['wg-a' => $a, 'wg-b' => $b],
        'probes' => ['wg-a' => uu_test_probe('none', '0.0 %', 300), 'wg-b' => uu_test_probe('none', '0.0 %', 300)],
        'named' => [],
        'unbound' => ['enabled' => true, 'pid_alive' => true, 'control_ok' => true, 'live_root' => $zone['addrs']],
        'zone' => $zone,
        'route' => ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false, 'ours' => false],
        'fib_sync_ms' => 1000,
        'contract_input' => $contract,
    ];
}

/**
 * The snapshot as tunnel mode through a member leaves it: the resolver is the live root and our route points at
 * the member.
 *
 * @param array{now: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, failback_delay: int,
 *         probe_name: string},
 *     trigger: string, tiers: list<list<string>>,
 *     members: array<string, array{name: string, interface: string, if: string, next_hop: string, disabled: bool,
 *         force_down: bool, monitor_disable: bool, monitor: string, time_period: int, interval: int,
 *         loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool},
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, resolver_is_monitor: list<string>, resolver_in_static: list<string>,
 *         unmonitored_members: list<string>, foreign_route: bool,
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int}} $s
 * @return array{now: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, failback_delay: int,
 *         probe_name: string},
 *     trigger: string, tiers: list<list<string>>,
 *     members: array<string, array{name: string, interface: string, if: string, next_hop: string, disabled: bool,
 *         force_down: bool, monitor_disable: bool, monitor: string, time_period: int, interval: int,
 *         loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool},
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, resolver_is_monitor: list<string>, resolver_in_static: list<string>,
 *         unmonitored_members: list<string>, foreign_route: bool,
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int}}
 */
function uu_test_in_tunnel(array $s, string $member): array
{
    $s['unbound']['live_root'] = [$s['settings']['resolver']];
    $s['route'] = ['present' => true, 'gateway' => $s['members'][$member]['next_hop'],
                   'interface' => $s['members'][$member]['if'], 'reject' => false, 'ours' => true];
    return $s;
}

/**
 * A state in tunnel mode on the member, or in fallback when it is null.
 *
 * @param array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *                            probe_failures: int}> $timers
 * @return array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int}>, control_failures: int, control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int}
 */
function uu_test_plan_state(
    ?string $member,
    array $timers = [],
    int $controlFailures = 0,
    ?int $silentSince = null
): array {
    $st = uu_state_new();
    $st['mode'] = $member === null ? 'fallback' : 'tunnel';
    $st['member'] = $member;
    $st['timers'] = $timers;
    $st['control_failures'] = $controlFailures;
    $st['control_silent_since'] = $silentSince;
    return $st;
}

/**
 * @param list<string> $reasons
 */
function uu_test_reason_has(array $reasons, string ...$needles): bool
{
    foreach ($reasons as $reason) {
        $all = true;
        foreach ($needles as $needle) {
            $all = $all && str_contains($reason, $needle);
        }
        if ($all) {
            return true;
        }
    }
    return false;
}

uu_register_suite('planner', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $now = 10000;
    $settledDown = uu_test_probe('down', '100.0 %', 300);
    $usable = ['wg-a' => uu_test_timer(500, null, $now - 60), 'wg-b' => uu_test_timer(500, null, $now - 60)];

    // Entering from fallback needs failback_delay seconds of settled usable readings.
    $s = uu_test_snapshot();
    $p = uu_plan($s, uu_test_plan_state(null, ['wg-a' => uu_test_timer(60, null, $now - 60)]));
    uu_check($t, 'fallback, wg-a settled 120 s → tunnel [wg-a]',
        $p['action'] === 'tunnel' && $p['candidates'] === ['wg-a'] && !$p['reassert'] && !$p['route_repair']
        && !$p['escalate_restart'] && $p['state']['timers']['wg-a']['counted'] === 120
        && $p['state']['timers']['wg-b']['counted'] === 0
        && uu_test_reason_has($p['reasons'], 'wg-a', '120 s', 'downloss'));
    $p = uu_plan($s, uu_test_plan_state(null, ['wg-a' => uu_test_timer(59, null, $now - 60)]));
    uu_check($t, 'fallback, wg-a settled 119 s → none, no candidates; reject route planned (route absent)',
        $p['action'] === 'none' && $p['candidates'] === [] && $p['route_repair'] && !$p['reassert']);
    $s2 = $s;
    $s2['route'] = ['present' => true, 'gateway' => '127.0.0.1', 'interface' => 'lo0', 'reject' => true,
                    'ours' => true];
    $p = uu_plan($s2, uu_test_plan_state(null));
    uu_check($t, 'fallback with our reject route → none, no route repair',
        $p['action'] === 'none' && !$p['route_repair'] && $p['state']['mode'] === 'fallback');

    // Leaving.
    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['probes']['wg-a'] = $settledDown;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'tunnel on wg-a, wg-a settled down → tunnel [wg-b]',
        $p['action'] === 'tunnel' && $p['candidates'] === ['wg-b'] && !$p['route_repair'] && !$p['reassert']
        && $p['state']['timers']['wg-a']['counted'] === 0
        && uu_test_reason_has($p['reasons'], 'wg-a', 'settled down', 'downloss')
        && uu_test_reason_has($p['reasons'], 'wg-b'));

    $s['probes']['wg-b'] = $settledDown;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'tunnel on wg-a, both down → fallback',
        $p['action'] === 'fallback' && $p['candidates'] === []
        && uu_test_reason_has($p['reasons'], 'wg-a', 'settled down', 'downloss')
        && uu_test_reason_has($p['reasons'], 'wg-b', 'settled down'));

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['probes']['wg-a'] = uu_test_probe('down', '25.0 %', 8);
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'tunnel on wg-a, wg-a young 25 % → none (no false leave)',
        $p['action'] === 'none' && $p['candidates'] === ['wg-a', 'wg-b'] && !$p['route_repair'] && !$p['reassert']
        && $p['state']['timers']['wg-a']['counted'] === 500);

    $s['probes']['wg-a'] = uu_test_probe('down', '~', null);
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'tunnel on wg-a, wg-a ~ with no watcher cache → none, no verdict',
        $p['action'] === 'none' && $p['candidates'] === ['wg-a', 'wg-b']);

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['members']['wg-a']['force_down'] = true;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'tunnel on wg-a, wg-a force_down → tunnel [wg-b] at once',
        $p['action'] === 'tunnel' && $p['candidates'] === ['wg-b']
        && uu_test_reason_has($p['reasons'], 'wg-a', 'force_down'));

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['probes']['wg-a'] = uu_test_probe('none', '0.0 %', 6, 'down');
    $s['named'] = ['wg-a'];
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'named wg-a with watcher down, dpinger has data → tunnel [wg-b]',
        $p['action'] === 'tunnel' && $p['candidates'] === ['wg-b']
        && uu_test_reason_has($p['reasons'], 'wg-a', 'watcher down'));
    $s['named'] = [];
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'the same watcher down without the monitor hook naming wg-a → none',
        $p['action'] === 'none' && $p['candidates'][0] === 'wg-a');

    // Reconcile.
    $s = uu_test_snapshot();
    $s['unbound']['live_root'] = ['10.2.0.1'];
    $s['probes']['wg-a'] = uu_test_probe('none', '0.0 %', 6, 'none');
    $s['probes']['wg-b'] = uu_test_probe('none', '0.0 %', 6, 'none');
    $s['named'] = ['wg-a', 'wg-b'];
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'named healthy wg-a (device recreation), route absent → none + route_repair',
        $p['action'] === 'none' && $p['candidates'] === ['wg-a'] && $p['route_repair'] && !$p['reassert']
        && $p['state']['member'] === 'wg-a');

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['route']['reject'] = true;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'tunnel on wg-a, our route carries reject → none + route_repair',
        $p['action'] === 'none' && $p['route_repair']);
    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-b');
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'tunnel on wg-a, our route points at wg-b → none + route_repair',
        $p['action'] === 'none' && $p['route_repair']);
    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['route']['interface'] = 'wg2';
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'tunnel on wg-a, our route has wg-a\'s next hop on another device → route_repair',
        $p['action'] === 'none' && $p['route_repair']);

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['unbound']['live_root'] = $s['zone']['addrs'];
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'tunnel mode, live root = configured DoT (Unbound restarted) → reassert',
        $p['action'] === 'none' && $p['reassert'] && !$p['route_repair'] && $p['candidates'][0] === 'wg-a'
        && $p['state']['mode'] === 'tunnel' && $p['state']['member'] === 'wg-a');

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'tunnel on wg-a, everything in place → none, candidates in full for apply',
        $p['action'] === 'none' && $p['candidates'] === ['wg-a', 'wg-b'] && !$p['reassert'] && !$p['route_repair']
        && !$p['escalate_restart']);

    // Returning to a better tier.
    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-b');
    $p = uu_plan($s, uu_test_plan_state('wg-b', ['wg-a' => uu_test_timer(59, null, $now - 60)]));
    uu_check($t, 'on wg-b, wg-a usable 119 s → stays on wg-b',
        $p['action'] === 'none' && $p['candidates'] === ['wg-b']);
    $p = uu_plan($s, uu_test_plan_state('wg-b', ['wg-a' => uu_test_timer(60, null, $now - 60)]));
    uu_check($t, 'on wg-b, wg-a usable 120 s → tunnel [wg-a, wg-b] (return, wg-b next)',
        $p['action'] === 'tunnel' && $p['candidates'] === ['wg-a', 'wg-b']
        && uu_test_reason_has($p['reasons'], 'wg-a', '120 s'));
    $p = uu_plan($s, uu_test_plan_state('wg-b', ['wg-a' => uu_test_timer(500, $now + 30, $now - 60)]));
    uu_check($t, 'on wg-b, wg-a past the delay but resolver-failed → stays on wg-b',
        $p['action'] === 'none' && $p['candidates'] === ['wg-b']);

    // Contract.
    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['contract_input']['fib_sync_ms'] = null;
    $s['fib_sync_ms'] = null;
    $inTunnel = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $s = uu_test_snapshot();
    $s['contract_input']['fib_sync_ms'] = null;
    $s['fib_sync_ms'] = null;
    $inFallback = uu_plan($s, uu_test_plan_state(null, $usable));
    uu_check($t, 'contract failure in tunnel → fallback; in fallback → none',
        $inTunnel['action'] === 'fallback' && $inFallback['action'] === 'none'
        && uu_test_reason_has($inTunnel['reasons'], 'fib sync delay unreadable')
        && uu_test_reason_has($inFallback['reasons'], 'fib sync delay unreadable'));

    $s = uu_test_snapshot();
    $s['route'] = ['present' => true, 'gateway' => '192.168.1.254', 'interface' => 'igc0', 'reject' => false,
                   'ours' => false];
    $s['contract_input']['foreign_route'] = true;
    $p = uu_plan($s, uu_test_plan_state(null, $usable));
    uu_check($t, 'a route the plugin did not make → none, never repaired',
        $p['action'] === 'none' && !$p['route_repair'] && uu_test_reason_has($p['reasons'], 'resolver route not ours'));

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['contract_input']['cacheflush'] = true;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'cacheflush on is a note, not a failure: tunnel stays',
        $p['action'] === 'none' && $p['candidates'][0] === 'wg-a');

    // Control channel.
    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['unbound']['control_ok'] = false;
    $s['unbound']['live_root'] = null;
    $p1 = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $s['now'] = $now + 60;
    $p2 = uu_plan($s, $p1['state']);
    $s['now'] = $now + UU_ESCALATE_MIN_SECONDS;
    $p3 = uu_plan($s, $p2['state']);
    $s4 = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s4['now'] = $now + 60;
    $p4 = uu_plan($s4, $p2['state']);
    uu_check($t, 'control silent once → skip; three evaluations in tunnel with live pid → escalate_restart',
        $p1['action'] === 'skip' && !$p1['escalate_restart'] && $p1['state']['control_failures'] === 1
        && $p1['state']['control_silent_since'] === $now
        && $p2['action'] === 'skip' && !$p2['escalate_restart'] && $p2['state']['control_failures'] === 2
        && $p2['state']['control_silent_since'] === $now
        && $p3['action'] === 'skip' && $p3['escalate_restart'] && $p3['state']['control_failures'] === 0
        && $p3['state']['control_silent_since'] === null
        && $p3['state']['mode'] === 'tunnel' && $p3['state']['member'] === 'wg-a'
        && uu_test_reason_has($p3['reasons'], 'restart')
        && $p4['action'] === 'none' && $p4['state']['control_failures'] === 0
        && $p4['state']['control_silent_since'] === null);

    $s['now'] = $now;
    $q1 = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $s['now'] = $now + 20;
    $q2 = uu_plan($s, $q1['state']);
    $s['now'] = $now + 40;
    $q3 = uu_plan($s, $q2['state']);
    $s['now'] = $now + UU_ESCALATE_MIN_SECONDS;
    $q4 = uu_plan($s, $q3['state']);
    uu_check($t, 'three silent evaluations 20 s apart → no escalation; the fourth at 120 s → escalation',
        $q3['action'] === 'skip' && !$q3['escalate_restart'] && $q3['state']['control_failures'] === 3
        && $q3['state']['control_silent_since'] === $now
        && $q4['action'] === 'skip' && $q4['escalate_restart']);

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['unbound']['control_ok'] = false;
    $s['unbound']['live_root'] = null;
    $r1 = uu_plan($s, uu_state_new());
    $s['now'] = $now + 60;
    $r2 = uu_plan($s, $r1['state']);
    $s['now'] = $now + UU_ESCALATE_MIN_SECONDS;
    $r3 = uu_plan($s, $r2['state']);
    uu_check($t, 'state lost, control silent, our route via wg-a → tunnel on wg-a; escalates after 120 s',
        $r1['action'] === 'skip' && $r1['state']['mode'] === 'tunnel' && $r1['state']['member'] === 'wg-a'
        && !$r1['escalate_restart'] && !$r2['escalate_restart'] && $r3['escalate_restart']
        && uu_test_reason_has($r1['reasons'], 'wg-a', 'route'));
    $s = uu_test_snapshot();
    $s['unbound']['control_ok'] = false;
    $s['unbound']['live_root'] = null;
    $s['route'] = ['present' => true, 'gateway' => '127.0.0.1', 'interface' => 'lo0', 'reject' => true,
                   'ours' => true];
    $p = uu_plan($s, uu_test_plan_state(null, $usable, UU_ESCALATE_EVALUATIONS, $now - UU_ESCALATE_MIN_SECONDS));
    uu_check($t, 'fallback, control silent, our reject route → stays fallback, never escalates',
        $p['action'] === 'skip' && $p['state']['mode'] === 'fallback' && $p['state']['member'] === null
        && !$p['escalate_restart']);

    $s = uu_test_snapshot();
    $s['unbound']['control_ok'] = false;
    $s['unbound']['live_root'] = null;
    $p = uu_plan($s, uu_test_plan_state(null, $usable, UU_ESCALATE_EVALUATIONS + 2,
        $now - UU_ESCALATE_MIN_SECONDS));
    uu_check($t, 'control silent in fallback → skip, never escalate',
        $p['action'] === 'skip' && !$p['escalate_restart']
        && $p['state']['control_failures'] === UU_ESCALATE_EVALUATIONS + 3);

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['unbound']['control_ok'] = false;
    $s['unbound']['live_root'] = null;
    $s['contract_input']['cacheflush'] = true;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable, UU_ESCALATE_EVALUATIONS - 1,
        $now - UU_ESCALATE_MIN_SECONDS));
    uu_check($t, 'cacheflush on → never escalate',
        $p['action'] === 'skip' && !$p['escalate_restart'] && uu_test_reason_has($p['reasons'], 'cacheflush'));

    // Stop.
    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['unbound']['enabled'] = false;
    $off = uu_plan($s, uu_test_plan_state('wg-a', $usable, UU_ESCALATE_EVALUATIONS,
        $now - UU_ESCALATE_MIN_SECONDS));
    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['unbound']['pid_alive'] = false;
    $s['unbound']['control_ok'] = false;
    $s['unbound']['live_root'] = null;
    $dead = uu_plan($s, uu_test_plan_state('wg-a', $usable, UU_ESCALATE_EVALUATIONS,
        $now - UU_ESCALATE_MIN_SECONDS));
    uu_check($t, 'Unbound disabled or pid dead → stop (route removed), never escalate',
        $off['action'] === 'stop' && !$off['escalate_restart'] && !$off['route_repair']
        && $dead['action'] === 'stop' && !$dead['escalate_restart'] && !$dead['route_repair']
        && $dead['state']['control_failures'] === 0 && $dead['state']['control_silent_since'] === null
        && $off['state']['control_silent_since'] === null
        && uu_test_reason_has($off['reasons'], 'Unbound not running')
        && uu_test_reason_has($dead['reasons'], 'Unbound not running'));

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['tiers'] = [];
    $s['members'] = [];
    $s['probes'] = [];
    $s['contract_input']['group_found'] = false;
    $s['contract_input']['members'] = 0;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'group deleted while in tunnel → fallback, reason names the group',
        $p['action'] === 'fallback' && $p['candidates'] === [] && $p['state']['timers'] === []
        && uu_test_reason_has($p['reasons'], 'group not found', 'grp_test'));

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['tiers'] = [['wg-b']];
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'current member removed from the group → tunnel [wg-b], reason names the group',
        $p['action'] === 'tunnel' && $p['candidates'] === ['wg-b']
        && uu_test_reason_has($p['reasons'], 'wg-a', 'grp_test'));

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    unset($s['members']['wg-a'], $s['probes']['wg-a']);
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'tier member without a gateway record is down → tunnel [wg-b]',
        $p['action'] === 'tunnel' && $p['candidates'] === ['wg-b']
        && uu_test_reason_has($p['reasons'], 'wg-a', 'no gateway record'));

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['settings']['enabled'] = false;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'disabled setting → stop', $p['action'] === 'stop' && !$p['escalate_restart']);

    // Mode recovery (Review Focus 4).
    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-b');
    $p = uu_plan($s, uu_state_new());
    uu_check($t, 'state file lost but live root is the resolver → treated as tunnel on the route\'s member',
        $p['action'] === 'none' && $p['candidates'] === ['wg-b'] && $p['state']['mode'] === 'tunnel'
        && $p['state']['member'] === 'wg-b' && !$p['route_repair'] && !$p['reassert']
        && uu_test_reason_has($p['reasons'], 'wg-b', 'route'));
    $s = uu_test_snapshot();
    $s['unbound']['live_root'] = ['10.2.0.1'];
    $p = uu_plan($s, uu_state_new());
    uu_check($t, 'state lost, live root is the resolver, no route of ours to a member → fallback',
        $p['action'] === 'fallback' && $p['candidates'] === [] && $p['state']['mode'] === 'tunnel'
        && $p['state']['member'] === null);

    return uu_tally_report('planner', $t);
});
