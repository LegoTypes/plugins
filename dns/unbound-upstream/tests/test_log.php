<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Status and logging (spec section 3.8): the blocked-count log line, the route flags, durations and the status
 * document.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/log.php';
require_once __DIR__ . '/test_planner.php';
require_once __DIR__ . '/test_snapshot.php';

uu_register_suite('log', function (): int {
    $t = ['fail' => 0, 'total' => 0];

    uu_check($t, 'blocked line: no counting table, or nothing blocked since it was → no line',
        uu_blocked_line(null, null) === null && uu_blocked_line(5, null) === null && uu_blocked_line(null, 0) === null
        && uu_blocked_line(7, 7) === null);
    uu_check($t, 'blocked line: a first count above zero is logged',
        uu_blocked_line(null, 5) === 'blocked 5 resolver packets on a non-member path since the rules were loaded');
    uu_check($t, 'blocked line: a rise is logged with the difference',
        uu_blocked_line(5, 9) === 'blocked 4 more resolver packets on a non-member path (9 since the rules were loaded)');
    uu_check($t, 'blocked line: a lower count is a recreated table (counters reset), logged only above zero',
        uu_blocked_line(9, 2) === 'blocked 2 resolver packets on a non-member path since the rules were loaded'
        && uu_blocked_line(9, 0) === null);

    uu_check($t, 'route flags from route get', uu_status_route_flags(uu_snapshot_fixture('route_get_member.txt'))
        === ['UP', 'GATEWAY', 'HOST', 'DONE', 'STATIC']);
    uu_check($t, 'route flags: none for empty output', uu_status_route_flags('') === []);

    uu_check($t, 'duration: two largest units',
        uu_duration_text(0) === '0 s' && uu_duration_text(59) === '59 s' && uu_duration_text(60) === '1 min 0 s'
        && uu_duration_text(130) === '2 min 10 s' && uu_duration_text(40979) === '11 h 22 min'
        && uu_duration_text(273600) === '3 d 4 h' && uu_duration_text(86400) === '1 d 0 h');

    $now = 10000;
    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['probes']['wg-b'] = uu_test_probe('down', '100.0 %', 300);
    $down = ['at' => 1792390000, 'reason' => 'settled down'];
    $timers = ['wg-a' => uu_test_timer(40919, null, $now - 60), 'wg-b' => uu_test_timer(0, $now + 30, null)];
    $timers['wg-a']['probe_failures'] = 1;
    $timers['wg-b']['last_down'] = $down;
    $st = uu_test_plan_state('wg-a', $timers);
    $st['checks'] = ['direct' => ['ok' => true, 'at' => 1760000000, 'member' => 'wg-a'], 'unbound' => null];
    $st['tls_applied'] = false;
    $plan = uu_plan($s, $st);
    $armed = ['armed' => true, 'fill' => false, 'blocked' => 37];
    $route = uu_snapshot_fixture('route_get_member.txt');
    $doc = uu_status_doc($s, $plan, $armed, $route);
    uu_check($t, 'status: every section 3.8 field',
        array_keys($doc) === ['enabled', 'dry_run', 'resolver', 'mode', 'member', 'tier', 'unbound', 'live_root',
            'configured_root', 'tls_applied', 'route', 'rules_loaded', 'rules', 'counter_armed', 'blocked', 'checks',
            'members', 'last_switch', 'contract', 'next']);
    uu_check($t, 'status: the resolver, mode, member and its tier; live and configured roots; the TLS flag applied',
        $doc['resolver'] === $s['settings']['resolver'] && $doc['mode'] === 'tunnel' && $doc['member'] === 'wg-a' && $doc['tier'] === 1
        && $doc['live_root'] === ['10.2.0.1'] && $doc['configured_root'] === $s['zone'] && $doc['tls_applied'] === false
        && $doc['unbound'] === ['enabled' => true, 'running' => true, 'control_ok' => true]);
    uu_check($t, 'status: the route with its flags',
        $doc['route'] === $s['route'] + ['flags' => ['UP', 'GATEWAY', 'HOST', 'DONE', 'STATIC']]);
    uu_check($t, 'status: the rules as the snapshot verified them, loaded; the counter armed with its table\'s count',
        $doc['rules_loaded'] === true
        && $doc['rules'] === ['state' => 'loaded', 'problems' => [], 'verified_at' => 1792399000]
        && $doc['counter_armed'] === true && $doc['blocked'] === 37);
    $missing = $s;
    $problem = 'no pass rule for wg-b (opt2)';
    $missing['rules'] = ['state' => 'missing', 'problems' => [$problem], 'verified_at' => 1792399500, 'record' => null];
    $missing['contract_input']['rules'] = ['state' => 'missing', 'problems' => [$problem]];
    $d = uu_status_doc($missing, uu_plan($missing, $st), $armed, $route);
    uu_check($t, 'status: rules missing are not loaded, their problems carried and named in the contract',
        $d['rules_loaded'] === false
        && $d['rules'] === ['state' => 'missing', 'problems' => [$problem], 'verified_at' => 1792399500]
        && $d['contract']['failures'] === ['firewall rules: ' . $problem]);
    $verifying = $s;
    $verifying['rules'] = ['state' => 'verifying', 'problems' => [], 'verified_at' => null, 'record' => null];
    $verifying['contract_input']['rules'] = ['state' => 'verifying', 'problems' => []];
    $d = uu_status_doc($verifying, uu_plan($verifying, $st), $armed, $route);
    uu_check($t, 'status: verifying is not loaded, has no time, and the contract carries the note only',
        $d['rules_loaded'] === false && $d['rules'] === ['state' => 'verifying', 'problems' => [], 'verified_at' => null]
        && $d['contract']['ok']
        && $d['contract']['notes'] === ['firewall rules are being verified (the ruleset changed)']);
    $d = uu_status_doc($s, $plan, ['armed' => false, 'fill' => true, 'blocked' => 0], $route);
    uu_check($t, 'status: a table that does not hold the resolver is not armed; its count is still the table\'s',
        $d['counter_armed'] === false && $d['blocked'] === 0);
    $d = uu_status_doc($s, $plan, ['armed' => false, 'fill' => false, 'blocked' => null], $route);
    uu_check($t, 'status: no table (or a user alias of its name): not armed, no count',
        $d['counter_armed'] === false && $d['blocked'] === null);
    uu_check($t, 'status: members with tier, reading kind, verdict, health as a duration, last down, resolver-failed '
        . 'time and failures',
        $doc['members'] === [
            ['name' => 'wg-a', 'tier' => 1, 'kind' => 'settled', 'verdict' => null, 'usable' => true,
             'healthy_for' => 40979, 'healthy_for_text' => '11 h 22 min', 'last_down' => null,
             'resolver_failed_for' => null, 'probe_failures' => 1],
            ['name' => 'wg-b', 'tier' => 2, 'kind' => 'settled', 'verdict' => 'settled down', 'usable' => false,
             'healthy_for' => 0, 'healthy_for_text' => '0 s', 'last_down' => $down,
             'resolver_failed_for' => 30, 'probe_failures' => 0],
        ]);
    uu_check($t, 'status: checks, contract and the next evaluation\'s action',
        $doc['checks'] === $st['checks'] && $doc['contract'] === uu_contract($s['contract_input'])
        && $doc['next']['action'] === 'none' && $doc['last_switch'] === null);

    $gone = $s;
    $gone['unbound'] = ['enabled' => true, 'pid_alive' => false, 'control_ok' => false, 'live_root' => null];
    $doc = uu_status_doc($gone, uu_plan($gone, $st), ['armed' => false, 'fill' => false, 'blocked' => null], '');
    uu_check($t, 'status: Unbound not running is reported, with no blocked count and no route flags',
        $doc['unbound']['running'] === false && $doc['blocked'] === null && $doc['route']['flags'] === []
        && uu_test_reason_has($doc['next']['reasons'], 'Unbound not running'));

    return uu_tally_report('log', $t);
});
