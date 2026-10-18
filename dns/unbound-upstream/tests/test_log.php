<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Status and logging (spec section 3.8): the rule counters from pfctl -vsr, the blocked-count log line, the route
 * flags and the status document.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/log.php';
require_once __DIR__ . '/test_planner.php';
require_once __DIR__ . '/test_snapshot.php';

uu_register_suite('log', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $block = '172df6b9154ad996a4f8022b74f4dcb1';
    $passA = '3f3c211bfd2d6aae89e7778868f83aeb';
    $pf = uu_snapshot_fixture('pfctl_vsr.txt');

    uu_check($t, 'labels are md5("uu-block") and md5("uu-pass-<interface>"), as render.php registers them',
        uu_label_block() === $block && uu_label_pass('opt1') === $passA);
    uu_check($t, 'pfctl -vsr: packets per label, summed over the rules one label expands to',
        uu_pf_label_packets($pf) === ['02f4bab031b57d1e30553ce08e0ec131' => 3, $passA => 246, $block => 37]);
    uu_check($t, 'pfctl -vsr: empty output has no labels', uu_pf_label_packets('') === []);

    uu_check($t, 'blocked line: rule not loaded, or nothing blocked since it was → no line',
        uu_blocked_line(null, null) === null && uu_blocked_line(5, null) === null && uu_blocked_line(null, 0) === null
        && uu_blocked_line(7, 7) === null);
    uu_check($t, 'blocked line: a first count above zero is logged',
        uu_blocked_line(null, 5) === 'blocked 5 resolver packets on a non-member path since the rules were loaded');
    uu_check($t, 'blocked line: a rise is logged with the difference',
        uu_blocked_line(5, 9) === 'blocked 4 more resolver packets on a non-member path (9 since the rules were loaded)');
    uu_check($t, 'blocked line: a lower count is a filter reload (counters reset), logged only above zero',
        uu_blocked_line(9, 2) === 'blocked 2 resolver packets on a non-member path since the rules were loaded'
        && uu_blocked_line(9, 0) === null);

    uu_check($t, 'route flags from route get', uu_status_route_flags(uu_snapshot_fixture('route_get_member.txt'))
        === ['UP', 'GATEWAY', 'HOST', 'DONE', 'STATIC']);
    uu_check($t, 'route flags: none for empty output', uu_status_route_flags('') === []);

    $now = 10000;
    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['probes']['wg-b'] = uu_test_probe('down', '100.0 %', 300);
    $timers = ['wg-a' => uu_test_timer(500, null, $now - 60), 'wg-b' => uu_test_timer(0, $now + 30, null)];
    $timers['wg-a']['probe_failures'] = 1;
    $st = uu_test_plan_state('wg-a', $timers);
    $st['checks'] = ['direct' => ['ok' => true, 'at' => 1760000000, 'member' => 'wg-a'], 'unbound' => null];
    $st['tls_applied'] = false;
    $plan = uu_plan($s, $st);
    $doc = uu_status_doc($s, $plan, $pf, uu_snapshot_fixture('route_get_member.txt'));
    uu_check($t, 'status: every section 3.8 field',
        array_keys($doc) === ['enabled', 'dry_run', 'mode', 'member', 'tier', 'unbound', 'live_root', 'configured_root',
            'tls_applied', 'route', 'rules_loaded', 'blocked', 'checks', 'members', 'last_switch', 'contract', 'next']);
    uu_check($t, 'status: mode, member and its tier; live and configured roots; the TLS flag applied',
        $doc['mode'] === 'tunnel' && $doc['member'] === 'wg-a' && $doc['tier'] === 1
        && $doc['live_root'] === ['10.2.0.1'] && $doc['configured_root'] === $s['zone'] && $doc['tls_applied'] === false
        && $doc['unbound'] === ['enabled' => true, 'running' => true, 'control_ok' => true]);
    uu_check($t, 'status: the route with its flags',
        $doc['route'] === $s['route'] + ['flags' => ['UP', 'GATEWAY', 'HOST', 'DONE', 'STATIC']]);
    uu_check($t, 'status: rules not loaded while a member\'s pass is missing (wg-b on opt2); blocked from the block rule',
        $doc['rules_loaded'] === false && $doc['blocked'] === 37);
    uu_check($t, 'status: rules loaded with the block and every member\'s pass',
        uu_status_doc($s, $plan, $pf . 'pass out quick on wg2 inet proto udp label "' . uu_label_pass('opt2') . "\"\n",
            '')['rules_loaded'] === true);
    uu_check($t, 'status: members with tier, reading kind, verdict, timer, resolver-failed time and failures',
        $doc['members'] === [
            ['name' => 'wg-a', 'tier' => 1, 'kind' => 'settled', 'verdict' => null, 'usable' => true, 'counted' => 560,
             'resolver_failed_for' => null, 'probe_failures' => 1],
            ['name' => 'wg-b', 'tier' => 2, 'kind' => 'settled', 'verdict' => 'settled down', 'usable' => false,
             'counted' => 0, 'resolver_failed_for' => 30, 'probe_failures' => 0],
        ]);
    uu_check($t, 'status: checks, contract and the next evaluation\'s action',
        $doc['checks'] === $st['checks'] && $doc['contract'] === uu_contract($s['contract_input'])
        && $doc['next']['action'] === 'none' && $doc['last_switch'] === null);

    $gone = $s;
    $gone['unbound'] = ['enabled' => true, 'pid_alive' => false, 'control_ok' => false, 'live_root' => null];
    $doc = uu_status_doc($gone, uu_plan($gone, $st), '', '');
    uu_check($t, 'status: Unbound not running is reported, with nothing loaded and no blocked count',
        $doc['unbound']['running'] === false && $doc['rules_loaded'] === false && $doc['blocked'] === null
        && uu_test_reason_has($doc['next']['reasons'], 'Unbound not running'));

    return uu_tally_report('log', $t);
});
