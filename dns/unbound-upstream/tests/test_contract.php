<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Core contract (spec section 3.10): each broken input refuses tunnel mode with its own named failure.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/contract.php';

/**
 * A contract input that passes, with a restorable single root zone.
 *
 * @return array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *     status_fields: bool, resolver_is_monitor: list<string>, resolver_in_static: list<string>,
 *     unmonitored_members: list<string>, foreign_route: bool,
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int}
 */
function uu_test_contract_input(): array
{
    return [
        'unbound_hooks_registered' => true,
        'unbound_sorts_first' => true,
        'groups_have_tiers' => true,
        'status_fields' => true,
        'resolver_is_monitor' => [],
        'resolver_in_static' => [],
        'unmonitored_members' => [],
        'foreign_route' => false,
        'zone' => ['shape' => 'one', 'addrs' => ['192.0.2.53@853#dns.example'], 'tls' => true, 'problems' => []],
        'fib_sync_ms' => 100,
        'cacheflush' => false,
        'group_found' => true,
        'members' => 2,
    ];
}

uu_register_suite('contract', function (): int {
    $t = ['fail' => 0, 'total' => 0];

    $c = uu_contract(uu_test_contract_input());
    uu_check($t, 'a clean input is ok with no failures and no notes',
        $c['ok'] && $c['failures'] === [] && $c['notes'] === []);

    $cases = [
        ['unbound_hooks_registered', false, 'unbound_start hook missing'],
        ['unbound_sorts_first', false, 'unbound.inc no longer sorts before unboundupstream.inc'],
        ['groups_have_tiers', false, 'gateway groups lack tiers'],
        ['status_fields', false, 'gateway status lacks expected fields'],
        ['foreign_route', true, 'resolver route not ours'],
        ['fib_sync_ms', null, 'fib sync delay unreadable'],
        ['group_found', false, 'group not found'],
        ['members', 0, 'group has no members'],
    ];
    foreach ($cases as [$key, $value, $failure]) {
        $in = uu_test_contract_input();
        $in[$key] = $value;
        $c = uu_contract($in);
        uu_check($t, "$key flipped alone: exactly \"$failure\"", !$c['ok'] && $c['failures'] === [$failure]);
    }

    $in = uu_test_contract_input();
    $in['resolver_is_monitor'] = ['wg-a', 'wg-b'];
    $c = uu_contract($in);
    uu_check($t, 'resolver is the monitor: one failure per gateway',
        !$c['ok'] && $c['failures'] === ['resolver is the monitor of wg-a', 'resolver is the monitor of wg-b']);

    $in = uu_test_contract_input();
    $in['resolver_in_static'] = ['10.2.0.0/24', '10.0.0.0/8'];
    $c = uu_contract($in);
    uu_check($t, 'resolver inside static routes: one failure per route',
        !$c['ok'] && $c['failures'] === ['resolver is inside static route 10.2.0.0/24',
            'resolver is inside static route 10.0.0.0/8']);

    $in = uu_test_contract_input();
    $in['unmonitored_members'] = ['wg-b'];
    $c = uu_contract($in);
    uu_check($t, 'unmonitored member: failure names it',
        !$c['ok'] && $c['failures'] === ['member wg-b is not monitored']);

    $in = uu_test_contract_input();
    $in['zone'] = ['shape' => 'unrestorable', 'addrs' => [], 'tls' => false,
        'problems' => ['second . zone', 'forward-first']];
    $c = uu_contract($in);
    uu_check($t, 'unrestorable zone: failure lists the problems',
        !$c['ok'] && $c['failures'] === ['root zone cannot be restored: second . zone, forward-first']);

    $in = uu_test_contract_input();
    $in['zone'] = ['shape' => 'none', 'addrs' => [], 'tls' => false, 'problems' => []];
    $c = uu_contract($in);
    uu_check($t, 'no root zone: ok, with the recursion note',
        $c['ok'] && $c['failures'] === []
        && $c['notes'] === ['no root zone: fallback is recursion over the WAN']);

    $in = uu_test_contract_input();
    $in['zone'] = ['shape' => 'one', 'addrs' => [], 'tls' => false, 'problems' => []];
    $c = uu_contract($in);
    uu_check($t, 'root zone with no forward-addr: failure',
        !$c['ok'] && $c['failures'] === ['root zone has no forward-addr']);

    $in = uu_test_contract_input();
    $in['cacheflush'] = true;
    $c = uu_contract($in);
    uu_check($t, 'cacheflush on: a note only',
        $c['ok'] && $c['failures'] === [] && $c['notes'] === ['cacheflush on: restart escalation disabled']);

    $in = uu_test_contract_input();
    $in['foreign_route'] = true;
    $in['group_found'] = false;
    $in['fib_sync_ms'] = null;
    $c = uu_contract($in);
    uu_check($t, 'several broken inputs report every failure',
        !$c['ok'] && count($c['failures']) === 3);

    return uu_tally_report('contract', $t);
});
