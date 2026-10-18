<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Live snapshot parsers (spec section 3.2): route get, unbound-control forward, sysctl, ps, group tiers.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/snapshot.php';
require_once __DIR__ . '/test_verdict.php';

function uu_snapshot_fixture(string $name): string
{
    $text = file_get_contents(__DIR__ . '/fixtures/' . $name);
    return $text === false ? '' : $text;
}

uu_register_suite('snapshot', function (): int {
    $t = ['fail' => 0, 'total' => 0];

    $r = uu_parse_route_get(uu_snapshot_fixture('route_get_member.txt'));
    uu_check($t, 'route via a member: present, gateway and device as printed, no reject',
        $r === ['present' => true, 'gateway' => '10.2.0.4', 'interface' => 'wg1', 'reject' => false]);
    $r = uu_parse_route_get(uu_snapshot_fixture('route_get_reject.txt'));
    uu_check($t, 'REJECT route (real output): present, no gateway, on lo0, reject',
        $r === ['present' => true, 'gateway' => '', 'interface' => 'lo0', 'reject' => true]);
    uu_check($t, 'the real REJECT route is ours', uu_route_ours($r, []));
    $r = uu_parse_route_get(uu_snapshot_fixture('route_get_absent.txt'));
    uu_check($t, 'not in table: absent', $r['present'] === false && !$r['reject']);
    uu_check($t, 'empty output: absent', uu_parse_route_get('')['present'] === false);
    $r = uu_parse_route_get(uu_snapshot_fixture('route_get_default.txt'));
    uu_check($t, 'the default route (0.0.0.0/0) is not a route of the resolver: absent',
        $r['present'] === false && $r['gateway'] === '' && $r['interface'] === '');
    uu_check($t, 'the default route printed as "default" is absent too',
        uu_parse_route_get(uu_snapshot_fixture('route_get_default_word.txt'))['present'] === false);
    $r = uu_parse_route_get(uu_snapshot_fixture('route_get_connected.txt'));
    uu_check($t, 'a connected network route covering the resolver is not the resolver\'s host route: absent',
        uu_parse_route_get(uu_snapshot_fixture('route_get_connected.txt'))['present'] === false);
    uu_check($t, 'a 0.0.0.0/1 covering route is absent',
        uu_parse_route_get(uu_snapshot_fixture('route_get_covering.txt'))['present'] === false);

    uu_check($t, 'forward: addresses in order',
        uu_parse_forward("192.0.2.53 198.51.100.53 2001:db8::53\n") === ['192.0.2.53', '198.51.100.53', '2001:db8::53']);
    uu_check($t, 'forward: DoT form keeps port and name',
        uu_parse_forward("192.0.2.53@853#dns.example\n") === ['192.0.2.53@853#dns.example']);
    uu_check($t, 'forward: off is the empty list', uu_parse_forward("off\n") === []);
    uu_check($t, 'forward: Unbound 1.26.1\'s real "off (using root hints)" (no root forward) is the empty list',
        uu_parse_forward("off (using root hints)\n") === []);
    uu_check($t, 'forward: other text after off is null', uu_parse_forward("off and on\n") === null);
    uu_check($t, 'forward: an error line is null',
        uu_parse_forward("error: connect: Connection refused for 127.0.0.1 port 8953\n") === null);
    uu_check($t, 'forward: empty output (timeout) is null', uu_parse_forward('') === null && uu_parse_forward("\n") === null);
    uu_check($t, 'forward: text that is not an address list is null', uu_parse_forward("unknown command\n") === null);

    uu_check($t, 'sysctl: 1000', uu_parse_sysctl_int("1000\n") === 1000);
    uu_check($t, 'sysctl: 0 is a value', uu_parse_sysctl_int("0\n") === 0);
    uu_check($t, 'sysctl: empty is null', uu_parse_sysctl_int('') === null && uu_parse_sysctl_int("\n") === null);
    uu_check($t, 'sysctl: not a number is null',
        uu_parse_sysctl_int("sysctl: unknown oid\n") === null && uu_parse_sysctl_int("-5\n") === null);

    uu_check($t, 'ps etimes: pid => seconds, junk skipped',
        uu_parse_ps_etimes("  101  86\n 202 3\nheader\n") === [101 => 86, 202 => 3]);

    $groups = ['name' => 'grp_test', 'trigger' => 'downloss',
               'tiers' => ['1' => ['wg-a'], '2' => ['wg-b', 'wg-c'], '3' => [''], '4' => [''], '5' => ['']]];
    uu_check($t, 'tiers: unused tiers ([""]) dropped, order kept',
        uu_group_tiers($groups) === [['wg-a'], ['wg-b', 'wg-c']]);
    uu_check($t, 'tiers: an empty name inside a tier is dropped, a hole in the numbering closes',
        uu_group_tiers(['tiers' => ['1' => ['wg-a'], '2' => [''], '3' => ['', 'wg-b']]]) === [['wg-a'], ['wg-b']]);
    uu_check($t, 'tiers: tiers listed out of key order sort by key',
        uu_group_tiers(['tiers' => ['2' => ['wg-b'], '1' => ['wg-a']]]) === [['wg-a'], ['wg-b']]);
    uu_check($t, 'tiers: a group without tiers is no tiers', uu_group_tiers(['name' => 'x']) === []);

    uu_check($t, 'network: inside /24, outside, /32 host, /0 everything',
        uu_ipv4_in_network('10.2.0.1', '10.2.0.0/24') && !uu_ipv4_in_network('10.2.1.1', '10.2.0.0/24')
        && uu_ipv4_in_network('10.2.0.1', '10.2.0.1') && uu_ipv4_in_network('10.2.0.1', '0.0.0.0/0')
        && !uu_ipv4_in_network('10.2.0.1', '10.2.0.2/32'));
    uu_check($t, 'network: IPv6 and malformed networks never match',
        !uu_ipv4_in_network('10.2.0.1', '2001:db8::/32') && !uu_ipv4_in_network('10.2.0.1', 'nonsense')
        && !uu_ipv4_in_network('10.2.0.1', '10.2.0.0/33'));

    uu_check($t, 'hook order: unbound before unboundupstream',
        uu_unbound_sorts_first(['core', 'unbound', 'unboundupstream', 'wireguard']));
    uu_check($t, 'hook order: unboundupstream not listed is a fault',
        !uu_unbound_sorts_first(['core', 'unbound', 'wireguard']));
    uu_check($t, 'hook order: scan order putting unboundupstream first fails',
        !uu_unbound_sorts_first(['unboundupstream', 'unbound']));
    uu_check($t, 'hook order: no unbound plugin fails', !uu_unbound_sorts_first(['core', 'wireguard']));

    $a = uu_test_member();
    $a['next_hop'] = '10.2.0.4';
    $members = ['wg-a' => $a];
    $via = ['present' => true, 'gateway' => '10.2.0.4', 'interface' => 'wg1', 'reject' => false];
    uu_check($t, 'ours: gateway and device of a member', uu_route_ours($via, $members));
    uu_check($t, 'ours: right gateway, wrong device is not ours',
        !uu_route_ours(['interface' => 'wg9'] + $via, $members));
    uu_check($t, 'ours: a gateway no member has is not ours',
        !uu_route_ours(['gateway' => '10.9.9.9'] + $via, $members));
    uu_check($t, 'ours: a REJECT route on lo0 is the block route, whatever the gateway',
        uu_route_ours(['gateway' => '', 'interface' => 'lo0', 'reject' => true] + $via, $members));
    uu_check($t, 'ours: a REJECT route on another device is not ours',
        !uu_route_ours(['gateway' => '', 'interface' => 'wg1', 'reject' => true] + $via, $members));
    uu_check($t, 'ours: a route on lo0 without REJECT is not ours',
        !uu_route_ours(['gateway' => '127.0.0.1', 'interface' => 'lo0'] + $via, $members));
    uu_check($t, 'ours: no route is not ours, and a connected route (no gateway) is not ours',
        !uu_route_ours(['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false], $members)
        && !uu_route_ours(['gateway' => ''] + $via, ['wg-a' => ['next_hop' => ''] + $a]));

    return uu_tally_report('snapshot', $t);
});
