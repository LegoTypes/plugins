<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The one address type: family, canonical form, the refused ranges and the next hop route(8) takes.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/address.php';
require_once __DIR__ . '/scratch.php';

uu_register_suite('address', function (): int {
    $t = ['fail' => 0, 'total' => 0];

    uu_check($t, '(t1) families: IPv4 is inet, IPv6 is inet6',
        uu_try_case(fn (): bool => uu_ip_family('10.2.0.1') === 'inet' && uu_ip_family('2001:db8::53') === 'inet6'
            && uu_ip_family('2001:DB8:0:0::53') === 'inet6' && uu_ip_family('::1') === 'inet6'));
    uu_check($t, '(t1) families: no family for an empty string, a prefix, a scoped address, a host name or an IPv4-mapped '
        . 'address',
        uu_try_case(fn (): bool => uu_ip_family('') === null && uu_ip_family('192.0.2.1/32') === null
            && uu_ip_family('fe80::1%wg0') === null && uu_ip_family('dns.example') === null
            && uu_ip_family('::ffff:192.0.2.1') === null && uu_ip_family('::ffff:c000:201') === null
            && uu_ip_family('2001:db8::/32') === null));
    uu_check($t, '(t1) families: surrounding white space is no address',
        uu_try_case(fn (): bool => uu_ip_family("192.0.2.1\n") === null && uu_ip_family(' 192.0.2.1') === null
            && uu_ip_family("2001:db8::53\n") === null && uu_ip_family('999.1.1.1') === null
            && uu_ip_family('010.2.0.1') === null));
    uu_check($t, '(t1) canonical: IPv6 is lower case and shortest, IPv4 is as written',
        uu_try_case(fn (): bool => uu_ip_canonical('2001:DB8:0:0::53') === '2001:db8::53'
            && uu_ip_canonical('2001:0db8::0053') === '2001:db8::53' && uu_ip_canonical('10.2.0.1') === '10.2.0.1'
            && uu_ip_canonical('2001:DB8:A:0::53') === '2001:db8:a::53'
            && uu_ip_canonical('2001:db8::1:0:0:1') === uu_ip_canonical('2001:db8:0:0:1::1')
            && uu_ip_canonical('2001:db8::1:0:0:1') === '2001:db8::1:0:0:1'));
    uu_check($t, '(t1) canonical: null where there is no family',
        uu_try_case(fn (): bool => uu_ip_canonical('') === null && uu_ip_canonical('192.0.2.1/32') === null
            && uu_ip_canonical('fe80::1%wg0') === null && uu_ip_canonical('dns.example') === null
            && uu_ip_canonical('::ffff:192.0.2.1') === null));
    uu_check($t, '(t1) same: compares canonical forms, never across families, never for a non-address',
        uu_try_case(fn (): bool => uu_ip_same('2001:DB8:A:0::53', '2001:0db8:a::0053')
            && uu_ip_same('10.2.0.1', '10.2.0.1') && !uu_ip_same('10.2.0.1', '10.2.0.2')
            && !uu_ip_same('2001:db8::2:1', '2001:db8::2:10') && !uu_ip_same('dns.example', 'dns.example')
            && !uu_ip_same('', '')));

    $problem = fn (string $addr): ?string => uu_ip_problem($addr);
    uu_check($t, '(t2) problems: link-local in both families',
        uu_try_case(fn (): bool => $problem('fe80::1') === 'link-local' && $problem('febf::1') === 'link-local'
            && $problem('169.254.0.1') === 'link-local' && $problem('2001:db8::53') === null
            && $problem('fec0::1') === null && $problem('169.253.0.1') === null));
    uu_check($t, '(t2) problems: multicast is exactly 224.0.0.0/4 and ff00::/8',
        uu_try_case(fn (): bool => $problem('ff02::1') === 'multicast' && $problem('ff00::1') === 'multicast'
            && $problem('224.0.0.251') === 'multicast' && $problem('239.255.255.255') === 'multicast'
            && $problem('223.255.255.255') === null && $problem('240.0.0.1') === null
            && $problem('255.255.255.255') === null));
    uu_check($t, '(t2) problems: unspecified and loopback',
        uu_try_case(fn (): bool => $problem('::') === 'unspecified' && $problem('0.0.0.0') === 'unspecified'
            && $problem('::1') === 'loopback' && $problem('127.0.0.53') === 'loopback'
            && $problem('0.0.0.1') === null));
    uu_check($t, '(t2) problems: an IPv4-mapped address, a prefix, a scoped address, a host name and nothing are not '
        . 'addresses',
        uu_try_case(fn (): bool => $problem('::ffff:192.0.2.1') === 'not an address'
            && $problem('192.0.2.1/32') === 'not an address' && $problem('fe80::1%wg0') === 'not an address'
            && $problem('dns.example') === 'not an address' && $problem('') === 'not an address'));
    uu_check($t, '(t2) problems: a documentation address of each family has none',
        uu_try_case(fn (): bool => $problem('2001:db8::53') === null && $problem('192.0.2.53') === null));

    uu_check($t, '(t2) refusal wording: one sentence ending per problem kind, null for a usable address',
        uu_try_case(fn (): bool => uu_resolver_refusal('dns.example') === 'not an IPv4 or IPv6 address'
            && uu_resolver_refusal('') === 'not an IPv4 or IPv6 address'
            && uu_resolver_refusal('::ffff:192.0.2.1') === 'not an IPv4 or IPv6 address'
            && uu_resolver_refusal('fe80::1') === 'link-local' && uu_resolver_refusal('169.254.0.1') === 'link-local'
            && uu_resolver_refusal('ff02::1') === 'multicast' && uu_resolver_refusal('224.0.0.1') === 'multicast'
            && uu_resolver_refusal('::') === 'unspecified' && uu_resolver_refusal('0.0.0.0') === 'unspecified'
            && uu_resolver_refusal('::1') === 'loopback' && uu_resolver_refusal('127.0.0.1') === 'loopback'
            && uu_resolver_refusal('2001:db8::53') === null && uu_resolver_refusal('192.0.2.53') === null));
    uu_check($t, '(t3) route hop: a link-local next hop takes its device, any other is unchanged',
        uu_try_case(fn (): bool => uu_route_hop('fe80::1', 'gif0') === 'fe80::1%gif0'
            && uu_route_hop('FE80:0::1', 'gif0') === 'fe80::1%gif0'
            && uu_route_hop('fd00::3:2', 'wg3') === 'fd00::3:2' && uu_route_hop('10.2.0.2', 'wg1') === '10.2.0.2'
            && uu_route_hop('169.254.0.1', 'wg1') === '169.254.0.1'));
    uu_check($t, '(t3) next hop: canonical, a scope dropped, a non-address as it is',
        uu_try_case(fn (): bool => uu_next_hop('fe80::1%gif0') === 'fe80::1' && uu_next_hop('FD00:0::3:2') === 'fd00::3:2'
            && uu_next_hop('10.2.0.2') === '10.2.0.2' && uu_next_hop('') === '' && uu_next_hop('dynamic') === 'dynamic'));
    uu_check($t, '(t3) family argument: -inet or -inet6',
        uu_try_case(fn (): bool => uu_family_arg('inet') === '-inet' && uu_family_arg('inet6') === '-inet6'));

    uu_check($t, '(t3) route get arguments: the family argument and the quoted address, none without a family',
        uu_try_case(fn (): bool => uu_route_get_args('2001:db8::53') === "-inet6 '2001:db8::53'"
            && uu_route_get_args('10.2.0.1') === "-inet '10.2.0.1'" && uu_route_get_args('') === null
            && uu_route_get_args('dns.example') === null && uu_route_get_args('::ffff:192.0.2.1') === null));
    uu_check($t, '(t3) route delete text: the IPv4 form has no family argument, IPv6 needs -inet6, a placeholder reads '
        . 'as IPv4',
        uu_try_case(fn (): bool => uu_route_delete_text('192.0.2.1') === 'route delete -host 192.0.2.1'
            && uu_route_delete_text('2001:db8:a::53') === 'route delete -inet6 -host 2001:db8:a::53'
            && uu_route_delete_text('<resolver>') === 'route delete -host <resolver>'));

    /* each member's effective resolver: its own row, else the Default, else none */
    $uuidA = '0b6a7f9e-5c1d-4e0a-9d2b-3f8a1c4e5d6a';
    $uuidB = '0b6a7f9e-5c1d-4e0a-9d2b-3f8a1c4e5d6b';
    $uuidC = '0b6a7f9e-5c1d-4e0a-9d2b-3f8a1c4e5d6c';
    $uuidGone = '0b6a7f9e-5c1d-4e0a-9d2b-3f8a1c4e5d60';
    $names = [$uuidA => 'wg-a', $uuidB => 'wg-b', $uuidC => 'wg-c'];
    uu_check($t, '(p1) member resolvers: a member with its own row has its address, one without has the Default',
        uu_try_case(fn (): bool => uu_member_resolvers(['wg-a', 'wg-b'], [$uuidB => '2001:db8:b::53'], $names,
            '2001:db8:a::53') === ['resolvers' => ['wg-a' => '2001:db8:a::53', 'wg-b' => '2001:db8:b::53'],
                                   'notes' => []]));
    uu_check($t, '(p1) member resolvers: with no Default a member without a row has none, and is noted',
        uu_try_case(fn (): bool => uu_member_resolvers(['wg-a', 'wg-b'], [$uuidB => '2001:db8:b::53'], $names, '')
            === ['resolvers' => ['wg-a' => '', 'wg-b' => '2001:db8:b::53'],
                 'notes' => ['wg-a has no resolver: not a candidate']]));
    uu_check($t, '(p1) member resolvers: a row for a gateway outside the group and a row whose id names no gateway are '
        . 'noted and change nothing',
        uu_try_case(fn (): bool => uu_member_resolvers(['wg-a', 'wg-b'],
            [$uuidC => '2001:db8:c::53', $uuidGone => '2001:db8:d::53'], $names, '2001:db8:a::53')
            === ['resolvers' => ['wg-a' => '2001:db8:a::53', 'wg-b' => '2001:db8:a::53'],
                 'notes' => ['row for wg-c ignored: not a member of the group',
                             "row for gateway $uuidGone ignored: no such gateway"]]));
    uu_check($t, '(p1) member resolvers: one IPv4 Default and no rows (the one-address setup) is that address for '
        . 'every member, with no note',
        uu_try_case(fn (): bool => uu_member_resolvers(['wg-a', 'wg-b'], [], $names, '10.2.0.1')
            === ['resolvers' => ['wg-a' => '10.2.0.1', 'wg-b' => '10.2.0.1'], 'notes' => []]));
    uu_check($t, '(p1) member resolvers: a row for the only member with no Default is its resolver, with no note',
        uu_try_case(fn (): bool => uu_member_resolvers(['wg-a'], [$uuidA => '192.0.2.53'], $names, '')
            === ['resolvers' => ['wg-a' => '192.0.2.53'], 'notes' => []]));

    /* the group's family: the first member's in tier order */
    $proto = fn (string $p): array => ['ipprotocol' => $p];
    uu_check($t, '(p2) group family: an IPv4 group, an IPv6 group, the first member in tier order deciding a mixed one',
        uu_try_case(fn (): bool => uu_group_family(['wg-a' => $proto('inet'), 'wg-b' => $proto('inet')],
                [['wg-a'], ['wg-b']]) === ['family' => 'inet', 'mixed' => false]
            && uu_group_family(['wg-a' => $proto('inet6'), 'wg-b' => $proto('inet6')], [['wg-a', 'wg-b']])
                === ['family' => 'inet6', 'mixed' => false]
            && uu_group_family(['wg-a' => $proto('inet'), 'wg-b' => $proto('inet6')], [['wg-b'], ['wg-a']])
                === ['family' => 'inet6', 'mixed' => true]
            && uu_group_family(['wg-a' => $proto('inet'), 'wg-b' => $proto('inet6')], [['wg-a'], ['wg-b']])
                === ['family' => 'inet', 'mixed' => true]));
    uu_check($t, '(p2) group family: \'\' with no members, and a member with no family (or no record) is skipped',
        uu_try_case(fn (): bool => uu_group_family([], []) === ['family' => '', 'mixed' => false]
            && uu_group_family(['wg-a' => $proto('')], [['wg-a']]) === ['family' => '', 'mixed' => false]
            && uu_group_family(['wg-b' => $proto('inet6')], [['wg-a', 'wg-b']])
                === ['family' => 'inet6', 'mixed' => false]
            && uu_group_family(['wg-a' => $proto(''), 'wg-b' => $proto('inet')], [['wg-a'], ['wg-b']])
                === ['family' => 'inet', 'mixed' => false]));

    uu_check($t, '(c5) family mismatch: the addresses of the other family, in order; none for a group of no '
        . 'family or of both (its family is only its first member\'s)',
        uu_try_case(function (): bool {
            $v4 = ['family' => 'inet', 'mixed' => false];
            $v6 = ['family' => 'inet6', 'mixed' => false];
            return uu_family_mismatch($v4, ['192.0.2.53', '2001:db8::53', '198.51.100.9', '2001:db8::54'])
                    === ['2001:db8::53', '2001:db8::54']
                && uu_family_mismatch($v6, ['192.0.2.53', '2001:db8::53', '198.51.100.9']) === ['192.0.2.53',
                    '198.51.100.9']
                && uu_family_mismatch($v4, ['192.0.2.53']) === [] && uu_family_mismatch($v6, []) === []
                && uu_family_mismatch(['family' => '', 'mixed' => false], ['192.0.2.53', '2001:db8::53']) === []
                && uu_family_mismatch(['family' => 'inet6', 'mixed' => true], ['192.0.2.53', '2001:db8::53']) === []
                && uu_family_mismatch(['family' => 'inet', 'mixed' => true], ['192.0.2.53', '2001:db8::53']) === [];
        }));

    uu_check($t, '(p15) next hop routable: an address of either family, a link-local one with its scope; never empty '
        . 'or dynamic',
        uu_try_case(fn (): bool => uu_next_hop_routable('10.2.0.2') && uu_next_hop_routable('fd00::3:2')
            && uu_next_hop_routable('fe80::1%wg3') && uu_next_hop_routable('fe80::1')
            && !uu_next_hop_routable('') && !uu_next_hop_routable('dynamic')
            && !uu_next_hop_routable('%wg3')));

    return uu_tally_report('address', $t);
});
