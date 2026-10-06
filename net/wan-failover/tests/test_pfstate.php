<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * pfctl -vvss / -vvsr parsing and flow pairing, spec section 3.5.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/pfstate.php';

/** @return array<string, string> gateway ip => WAN name */
function wf_t_gws(): array
{
    return ['203.0.113.1@igc1' => 'PRIMARY_WAN', '172.16.12.1@igc2' => 'WAN2'];
}

wf_register_suite('pfstate', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $states = wf_parse_states((string)file_get_contents(__DIR__ . '/fixtures/states.txt'));
    wf_check($t, 'parses all 18 states', count($states) === 18);
    $u = $states[1];
    wf_check($t, 'NAT out-state: src, orig_src, dst', $u['dir'] === 'out' && $u['src'] === '172.16.12.148:63800'
        && $u['orig_src'] === '10.0.30.20:37460' && $u['dst'] === '198.51.100.57:51820');
    wf_check($t, 'out-state route-to gateway and interface', $u['route_to_gw'] === '172.16.12.1' && $u['route_to_if'] === 'igc2');
    wf_check($t, 'id and creatorid', $u['id'] === '33f6d16a00000000' && $u['creatorid'] === '4a28027f');
    wf_check($t, 'rlabel without trailing comma', $u['rlabel'] === 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    $i = $states[0];
    wf_check($t, 'in-state "dst <- src" maps src and dst', $i['dir'] === 'in' && $i['src'] === '10.0.30.20:37460' && $i['dst'] === '198.51.100.57:51820');
    wf_check($t, 'in-state of a route-to rule keeps its route-to', $states[2]['route_to_gw'] === '172.16.12.1');
    wf_check($t, 'state without rlabel parses with rlabel null', $states[17]['rlabel'] === null && $states[17]['rule'] === 900);
    wf_check($t, 'IPv6 bracket ports parse', $states[12]['src'] === '2001:db8:7::20[49450]' && $states[12]['route_to_gw'] === 'fe80::1');
    wf_check($t, 'wf_addr_host IPv4', wf_addr_host('198.51.100.57:51820') === '198.51.100.57');
    wf_check($t, 'wf_addr_host IPv6', wf_addr_host('2001:db8:100::5[8883]') === '2001:db8:100::5');
    wf_check($t, 'empty output parses to no states', wf_parse_states('') === []);

    $flows = wf_flows($states, wf_t_gws());
    wf_check($t, '7 anchors: ICMP, IPv6, tunnel pin and in-states excluded', count($flows) === 7);
    $kinds = array_count_values(array_column($flows, 'kind'));
    wf_check($t, '5 forwarded, 2 local', ($kinds['forwarded'] ?? 0) === 5 && ($kinds['local'] ?? 0) === 2);
    wf_check($t, 'exit-node pair is forwarded on WAN2 with its in-state partner', $flows[0]['kind'] === 'forwarded'
        && $flows[0]['current'] === 'WAN2' && $flows[0]['partner']['rlabel'] === '11111111-1111-4111-8111-111111111111');
    wf_check($t, 'no anchor is an in-state', count(array_filter($flows, fn (array $f): bool => $f['anchor']['dir'] !== 'out')) === 0);

    $dup = [$states[0], $states[0], $states[1]];
    $amb = wf_flows($dup, wf_t_gws());
    wf_check($t, 'two matching in-states make the flow ambiguous', count($amb) === 1 && $amb[0]['kind'] === 'ambiguous' && $amb[0]['partner'] === null);
    wf_check($t, 'no states, no flows', wf_flows([], wf_t_gws()) === []);
    $other = $states[1];
    $other['route_to_if'] = 'igc1';
    $shared = wf_flows([$states[1], $other], ['172.16.12.1@igc1' => 'WAN_A', '172.16.12.1@igc2' => 'WAN_B']);
    wf_check($t, 'WANs sharing a gateway address are told apart by interface', count($shared) === 2
        && $shared[0]['current'] === 'WAN_B' && $shared[1]['current'] === 'WAN_A');
    wf_check($t, 'wf_route_target joins gateway and interface as pf prints it', wf_route_target('172.16.12.1', 'igc2') === '172.16.12.1@igc2');

    $rules = wf_parse_rules((string)file_get_contents(__DIR__ . '/fixtures/rules.txt'));
    wf_check($t, 'automatic WAN2 out rule renders route-to igc2', $rules['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'] === [['gw' => '172.16.12.1', 'if' => 'igc2', 'balanced' => false]]);
    wf_check($t, 'one label, two renderings', count($rules['22222222-2222-4222-8222-222222222222']) === 2);
    wf_check($t, 'no route-to renders gw null', $rules['11111111-1111-4111-8111-111111111111'][0]['gw'] === null);
    wf_check($t, 'load-balanced route-to is flagged, gw null', $rules['55555555-5555-4555-8555-555555555555'][0]['balanced'] === true
        && $rules['55555555-5555-4555-8555-555555555555'][0]['gw'] === null);
    wf_check($t, 'empty rules output', wf_parse_rules('') === []);
    $pool = wf_parse_rules('@2901 pass in quick on vlan0.20 route-to { (igc2 172.16.12.1), (igc2 172.16.12.1) } round-robin inet proto tcp from <secondary_first_hosts:3> to ! (self:13) flags S/SA keep state label "77777777-7777-4777-8777-777777777777"');
    wf_check($t, 'a pool listing one target several times (gateway weight) routes to that target, not balanced',
        $pool['77777777-7777-4777-8777-777777777777'] === [['gw' => '172.16.12.1', 'if' => 'igc2', 'balanced' => false]]);

    $raw = (string)file_get_contents(__DIR__ . '/fixtures/states.txt');
    wf_check($t, 'self-check passes on the real format', wf_pf_selfcheck($raw, $states));
    $renamed = str_replace('route-to: ', 'route_to=', $raw);
    wf_check($t, 'self-check fails when route-to tokens no longer parse', !wf_pf_selfcheck($renamed, wf_parse_states($renamed)));
    $headers = preg_replace('/^all /m', 'any ', $raw);
    wf_check($t, 'self-check fails when state headers no longer parse', !wf_pf_selfcheck($headers, wf_parse_states($headers)));
    wf_check($t, 'self-check fails on empty pfctl output (a live firewall always has states)', !wf_pf_selfcheck('', []));
    $noLabel = str_replace('rlabel ', 'xlabel ', $raw);
    wf_check($t, 'self-check fails when no state carries a parsed rlabel', !wf_pf_selfcheck($noLabel, wf_parse_states($noLabel)));
    $noId = str_replace('id: ', 'ident: ', $raw);
    wf_check($t, 'self-check fails when no state carries a parsed id', !wf_pf_selfcheck($noId, wf_parse_states($noId)));
    wf_check($t, 'first tier: tiers in order, empty tiers skipped', wf_first_tier([3 => ['WAN_C'], 1 => [''], 2 => ['WAN_B', 'WAN_A']]) === ['WAN_B', 'WAN_A']
        && wf_first_tier([1 => [''], 2 => []]) === []);
    $looked = [];
    $lookup = function (string $h, array $f) use (&$looked): bool { $looked[] = $h; return $h === '198.51.100.7'; };
    $local = fn (string $dst): array => ['anchor' => ['dst' => $dst], 'partner' => null, 'kind' => 'local', 'current' => 'WAN2'];
    $pins = wf_pinned_hosts([$local('198.51.100.7:53'), $local('198.51.100.8:53'), $local('198.51.100.9:53'), $local('198.51.100.7:853')], $lookup, 2);
    wf_check($t, 'pinned: looked-up hosts by route, hosts past the cap spared as pinned, each host looked up once',
        $pins === ['198.51.100.7' => true, '198.51.100.9' => true] && $looked === ['198.51.100.7', '198.51.100.8']);
    return wf_tally_report('pfstate', $t);
});
