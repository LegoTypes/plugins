<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * pfctl -vvss / -vvsr parsing and flow pairing.
 */

require_once __DIR__ . '/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/pfstate.php';

/** @return array<string, string> gateway ip => WAN name */
function wf_t_gws(): array
{
    return ['203.0.113.1@vtnet1' => 'WAN_A', '198.51.100.254@vtnet2' => 'WAN_B'];
}

/**
 * A pfctl that lists $listing for -vvss, exiting $listRc, and fails the kill commands named in $fail.
 *
 * @param list<string> $fail
 * @return array{run: callable(string): array{out: string, rc: int}, calls: ArrayObject}
 */
function wf_t_pfctl(string $listing, array $fail = [], int $listRc = 0): array
{
    $calls = new ArrayObject();
    $run = function (string $cmd) use ($calls, $listing, $fail, $listRc): array {
        $calls[] = $cmd;
        return $cmd === '/sbin/pfctl -vvss' ? ['out' => $listing, 'rc' => $listRc] : ['out' => '', 'rc' => in_array($cmd, $fail, true) ? 1 : 0];
    };
    return ['run' => $run, 'calls' => $calls];
}

wf_register_suite('pfstate', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $states = wf_parse_states((string)file_get_contents(__DIR__ . '/fixtures/states.txt'));
    wf_check($t, 'parses all 21 states', count($states) === 21);
    $u = $states[1];
    wf_check($t, 'NAT out-state: src, orig_src, dst', $u['dir'] === 'out' && $u['src'] === '198.51.100.148:63800'
        && $u['orig_src'] === '192.0.2.140:37460' && $u['dst'] === '198.51.100.57:51820');
    wf_check($t, 'out-state route-to gateway and interface', $u['route_to_gw'] === '198.51.100.254' && $u['route_to_if'] === 'vtnet2');
    wf_check($t, 'id and creatorid', $u['id'] === '33f6d16a00000000' && $u['creatorid'] === '4a28027f');
    wf_check($t, 'rlabel without trailing comma', $u['rlabel'] === 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
    $i = $states[0];
    wf_check($t, 'in-state "dst <- src" maps src and dst', $i['dir'] === 'in' && $i['src'] === '192.0.2.140:37460' && $i['dst'] === '198.51.100.57:51820');
    wf_check($t, 'in-state of a route-to rule keeps its route-to', $states[2]['route_to_gw'] === '198.51.100.254');
    wf_check($t, 'state without rlabel parses with rlabel null', $states[17]['rlabel'] === null && $states[17]['rule'] === 900);
    wf_check($t, 'IPv6 bracket ports parse', $states[12]['src'] === '2001:db8:7::20[49450]' && $states[12]['route_to_gw'] === 'fe80::1');
    wf_check($t, 'wf_addr_host IPv4', wf_addr_host('198.51.100.57:51820') === '198.51.100.57');
    wf_check($t, 'wf_addr_host IPv6', wf_addr_host('2001:db8:100::5[8883]') === '2001:db8:100::5');
    wf_check($t, 'empty output parses to no states', wf_parse_states('') === []);

    $flows = wf_flows($states, wf_t_gws());
    wf_check($t, '7 anchors: ICMP, IPv6, tunnel pin and in-states excluded', count($flows) === 7);
    $kinds = array_count_values(array_column($flows, 'kind'));
    wf_check($t, '5 forwarded, 2 local', ($kinds['forwarded'] ?? 0) === 5 && ($kinds['local'] ?? 0) === 2);
    wf_check($t, 'exit-node pair is forwarded on WAN_B with its in-state partner', $flows[0]['kind'] === 'forwarded'
        && $flows[0]['current'] === 'WAN_B' && $flows[0]['partner']['rlabel'] === '11111111-1111-4111-8111-111111111111');
    wf_check($t, 'no anchor is an in-state', count(array_filter($flows, fn (array $f): bool => $f['anchor']['dir'] !== 'out')) === 0);

    $dup = [$states[0], $states[0], $states[1]];
    $amb = wf_flows($dup, wf_t_gws());
    wf_check($t, 'two matching in-states make the flow ambiguous', count($amb) === 1 && $amb[0]['kind'] === 'ambiguous' && $amb[0]['partner'] === null);
    wf_check($t, 'no states, no flows', wf_flows([], wf_t_gws()) === []);
    $other = $states[1];
    $other['route_to_if'] = 'vtnet1';
    $shared = wf_flows([$states[1], $other], ['198.51.100.254@vtnet1' => 'WAN_A', '198.51.100.254@vtnet2' => 'WAN_B']);
    wf_check($t, 'WANs sharing a gateway address are told apart by interface', count($shared) === 2
        && $shared[0]['current'] === 'WAN_B' && $shared[1]['current'] === 'WAN_A');
    wf_check($t, 'wf_route_target joins gateway and interface as pf prints it', wf_route_target('198.51.100.254', 'vtnet2') === '198.51.100.254@vtnet2');

    wf_check($t, 'route target: an IPv4 gateway is unchanged', wf_route_target('192.0.2.1', 'vtnet1') === '192.0.2.1@vtnet1');
    wf_check($t, 'route target: one IPv6 gateway written two ways is one target',
        wf_route_target('2001:DB8::0050', 'vtnet1') === '2001:db8::50@vtnet1'
        && wf_route_target('2001:db8::50', 'vtnet1') === '2001:db8::50@vtnet1');
    wf_check($t, 'route target: a zoned address, dynamic and a link name stay as written',
        wf_route_target('fe80::1%vtnet1', 'vtnet1') === 'fe80::1%vtnet1@vtnet1'
        && wf_route_target('dynamic', 'vtnet1') === 'dynamic@vtnet1' && wf_route_target('link#5', 'vtnet1') === 'link#5@vtnet1');
    $v6State = wf_parse_states("all tcp 192.0.2.10:30090 -> 198.51.100.128:443       ESTABLISHED:ESTABLISHED\n"
        . "   id: d0000000000000da creatorid: 4a28027f route-to: 2001:db8::50@vtnet1\n");
    wf_check($t, "pf states: a state's target equals the config's target written another way",
        count($v6State) === 1 && $v6State[0]['rt_target'] === wf_route_target('2001:DB8::0050', 'vtnet1'));

    $rules = wf_parse_rules((string)file_get_contents(__DIR__ . '/fixtures/rules.txt'));
    wf_check($t, 'automatic WAN_B out rule renders route-to vtnet2', $rules['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'] === [['gw' => '198.51.100.254', 'if' => 'vtnet2', 'balanced' => false]]);
    wf_check($t, 'one label, two renderings', count($rules['22222222-2222-4222-8222-222222222222']) === 2);
    wf_check($t, 'no route-to renders gw null', $rules['11111111-1111-4111-8111-111111111111'][0]['gw'] === null);
    wf_check($t, 'load-balanced route-to is flagged, gw null', $rules['55555555-5555-4555-8555-555555555555'][0]['balanced'] === true
        && $rules['55555555-5555-4555-8555-555555555555'][0]['gw'] === null);
    wf_check($t, 'empty rules output', wf_parse_rules('') === []);
    $pool = wf_parse_rules('@2901 pass in quick on vlan0.120 route-to { (vtnet2 198.51.100.254), (vtnet2 198.51.100.254) } round-robin inet proto tcp from <b_first_hosts:3> to ! (self:13) flags S/SA keep state label "77777777-7777-4777-8777-777777777777"');
    wf_check($t, 'a pool listing one target several times (gateway weight) routes to that target, not balanced',
        $pool['77777777-7777-4777-8777-777777777777'] === [['gw' => '198.51.100.254', 'if' => 'vtnet2', 'balanced' => false]]);

    $raw = (string)file_get_contents(__DIR__ . '/fixtures/states.txt');
    wf_check($t, 'self-check passes on the real format', wf_pf_selfcheck($raw, $states));
    $renamed = str_replace('route-to: ', 'route_to=', $raw);
    wf_check($t, 'self-check fails when route-to tokens no longer parse', !wf_pf_selfcheck($renamed, wf_parse_states($renamed)));
    /* the first token may be any interface name now, so the drift is in the direction token */
    $headers = str_replace([' -> ', ' <- '], [' => ', ' <= '], $raw);
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
    $local = fn (string $dst): array => ['anchor' => ['dst' => $dst], 'partner' => null, 'kind' => 'local', 'current' => 'WAN_B'];
    $pins = wf_pinned_hosts([$local('198.51.100.7:53'), $local('198.51.100.8:53'), $local('198.51.100.9:53'), $local('198.51.100.7:853')], $lookup, 2);
    wf_check($t, 'pinned: looked-up hosts by route, hosts past the cap spared as pinned, each host looked up once',
        $pins === ['198.51.100.7' => true, '198.51.100.9' => true] && $looked === ['198.51.100.7', '198.51.100.8']);

    wf_check($t, '(p2) rt is the token pf printed and rt_target its gateway@interface; route_to_gw and route_to_if are set for route-to only',
        $states[18]['rt'] === 'route-to' && $states[18]['rt_target'] === '192.0.2.1@vtnet1'
        && $states[18]['route_to_gw'] === '192.0.2.1' && $states[18]['route_to_if'] === 'vtnet1'
        && $states[20]['rt'] === 'reply-to' && $states[20]['rt_target'] === '192.0.2.1@vtnet1'
        && $states[20]['route_to_gw'] === null && $states[20]['route_to_if'] === null
        && $states[17]['rt'] === null && $states[17]['rt_target'] === null);
    $dupTo = wf_parse_states("all tcp 192.0.2.10:30040 -> 198.51.100.124:443       ESTABLISHED:ESTABLISHED\n"
        . "   id: d0000000000000d4 creatorid: 4a28027f dup-to: 192.0.2.1@vtnet1\n");
    wf_check($t, '(p2) any other "-to:" token pf prints parses into rt, never into route_to_gw',
        $dupTo[0]['rt'] === 'dup-to' && $dupTo[0]['rt_target'] === '192.0.2.1@vtnet1' && $dupTo[0]['route_to_gw'] === null);
    /* a state header in a form the parser does not know (here a direction token it has never seen) */
    $unparsed = wf_parse_states("all tcp 192.0.2.10:30050 -> 198.51.100.125:443       ESTABLISHED:ESTABLISHED\n"
        . "   id: d0000000000000d5 creatorid: 4a28027f route-to: 192.0.2.1@vtnet1\n"
        . "all tcp 192.0.2.20:30060 => 198.51.100.125:443       ESTABLISHED:ESTABLISHED\n"
        . "   id: d0000000000000d6 creatorid: 4a28027f\n");
    wf_check($t, '(p4) the lines of a state whose header does not parse belong to no state: its id never pairs with the target before it',
        count($unparsed) === 1 && $unparsed[0]['id'] === 'd0000000000000d5' && $unparsed[0]['rt_target'] === '192.0.2.1@vtnet1');
    $replyRenamed = str_replace('reply-to: ', 'reply_to=', $raw);
    wf_check($t, '(p5) self-check fails when one target token no longer parses while another still does',
        !wf_pf_selfcheck($replyRenamed, wf_parse_states($replyRenamed)));

    wf_check($t, '(p1) the states via 192.0.2.1@vtnet1 are its route-to and reply-to states, none of vtnet2\'s',
        wf_states_via($states, '192.0.2.1@vtnet1') === [['id' => 'd0000000000000d1', 'creatorid' => '4a28027f'],
                                                       ['id' => 'd0000000000000d3', 'creatorid' => '4a28027f']]);
    $p = wf_t_pfctl($raw);
    wf_check($t, '(p3) a kill via 192.0.2.1@vtnet1 lists the states once, then kills exactly its two states by id',
        wf_kill_states_run('192.0.2.1@vtnet1', $p['run']) === ['line' => 'killed 2 states (0 failed)', 'rc' => 0]
        && $p['calls']->getArrayCopy() === ['/sbin/pfctl -vvss', '/sbin/pfctl -k id -k d0000000000000d1/4a28027f',
                                            '/sbin/pfctl -k id -k d0000000000000d3/4a28027f']);
    $p = wf_t_pfctl($raw, ['/sbin/pfctl -k id -k d0000000000000d3/4a28027f']);
    wf_check($t, '(p3) a kill pfctl fails is counted as failed, not killed',
        wf_kill_states_run('192.0.2.1@vtnet1', $p['run']) === ['line' => 'killed 1 states (1 failed)', 'rc' => 0]);
    $p = wf_t_pfctl($raw);
    wf_check($t, '(p3) a target that is not gateway@interface is rejected before any pfctl call',
        wf_kill_states_run('x;y', $p['run']) === ['line' => 'rejected target', 'rc' => 1] && $p['calls']->getArrayCopy() === []);
    $p = wf_t_pfctl($raw, [], 1);
    wf_check($t, '(p6) a listing pfctl fails is reported with its exit status, and nothing is killed',
        wf_kill_states_run('192.0.2.1@vtnet1', $p['run']) === ['line' => 'listing failed: pfctl exited 1', 'rc' => 1]
        && $p['calls']->getArrayCopy() === ['/sbin/pfctl -vvss']);
    $p = wf_t_pfctl('');
    wf_check($t, '(p7) a listing that fails the self-check (no states at all) is reported, and nothing is killed',
        wf_kill_states_run('192.0.2.1@vtnet1', $p['run']) === ['line' => 'listing failed: the state listing did not parse', 'rc' => 1]
        && $p['calls']->getArrayCopy() === ['/sbin/pfctl -vvss']);

    /* "bind states to interface": an interface-bound state prints its interface where a floating one prints "all" */
    $mixedRaw = "all tcp 192.0.2.10:30070 -> 198.51.100.126:443       ESTABLISHED:ESTABLISHED\n"
        . "   age 00:01:00, expires in 23:59:59, 10:10 pkts, 900:900 bytes, rule 196, rlabel eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee, allow-opts\n"
        . "   id: d0000000000000d7 creatorid: 4a28027f route-to: 192.0.2.1@vtnet1\n"
        . "   origif: vtnet1\n"
        . "vtnet1 tcp 192.0.2.10:30080 -> 198.51.100.127:443       ESTABLISHED:ESTABLISHED\n"
        . "   age 00:01:00, expires in 23:59:59, 10:10 pkts, 900:900 bytes, rule 198, rlabel 88888888-8888-4888-8888-888888888888, allow-opts\n"
        . "   id: d0000000000000d8 creatorid: 5b39138a route-to: 192.0.2.1@vtnet1\n"
        . "   origif: vtnet1\n"
        . "vtnet0 tcp 198.51.100.126:443 <- 192.0.2.10:30070       ESTABLISHED:ESTABLISHED\n"
        . "   age 00:01:00, expires in 23:59:59, 10:10 pkts, 900:900 bytes, rule 2610, rlabel 99999999-9999-4999-8999-999999999999\n"
        . "   id: d0000000000000d9 creatorid: 5b39138a\n"
        . "   origif: vtnet0\n";
    $mixed = wf_parse_states($mixedRaw);
    wf_check($t, '(p8) a floating and an interface-bound state via one target are both killed by it, and the listing passes the self-check',
        count($mixed) === 3 && $mixed[0]['bound'] === null && $mixed[1]['bound'] === 'vtnet1' && $mixed[2]['bound'] === 'vtnet0'
        && wf_states_via($mixed, '192.0.2.1@vtnet1') === [['id' => 'd0000000000000d7', 'creatorid' => '4a28027f'],
                                                         ['id' => 'd0000000000000d8', 'creatorid' => '5b39138a']]
        && wf_pf_selfcheck($mixedRaw, $mixed));
    $mixedFlows = wf_flows($mixed, ['192.0.2.1@vtnet1' => 'WAN_A']);
    wf_check($t, '(p9) failback pairs floating states only: the bound anchor is skipped and the bound in-state is no partner',
        count($mixed) === 3 && count($mixedFlows) === 1 && $mixedFlows[0]['anchor']['id'] === 'd0000000000000d7'
        && $mixedFlows[0]['kind'] === 'local' && $mixedFlows[0]['partner'] === null);
    wf_check($t, '(h4) a kill answer is clean only when every state it found was killed, as wf_kill_states_run() says it',
        wf_kill_answer_clean('killed 3 states (0 failed)') && wf_kill_answer_clean('killed 0 states (0 failed)')
        && !wf_kill_answer_clean('killed 3 states (1 failed)') && !wf_kill_answer_clean('listing failed: pfctl exited 1')
        && !wf_kill_answer_clean("killed 3 states (0 failed)\n") && !wf_kill_answer_clean('rejected target'));

    /* each line of every fixture, with the rendering it parses to: the cases above, line by line, and the weighted pool */
    $rulesRaw = (string)file_get_contents(__DIR__ . '/fixtures/rules.txt');
    $ruleLines = preg_split('/\R/', trim($rulesRaw)) ?: [];
    $weighted = '@2901 pass in quick on vlan0.120 route-to { (vtnet2 198.51.100.254), (vtnet2 198.51.100.254) } round-robin inet proto tcp from <b_first_hosts:3> to ! (self:13) flags S/SA keep state label "77777777-7777-4777-8777-777777777777"';
    $toB = [['gw' => '198.51.100.254', 'if' => 'vtnet2', 'balanced' => false]];
    $rendered = [
        [$ruleLines[0] ?? '', ['dddddddddddddddddddddddddddddddd' => [['gw' => '203.0.113.1', 'if' => 'vtnet1', 'balanced' => false]]]],
        [$ruleLines[1] ?? '', ['aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' => $toB]],
        [$ruleLines[2] ?? '', ['22222222-2222-4222-8222-222222222222' => $toB]],
        [$ruleLines[3] ?? '', ['22222222-2222-4222-8222-222222222222' => $toB]],
        [$ruleLines[4] ?? '', ['11111111-1111-4111-8111-111111111111' => [['gw' => null, 'if' => null, 'balanced' => false]]]],
        [$ruleLines[5] ?? '', ['55555555-5555-4555-8555-555555555555' => [['gw' => null, 'if' => null, 'balanced' => true]]]],
        [$weighted, ['77777777-7777-4777-8777-777777777777' => $toB]],
    ];
    foreach (preg_split('/\R/', $raw) ?: [] as $stateLine) {
        $rendered[] = [$stateLine, []];
    }
    $unchanged = count($ruleLines) === 6;
    foreach ($rendered as [$line, $want]) {
        $unchanged = $unchanged && wf_parse_rules($line) === $want;
    }
    wf_check($t, "parse rules: the fixture's renderings are unchanged", $unchanged);

    $agree = wf_rule_targets($ruleLines[5] ?? '') === ['vtnet1 203.0.113.1' => ['vtnet1', '203.0.113.1'],
                                                       'vtnet2 198.51.100.254' => ['vtnet2', '198.51.100.254']]
        && wf_rule_targets($weighted) === ['vtnet2 198.51.100.254' => ['vtnet2', '198.51.100.254']]
        && wf_rule_targets($ruleLines[4] ?? '') === [];
    foreach ($rendered as [$line, $want]) {
        $targets = wf_rule_targets($line);
        $single = count($targets) === 1 ? reset($targets) : null;
        $agree = $agree && ($want === [] || array_values($want)[0] === [['gw' => $single === null ? null : $single[1],
            'if' => $single === null ? null : $single[0], 'balanced' => count($targets) > 1]]);
    }
    wf_check($t, "rule targets: each fixture line's targets are what its rendering reads", $agree);

    wf_check($t, 'rules selfcheck: the fixture listing is clean', wf_rules_selfcheck($rulesRaw));
    wf_check($t, 'rules selfcheck: an empty listing is a drift', !wf_rules_selfcheck(''));
    $labelsMoved = str_replace('label "', 'label:', $rulesRaw);
    wf_check($t, 'rules selfcheck: labels that no longer parse are a drift',
        $labelsMoved !== $rulesRaw && !wf_rules_selfcheck($labelsMoved));
    $targetsMoved = (string)preg_replace('/\((vtnet\d+) /', '($1:', $rulesRaw);
    wf_check($t, 'rules selfcheck: route-to targets that no longer parse are a drift',
        !str_contains($targetsMoved, '(vtnet1 ') && !str_contains($targetsMoved, '(vtnet2 ') && !wf_rules_selfcheck($targetsMoved));
    wf_check($t, 'rules selfcheck: a listing with labels and no route-to is clean', wf_rules_selfcheck($ruleLines[4] ?? ''));
    wf_check($t, 'rules selfcheck: one route-to line of an unread form beside parsed ones is not a drift',
        wf_rules_selfcheck($rulesRaw . '@2500 pass in quick on vlan0.140 route-to vtnet9 inet proto tcp from any to any keep state '
            . "label \"66666666-6666-4666-8666-666666666666\"\n"));
    return wf_tally_report('pfstate', $t);
});
