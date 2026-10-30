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
 * Failback preference and live-rule gate.
 */

require_once __DIR__ . '/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/pfstate.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/failback.php';

wf_register_suite('failback', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $states = wf_parse_states((string)file_get_contents(__DIR__ . '/fixtures/states.txt'));
    $rules = wf_parse_rules((string)file_get_contents(__DIR__ . '/fixtures/rules.txt'));
    $flows = wf_flows($states, ['203.0.113.1@vtnet1' => 'WAN_A', '198.51.100.254@vtnet2' => 'WAN_B']);
    $gwIp = ['WAN_A' => '203.0.113.1@vtnet1', 'WAN_B' => '198.51.100.254@vtnet2'];
    $pinned = ['198.51.100.200' => true];
    $pref = [
        '22222222-2222-4222-8222-222222222222' => ['WAN_B'],
        '33333333-3333-4333-8333-333333333333' => [],
    ];
    $ids = fn (array $g): array => array_map(fn (array $k): string => $k['id'], $g['kills']);

    $g = wf_failback_gate('WAN_A', $flows, $pref, $rules, $gwIp, 'WAN_A', true, $pinned);
    wf_check($t, 'WAN_A recovery with default on WAN_A: ready', $g['ready'] && $g['default_ok']);
    wf_check($t, 'kills exit-node pair, default-route pair, firewall DoT flow (anchor first, then partner)', $ids($g) === [
        '33f6d16a00000000', '32f6d16a00000000', '50000000000000b2', '50000000000000b1', '60000000000000c1']);
    wf_check($t, 'spares WAN_B-first, pinned, flows already on WAN_A', $g['spared'] === 4);

    $g = wf_failback_gate('WAN_A', $flows, $pref, $rules, $gwIp, 'WAN_B', true, $pinned);
    wf_check($t, 'default not yet on WAN_A: not ready, nothing killed, so no flow moves ahead of the default', !$g['ready'] && !$g['default_ok'] && $g['kills'] === []);

    $g = wf_failback_gate('WAN_B', $flows, $pref, $rules, $gwIp, 'WAN_A', false, $pinned);
    wf_check($t, 'WAN_B recovery: only the WAN_B-first pair on WAN_A is killed', $g['ready'] && $ids($g) === ['c0000000000000c2', 'c0000000000000c1']);

    $staleRules = $rules;
    $staleRules['22222222-2222-4222-8222-222222222222'][1] = ['gw' => '203.0.113.1', 'if' => 'vtnet1', 'balanced' => false];
    $g = wf_failback_gate('WAN_B', $flows, $pref, $staleRules, $gwIp, 'WAN_A', false, $pinned);
    wf_check($t, 'one of two renderings still on WAN_A: stale, not ready, not killed', !$g['ready']
        && $g['stale_labels'] === ['22222222-2222-4222-8222-222222222222'] && $g['kills'] === []);

    $split = $pref + ['11111111-1111-4111-8111-111111111111' => ['WAN_A']];
    $g = wf_failback_gate('WAN_A', $flows, $split, $rules, $gwIp, 'WAN_A', true, $pinned);
    wf_check($t, 'after the exit-node rule split, rule 1111 rendered without route-to is stale', !$g['ready']
        && in_array('11111111-1111-4111-8111-111111111111', $g['stale_labels'], true)
        && !in_array('32f6d16a00000000', $ids($g), true));
    $moved = $rules;
    $moved['11111111-1111-4111-8111-111111111111'] = [['gw' => '203.0.113.1', 'if' => 'vtnet1', 'balanced' => false]];
    $g = wf_failback_gate('WAN_A', $flows, $split, $moved, $gwIp, 'WAN_A', true, $pinned);
    wf_check($t, 'after the split, once rendered to WAN_A: exit-node pair killed', $g['ready'] && in_array('32f6d16a00000000', $ids($g), true));

    $wrongIf = $rules;
    $wrongIf['22222222-2222-4222-8222-222222222222'][1] = ['gw' => '198.51.100.254', 'if' => 'vtnet1', 'balanced' => false];
    $g = wf_failback_gate('WAN_B', $flows, $pref, $wrongIf, $gwIp, 'WAN_A', false, $pinned);
    wf_check($t, 'a rendering to the same gateway address on another interface is not on the recovering WAN', !$g['ready']
        && $g['stale_labels'] === ['22222222-2222-4222-8222-222222222222']);

    $weighted = $rules;
    $weighted['22222222-2222-4222-8222-222222222222'] = wf_parse_rules('@2310 pass in quick on vlan0.120 route-to { (vtnet2 198.51.100.254), (vtnet2 198.51.100.254) } round-robin inet proto tcp from <b_first_hosts:2> to ! (self) flags S/SA keep state label "22222222-2222-4222-8222-222222222222"')['22222222-2222-4222-8222-222222222222'];
    $g = wf_failback_gate('WAN_B', $flows, $pref, $weighted, $gwIp, 'WAN_A', false, $pinned);
    wf_check($t, 'WAN_B recovery with the group rendered as a weighted pool of WAN_B alone: ready, WAN_B-first pair killed',
        $g['ready'] && $ids($g) === ['c0000000000000c2', 'c0000000000000c1']);

    $v6Targets = ['WAN_A' => $gwIp['WAN_A'], 'WAN_B' => wf_route_target('2001:DB8::0050', 'vtnet2')];
    $v6Rules = $rules;
    $v6Rules['22222222-2222-4222-8222-222222222222'] = [['gw' => '2001:db8::50', 'if' => 'vtnet2', 'balanced' => false],
                                                         ['gw' => '2001:db8::50', 'if' => 'vtnet2', 'balanced' => false]];
    $g = wf_failback_gate('WAN_B', $flows, $pref, $v6Rules, $v6Targets, 'WAN_A', false, $pinned);
    wf_check($t, 'failback: a rule rendering written another way still counts as on the recovering WAN',
        $g['ready'] && $g['stale_labels'] === [] && $ids($g) === ['c0000000000000c2', 'c0000000000000c1']);

    $amb = [['anchor' => $states[1], 'partner' => null, 'kind' => 'ambiguous', 'current' => 'WAN_B']];
    $g = wf_failback_gate('WAN_A', $amb, $pref, $rules, $gwIp, 'WAN_A', true, $pinned);
    wf_check($t, 'ambiguous flows are spared', $g['kills'] === [] && $g['spared'] === 1);

    wf_check($t, 'wf_preferred: local flow to a pinned destination has no preference',
        wf_preferred($flows[4], $pref, 'WAN_A', $pinned) === null);

    /* core 26.7.7's group rows: tiers 1-5, each explode(',') of its item field, an empty tier [''] */
    $core = fn (array $named): array => ['tiers' => array_replace([1 => [''], 2 => [''], 3 => [''], 4 => [''], 5 => ['']], $named)];
    $coreGroups = ['G_ONE' => $core([1 => ['WAN_A']]), 'G_EMPTY' => $core([]), 'G_LATE' => $core([2 => ['WAN_B']]),
                   'G_NONE' => ['tiers' => []]];
    $ruleGateways = ['r1' => 'G_ONE', 'r2' => 'G_EMPTY', 'r3' => 'G_LATE', 'r4' => 'G_NONE', 'r5' => 'WAN_A', 'r6' => ''];
    wf_check($t, "rule pref: core's group shapes give the first tier with members, an empty group none",
        wf_rule_pref($ruleGateways, $coreGroups) === ['r1' => ['WAN_A'], 'r2' => [], 'r3' => ['WAN_B'], 'r4' => [],
                                                      'r5' => ['WAN_A'], 'r6' => []]);
    $drifted = $coreGroups + ['G_STR' => ['tiers' => 'WAN_A'], 'G_ROW' => [], 'G_INT' => ['tiers' => [1 => [7]]], 'G_SCALAR' => 'WAN_A'];
    wf_check($t, 'rule pref: a drifted group, or groups that cannot be read, give no preference and never throw',
        wf_rule_pref(['r1' => 'G_ONE', 'r7' => 'G_STR', 'r8' => 'G_ROW', 'r9' => 'G_INT', 'r10' => 'G_SCALAR'], $drifted)
            === ['r1' => ['WAN_A'], 'r7' => [], 'r8' => [], 'r9' => [], 'r10' => []]
        && wf_rule_pref($ruleGateways, null) === ['r1' => [], 'r2' => [], 'r3' => [], 'r4' => [], 'r5' => [], 'r6' => []]);

    /* the dry run reads the same pf state the gate would and says what the gate would do with it */
    $pf = ['flows' => $flows, 'renderings' => $rules, 'pinned' => $pinned, 'rule_pref' => $pref, 'default' => 'WAN_A',
           'selfcheck' => true, 'drift' => []];
    $ready = wf_failback_gate('WAN_A', $flows, $pref, $rules, $gwIp, 'WAN_A', true, $pinned);
    $stale = wf_failback_gate('WAN_A', $flows, $pref, $rules, $gwIp, 'WAN_B', true, $pinned);
    wf_check($t, 'failback dry run: a read the gate would suspend on says failback suspended, as the gate logs it',
        wf_failback_dry('WAN_A', array_merge($pf, ['drift' => ['x']]), $gwIp, true)
            === '[dry] failback WAN_A: x (core contract); failback suspended'
        && wf_failback_dry('WAN_A', array_merge($pf, ['selfcheck' => false]), $gwIp, true)
            === '[dry] failback WAN_A: pf state format did not parse (core contract); failback suspended'
        && wf_failback_dry('WAN_A', array_merge($pf, ['selfcheck' => false, 'drift' => ['x']]), $gwIp, true)
            === '[dry] failback WAN_A: x; pf state format did not parse (core contract); failback suspended');
    wf_check($t, 'failback dry run: a read the gate would act on says what it would kill and spare',
        $ready['ready'] && $ready['kills'] !== [] && !$stale['ready']
        && wf_failback_dry('WAN_A', $pf, $gwIp, true) === sprintf('[dry] failback WAN_A would kill %d states, spare %d flows',
            count($ready['kills']), $ready['spared'])
        && wf_failback_dry('WAN_A', array_merge($pf, ['default' => 'WAN_B']), $gwIp, true)
            === sprintf('[dry] failback WAN_A would kill %d states, spare %d flows (not ready)', count($stale['kills']), $stale['spared']));
    /* a listing pfctl did not give whole on two tries (wf_pf_listing()) tells no drift */
    $rulesUnread = 'pfctl -vvsr could not be read';
    $statesUnread = 'pfctl -vvss could not be read';
    wf_check($t, 'failback: a pf listing that could not be read leaves the failback pending and names the listing, not a drift',
        wf_failback_suspended('WAN_A', array_merge($pf, ['drift' => [$rulesUnread]]))
            === 'failback WAN_A: pfctl -vvsr could not be read; still pending'
        && wf_failback_suspended('WAN_A', array_merge($pf, ['selfcheck' => false, 'drift' => [$statesUnread, $rulesUnread, 'x']]))
            === 'failback WAN_A: pfctl -vvss could not be read; pfctl -vvsr could not be read; still pending'
        && wf_failback_dry('WAN_A', array_merge($pf, ['drift' => [$rulesUnread]]), $gwIp, true)
            === '[dry] failback WAN_A: pfctl -vvsr could not be read; still pending');
    return wf_tally_report('failback', $t);
});
