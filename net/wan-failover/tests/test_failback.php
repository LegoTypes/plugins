<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Failback preference and live-rule gate.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/selftest.php';
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

    $amb = [['anchor' => $states[1], 'partner' => null, 'kind' => 'ambiguous', 'current' => 'WAN_B']];
    $g = wf_failback_gate('WAN_A', $amb, $pref, $rules, $gwIp, 'WAN_A', true, $pinned);
    wf_check($t, 'ambiguous flows are spared', $g['kills'] === [] && $g['spared'] === 1);

    wf_check($t, 'wf_preferred: local flow to a pinned destination has no preference',
        wf_preferred($flows[4], $pref, 'WAN_A', $pinned) === null);
    return wf_tally_report('failback', $t);
});
