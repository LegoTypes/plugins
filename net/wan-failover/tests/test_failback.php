<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Failback preference and live-rule gate, spec section 3.5.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/pfstate.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/failback.php';

wf_register_suite('failback', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $states = wf_parse_states((string)file_get_contents(__DIR__ . '/fixtures/states.txt'));
    $rules = wf_parse_rules((string)file_get_contents(__DIR__ . '/fixtures/rules.txt'));
    $flows = wf_flows($states, ['203.0.113.1@igc1' => 'PRIMARY_WAN', '192.168.12.1@igc2' => 'WAN2']);
    $gwIp = ['PRIMARY_WAN' => '203.0.113.1@igc1', 'WAN2' => '192.168.12.1@igc2'];
    $pinned = ['198.51.100.200' => true];
    $pref = [
        '22222222-2222-4222-8222-222222222222' => ['WAN2'],
        '33333333-3333-4333-8333-333333333333' => [],
    ];
    $ids = fn (array $g): array => array_map(fn (array $k): string => $k['id'], $g['kills']);

    $g = wf_failback_gate('PRIMARY_WAN', $flows, $pref, $rules, $gwIp, 'PRIMARY_WAN', true, $pinned);
    wf_check($t, 'PRIMARY recovery with default on PRIMARY: ready', $g['ready'] && $g['default_ok']);
    wf_check($t, 'kills unifi pair, default-route pair, firewall DoT flow (anchor first, then partner)', $ids($g) === [
        '33f6d16a00000000', '32f6d16a00000000', '50000000000000b2', '50000000000000b1', '60000000000000c1']);
    wf_check($t, 'spares WAN2-first, pinned, flows already on PRIMARY', $g['spared'] === 4);

    $g = wf_failback_gate('PRIMARY_WAN', $flows, $pref, $rules, $gwIp, 'WAN2', true, $pinned);
    wf_check($t, 'default not yet on PRIMARY: not ready, nothing killed (B2, M4)', !$g['ready'] && !$g['default_ok'] && $g['kills'] === []);

    $g = wf_failback_gate('WAN2', $flows, $pref, $rules, $gwIp, 'PRIMARY_WAN', false, $pinned);
    wf_check($t, 'WAN2 recovery: only the WAN2-first pair on PRIMARY is killed', $g['ready'] && $ids($g) === ['c0000000000000c2', 'c0000000000000c1']);

    $staleRules = $rules;
    $staleRules['22222222-2222-4222-8222-222222222222'][1] = ['gw' => '203.0.113.1', 'if' => 'igc1', 'balanced' => false];
    $g = wf_failback_gate('WAN2', $flows, $pref, $staleRules, $gwIp, 'PRIMARY_WAN', false, $pinned);
    wf_check($t, 'one of two renderings still on PRIMARY: stale, not ready, not killed', !$g['ready']
        && $g['stale_labels'] === ['22222222-2222-4222-8222-222222222222'] && $g['kills'] === []);

    $split = $pref + ['11111111-1111-4111-8111-111111111111' => ['PRIMARY_WAN']];
    $g = wf_failback_gate('PRIMARY_WAN', $flows, $split, $rules, $gwIp, 'PRIMARY_WAN', true, $pinned);
    wf_check($t, 'after the unifi split, rule 1111 rendered without route-to is stale', !$g['ready']
        && in_array('11111111-1111-4111-8111-111111111111', $g['stale_labels'], true)
        && !in_array('32f6d16a00000000', $ids($g), true));
    $moved = $rules;
    $moved['11111111-1111-4111-8111-111111111111'] = [['gw' => '203.0.113.1', 'if' => 'igc1', 'balanced' => false]];
    $g = wf_failback_gate('PRIMARY_WAN', $flows, $split, $moved, $gwIp, 'PRIMARY_WAN', true, $pinned);
    wf_check($t, 'after the split, once rendered to PRIMARY: unifi pair killed', $g['ready'] && in_array('32f6d16a00000000', $ids($g), true));

    $wrongIf = $rules;
    $wrongIf['22222222-2222-4222-8222-222222222222'][1] = ['gw' => '192.168.12.1', 'if' => 'igc1', 'balanced' => false];
    $g = wf_failback_gate('WAN2', $flows, $pref, $wrongIf, $gwIp, 'PRIMARY_WAN', false, $pinned);
    wf_check($t, 'a rendering to the same gateway address on another interface is not on the recovering WAN', !$g['ready']
        && $g['stale_labels'] === ['22222222-2222-4222-8222-222222222222']);

    $amb = [['anchor' => $states[1], 'partner' => null, 'kind' => 'ambiguous', 'current' => 'WAN2']];
    $g = wf_failback_gate('PRIMARY_WAN', $amb, $pref, $rules, $gwIp, 'PRIMARY_WAN', true, $pinned);
    wf_check($t, 'ambiguous flows are spared', $g['kills'] === [] && $g['spared'] === 1);

    wf_check($t, 'wf_preferred: local flow to a pinned destination has no preference',
        wf_preferred($flows[4], $pref, 'PRIMARY_WAN', $pinned) === null);
    return wf_tally_report('failback', $t);
});
