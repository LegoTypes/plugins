<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The shape checks for names that come from a restored configuration: gateway names, interface names and
 * state-kill targets. Pure; runs anywhere.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/parsers.php';

wf_register_suite('parsers', function (): int {
    $t = ['fail' => 0, 'total' => 0];

    /* core's mask allows a dash, so a tunnel gateway name such as wg-test-429 is a valid name */
    $good = ['WAN_A', 'WAN_B', 'WAN_DHCP', 'wg-test-429', str_repeat('a', 32)];
    $bad = ['../x', 'a b', 'x;y', '', "WAN_A\n", str_repeat('a', 33)];
    wf_check($t, '(n1) wf_name_ok accepts ' . implode(', ', array_slice($good, 0, 4)) . ' and a 32-character name',
        array_filter($good, 'wf_name_ok') === $good);
    wf_check($t, '(n2) wf_name_ok rejects a path, a space, a semicolon, an empty name, a trailing newline and 33 characters',
        array_filter($bad, 'wf_name_ok') === []);

    wf_check($t, '(i1) wf_if_ok accepts vtnet1, vtnet0, epair1a, vlan0.100 and wg9',
        array_filter(['vtnet1', 'vtnet0', 'epair1a', 'vlan0.100', 'wg9'], 'wf_if_ok') === ['vtnet1', 'vtnet0', 'epair1a', 'vlan0.100', 'wg9']);
    wf_check($t, '(i2) wf_if_ok rejects a semicolon, a capital, a trailing newline and an empty name',
        array_filter(['vtnet1;x', 'Vtnet1', "vtnet1\n", ''], 'wf_if_ok') === []);

    wf_check($t, '(k1) wf_kill_target_ok accepts 192.0.2.1@vtnet1', wf_kill_target_ok('192.0.2.1@vtnet1'));
    $badTargets = ['999.1.1.1@vtnet1', '192.0.2.1@', '@vtnet1', '192.0.2.1@vtnet1;x', '2001:db8::1@vtnet1', "192.0.2.1@vtnet1\n"];
    wf_check($t, '(k2) wf_kill_target_ok rejects an address out of range, a missing side, a trailing token, IPv6 and a trailing newline',
        array_filter($badTargets, 'wf_kill_target_ok') === []);

    return wf_tally_report('parsers', $t);
});
