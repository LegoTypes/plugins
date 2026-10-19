<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The text core's firewall plugin renders from the allow-list confs. Runs only where core's MVC library is
 * present (the test VM); elsewhere it registers a suite that skips.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/constants.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/render.php';
require_once __DIR__ . '/test_verdict.php';

uu_register_suite('render_vm', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    if (!is_readable('/usr/local/opnsense/mvc/app/library/OPNsense/Firewall/Plugin.php')) {
        printf("[SKIP] render_vm: core's firewall plugin is not on this machine\n");
        return uu_tally_report('render_vm', $t);
    }
    $fw = new \OPNsense\Firewall\Plugin();
    $mapping = [
        'opt1' => ['if' => 'wg1', 'descr' => 'WG_TEST_A', 'ifconfig' => ['ipv4' => [['ipaddr' => '10.2.0.2', 'subnetbits' => 32]]]],
        'opt2' => ['if' => 'wg2', 'descr' => 'WG_TEST_B', 'ifconfig' => ['ipv4' => [['ipaddr' => '10.2.0.3', 'subnetbits' => 32]]]],
    ];
    $fw->setInterfaceMapping($mapping);
    $a = uu_test_member();
    $b = uu_test_member();
    $b['name'] = 'wg-b';
    $b['interface'] = 'opt2';
    $b['if'] = 'wg2';
    uu_render_firewall($fw, fn (): array => ['enabled' => true, 'resolver' => '10.2.0.1', 'members' => [$a, $b]]);
    $text = $fw->outputFilterRules();
    uu_check($t, 'rendered on the tunnel device wg1', str_contains($text, 'on wg1 '));
    uu_check($t, 'rendered on the tunnel device wg2', str_contains($text, 'on wg2 '));
    uu_check($t, 'the source is the interface address (opt1ip rendered as (wg1))', str_contains($text, 'on wg1 inet proto {tcp udp} from {(wg1)} to {10.2.0.1} port {53}'));
    uu_check($t, 'the backstop block to the resolver literal is present', str_contains($text, 'block out log quick inet from {any} to {10.2.0.1}'));
    uu_check($t, 'the counting block targets the plugin table',
        str_contains($text, 'block out log quick inet from {any} to {<__unboundupstream_block>}'));
    uu_check($t, 'the table is declared bare: no persist, no file',
        preg_match('/^table <__unboundupstream_block>$/m', $fw->tablesToText()) === 1);
    uu_check($t, 'no unresolved ## placeholder', !str_contains($text, '##'));
    printf("%s", preg_replace('/^/m', '    | ', $text));
    return uu_tally_report('render_vm', $t);
});
