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
require_once __DIR__ . '/scratch.php';

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
    $resolving = fn (array $members, string $resolver): array
        => array_map(fn (array $m): array => $m + ['resolver' => $resolver], $members);
    uu_render_firewall($fw, fn (): array => ['enabled' => true, 'default' => '10.2.0.1',
        'members' => $resolving([$a, $b], '10.2.0.1'), 'addresses' => ['10.2.0.1'], 'footprints' => [],
        'footprint_problem' => null, 'error' => null]);
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
    /* 1.3_2's pass line for one IPv4 resolver, as core rendered its conf */
    $line132 = fn (string $dev, string $opt): string => 'pass out quick on ' . $dev . ' inet proto {tcp udp} from {('
        . $dev . ')} to {10.2.0.1} port {53} label "' . md5('uu-pass-' . $opt) . '" # Unbound upstream: the resolver '
        . 'through this member';
    $now = fn (string $dev, string $opt): string => str_replace('port {53} label "' . md5('uu-pass-' . $opt) . '"',
        'port {53} flags any keep state ( if-bound ) label "' . md5('uu-pass-' . $opt . '-10.2.0.1') . '"',
        $line132($dev, $opt));
    uu_check($t, '(r5) each one-address pass is 1.3_2\'s line but for its label and its states, kept if-bound with '
        . 'any flags',
        $now('wg1', 'opt1') !== $line132('wg1', 'opt1')
        && in_array($now('wg1', 'opt1'), explode("\n", $text), true)
        && in_array($now('wg2', 'opt2'), explode("\n", $text), true));
    printf("%s", preg_replace('/^/m', '    | ', $text));

    /* (r10) the footprint's rules with the plugin disabled: a pass on the route's device */
    $fw = new \OPNsense\Firewall\Plugin();
    $fw->setInterfaceMapping($mapping);
    uu_render_firewall($fw, fn (): array => ['enabled' => false, 'default' => '', 'members' => [], 'addresses' => [],
        'footprints' => [['resolver' => '192.0.2.1', 'interface' => 'opt1']], 'footprint_problem' => null,
        'error' => null]);
    $text = $fw->outputFilterRules();
    uu_check($t, '(r10) the footprint pass on opt1 renders on wg1, from its address, to 192.0.2.1 port 53, under '
        . 'its own label',
        preg_match('/on wg1 inet proto \{tcp udp\} from \{\(wg1\)\} to \{192\.0\.2\.1\} port \{53\}[^\n]*label "'
            . md5('uu-footprint-pass-opt1-192.0.2.1') . '"/', $text) === 1);
    uu_check($t, '(r10) the footprint block to the address, under its own label',
        preg_match('/block out log quick inet from \{any\} to \{192\.0\.2\.1\}[^\n]*label "' . md5('uu-footprint')
            . '"/', $text) === 1);
    uu_check($t, '(r10) no table and no unresolved ## placeholder',
        !str_contains($text, UU_BLOCK_TABLE) && !str_contains($text, '##') && trim($fw->tablesToText()) === '');
    printf("%s", preg_replace('/^/m', '    | ', $text));

    /* (t9) an IPv6 resolver: core renders the passes and blocks as inet6 (core's address map is built once per
     * process, so this uses the interface the first render did) */
    $fw = new \OPNsense\Firewall\Plugin();
    $mapping6 = [
        'opt1' => ['if' => 'wg1', 'descr' => 'WG_TEST_A', 'ifconfig' => ['ipv6' => [['ipaddr' => 'fd00::1:1', 'subnetbits' => 128]]]],
    ];
    $fw->setInterfaceMapping($mapping6);
    $c = uu_test_member();
    $c['name'] = 'wg-a6';
    $c['interface'] = 'opt1';
    $c['if'] = 'wg1';
    uu_render_firewall($fw, fn (): array => ['enabled' => true, 'default' => '2001:db8:a::53',
        'members' => $resolving([$c], '2001:db8:a::53'), 'addresses' => ['2001:db8:a::53'], 'footprints' => [],
        'footprint_problem' => null, 'error' => null]);
    $text = $fw->outputFilterRules();
    uu_check($t, '(t9) the IPv6 pass renders on wg1 as inet6, from the interface address, to the resolver, port 53',
        str_contains($text, 'on wg1 inet6 proto {tcp udp} from {(wg1)} to {2001:db8:a::53} port {53}'));
    uu_check($t, '(t9) the IPv6 backstop and counting blocks render as inet6',
        str_contains($text, 'block out log quick inet6 from {any} to {2001:db8:a::53}')
        && str_contains($text, 'block out log quick inet6 from {any} to {<__unboundupstream_block>}'));
    uu_check($t, '(t9) no unresolved ## placeholder in the IPv6 rules', !str_contains($text, '##'));
    printf("%s", preg_replace('/^/m', '    | ', $text));

    /* (r5) a resolver per member in an IPv6 group: core renders each pass on its own device as inet6, to its own
     * resolver, with its states bound to the interface, and the footprint pass too */
    $fw = new \OPNsense\Firewall\Plugin();
    $mapping6b = [
        'opt1' => ['if' => 'wg1', 'descr' => 'WG_TEST_A',
                   'ifconfig' => ['ipv6' => [['ipaddr' => 'fd00::1:1', 'subnetbits' => 128]]]],
        'opt2' => ['if' => 'wg2', 'descr' => 'WG_TEST_B',
                   'ifconfig' => ['ipv6' => [['ipaddr' => 'fd00::2:1', 'subnetbits' => 128]]]],
    ];
    $fw->setInterfaceMapping($mapping6b);
    $a6 = ['name' => 'wg-a6', 'interface' => 'opt1', 'if' => 'wg1', 'resolver' => '2001:db8:a::53'];
    $b6 = ['name' => 'wg-b6', 'interface' => 'opt2', 'if' => 'wg2', 'resolver' => '2001:db8:b::53'];
    uu_render_firewall($fw, fn (): array => ['enabled' => true, 'default' => '', 'members' => [$a6, $b6],
        'addresses' => ['2001:db8:a::53', '2001:db8:b::53'],
        'footprints' => [['resolver' => '2001:db8:c::53', 'interface' => 'opt1']], 'footprint_problem' => null,
        'error' => null]);
    $text = $fw->outputFilterRules();
    $rule = fn (string $head, string $label): bool
        => preg_match('/^' . preg_quote($head, '/') . '[^\n]*label "' . $label . '"/m', $text) === 1;
    uu_check($t, '(r5) each member\'s pass on its own device, inet6, to its own resolver, if-bound, under its label',
        $rule('pass out quick on wg1 inet6 proto {tcp udp} from {(wg1)} to {2001:db8:a::53} port {53} flags any '
            . 'keep state ( if-bound )', md5('uu-pass-opt1-2001:db8:a::53'))
        && $rule('pass out quick on wg2 inet6 proto {tcp udp} from {(wg2)} to {2001:db8:b::53} port {53} flags any '
            . 'keep state ( if-bound )', md5('uu-pass-opt2-2001:db8:b::53')));
    uu_check($t, '(r5) the footprint pass is if-bound too',
        $rule('pass out quick on wg1 inet6 proto {tcp udp} from {(wg1)} to {2001:db8:c::53} port {53} flags any '
            . 'keep state ( if-bound )', md5('uu-footprint-pass-opt1-2001:db8:c::53')));
    uu_check($t, '(r5) one inet6 counting block, a backstop per address, the footprint block, no ## placeholder',
        substr_count($text, 'label "' . md5('uu-block') . '"') === 1
        && str_contains($text, 'block out log quick inet6 from {any} to {<__unboundupstream_block>}')
        && $rule('block out log quick inet6 from {any} to {2001:db8:a::53}', md5('uu-backstop'))
        && $rule('block out log quick inet6 from {any} to {2001:db8:b::53}', md5('uu-backstop'))
        && $rule('block out log quick inet6 from {any} to {2001:db8:c::53}', md5('uu-footprint'))
        && !str_contains($text, '##'));
    printf("%s", preg_replace('/^/m', '    | ', $text));

    /* (r5) pf takes the rules as core renders them: pfctl -n parses a file of them, never loading it */
    $listed = '';
    $parsed = uu_scratch_case(function (string $dir) use ($fw, &$listed): bool {
        file_put_contents($dir . '/rules.conf', $fw->tablesToText() . "\n" . $fw->outputFilterRules());
        $out = [];
        $rc = 0;
        exec('/sbin/pfctl -nvf ' . escapeshellarg($dir . '/rules.conf') . ' 2>&1', $out, $rc);
        $listed = implode("\n", $out);
        return $rc === 0;
    });
    uu_check($t, '(r5) pfctl -n takes the rules on {tcp udp}: the tcp pass with any flags and if-bound, the udp pass '
        . 'if-bound', $parsed
        && str_contains($listed, 'pass out quick on wg1 inet6 proto tcp from (wg1) to 2001:db8:a::53 port = domain '
            . 'flags any keep state (if-bound) label')
        && str_contains($listed, 'pass out quick on wg1 inet6 proto udp from (wg1) to 2001:db8:a::53 port = domain '
            . 'keep state (if-bound) label'));
    if (!$parsed) {
        printf("%s\n", preg_replace('/^/m', '    | ', $listed));
    }

    /* (r6) the saved model's rows reach the render by each gateway's UUID: a child php enables the plugin on the VM's
     * proton_test_grp with the Default and rows (gateway name => address) in its own copy of the configuration, never
     * saved, and returns what the render would render */
    $wantedOf = function (string $default, array $rows): ?array {
        $code = 'require "config.inc"; require "/usr/local/opnsense/mvc/script/load_phalcon.php"; '
            . 'require $argv[1]; require dirname($argv[1]) . "/views.php"; $rows = json_decode($argv[3], true); '
            . '$recs = (new \\OPNsense\\Routing\\Gateways())->gatewaysIndexedByName(true); $group = ""; '
            . 'foreach ((new \\OPNsense\\Routing\\GatewayGroups())->gateway_group->iterateItems() as $k => $g) { '
            . 'if ($g->name->getValue() === "proton_test_grp") { $group = (string)$k; } } '
            . '$m = new \\OPNsense\\UnboundUpstream\\UnboundUpstream(); '
            . '$m->setNodes(["enabled" => "1", "gateway_group" => $group, "resolver" => $argv[2]]); '
            . 'foreach ($rows as $name => $address) { $m->getNodeByReference("resolvers.resolver")->Add()->setNodes('
            . '["gateway" => (string)($recs[$name]["uuid"] ?? ""), "address" => $address]); } '
            . '$m->serializeToConfig(); echo json_encode(uu_wanted_render());';
        $out = (string)shell_exec('/usr/local/bin/php -d log_errors=0 -r ' . escapeshellarg($code) . ' '
            . escapeshellarg(__DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/render.php') . ' '
            . escapeshellarg($default) . ' ' . escapeshellarg((string)json_encode($rows)) . ' 2>&1');
        $w = json_decode($out, true);
        if (!is_array($w)) {
            printf("  the child php printed: %s\n", substr(preg_replace('/[^\x20-\x7e]/', '?', $out) ?? '', 0, 400));
            return null;
        }
        return $w;
    };
    $w = $wantedOf('10.2.0.1', ['wg-test-529' => '10.2.0.9']);
    uu_check($t, '(r6) the saved model\'s row reaches its member by the gateway\'s UUID, the other member takes the '
        . 'Default, and the setting\'s addresses are both',
        is_array($w) && array_column($w['members'] ?? [], 'resolver', 'name')
            === ['wg-test-429' => '10.2.0.1', 'wg-test-529' => '10.2.0.9']
        && ($w['addresses'] ?? null) === ['10.2.0.1', '10.2.0.9'] && ($w['enabled'] ?? null) === true);
    $w = $wantedOf('', ['wg-test-429' => '10.2.0.1', 'wg-test-529' => '10.2.0.9']);
    uu_check($t, '(r6) with no Default and a row for every member, the plugin still renders: each member its row',
        is_array($w) && ($w['enabled'] ?? null) === true
        && array_column($w['members'] ?? [], 'resolver', 'name')
            === ['wg-test-429' => '10.2.0.1', 'wg-test-529' => '10.2.0.9']
        && ($w['addresses'] ?? null) === ['10.2.0.1', '10.2.0.9']);
    return uu_tally_report('render_vm', $t);
});
