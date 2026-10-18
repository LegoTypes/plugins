<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Rendered allow-list for the resolver (spec section 3.6b): the confs, and the registration hook's
 * never-throws behaviour. The text core renders from them is checked by test_render_vm.php.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/constants.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/render.php';
require_once __DIR__ . '/test_verdict.php';

/**
 * A stand-in for core's firewall plugin registry that only records what is registered. Its constructor skips
 * the parent's, which reads the configuration.
 *
 * @return \OPNsense\Firewall\Plugin&object{rules: list<array{int, array<string, string|bool>}>}
 */
function uu_test_fw(): \OPNsense\Firewall\Plugin
{
    return new class extends \OPNsense\Firewall\Plugin {
        /** @var list<array{int, array<string, string|bool>}> */
        public array $rules = [];

        public function __construct()
        {
        }

        /**
         * @param array<string, string|bool> $conf
         * @param ?array<string, string|bool> $defaults
         */
        public function registerFilterRule($prio, $conf, $defaults = null)
        {
            $this->rules[] = [$prio, $conf];
        }
    };
}

uu_register_suite('render', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $a = uu_test_member();
    $a['interface'] = 'opt14';
    $a['if'] = 'wg4';
    $b = uu_test_member();
    $b['name'] = 'wg-b';
    $b['interface'] = 'opt15';
    $b['if'] = 'wg5';

    $c = uu_rule_confs('10.2.0.1', [$a, $b]);
    uu_check($t, 'one pass per member and one block: three confs', count($c) === 3);
    uu_check($t, 'per member: pass out quick on the friendly interface, from <opt>ip, tcp/udp to resolver port 53',
        $c[0] == ['type' => 'pass', 'direction' => 'out', 'quick' => true, 'interface' => 'opt14',
            'ipprotocol' => 'inet', 'protocol' => 'tcp/udp', 'from' => 'opt14ip', 'to' => '10.2.0.1', 'to_port' => '53',
            'disablereplyto' => true, 'label' => md5('uu-pass-opt14'),
            'descr' => 'Unbound upstream: the resolver through this member']);
    uu_check($t, 'the second member gets its own interface and label',
        $c[1]['interface'] === 'opt15' && $c[1]['from'] === 'opt15ip' && $c[1]['label'] === md5('uu-pass-opt15'));
    uu_check($t, 'last: block out log quick inet to the resolver',
        end($c) == ['type' => 'block', 'direction' => 'out', 'quick' => true, 'log' => true, 'ipprotocol' => 'inet',
            'to' => '10.2.0.1', 'label' => md5('uu-block'),
            'descr' => 'Unbound upstream: the resolver never leaves by another interface']);
    uu_check($t, 'two members on one interface render one pass',
        count(uu_rule_confs('10.2.0.1', [$a, $a])) === 2);
    uu_check($t, 'no members still blocks the resolver everywhere',
        count(uu_rule_confs('10.2.0.1', [])) === 1 && uu_rule_confs('10.2.0.1', [])[0]['type'] === 'block');
    uu_check($t, 'a member without a friendly interface gets no pass',
        count(uu_rule_confs('10.2.0.1', [array_merge($a, ['interface' => ''])])) === 1);
    uu_check($t, 'priority is the constant', UU_RULE_PRIORITY === 99998);

    $wanted = function () use ($a, $b): array {
        return ['enabled' => true, 'resolver' => '10.2.0.1', 'members' => [$a, $b]];
    };
    $fw = uu_test_fw();
    uu_render_firewall($fw, $wanted);
    uu_check($t, 'enabled: every conf registered at UU_RULE_PRIORITY',
        count($fw->rules) === 3 && $fw->rules[0][0] === UU_RULE_PRIORITY && $fw->rules[2][0] === UU_RULE_PRIORITY
        && $fw->rules[2][1]['type'] === 'block');

    $fw = uu_test_fw();
    uu_render_firewall($fw, fn (): array => ['enabled' => false, 'resolver' => '10.2.0.1', 'members' => [$a]]);
    uu_check($t, 'disabled: no rules registered', $fw->rules === []);

    $fw = uu_test_fw();
    $threw = false;
    try {
        uu_render_firewall($fw, function (): array {
            throw new \RuntimeException('boom');
        });
    } catch (\Throwable) {
        $threw = true;
    }
    uu_check($t, 'a throwing $wanted: no rules, no exception', !$threw && $fw->rules === []);

    $fw = uu_test_fw();
    uu_render_firewall($fw, fn (): array => ['enabled' => true, 'resolver' => 'not an address', 'members' => [$a]]);
    uu_check($t, 'an invalid resolver address renders nothing', $fw->rules === []);

    return uu_tally_report('render', $t);
});
