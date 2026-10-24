<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Rendered allow-list for the resolver (spec section 3.6b): the confs, and the registration hook's
 * never-throws behaviour. The text core renders from them is checked by test_render_vm.php. The footprint's rules
 * (spec -04 section 3.2) are rendered from a state file in a scratch directory, as uu_wanted_render() reads the
 * plugin's own.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/constants.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/state.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/render.php';
require_once __DIR__ . '/test_verdict.php';
require_once __DIR__ . '/scratch.php';

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

        /** @var list<array{string, bool, ?string}> */
        public array $tables = [];

        public function __construct()
        {
        }

        public bool $tableThrows = false;

        public function registerTable($name, $persist = false, $file = null)
        {
            if ($this->tableThrows) {
                throw new \RuntimeException("table\nfailed");
            }
            $this->tables[] = [$name, $persist, $file];
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

    $c = uu_rule_confs('10.2.0.1', [$a, $b], true, null);
    uu_check($t, 'rules: passes, counting block, backstop in that order',
        count($c) === 4 && $c[0]['type'] === 'pass' && $c[1]['type'] === 'pass'
        && $c[2]['label'] === md5('uu-block') && $c[3]['label'] === md5('uu-backstop'));
    uu_check($t, 'per member: pass out quick on the friendly interface, from <opt>ip, tcp/udp to resolver port 53',
        $c[0] == ['type' => 'pass', 'direction' => 'out', 'quick' => true, 'interface' => 'opt14',
            'ipprotocol' => 'inet', 'protocol' => 'tcp/udp', 'from' => 'opt14ip', 'to' => '10.2.0.1', 'to_port' => '53',
            'disablereplyto' => true, 'label' => md5('uu-pass-opt14'),
            'descr' => 'Unbound upstream: the resolver through this member']);
    uu_check($t, 'the second member gets its own interface and label',
        $c[1]['interface'] === 'opt15' && $c[1]['from'] === 'opt15ip' && $c[1]['label'] === md5('uu-pass-opt15'));
    uu_check($t, 'rules: the counting block targets <__unboundupstream_block> and the backstop the resolver, both log '
        . 'and quick',
        $c[2] == ['type' => 'block', 'direction' => 'out', 'quick' => true, 'log' => true, 'ipprotocol' => 'inet',
            'to' => '<__unboundupstream_block>', 'label' => md5('uu-block'),
            'descr' => 'Unbound upstream: the resolver never leaves by another interface (counted)']
        && $c[3] == ['type' => 'block', 'direction' => 'out', 'quick' => true, 'log' => true, 'ipprotocol' => 'inet',
            'to' => '10.2.0.1', 'label' => md5('uu-backstop'),
            'descr' => 'Unbound upstream: the resolver never leaves by another interface (backstop)']);
    uu_check($t, 'two members on one interface render one pass',
        count(uu_rule_confs('10.2.0.1', [$a, $a], true, null)) === 3);
    uu_check($t, 'no members still blocks the resolver everywhere: counting block and backstop',
        count(uu_rule_confs('10.2.0.1', [], true, null)) === 2
        && uu_rule_confs('10.2.0.1', [], true, null)[1]['to'] === '10.2.0.1');
    uu_check($t, 'a member without a friendly interface gets no pass',
        count(uu_rule_confs('10.2.0.1', [array_merge($a, ['interface' => ''])], true, null)) === 2);
    $nc = uu_rule_confs('10.2.0.1', [$a], false, null);
    uu_check($t, 'rules: no counting block without its table (a registerTable failure)',
        count($nc) === 2 && $nc[1]['label'] === md5('uu-backstop') && $nc[1]['to'] === '10.2.0.1'
        && uu_rule_confs('10.2.0.1', [], false, null) === [$nc[1]]);
    uu_check($t, 'priority is the constant', UU_RULE_PRIORITY === 99998);

    $wanted = function () use ($a, $b): array {
        return ['enabled' => true, 'resolver' => '10.2.0.1', 'members' => [$a, $b], 'footprint' => null,
                'footprint_problem' => null, 'error' => null];
    };
    $fw = uu_test_fw();
    uu_render_firewall($fw, $wanted);
    uu_check($t, 'enabled: every conf registered at UU_RULE_PRIORITY',
        count($fw->rules) === 4 && $fw->rules[0][0] === UU_RULE_PRIORITY && $fw->rules[3][0] === UU_RULE_PRIORITY
        && $fw->rules[3][1]['type'] === 'block');
    uu_check($t, 'render: the table is registered in core\'s __ namespace, without persist or file',
        $fw->tables === [['__unboundupstream_block', false, null]]);

    $fw = uu_test_fw();
    $fw->tableThrows = true;
    $logged = [];
    $threw = false;
    try {
        uu_render_firewall($fw, $wanted, function (string $msg) use (&$logged): void {
            $logged[] = $msg;
        });
    } catch (\Throwable) {
        $threw = true;
    }
    uu_check($t, 'render: a throwing registerTable costs only the counting block, never the backstop',
        !$threw && $fw->tables === [] && count($fw->rules) === 3 && $fw->rules[2][1]['label'] === md5('uu-backstop')
        && $logged === ['rules: counting block not rendered: table; failed']);

    $fw = uu_test_fw();
    uu_render_firewall($fw, fn (): array => ['enabled' => false, 'resolver' => '10.2.0.1', 'members' => [$a],
        'footprint' => null, 'footprint_problem' => null, 'error' => null]);
    uu_check($t, 'disabled: no rules registered', $fw->rules === [] && $fw->tables === []);

    $fw = uu_test_fw();
    $threw = false;
    $logged = [];
    try {
        uu_render_firewall($fw, function (): array {
            throw new \RuntimeException("boom\nsecond line");
        }, function (string $msg) use (&$logged): void {
            $logged[] = $msg;
        });
    } catch (\Throwable) {
        $threw = true;
    }
    uu_check($t, 'a throwing $wanted: no rules, no exception', !$threw && $fw->rules === []);
    uu_check($t, 'the failure is logged once, newlines collapsed', $logged === ['rules not rendered: boom; second line']);

    $fw = uu_test_fw();
    $logged = [];
    uu_render_firewall($fw, fn (): array => ['enabled' => true, 'resolver' => 'not an address', 'members' => [$a],
        'footprint' => null, 'footprint_problem' => null, 'error' => null],
        function (string $msg) use (&$logged): void {
            $logged[] = $msg;
        });
    uu_check($t, 'an invalid resolver address renders nothing and is logged', $fw->rules === [] && count($logged) === 1);

    $logged = [];
    uu_render_firewall($fw, function (): array {
        throw new RuntimeException("bad\x1b[0m\tvalue");
    }, function (string $msg) use (&$logged): void {
        $logged[] = $msg;
    });
    uu_check($t, 'the failure line carries no control characters', $logged === ['rules not rendered: bad?[0m?value']);

    /* the footprint (spec -04 section 3.2; rulings R1, R2, R11, R47, R48): the address the plugin last used */
    uu_check($t, 'labels: the footprint block and a footprint pass have labels of their own',
        uu_try_case(fn (): bool => uu_label_footprint() === md5('uu-footprint')
            && uu_label_footprint_pass('opt14') === md5('uu-footprint-pass-opt14')
            && uu_label_footprint_pass('opt14') !== uu_label_pass('opt14')));
    $records = ['wg-a' => ['interface' => 'opt14', 'if' => 'wg1', 'gateway' => '192.0.2.2'],
                'wg-b' => ['interface' => 'opt15', 'if' => 'wg5', 'gateway' => '192.0.2.6']];
    $onWg1 = ['kind' => 'member', 'next_hop' => '192.0.2.2', 'if' => 'wg1'];
    $stateOf = function (?string $resolver, ?array $route): array {
        $st = uu_state_new();
        $st['mode'] = 'tunnel';
        $st['member'] = 'wg-a';
        $st['resolver'] = $resolver;
        $st['route_installed'] = $route;
        return $st;
    };
    $on = fn (string $resolver): array => ['resolver' => $resolver, 'gateways' => ['wg-a', 'wg-b']];
    $off = ['resolver' => '', 'gateways' => null];
    $fpPass = ['type' => 'pass', 'direction' => 'out', 'quick' => true, 'interface' => 'opt14', 'ipprotocol' => 'inet',
        'protocol' => 'tcp/udp', 'from' => 'opt14ip', 'to' => '192.0.2.1', 'to_port' => '53', 'disablereplyto' => true,
        'label' => md5('uu-footprint-pass-opt14'),
        'descr' => 'Unbound upstream: the address the plugin last used, through the device of its route'];
    $fpBlock = ['type' => 'block', 'direction' => 'out', 'quick' => true, 'log' => true, 'ipprotocol' => 'inet',
        'to' => '192.0.2.1', 'label' => md5('uu-footprint'),
        'descr' => 'Unbound upstream: the address the plugin last used never leaves by another interface'];
    /* the setting's rules for 192.0.2.9 on opt14 and opt15: two passes, the counting block, the backstop */
    $today = uu_rule_confs('192.0.2.9', [$a, $b], true, null);
    $at = fn (array $confs): array => array_map(fn (array $conf): array => [UU_RULE_PRIORITY, $conf], $confs);
    /*
     * Render what uu_wanted_from() gives for the state file at $path and the two readers: $model and $recs are what
     * they return, null for a reader that throws. Returns the registry, the tables, the lines logged, each as
     * [level, message], and how often each reader was called.
     *
     * @return array{rules: list<array{int, array<string, string|bool>}>, tables: list<array{string, bool, ?string}>,
     *     logged: list<array{string, string}>, model_reads: int, records_reads: int}
     */
    $render = function (string $path, ?array $model, ?array $recs): array {
        $reads = ['model' => 0, 'records' => 0];
        $w = uu_wanted_from(function () use ($model, &$reads): array {
            $reads['model']++;
            return $model ?? throw new RuntimeException('model unreadable');
        }, function () use ($recs, &$reads): array {
            $reads['records']++;
            return $recs ?? throw new RuntimeException('records unreadable');
        }, $path);
        $fw = uu_test_fw();
        $logged = [];
        uu_render_firewall($fw, fn (): array => $w, function (string $msg, string $level = '') use (&$logged): void {
            $logged[] = [$level, $msg];
        });
        return ['rules' => $fw->rules, 'tables' => $fw->tables, 'logged' => $logged, 'model_reads' => $reads['model'],
                'records_reads' => $reads['records']];
    };
    uu_check($t, '(r1) disabled, a footprint on a member route: exactly the footprint pass on the record\'s interface '
        . 'and the footprint block; no table, no counting block, no line',
        uu_scratch_case(function (string $dir) use ($render, $stateOf, $onWg1, $records, $off, $at, $fpPass,
            $fpBlock): bool {
            uu_state_save($dir . '/state.json', $stateOf('192.0.2.1', $onWg1));
            $r = $render($dir . '/state.json', $off, $records);
            return $r['rules'] === $at([$fpPass, $fpBlock]) && $r['tables'] === [] && $r['logged'] === [];
        }));
    uu_check($t, '(r2) no gateway record names the route\'s device and next hop: the footprint block only',
        uu_scratch_case(function (string $dir) use ($render, $stateOf, $records, $off, $at, $fpBlock): bool {
            uu_state_save($dir . '/state.json', $stateOf('192.0.2.1', ['kind' => 'member', 'next_hop' => '192.0.2.2',
                'if' => 'wg9']));
            $r = $render($dir . '/state.json', $off, $records);
            return $r['rules'] === $at([$fpBlock]) && $r['tables'] === [] && $r['logged'] === [];
        }));
    uu_check($t, '(r3) enabled on 192.0.2.9 with the footprint 192.0.2.1: the setting\'s passes, the footprint pass, '
        . 'the counting block, the backstop, the footprint block, all at UU_RULE_PRIORITY in that order (R47)',
        uu_scratch_case(function (string $dir) use ($render, $stateOf, $onWg1, $records, $on, $at, $today, $fpPass,
            $fpBlock): bool {
            uu_state_save($dir . '/state.json', $stateOf('192.0.2.1', $onWg1));
            $r = $render($dir . '/state.json', $on('192.0.2.9'), $records);
            return count($today) === 4
                && $r['rules'] === $at([$today[0], $today[1], $fpPass, $today[2], $today[3], $fpBlock])
                && $r['tables'] === [[UU_BLOCK_TABLE, false, null]] && $r['logged'] === [];
        }));
    uu_check($t, '(r11) enabled on B with the footprint A: the footprint pass to A comes before the counting block, '
        . 'and every pass before every block (R47)',
        uu_try_case(function () use ($a, $b): bool {
            $c = uu_rule_confs('192.0.2.9', [$a, $b], true, ['resolver' => '192.0.2.1', 'interface' => 'opt14']);
            $types = array_column($c, 'type');
            $labels = array_column($c, 'label');
            $lastPass = max(array_keys($types, 'pass', true));
            $firstBlock = min(array_keys($types, 'block', true));
            return array_search(md5('uu-footprint-pass-opt14'), $labels, true)
                < array_search(md5('uu-block'), $labels, true)
                && $lastPass < $firstBlock && count($c) === 6;
        }));
    uu_check($t, '(r4) a footprint equal to the resolver renders nothing extra: today\'s rules exactly',
        uu_scratch_case(function (string $dir) use ($render, $stateOf, $onWg1, $records, $on, $at, $today): bool {
            uu_state_save($dir . '/state.json', $stateOf('192.0.2.9', $onWg1));
            $r = $render($dir . '/state.json', $on('192.0.2.9'), $records);
            return $r['rules'] === $at($today) && $r['logged'] === [];
        }));
    uu_check($t, '(r5) a recorded address that is not IPv4: today\'s rules, and one warning that never quotes it',
        uu_scratch_case(function (string $dir) use ($render, $stateOf, $onWg1, $records, $on, $at, $today): bool {
            uu_state_save($dir . '/state.json', $stateOf('not-an-ip', $onWg1));
            $r = $render($dir . '/state.json', $on('192.0.2.9'), $records);
            return $r['rules'] === $at($today) && count($r['logged']) === 1 && $r['logged'][0][0] === 'warning'
                && str_contains($r['logged'][0][1], 'not an IPv4 address')
                && !str_contains($r['logged'][0][1], 'not-an-ip');
        }));
    uu_check($t, '(r6) a directory at the state path: today\'s rules, and one warning naming "not a regular file"',
        uu_scratch_case(function (string $dir) use ($render, $records, $on, $at, $today): bool {
            uu_scratch_place('dir', $dir . '/state.json', '');
            $r = $render($dir . '/state.json', $on('192.0.2.9'), $records);
            return $r['rules'] === $at($today) && count($r['logged']) === 1 && $r['logged'][0][0] === 'warning'
                && str_contains($r['logged'][0][1], 'not a regular file');
        }));
    uu_check($t, '(r7) enabled with the resolver "x" and the footprint 192.0.2.1: only the footprint rules, no table, '
        . 'and one error for the resolver',
        uu_scratch_case(function (string $dir) use ($render, $stateOf, $onWg1, $records, $on, $at, $fpPass,
            $fpBlock): bool {
            uu_state_save($dir . '/state.json', $stateOf('192.0.2.1', $onWg1));
            $r = $render($dir . '/state.json', $on('x'), $records);
            return $r['rules'] === $at([$fpPass, $fpBlock]) && $r['tables'] === []
                && count($r['logged']) === 1 && $r['logged'][0][0] === 'err'
                && str_contains($r['logged'][0][1], 'resolver is not an IPv4 address');
        }));
    uu_check($t, '(r8) no state file: today\'s rules and no line',
        uu_scratch_case(function (string $dir) use ($render, $records, $on, $at, $today): bool {
            $r = $render($dir . '/state.json', $on('192.0.2.9'), $records);
            return $r['rules'] === $at($today) && $r['logged'] === [];
        }));
    uu_check($t, '(r12) the settings cannot be read, a footprint recorded: the footprint pass and block, no table, and '
        . 'one error (R48)',
        uu_scratch_case(function (string $dir) use ($render, $stateOf, $onWg1, $records, $at, $fpPass,
            $fpBlock): bool {
            uu_state_save($dir . '/state.json', $stateOf('192.0.2.1', $onWg1));
            $r = $render($dir . '/state.json', null, $records);
            return $r['rules'] === $at([$fpPass, $fpBlock]) && $r['tables'] === []
                && count($r['logged']) === 1 && $r['logged'][0][0] === 'err'
                && str_contains($r['logged'][0][1], 'cannot read the settings: model unreadable');
        }));
    uu_check($t, '(r13) the settings and the gateway records cannot be read: the footprint block alone, and one error '
        . 'naming both (R48)',
        uu_scratch_case(function (string $dir) use ($render, $stateOf, $onWg1, $at, $fpBlock): bool {
            uu_state_save($dir . '/state.json', $stateOf('192.0.2.1', $onWg1));
            $r = $render($dir . '/state.json', null, null);
            return $r['rules'] === $at([$fpBlock]) && $r['tables'] === []
                && count($r['logged']) === 1 && $r['logged'][0][0] === 'err'
                && str_contains($r['logged'][0][1], 'cannot read the settings: model unreadable')
                && str_contains($r['logged'][0][1], 'cannot read the gateway records: records unreadable');
        }));
    uu_check($t, '(r14) disabled with no footprint: the settings are read once, the gateway records never, nothing is '
        . 'rendered and nothing logged (R48)',
        uu_scratch_case(function (string $dir) use ($render, $stateOf, $off): bool {
            $none = $render($dir . '/state.json', $off, null);
            uu_state_save($dir . '/state.json', $stateOf(null, null));
            $fresh = $render($dir . '/state.json', $off, null);
            return $none['rules'] === [] && $none['logged'] === [] && $none['model_reads'] === 1
                && $none['records_reads'] === 0
                && $fresh['rules'] === [] && $fresh['logged'] === [] && $fresh['records_reads'] === 0;
        }));
    uu_check($t, '(r15) the settings cannot be read and no footprint is recorded: no gateway records read, nothing '
        . 'rendered, one error',
        uu_scratch_case(function (string $dir) use ($render): bool {
            $r = $render($dir . '/state.json', null, null);
            return $r['rules'] === [] && $r['records_reads'] === 0 && count($r['logged']) === 1
                && $r['logged'][0][0] === 'err';
        }));
    uu_check($t, '(r16) enabled, the gateway records cannot be read: no setting rules, the recorded resolver keeps its '
        . 'block alone, one error',
        uu_scratch_case(function (string $dir) use ($render, $stateOf, $onWg1, $on, $at, $fpBlock): bool {
            uu_state_save($dir . '/state.json', $stateOf('192.0.2.9', $onWg1));
            $r = $render($dir . '/state.json', $on('192.0.2.9'), null);
            return $r['rules'] === $at([array_replace($fpBlock, ['to' => '192.0.2.9'])])
                && $r['tables'] === [] && count($r['logged']) === 1 && $r['logged'][0][0] === 'err'
                && str_contains($r['logged'][0][1], 'cannot read the gateway records');
        }));

    /* the footprint reader itself (ruling R1) */
    uu_check($t, 'footprint: none recorded is none, and no problem',
        uu_try_case(fn (): bool => uu_footprint_from_state($stateOf(null, null), $records, '')
            === ['footprint' => null, 'problem' => null]));
    uu_check($t, 'footprint: a reject route, or none, gives the block only (no interface)',
        uu_try_case(fn (): bool => uu_footprint_from_state($stateOf('192.0.2.1', ['kind' => 'reject',
            'next_hop' => '', 'if' => 'lo0']), $records, '')
            === ['footprint' => ['resolver' => '192.0.2.1', 'interface' => ''], 'problem' => null]
            && uu_footprint_from_state($stateOf('192.0.2.1', null), $records, '')
            === ['footprint' => ['resolver' => '192.0.2.1', 'interface' => ''], 'problem' => null]));
    uu_check($t, 'footprint: a record on the device with another next hop is not the route\'s',
        uu_try_case(fn (): bool => uu_footprint_from_state($stateOf('192.0.2.1', ['kind' => 'member',
            'next_hop' => '192.0.2.3', 'if' => 'wg1']), $records, '')['footprint']
            === ['resolver' => '192.0.2.1', 'interface' => '']));
    uu_check($t, 'footprint: of two matching records the first by sorted name wins, and one without an interface '
        . 'is passed over',
        uu_try_case(fn (): bool => uu_footprint_from_state($stateOf('192.0.2.1', $onWg1),
            ['wg-c' => ['interface' => 'opt16', 'if' => 'wg1', 'gateway' => '192.0.2.2'],
             'wg-b' => ['interface' => 'opt15', 'if' => 'wg1', 'gateway' => '192.0.2.2']], '')['footprint']
            === ['resolver' => '192.0.2.1', 'interface' => 'opt15']
            && uu_footprint_from_state($stateOf('192.0.2.1', $onWg1),
                ['wg-a' => ['interface' => '', 'if' => 'wg1', 'gateway' => '192.0.2.2'],
                 'wg-b' => ['interface' => 'opt15', 'if' => 'wg1', 'gateway' => '192.0.2.2']], '')['footprint']
            === ['resolver' => '192.0.2.1', 'interface' => 'opt15']));
    uu_check($t, 'footprint: the setting\'s own address is no footprint; another setting, or none, leaves it one',
        uu_try_case(fn (): bool
            => uu_footprint_from_state($stateOf('192.0.2.1', $onWg1), $records, '192.0.2.1')
                === ['footprint' => null, 'problem' => null]
            && uu_footprint_from_state($stateOf('192.0.2.1', $onWg1), $records, '192.0.2.9')['footprint']
                === ['resolver' => '192.0.2.1', 'interface' => 'opt14']));
    uu_check($t, 'footprint: a recorded address that is not IPv4 (an IPv6 one too) is a problem, not a footprint',
        uu_try_case(fn (): bool
            => uu_footprint_from_state($stateOf('2001:db8::1', $onWg1), $records, '')['footprint'] === null
            && is_string(uu_footprint_from_state($stateOf('2001:db8::1', $onWg1), $records, '')['problem'])));
    uu_check($t, 'wanted: a setting with an address that is not IPv4 covers no footprint, and its members come from '
        . 'the records',
        uu_scratch_case(function (string $dir) use ($stateOf, $onWg1, $records, $on): bool {
            uu_state_save($dir . '/state.json', $stateOf('192.0.2.1', $onWg1));
            $bad = uu_wanted_from(fn (): array => $on('192.0.2.1/32'), fn (): array => $records,
                $dir . '/state.json');
            return $bad['footprint'] === ['resolver' => '192.0.2.1', 'interface' => 'opt14']
                && $bad['footprint_problem'] === null && $bad['error'] === null && $bad['enabled'] === true
                && $bad['members'] === [['name' => 'wg-a', 'interface' => 'opt14', 'if' => 'wg1'],
                                        ['name' => 'wg-b', 'interface' => 'opt15', 'if' => 'wg5']];
        }));

    return uu_tally_report('render', $t);
});
