<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Rendered allow-list for the resolver: the confs, and the registration hook's
 * never-throws behaviour. The text core renders from them is checked by test_render_vm.php. The footprint's rules
 * are rendered from a state file in a scratch directory, as uu_wanted_render() reads the
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

        /** a rule carrying this label is refused, as core may refuse one */
        public ?string $ruleThrowsOn = null;

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
            if ($this->ruleThrowsOn !== null && ($conf['label'] ?? null) === $this->ruleThrowsOn) {
                throw new \RuntimeException("refused\ntwice");
            }
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
    /* members with their resolver, as uu_wanted_from() gives them */
    $resolving = fn (array $members, string $resolver): array
        => array_map(fn (array $m): array => $m + ['resolver' => $resolver], $members);
    $records = ['wg-a' => ['interface' => 'opt14', 'if' => 'wg1', 'gateway' => '192.0.2.2'],
                'wg-b' => ['interface' => 'opt15', 'if' => 'wg5', 'gateway' => '192.0.2.6']];
    $onWg1 = ['kind' => 'member', 'next_hop' => '192.0.2.2', 'if' => 'wg1'];
    $stateOf = function (?string $resolver, ?array $route): array {
        $st = uu_state_new();
        $st['mode'] = 'tunnel';
        $st['member'] = 'wg-a';
        if ($resolver !== null) {
            $st['addresses'][$resolver] = ['route' => $route, 'forwarded' => false, 'released_at' => null];
        }
        return $st;
    };
    $on = fn (string $resolver): array => ['default' => $resolver, 'rows' => [], 'gateways' => ['wg-a', 'wg-b']];
    $off = ['default' => '', 'rows' => [], 'gateways' => null];
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
    /*
     * Rules per member and address. The expected confs are written out here, apart from the code: a pass per
     * interface and resolver, its states bound to the interface; a counting block per family; a backstop per setting
     * address; a footprint's pass while its route is a member route, and its block.
     */
    $passConf = fn (string $opt, string $to, string $family): array => ['type' => 'pass', 'direction' => 'out',
        'quick' => true, 'interface' => $opt, 'ipprotocol' => $family, 'protocol' => 'tcp/udp', 'from' => $opt . 'ip',
        'to' => $to, 'to_port' => '53', 'disablereplyto' => true, 'flags' => 'any', 'statetype' => 'keep',
        'state-policy' => 'if-bound',
        'label' => md5('uu-pass-' . $opt . '-' . $to), 'descr' => 'Unbound upstream: the resolver through this member'];
    $countConf = fn (string $family): array => ['type' => 'block', 'direction' => 'out', 'quick' => true,
        'log' => true, 'ipprotocol' => $family, 'to' => '<__unboundupstream_block>', 'label' => md5('uu-block'),
        'descr' => 'Unbound upstream: the resolver never leaves by another interface (counted)'];
    $backstopConf = fn (string $to, string $family): array => ['type' => 'block', 'direction' => 'out',
        'quick' => true, 'log' => true, 'ipprotocol' => $family, 'to' => $to, 'label' => md5('uu-backstop'),
        'descr' => 'Unbound upstream: the resolver never leaves by another interface (backstop)'];
    $fpPassConf = fn (string $opt, string $to, string $family): array => ['type' => 'pass', 'direction' => 'out',
        'quick' => true, 'interface' => $opt, 'ipprotocol' => $family, 'protocol' => 'tcp/udp', 'from' => $opt . 'ip',
        'to' => $to, 'to_port' => '53', 'disablereplyto' => true, 'flags' => 'any', 'statetype' => 'keep',
        'state-policy' => 'if-bound',
        'label' => md5('uu-footprint-pass-' . $opt . '-' . $to),
        'descr' => 'Unbound upstream: the address the plugin last used, through the device of its route'];
    $fpBlockConf = fn (string $to, string $family): array => ['type' => 'block', 'direction' => 'out', 'quick' => true,
        'log' => true, 'ipprotocol' => $family, 'to' => $to, 'label' => md5('uu-footprint'),
        'descr' => 'Unbound upstream: the address the plugin last used never leaves by another interface'];
    $uuidA = '0b6a7f9e-5c1d-4e0a-9d2b-3f8a1c4e5d6a';
    $uuidB = '0b6a7f9e-5c1d-4e0a-9d2b-3f8a1c4e5d6b';
    $recs6 = ['wg-a6' => ['interface' => 'opt1', 'if' => 'wg1', 'gateway' => 'fd00::1:2', 'uuid' => $uuidA],
              'wg-b6' => ['interface' => 'opt2', 'if' => 'wg2', 'gateway' => 'fd00::2:2', 'uuid' => $uuidB]];
    $perMember6 = ['default' => '', 'rows' => [$uuidA => '2001:db8:a::53', $uuidB => '2001:db8:b::53'],
                   'gateways' => ['wg-a6', 'wg-b6']];
    uu_check($t, '(r2) an IPv6 group with a resolver per member on two interfaces: two inet6 passes, each to its own '
        . 'resolver and if-bound, one inet6 counting block, a backstop per address, the table once',
        uu_scratch_case(function (string $dir) use ($render, $recs6, $perMember6, $at, $passConf, $countConf,
            $backstopConf): bool {
            $r = $render($dir . '/state.json', $perMember6, $recs6);
            return $r['rules'] === $at([$passConf('opt1', '2001:db8:a::53', 'inet6'),
                    $passConf('opt2', '2001:db8:b::53', 'inet6'), $countConf('inet6'),
                    $backstopConf('2001:db8:a::53', 'inet6'), $backstopConf('2001:db8:b::53', 'inet6')])
                && $r['tables'] === [[UU_BLOCK_TABLE, false, null]] && $r['logged'] === [];
        }));
    uu_check($t, '(r4) a footprint with a member route gets its pass and block, one with a reject route its block '
        . 'only; the setting\'s rules are unchanged and the table is registered once',
        uu_scratch_case(function (string $dir) use ($render, $stateOf, $onWg1, $records, $on, $at, $passConf,
            $countConf, $backstopConf, $fpPassConf, $fpBlockConf): bool {
            $st = $stateOf('192.0.2.1', $onWg1);
            $st['addresses']['192.0.2.5'] = ['route' => ['kind' => 'reject', 'next_hop' => '', 'if' => 'lo0'],
                'forwarded' => false, 'released_at' => 40];
            uu_state_save($dir . '/state.json', $st);
            $r = $render($dir . '/state.json', $on('192.0.2.9'), $records);
            return $r['rules'] === $at([$passConf('opt14', '192.0.2.9', 'inet'),
                    $passConf('opt15', '192.0.2.9', 'inet'), $fpPassConf('opt14', '192.0.2.1', 'inet'),
                    $countConf('inet'), $backstopConf('192.0.2.9', 'inet'), $fpBlockConf('192.0.2.1', 'inet'),
                    $fpBlockConf('192.0.2.5', 'inet')])
                && $r['tables'] === [[UU_BLOCK_TABLE, false, null]] && $r['logged'] === [];
        }));
    uu_check($t, '(r4) a member\'s own resolver recorded in the state is no footprint: with a resolver per member, '
        . 'neither recorded address gets a footprint rule',
        uu_scratch_case(function (string $dir) use ($render, $stateOf, $recs6, $perMember6): bool {
            $st = $stateOf('2001:db8:a::53', ['kind' => 'member', 'next_hop' => 'fd00::1:2', 'if' => 'wg1']);
            $st['addresses']['2001:db8:b::53'] = ['route' => ['kind' => 'reject', 'next_hop' => '', 'if' => 'lo0'],
                'forwarded' => false, 'released_at' => null];
            uu_state_save($dir . '/state.json', $st);
            $r = $render($dir . '/state.json', $perMember6, $recs6);
            $labels = array_map(fn (array $rule): string => (string)$rule[1]['label'], $r['rules']);
            return count($labels) === 5 && !in_array(md5('uu-footprint'), $labels, true)
                && !in_array(md5('uu-footprint-pass-opt1-2001:db8:a::53'), $labels, true);
        }));
    uu_check($t, '(r6) disabled, the state recording 10.2.0.1 on a member route: the footprint pass and block only, '
        . 'no table, no line',
        uu_scratch_case(function (string $dir) use ($render, $stateOf, $off, $at, $fpPassConf, $fpBlockConf): bool {
            $recs = ['wg-test-429' => ['interface' => 'opt1', 'if' => 'wg1', 'gateway' => '10.2.0.2'],
                     'wg-test-529' => ['interface' => 'opt2', 'if' => 'wg2', 'gateway' => '10.2.0.3']];
            uu_state_save($dir . '/state.json', $stateOf('10.2.0.1', ['kind' => 'member', 'next_hop' => '10.2.0.2',
                'if' => 'wg1']));
            $r = $render($dir . '/state.json', $off, $recs);
            return $r['rules'] === $at([$fpPassConf('opt1', '10.2.0.1', 'inet'), $fpBlockConf('10.2.0.1', 'inet')])
                && $r['tables'] === [] && $r['logged'] === [];
        }));
    uu_check($t, '(r6) a row whose gateway UUID matches no record, and one for a dynamic gateway (whose record has no '
        . 'uuid), render nothing: both members take the Default',
        uu_scratch_case(function (string $dir) use ($render, $at, $passConf, $countConf, $backstopConf): bool {
            $recs = ['wg-a' => ['interface' => 'opt14', 'if' => 'wg1', 'gateway' => '192.0.2.2',
                                'uuid' => '0b6a7f9e-5c1d-4e0a-9d2b-3f8a1c4e5d6a'],
                     'wg-dyn' => ['interface' => 'opt16', 'if' => 'ovpnc1', 'gateway' => 'dynamic', 'uuid' => '']];
            $model = ['default' => '192.0.2.9', 'rows' => ['0b6a7f9e-5c1d-4e0a-9d2b-3f8a1c4e5d6f' => '192.0.2.77',
                '0b6a7f9e-5c1d-4e0a-9d2b-3f8a1c4e5d6e' => '192.0.2.78'], 'gateways' => ['wg-a', 'wg-dyn']];
            $r = $render($dir . '/state.json', $model, $recs);
            return $r['rules'] === $at([$passConf('opt14', '192.0.2.9', 'inet'),
                    $passConf('opt16', '192.0.2.9', 'inet'), $countConf('inet'), $backstopConf('192.0.2.9', 'inet')])
                && $r['logged'] === [];
        }));
    uu_check($t, '(r6) the records read fails with two footprints: their blocks only, and one error naming both '
        . 'addresses',
        uu_scratch_case(function (string $dir) use ($render, $stateOf, $onWg1, $off, $at, $fpBlockConf): bool {
            $st = $stateOf('192.0.2.1', $onWg1);
            $st['addresses']['2001:db8:a::53'] = ['route' => null, 'forwarded' => true, 'released_at' => null];
            uu_state_save($dir . '/state.json', $st);
            $r = $render($dir . '/state.json', $off, null);
            return $r['rules'] === $at([$fpBlockConf('192.0.2.1', 'inet'), $fpBlockConf('2001:db8:a::53', 'inet6')])
                && $r['logged'] === [['err', 'rules for the setting not rendered: cannot read the gateway records: '
                    . 'records unreadable; DNS to 192.0.2.1, 2001:db8:a::53 is blocked until a filter reload can '
                    . 'read the gateway records']];
        }));
    uu_check($t, '(v7) a Default stored as 2001:DB8:A:0::53: the pass, its label and the backstop use 2001:db8:a::53',
        uu_scratch_case(function (string $dir) use ($render, $recs6, $at, $passConf, $countConf, $backstopConf): bool {
            $r = $render($dir . '/state.json', ['default' => '2001:DB8:A:0::53', 'rows' => [], 'gateways' => ['wg-a6']],
                $recs6);
            return $r['rules'] === $at([$passConf('opt1', '2001:db8:a::53', 'inet6'), $countConf('inet6'),
                    $backstopConf('2001:db8:a::53', 'inet6')]) && $r['logged'] === [];
        }));
    uu_check($t, '(p16) a found group whose one gateway has no record, and a group with no gateway: 1.3_2\'s counting '
        . 'block and backstop for the Default, the table once, nothing logged',
        uu_scratch_case(function (string $dir) use ($render, $records, $at, $countConf, $backstopConf): bool {
            $gone = $render($dir . '/state.json', ['default' => '192.0.2.9', 'rows' => [], 'gateways' => ['wg-gone']],
                $records);
            $empty = $render($dir . '/state.json', ['default' => '192.0.2.9', 'rows' => [], 'gateways' => []],
                $records);
            $want = $at([$countConf('inet'), $backstopConf('192.0.2.9', 'inet')]);
            return $gone['rules'] === $want && $gone['tables'] === [[UU_BLOCK_TABLE, false, null]]
                && $gone['logged'] === [] && $empty['rules'] === $want && $empty['logged'] === [];
        }));
    uu_check($t, '(p16) the same with the Default recorded on its reject route: no footprint rule for it',
        uu_scratch_case(function (string $dir) use ($render, $stateOf, $records, $at, $countConf, $backstopConf): bool {
            uu_state_save($dir . '/state.json', $stateOf('192.0.2.9', ['kind' => 'reject', 'next_hop' => '',
                'if' => 'lo0']));
            $r = $render($dir . '/state.json', ['default' => '192.0.2.9', 'rows' => [], 'gateways' => ['wg-gone']],
                $records);
            return $r['rules'] === $at([$countConf('inet'), $backstopConf('192.0.2.9', 'inet')]) && $r['logged'] === [];
        }));
    uu_check($t, '(p16) a refused Default with no member: no rules and one error',
        uu_scratch_case(function (string $dir) use ($render, $records): bool {
            $r = $render($dir . '/state.json', ['default' => 'fe80::1', 'rows' => [], 'gateways' => ['wg-gone']],
                $records);
            return $r['rules'] === [] && $r['tables'] === [] && count($r['logged']) === 1
                && $r['logged'][0] === ['err', 'rules for the resolver setting not rendered: resolver is link-local'];
        }));
    uu_check($t, 'the records read fails with no footprint: no rules, and one error naming the read alone',
        uu_scratch_case(function (string $dir) use ($render, $on): bool {
            $r = $render($dir . '/state.json', $on('192.0.2.9'), null);
            return uu_footprints_from_state(uu_state_new(), null, []) === ['footprints' => [], 'problem' => null]
                && $r['rules'] === [] && $r['logged'] === [['err', 'rules for the setting not rendered: cannot read '
                    . 'the gateway records: records unreadable']];
        }));
    uu_check($t, '(v7) a member\'s resolver given as 2001:DB8:A:0::53: its pass goes to 2001:db8:a::53 under the label '
        . 'of that address',
        uu_try_case(fn (): bool => uu_rule_confs([['interface' => 'opt1', 'resolver' => '2001:DB8:A:0::53']], false,
            [], []) === [$passConf('opt1', '2001:db8:a::53', 'inet6')]));
    uu_check($t, '(r1) one IPv4 member pair on 10.2.0.1: the confs are 1.3_2\'s in every field but the two pass labels '
        . 'and the passes\' states, kept if-bound with any flags',
        uu_try_case(function (): bool {
            $descr = 'Unbound upstream: the resolver through this member';
            $old = [
                ['type' => 'pass', 'direction' => 'out', 'quick' => true, 'interface' => 'opt1', 'ipprotocol' => 'inet',
                 'protocol' => 'tcp/udp', 'from' => 'opt1ip', 'to' => '10.2.0.1', 'to_port' => '53',
                 'disablereplyto' => true, 'label' => md5('uu-pass-opt1'), 'descr' => $descr],
                ['type' => 'pass', 'direction' => 'out', 'quick' => true, 'interface' => 'opt2', 'ipprotocol' => 'inet',
                 'protocol' => 'tcp/udp', 'from' => 'opt2ip', 'to' => '10.2.0.1', 'to_port' => '53',
                 'disablereplyto' => true, 'label' => md5('uu-pass-opt2'), 'descr' => $descr],
                ['type' => 'block', 'direction' => 'out', 'quick' => true, 'log' => true, 'ipprotocol' => 'inet',
                 'to' => '<__unboundupstream_block>', 'label' => md5('uu-block'),
                 'descr' => 'Unbound upstream: the resolver never leaves by another interface (counted)'],
                ['type' => 'block', 'direction' => 'out', 'quick' => true, 'log' => true, 'ipprotocol' => 'inet',
                 'to' => '10.2.0.1', 'label' => md5('uu-backstop'),
                 'descr' => 'Unbound upstream: the resolver never leaves by another interface (backstop)'],
            ];
            $members = [['name' => 'wg-test-429', 'interface' => 'opt1', 'resolver' => '10.2.0.1'],
                        ['name' => 'wg-test-529', 'interface' => 'opt2', 'resolver' => '10.2.0.1']];
            $c = uu_rule_confs($members, true, ['10.2.0.1'], []);
            $bare = fn (array $conf): array => array_diff_key($conf, ['label' => true, 'flags' => true,
                'statetype' => true, 'state-policy' => true]);
            return count($c) === 4 && $bare($c[0]) === $bare($old[0]) && $bare($c[1]) === $bare($old[1])
                && $c[0]['label'] === md5('uu-pass-opt1-10.2.0.1') && $c[1]['label'] === md5('uu-pass-opt2-10.2.0.1')
                && $c[0]['flags'] === 'any' && $c[0]['statetype'] === 'keep' && $c[0]['state-policy'] === 'if-bound'
                && $c[1]['flags'] === 'any' && $c[1]['statetype'] === 'keep' && $c[1]['state-policy'] === 'if-bound'
                && array_keys($c[0]) === ['type', 'direction', 'quick', 'interface', 'ipprotocol', 'protocol', 'from',
                    'to', 'to_port', 'disablereplyto', 'flags', 'statetype', 'state-policy', 'label', 'descr']
                && $c[2] === $old[2] && $c[3] === $old[3];
        }));
    uu_check($t, '(r3) two members on one interface with two resolvers: two passes on it with distinct labels; a third '
        . 'with one of those resolvers adds none',
        uu_try_case(function () use ($passConf, $countConf, $backstopConf): bool {
            $members = [['interface' => 'opt14', 'resolver' => '192.0.2.9'],
                        ['interface' => 'opt14', 'resolver' => '192.0.2.10'],
                        ['interface' => 'opt14', 'resolver' => '192.0.2.9']];
            $c = uu_rule_confs($members, true, ['192.0.2.10', '192.0.2.9'], []);
            return $c === [$passConf('opt14', '192.0.2.9', 'inet'), $passConf('opt14', '192.0.2.10', 'inet'),
                    $countConf('inet'), $backstopConf('192.0.2.10', 'inet'), $backstopConf('192.0.2.9', 'inet')]
                && uu_label_pass('opt14', '192.0.2.9') !== uu_label_pass('opt14', '192.0.2.10');
        }));
    uu_check($t, '(r3) a member with no resolver gets no pass, and the counting blocks are one per family: none '
        . 'without their table',
        uu_try_case(function () use ($passConf, $backstopConf): bool {
            $c = uu_rule_confs([['interface' => 'opt14', 'resolver' => ''],
                ['interface' => 'opt15', 'resolver' => '2001:db8:b::53']], false, ['2001:db8:b::53'], []);
            return $c === [$passConf('opt15', '2001:db8:b::53', 'inet6'), $backstopConf('2001:db8:b::53', 'inet6')];
        }));


    $c = uu_rule_confs($resolving([$a, $b], '10.2.0.1'), true, ['10.2.0.1'], []);
    uu_check($t, 'rules: passes, counting block, backstop in that order',
        count($c) === 4 && $c[0]['type'] === 'pass' && $c[1]['type'] === 'pass'
        && $c[2]['label'] === md5('uu-block') && $c[3]['label'] === md5('uu-backstop'));
    uu_check($t, 'per member: pass out quick on the friendly interface, from <opt>ip, tcp/udp to resolver port 53',
        $c[0] == ['type' => 'pass', 'direction' => 'out', 'quick' => true, 'interface' => 'opt14',
            'ipprotocol' => 'inet', 'protocol' => 'tcp/udp', 'from' => 'opt14ip', 'to' => '10.2.0.1', 'to_port' => '53',
            'disablereplyto' => true, 'flags' => 'any', 'statetype' => 'keep', 'state-policy' => 'if-bound',
            'label' => md5('uu-pass-opt14-10.2.0.1'),
            'descr' => 'Unbound upstream: the resolver through this member']);
    uu_check($t, 'the second member gets its own interface and label',
        $c[1]['interface'] === 'opt15' && $c[1]['from'] === 'opt15ip'
        && $c[1]['label'] === md5('uu-pass-opt15-10.2.0.1'));
    uu_check($t, 'rules: the counting block targets <__unboundupstream_block> and the backstop the resolver, both log '
        . 'and quick',
        $c[2] == ['type' => 'block', 'direction' => 'out', 'quick' => true, 'log' => true, 'ipprotocol' => 'inet',
            'to' => '<__unboundupstream_block>', 'label' => md5('uu-block'),
            'descr' => 'Unbound upstream: the resolver never leaves by another interface (counted)']
        && $c[3] == ['type' => 'block', 'direction' => 'out', 'quick' => true, 'log' => true, 'ipprotocol' => 'inet',
            'to' => '10.2.0.1', 'label' => md5('uu-backstop'),
            'descr' => 'Unbound upstream: the resolver never leaves by another interface (backstop)']);
    uu_check($t, 'two members on one interface render one pass',
        count(uu_rule_confs($resolving([$a, $a], '10.2.0.1'), true, ['10.2.0.1'], [])) === 3);
    uu_check($t, 'no members still blocks the resolver everywhere: counting block and backstop',
        count(uu_rule_confs([], true, ['10.2.0.1'], [])) === 2
        && uu_rule_confs([], true, ['10.2.0.1'], [])[1]['to'] === '10.2.0.1');
    uu_check($t, 'a member without a friendly interface gets no pass',
        count(uu_rule_confs($resolving([array_merge($a, ['interface' => ''])], '10.2.0.1'), true, ['10.2.0.1'], []))
        === 2);
    $nc = uu_rule_confs($resolving([$a], '10.2.0.1'), false, ['10.2.0.1'], []);
    uu_check($t, 'rules: no counting block without its table (a registerTable failure)',
        count($nc) === 2 && $nc[1]['label'] === md5('uu-backstop') && $nc[1]['to'] === '10.2.0.1'
        && uu_rule_confs([], false, ['10.2.0.1'], []) === [$nc[1]]);
    uu_check($t, 'priority is the constant', UU_RULE_PRIORITY === 99998);

    $fw = uu_test_fw();
    uu_render_firewall($fw, fn (): array => ['enabled' => true, 'default' => '2001:DB8:A:0::0053',
        'members' => $resolving([$a], '2001:DB8:A:0::0053'), 'addresses' => ['2001:DB8:A:0::0053'], 'footprints' => [],
        'footprint_problem' => null, 'error' => null]);
    uu_check($t, '(t9) a resolver typed in a non-canonical form renders in its canonical form',
        uu_try_case(fn (): bool => count($fw->rules) === 3 && $fw->rules[0][1]['to'] === '2001:db8:a::53'
            && $fw->rules[2][1]['to'] === '2001:db8:a::53' && $fw->rules[0][1]['ipprotocol'] === 'inet6'));

    $wanted = function () use ($a, $b, $resolving): array {
        return ['enabled' => true, 'default' => '10.2.0.1', 'members' => $resolving([$a, $b], '10.2.0.1'),
                'addresses' => ['10.2.0.1'], 'footprints' => [], 'footprint_problem' => null, 'error' => null];
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
    uu_render_firewall($fw, fn (): array => ['enabled' => false, 'default' => '10.2.0.1',
        'members' => $resolving([$a], '10.2.0.1'), 'addresses' => ['10.2.0.1'], 'footprints' => [],
        'footprint_problem' => null, 'error' => null]);
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
    uu_render_firewall($fw, fn (): array => ['enabled' => true, 'default' => 'not an address',
        'members' => $resolving([$a], ''), 'addresses' => [], 'footprints' => [], 'footprint_problem' => null,
        'error' => null],
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

    /* the footprint: the address the plugin last used */
    uu_check($t, 'labels: the footprint block and a footprint pass have labels of their own',
        uu_try_case(fn (): bool => uu_label_footprint() === md5('uu-footprint')
            && uu_label_footprint_pass('opt14', '192.0.2.1') === md5('uu-footprint-pass-opt14-192.0.2.1')
            && uu_label_footprint_pass('opt14', '192.0.2.1') !== uu_label_pass('opt14', '192.0.2.1')));
    $fpPass = ['type' => 'pass', 'direction' => 'out', 'quick' => true, 'interface' => 'opt14', 'ipprotocol' => 'inet',
        'protocol' => 'tcp/udp', 'from' => 'opt14ip', 'to' => '192.0.2.1', 'to_port' => '53', 'disablereplyto' => true,
        'flags' => 'any', 'statetype' => 'keep', 'state-policy' => 'if-bound',
        'label' => md5('uu-footprint-pass-opt14-192.0.2.1'),
        'descr' => 'Unbound upstream: the address the plugin last used, through the device of its route'];
    $fpBlock = ['type' => 'block', 'direction' => 'out', 'quick' => true, 'log' => true, 'ipprotocol' => 'inet',
        'to' => '192.0.2.1', 'label' => md5('uu-footprint'),
        'descr' => 'Unbound upstream: the address the plugin last used never leaves by another interface'];
    /* the setting's rules for 192.0.2.9 on opt14 and opt15: two passes, the counting block, the backstop */
    $today = uu_rule_confs($resolving([$a, $b], '192.0.2.9'), true, ['192.0.2.9'], []);
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
        . 'the counting block, the backstop, the footprint block, all at UU_RULE_PRIORITY in that order',
        uu_scratch_case(function (string $dir) use ($render, $stateOf, $onWg1, $records, $on, $at, $today, $fpPass,
            $fpBlock): bool {
            uu_state_save($dir . '/state.json', $stateOf('192.0.2.1', $onWg1));
            $r = $render($dir . '/state.json', $on('192.0.2.9'), $records);
            return count($today) === 4
                && $r['rules'] === $at([$today[0], $today[1], $fpPass, $today[2], $today[3], $fpBlock])
                && $r['tables'] === [[UU_BLOCK_TABLE, false, null]] && $r['logged'] === [];
        }));
    uu_check($t, '(r11) enabled on B with the footprint A: the footprint pass to A comes before the counting block, '
        . 'and every pass before every block',
        uu_try_case(function () use ($a, $b, $resolving): bool {
            $c = uu_rule_confs($resolving([$a, $b], '192.0.2.9'), true, ['192.0.2.9'],
                [['resolver' => '192.0.2.1', 'interface' => 'opt14']]);
            $types = array_column($c, 'type');
            $labels = array_column($c, 'label');
            $lastPass = max(array_keys($types, 'pass', true));
            $firstBlock = min(array_keys($types, 'block', true));
            return array_search(md5('uu-footprint-pass-opt14-192.0.2.1'), $labels, true)
                < array_search(md5('uu-block'), $labels, true)
                && $lastPass < $firstBlock && count($c) === 6;
        }));
    uu_check($t, '(t9) a recorded IPv6 address is a footprint: its pass and block are inet6, on the route\'s device',
        uu_scratch_case(function (string $dir) use ($render, $stateOf, $off): bool {
            $recs = ['wg-a6' => ['interface' => 'opt14', 'if' => 'wg3', 'gateway' => 'fd00::3:2']];
            uu_state_save($dir . '/state.json', $stateOf('2001:db8:a::53', ['kind' => 'member', 'next_hop' => 'fd00::3:2',
                'if' => 'wg3']));
            $r = $render($dir . '/state.json', $off, $recs);
            $confs = array_map(fn (array $rule): array => $rule[1], $r['rules']);
            return count($confs) === 2 && array_column($confs, 'ipprotocol') === ['inet6', 'inet6']
                && array_column($confs, 'to') === ['2001:db8:a::53', '2001:db8:a::53']
                && array_column($confs, 'label')
                    === [md5('uu-footprint-pass-opt14-2001:db8:a::53'), md5('uu-footprint')]
                && $r['logged'] === [];
        }));
    uu_check($t, '(t9) a footprint equal to the setting in another spelling renders nothing extra',
        uu_scratch_case(function (string $dir) use ($render, $stateOf): bool {
            $recs = ['wg-a6' => ['interface' => 'opt14', 'if' => 'wg3', 'gateway' => 'fd00::3:2']];
            uu_state_save($dir . '/state.json', $stateOf('2001:db8:a::53', ['kind' => 'member', 'next_hop' => 'fd00::3:2',
                'if' => 'wg3']));
            $r = $render($dir . '/state.json', ['default' => '2001:DB8:A::53', 'rows' => [], 'gateways' => ['wg-a6']],
                $recs);
            $labels = array_map(fn (array $rule): string => (string)$rule[1]['label'], $r['rules']);
            return !in_array(md5('uu-footprint'), $labels, true)
                && !in_array(md5('uu-footprint-pass-opt14-2001:db8:a::53'), $labels, true)
                && count($labels) === 3 && $r['logged'] === [];
        }));
    uu_check($t, '(t9) an IPv6 resolver: every pass and block is inet6, to the address, the table block too',
        uu_try_case(function () use ($a, $b, $resolving): bool {
            $c6 = uu_rule_confs($resolving([$a, $b], '2001:db8:a::53'), true, ['2001:db8:a::53'], []);
            return count($c6) === 4 && array_column($c6, 'ipprotocol') === ['inet6', 'inet6', 'inet6', 'inet6']
                && $c6[0]['to'] === '2001:db8:a::53' && $c6[1]['to'] === '2001:db8:a::53'
                && $c6[2]['to'] === '<__unboundupstream_block>' && $c6[3]['to'] === '2001:db8:a::53'
                && $c6[0]['from'] === 'opt14ip' && $c6[0]['label'] === md5('uu-pass-opt14-2001:db8:a::53')
                && array_column($c6, 'label') === [md5('uu-pass-opt14-2001:db8:a::53'),
                    md5('uu-pass-opt15-2001:db8:a::53'), md5('uu-block'), md5('uu-backstop')];
        }));
    uu_check($t, '(t9) an IPv6 footprint beside an IPv4 setting: each rule has the protocol of its own address',
        uu_try_case(function () use ($a, $resolving): bool {
            $mixed = uu_rule_confs($resolving([$a], '192.0.2.9'), true, ['192.0.2.9'],
                [['resolver' => '2001:db8:b::53', 'interface' => 'opt14']]);
            return array_column($mixed, 'ipprotocol') === ['inet', 'inet6', 'inet', 'inet', 'inet6']
                && $mixed[1]['to'] === '2001:db8:b::53' && $mixed[4]['to'] === '2001:db8:b::53';
        }));
    uu_check($t, 'the footprint\'s interface is found when the record spells the next hop another way',
        uu_scratch_case(function (string $dir) use ($render, $stateOf, $off): bool {
            $recs = ['wg-a6' => ['interface' => 'opt14', 'if' => 'wg3', 'gateway' => 'FD00:0::3:2']];
            uu_state_save($dir . '/state.json', $stateOf('2001:db8:a::53', ['kind' => 'member', 'next_hop' => 'fd00::3:2',
                'if' => 'wg3']));
            $r = $render($dir . '/state.json', $off, $recs);
            return array_column(array_map(fn (array $rule): array => $rule[1], $r['rules']), 'label')
                === [md5('uu-footprint-pass-opt14-2001:db8:a::53'), md5('uu-footprint')];
        }));
    uu_check($t, 'a setting the model refuses (link-local, multicast, loopback) renders no setting rules, one error '
        . 'naming why; the footprint still renders',
        uu_scratch_case(function (string $dir) use ($render, $stateOf, $onWg1, $records, $at, $fpPass, $fpBlock): bool {
            uu_state_save($dir . '/state.json', $stateOf('192.0.2.1', $onWg1));
            foreach (['fe80::1' => 'link-local', 'ff02::1' => 'multicast', '::1' => 'loopback',
                      '224.0.0.251' => 'multicast'] as $addr => $why) {
                $r = $render($dir . '/state.json', ['default' => $addr, 'rows' => [], 'gateways' => ['wg-a', 'wg-b']],
                    $records);
                if ($r['rules'] !== $at([$fpPass, $fpBlock]) || $r['tables'] !== [] || count($r['logged']) !== 1
                    || $r['logged'][0][0] !== 'err' || !str_contains($r['logged'][0][1], 'resolver is ' . $why)) {
                    return false;
                }
            }
            return true;
        }));
    uu_check($t, 'a refused setting equal to the recorded address is still no setting: the footprint keeps its pass '
        . 'and block',
        uu_scratch_case(function (string $dir) use ($render, $stateOf, $onWg1, $records): bool {
            uu_state_save($dir . '/state.json', $stateOf('192.0.2.1', $onWg1));
            $refused = ['default' => '224.0.0.251', 'rows' => [], 'gateways' => ['wg-a']];
            $r = $render($dir . '/state.json', $refused, $records);
            uu_state_save($dir . '/state.json', $stateOf('224.0.0.251', $onWg1));
            $same = $render($dir . '/state.json', $refused, $records);
            return count($r['rules']) === 2
                && array_column(array_map(fn (array $rule): array => $rule[1], $same['rules']), 'label')
                    === [md5('uu-footprint-pass-opt14-224.0.0.251'), md5('uu-footprint')];
        }));
    uu_check($t, '(r4) a footprint equal to the resolver renders nothing extra: today\'s rules exactly',
        uu_scratch_case(function (string $dir) use ($render, $stateOf, $onWg1, $records, $on, $at, $today): bool {
            uu_state_save($dir . '/state.json', $stateOf('192.0.2.9', $onWg1));
            $r = $render($dir . '/state.json', $on('192.0.2.9'), $records);
            return $r['rules'] === $at($today) && $r['logged'] === [];
        }));
    uu_check($t, '(r5) a recorded address that is no address: a version 5 file gives today\'s rules and no line; a '
        . 'version 6 file with such a key is not this version\'s shape, one warning that never quotes it',
        uu_scratch_case(function (string $dir) use ($render, $stateOf, $onWg1, $records, $on, $at, $today): bool {
            $v5 = ['version' => 5, 'mode' => 'tunnel', 'member' => 'wg-a', 'timers' => [], 'control_failures' => 0,
                   'control_silent_since' => null, 'last_switch' => null,
                   'checks' => ['direct' => null, 'unbound' => null], 'tls_applied' => null, 'blocked' => null,
                   'route_installed' => $onWg1, 'resolver' => 'not-an-ip'];
            file_put_contents($dir . '/state.json', json_encode($v5));
            $old = $render($dir . '/state.json', $on('192.0.2.9'), $records);
            uu_state_save($dir . '/state.json', $stateOf('not-an-ip', $onWg1));
            $r = $render($dir . '/state.json', $on('192.0.2.9'), $records);
            return $old['rules'] === $at($today) && $old['logged'] === []
                && $r['rules'] === $at($today) && count($r['logged']) === 1 && $r['logged'][0][0] === 'warning'
                && str_contains($r['logged'][0][1], 'not this version')
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
                && str_contains($r['logged'][0][1], 'resolver is not an IPv4 or IPv6 address');
        }));
    uu_check($t, '(r8) no state file: today\'s rules and no line',
        uu_scratch_case(function (string $dir) use ($render, $records, $on, $at, $today): bool {
            $r = $render($dir . '/state.json', $on('192.0.2.9'), $records);
            return $r['rules'] === $at($today) && $r['logged'] === [];
        }));
    uu_check($t, '(r12) the settings cannot be read, a footprint recorded: the footprint pass and block, no table, and '
        . 'one error',
        uu_scratch_case(function (string $dir) use ($render, $stateOf, $onWg1, $records, $at, $fpPass,
            $fpBlock): bool {
            uu_state_save($dir . '/state.json', $stateOf('192.0.2.1', $onWg1));
            $r = $render($dir . '/state.json', null, $records);
            return $r['rules'] === $at([$fpPass, $fpBlock]) && $r['tables'] === []
                && count($r['logged']) === 1 && $r['logged'][0][0] === 'err'
                && str_contains($r['logged'][0][1], 'cannot read the settings: model unreadable')
                && !str_contains($r['logged'][0][1], 'is blocked');
        }));
    uu_check($t, '(r13) the settings and the gateway records cannot be read: the footprint block alone, and one error '
        . 'naming both reads and the address now blocked',
        uu_scratch_case(function (string $dir) use ($render, $stateOf, $onWg1, $at, $fpBlock): bool {
            uu_state_save($dir . '/state.json', $stateOf('192.0.2.1', $onWg1));
            $r = $render($dir . '/state.json', null, null);
            return $r['rules'] === $at([$fpBlock]) && $r['tables'] === []
                && count($r['logged']) === 1 && $r['logged'][0][0] === 'err'
                && $r['logged'][0][1] === 'rules for the setting not rendered: cannot read the settings: model '
                    . 'unreadable; cannot read the gateway records: records unreadable; DNS to 192.0.2.1 is blocked '
                    . 'until a filter reload can read the gateway records';
        }));
    uu_check($t, '(r14) disabled with no footprint: the settings are read once, the gateway records never, nothing is '
        . 'rendered and nothing logged',
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
        . 'block alone, and one error saying DNS to it is blocked until a reload can read the records',
        uu_scratch_case(function (string $dir) use ($render, $stateOf, $onWg1, $on, $at, $fpBlock): bool {
            uu_state_save($dir . '/state.json', $stateOf('192.0.2.9', $onWg1));
            $r = $render($dir . '/state.json', $on('192.0.2.9'), null);
            return $r['rules'] === $at([array_replace($fpBlock, ['to' => '192.0.2.9'])])
                && $r['tables'] === [] && count($r['logged']) === 1 && $r['logged'][0][0] === 'err'
                && $r['logged'][0][1] === 'rules for the setting not rendered: cannot read the gateway records: '
                    . 'records unreadable; DNS to 192.0.2.9 is blocked until a filter reload can read the gateway '
                    . 'records';
        }));

    /* the footprint reader itself: the first footprint, as one address was read before there were several */
    $first = fn (array $state, ?array $recs, array $setting): ?array
        => uu_footprints_from_state($state, $recs, $setting)['footprints'][0] ?? null;
    uu_check($t, 'footprint: none recorded is none',
        uu_try_case(fn (): bool => $first($stateOf(null, null), $records, [])
            === null));
    uu_check($t, 'footprint: a reject route, or none, gives the block only (no interface)',
        uu_try_case(fn (): bool => $first($stateOf('192.0.2.1', ['kind' => 'reject',
            'next_hop' => '', 'if' => 'lo0']), $records, [])
            === ['resolver' => '192.0.2.1', 'interface' => '']
            && $first($stateOf('192.0.2.1', null), $records, [])
            === ['resolver' => '192.0.2.1', 'interface' => '']));
    uu_check($t, '(r4) footprint: a route of the reject kind is no member route, even recorded on a member\'s device '
        . 'and next hop: its block only',
        uu_try_case(fn (): bool => uu_footprints_from_state($stateOf('192.0.2.1', ['kind' => 'reject',
            'next_hop' => '192.0.2.2', 'if' => 'wg1']), $records, [])
            === ['footprints' => [['resolver' => '192.0.2.1', 'interface' => '']], 'problem' => null]));
    uu_check($t, '(v7) footprint: a setting address in another spelling is still the setting\'s: no footprint',
        uu_try_case(fn (): bool => uu_footprints_from_state($stateOf('2001:db8:a::53', null), $records,
            ['2001:DB8:A:0::53']) === ['footprints' => [], 'problem' => null]));
    uu_check($t, 'footprint: a record on the device with another next hop is not the route\'s',
        uu_try_case(fn (): bool => $first($stateOf('192.0.2.1', ['kind' => 'member',
            'next_hop' => '192.0.2.3', 'if' => 'wg1']), $records, [])
            === ['resolver' => '192.0.2.1', 'interface' => '']));
    uu_check($t, 'footprint: of two matching records the first by sorted name wins, and one without an interface '
        . 'is passed over',
        uu_try_case(fn (): bool => $first($stateOf('192.0.2.1', $onWg1),
            ['wg-c' => ['interface' => 'opt16', 'if' => 'wg1', 'gateway' => '192.0.2.2'],
             'wg-b' => ['interface' => 'opt15', 'if' => 'wg1', 'gateway' => '192.0.2.2']], [])
            === ['resolver' => '192.0.2.1', 'interface' => 'opt15']
            && $first($stateOf('192.0.2.1', $onWg1),
                ['wg-a' => ['interface' => '', 'if' => 'wg1', 'gateway' => '192.0.2.2'],
                 'wg-b' => ['interface' => 'opt15', 'if' => 'wg1', 'gateway' => '192.0.2.2']], [])
            === ['resolver' => '192.0.2.1', 'interface' => 'opt15']));
    uu_check($t, 'footprint: the setting\'s own address is no footprint; another setting, or none, leaves it one',
        uu_try_case(fn (): bool
            => $first($stateOf('192.0.2.1', $onWg1), $records, ['192.0.2.1'])
                === null
            && $first($stateOf('192.0.2.1', $onWg1), $records, ['192.0.2.9'])
                === ['resolver' => '192.0.2.1', 'interface' => 'opt14']));
    uu_check($t, 'footprint: a version 5 file whose resolver is no address (a host name, an IPv4-mapped one) converts to '
        . 'an empty map: no footprint and no problem',
        uu_try_case(function () use ($records, $first): bool {
            $v5 = ['version' => 5, 'mode' => 'tunnel', 'member' => 'wg-a', 'timers' => [], 'control_failures' => 0,
                   'control_silent_since' => null, 'last_switch' => null, 'checks' => ['direct' => null, 'unbound' => null],
                   'tls_applied' => null, 'blocked' => null,
                   'route_installed' => ['kind' => 'member', 'next_hop' => '192.0.2.2', 'if' => 'wg1'],
                   'resolver' => 'resolver.example'];
            $named = uu_state_from_doc($v5);
            $mapped = uu_state_from_doc(['resolver' => '::ffff:192.0.2.1'] + $v5);
            return $named !== null && $mapped !== null
                && $first($named, $records, []) === null
                && $first($mapped, $records, []) === null;
        }));
    uu_check($t, 'footprint: of several recorded addresses, the first in sorted order that is not the setting\'s',
        uu_try_case(function () use ($records, $onWg1, $first): bool {
            $st = uu_state_new();
            $st['addresses'] = [
                '2001:db8:a::53' => ['route' => null, 'forwarded' => true, 'released_at' => null],
                '192.0.2.1' => ['route' => $onWg1, 'forwarded' => false, 'released_at' => null],
            ];
            return $first($st, $records, [])
                === ['resolver' => '192.0.2.1', 'interface' => 'opt14']
                && $first($st, $records, ['192.0.2.1'])
                === ['resolver' => '2001:db8:a::53', 'interface' => '']
                && $first($st, $records, ['2001:db8:a::53'])
                === ['resolver' => '192.0.2.1', 'interface' => 'opt14'];
        }));
    uu_check($t, 'wanted: a setting with an address that is not IPv4 covers no footprint, and its members come from '
        . 'the records',
        uu_scratch_case(function (string $dir) use ($stateOf, $onWg1, $records, $on): bool {
            uu_state_save($dir . '/state.json', $stateOf('192.0.2.1', $onWg1));
            $bad = uu_wanted_from(fn (): array => $on('192.0.2.1/32'), fn (): array => $records,
                $dir . '/state.json');
            return $bad['footprints'] === [['resolver' => '192.0.2.1', 'interface' => 'opt14']]
                && $bad['footprint_problem'] === null && $bad['error'] === null && $bad['enabled'] === true
                && $bad['members'] === [['name' => 'wg-a', 'interface' => 'opt14', 'if' => 'wg1', 'resolver' => ''],
                                        ['name' => 'wg-b', 'interface' => 'opt15', 'if' => 'wg5', 'resolver' => '']];
        }));

    /* a rule core refuses costs only itself: every block after it still registers, with one error naming it */
    $refused = function (string $label) use ($a, $b, $resolving): array {
        $fw = uu_test_fw();
        $fw->ruleThrowsOn = $label;
        $logged = [];
        $threw = false;
        try {
            uu_render_firewall($fw, fn (): array => ['enabled' => true, 'default' => '192.0.2.9',
                'members' => $resolving([$a, $b], '192.0.2.9'), 'addresses' => ['192.0.2.9'],
                'footprints' => [['resolver' => '192.0.2.1', 'interface' => 'opt14']],
                'footprint_problem' => null, 'error' => null],
                function (string $msg, string $level) use (&$logged): void {
                    $logged[] = [$level, $msg];
                });
        } catch (\Throwable) {
            $threw = true;
        }
        return ['threw' => $threw, 'labels' => array_map(fn (array $r): string => (string)$r[1]['label'], $fw->rules),
                'logged' => $logged];
    };
    $r = $refused(md5('uu-footprint-pass-opt14-192.0.2.1'));
    uu_check($t, 'a refused footprint pass costs only itself: the setting\'s passes, the counting block, the '
        . 'backstop and the footprint block all register, one error naming the rule',
        !$r['threw'] && $r['labels'] === [md5('uu-pass-opt14-192.0.2.9'), md5('uu-pass-opt15-192.0.2.9'),
            md5('uu-block'), md5('uu-backstop'), md5('uu-footprint')]
        && $r['logged'] === [['err', 'rules: "Unbound upstream: the address the plugin last used, through the device '
            . 'of its route" not rendered: refused; twice']]);
    $r = $refused(md5('uu-pass-opt14-192.0.2.9'));
    uu_check($t, 'a refused first setting pass costs only itself: the other passes and every block register',
        !$r['threw'] && $r['labels'] === [md5('uu-pass-opt15-192.0.2.9'), md5('uu-footprint-pass-opt14-192.0.2.1'),
            md5('uu-block'), md5('uu-backstop'), md5('uu-footprint')]
        && count($r['logged']) === 1 && $r['logged'][0][0] === 'err');

    return uu_tally_report('render', $t);
});
