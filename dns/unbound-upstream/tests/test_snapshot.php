<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Live snapshot parsers: route get, unbound-control forward, sysctl, ps, group tiers; and the pf
 * observation the snapshot makes through an injected pfctl: what it reads, and that a status never
 * lists the ruleset; and the pfctl runner, whose stderr file lives in the root-only run directory.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/snapshot.php';
require_once __DIR__ . '/test_verdict.php';
require_once __DIR__ . '/test_pfobserve.php';
require_once __DIR__ . '/scratch.php';

function uu_snapshot_fixture(string $name): string
{
    $text = file_get_contents(__DIR__ . '/fixtures/' . $name);
    return $text === false ? '' : $text;
}

uu_register_suite('snapshot', function (): int {
    $t = ['fail' => 0, 'total' => 0];

    $r = uu_parse_route_get(uu_snapshot_fixture('route_get_member.txt'));
    uu_check($t, 'route via a member: present, gateway and device as printed, no reject',
        $r === ['present' => true, 'gateway' => '10.2.0.4', 'interface' => 'wg1', 'reject' => false]);
    $r = uu_parse_route_get(uu_snapshot_fixture('route_get_reject.txt'));
    uu_check($t, 'REJECT route (real output): present, no gateway, on lo0, reject',
        $r === ['present' => true, 'gateway' => '', 'interface' => 'lo0', 'reject' => true]);
    uu_check($t, 'the real REJECT route is ours', uu_route_ours($r, []));
    $r = uu_parse_route_get(uu_snapshot_fixture('route_get_absent.txt'));
    uu_check($t, 'not in table: absent', $r['present'] === false && !$r['reject']);
    uu_check($t, 'empty output: absent', uu_parse_route_get('')['present'] === false);
    $absent = ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false];
    uu_check($t, '(t4) IPv4 not in table, as route(8) prints it: absent',
        uu_parse_route_get("route: writing to routing socket: No such process\n  not in table\n") === $absent);
    uu_check($t, '(t4) IPv6 "route has not been found", as route(8) prints it (real output): absent',
        uu_parse_route_get(uu_snapshot_fixture('route_get_absent6.txt')) === $absent
        && uu_parse_route_get("route: route has not been found\n") === $absent);
    uu_check($t, '(t4) any other route(8) complaint is absent too, never a route',
        uu_parse_route_get("route: bad address: dns.example\n") === $absent);
    $r = uu_parse_route_get(uu_snapshot_fixture('route_get_member6.txt'));
    uu_check($t, '(t4) IPv6 route via a member: present, gateway and device as printed, no reject',
        $r === ['present' => true, 'gateway' => 'fd00::3:2', 'interface' => 'wg3', 'reject' => false]);
    $r = uu_parse_route_get(uu_snapshot_fixture('route_get_reject6.txt'));
    uu_check($t, '(t4) IPv6 REJECT route (real output): present, no gateway, on lo0, reject, and ours',
        $r === ['present' => true, 'gateway' => '', 'interface' => 'lo0', 'reject' => true]
        && uu_route_ours($r, []));
    $r = uu_parse_route_get(uu_snapshot_fixture('route_get_default.txt'));
    uu_check($t, 'the default route (0.0.0.0/0) is not a route of the resolver: absent',
        $r['present'] === false && $r['gateway'] === '' && $r['interface'] === '');
    uu_check($t, 'the default route printed as "default" is absent too',
        uu_parse_route_get(uu_snapshot_fixture('route_get_default_word.txt'))['present'] === false);
    $r = uu_parse_route_get(uu_snapshot_fixture('route_get_connected.txt'));
    uu_check($t, 'a connected network route covering the resolver is not the resolver\'s host route: absent',
        uu_parse_route_get(uu_snapshot_fixture('route_get_connected.txt'))['present'] === false);
    uu_check($t, 'a 0.0.0.0/1 covering route is absent',
        uu_parse_route_get(uu_snapshot_fixture('route_get_covering.txt'))['present'] === false);

    uu_check($t, 'forward: addresses in order',
        uu_parse_forward("192.0.2.53 198.51.100.53 2001:db8::53\n") === ['192.0.2.53', '198.51.100.53', '2001:db8::53']);
    uu_check($t, 'forward: DoT form keeps port and name',
        uu_parse_forward("192.0.2.53@853#dns.example\n") === ['192.0.2.53@853#dns.example']);
    uu_check($t, 'forward: off is the empty list', uu_parse_forward("off\n") === []);
    uu_check($t, 'forward: Unbound 1.26.1\'s real "off (using root hints)" (no root forward) is the empty list',
        uu_parse_forward("off (using root hints)\n") === []);
    uu_check($t, 'forward: other text after off is null', uu_parse_forward("off and on\n") === null);
    uu_check($t, 'forward: an error line is null',
        uu_parse_forward("error: connect: Connection refused for 127.0.0.1 port 8953\n") === null);
    uu_check($t, 'forward: empty output (timeout) is null', uu_parse_forward('') === null && uu_parse_forward("\n") === null);
    uu_check($t, 'forward: text that is not an address list is null', uu_parse_forward("unknown command\n") === null);

    uu_check($t, '(f1) forward: a DoT answer with a port and an authentication name is kept, IPv4 and IPv6',
        uu_parse_forward("192.0.2.53@853#dns.example 2001:db8::53@853#dns.example\n")
        === ['192.0.2.53@853#dns.example', '2001:db8::53@853#dns.example']);
    uu_check($t, '(f1) forward: markup, a space in the name, a non-address and a port longer than five digits are null',
        uu_parse_forward("192.0.2.53#dns<b>\n") === null && uu_parse_forward("192.0.2.53#a b\n") === null
        && uu_parse_forward("999.1.1.1\n") === null && uu_parse_forward("192.0.2.53@99999999\n") === null);
    uu_check($t, '(f1) forward: a value with a trailing LF fails uu_forward_addr_ok(), and so do markup and a bad address',
        uu_try_case(fn (): bool => uu_forward_addr_ok('192.0.2.53@853#dns.example')
            && !uu_forward_addr_ok("192.0.2.53@853#dns.example\n") && !uu_forward_addr_ok("192.0.2.53\n")
            && !uu_forward_addr_ok('192.0.2.53#dns<b>') && !uu_forward_addr_ok('999.1.1.1')
            && !uu_forward_addr_ok('1.2.3')));

    uu_check($t, 'sysctl: 1000', uu_parse_sysctl_int("1000\n") === 1000);
    uu_check($t, 'sysctl: 0 is a value', uu_parse_sysctl_int("0\n") === 0);
    uu_check($t, 'sysctl: empty is null', uu_parse_sysctl_int('') === null && uu_parse_sysctl_int("\n") === null);
    uu_check($t, 'sysctl: not a number is null',
        uu_parse_sysctl_int("sysctl: unknown oid\n") === null && uu_parse_sysctl_int("-5\n") === null);

    uu_check($t, 'ps etimes: pid => seconds, junk skipped',
        uu_parse_ps_etimes("  101  86\n 202 3\nheader\n") === [101 => 86, 202 => 3]);

    $groups = ['name' => 'grp_test', 'trigger' => 'downloss',
               'tiers' => ['1' => ['wg-a'], '2' => ['wg-b', 'wg-c'], '3' => [''], '4' => [''], '5' => ['']]];
    uu_check($t, 'tiers: unused tiers ([""]) dropped, order kept',
        uu_group_tiers($groups) === [['wg-a'], ['wg-b', 'wg-c']]);
    uu_check($t, 'tiers: an empty name inside a tier is dropped, a hole in the numbering closes',
        uu_group_tiers(['tiers' => ['1' => ['wg-a'], '2' => [''], '3' => ['', 'wg-b']]]) === [['wg-a'], ['wg-b']]);
    uu_check($t, 'tiers: tiers listed out of key order sort by key',
        uu_group_tiers(['tiers' => ['2' => ['wg-b'], '1' => ['wg-a']]]) === [['wg-a'], ['wg-b']]);
    uu_check($t, 'tiers: a group without tiers is no tiers', uu_group_tiers(['name' => 'x']) === []);

    uu_check($t, 'hook order: unbound before unboundupstream',
        uu_unbound_sorts_first(['core', 'unbound', 'unboundupstream', 'wireguard']));
    uu_check($t, 'hook order: unboundupstream not listed is a fault',
        !uu_unbound_sorts_first(['core', 'unbound', 'wireguard']));
    uu_check($t, 'hook order: scan order putting unboundupstream first fails',
        !uu_unbound_sorts_first(['unboundupstream', 'unbound']));
    uu_check($t, 'hook order: no unbound plugin fails', !uu_unbound_sorts_first(['core', 'wireguard']));

    $a = uu_test_member();
    $a['next_hop'] = '10.2.0.4';
    $members = ['wg-a' => $a];
    $via = ['present' => true, 'gateway' => '10.2.0.4', 'interface' => 'wg1', 'reject' => false];
    uu_check($t, 'ours: gateway and device of a member', uu_route_ours($via, $members));
    uu_check($t, 'ours: right gateway, wrong device is not ours',
        !uu_route_ours(['interface' => 'wg9'] + $via, $members));
    uu_check($t, 'ours: a gateway no member has is not ours',
        !uu_route_ours(['gateway' => '10.9.9.9'] + $via, $members));
    uu_check($t, 'ours: a REJECT route on lo0 is the block route, whatever the gateway',
        uu_route_ours(['gateway' => '', 'interface' => 'lo0', 'reject' => true] + $via, $members));
    uu_check($t, 'ours: a REJECT route on another device is not ours',
        !uu_route_ours(['gateway' => '', 'interface' => 'wg1', 'reject' => true] + $via, $members));
    uu_check($t, 'ours: a route on lo0 without REJECT is not ours',
        !uu_route_ours(['gateway' => '127.0.0.1', 'interface' => 'lo0'] + $via, $members));
    $records = ['gw-a' => ['monitor' => '2001:DB8:A:0::53'], 'gw-b' => ['monitor' => '10.2.0.1'], 'gw-c' => [],
                'gw-d' => ['monitor' => '']];
    uu_check($t, '(t7) monitor match: the gateways whose monitor is the resolver, compared in canonical form, both families',
        uu_try_case(fn (): bool => uu_resolver_monitors($records, '2001:db8:a::53') === ['gw-a']
            && uu_resolver_monitors($records, '10.2.0.1') === ['gw-b'] && uu_resolver_monitors($records, '') === []
            && uu_resolver_monitors($records, '2001:db8:a::54') === []));
    $adopt = function (string $gateway, string $dev, string $hop, string $if): bool {
        $route = ['present' => true, 'gateway' => $gateway, 'interface' => $dev, 'reject' => false, 'ours' => false];
        $s = ['settings' => ['default' => '192.0.2.1'], 'routes' => ['192.0.2.1' => $route],
              'contract_input' => ['foreign' => ['192.0.2.1']]];
        $r = uu_route_adopt($s, ['192.0.2.1' => ['route' => ['kind' => 'member', 'next_hop' => $hop, 'if' => $if],
                                                 'forwarded' => true, 'released_at' => null]]);
        return $r['routes']['192.0.2.1']['ours'] === true && $r['contract_input']['foreign'] === [];
    };
    uu_check($t, '(t7) adopt: a recorded member route is ours again when route(8) prints the next hop scoped or in '
        . 'another spelling, and not when it is another hop',
        uu_try_case(fn (): bool => $adopt('fe80::1%gif0', 'gif0', 'fe80::1', 'gif0')
            && $adopt('FD00:0::3:2', 'wg3', 'fd00::3:2', 'wg3') && $adopt('10.2.0.4', 'wg1', '10.2.0.4', 'wg1')
            && !$adopt('fe80::2%gif0', 'gif0', 'fe80::1', 'gif0') && !$adopt('fe80::1%gif0', 'gif1', 'fe80::1', 'gif0')));
    $gif = ['next_hop' => 'fe80::1', 'if' => 'gif0'] + $a;
    $viaGif = ['present' => true, 'gateway' => 'fe80::1%gif0', 'interface' => 'gif0', 'reject' => false];
    uu_check($t, '(t7) ours: a link-local gateway printed with its device scope is the member\'s next hop',
        uu_try_case(fn (): bool => uu_route_ours($viaGif, ['wg-gif' => $gif])
            && uu_route_ours(['gateway' => 'fe80::1'] + $viaGif, ['wg-gif' => $gif])
            && !uu_route_ours(['gateway' => 'fe80::2%gif0'] + $viaGif, ['wg-gif' => $gif])
            && !uu_route_ours(['interface' => 'gif1'] + $viaGif, ['wg-gif' => $gif])));
    uu_check($t, '(t7) ours: a gateway written in capitals matches the next hop in its canonical form',
        uu_try_case(fn (): bool => uu_route_ours(['gateway' => 'FD00:0::3:2', 'interface' => 'wg3'] + $via,
            ['wg-a6' => ['next_hop' => 'fd00::3:2', 'if' => 'wg3'] + $a])));
    uu_check($t, 'ours: no route is not ours, and a connected route (no gateway) is not ours',
        !uu_route_ours(['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false], $members)
        && !uu_route_ours(['gateway' => ''] + $via, ['wg-a' => ['next_hop' => ''] + $a]));

    /* the members the renderer gives pass rules: those with an interface */
    $b = uu_test_member();
    $b['name'] = 'wg-b';
    $b['interface'] = 'opt2';
    $b['if'] = 'wg2';
    $c = uu_test_member();
    $c['name'] = 'wg-c';
    $c['interface'] = '';
    $c['if'] = '';
    $ruledA = ['resolver' => '10.2.0.1'] + $a;
    $ruledB = ['resolver' => '10.2.0.1'] + $b;
    uu_check($t, 'ruled members: a member with no resolver gets no pass, so it is not asked for one; each '
        . 'resolver is in its canonical form',
        uu_try_case(fn (): bool => uu_ruled_members(['wg-a' => ['resolver' => '2001:DB8:A:0::53'] + $a,
            'wg-b' => ['resolver' => ''] + $b])
            === [['name' => 'wg-a', 'interface' => 'opt1', 'if' => 'wg1', 'resolver' => '2001:db8:a::53']]));
    $ruled = uu_ruled_members(['wg-a' => $ruledA, 'wg-c' => ['resolver' => '10.2.0.1'] + $c, 'wg-b' => $ruledB]);
    uu_check($t, 'ruled members: name, interface and device of each member with an interface, in order',
        $ruled === [['name' => 'wg-a', 'interface' => 'opt1', 'if' => 'wg1', 'resolver' => '10.2.0.1'],
                    ['name' => 'wg-b', 'interface' => 'opt2', 'if' => 'wg2', 'resolver' => '10.2.0.1']]);

    /* pf observation through a recording pfctl */
    $si = uu_snapshot_fixture('pfctl_si_v.txt');
    $sum = '0x86046332dac3627299e22fb166d0fef2';
    $outputs = ['-si -v' => $si, '-vsr' => uu_pfobserve_vsr12(),
                '-vvsTables' => uu_snapshot_fixture('pfctl_vvsTables.txt'),
                '-t ' . UU_BLOCK_TABLE . ' -T show' => "   10.2.0.1\n"];
    $observe = function (?array $record, bool $listRules, array $outputs) use ($ruled): array {
        $calls = [];
        $pfctl = function (array $args) use (&$calls, $outputs): array {
            $calls[] = implode(' ', $args);
            return ['out' => $outputs[implode(' ', $args)] ?? '', 'err' => "No ALTQ support in kernel\n"];
        };
        $o = uu_pf_observe($ruled, ['10.2.0.1'], '10.2.0.1', $record, 1792400000, $listRules, $pfctl);
        return [$o, $calls];
    };
    /* the runner returns stdout and stderr apart: stderr decides a listing's use and never reaches a parser */
    $observe2 = function (?array $record, array $vsr) use ($ruled, $si): array {
        $calls = [];
        $altq = "No ALTQ support in kernel\nALTQ related functions disabled\n";
        $pfctl = function (array $args) use (&$calls, &$vsr, $si, $altq): array {
            $key = implode(' ', $args);
            $calls[] = $key;
            return match ($key) {
                '-si -v' => ['out' => $si, 'err' => $altq],
                '-vsr' => array_shift($vsr) ?? ['out' => '', 'err' => ''],
                '-vvsTables' => ['out' => uu_snapshot_fixture('pfctl_vvsTables.txt'), 'err' => $altq],
                default => ['out' => "   10.2.0.1\n", 'err' => ''],
            };
        };
        return [uu_pf_observe($ruled, ['10.2.0.1'], '10.2.0.1', $record, 1792400000, true, $pfctl), $calls];
    };
    $whole = uu_pfobserve_vsr12();
    $half = implode("\n", array_slice(explode("\n", $whole), 0, 8)) . "\n";
    $try = function (callable $case): bool {
        try {
            return (bool)$case();
        } catch (\Throwable) {
            return false;
        }
    };
    uu_check($t, 'observe: a listing pfctl cut short (DIOCGETRULE: Device busy, exit 0, same checksum) is listed '
        . 'again and the whole one recorded',
        $try(function () use ($observe2, $half, $whole): bool {
            [$o, $calls] = $observe2(null, [['out' => $half, 'err' => "pfctl: DIOCGETRULE: Device busy\n"],
                ['out' => $whole, 'err' => "No ALTQ support in kernel\n"]]);
            return count(array_keys($calls, '-vsr', true)) === 2 && $o['rules']['state'] === 'loaded'
                && $o['rules']['record'] !== null && $o['rules']['record']['loaded'] === true;
        }));
    uu_check($t, 'observe: a listing with only the ALTQ notices on stderr is used at once',
        $try(function () use ($observe2, $whole): bool {
            [$o, $calls] = $observe2(null, [['out' => $whole,
                'err' => "No ALTQ support in kernel\nALTQ related functions disabled\n"]]);
            return count(array_keys($calls, '-vsr', true)) === 1 && $o['rules']['state'] === 'loaded'
                && $o['rules']['record'] !== null;
        }));
    /*
     * the runner on a stand-in binary: a pfctl that exits non-zero, or is killed mid-listing, keeps the stdout it
     * printed and gets a "pfctl: exit N" line on stderr, so its listing is unusable; each in a scratch run directory
     */
    uu_check($t, 'runner: a non-zero exit keeps stdout and adds "pfctl: exit 3" to stderr, so a listing is unusable',
        uu_scratch_case(function (string $dir): bool {
            $exit3 = uu_pfctl_run(['-c', 'printf partial; exit 3'], '/bin/sh', $dir);
            return $exit3['out'] === 'partial' && str_contains($exit3['err'], 'pfctl: exit 3')
                && !uu_pf_listing_usable($exit3['err']);
        }));
    uu_check($t, 'runner: a pfctl killed mid-listing makes the listing unusable',
        uu_scratch_case(function (string $dir): bool {
            $killed = uu_pfctl_run(['-c', 'printf partial; kill -9 $$'], '/bin/sh', $dir);
            return $killed['out'] === 'partial' && !uu_pf_listing_usable($killed['err']);
        }));
    uu_check($t, 'runner: exit 0 with only an ALTQ notice on stderr is a usable listing, the streams apart',
        uu_scratch_case(function (string $dir): bool {
            $clean = uu_pfctl_run(['-c', 'printf whole; echo "No ALTQ support in kernel" >&2'], '/bin/sh', $dir);
            return $clean === ['out' => 'whole', 'err' => "No ALTQ support in kernel\n"]
                && uu_pf_listing_usable($clean['err']);
        }));
    /* the stderr file lives in the run directory it is given, never in /tmp; tempnam() falls back
     * to the system temporary directory when that one is unusable, which is refused */
    $stub = function (string $dir): string {
        file_put_contents($dir . '/stub.sh', "#!/bin/sh\nls \"\$1\"\n");
        chmod($dir . '/stub.sh', 0700);
        return $dir . '/stub.sh';
    };
    uu_check($t, '(t1) runner: the stderr file is a uu_pfctl* file in the run directory while pfctl runs, gone after',
        uu_scratch_case(function (string $dir) use ($stub): bool {
            $run = uu_pfctl_run([$dir], $stub($dir), $dir);
            $listed = preg_grep('/^uu_pfctl/', explode("\n", $run['out'])) ?: [];
            return count($listed) === 1 && $run['err'] === '' && (glob($dir . '/uu_pfctl*') ?: []) === [];
        }));
    uu_check($t, '(t2) runner: a run directory that does not exist is "no temporary file for its stderr", and no '
        . 'uu_pfctl file is left in /tmp or the system temporary directory (tempnam()\'s fallback)',
        uu_scratch_case(function (string $dir) use ($stub): bool {
            $temps = fn (): array => array_values(array_unique(array_merge(glob('/tmp/uu_pfctl*') ?: [],
                glob(sys_get_temp_dir() . '/uu_pfctl*') ?: [])));
            $before = $temps();
            $run = uu_pfctl_run([], $stub($dir), '/nonexistent/uu');
            return $run === ['out' => '', 'err' => 'pfctl: no temporary file for its stderr'] && $temps() === $before;
        }));
    [$o, $calls] = $observe(null, false, $outputs);
    uu_check($t, 'observe, status (no listing) without a record: verifying; the checksum and the table are read, '
        . 'the ruleset is never listed',
        $o['rules'] === ['state' => 'verifying', 'problems' => [], 'verified_at' => null, 'record' => null]
        && $calls === ['-si -v', '-vvsTables', '-t ' . UU_BLOCK_TABLE . ' -T show']);
    uu_check($t, 'observe: the counting table\'s facts and addresses',
        $o['block_table'] === ['table' => ['addresses' => 1, 'references' => 1, 'out_block' => 6],
                               'addresses' => ['10.2.0.1']]);
    $in = uu_rules_inputs($ruled, '10.2.0.1');
    $record = ['checksum' => $sum, 'inputs' => $in, 'at' => 1792399000, 'loaded' => true, 'problems' => []];
    [$o, $calls] = $observe($record, false, $outputs);
    uu_check($t, 'observe, status with a record of the live checksum: its verdict and time, no listing',
        $o['rules'] === ['state' => 'loaded', 'problems' => [], 'verified_at' => 1792399000, 'record' => null]
        && !in_array('-vsr', $calls, true));
    [$o, $calls] = $observe(null, true, $outputs);
    uu_check($t, 'observe, evaluation without a record: lists once between two checksum reads and returns the record',
        $o['rules'] === ['state' => 'loaded', 'problems' => [], 'verified_at' => 1792400000,
                         'record' => ['checksum' => $sum, 'inputs' => $in, 'at' => 1792400000, 'loaded' => true,
                                      'problems' => []]]
        && array_slice($calls, 0, 3) === ['-si -v', '-vsr', '-si -v']
        && count(array_keys($calls, '-vsr', true)) === 1);
    [$o, $calls] = $observe(['checksum' => '0x1'] + $record, true, $outputs);
    uu_check($t, 'observe, evaluation with a stale record: lists again',
        in_array('-vsr', $calls, true) && $o['rules']['record'] !== null && $o['rules']['record']['checksum'] === $sum);
    [$o, $calls] = $observe($record, true, $outputs);
    uu_check($t, 'observe, evaluation with a record of the live checksum: no listing and nothing to save',
        !in_array('-vsr', $calls, true) && $o['rules']['state'] === 'loaded' && $o['rules']['record'] === null);
    $otherInputs = ['inputs' => uu_rules_inputs(array_map(fn (array $m): array => ['resolver' => '10.2.0.9'] + $m,
        $ruled), '10.2.0.9')] + $record;
    [$o, $calls] = $observe($otherInputs, true, $outputs);
    uu_check($t, 'observe: the live checksum recorded for other inputs (another resolver) lists and records these',
        in_array('-vsr', $calls, true) && $o['rules']['record'] !== null && $o['rules']['record']['inputs'] === $in);
    [$o, $calls] = $observe($otherInputs, false, $outputs);
    uu_check($t, 'observe, status: the live checksum recorded for other inputs reads verifying, no listing',
        $o['rules']['state'] === 'verifying' && !in_array('-vsr', $calls, true));
    [$o, $calls] = $observe(null, true, ['-vvsTables' => ''] + $outputs);
    uu_check($t, 'observe: no table listed, so its addresses are not asked for',
        $o['block_table'] === ['table' => null, 'addresses' => []]
        && !in_array('-t ' . UU_BLOCK_TABLE . ' -T show', $calls, true));
    [$o, $calls] = $observe(null, true, ['-si -v' => ''] + $outputs);
    uu_check($t, 'observe: pf status unreadable is missing, named, and nothing is listed',
        $o['rules'] === ['state' => 'missing', 'problems' => ['pf status unreadable'], 'verified_at' => null,
                         'record' => null] && !in_array('-vsr', $calls, true));

    $good = ['resolver' => '192.0.2.1', 'rows' => [], 'probe_name' => '.', 'failback_delay' => '120',
             'group_uuid' => '0b6a7f9e-5c1d-4e0a-9d2b-3f8a1c4e5d60', 'fallback' => '1', 'fail_closed' => '',
             'fail_closed_networks' => ''];
    $clean = fn (array $over): array => uu_settings_clean($over + $good);
    $one = function (array $over, string $key, string|int $want) use ($clean): bool {
        $r = $clean($over);
        return $r['settings'][$key] === $want && count($r['problems']) === 1;
    };
    uu_check($t, 'settings: fail-closed lists cleaned',
        uu_try_case(fn (): bool => $clean(['fail_closed' => 'opt3,opt1,opt3'])['settings']['fail_closed']
                === ['opt1', 'opt3']
            && $clean(['fail_closed_networks' => '2001:DB8::/48,192.0.2.0/24'])['settings']['fail_closed_networks']
                === ['192.0.2.0/24', '2001:db8::/48']));
    uu_check($t, 'settings: an unparseable network is dropped with a problem line',
        uu_try_case(function () use ($clean): bool {
            $r = $clean(['fail_closed_networks' => 'bogus,192.0.2.0/24']);
            return $r['settings']['fail_closed_networks'] === ['192.0.2.0/24']
                && $r['problems'] === ['settings: fail-closed network bogus is not a network; ignored'];
        }));
    uu_check($t, 'settings: fallback "0" is false',
        uu_try_case(fn (): bool => $clean(['fallback' => '0'])['settings']['fallback'] === false
            && $clean(['fallback' => '1'])['settings']['fallback'] === true));
    /* each settings_clean case runs inside uu_try_case(), so on a version without it each fails on its own */
    uu_check($t, 'settings_clean: the defaults pass unchanged with no problem',
        uu_try_case(fn (): bool => uu_settings_clean($good) === ['settings' => [
            'default' => '192.0.2.1', 'rows' => [], 'probe_name' => '.', 'failback_delay' => 120,
            'group_uuid' => '0b6a7f9e-5c1d-4e0a-9d2b-3f8a1c4e5d60', 'fallback' => true, 'fail_closed' => [],
            'fail_closed_networks' => []], 'problems' => []]));
    uu_check($t, 'settings_clean: a resolver with a prefix length or a host name is unset, one problem each',
        uu_try_case(fn (): bool => $one(['resolver' => '192.0.2.1/32'], 'default', '')
            && $one(['resolver' => 'resolver.example'], 'default', '')
            && $one(['resolver' => '::ffff:192.0.2.1'], 'default', '')));
    uu_check($t, '(t10) settings_clean: an IPv6 resolver is kept in its canonical form with no problem',
        uu_try_case(fn (): bool => $clean(['resolver' => '2001:DB8::53'])['settings']['default'] === '2001:db8::53'
            && $clean(['resolver' => '2001:DB8::53'])['problems'] === []
            && $clean(['resolver' => '2001:DB8:A:0::53'])['settings']['default'] === '2001:db8:a::53'
            && $clean(['resolver' => '192.0.2.1'])['problems'] === []));
    uu_check($t, '(t10) settings_clean: a link-local resolver is unset with one problem naming link-local, and a '
        . 'value that is no address says so',
        uu_try_case(function () use ($clean, $one): bool {
            $linkLocal = $clean(['resolver' => 'fe80::1']);
            $text = $clean(['resolver' => 'dns.example']);
            return $one(['resolver' => 'fe80::1'], 'default', '')
                && $linkLocal['problems'] === ['settings: the resolver is link-local; evaluating as unset']
                && $text['problems'] === ['settings: the resolver is not an IPv4 or IPv6 address; evaluating as unset']
                && $clean(['resolver' => '224.0.0.1'])['problems']
                    === ['settings: the resolver is multicast; evaluating as unset']
                && $clean(['resolver' => '::1'])['problems']
                    === ['settings: the resolver is loopback; evaluating as unset']
                && $clean(['resolver' => '0.0.0.0'])['problems']
                    === ['settings: the resolver is unspecified; evaluating as unset'];
        }));
    uu_check($t, 'settings_clean: a probe name with a space is the root, one problem',
        uu_try_case(fn (): bool => $one(['probe_name' => 'a b'], 'probe_name', '.')));
    uu_check($t, 'settings_clean: failback_delay is clamped to 60..UU_FAILBACK_DELAY_MAX, one problem each',
        uu_try_case(fn (): bool => $one(['failback_delay' => '10'], 'failback_delay', 60)
            && $one(['failback_delay' => '99999'], 'failback_delay', UU_FAILBACK_DELAY_MAX)));
    uu_check($t, 'settings_clean: a group id that is not a UUID is none, one problem',
        uu_try_case(fn (): bool => $one(['group_uuid' => 'not-a-uuid'], 'group_uuid', '')));
    uu_check($t, 'settings_clean: an empty group id (none chosen) is not a problem',
        uu_try_case(fn (): bool => $clean(['group_uuid' => ''])['problems'] === []));
    uu_check($t,
        'settings_clean: a failback_delay that is not digits is the default 120, one problem, value not quoted',
        uu_try_case(fn (): bool => $one(['failback_delay' => '120abc'], 'failback_delay', 120)
            && $one(['failback_delay' => '1e2'], 'failback_delay', 120)
            && $one(['failback_delay' => ''], 'failback_delay', 120)
            && $one(['failback_delay' => '-5'], 'failback_delay', 120)
            && !str_contains(implode(' ', $clean(['failback_delay' => '120abc'])['problems']), '120abc')));
    uu_check($t, 'settings_clean: a trailing newline never passes the probe name or the group id masks',
        uu_try_case(fn (): bool => $one(['probe_name' => "example.org\n"], 'probe_name', '.')
            && $one(['group_uuid' => "0b6a7f9e-5c1d-4e0a-9d2b-3f8a1c4e5d60\n"], 'group_uuid', '')));
    uu_check($t, 'settings_clean: no problem quotes the value',
        uu_try_case(function () use ($clean): bool {
            $r = $clean(['resolver' => 'secret.example', 'probe_name' => 'a b secret']);
            return count($r['problems']) === 2 && !str_contains(implode(' ', $r['problems']), 'secret');
        }));

    uu_check($t, '(g11) adopt per address: the Default\'s route and a row\'s address, each matching its record and '
        . 'explained by no member, are both the plugin\'s; foreign empties; each is adopted only by its own record',
        uu_try_case(function (): bool {
            $viaWg1 = ['present' => true, 'gateway' => '10.2.0.2', 'interface' => 'wg1', 'reject' => false,
                       'ours' => false];
            $viaWg4 = ['present' => true, 'gateway' => 'fd00::4:2', 'interface' => 'wg4', 'reject' => false,
                       'ours' => false];
            $s = ['settings' => ['default' => '10.2.0.1'],
                  'routes' => ['10.2.0.1' => $viaWg1, '2001:db8:b::53' => $viaWg4],
                  'contract_input' => ['foreign' => ['10.2.0.1', '2001:db8:b::53']]];
            $map = ['10.2.0.1' => ['route' => ['kind' => 'member', 'next_hop' => '10.2.0.2', 'if' => 'wg1'],
                                   'forwarded' => true, 'released_at' => null],
                    '2001:db8:b::53' => ['route' => ['kind' => 'member', 'next_hop' => 'fd00::4:2', 'if' => 'wg4'],
                                         'forwarded' => false, 'released_at' => null]];
            $both = uu_route_adopt($s, $map);
            $rowOnly = uu_route_adopt($s, ['2001:db8:b::53' => $map['2001:db8:b::53']]);
            return $both['routes']['10.2.0.1']['ours'] && $both['routes']['2001:db8:b::53']['ours']
                && $both['contract_input']['foreign'] === []
                && $rowOnly['routes']['2001:db8:b::53']['ours']
                && !$rowOnly['routes']['10.2.0.1']['ours'] && $rowOnly['contract_input']['foreign'] === ['10.2.0.1'];
        }));

    // The per-member rows, cleaned as the Default is.
    $gwA = '0b6a7f9e-5c1d-4e0a-9d2b-3f8a1c4e5d6a';
    $gwB = '0b6a7f9e-5c1d-4e0a-9d2b-3f8a1c4e5d6b';
    $badRow = 'settings: a per-member resolver row is not a gateway id and an IPv4 or IPv6 address; ignored';
    uu_check($t, 'settings_clean: the rows keyed by gateway id, each address canonical, the Default beside them',
        uu_try_case(function () use ($clean, $gwA, $gwB): bool {
            $r = $clean(['resolver' => '2001:DB8:A:0::53', 'rows' => [
                ['gateway' => $gwA, 'address' => '2001:0DB8:B::0053'], ['gateway' => $gwB, 'address' => '192.0.2.9']]]);
            return $r['problems'] === [] && $r['settings']['default'] === '2001:db8:a::53'
                && !array_key_exists('resolver', $r['settings'])
                && $r['settings']['rows'] === [$gwA => '2001:db8:b::53', $gwB => '192.0.2.9'];
        }));
    uu_check($t, 'settings_clean: a row whose gateway is no id, or whose address is no address or one the model '
        . 'refuses, is dropped with one problem each, the value never quoted',
        uu_try_case(function () use ($clean, $gwA, $badRow): bool {
            $r = $clean(['rows' => [['gateway' => 'wg-secret', 'address' => '192.0.2.9'],
                ['gateway' => $gwA, 'address' => 'secret.example'], ['gateway' => $gwA, 'address' => 'fe80::1'],
                ['gateway' => $gwA, 'address' => '192.0.2.0/24'], ['gateway' => '', 'address' => '192.0.2.9']]]);
            return $r['settings']['rows'] === [] && $r['problems'] === array_fill(0, 5, $badRow)
                && !str_contains(implode(' ', $r['problems']), 'secret');
        }));
    uu_check($t, 'settings_clean: a second row for one gateway is dropped with its problem, the first kept; a bad row '
        . 'before it does not count as the first',
        uu_try_case(function () use ($clean, $gwA, $badRow): bool {
            $r = $clean(['rows' => [['gateway' => $gwA, 'address' => 'nonsense'],
                ['gateway' => $gwA, 'address' => '192.0.2.9'], ['gateway' => $gwA, 'address' => '192.0.2.10']]]);
            return $r['settings']['rows'] === [$gwA => '192.0.2.9'] && $r['problems'] === [$badRow,
                'settings: two per-member resolver rows name one gateway; the second is ignored'];
        }));

    // A recording made before 1.4 is refused by name; this version's passes through.
    uu_check($t, '(p17) recorded: a recording with a route and no routes (made before 1.4) is refused, naming it',
        uu_try_case(function (): bool {
            try {
                uu_snapshot_recorded(['route' => ['present' => false], 'contract_input' => ['core_commands' => []]],
                    '/root/old.json');
            } catch (\RuntimeException $e) {
                return $e->getMessage() === '/root/old.json was recorded before 1.4: record it again';
            }
            return false;
        }));
    uu_check($t, '(p17) recorded: a recording with routes passes through unchanged',
        uu_try_case(function (): bool {
            $rec = ['routes' => [], 'route_flags' => ['10.2.0.1' => ['UP', 'HOST']],
                    'contract_input' => ['core_commands' => ['cron restart']]];
            $read = uu_snapshot_recorded($rec, '/root/new.json');
            return array_slice($read, 0, 3) === $rec
                && array_keys($read) === [...array_keys($rec), 'upgrade', 'view'];
        }));
    uu_check($t, 'recorded: an earlier 1.4 recording with no route_flags gains none read, right after routes',
        uu_try_case(function (): bool {
            $rec = ['now' => 10000, 'routes' => ['10.2.0.1' => ['present' => false]], 'fib_sync_ms' => 1000,
                    'contract_input' => ['core_commands' => []]];
            $read = uu_snapshot_recorded($rec, '/root/earlier.json');
            return array_keys($read) === ['now', 'routes', 'route_flags', 'fib_sync_ms', 'contract_input', 'upgrade',
                    'view']
                && $read['route_flags'] === [] && $read['routes'] === $rec['routes'];
        }));

    /* the fail-closed view the snapshot reads */
    $viewSettings = fn (array $over = []): array => $over + ['fallback' => true, 'fail_closed' => ['lan'],
        'fail_closed_networks' => []];
    $viewDetails = fn (): array => ['details' => ['igc1' => [
        'ipv4' => [['ipaddr' => '192.0.2.1', 'subnetbits' => 24]], 'ipv6' => []]], 'devices' => ['lan' => 'igc1']];
    $noFile = fn (string $path): array => ['text' => null, 'problem' => null];
    $zonesReply = "localhost. transparent\n127.in-addr.arpa. nodefault\n. refuse\n";
    $dataReply = "host.example. 3600 IN A 192.0.2.9\n";
    $recorder = function (array $replies): array {
        $calls = new ArrayObject();
        $uc = function (array $args) use ($calls, $replies): ?string {
            $calls[] = implode(' ', $args);
            return $replies[$args[0]] ?? null;
        };
        return [$uc, $calls];
    };

    [$uc, $calls] = $recorder([]);
    $v = uu_view_snapshot($viewSettings(['fail_closed' => []]), true, $uc, $viewDetails, "server:\n", $noFile);
    uu_check($t, 'snapshot: an empty set with no file reads nothing',
        $v['loaded'] === 'skipped' && $calls->getArrayCopy() === [] && $v['scope'] === 'none' && $v['nets'] === []
        && $v['file'] === null && $v['copy'] === null && $v['zones'] === null && $v['data'] === null
        && $v['view_zones'] === [] && $v['view_data'] === []);

    [$uc, $calls] = $recorder(['view_list_local_zones' => "no view with name: unboundupstream\n"]);
    $v = uu_view_snapshot($viewSettings(), false, $uc, $viewDetails, "server:\n", $noFile);
    uu_check($t, 'snapshot: no view with name is absent',
        $v['loaded'] === 'absent' && $calls->getArrayCopy() === ['view_list_local_zones unboundupstream']
        && $v['nets'] === ['192.0.2.0/24'] && $v['scope'] === 'selected' && $v['view_zones'] === []);

    [$uc, $calls] = $recorder(['view_list_local_zones' => "error unknown command 'view_list_local_zones'\n"]);
    $v = uu_view_snapshot($viewSettings(), false, $uc, $viewDetails, null, $noFile);
    uu_check($t, 'snapshot: error unknown command is unsupported',
        $v['loaded'] === 'unsupported' && $v['acl'] === null && $v['copy'] === null);

    [$uc, $calls] = $recorder([]);
    $v = uu_view_snapshot($viewSettings(), true, $uc, $viewDetails, null, $noFile);
    uu_check($t, 'snapshot: silence is silent and lists nothing more',
        $v['loaded'] === 'silent' && $calls->getArrayCopy() === ['view_list_local_zones unboundupstream']
        && $v['zones'] === null);

    [$uc, $calls] = $recorder(['view_list_local_zones' => $zonesReply, 'view_list_local_data' => $dataReply]);
    $v = uu_view_snapshot($viewSettings(), false, $uc, $viewDetails, null, $noFile);
    uu_check($t, 'snapshot: zones false never lists',
        $v['loaded'] === 'zones' && $calls->getArrayCopy() === ['view_list_local_zones unboundupstream',
            'view_list_local_data unboundupstream'] && $v['zones'] === null && $v['data'] === null
        && $v['view_zones'] === ['localhost.' => 'transparent', '127.in-addr.arpa.' => 'nodefault', '.' => 'refuse']
        && $v['view_data'] === ['host.example. 3600 IN A 192.0.2.9']);

    [$uc, $calls] = $recorder(['view_list_local_zones' => $zonesReply, 'view_list_local_data' => $dataReply,
        'list_local_zones' => "localhost. transparent\n127.in-addr.arpa. nodefault\n",
        'list_forwards' => ". IN forward 192.0.2.53\n", 'list_stubs' => "\n",
        'list_local_data' => "nas.example. 3600 IN A 192.0.2.8\n"]);
    $v = uu_view_snapshot($viewSettings(), true, $uc, $viewDetails, null, $noFile);
    uu_check($t, 'snapshot: zones true reads the daemon lists too',
        $v['loaded'] === 'zones' && count($calls) === 6 && $v['data'] === ['nas.example. 3600 IN A 192.0.2.8']
        && $v['zones'] === ['127.in-addr.arpa.' => 'nodefault', 'localhost.' => 'transparent']);

    [$uc, $calls] = $recorder([]);
    $v = uu_view_snapshot($viewSettings(), true, $uc, $viewDetails, null, $noFile, false);
    uu_check($t, "snapshot: Unbound's pid not alive reads no view",
        $v['loaded'] === 'skipped' && $calls->getArrayCopy() === [] && $v['nets'] === ['192.0.2.0/24']);

    [$uc, $calls] = $recorder(['view_list_local_zones' => "no view with name: unboundupstream\n"]);
    $fileCopy = "server:\n    access-control: 0.0.0.0/0 allow\n    access-control: ::/0 allow\n"
        . UU_VIEW_BEGIN . "\nserver:\n" . UU_VIEW_END . "\n";
    $withFile = fn (string $path): array => ['text' => $path === UU_VIEW_FILE ? "rendered\n" : null,
        'problem' => null];
    $v = uu_view_snapshot($viewSettings(['fail_closed' => []]), false, $uc, $viewDetails, $fileCopy, $withFile);
    uu_check($t, 'snapshot: a file or copy on disk reads the view with an empty set; core\'s ACL and the copy are kept',
        $v['loaded'] === 'absent' && $v['file'] === "rendered\n" && $v['copy'] === UU_VIEW_BEGIN . "\nserver:\n"
            . UU_VIEW_END . "\n"
        && $v['acl'] === ['nodes' => [['net' => '0.0.0.0/0', 'action' => 'allow'],
            ['net' => '::/0', 'action' => 'allow']], 'foreign' => []]);

    $tooLarge = fn (string $path): array => $path === UU_VIEW_FILE ? ['text' => null, 'problem' => 'larger than 1 MiB']
        : ['text' => null, 'problem' => null];
    $results = [];
    foreach (['too large' => $tooLarge, 'missing' => $noFile, 'readable' => $withFile] as $what => $reader) {
        [$uc, $calls] = $recorder(['view_list_local_zones' => "no view with name: unboundupstream\n"]);
        $v = uu_view_snapshot($viewSettings(['fail_closed' => []]), false, $uc, $viewDetails, "server:\n", $reader);
        $results[$what] = [$v['file'], $v['file_present'], $v['loaded']];
    }
    uu_check($t, 'snapshot: a view file that cannot be read is still on disk: it has no text, counts as present, and '
        . 'the view is read with an empty set',
        $results === ['too large' => [null, true, 'absent'], 'missing' => [null, false, 'skipped'],
            'readable' => ["rendered\n", true, 'absent']]);

    $waitState = [
        'settings' => ['enabled' => true], 'stop' => null,
        'unbound' => ['enabled' => true, 'pid_alive' => true, 'control_ok' => false, 'live_root' => null],
        'view' => ['scope' => 'selected', 'nets' => ['192.0.2.0/24'], 'notes' => [], 'acl' => null, 'zones' => null,
            'data' => null, 'loaded' => 'silent', 'view_zones' => [], 'view_data' => [], 'file' => null,
            'copy' => null, 'file_present' => false]];
    [$uc, $calls] = $recorder(['view_list_local_zones' => $zonesReply, 'view_list_local_data' => $dataReply,
        'list_local_zones' => "localhost. transparent\n127.in-addr.arpa. nodefault\n",
        'list_forwards' => "\n", 'list_stubs' => "\n", 'list_local_data' => "\n"]);
    $answers = [null, null, ['192.0.2.53']];
    $liveRoot = function () use (&$answers): ?array {
        return array_shift($answers);
    };
    $w = uu_wait_control($waitState, 'fallback', $liveRoot, $uc, function (): void {
    });
    uu_check($t, 'snapshot: a channel that answers after the wait reads the view',
        $w['unbound']['control_ok'] && $w['view']['loaded'] === 'zones' && $w['view']['data'] === []
        && $w['view']['view_zones']['.'] === 'refuse' && count($calls) === 6);

    [$uc, $calls] = $recorder([]);
    $answers = [null, null, ['192.0.2.53']];
    $skipped = $waitState;
    $skipped['view']['loaded'] = 'skipped';
    $w = uu_wait_control($skipped, 'fallback', $liveRoot, $uc, function (): void {
    });
    uu_check($t, 'snapshot: a recovered channel with no view to read runs no view command',
        $w['unbound']['control_ok'] && $w['view']['loaded'] === 'skipped' && $calls->getArrayCopy() === []);

    $converted = uu_snapshot_recorded(['routes' => [], 'contract_input' => ['core_commands' => []]], '/root/r.json');
    uu_check($t, 'recorded: a 1.4 recording gains upgrade false and a skipped view with scope none, last',
        $converted['upgrade'] === false && $converted['view']['loaded'] === 'skipped'
        && $converted['view']['scope'] === 'none' && array_slice(array_keys($converted), -2) === ['upgrade', 'view']);

    return uu_tally_report('snapshot', $t);
});
