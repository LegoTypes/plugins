<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Live snapshot parsers (spec section 3.2): route get, unbound-control forward, sysctl, ps, group tiers; and the pf
 * observation the snapshot makes through an injected pfctl (section 3.6c): what it reads, and that a status never
 * lists the ruleset; and the pfctl runner, whose stderr file lives in the root-only run directory (convention C3).
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/snapshot.php';
require_once __DIR__ . '/test_verdict.php';
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

    uu_check($t, 'network: inside /24, outside, /32 host, /0 everything',
        uu_ipv4_in_network('10.2.0.1', '10.2.0.0/24') && !uu_ipv4_in_network('10.2.1.1', '10.2.0.0/24')
        && uu_ipv4_in_network('10.2.0.1', '10.2.0.1') && uu_ipv4_in_network('10.2.0.1', '0.0.0.0/0')
        && !uu_ipv4_in_network('10.2.0.1', '10.2.0.2/32'));
    uu_check($t, 'network: IPv6 and malformed networks never match',
        !uu_ipv4_in_network('10.2.0.1', '2001:db8::/32') && !uu_ipv4_in_network('10.2.0.1', 'nonsense')
        && !uu_ipv4_in_network('10.2.0.1', '10.2.0.0/33'));

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
    $ruled = uu_ruled_members(['wg-a' => $a, 'wg-c' => $c, 'wg-b' => $b]);
    uu_check($t, 'ruled members: name, interface and device of each member with an interface, in order',
        $ruled === [['name' => 'wg-a', 'interface' => 'opt1', 'if' => 'wg1'],
                    ['name' => 'wg-b', 'interface' => 'opt2', 'if' => 'wg2']]);

    /* pf observation through a recording pfctl */
    $si = uu_snapshot_fixture('pfctl_si_v.txt');
    $sum = '0x86046332dac3627299e22fb166d0fef2';
    $outputs = ['-si -v' => $si, '-vsr' => uu_snapshot_fixture('pfctl_vsr_12.txt'),
                '-vvsTables' => uu_snapshot_fixture('pfctl_vvsTables.txt'),
                '-t ' . UU_BLOCK_TABLE . ' -T show' => "   10.2.0.1\n"];
    $observe = function (?array $record, bool $listRules, array $outputs) use ($ruled): array {
        $calls = [];
        $pfctl = function (array $args) use (&$calls, $outputs): array {
            $calls[] = implode(' ', $args);
            return ['out' => $outputs[implode(' ', $args)] ?? '', 'err' => "No ALTQ support in kernel\n"];
        };
        $o = uu_pf_observe('10.2.0.1', $ruled, $record, 1792400000, $listRules, $pfctl);
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
        return [uu_pf_observe('10.2.0.1', $ruled, $record, 1792400000, true, $pfctl), $calls];
    };
    $whole = uu_snapshot_fixture('pfctl_vsr_12.txt');
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
    /* convention C3: the stderr file lives in the run directory it is given, never in /tmp; tempnam() falls back
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
    $in = uu_rules_inputs('10.2.0.1', $ruled);
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
    $otherInputs = ['inputs' => uu_rules_inputs('10.2.0.9', $ruled)] + $record;
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

    $good = ['resolver' => '192.0.2.1', 'probe_name' => '.', 'failback_delay' => '120',
             'group_uuid' => '0b6a7f9e-5c1d-4e0a-9d2b-3f8a1c4e5d60'];
    $clean = fn (array $over): array => uu_settings_clean($over + $good);
    $one = function (array $over, string $key, string|int $want) use ($clean): bool {
        $r = $clean($over);
        return $r['settings'][$key] === $want && count($r['problems']) === 1;
    };
    uu_check($t, 'settings_clean: the defaults pass unchanged with no problem',
        uu_settings_clean($good) === ['settings' => ['resolver' => '192.0.2.1', 'probe_name' => '.',
            'failback_delay' => 120, 'group_uuid' => '0b6a7f9e-5c1d-4e0a-9d2b-3f8a1c4e5d60'], 'problems' => []]);
    uu_check($t, 'settings_clean: a resolver with a prefix length or a host name is unset, one problem each',
        $one(['resolver' => '192.0.2.1/32'], 'resolver', '') && $one(['resolver' => 'resolver.example'], 'resolver', '')
            && $one(['resolver' => '2001:db8::1'], 'resolver', ''));
    uu_check($t, 'settings_clean: a probe name with a space is the root, one problem',
        $one(['probe_name' => 'a b'], 'probe_name', '.'));
    uu_check($t, 'settings_clean: failback_delay is clamped to 60..UU_FAILBACK_DELAY_MAX, one problem each',
        $one(['failback_delay' => '10'], 'failback_delay', 60)
            && $one(['failback_delay' => '99999'], 'failback_delay', UU_FAILBACK_DELAY_MAX));
    uu_check($t, 'settings_clean: a group id that is not a UUID is none, one problem',
        $one(['group_uuid' => 'not-a-uuid'], 'group_uuid', ''));
    uu_check($t, 'settings_clean: an empty group id (none chosen) is not a problem',
        $clean(['group_uuid' => ''])['problems'] === []);
    uu_check($t, 'settings_clean: a failback_delay that is not digits is the default 120, one problem, value not quoted',
        $one(['failback_delay' => '120abc'], 'failback_delay', 120) && $one(['failback_delay' => '1e2'], 'failback_delay', 120)
            && $one(['failback_delay' => ''], 'failback_delay', 120) && $one(['failback_delay' => '-5'], 'failback_delay', 120)
            && !str_contains(implode(' ', $clean(['failback_delay' => '120abc'])['problems']), '120abc'));
    uu_check($t, 'settings_clean: a trailing newline never passes the probe name or the group id masks',
        $one(['probe_name' => "example.org\n"], 'probe_name', '.')
            && $one(['group_uuid' => "0b6a7f9e-5c1d-4e0a-9d2b-3f8a1c4e5d60\n"], 'group_uuid', ''));
    $r = $clean(['resolver' => 'secret.example', 'probe_name' => 'a b secret']);
    uu_check($t, 'settings_clean: no problem quotes the value',
        count($r['problems']) === 2 && !str_contains(implode(' ', $r['problems']), 'secret'));

    return uu_tally_report('snapshot', $t);
});
