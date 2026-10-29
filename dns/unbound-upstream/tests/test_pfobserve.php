<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Observing pf: the ruleset checksum, a table's counters, the rule verdict read from the
 * kernel's own text by keyword, and the verification kept once per checksum, in a record read as a regular file
 * only.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/pfobserve.php';
require_once __DIR__ . '/scratch.php';

/**
 * The record read of a named pipe, in a child php under timeout -f: a reader that blocks on the pipe, as
 * one that opens it without O_NONBLOCK does while no writer comes, fails the case after 5 s with the evidence instead
 * of hanging the suite. True when the child read null.
 */
function uu_test_fifo_record_null(string $path): bool
{
    $lib = __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/pfobserve.php';
    $code = 'require $argv[1]; echo uu_rules_record_load($argv[2]) === null ? "null" : "read", PHP_EOL;';
    $out = [];
    $rc = 0;
    exec('/usr/bin/timeout -f 5 ' . escapeshellarg(PHP_BINARY) . ' -d log_errors=0 -r ' . escapeshellarg($code) . ' '
        . escapeshellarg($lib) . ' ' . escapeshellarg($path) . ' 2>&1', $out, $rc);
    if ($rc !== 0 || $out !== ['null']) {
        printf("  the read in a child php: exit %d%s, output '%s'\n", $rc,
            $rc === 124 ? ' (killed after 5 s: it blocked on the pipe)' : '', implode(' | ', $out));
        return false;
    }
    return true;
}

function uu_pfobserve_fixture(string $name): string
{
    $text = file_get_contents(__DIR__ . '/fixtures/' . $name);
    return $text === false ? '' : $text;
}

/**
 * The 1.3_2 capture pfctl_vsr_12.txt (members on opt1/wg1 and opt2/wg2, resolver 10.2.0.1) as this version's rules
 * print: each pass under its interface-and-address label, with its states bound to the interface, and its tcp pass
 * with any flags.
 */
function uu_pfobserve_vsr12(): string
{
    return str_replace(
        ['label "' . md5('uu-pass-opt1') . '"', 'label "' . md5('uu-pass-opt2') . '"', 'flags S/SA keep state label',
         'keep state label'],
        ['label "' . uu_label_pass('opt1', '10.2.0.1') . '"', 'label "' . uu_label_pass('opt2', '10.2.0.1') . '"',
         'flags any keep state (if-bound) label', 'keep state (if-bound) label'],
        uu_pfobserve_fixture('pfctl_vsr_12.txt')
    );
}

uu_register_suite('pfobserve', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $members = [
        ['name' => 'wg-a', 'interface' => 'opt1', 'if' => 'wg1', 'resolver' => '10.2.0.1'],
        ['name' => 'wg-b', 'interface' => 'opt2', 'if' => 'wg2', 'resolver' => '10.2.0.1'],
    ];
    $resolver = '10.2.0.1';
    $resolving = fn (array $members, string $resolver): array
        => array_map(fn (array $m): array => ['resolver' => $resolver] + $m, $members);
    /* the plugin's own lines of a test VM listing (members on opt1/wg1 and opt2/wg2), with their counter lines */
    $vsr = uu_pfobserve_vsr12();
    $verdict = fn (string $text): array => uu_rules_verdict($text, $members, [$resolver]);
    /* every edit below must change the capture, or the case it builds would test nothing */
    $missed = [];
    $without = function (string $needle) use ($vsr, &$missed): string {
        $out = implode("\n", array_filter(
            explode("\n", $vsr),
            fn (string $line): bool => !str_contains($line, $needle)
        ));
        if ($out === $vsr) {
            $missed[] = $needle;
        }
        return $out;
    };
    $edit = function (string $from, string $to) use ($vsr, &$missed): string {
        $out = str_replace($from, $to, $vsr);
        if ($out === $vsr) {
            $missed[] = $from;
        }
        return $out;
    };

    /* checksum */
    uu_check($t, 'checksum: parsed',
        uu_pf_checksum(uu_pfobserve_fixture('pfctl_si_v.txt')) === '0x86046332dac3627299e22fb166d0fef2');
    uu_check($t, 'checksum: absent is null', uu_pf_checksum("Status: Enabled\nHostid:   0x1\n") === null);

    /* tables */
    $tables = uu_pfobserve_fixture('pfctl_vvsTables.txt');
    uu_check($t, 'table: parsed',
        uu_pf_table($tables, UU_BLOCK_TABLE) === ['addresses' => 1, 'references' => 1, 'out_block' => 6]);
    uu_check($t, 'table: absent is null', uu_pf_table($tables, 'nosuchtable') === null);
    uu_check($t, 'table: another table is read from its own block',
        uu_pf_table($tables, 'virusprot') === ['addresses' => 0, 'references' => 1, 'out_block' => 0]);
    uu_check($t, 'show: addresses, one per line',
        uu_pf_show_addresses("   10.2.0.1\n   10.2.0.9\n") === ['10.2.0.1', '10.2.0.9']
        && uu_pf_show_addresses('') === []);

    /* rules per member and address: a test VM listing of an IPv6 group whose members have resolvers of their own
     * (wg-a6 on opt1/wg1 to 2001:db8:a::53, wg-b6 on opt2/wg2 to 2001:db8:b::53), with its counter lines */
    $vsrV6 = uu_pfobserve_fixture('pfctl_vsr_v6.txt');
    $members6 = [['name' => 'wg-a6', 'interface' => 'opt1', 'if' => 'wg1', 'resolver' => '2001:db8:a::53'],
                 ['name' => 'wg-b6', 'interface' => 'opt2', 'if' => 'wg2', 'resolver' => '2001:db8:b::53']];
    $setting6 = ['2001:db8:a::53', '2001:db8:b::53'];
    /* every line of the listing that has all of the needles, edited; the case fails when no line has them */
    $editV6 = function (array $needles, string $from, string $to) use ($vsrV6): ?string {
        $hit = false;
        $lines = array_map(function (string $line) use ($needles, $from, $to, &$hit): string {
            foreach ($needles as $needle) {
                if (!str_contains($line, $needle)) {
                    return $line;
                }
            }
            $hit = true;
            return str_replace($from, $to, $line);
        }, explode("\n", $vsrV6));
        return $hit ? implode("\n", $lines) : null;
    };
    $verdictV6 = fn (?string $text): array => $text === null ? ['loaded' => true, 'problems' => ['no such line']]
        : uu_rules_verdict($text, $members6, $setting6);
    uu_check($t, '(v1) a listing of the per-member IPv6 rules reads loaded',
        uu_try_case(fn (): bool => $vsrV6 !== '' && $verdictV6($vsrV6) === ['loaded' => true, 'problems' => []]));
    uu_check($t, '(v2) a pass rendered inet to an IPv6 resolver reads "pass: wrong family"',
        uu_try_case(fn (): bool => $verdictV6($editV6(['on wg1 inet6 proto tcp'], ' inet6 ', ' inet '))
            === ['loaded' => false, 'problems' => ['wg-a6 pass: wrong family']]));
    uu_check($t, '(v2) with no backstop to one of two addresses, it is named missing',
        uu_try_case(fn (): bool => $verdictV6($editV6(['to 2001:db8:b::53 label "' . uu_label_backstop() . '"'],
            'label "' . uu_label_backstop() . '"', 'label "' . uu_label_footprint() . '"'))
            === ['loaded' => false, 'problems' => ['backstop block for 2001:db8:b::53 missing']]));
    uu_check($t, '(v2) a counting block in the other family only reads "counting block: no inet6 rule"; a backstop in '
        . 'the wrong family reads so',
        uu_try_case(fn (): bool => $verdictV6($editV6(['label "' . uu_label_block() . '"'], ' inet6 ', ' inet '))
            === ['loaded' => false, 'problems' => ['counting block: no inet6 rule']]
            && $verdictV6($editV6(['to 2001:db8:a::53 label "' . uu_label_backstop() . '"'], ' inet6 ', ' inet '))
            === ['loaded' => false, 'problems' => ['backstop block: wrong family']]));
    uu_check($t, '(v2) a backstop to an address outside the setting is the wrong target, and nothing more',
        uu_try_case(fn (): bool => $verdictV6($editV6(['to 2001:db8:b::53 label "' . uu_label_backstop() . '"'],
            '2001:db8:b::53', '2001:db8:c::53'))
            === ['loaded' => false, 'problems' => ['backstop block: wrong target']]));
    uu_check($t, '(v2) one member\'s pass under the other\'s resolver is no pass of its own',
        uu_try_case(fn (): bool => uu_rules_verdict($vsrV6, [['resolver' => '2001:db8:b::53'] + $members6[0],
            $members6[1]], $setting6) === ['loaded' => false, 'problems' => ['no pass rule for wg-a6 (opt1)']]));
    uu_check($t, 'a pass whose states are not if-bound reads "pass: missing if-bound", in either family; so does '
        . '1.3_2\'s own listing under this version\'s labels',
        uu_try_case(fn (): bool => $verdictV6($editV6(['on wg2 inet6 proto udp'], ' (if-bound)', ''))
            === ['loaded' => false, 'problems' => ['wg-b6 pass: missing if-bound']]
            && uu_rules_verdict(str_replace(' (if-bound)', '', uu_pfobserve_vsr12()), $members, [$resolver])
            === ['loaded' => false, 'problems' => ['wg-a pass: missing if-bound', 'wg-b pass: missing if-bound']]));
    uu_check($t, 'a tcp pass with pf\'s default flags S/SA reads "pass: missing flags any"; a udp pass has no flags',
        uu_try_case(fn (): bool => $verdictV6($editV6(['on wg2 inet6 proto tcp'], 'flags any', 'flags S/SA'))
            === ['loaded' => false, 'problems' => ['wg-b6 pass: missing flags any']]
            && !str_contains(implode("\n", preg_grep('/proto udp/', explode("\n", $vsrV6)) ?: []), 'flags')));
    /* the counting block and one backstop to the longer of two setting addresses, in each family */
    $oneBackstop = fn (string $family, string $address): string => "block drop out log quick {$family} from any to "
        . '<' . UU_BLOCK_TABLE . '> label "' . uu_label_block() . "\"\nblock drop out log quick {$family} from any to "
        . $address . ' label "' . uu_label_backstop() . "\"\n";
    uu_check($t, '(v2) a backstop to 192.0.2.10 is no backstop to 192.0.2.1, nor one to 2001:db8::2:10 to '
        . '2001:db8::2:1',
        uu_try_case(fn (): bool => uu_rules_verdict($oneBackstop('inet', '192.0.2.10'), [], ['192.0.2.1', '192.0.2.10'])
            === ['loaded' => false, 'problems' => ['backstop block for 192.0.2.1 missing']]
            && uu_rules_verdict($oneBackstop('inet6', '2001:db8::2:10'), [], ['2001:db8::2:1', '2001:db8::2:10'])
            === ['loaded' => false, 'problems' => ['backstop block for 2001:db8::2:1 missing']]));
    uu_check($t, 'if-bound among other state options still reads loaded',
        uu_try_case(fn (): bool => $verdictV6($editV6(['on wg1 inet6 proto udp'], '(if-bound)',
            '(max 10, if-bound, adaptive.start 6, adaptive.end 12)')) === ['loaded' => true, 'problems' => []]));
    uu_check($t, '(v5) 1.3_2\'s capture with this version\'s labels reads loaded; under its own labels every pass is '
        . 'missing',
        uu_try_case(fn (): bool => uu_rules_verdict(uu_pfobserve_vsr12(), $members, [$resolver])
            === ['loaded' => true, 'problems' => []]
            && uu_rules_verdict(uu_pfobserve_fixture('pfctl_vsr_12.txt'), $members, [$resolver])['problems']
            === ['no pass rule for wg-a (opt1)', 'no pass rule for wg-b (opt2)']));
    uu_check($t, '(v7) a Default stored as 2001:DB8:A:0::53 reads the listing that prints 2001:db8:a::53 as loaded',
        uu_try_case(fn (): bool => uu_rules_verdict($vsrV6, [['resolver' => '2001:DB8:A:0::53'] + $members6[0],
            $members6[1]], ['2001:DB8:A:0::53', '2001:db8:b::53']) === ['loaded' => true, 'problems' => []]));
    uu_check($t, '(v3) inputs change when one member\'s resolver changes, or the Default, never with the members\' '
        . 'order',
        uu_try_case(function () use ($members6): bool {
            $in = uu_rules_inputs($members6, '');
            $changed = $members6;
            $changed[1]['resolver'] = '2001:db8:c::53';
            return uu_rules_inputs(array_reverse($members6), '') === $in && uu_rules_inputs($changed, '') !== $in
                && uu_rules_inputs($members6, '2001:db8:a::53') !== $in
                && uu_rules_inputs([['resolver' => '2001:DB8:A::53'] + $members6[0], $members6[1]], '') === $in;
        }));
    $table2 = ['addresses' => 2, 'references' => 1, 'out_block' => 4];
    uu_check($t, '(v4) table: {a, b} against the setting {b, a} is armed; {a} against {a, b} is filled',
        uu_try_case(fn (): bool => uu_block_table_view($table2, ['2001:db8:a::53', '2001:db8:b::53'],
            ['2001:db8:b::53', '2001:db8:a::53']) === ['armed' => true, 'fill' => false, 'blocked' => 4]
            && uu_block_table_view($table2, ['2001:db8:a::53'], ['2001:db8:a::53', '2001:db8:b::53'])
            === ['armed' => false, 'fill' => true, 'blocked' => 4]));
    uu_check($t, '(v4) table: an unreferenced table never fills, whatever it holds; a listing in another spelling is '
        . 'the same set',
        uu_try_case(fn (): bool => uu_block_table_view(['references' => 0] + $table2, [], ['2001:db8:a::53'])['fill']
            === false
            && uu_block_table_view(['references' => 0] + $table2, ['192.0.2.1'], ['2001:db8:a::53'])['fill'] === false
            && uu_block_table_view($table2, ['2001:DB8:A:0::53', '2001:db8:b::53'],
                ['2001:db8:b::53', '2001:db8:a::53'])['armed']));
    uu_check($t, '(v4) table: an orphan in its hold is no setting address: a table still holding it alone is filled, '
        . 'one holding the setting is armed beside it, and one holding both is filled to leave it',
        uu_try_case(fn (): bool => uu_block_table_view($table2, ['192.0.2.1'], ['192.0.2.9'])
            === ['armed' => false, 'fill' => true, 'blocked' => 4]
            && uu_block_table_view($table2, ['192.0.2.9'], ['192.0.2.9'])['armed']
            && uu_block_table_view($table2, ['192.0.2.1', '192.0.2.9'], ['192.0.2.9'])
            === ['armed' => false, 'fill' => true, 'blocked' => 4]));
    uu_check($t, '(v4) table: an empty table with no setting address is never armed',
        uu_try_case(fn (): bool => uu_block_table_view(['addresses' => 0] + $table2, [], [])
            === ['armed' => false, 'fill' => false, 'blocked' => 4]));
    /* the fill through a recording runner: each command line and each line logged */
    $fill = function (array $addresses, int $rc): array {
        $calls = [];
        $logged = [];
        uu_block_table_fill($addresses, function (string $cmd) use (&$calls, $rc): array {
            $calls[] = $cmd;
            return ['rc' => $rc, 'out' => ''];
        }, function (string $msg, int $prio) use (&$logged): void {
            $logged[] = [$prio, $msg];
        });
        return ['calls' => $calls, 'logged' => $logged];
    };
    uu_check($t, '(v6) fill, one address: 1.3_2\'s command, and its line or its failure line, byte for byte',
        uu_try_case(fn (): bool => $fill(['10.2.0.1'], 0) === [
                'calls' => ["/sbin/pfctl -t '__unboundupstream_block' -T replace '10.2.0.1' 2>/dev/null"],
                'logged' => [[LOG_NOTICE, 'rules: the counting table holds 10.2.0.1 again']]]
            && $fill(['10.2.0.1'], 1)['logged'] === [[LOG_WARNING, 'rules: the counting table could not be filled '
                . 'with 10.2.0.1 (pfctl exit 1): blocked packets are not counted until it is']]));
    uu_check($t, '(v6) fill, two addresses: one replace with both, the line naming both; nothing for none or for a '
        . 'list with something that is no address',
        uu_try_case(fn (): bool => $fill(['2001:db8:a::53', '2001:db8:b::53'], 0) === [
                'calls' => ["/sbin/pfctl -t '__unboundupstream_block' -T replace '2001:db8:a::53' '2001:db8:b::53' "
                    . '2>/dev/null'],
                'logged' => [[LOG_NOTICE, 'rules: the counting table holds 2001:db8:a::53 2001:db8:b::53 again']]]
            && $fill([], 0) === ['calls' => [], 'logged' => []]
            && $fill(['192.0.2.9', '192.0.2.0/24'], 0) === ['calls' => [], 'logged' => []]));

    /* verdict */
    uu_check($t, 'verdict: the full set is loaded', $verdict($vsr) === ['loaded' => true, 'problems' => []]);
    uu_check($t, 'verdict: other rules in the listing change nothing',
        $verdict("block drop in log inet all label \"02f4bab031b57d1e30553ce08e0ec131\"\n" . $vsr
            . "\npass out on wan inet from (wan:network) to any keep state label \"1f2e3d4c5b6a79880918273645546372\"\n")
        === ['loaded' => true, 'problems' => []]);
    $v = $verdict($without(uu_label_pass('opt2', '10.2.0.1')));
    uu_check($t, 'verdict: a member with no pass names it',
        !$v['loaded'] && $v['problems'] === ['no pass rule for wg-b (opt2)']);
    $v = $verdict($without('proto udp from (wg1)'));
    uu_check($t, 'verdict: one protocol missing', !$v['loaded'] && $v['problems'] === ['wg-a: no udp pass']);
    $v = $verdict($edit('pass out quick on wg1 inet proto tcp', 'pass out on wg1 inet proto tcp'));
    uu_check($t, 'verdict: a pass without quick', !$v['loaded'] && $v['problems'] === ['wg-a pass: missing quick']);
    $v = $verdict($edit('pass out quick on wg1 inet proto tcp', 'pass in quick on wg1 inet proto tcp'));
    uu_check($t, 'verdict: an in pass', !$v['loaded'] && $v['problems'] === ['wg-a pass: missing out']);
    $v = $verdict($edit('pass out quick on wg1 inet proto tcp', 'pass out quick on wg9 inet proto tcp'));
    uu_check($t, 'verdict: a pass on another device', !$v['loaded'] && $v['problems'] === ['wg-a pass: not on wg1']);
    $v = $verdict($edit('from (wg1) to 10.2.0.1 port = domain flags', 'from (wg1) to 10.2.0.1 port = 8053 flags'));
    uu_check($t, 'verdict: a pass on another port', !$v['loaded'] && $v['problems'] === ['wg-a pass: wrong port']);
    $v = $verdict($edit('port = domain flags', 'port = 53 flags'));
    uu_check($t, 'verdict: port 53 as a number is fine', $v['loaded']);
    $v = $verdict($edit('block drop out log quick inet from any to 10.2.0.1', 'block drop out log inet from any to 10.2.0.1'));
    uu_check($t, 'verdict: a block without quick',
        !$v['loaded'] && $v['problems'] === ['backstop block: missing quick']);
    $v = $verdict($without(uu_label_backstop()));
    uu_check($t, 'verdict: the backstop missing',
        !$v['loaded'] && $v['problems'] === ['backstop block missing']);
    $v = $verdict($without(uu_label_block()));
    uu_check($t, 'verdict: the counting block missing', !$v['loaded'] && $v['problems'] === ['counting block missing']);
    $v = $verdict($edit('to <' . UU_BLOCK_TABLE . '>', 'to 10.2.0.1'));
    uu_check($t, 'verdict: the counting block must target its table',
        !$v['loaded'] && $v['problems'] === ['counting block: wrong target']);
    $v = $verdict($edit('to <' . UU_BLOCK_TABLE . '>', 'to <' . UU_BLOCK_TABLE . '2>'));
    uu_check($t, 'verdict: a table that only starts with the counting table\'s name is another',
        !$v['loaded'] && $v['problems'] === ['counting block: wrong target']);
    /* boundaries: a device, an address or a label that only starts with the expected one is another */
    $v = $verdict($edit('pass out quick on wg1 inet proto tcp', 'pass out quick on wg1.65 inet proto tcp'));
    uu_check($t, 'verdict: on wg1.65 is not on wg1', !$v['loaded'] && $v['problems'] === ['wg-a pass: not on wg1']);
    $v = $verdict($edit('pass out quick on wg1 inet proto tcp', 'pass out quick on wg10 inet proto tcp'));
    uu_check($t, 'verdict: on wg10 is not on wg1', !$v['loaded'] && $v['problems'] === ['wg-a pass: not on wg1']);
    $v = $verdict($edit('from (wg1) to 10.2.0.1 port = domain flags', 'from (wg1) to 10.2.0.10 port = domain flags'));
    uu_check($t, 'verdict: to 10.2.0.10 is not the resolver',
        !$v['loaded'] && $v['problems'] === ['wg-a pass: wrong address']);
    uu_check($t, '(t5) show: a table address is listed canonical, whatever case or zeros pfctl printed',
        uu_try_case(fn (): bool => uu_pf_show_addresses("   2001:DB8:0:0::53\n   10.2.0.1\n") === ['2001:db8::53', '10.2.0.1']));
    /* an IPv6 resolver: the same listing with its address, and the boundary after the last group */
    $vsr6 = str_replace(['inet ', '10.2.0.1', uu_label_pass('opt1', '10.2.0.1'), uu_label_pass('opt2', '10.2.0.1')],
        ['inet6 ', '2001:db8::2:1', uu_label_pass('opt1', '2001:db8::2:1'), uu_label_pass('opt2', '2001:db8::2:1')],
        $vsr);
    $members6 = $resolving($members, '2001:db8::2:1');
    $verdict6 = fn (string $text): array => uu_rules_verdict($text, $members6, ['2001:db8::2:1']);
    uu_check($t, '(t5) verdict: an IPv6 resolver\'s full set is loaded',
        uu_try_case(fn (): bool => $vsr6 !== $vsr && $verdict6($vsr6) === ['loaded' => true, 'problems' => []]));
    uu_check($t, '(t5) verdict: to 2001:db8::2:10 is not the resolver 2001:db8::2:1, in a pass and in the backstop',
        uu_try_case(function () use ($verdict6, $vsr6): bool {
            $pass = $verdict6(str_replace('from (wg1) to 2001:db8::2:1 port', 'from (wg1) to 2001:db8::2:10 port', $vsr6));
            $block = $verdict6(str_replace('inet6 from any to 2001:db8::2:1 label', 'inet6 from any to 2001:db8::2:10 label',
                $vsr6));
            return $pass['problems'] === ['wg-a pass: wrong address']
                && $block['problems'] === ['backstop block: wrong target'];
        }));
    uu_check($t, '(t5) verdict: 2001:db8::2:1:5 and 2001:db8::2:1 followed by a colon are not the resolver either',
        uu_try_case(fn (): bool => $verdict6(str_replace('inet6 from any to 2001:db8::2:1 label',
            'inet6 from any to 2001:db8::2:1:5 label', $vsr6))['problems'] === ['backstop block: wrong target']));
    uu_check($t, '(t5) verdict: the pass to 2001:db8::2:1:5 or 2001:db8::2:1/64, and the backstop to the latter, are '
        . 'not the resolver',
        uu_try_case(function () use ($verdict6, $vsr6): bool {
            $colon = $verdict6(str_replace('from (wg1) to 2001:db8::2:1 port', 'from (wg1) to 2001:db8::2:1:5 port', $vsr6));
            $slash = $verdict6(str_replace('from (wg1) to 2001:db8::2:1 port', 'from (wg1) to 2001:db8::2:1/64 port',
                $vsr6));
            $block = $verdict6(str_replace('inet6 from any to 2001:db8::2:1 label', 'inet6 from any to 2001:db8::2:1/64 label',
                $vsr6));
            return $colon['problems'] === ['wg-a pass: wrong address'] && $slash['problems'] === ['wg-a pass: wrong address']
                && $block['problems'] === ['backstop block: wrong target'];
        }));
    uu_check($t, '(t5) verdict: a resolver in a non-canonical spelling reads the canonical listing, pass and backstop',
        uu_try_case(fn (): bool
            => uu_rules_verdict($vsr6, $resolving($members, '2001:DB8:0::2:1'), ['2001:DB8:0::2:1'])
            === ['loaded' => true, 'problems' => []]));
    uu_check($t, '(t5) verdict: to 10.2.0.10 is still not the resolver 10.2.0.1 in the backstop',
        uu_try_case(fn (): bool => $verdict(str_replace('inet from any to 10.2.0.1 label', 'inet from any to 10.2.0.10 label',
            $vsr))['problems'] === ['backstop block: wrong target']));
    $v = $verdict($edit('label "' . uu_label_pass('opt1', '10.2.0.1') . '"',
        'label "' . uu_label_pass('opt1', '10.2.0.1') . '0"'));
    uu_check($t, 'verdict: a label that only starts with the member\'s is not its pass',
        !$v['loaded'] && $v['problems'] === ['no pass rule for wg-a (opt1)']);
    $v = uu_rules_verdict($vsr, [['if' => ''] + $members[0], $members[1]], [$resolver]);
    uu_check($t, 'verdict: a member without a device is reported, not matched to any device',
        !$v['loaded'] && $v['problems'] === ['wg-a pass: no device']);
    /* the footprint's rules: the verdict reads neither, so the old address's rules
     * beside the setting's leave the setting's verdict as it is; a footprint block under the backstop's label would
     * not, and a footprint pass under the member's pass label would not either */
    $fpBlock = fn (string $label): string => $vsr
        . "block drop out log quick inet from any to 192.0.2.1 label \"{$label}\"\n";
    uu_check($t, '(p2) a footprint block beside the setting\'s rules reads loaded, with no problems',
        uu_try_case(fn (): bool
            => $verdict($fpBlock(uu_label_footprint())) === ['loaded' => true, 'problems' => []]));
    uu_check($t, '(p2) the same block under the backstop\'s label reads "backstop block: wrong target"',
        uu_try_case(fn (): bool => $verdict($fpBlock(uu_label_backstop()))
            === ['loaded' => false, 'problems' => ['backstop block: wrong target']]));
    $fpPass = fn (string $label): string => $vsr
        . "pass out quick on wg1 inet proto tcp from (wg1) to 192.0.2.1 port = domain flags any keep state (if-bound) "
        . "label \"{$label}\"\n"
        . "pass out quick on wg1 inet proto udp from (wg1) to 192.0.2.1 port = domain keep state (if-bound) label "
        . "\"{$label}\"\n";
    uu_check($t, '(p3) a footprint pass to the old address on a member\'s device reads loaded under its own label',
        uu_try_case(fn (): bool
            => $verdict($fpPass(uu_label_footprint_pass('opt1', '192.0.2.1')))
                === ['loaded' => true, 'problems' => []]));
    uu_check($t, '(p3) the same pass under the member\'s pass label reads "wg-a pass: wrong address" (why it gets '
        . 'its own)',
        uu_try_case(fn (): bool => $verdict($fpPass(uu_label_pass('opt1', '10.2.0.1')))
            === ['loaded' => false, 'problems' => ['wg-a pass: wrong address']]));
    uu_check($t, 'fixture: every edit applies to the capture' . ($missed === [] ? '' : ': ' . implode(', ', $missed)),
        $missed === []);
    uu_check($t, 'verdict: nothing listed is every rule missing',
        $verdict('')['problems'] === ['no pass rule for wg-a (opt1)', 'no pass rule for wg-b (opt2)',
            'counting block missing', 'backstop block missing']);

    /* inputs */
    $in = uu_rules_inputs($members, $resolver);
    $moved = $members;
    $moved[1]['if'] = 'wg7';
    uu_check($t, 'inputs: order-independent over the members',
        uu_rules_inputs(array_reverse($members), $resolver) === $in);
    uu_check($t, 'inputs: change with the resolver, or a member\'s device or interface, or the members',
        uu_rules_inputs($resolving($members, '10.2.0.9'), '10.2.0.9') !== $in
        && uu_rules_inputs($moved, $resolver) !== $in
        && uu_rules_inputs([['interface' => 'opt9'] + $members[0], $members[1]], $resolver) !== $in
        && uu_rules_inputs([$members[0]], $resolver) !== $in);

    /* check */
    $good = ['loaded' => true, 'problems' => []];
    $boom = function (): string {
        throw new RuntimeException('listed');
    };
    $reads = function (array $values): callable {
        return function () use (&$values): ?string {
            return array_shift($values);
        };
    };
    $record = ['checksum' => '0xaa', 'inputs' => $in, 'at' => 500, 'loaded' => true, 'problems' => []];
    $r = uu_rules_check($record, $in, $reads(['0xaa']), $boom, fn (string $s): array => $good, 900, true);
    uu_check($t, 'check: a live recorded checksum with the same inputs is used without listing',
        $r === ['state' => 'loaded', 'problems' => [], 'verified_at' => 500, 'record' => null]);
    $bad = ['checksum' => '0xaa', 'inputs' => $in, 'at' => 500, 'loaded' => false,
            'problems' => ['backstop block missing']];
    $r = uu_rules_check($bad, $in, $reads(['0xaa']), $boom, fn (string $s): array => $good, 900, false);
    uu_check($t, 'check: a status call shows a recorded fault (missing, its problems) without listing',
        $r === ['state' => 'missing', 'problems' => ['backstop block missing'], 'verified_at' => 500, 'record' => null]);
    $lists = 0;
    $r = uu_rules_check($bad, $in, $reads(['0xaa', '0xaa']), function () use (&$lists): string {
        $lists++;
        return 'whole';
    }, fn (string $s): array => $s === 'whole' ? $good : ['loaded' => false, 'problems' => ['x']], 900, true);
    uu_check($t, 'check: an evaluation never reuses a recorded fault: it lists again and records the new verdict',
        $lists === 1 && $r === ['state' => 'loaded', 'problems' => [], 'verified_at' => 900,
            'record' => ['checksum' => '0xaa', 'inputs' => $in, 'at' => 900, 'loaded' => true, 'problems' => []]]);
    $other = uu_rules_inputs($resolving($members, '10.2.0.9'), '10.2.0.9');
    $lists = 0;
    $r = uu_rules_check($record, $other, $reads(['0xaa', '0xaa']), function () use (&$lists): string {
        $lists++;
        return 'listing';
    }, fn (string $s): array => ['loaded' => false, 'problems' => ['wg-a pass: wrong address']], 900, true);
    uu_check($t, 'check: a recorded checksum with other inputs lists',
        $lists === 1 && $r['state'] === 'missing' && $r['problems'] === ['wg-a pass: wrong address']
        && $r['record'] === ['checksum' => '0xaa', 'inputs' => $other, 'at' => 900, 'loaded' => false,
                             'problems' => ['wg-a pass: wrong address']]);
    $r = uu_rules_check($record, $other, $reads(['0xaa']), $boom, fn (string $s): array => $good, 900, false);
    uu_check($t, 'check: other inputs with no listing allowed read verifying',
        $r === ['state' => 'verifying', 'problems' => [], 'verified_at' => null, 'record' => null]);
    $lists = 0;
    $r = uu_rules_check($record, $in, $reads(['0xbb', '0xbb']), function () use (&$lists): string {
        $lists++;
        return 'listing';
    }, fn (string $s): array => $s === 'listing' ? $good : ['loaded' => false, 'problems' => ['x']], 900, true);
    uu_check($t, 'check: a changed checksum lists once and records',
        $lists === 1 && $r['state'] === 'loaded' && $r['verified_at'] === 900
        && $r['record'] === ['checksum' => '0xbb', 'inputs' => $in, 'at' => 900, 'loaded' => true, 'problems' => []]);
    $r = uu_rules_check(null, $in, $reads(['0xbb', '0xbb']), fn (): string => 'l',
        fn (string $s): array => ['loaded' => false, 'problems' => ['counting block missing']], 900, true);
    uu_check($t, 'check: a faulty listing records the fault',
        $r['state'] === 'missing' && $r['problems'] === ['counting block missing']
        && is_array($r['record']) && $r['record']['loaded'] === false);
    /* a listing whose checksum reads disagree spans two rulesets and may be cut short: list again, never judge it */
    $listings = function (array $texts, int &$lists): callable {
        return function () use (&$texts, &$lists): string {
            $lists++;
            return array_shift($texts) ?? '';
        };
    };
    $judge = fn (string $s): array => $s === 'whole' ? $good
        : ['loaded' => false, 'problems' => ['backstop block missing']];
    $lists = 0;
    $r = uu_rules_check($record, $in, $reads(['0xbb', '0xcc', '0xcc', '0xcc']), $listings(['cut', 'whole'], $lists),
        $judge, 900, true);
    uu_check($t, 'check: a reload during the listing lists again and records the second',
        $lists === 2 && $r === ['state' => 'loaded', 'problems' => [], 'verified_at' => 900,
            'record' => ['checksum' => '0xcc', 'inputs' => $in, 'at' => 900, 'loaded' => true, 'problems' => []]]);
    $lists = 0;
    $r = uu_rules_check($record, $in, $reads(['0xbb', '0xcc', '0xdd', '0xee']), $listings(['cut', 'cut'], $lists),
        $judge, 900, true);
    uu_check($t, 'check: two straddled listings keep the last verdict and no record',
        $lists === 2 && $r === ['state' => 'loaded', 'problems' => [], 'verified_at' => 500, 'record' => null]);
    $lists = 0;
    $r = uu_rules_check(null, $in, $reads(['0xbb', '0xcc', '0xdd', '0xee']), $listings(['whole', 'whole'], $lists),
        $judge, 900, true);
    uu_check($t, 'check: two straddled listings with nothing recorded read not loaded, and no record',
        $lists === 2 && $r === ['state' => 'missing', 'problems' => ['the ruleset changed during every listing'],
            'verified_at' => null, 'record' => null]);
    $lists = 0;
    $r = uu_rules_check($record, $other, $reads(['0xbb', '0xcc', '0xdd', '0xee']),
        $listings(['whole', 'whole'], $lists), $judge, 900, true);
    uu_check($t, 'check: two straddled listings never keep a verdict made for other inputs',
        $lists === 2 && $r === ['state' => 'missing', 'problems' => ['the ruleset changed during every listing'],
            'verified_at' => null, 'record' => null]);
    $lists = 0;
    $r = uu_rules_check(null, $in, $reads(['0xbb', null, null]), $listings(['whole'], $lists),
        fn (string $s): array => $good, 900, true);
    uu_check($t, 'check: an unreadable checksum after the listing is a disagreement: no record, no listing while '
        . 'the checksum stays unreadable, and the problem names the unreadable status',
        $lists === 1 && $r === ['state' => 'missing', 'problems' => ['pf status unreadable'],
            'verified_at' => null, 'record' => null]);
    /*
     * a listing pfctl cut short (a `pfctl:` line on its stderr, exit 0) is unusable, null here: retried like a
     * straddle, whatever the checksums say; a TypeError from a build that judges it anyway is a FAIL, not a crash
     */
    $try = function (callable $case): bool {
        try {
            return (bool)$case();
        } catch (\Throwable) {
            return false;
        }
    };
    $cut = function (array $texts, int &$lists): callable {
        return function () use (&$texts, &$lists): ?string {
            $lists++;
            return array_shift($texts);
        };
    };
    $judgeCut = fn (?string $s): array => $s === 'whole' ? $good
        : ['loaded' => false, 'problems' => ['backstop block missing']];
    uu_check($t, 'check: a listing cut short is retried and the second, whole listing is recorded',
        $try(function () use ($record, $in, $reads, $cut, $judgeCut): bool {
            $lists = 0;
            $r = uu_rules_check($record, $in, $reads(['0xbb', '0xbb', '0xbb', '0xbb']), $cut([null, 'whole'], $lists),
                $judgeCut, 900, true);
            return $lists === 2 && $r === ['state' => 'loaded', 'problems' => [], 'verified_at' => 900,
                'record' => ['checksum' => '0xbb', 'inputs' => $in, 'at' => 900, 'loaded' => true, 'problems' => []]];
        }));
    uu_check($t, 'check: two listings cut short end as two straddles: a record of these inputs is kept, none reads '
        . 'not loaded, and nothing is recorded',
        $try(function () use ($record, $in, $reads, $cut, $judgeCut): bool {
            $lists = 0;
            $kept = uu_rules_check($record, $in, $reads(['0xbb', '0xbb', '0xbb', '0xbb']), $cut([null, null], $lists),
                $judgeCut, 900, true);
            $lists2 = 0;
            $none = uu_rules_check(null, $in, $reads(['0xbb', '0xbb', '0xbb', '0xbb']), $cut([null, null], $lists2),
                $judgeCut, 900, true);
            return $lists === 2 && $lists2 === 2
                && $kept === ['state' => 'loaded', 'problems' => [], 'verified_at' => 500, 'record' => null]
                && $none === ['state' => 'missing', 'problems' => ['the ruleset changed during every listing'],
                    'verified_at' => null, 'record' => null];
        }));
    uu_check($t, 'listing: a pfctl: line on stderr makes it unusable; pf\'s ALTQ notices alone do not',
        $try(fn (): bool => uu_pf_listing_usable("No ALTQ support in kernel\nALTQ related functions disabled\n")
            && uu_pf_listing_usable('')
            && !uu_pf_listing_usable("No ALTQ support in kernel\npfctl: DIOCGETRULE: Device busy\n")
            && !uu_pf_listing_usable('pfctl: DIOCGETRULE: Device busy')));
    $r = uu_rules_check($record, $in, $reads(['0xbb']), $boom, fn (string $s): array => $good, 900, false);
    uu_check($t, 'check: no listing allowed reads verifying',
        $r === ['state' => 'verifying', 'problems' => [], 'verified_at' => null, 'record' => null]);
    $r = uu_rules_check($record, $in, $reads([null]), $boom, fn (string $s): array => $good, 900, true);
    uu_check($t, 'check: an unreadable checksum is missing with problem "pf status unreadable"',
        $r === ['state' => 'missing', 'problems' => ['pf status unreadable'], 'verified_at' => null, 'record' => null]);

    /* record file */
    $dir = sys_get_temp_dir() . '/uu_pfobserve_' . getmypid();
    $path = $dir . '/sub/rules.json';
    uu_rules_record_save($path, $record);
    uu_check($t, 'record: saved and loaded back, no temp file left',
        uu_rules_record_load($path) === $record && !file_exists($path . '.tmp'));
    uu_check($t, 'record: a missing file is null', uu_rules_record_load($dir . '/none.json') === null);
    file_put_contents($path, '{"checksum":"0xaa","at":"x"');
    uu_check($t, 'record: a truncated file is null', uu_rules_record_load($path) === null);
    file_put_contents($path, json_encode($record + ['x' => 1]));
    uu_check($t, 'record: a wrong shape is null', uu_rules_record_load($path) === null);
    file_put_contents($path, json_encode(['checksum' => '0xaa', 'at' => 5, 'loaded' => true, 'problems' => []]));
    uu_check($t, 'record: a record without inputs (an earlier build\'s) is null, so it lists once',
        uu_rules_record_load($path) === null);
    file_put_contents($path, json_encode(['inputs' => 7] + $record));
    uu_check($t, 'record: non-string inputs are null', uu_rules_record_load($path) === null);
    file_put_contents($path, json_encode(['problems' => [3]] + $record));
    uu_check($t, 'record: a non-string problem is null', uu_rules_record_load($path) === null);
    unlink($path);
    rmdir($dir . '/sub');
    rmdir($dir);
    /* the record is read as a regular file of at most UU_FILE_MAX_BYTES only */
    $valid = (string)json_encode($record);
    foreach (['link' => '(p1) record: a symbolic link to a valid record',
              'dir' => '(p1) record: a directory at the path', 'fifo' => 'record: a named pipe at the path',
              'large' => '(p1) record: a valid record padded to 1 MiB + 1 byte'] as $kind => $what) {
        uu_check($t, "$what is null",
            uu_scratch_case(function (string $dir) use ($kind, $valid): bool {
                uu_scratch_place($kind, $dir . '/rules.json', $valid);
                return $kind === 'fifo' ? uu_test_fifo_record_null($dir . '/rules.json')
                    : uu_rules_record_load($dir . '/rules.json') === null;
            }));
    }
    uu_check($t, 'record: a valid record padded to exactly 1 MiB is read',
        uu_scratch_case(function (string $dir) use ($valid, $record): bool {
            file_put_contents($dir . '/rules.json', str_pad($valid, UU_SCRATCH_MIB, ' '));
            return uu_rules_record_load($dir . '/rules.json') === $record;
        }));

    /* block table view */
    $armedTable = ['addresses' => 1, 'references' => 1, 'out_block' => 37];
    uu_check($t, 'table: empty is not armed and is filled',
        uu_try_case(fn (): bool => uu_block_table_view(['addresses' => 0, 'references' => 1, 'out_block' => 0], [],
            [$resolver]) === ['armed' => false, 'fill' => true, 'blocked' => 0]));
    uu_check($t, 'table: armed with the resolver',
        uu_try_case(fn (): bool => uu_block_table_view($armedTable, [$resolver], [$resolver])
            === ['armed' => true, 'fill' => false, 'blocked' => 37]));
    uu_check($t, 'table: holding another address is not armed and is filled',
        uu_try_case(fn (): bool => uu_block_table_view($armedTable, ['10.9.9.9'], [$resolver])
            === ['armed' => false, 'fill' => true, 'blocked' => 37]));
    uu_check($t, 'table: no fill for an unreferenced table',
        uu_try_case(fn (): bool => uu_block_table_view(['addresses' => 0, 'references' => 0, 'out_block' => 0], [],
            [$resolver]) === ['armed' => false, 'fill' => false, 'blocked' => 0]));
    uu_check($t, 'table: absent is not armed, no fill',
        uu_try_case(fn (): bool => uu_block_table_view(null, [], [$resolver])
            === ['armed' => false, 'fill' => false, 'blocked' => null]));
    uu_check($t, 'table: no fill without a resolver',
        uu_try_case(fn (): bool => uu_block_table_view(['addresses' => 0, 'references' => 1, 'out_block' => 0], [],
            [])['fill'] === false));

    return uu_tally_report('pfobserve', $t);
});
