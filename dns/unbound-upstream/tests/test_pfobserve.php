<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Observing pf (spec section 3.6c): the ruleset checksum, a table's counters, the rule verdict read from the
 * kernel's own text by keyword, and the verification kept once per checksum, in a record read as a regular file
 * only (convention C3).
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/pfobserve.php';
require_once __DIR__ . '/scratch.php';

function uu_pfobserve_fixture(string $name): string
{
    $text = file_get_contents(__DIR__ . '/fixtures/' . $name);
    return $text === false ? '' : $text;
}

uu_register_suite('pfobserve', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $members = [
        ['name' => 'wg-a', 'interface' => 'opt1', 'if' => 'wg1'],
        ['name' => 'wg-b', 'interface' => 'opt2', 'if' => 'wg2'],
    ];
    $resolver = '10.2.0.1';
    /* the plugin's own lines of a test VM listing (members on opt1/wg1 and opt2/wg2), with their counter lines */
    $vsr = uu_pfobserve_fixture('pfctl_vsr_12.txt');
    $verdict = fn (string $text): array => uu_rules_verdict($text, $resolver, $members);
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

    /* verdict */
    uu_check($t, 'verdict: the full set is loaded', $verdict($vsr) === ['loaded' => true, 'problems' => []]);
    uu_check($t, 'verdict: other rules in the listing change nothing',
        $verdict("block drop in log inet all label \"02f4bab031b57d1e30553ce08e0ec131\"\n" . $vsr
            . "\npass out on wan inet from (wan:network) to any keep state label \"1f2e3d4c5b6a79880918273645546372\"\n")
        === ['loaded' => true, 'problems' => []]);
    $v = $verdict($without(uu_label_pass('opt2')));
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
    $v = $verdict($edit('label "' . uu_label_pass('opt1') . '"', 'label "' . uu_label_pass('opt1') . '0"'));
    uu_check($t, 'verdict: a label that only starts with the member\'s is not its pass',
        !$v['loaded'] && $v['problems'] === ['no pass rule for wg-a (opt1)']);
    $v = uu_rules_verdict($vsr, $resolver, [['if' => ''] + $members[0], $members[1]]);
    uu_check($t, 'verdict: a member without a device is reported, not matched to any device',
        !$v['loaded'] && $v['problems'] === ['wg-a pass: no device']);
    /* the footprint's rules (spec -04 section 3.2, ruling R2): the verdict reads neither, so the old address's rules
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
        . "pass out quick on wg1 inet proto tcp from (wg1) to 192.0.2.1 port = domain flags S/SA keep state label "
        . "\"{$label}\"\n"
        . "pass out quick on wg1 inet proto udp from (wg1) to 192.0.2.1 port = domain keep state label \"{$label}\"\n";
    uu_check($t, '(p3) a footprint pass to the old address on a member\'s device reads loaded under its own label',
        uu_try_case(fn (): bool
            => $verdict($fpPass(uu_label_footprint_pass('opt1'))) === ['loaded' => true, 'problems' => []]));
    uu_check($t, '(p3) the same pass under the member\'s pass label reads "wg-a pass: wrong address" (why R2 gives it '
        . 'its own)',
        uu_try_case(fn (): bool => $verdict($fpPass(uu_label_pass('opt1')))
            === ['loaded' => false, 'problems' => ['wg-a pass: wrong address']]));
    uu_check($t, 'fixture: every edit applies to the capture' . ($missed === [] ? '' : ': ' . implode(', ', $missed)),
        $missed === []);
    uu_check($t, 'verdict: nothing listed is every rule missing',
        $verdict('')['problems'] === ['no pass rule for wg-a (opt1)', 'no pass rule for wg-b (opt2)',
            'counting block missing', 'backstop block missing']);

    /* inputs */
    $in = uu_rules_inputs($resolver, $members);
    $moved = $members;
    $moved[1]['if'] = 'wg7';
    uu_check($t, 'inputs: order-independent over the members',
        uu_rules_inputs($resolver, array_reverse($members)) === $in);
    uu_check($t, 'inputs: change with the resolver, or a member\'s device or interface, or the members',
        uu_rules_inputs('10.2.0.9', $members) !== $in && uu_rules_inputs($resolver, $moved) !== $in
        && uu_rules_inputs($resolver, [['interface' => 'opt9'] + $members[0], $members[1]]) !== $in
        && uu_rules_inputs($resolver, [$members[0]]) !== $in);

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
    $other = uu_rules_inputs('10.2.0.9', $members);
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
    /* convention C3: the record is read as a regular file of at most UU_FILE_MAX_BYTES only */
    $valid = (string)json_encode($record);
    foreach (['link' => '(p1) record: a symbolic link to a valid record',
              'dir' => '(p1) record: a directory at the path', 'fifo' => 'record: a named pipe at the path',
              'large' => '(p1) record: a valid record padded to 1 MiB + 1 byte'] as $kind => $what) {
        uu_check($t, "$what is null",
            uu_scratch_case(function (string $dir) use ($kind, $valid): bool {
                uu_scratch_place($kind, $dir . '/rules.json', $valid);
                return uu_rules_record_load($dir . '/rules.json') === null;
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
        uu_block_table_view(['addresses' => 0, 'references' => 1, 'out_block' => 0], [], $resolver, null)
        === ['armed' => false, 'fill' => true, 'blocked' => 0]);
    uu_check($t, 'table: armed with the resolver',
        uu_block_table_view($armedTable, [$resolver], $resolver, $resolver)
        === ['armed' => true, 'fill' => false, 'blocked' => 37]);
    uu_check($t, 'table: holding another address is not armed and is filled',
        uu_block_table_view($armedTable, ['10.9.9.9'], $resolver, null)
        === ['armed' => false, 'fill' => true, 'blocked' => 37]);
    uu_check($t, 'table: no fill while the recorded resolver differs',
        uu_block_table_view(['addresses' => 0, 'references' => 1, 'out_block' => 0], [], $resolver, '10.9.9.9')
        === ['armed' => false, 'fill' => false, 'blocked' => 0]);
    uu_check($t, 'table: no fill for an unreferenced table',
        uu_block_table_view(['addresses' => 0, 'references' => 0, 'out_block' => 0], [], $resolver, null)
        === ['armed' => false, 'fill' => false, 'blocked' => 0]);
    uu_check($t, 'table: absent is not armed, no fill',
        uu_block_table_view(null, [], $resolver, null) === ['armed' => false, 'fill' => false, 'blocked' => null]);
    uu_check($t, 'table: no fill without a resolver',
        uu_block_table_view(['addresses' => 0, 'references' => 1, 'out_block' => 0], [], '', null)['fill'] === false);

    return uu_tally_report('pfobserve', $t);
});
