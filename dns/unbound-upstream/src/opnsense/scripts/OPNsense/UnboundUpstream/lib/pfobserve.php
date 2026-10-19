<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Observing pf (spec 2026-10-17 section 3.6c): the ruleset checksum, a table's counters, the verdict on the
 * plugin's rules read from the kernel's own listing by keyword, and that verdict kept once per checksum so the
 * 2.5 s ruleset listing is only paid after the ruleset changed. Pure apart from the record file.
 *
 * Record = array{checksum: string, at: int, loaded: bool, problems: list<string>}
 * Verdict = array{loaded: bool, problems: list<string>}
 * RulesCheck = array{state: string, problems: list<string>, verified_at: ?int, record: ?Record}  (uu_rules_check())
 * TableFacts = array{addresses: int, references: int, out_block: int}  (uu_pf_table())
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/render.php';

/** The ruleset checksum `pfctl -si -v` prints ("Checksum: 0x..."), or null when it prints none. */
function uu_pf_checksum(string $siOut): ?string
{
    return preg_match('/^Checksum:\s+(0x[0-9a-f]+)\s*$/mi', $siOut, $m) === 1 ? $m[1] : null;
}

/**
 * One table's facts from `pfctl -vvsTables`: its address count, the rules that reference it and its Out/Block
 * packets. Null when the table is not listed (or its block does not read).
 *
 * @return ?array{addresses: int, references: int, out_block: int}
 */
function uu_pf_table(string $vvsTablesOut, string $name): ?array
{
    $found = false;
    $block = [];
    foreach (preg_split('/\R/', $vvsTablesOut) ?: [] as $line) {
        if ($line !== '' && $line[0] !== "\t" && $line[0] !== ' ') {
            if ($found) {
                break;
            }
            $found = preg_match('/^\S+\s+' . preg_quote($name, '/') . '\s*$/', $line) === 1;
            continue;
        }
        if ($found) {
            $block[] = $line;
        }
    }
    $text = implode("\n", $block);
    if (!$found
        || preg_match('/^\s*Addresses:\s+(\d+)/m', $text, $addresses) !== 1
        || preg_match('/^\s*References:\s+\[\s*Anchors:\s*\d+\s+Rules:\s*(\d+)/m', $text, $references) !== 1
        || preg_match('/^\s*Out\/Block:\s+\[\s*Packets:\s*(\d+)/m', $text, $outBlock) !== 1) {
        return null;
    }
    return ['addresses' => (int)$addresses[1], 'references' => (int)$references[1], 'out_block' => (int)$outBlock[1]];
}

/**
 * The addresses `pfctl -t <table> -T show` lists, one per line.
 *
 * @return list<string>
 */
function uu_pf_show_addresses(string $showOut): array
{
    $addresses = [];
    foreach (preg_split('/\R/', $showOut) ?: [] as $line) {
        if (trim($line) !== '') {
            $addresses[] = trim($line);
        }
    }
    return $addresses;
}

/**
 * The rule lines of a `pfctl -vsr` listing that carry a label (the counter lines under each rule start with blanks).
 *
 * @return list<string>
 */
function uu_rules_lines(string $vsrOut, string $label): array
{
    $lines = [];
    foreach (preg_split('/\R/', $vsrOut) ?: [] as $line) {
        if ($line !== '' && $line[0] !== ' ' && $line[0] !== "\t" && str_contains($line, 'label "' . $label . '"')) {
            $lines[] = $line;
        }
    }
    return $lines;
}

/**
 * Whether a rule line has a keyword; the listing is pf's own text, so only words are looked for, never layout.
 */
function uu_rules_has(string $line, string $pattern): bool
{
    return preg_match('/' . $pattern . '/', $line) === 1;
}

/**
 * The problems of one block rule (counting or backstop), empty when it is as rendered.
 *
 * @param list<string> $lines
 * @return list<string>
 */
function uu_rules_block_problems(array $lines, string $what, string $target): array
{
    if ($lines === []) {
        return [$what . ' missing'];
    }
    $problems = [];
    foreach ($lines as $line) {
        foreach (['block' => 'block', 'out' => 'out', 'log' => 'log', 'quick' => 'quick'] as $word => $label) {
            if (!uu_rules_has($line, '\b' . $word . '\b')) {
                $problems[] = $what . ': missing ' . $label;
            }
        }
        if (!uu_rules_has($line, '\bto ' . preg_quote($target, '/') . '(?![\w.])')) {
            $problems[] = $what . ': wrong target';
        }
    }
    return array_values(array_unique($problems));
}

/**
 * Whether the plugin's rules are in the listing, member by member (tcp and udp pass, by label) and block by block
 * (the counting block only when counting), with the shape of each checked by keyword on its own line.
 *
 * @param list<array{name: string, interface: string, if: string}> $members
 * @return array{loaded: bool, problems: list<string>}
 */
function uu_rules_verdict(string $vsrOut, string $resolver, array $members, bool $counting): array
{
    $problems = [];
    $address = preg_quote($resolver, '/');
    foreach ($members as $member) {
        $lines = uu_rules_lines($vsrOut, uu_label_pass($member['interface']));
        if ($lines === []) {
            $problems[] = 'no pass rule for ' . $member['name'] . ' (' . $member['interface'] . ')';
            continue;
        }
        foreach (['tcp', 'udp'] as $proto) {
            $protoLines = array_values(array_filter(
                $lines,
                fn (string $line): bool => uu_rules_has($line, '\bproto ' . $proto . '\b')
            ));
            if ($protoLines === []) {
                $problems[] = $member['name'] . ': no ' . $proto . ' pass';
            }
            foreach ($protoLines as $line) {
                $checks = [
                    'pass' => '\bpass\b', 'out' => '\bout\b', 'quick' => '\bquick\b',
                ];
                foreach ($checks as $word => $pattern) {
                    if (!uu_rules_has($line, $pattern)) {
                        $problems[] = $member['name'] . ' pass: missing ' . $word;
                    }
                }
                if (!uu_rules_has($line, '\bon ' . preg_quote($member['if'], '/') . '\b')) {
                    $problems[] = $member['name'] . ' pass: not on ' . $member['if'];
                }
                if (!uu_rules_has($line, '\bto ' . $address . '(?![\w.])')) {
                    $problems[] = $member['name'] . ' pass: wrong address';
                }
                if (!uu_rules_has($line, '\bport = (domain|53)\b')) {
                    $problems[] = $member['name'] . ' pass: wrong port';
                }
            }
        }
    }
    if ($counting) {
        array_push($problems, ...uu_rules_block_problems(
            uu_rules_lines($vsrOut, uu_label_block()),
            'counting block',
            '<' . UU_BLOCK_TABLE . '>'
        ));
    }
    array_push($problems, ...uu_rules_block_problems(
        uu_rules_lines($vsrOut, uu_label_backstop()),
        'backstop block',
        $resolver
    ));
    $problems = array_values(array_unique($problems));
    return ['loaded' => $problems === [], 'problems' => $problems];
}

/**
 * Whether the plugin's rules are loaded, verified once per ruleset checksum. A live checksum equal to the record's
 * uses the record, with no listing. Otherwise, when listing is allowed, the checksum is read, the ruleset listed
 * once and the checksum read again; the verdict is recorded only when both reads agree, since a reload in between
 * could have made the listing a mix of two rulesets. When listing is not allowed (a status call) the answer is
 * 'verifying'. state is 'loaded', 'missing' or 'verifying'; record is the new record to save, or null.
 *
 * @param ?array{checksum: string, at: int, loaded: bool, problems: list<string>} $record
 * @param callable(): ?string $checksum
 * @param callable(): string $listing
 * @param callable(string): array{loaded: bool, problems: list<string>} $verdictOf
 * @return array{state: string, problems: list<string>, verified_at: ?int,
 *     record: ?array{checksum: string, at: int, loaded: bool, problems: list<string>}}
 */
function uu_rules_check(?array $record, callable $checksum, callable $listing, callable $verdictOf, int $wall,
    bool $mayList): array
{
    $live = $checksum();
    if ($live === null) {
        return ['state' => 'missing', 'problems' => ['pf status unreadable'], 'verified_at' => null, 'record' => null];
    }
    if ($record !== null && $record['checksum'] === $live) {
        return ['state' => $record['loaded'] ? 'loaded' : 'missing', 'problems' => $record['problems'],
                'verified_at' => $record['at'], 'record' => null];
    }
    if (!$mayList) {
        return ['state' => 'verifying', 'problems' => [], 'verified_at' => null, 'record' => null];
    }
    $verdict = $verdictOf($listing());
    $state = $verdict['loaded'] ? 'loaded' : 'missing';
    if ($checksum() !== $live) {
        return ['state' => $state, 'problems' => $verdict['problems'], 'verified_at' => null, 'record' => null];
    }
    $new = ['checksum' => $live, 'at' => $wall, 'loaded' => $verdict['loaded'], 'problems' => $verdict['problems']];
    return ['state' => $state, 'problems' => $verdict['problems'], 'verified_at' => $wall, 'record' => $new];
}

/**
 * The saved record, or null when the file is missing, truncated or not exactly the Record shape.
 *
 * @return ?array{checksum: string, at: int, loaded: bool, problems: list<string>}
 */
function uu_rules_record_load(string $path): ?array
{
    $text = @file_get_contents($path);
    if ($text === false) {
        return null;
    }
    $doc = json_decode($text, true);
    if (!is_array($doc) || count($doc) !== 4
        || !isset($doc['checksum']) || !is_string($doc['checksum'])
        || !isset($doc['at']) || !is_int($doc['at'])
        || !isset($doc['loaded']) || !is_bool($doc['loaded'])
        || !isset($doc['problems']) || !is_array($doc['problems'])) {
        return null;
    }
    $problems = [];
    foreach ($doc['problems'] as $problem) {
        if (!is_string($problem)) {
            return null;
        }
        $problems[] = $problem;
    }
    return ['checksum' => $doc['checksum'], 'at' => $doc['at'], 'loaded' => $doc['loaded'], 'problems' => $problems];
}

/**
 * Write the record to path.tmp and rename it over path, like the state file. The directory is created 0700.
 *
 * @param array{checksum: string, at: int, loaded: bool, problems: list<string>} $record
 */
function uu_rules_record_save(string $path, array $record): void
{
    $dir = dirname($path);
    if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
        throw new RuntimeException("cannot create $dir");
    }
    $tmp = $path . '.tmp';
    if (file_put_contents($tmp, json_encode($record, JSON_THROW_ON_ERROR)) === false || !rename($tmp, $path)) {
        throw new RuntimeException("cannot write $path");
    }
}

/**
 * The counting block's table as the status reads it. armed: the table holds exactly the resolver. fill: the table
 * is referenced by a rule but is not armed, so the evaluation fills it; never for an unreferenced table, and not
 * while the resolver the state recorded differs from the setting (the old address is undone first). blocked: the
 * table's Out/Block packets, null without the table.
 *
 * @param ?array{addresses: int, references: int, out_block: int} $table
 * @param list<string> $addresses
 * @return array{armed: bool, fill: bool, blocked: ?int}
 */
function uu_block_table_view(?array $table, array $addresses, string $resolver, ?string $recordedResolver): array
{
    if ($table === null) {
        return ['armed' => false, 'fill' => false, 'blocked' => null];
    }
    $armed = $table['addresses'] === 1 && $addresses === [$resolver];
    $fill = $table['references'] >= 1 && !$armed && $resolver !== ''
        && ($recordedResolver === null || $recordedResolver === $resolver);
    return ['armed' => $armed, 'fill' => $fill, 'blocked' => $table['out_block']];
}
