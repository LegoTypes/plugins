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
 * Record = array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>}
 *   inputs is uu_rules_inputs() of what the verdict was made for; a record holds only for its checksum AND inputs
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
 * (the counting block and the backstop), with the shape of each checked by keyword on its own line. A device, an
 * address or a target is bounded like a word that may not continue with a word character or a dot, so wg1 is
 * not wg10 or wg1.65 and 10.2.0.1 is not 10.2.0.10.
 *
 * @param list<array{name: string, interface: string, if: string}> $members
 * @return array{loaded: bool, problems: list<string>}
 */
function uu_rules_verdict(string $vsrOut, string $resolver, array $members): array
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
                if ($member['if'] === '') {
                    $problems[] = $member['name'] . ' pass: no device';
                } elseif (!uu_rules_has($line, '\bon ' . preg_quote($member['if'], '/') . '(?![\w.])')) {
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
    array_push($problems, ...uu_rules_block_problems(
        uu_rules_lines($vsrOut, uu_label_block()),
        'counting block',
        '<' . UU_BLOCK_TABLE . '>'
    ));
    array_push($problems, ...uu_rules_block_problems(
        uu_rules_lines($vsrOut, uu_label_backstop()),
        'backstop block',
        $resolver
    ));
    $problems = array_values(array_unique($problems));
    return ['loaded' => $problems === [], 'problems' => $problems];
}

/**
 * What a verdict depends on besides the ruleset: the resolver and each ruled member's interface and device.
 * Order-independent over the members. Between a Save and its filter reload the checksum is unchanged while the
 * settings already differ, so a record is reused only for the same inputs.
 *
 * @param list<array{name: string, interface: string, if: string}> $members
 */
function uu_rules_inputs(string $resolver, array $members): string
{
    $pairs = array_map(fn (array $m): array => [$m['interface'], $m['if']], $members);
    sort($pairs);
    return md5(json_encode([$resolver, $pairs], JSON_THROW_ON_ERROR));
}

/**
 * Whether the plugin's rules are loaded, verified once per ruleset checksum and inputs. A record whose checksum is
 * live and whose inputs are these is used, with no listing. Otherwise, when listing is allowed, the checksum is
 * read, the ruleset listed once and the checksum read again; the verdict is used and recorded (under these
 * inputs) only when both reads agree. When they differ a reload ran during the listing, which may have cut it
 * short, so its verdict is never judged: the pair is tried again, up to UU_RULES_LIST_PAIRS pairs. When no pair
 * agrees, a record made for these inputs keeps its verdict (none, or one made for other inputs: not loaded) and
 * nothing is recorded, so the next evaluation lists again. When listing is not allowed (a status call) the
 * answer is 'verifying'. state is 'loaded', 'missing' or 'verifying'; record is the new record to save, or null.
 *
 * @param ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>} $record
 * @param string $inputs uu_rules_inputs() of the verdict's inputs
 * @param callable(): ?string $checksum
 * @param callable(): string $listing
 * @param callable(string): array{loaded: bool, problems: list<string>} $verdictOf
 * @return array{state: string, problems: list<string>, verified_at: ?int,
 *     record: ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>}}
 */
function uu_rules_check(?array $record, string $inputs, callable $checksum, callable $listing, callable $verdictOf,
    int $wall, bool $mayList): array
{
    $live = $checksum();
    if ($live === null) {
        return ['state' => 'missing', 'problems' => ['pf status unreadable'], 'verified_at' => null, 'record' => null];
    }
    if ($record !== null && $record['checksum'] === $live && $record['inputs'] === $inputs) {
        return ['state' => $record['loaded'] ? 'loaded' : 'missing', 'problems' => $record['problems'],
                'verified_at' => $record['at'], 'record' => null];
    }
    if (!$mayList) {
        return ['state' => 'verifying', 'problems' => [], 'verified_at' => null, 'record' => null];
    }
    $unreadable = false;
    for ($pair = 1; $pair <= UU_RULES_LIST_PAIRS; $pair++) {
        $before = $pair === 1 ? $live : $checksum();
        if ($before === null) {
            $unreadable = true;
            continue;
        }
        $verdict = $verdictOf($listing());
        $after = $checksum();
        if ($after !== $before) {
            $unreadable = $unreadable || $after === null;
            continue;
        }
        $new = ['checksum' => $before, 'inputs' => $inputs, 'at' => $wall, 'loaded' => $verdict['loaded'],
                'problems' => $verdict['problems']];
        return ['state' => $verdict['loaded'] ? 'loaded' : 'missing', 'problems' => $verdict['problems'],
                'verified_at' => $wall, 'record' => $new];
    }
    if ($record !== null && $record['inputs'] === $inputs) {
        return ['state' => $record['loaded'] ? 'loaded' : 'missing', 'problems' => $record['problems'],
                'verified_at' => $record['at'], 'record' => null];
    }
    $problem = $unreadable ? 'pf status unreadable' : 'the ruleset changed during every listing';
    return ['state' => 'missing', 'problems' => [$problem], 'verified_at' => null, 'record' => null];
}

/**
 * The saved record, or null when the file is missing, truncated or not exactly the Record shape (a record without
 * inputs, from a build before them, is null too: the next evaluation lists once).
 *
 * @return ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>}
 */
function uu_rules_record_load(string $path): ?array
{
    $text = @file_get_contents($path);
    if ($text === false) {
        return null;
    }
    $doc = json_decode($text, true);
    if (!is_array($doc) || count($doc) !== 5
        || !isset($doc['checksum']) || !is_string($doc['checksum'])
        || !isset($doc['inputs']) || !is_string($doc['inputs'])
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
    return ['checksum' => $doc['checksum'], 'inputs' => $doc['inputs'], 'at' => $doc['at'], 'loaded' => $doc['loaded'],
            'problems' => $problems];
}

/**
 * Write the record to path.tmp and rename it over path, like the state file. The directory is created 0700.
 *
 * @param array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>} $record
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
