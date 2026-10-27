<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Observing pf: the ruleset checksum, a table's counters, the verdict on the
 * plugin's rules read from the kernel's own listing by keyword, and that verdict kept once per checksum so the
 * 2.5 s ruleset listing is only paid after the ruleset changed; and the counting table's upkeep (its view and its
 * fill). Pure apart from the record file and the fill, which runs and logs through its callables.
 *
 * Record = array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>}
 *   inputs is uu_rules_inputs() of what the verdict was made for; a record holds only for its checksum AND inputs
 * Verdict = array{loaded: bool, problems: list<string>}
 * RulesCheck = array{state: string, problems: list<string>, verified_at: ?int, record: ?Record}  (uu_rules_check())
 * TableFacts = array{addresses: int, references: int, out_block: int}  (uu_pf_table())
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/address.php';
require_once __DIR__ . '/render.php';
require_once __DIR__ . '/state.php';

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
        $address = trim($line);
        if ($address !== '') {
            $addresses[] = uu_ip_canonical($address) ?? $address;
        }
    }
    return $addresses;
}

/**
 * Whether a `pfctl -vsr` listing is whole, from its stderr. Every pf load advances pf's ticket, an identical one
 * too (it keeps the checksum), and pfctl then stops mid-listing with `pfctl: DIOCGETRULE: Device busy` and exit 0,
 * so any line beginning `pfctl:` makes the listing unusable. pf's ALTQ notices, printed on every call, do not.
 */
function uu_pf_listing_usable(string $stderr): bool
{
    foreach (preg_split('/\R/', $stderr) ?: [] as $line) {
        if (str_starts_with(ltrim($line), 'pfctl:')) {
            return false;
        }
    }
    return true;
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
 * Whether a rule line goes to an address or table: "to" and the target, bounded like a word that may not continue with
 * a word character, a dot, a colon or a slash, so 10.2.0.1 is not 10.2.0.10 and 2001:db8::2:1 is not 2001:db8::2:1:5
 * or 2001:db8::2:1/64.
 */
function uu_rules_to(string $line, string $target): bool
{
    return uu_rules_has($line, '\bto ' . preg_quote($target, '/') . '(?![\w.:\/])');
}

/** Whether a rule line is in a family: the word inet or inet6 (inet is not the start of inet6). */
function uu_rules_family(string $line, string $family): bool
{
    return uu_rules_has($line, '\b' . $family . '\b');
}

/**
 * The problems of the lines under one block label (the counting blocks or the backstops), empty when each is as
 * rendered: every line a quick logged out block to one of $targets, in that target's family when it is an address.
 *
 * @param list<string> $lines
 * @param list<string> $targets
 * @return list<string>
 */
function uu_rules_block_problems(array $lines, string $what, array $targets): array
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
        $to = array_values(array_filter($targets, fn (string $target): bool => uu_rules_to($line, $target)));
        $family = $to === [] ? null : uu_ip_family($to[0]);
        if ($to === []) {
            $problems[] = $what . ': wrong target';
        } elseif ($family !== null && !uu_rules_family($line, $family)) {
            $problems[] = $what . ': wrong family';
        }
    }
    return array_values(array_unique($problems));
}

/**
 * Whether the plugin's rules are in the listing, member by member (tcp and udp pass, by the label of the member's
 * interface and resolver) and block by block, with the shape of each checked by keyword on its own line: a pass out,
 * quick, if-bound, on the member's device, in its resolver's family, to it, port 53; a counting block for each family
 * of the setting's addresses, on the table; a backstop to each setting address, in its family, and to nothing else
 * (with no backstop at all, the one problem is that it is missing). A device is
 * bounded like a word that may not continue with a word character or a dot (wg1 is not wg10 or wg1.65), an address as
 * uu_rules_to() bounds it. Every address is compared in canonical form, as pf prints it.
 *
 * @param list<array{name: string, interface: string, if: string, resolver: string}> $members uu_ruled_members()
 * @param list<string> $settingAddresses uu_setting_addresses()
 * @return array{loaded: bool, problems: list<string>}
 */
function uu_rules_verdict(string $vsrOut, array $members, array $settingAddresses): array
{
    $problems = [];
    foreach ($members as $member) {
        $resolver = uu_ip_canonical($member['resolver']) ?? $member['resolver'];
        $lines = uu_rules_lines($vsrOut, uu_label_pass($member['interface'], $resolver));
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
                    'if-bound' => '\bkeep state \([^)]*\bif-bound\b',
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
                if (!uu_rules_family($line, uu_ip_family($resolver) ?? 'inet')) {
                    $problems[] = $member['name'] . ' pass: wrong family';
                }
                if (!uu_rules_to($line, $resolver)) {
                    $problems[] = $member['name'] . ' pass: wrong address';
                }
                if (!uu_rules_has($line, '\bport = (domain|53)\b')) {
                    $problems[] = $member['name'] . ' pass: wrong port';
                }
            }
        }
    }
    $setting = [];
    foreach ($settingAddresses as $address) {
        $setting[] = uu_ip_canonical($address) ?? $address;
    }
    $counting = uu_rules_lines($vsrOut, uu_label_block());
    array_push($problems, ...uu_rules_block_problems($counting, 'counting block', ['<' . UU_BLOCK_TABLE . '>']));
    foreach (['inet', 'inet6'] as $family) {
        $needed = array_filter($setting, fn (string $address): bool => uu_ip_family($address) === $family);
        $has = array_filter($counting, fn (string $line): bool => uu_rules_family($line, $family));
        if ($counting !== [] && $needed !== [] && $has === []) {
            $problems[] = 'counting block: no ' . $family . ' rule';
        }
    }
    /* a setting address no backstop goes to is named only while every backstop goes to a setting address: a backstop
     * to another address is the wrong target, which already says the set is wrong */
    $backstops = uu_rules_lines($vsrOut, uu_label_backstop());
    $backstopProblems = uu_rules_block_problems($backstops, 'backstop block', $setting);
    array_push($problems, ...$backstopProblems);
    $named = $backstops !== [] && !in_array('backstop block: wrong target', $backstopProblems, true);
    foreach ($named ? $setting : [] as $address) {
        if (array_filter($backstops, fn (string $line): bool => uu_rules_to($line, $address)) === []) {
            $problems[] = 'backstop block for ' . $address . ' missing';
        }
    }
    $problems = array_values(array_unique($problems));
    return ['loaded' => $problems === [], 'problems' => $problems];
}

/**
 * What a verdict depends on besides the ruleset: each ruled member's interface, device and resolver, as a set, and
 * the Default. Order-independent over the members. Between a Save and its filter reload the checksum is unchanged
 * while the settings already differ, so a record is reused only for the same inputs.
 *
 * @param list<array{interface: string, if: string, resolver: string}> $members
 */
function uu_rules_inputs(array $members, string $default): string
{
    $triples = array_map(fn (array $m): array => [$m['interface'], $m['if'],
        uu_ip_canonical($m['resolver']) ?? $m['resolver']], $members);
    sort($triples);
    return md5(json_encode([$triples, $default], JSON_THROW_ON_ERROR));
}

/**
 * Whether the plugin's rules are loaded, verified once per ruleset checksum and inputs. A record whose checksum is
 * live and whose inputs are these is used with no listing, except a recorded fault (loaded false) by an
 * evaluation: the plugin acts on that fault (fallback), so every evaluation lists again while it stands; a status
 * call shows it. Otherwise, when listing is allowed, the checksum is read, the ruleset listed once and the
 * checksum read again; the verdict is used and recorded (under these inputs) only when both reads agree and the
 * listing is whole (listing returns null when pfctl cut it short, uu_pf_listing_usable()). When the reads differ
 * or the listing was cut, a reload ran during it, so its verdict is never judged: the pair is tried again, up to
 * UU_RULES_LIST_PAIRS pairs. When no pair agrees, a record made for these inputs keeps its verdict (none, or one
 * made for other inputs: not loaded) and nothing is recorded, so the next evaluation lists again. When listing
 * is not allowed (a status call) the answer is 'verifying'. state is 'loaded', 'missing' or 'verifying'; record
 * is the new record to save, or null.
 *
 * @param ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>} $record
 * @param string $inputs uu_rules_inputs() of the verdict's inputs
 * @param callable(): ?string $checksum
 * @param callable(): ?string $listing the ruleset listing, or null when it is not whole
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
    if ($record !== null && $record['checksum'] === $live && $record['inputs'] === $inputs
        && ($record['loaded'] || !$mayList)) {
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
        $text = $listing();
        $after = $checksum();
        if ($after !== $before || $text === null) {
            $unreadable = $unreadable || $after === null;
            continue;
        }
        $verdict = $verdictOf($text);
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
 * The saved record, or null when the file is missing, not a regular file within the limit (never read through a link),
 * truncated or not exactly the Record shape (a record without inputs, from a build before them, is null too: the next
 * evaluation lists once).
 *
 * @return ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>}
 */
function uu_rules_record_load(string $path): ?array
{
    $read = uu_read_regular_file($path);
    if ($read['text'] === null) {
        return null;
    }
    $doc = json_decode($read['text'], true);
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
 * The counting blocks' table as the status reads it. armed: the table holds exactly the setting's addresses ($want,
 * uu_setting_addresses()), compared as canonical sets, and there is one; a footprint is never in it (its literal block
 * covers it), so an orphan in its hold neither arms nor stops the fill. fill: the table is referenced by a rule but is
 * not armed, so the evaluation fills it; never for an unreferenced table or with no setting address. blocked: the
 * table's Out/Block packets, null without the table.
 *
 * @param ?array{addresses: int, references: int, out_block: int} $table
 * @param list<string> $addresses what `pfctl -T show` listed (uu_pf_show_addresses())
 * @param list<string> $want
 * @return array{armed: bool, fill: bool, blocked: ?int}
 */
function uu_block_table_view(?array $table, array $addresses, array $want): array
{
    if ($table === null) {
        return ['armed' => false, 'fill' => false, 'blocked' => null];
    }
    $set = function (array $list): array {
        $canonical = array_values(array_unique(array_map(fn (string $a): string => uu_ip_canonical($a) ?? $a, $list)));
        sort($canonical, SORT_STRING);
        return $canonical;
    };
    $armed = $want !== [] && $set($addresses) === $set($want);
    $fill = $table['references'] >= 1 && !$armed && $want !== [];
    return ['armed' => $armed, 'fill' => $fill, 'blocked' => $table['out_block']];
}

/**
 * Put the setting's addresses back into the counting table, which the rules reference but which does not hold exactly
 * them (a boot, a flush from Diagnostics, the first reload after enabling, a changed address): `pfctl -T replace`
 * with the whole set, so a footprint's address leaves it. The plugin's only pf write, and in dry run too: the table is
 * the counting blocks' upkeep, and the rules are rendered in dry run. Nothing for an empty list or one holding
 * anything that is no address.
 *
 * @param list<string> $addresses canonical
 * @param callable(string): array{rc: int, out: string} $run the command line through sh (uu_core_shell())
 * @param callable(string, int): void $log
 */
function uu_block_table_fill(array $addresses, callable $run, callable $log): void
{
    if ($addresses === [] || in_array(null, array_map('uu_ip_family', $addresses), true)) {
        return;
    }
    $list = implode(' ', $addresses);
    $rc = $run('/sbin/pfctl -t ' . escapeshellarg(UU_BLOCK_TABLE) . ' -T replace '
        . implode(' ', array_map('escapeshellarg', $addresses)) . ' 2>/dev/null')['rc'];
    if ($rc === 0) {
        $log("rules: the counting table holds $list again", LOG_NOTICE);
    } else {
        $log("rules: the counting table could not be filled with $list (pfctl exit $rc): blocked packets are "
            . 'not counted until it is', LOG_WARNING);
    }
}
