<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Root-zone parser and shape (spec 2026-10-17 section 3.4). Pure.
 *
 * Reads the forward zones out of Unbound's generated configuration and reports whether the root zone has a
 * shape forward_add can restore: no "." zone, or exactly one whose only options are forward-addr and
 * forward-tls-upstream. Anything else is "unrestorable" and its problems are named, and so is a configuration that
 * could not be read in full: "could not look" is never "no . zone", which restores as recursion over the WAN.
 *
 * ZoneBlock = array{name: string, lines: list<array{0: string, 1: string}>}  (lines are [option, value])
 * Zone      = array{shape: string, addrs: list<string>, tls: bool, problems: list<string>}
 *             shape is 'none', 'one' or 'unrestorable'
 */

/**
 * Whether a forward-addr value, as Unbound prints and takes it, is an address with an optional port and an optional
 * authentication name and nothing else, so text from Unbound never reaches the page, the log or forward_add unchecked.
 */
function uu_forward_addr_ok(string $value): bool
{
    if (preg_match('/^([0-9a-f:.]+)(@\d{1,5})?(#[A-Za-z0-9.-]+)?$/iD', $value, $m) !== 1) {
        return false;
    }
    return inet_pton($m[1]) !== false;
}

/**
 * Whether a configuration option name is a plain name (lower-case letters, digits, hyphens), as one may be named in a
 * problem.
 */
function uu_zone_option_name_ok(string $option): bool
{
    return preg_match('/^[a-z0-9-]+$/D', $option) === 1;
}

/**
 * One configuration line without its comment, split into [option, value] with surrounding quotes removed;
 * null for a blank or comment-only line. A clause header such as "server:" has an empty value.
 *
 * @return ?array{0: string, 1: string}
 */
function uu_zone_split_line(string $line): ?array
{
    $line = trim($line);
    if ($line === '' || $line[0] === '#') {
        return null;
    }
    $colon = strpos($line, ':');
    if ($colon === false) {
        return null;
    }
    $option = strtolower(trim(substr($line, 0, $colon)));
    $value = ltrim(substr($line, $colon + 1));
    if ($value !== '' && ($value[0] === '"' || $value[0] === "'")) {
        $end = strpos($value, $value[0], 1);
        $value = $end === false ? substr($value, 1) : substr($value, 1, $end - 1);
    } else {
        // a comment starts at a '#' that begins the value or follows whitespace; "addr#authname" has neither
        $value = preg_replace('/(^|\s)#.*$/', '', $value) ?? $value;
        $value = trim($value);
    }
    return [$option, $value];
}

/**
 * Every forward-zone block in a configuration text. A block ends at the next top-level clause.
 *
 * @return list<array{name: string, lines: list<array{0: string, 1: string}>}>
 */
function uu_parse_forward_zones(string $text): array
{
    $clauses = ['server', 'forward-zone', 'stub-zone', 'remote-control', 'auth-zone', 'view', 'python',
                'dynlib', 'cachedb', 'dnstap', 'rpz'];
    $zones = [];
    $open = null;
    foreach (preg_split('/\R/', $text) ?: [] as $raw) {
        $pair = uu_zone_split_line($raw);
        if ($pair === null) {
            continue;
        }
        [$option, $value] = $pair;
        if (in_array($option, $clauses, true) && $value === '') {
            if ($open !== null) {
                $zones[] = $open;
            }
            $open = $option === 'forward-zone' ? ['name' => '', 'lines' => []] : null;
            continue;
        }
        if ($open === null) {
            continue;
        }
        if ($option === 'name') {
            $open['name'] = $value;
        } else {
            $open['lines'][] = [$option, $value];
        }
    }
    if ($open !== null) {
        $zones[] = $open;
    }
    return $zones;
}

/**
 * The shape of the "." zone across the generated files, given in file-name order; null (uu_zone_texts() could not
 * read them) is unrestorable, "configuration unreadable".
 *
 * @param ?list<string> $texts
 * @return array{shape: string, addrs: list<string>, tls: bool, problems: list<string>}
 */
function uu_root_zone(?array $texts): array
{
    if ($texts === null) {
        return ['shape' => 'unrestorable', 'addrs' => [], 'tls' => false, 'problems' => ['configuration unreadable']];
    }
    $roots = [];
    foreach ($texts as $text) {
        foreach (uu_parse_forward_zones($text) as $zone) {
            if (rtrim($zone['name'], '.') === '') {
                $roots[] = $zone;
            }
        }
    }
    if ($roots === []) {
        return ['shape' => 'none', 'addrs' => [], 'tls' => false, 'problems' => []];
    }

    $addrs = [];
    $tls = false;
    $problems = [];
    foreach ($roots[0]['lines'] as [$option, $value]) {
        if ($option === 'forward-addr') {
            if (uu_forward_addr_ok($value)) {
                $addrs[] = $value;
            } elseif (!in_array('forward-addr value', $problems, true)) {
                $problems[] = 'forward-addr value';
            }
        } elseif ($option === 'forward-tls-upstream') {
            $tls = in_array(strtolower($value), ['yes', '1', 'true'], true);
        } else {
            $named = uu_zone_option_name_ok($option) ? $option : 'unknown option';
            if (!in_array($named, $problems, true)) {
                $problems[] = $named;
            }
        }
    }
    if (count($roots) > 1) {
        $problems[] = 'second . zone';
    }
    return ['shape' => $problems === [] ? 'one' : 'unrestorable', 'addrs' => $addrs, 'tls' => $tls,
            'problems' => $problems];
}
