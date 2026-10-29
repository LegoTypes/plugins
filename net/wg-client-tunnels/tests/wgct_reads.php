<?php

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
 * Static test: the hook and controller paths read model fields through the field API (isEqual(), isEmpty(),
 * getValue()), never through a (string) cast. OPNsense's PHP has no tokenizer extension, so it works on text: it
 * cuts each mapped function's body out of its file and reports
 *   1. (string) of a variable bound by foreach (... ->iterateItems() as [$k =>] $v) or assigned from
 *      ->Add() or ->getNodeByReference(...), or of a field of it (an attribute, ->getAttribute(), is not a field);
 *   2. (string) of a field of a freshly built model, (string)(new Model())->field;
 *   3. in M3_1_0::run, (string)$node->enabled and (string)$node->health_mirror.
 * Raw-config casts ($root->..., $if->..., array keys) match none of them. A mapped file or function that cannot
 * be found is a failure, so the test cannot pass by looking at nothing.
 *
 * Known limits: a foreach whose header is split across lines binds no variable, and the brace counter does not skip
 * braces inside strings or comments.
 *
 * Usage: php wgct_reads.php /path/to/scripts /path/to/mvc
 */

const READS_MAP = [
    ['scripts', 'lib/tunnels.php', ['wgct_core_read', 'wgct_core_read_context']],
    ['scripts', 'lib/writer.php', ['wgct_action_snapshot', 'wgct_sentinel_commit', 'wgct_edit_swap_state', 'wgct_write_edit']],
    ['scripts', 'lib/mirror.php', ['wgct_apply_changes']],
    ['mvc', 'app/controllers/OPNsense/WGClientTunnels/Api/TunnelsController.php', ['choices']],
    ['mvc', 'app/models/OPNsense/WGClientTunnels/Engine.php', ['managedList', 'setManaged', 'holdRows']],
    ['mvc', 'app/models/OPNsense/WGClientTunnels/Migrations/M3_1_0.php', ['run']],
];

/**
 * @return array{0: int, 1: string}|null the offset of the body's first character and the body, or null
 */
function reads_body(string $text, string $name): ?array
{
    if (!preg_match('/function ' . preg_quote($name, '/') . '\(/', $text, $m, PREG_OFFSET_CAPTURE)) {
        return null;
    }
    $open = strpos($text, '{', $m[0][1]);
    if ($open === false) {
        return null;
    }
    $depth = 0;
    for ($i = $open, $n = strlen($text); $i < $n; $i++) {
        if ($text[$i] === '{') {
            $depth++;
        } elseif ($text[$i] === '}' && --$depth === 0) {
            return [$open, substr($text, $open, $i - $open + 1)];
        }
    }
    return null;
}

/**
 * Scan one function's body for the casts the header lists, adding each site to $sites.
 *
 * @param array<string, string> $sites file:line => the line's text, appended to
 * @return bool false when the function cannot be found in $text
 */
function reads_scan(string $file, string $text, string $name, array &$sites): bool
{
    $found = reads_body($text, $name);
    if ($found === null) {
        return false;
    }
    [$start, $body] = $found;
    $patterns = [
        '/\(string\)\s*\(new\s+[\\\\\w]+\(\)\)->\w+/',
    ];
    if ($name === 'run') {
        $patterns[] = '/\(string\)\s*\$node->(?:enabled|health_mirror)\b/';
    }
    $bound = [];
    if (preg_match_all('/\\$(\w+)\s*=(?![>=])\s*[^;{}]*->(?:Add\(\)|getNodeByReference\([^;]*\))\s*;/', $body, $assigned)) {
        $bound = $assigned[1];
    }
    if (preg_match_all('/foreach\s*\(.*->iterateItems\(\)\s+as\s+(?:\$\w+\s*=>\s*)?\$(\w+)\s*\)/', $body, $vars)) {
        $bound = array_merge($bound, $vars[1]);
    }
    foreach (array_unique($bound) as $v) {
        $patterns[] = '/\(string\)\s*\$' . $v . '\b(?!->getAttribute\()(?:->(?:\w+|\{\$\w+\}))*/';
    }
    $lines = explode("\n", $text);
    foreach ($patterns as $pattern) {
        if (!preg_match_all($pattern, $body, $hits, PREG_OFFSET_CAPTURE)) {
            continue;
        }
        foreach ($hits[0] as [, $off]) {
            $line = substr_count($text, "\n", 0, $start + $off) + 1;
            $sites[basename($file) . ':' . $line] = trim($lines[$line - 1]);
        }
    }
    return true;
}

[, $scripts, $mvc] = $argv + [null, '', ''];
$dirs = ['scripts' => rtrim((string)$scripts, '/'), 'mvc' => rtrim((string)$mvc, '/')];
$total = 0;
$failed = 0;
$sites = [];
foreach (READS_MAP as [$dir, $rel, $functions]) {
    $file = "{$dirs[$dir]}/$rel";
    $text = is_readable($file) ? (string)file_get_contents($file) : null;
    foreach ($functions as $name) {
        $total++;
        if ($text === null || !reads_scan($file, $text, $name, $sites)) {
            $failed++;
            echo "[FAIL] reads: $rel $name() cannot be found\n";
        }
    }
}
$total++;
ksort($sites, SORT_NATURAL);
foreach ($sites as $where => $line) {
    echo "[FAIL] reads: $where $line\n";
}
if ($sites === []) {
    echo "[PASS] reads: no model field is read by a cast in the hook and controller paths\n";
} else {
    $failed++;
}
printf("reads: %d/%d passed\n", $total - $failed, $total);
exit($failed === 0 ? 0 : 1);
