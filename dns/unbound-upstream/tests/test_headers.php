<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Every copyright line in the plugin tree names the handle and nothing else.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';

/**
 * One row per file under $root that carries a copyright marker: the file's path below $root and the numbers of its
 * lines that are not exactly the handle's header; a file $read cannot read is a row with null.
 *
 * @return list<array{path: string, bad: ?list<int>}>
 */
function uu_headers_scan(string $root, callable $read): array
{
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
    $paths = [];
    foreach ($files as $file) {
        if ($file->isFile() && !$file->isLink()) {
            $paths[] = $file->getPathname();
        }
    }
    sort($paths);
    $rows = [];
    foreach ($paths as $path) {
        $rel = substr($path, strlen($root) + 1);
        $text = $read($path);
        if (!is_string($text)) {
            $rows[] = ['path' => $rel, 'bad' => null];
            continue;
        }
        $bad = [];
        foreach (explode("\n", $text) as $n => $line) {
            if (preg_match('/copyright\s*\(c\)/i', $line) === 1
                && preg_match('/^ ?[#*]? ?Copyright \(C\) 2026 cayossarian$/', $line) !== 1) {
                $bad[] = $n + 1;
            }
        }
        if ($bad !== [] || preg_match('/copyright\s*\(c\)/i', $text) === 1) {
            $rows[] = ['path' => $rel, 'bad' => $bad];
        }
    }
    return $rows;
}

uu_register_suite('headers', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $read = fn (string $path): string|false => @file_get_contents($path);

    /* the scan itself, on a scratch tree */
    $dir = sys_get_temp_dir() . '/uu_headers_' . getmypid();
    mkdir($dir);
    $m = 'Copyright ' . '(C)';
    $mk = ['ok.php' => "# $m 2026 cayossarian\n", 'lower.php' => '# ' . strtolower($m) . " 2026 cayossarian\n",
           'spaced.php' => '# ' . str_replace(' ', '', $m) . " 2026 cayossarian\n", 'locked.php' => "# $m 2026 cayossarian\n",
           'none.txt' => "no marker here\n"];
    foreach ($mk as $name => $text) {
        file_put_contents($dir . '/' . $name, $text);
    }
    $rows = uu_headers_scan($dir, fn (string $p): string|false => basename($p) === 'locked.php' ? false : $read($p));
    $by = array_column($rows, 'bad', 'path');
    uu_check($t, 'scan: the exact header passes, a file with no marker is not listed',
        ($by['ok.php'] ?? null) === [] && !array_key_exists('none.txt', $by));
    uu_check($t, 'scan: a lower-case marker is held to the exact header', ($by['lower.php'] ?? null) === [1]);
    uu_check($t, 'scan: a marker spelled without the space is held to the exact header', ($by['spaced.php'] ?? null) === [1]);
    uu_check($t, 'scan: an unreadable file is a row, not a skip', array_key_exists('locked.php', $by) && $by['locked.php'] === null);
    foreach (array_keys($mk) as $name) {
        unlink($dir . '/' . $name);
    }
    rmdir($dir);

    /* the plugin tree */
    $root = dirname(__DIR__);
    $before = $t['total'];
    foreach (uu_headers_scan($root, $read) as $row) {
        if ($row['bad'] === null) {
            uu_check($t, sprintf('%s: the file cannot be read', $row['path']), false);
        } else {
            uu_check($t, sprintf('%s: every copyright line is the handle%s', $row['path'],
                $row['bad'] === [] ? '' : ' (lines ' . implode(', ', $row['bad']) . ')'), $row['bad'] === []);
        }
    }
    if ($t['total'] === $before) {
        uu_check($t, 'some file holds a copyright line', false);
    }
    return uu_tally_report('headers', $t);
});
