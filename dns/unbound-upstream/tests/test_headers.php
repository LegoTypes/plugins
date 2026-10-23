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

uu_register_suite('headers', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $root = dirname(__DIR__);
    $needle = 'Copyright ' . '(C)';
    $files = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
    $paths = [];
    foreach ($files as $file) {
        if ($file->isFile() && !$file->isLink()) {
            $paths[] = $file->getPathname();
        }
    }
    sort($paths);
    foreach ($paths as $path) {
        $text = file_get_contents($path);
        if ($text === false) {
            continue;
        }
        $bad = [];
        foreach (explode("\n", $text) as $n => $line) {
            if (str_contains($line, $needle) && preg_match('/^ ?[#*]? ?Copyright \(C\) 2026 cayossarian$/', $line) !== 1) {
                $bad[] = $n + 1;
            }
        }
        if ($bad === [] && !str_contains($text, $needle)) {
            continue;
        }
        $rel = substr($path, strlen($root) + 1);
        uu_check($t, sprintf('%s: every copyright line is the handle%s', $rel, $bad === [] ? '' : ' (lines ' . implode(', ', $bad) . ')'), $bad === []);
    }
    if ($t['total'] === 0) {
        uu_check($t, 'some file holds a copyright line', false);
    }
    return uu_tally_report('headers', $t);
});
