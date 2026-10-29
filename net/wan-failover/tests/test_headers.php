<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Holds every copyright line in the plugin tree to the handle-only form.
 */

require_once __DIR__ . '/selftest.php';

wf_register_suite('headers', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $root = dirname(__DIR__);
    $marker = 'Copyright ' . '(C)';
    $files = [];
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS));
    foreach ($it as $info) {
        if ($info instanceof SplFileInfo && $info->isFile()) {
            $files[] = $info->getPathname();
        }
    }
    sort($files);

    $headers = 0;
    foreach ($files as $path) {
        $lines = @file($path, FILE_IGNORE_NEW_LINES);
        if ($lines === false) {
            /* a file that cannot be read cannot be shown to carry no copyright line other than the handle's */
            wf_check($t, 'readable for the header check: ' . substr($path, strlen($root) + 1), false);
            continue;
        }
        $held = [];
        foreach ($lines as $line) {
            if (str_contains($line, $marker)) {
                $held[] = $line;
            }
        }
        if ($held === []) {
            continue;
        }
        $headers++;
        $ok = true;
        foreach ($held as $line) {
            if (preg_match('/^ ?[#*]? ?Copyright \(C\) 2026 cayossarian\z/', $line) !== 1) {
                $ok = false;
            }
        }
        wf_check($t, 'copyright line is the handle only: ' . substr($path, strlen($root) + 1), $ok);
    }
    if ($headers === 0) {
        wf_check($t, 'the tree holds at least one copyright header', false);
    }
    return wf_tally_report('headers', $t);
});
