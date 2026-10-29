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
 * Every copyright line in the plugin tree names the handle and nothing else, and the 22 lines of the licence text
 * follow it, as the hooks file carries them.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';

/**
 * The licence text under the handle line of the hooks file's header: its 22 lines, comment prefix removed.
 *
 * @return list<string>
 */
function uu_headers_licence(string $hooks): array
{
    $lines = explode("\n", $hooks);
    $body = [];
    foreach (array_slice($lines, 4, 22) as $line) {
        $body[] = (string) preg_replace('/^ \* ?/', '', $line);
    }
    return $body;
}

/**
 * One row per file under $root that carries a copyright marker: the file's path below $root, the numbers of its
 * lines that are not exactly the handle's header, and whether the handle line is followed, line by line, by the
 * $licence lines after each line's comment prefix (" *", "#" or " #", then one space; a blank line is the prefix
 * alone); a file $read cannot read is a row with null for bad and false for licence.
 *
 * @param list<string> $licence
 * @return list<array{path: string, bad: ?list<int>, licence: bool}>
 */
function uu_headers_scan(string $root, callable $read, array $licence): array
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
            $rows[] = ['path' => $rel, 'bad' => null, 'licence' => false];
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
            $lines = explode("\n", $text);
            $at = array_search(true, array_map(
                fn (string $line): bool => preg_match('/^ ?[#*]? ?Copyright \(C\) 2026 cayossarian$/', $line) === 1,
                $lines,
            ), true);
            $held = is_int($at);
            foreach ($licence as $k => $want) {
                $got = $lines[(is_int($at) ? $at : 0) + 1 + $k] ?? null;
                $held = $held && $got !== null && preg_match('/^( \*|#| #)(?: (.*))?$/', $got, $m) === 1
                    && ($m[2] ?? '') === $want;
            }
            $rows[] = ['path' => $rel, 'bad' => $bad, 'licence' => $held];
        }
    }
    return $rows;
}

uu_register_suite('headers', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $read = fn (string $path): string|false => @file_get_contents($path);

    /* the scan itself, on a scratch tree */
    $dir = sys_get_temp_dir() . '/uu_headers_' . bin2hex(random_bytes(6));
    if (!mkdir($dir, 0700)) {
        uu_check($t, sprintf('scan: the scratch directory %s cannot be made', $dir), false);
    } else {
        try {
            $m = 'Copyright ' . '(C)';
            $mk = ['ok.php' => "# $m 2026 cayossarian\n", 'lower.php' => '# ' . strtolower($m) . " 2026 cayossarian\n",
                   'spaced.php' => '# ' . str_replace(' ', '', $m) . " 2026 cayossarian\n", 'locked.php' => "# $m 2026 cayossarian\n",
                   'none.txt' => "no marker here\n",
                   'full.php' => "/*\n * $m 2026 cayossarian\n * All rights reserved.\n *\n * Redistribution.\n */\n",
                   'full.py' => "# $m 2026 cayossarian\n# All rights reserved.\n#\n# Redistribution.\n",
                   'full.volt' => "{#\n # $m 2026 cayossarian\n # All rights reserved.\n #\n # Redistribution.\n #}\n",
                   'ref.php' => "/*\n * $m 2026 cayossarian\n * All rights reserved.\n * BSD 2-Clause License\n */\n",
                   'short.py' => "# $m 2026 cayossarian\n# All rights reserved.\n#\n",
                   'ref.volt' => "{#\n # $m 2026 cayossarian\n # All rights reserved.\n # BSD 2-Clause License\n #}\n"];
            foreach ($mk as $name => $text) {
                file_put_contents($dir . '/' . $name, $text);
            }
            $rows = uu_headers_scan($dir, fn (string $p): string|false => basename($p) === 'locked.php' ? false : $read($p), ['All rights reserved.', '', 'Redistribution.']);
            $by = array_column($rows, 'bad', 'path');
            $has = array_column($rows, 'licence', 'path');
            uu_check($t, 'scan: the exact header passes, a file with no marker is not listed',
                ($by['ok.php'] ?? null) === [] && !array_key_exists('none.txt', $by));
            uu_check($t, 'scan: a lower-case marker is held to the exact header', ($by['lower.php'] ?? null) === [1]);
            uu_check($t, 'scan: a marker spelled without the space is held to the exact header', ($by['spaced.php'] ?? null) === [1]);
            uu_check($t, 'scan: a handle line followed by the full licence passes, in PHP, # and volt comments',
                ($has['full.php'] ?? null) === true && ($has['full.py'] ?? null) === true && ($has['full.volt'] ?? null) === true);
            uu_check($t, 'scan: the one-line reference fails, naming the file',
                ($has['ref.php'] ?? null) === false && ($has['ref.volt'] ?? null) === false
                && ($has['short.py'] ?? null) === false && ($has['ok.php'] ?? null) === false);
            uu_check($t, 'scan: an unreadable file is a row, not a skip', array_key_exists('locked.php', $by) && $by['locked.php'] === null);
        } finally {
            foreach (glob($dir . '/*') ?: [] as $file) {
                unlink($file);
            }
            rmdir($dir);
        }
    }

    /* the plugin tree */
    $root = dirname(__DIR__);
    $before = $t['total'];
    $hooks = $read($root . '/src/etc/inc/plugins.inc.d/unboundupstream.inc');
    $licence = is_string($hooks) ? uu_headers_licence($hooks) : [];
    uu_check($t, 'the hooks file holds the licence text under its handle line',
        count($licence) === 22 && $licence[0] === 'All rights reserved.' && str_starts_with($licence[21], 'POSSIBILITY OF SUCH DAMAGE'));
    foreach (uu_headers_scan($root, $read, $licence) as $row) {
        if ($row['bad'] === null) {
            uu_check($t, sprintf('%s: the file cannot be read', $row['path']), false);
        } else {
            uu_check($t, sprintf('%s: the handle line is followed by the full licence text', $row['path']), $row['licence']);
            uu_check($t, sprintf('%s: every copyright line is the handle%s', $row['path'],
                $row['bad'] === [] ? '' : ' (lines ' . implode(', ', $row['bad']) . ')'), $row['bad'] === []);
        }
    }
    if ($t['total'] === $before) {
        uu_check($t, 'some file holds a copyright line', false);
    }
    return uu_tally_report('headers', $t);
});
