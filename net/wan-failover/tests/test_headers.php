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
 */

/*
 * Holds every copyright line in the plugin tree to the handle-only form, and the 22 lines of the licence text to
 * follow it, in the comment syntax of the file (PHP, sh, volt or XML).
 */

require_once __DIR__ . '/selftest.php';

/* the licence text under the handle line, as the settings model carries it, each line without its comment prefix */
const WF_T_LICENCE = [
    "All rights reserved.",
    "",
    "Redistribution and use in source and binary forms, with or without",
    "modification, are permitted provided that the following conditions are met:",
    "",
    "1. Redistributions of source code must retain the above copyright notice,",
    "   this list of conditions and the following disclaimer.",
    "",
    "2. Redistributions in binary form must reproduce the above copyright",
    "   notice, this list of conditions and the following disclaimer in the",
    "   documentation and/or other materials provided with the distribution.",
    "",
    "THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,",
    "INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY",
    "AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE",
    "AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,",
    "OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF",
    "SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS",
    "INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN",
    "CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)",
    "ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE",
    "POSSIBILITY OF SUCH DAMAGE.",
];

/**
 * The line index of the file's handle line (the copyright line with its comment prefix), or null.
 *
 * @param list<string> $lines
 */
function wf_t_copyright_at(array $lines): ?int
{
    foreach ($lines as $i => $line) {
        if (preg_match('/^ ?[#*]? ?Copyright \(C\) 2026 cayossarian\z/', $line) === 1) {
            return $i;
        }
    }
    return null;
}

/**
 * Whether the lines after index $at are the licence text, each with one comment marker and its indent removed, then
 * one space. A blank licence line is the prefix alone (or empty, in XML): trailing space on it fails.
 *
 * @param list<string> $lines
 */
function wf_t_licence_ok(array $lines, int $at): bool
{
    foreach (WF_T_LICENCE as $k => $want) {
        $line = $lines[$at + 1 + $k] ?? null;
        if ($line === null) {
            return false;
        }
        if ((string) preg_replace('/^(?:\s*[*#])?\s?/', '', $line) !== $want) {
            return false;
        }
        if ($want === '' && preg_match('/^(?:\s*[*#])?\z/', $line) !== 1) {
            return false;
        }
    }
    return true;
}

/** Whether the file at $path has a handle line followed by the licence text. */
function wf_t_licence_in_file(string $path): bool
{
    $lines = @file($path, FILE_IGNORE_NEW_LINES);
    if ($lines === false) {
        return false;
    }
    $at = wf_t_copyright_at($lines);
    return $at !== null && wf_t_licence_ok($lines, $at);
}

/**
 * A scratch file's text: the handle line and the licence text in one comment syntax.
 *
 * @param 'php'|'sh'|'volt'|'xml' $syntax
 */
function wf_t_licence_text(string $syntax, string $handle): string
{
    [$open, $first, $blank, $each, $close] = match ($syntax) {
        'php' => ["<?php\n\n/*\n", ' * ', ' *', ' * ', " */\n"],
        'sh' => ["#!/bin/sh\n\n", '# ', '#', '# ', ''],
        'volt' => ["{#\n", ' # ', ' #', ' # ', " #}\n"],
        'xml' => ["<!--\n", ' ', '', ' ', "-->\n"],
    };
    $text = $open . $first . $handle . "\n";
    foreach (WF_T_LICENCE as $want) {
        $text .= ($want === '' ? $blank : $each . $want) . "\n";
    }
    return $text . $close;
}

wf_register_suite('headers', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $root = dirname(__DIR__);
    $marker = 'Copyright ' . '(C)';
    $handle = $marker . ' 2026 cayossarian';

    /* the check itself, on a scratch tree */
    $dir = sys_get_temp_dir() . '/wf_headers_' . bin2hex(random_bytes(6));
    if (!mkdir($dir, 0700)) {
        wf_check($t, 'the scratch directory for the header check can be made: ' . $dir, false);
    } else {
        try {
            $full = [];
            foreach (['php', 'sh', 'volt', 'xml'] as $syntax) {
                $full[$syntax] = $dir . '/full.' . $syntax;
                file_put_contents($full[$syntax], wf_t_licence_text($syntax, $handle));
            }
            wf_check($t, 'headers: the check accepts the full text in PHP, sh, volt and XML comment syntax',
                array_map('wf_t_licence_in_file', $full) === array_fill_keys(array_keys($full), true));

            file_put_contents($dir . '/short.php', "/*\n * $handle\n * All rights reserved.\n * BSD 2-Clause License\n */\n");
            file_put_contents($dir . '/short.sh', "# $handle\n# All rights reserved.\n# BSD 2-Clause License\n");
            file_put_contents($dir . '/short.volt', "{#\n # $handle\n # All rights reserved.\n # BSD 2-Clause License\n #}\n");
            wf_check($t, 'headers: the check refuses the short form',
                !wf_t_licence_in_file($dir . '/short.php') && !wf_t_licence_in_file($dir . '/short.sh')
                && !wf_t_licence_in_file($dir . '/short.volt'));

            $full_php = wf_t_licence_text('php', $handle);
            file_put_contents($dir . '/word.php', str_replace('ARISING IN', 'ARISE IN', $full_php));
            file_put_contents($dir . '/line.php', str_replace(" * 2. Redistributions in binary form must reproduce the above copyright\n", '', $full_php));
            wf_check($t, 'headers: the check refuses a full text with one word changed',
                !wf_t_licence_in_file($dir . '/word.php') && !wf_t_licence_in_file($dir . '/line.php'));

            file_put_contents($dir . '/trail.php', str_replace(" *\n * Redistribution", " * \n * Redistribution", $full_php));
            file_put_contents($dir . '/trail.xml', str_replace("\n\n Redistribution", "\n \n Redistribution",
                wf_t_licence_text('xml', $handle)));
            file_put_contents($dir . '/indent.xml', str_replace("\n All rights reserved.", "\n  All rights reserved.",
                wf_t_licence_text('xml', $handle)));
            wf_check($t, 'headers: the check refuses a blank licence line with trailing space and a text line indented twice',
                !wf_t_licence_in_file($dir . '/trail.php') && !wf_t_licence_in_file($dir . '/trail.xml')
                && !wf_t_licence_in_file($dir . '/indent.xml') && wf_t_licence_in_file($full['php']));
        } finally {
            foreach (glob($dir . '/*') ?: [] as $file) {
                unlink($file);
            }
            rmdir($dir);
        }
    }

    /* the plugin tree */
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
        $at = wf_t_copyright_at($lines);
        wf_check($t, 'headers: the full licence follows the copyright line: ' . substr($path, strlen($root) + 1),
            $at !== null && wf_t_licence_ok($lines, $at));
    }
    if ($headers === 0) {
        wf_check($t, 'the tree holds at least one copyright header', false);
    }
    return wf_tally_report('headers', $t);
});
