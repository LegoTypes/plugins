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
 * What the self-tests share: the tally helpers, the directories their files lie in, the runner that turns a suite's
 * exception into a failed case, and the rule for the --selftest argument. Functions only, and no constant: nothing
 * here runs or is defined outside a function.
 */

/**
 * @param array{fail: int, total: int} $tally updated in place
 * @param string                       $desc  what the case proves
 * @param bool                         $ok    whether it passed
 */
function wgct_check(array &$tally, string $desc, bool $ok): void {
    $tally['total']++;
    if (!$ok) {
        $tally['fail']++;
    }
    printf("[%s] %s\n", $ok ? 'PASS' : 'FAIL', $desc);
}

/**
 * @param string                       $suite name printed before the count
 * @param array{fail: int, total: int} $tally
 * @return int exit code, 0 when every case passed
 */
function wgct_tally_report(string $suite, array $tally): int {
    printf("%s: %d/%d passed\n", $suite, $tally['total'] - $tally['fail'], $tally['total']);
    return $tally['fail'] === 0 ? 0 : 1;
}

/**
 * @return string the directory every self-test fixture lies under: root's alone, beside the plugin's run directory and
 *                never in it, so no test file lies among live state
 */
function wgct_selftest_root(): string {
    return '/var/run/wgclienttunnels-selftest';
}

/**
 * The fixture directories wgct_selftest_dir() made in this process and has not removed yet.
 *
 * @param array<string, string>|null $set the record to keep from now on; null leaves it as it is
 * @return array<string, string> directory => the root it was made under
 */
function wgct_selftest_made(?array $set = null): array {
    static $made = [];
    if ($set !== null) {
        $made = $set;
    }
    return $made;
}

/**
 * A new, empty directory for one self-test fixture: <root>/<label>.<32 hex digits>, mode 0700. The root is made 0700
 * when absent and must then be a directory (no link) of root's with exactly that mode, so no other account can
 * create, read or pre-empt anything in it. The name is random and the directory is made in one mkdir(), which fails
 * when the name exists in any form. Each directory made here is given its mode by chmod(), so the umask of the
 * caller decides nothing; a root that already exists is checked and never changed. A parent that cannot be written
 * is refused before mkdir() is tried.
 *
 * @param string      $label what the fixture is for: lower-case letters, digits and hyphens
 * @param string|null $root  the directory to make it under; null: wgct_selftest_root()
 * @return string the directory's path
 * @throws \RuntimeException naming the path, when the root is not root's alone or a directory cannot be made
 */
function wgct_selftest_dir(string $label, ?string $root = null): string {
    $root ??= wgct_selftest_root();
    if (preg_match('/^[a-z][a-z0-9-]*$/D', $label) !== 1) {
        throw new \InvalidArgumentException("not a self-test fixture label: {$label}");
    }
    clearstatcache(true, $root);
    if (!file_exists($root) && !is_link($root)) {
        $parent = dirname($root);
        if (!is_dir($parent) || !is_writable($parent)) {
            throw new \RuntimeException("the self-test root {$root} cannot be made");
        }
        if (mkdir($root, 0700)) {
            if (!chmod($root, 0700)) {
                throw new \RuntimeException("the self-test root {$root} cannot be given mode 0700");
            }
        } else {
            /* another self-test may have made it in the same moment: the check below decides */
            clearstatcache(true, $root);
            if (!is_dir($root)) {
                throw new \RuntimeException("the self-test root {$root} cannot be made");
            }
        }
    }
    clearstatcache(true, $root);
    $stat = file_exists($root) || is_link($root) ? lstat($root) : false;
    if ($stat === false || ($stat['mode'] & 0170000) !== 0040000 || $stat['uid'] !== 0 || ($stat['mode'] & 07777) !== 0700) {
        throw new \RuntimeException("the self-test root {$root} is not a directory of root's with mode 0700");
    }
    $dir = $root . '/' . $label . '.' . bin2hex(random_bytes(16));
    if (!is_writable($root) || !mkdir($dir, 0700) || !chmod($dir, 0700)) {
        throw new \RuntimeException("the self-test directory {$dir} cannot be made");
    }
    wgct_selftest_made(wgct_selftest_made() + [$dir => $root]);
    return $dir;
}

/**
 * Remove $path and everything below it, depth first. A symbolic link is unlinked and never followed, whatever it
 * points at. A path that does not exist is left alone.
 *
 * @return bool whether nothing is left at $path
 */
function wgct_selftest_remove_tree(string $path): bool {
    clearstatcache(true, $path);
    if (is_link($path)) {
        return unlink($path);
    }
    if (!file_exists($path)) {
        return true;
    }
    if (!is_dir($path)) {
        return unlink($path);
    }
    $entries = scandir($path);
    if ($entries === false) {
        return false;
    }
    $emptied = true;
    foreach ($entries as $entry) {
        if ($entry !== '.' && $entry !== '..') {
            $emptied = wgct_selftest_remove_tree($path . '/' . $entry) && $emptied;
        }
    }
    return $emptied && rmdir($path);
}

/**
 * Remove the fixture directories wgct_selftest_dir() made in this process: each one only where it lies directly
 * under the root it was made under. Directories of another process, a second self-test running at the same time
 * among them, are never touched. A directory that is not removed stays on record and is returned.
 *
 * @param string|null $root only the directories made under this root; null: every one
 * @return list<string> the directories it was to remove and did not
 */
function wgct_selftest_cleanup(?string $root = null): array {
    $kept = [];
    $left = [];
    foreach (wgct_selftest_made() as $dir => $under) {
        if ($root !== null && $under !== $root) {
            $kept[$dir] = $under;
        } elseif (dirname($dir) !== $under || !wgct_selftest_remove_tree($dir)) {
            $kept[$dir] = $under;
            $left[] = (string)$dir;
        }
    }
    wgct_selftest_made($kept);
    return $left;
}

/**
 * Run self-test suites. Whatever a suite throws (a fixture directory that cannot be made, a missing function) ends
 * that suite alone and is printed as one failed case with a summary line in the suites' own form, so each suite's
 * output stays one block. The fixture directories made on the way are removed at the end, also when a suite threw;
 * each one that is left is printed as one failed case and fails the run.
 *
 * @param array<string, callable(): int> $suites suite name => the suite, which prints its cases and returns its exit code
 * @return int 0 when every suite passed, else 1
 */
function wgct_selftest_run(array $suites): int {
    $status = 0;
    try {
        foreach ($suites as $name => $suite) {
            try {
                $code = $suite();
            } catch (\Throwable $e) {
                printf("[FAIL] selftest: %s: %s\n", get_class($e), trim((string)preg_replace('/\s*\R\s*/', '; ', $e->getMessage())));
                printf("%s: 0/1 passed\n", $name);
                $code = 1;
            }
            $status = $code === 0 ? $status : 1;
        }
    } finally {
        foreach (wgct_selftest_cleanup() as $dir) {
            printf("[FAIL] selftest: left %s\n", $dir);
            $status = 1;
        }
    }
    return $status;
}

/**
 * Whether a script's arguments ask for its self-tests. --selftest counts only as the sole argument, so a value
 * that reaches a script beside other words can never start them. Pure.
 *
 * @param list<string> $args argv without the script name
 * @return bool|null true for exactly --selftest, false when it is absent, null when it stands beside anything else
 */
function wgct_selftest_requested(array $args): ?bool {
    if ($args === ['--selftest']) {
        return true;
    }
    return in_array('--selftest', $args, true) ? null : false;
}

/**
 * wgct_selftest_requested() for an entry script: --selftest beside anything else ends the script with one line on
 * stderr and exit status 2, before it does anything.
 *
 * @param string       $script the entry script's file name, for the refusal
 * @param list<string> $args   argv without the script name
 * @return bool whether to run the self-tests
 */
function wgct_selftest_only(string $script, array $args): bool {
    $requested = wgct_selftest_requested($args);
    if ($requested === null) {
        fwrite(STDERR, "{$script}: --selftest takes no other argument\n");
        exit(2);
    }
    return $requested;
}
