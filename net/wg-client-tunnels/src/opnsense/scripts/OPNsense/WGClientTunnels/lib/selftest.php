<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Tally helpers for the action libraries' self-tests. Pure: prints only.
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
