<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Selftest tally helpers and suite registry. Pure: prints only.
 */

/**
 * @param array{fail: int, total: int} $tally updated in place
 */
function uu_check(array &$tally, string $desc, bool $ok): void
{
    $tally['total']++;
    if (!$ok) {
        $tally['fail']++;
    }
    printf("[%s] %s\n", $ok ? 'PASS' : 'FAIL', $desc);
}

/**
 * @param array{fail: int, total: int} $tally
 */
function uu_tally_report(string $suite, array $tally): int
{
    printf("%s: %d/%d passed\n", $suite, $tally['total'] - $tally['fail'], $tally['total']);
    return $tally['fail'] === 0 ? 0 : 1;
}

$GLOBALS['uu_suites'] = $GLOBALS['uu_suites'] ?? [];

function uu_register_suite(string $name, callable $fn): void
{
    $GLOBALS['uu_suites'][$name] = $fn;
}

function uu_run_suites(): int
{
    $rc = 0;
    foreach ($GLOBALS['uu_suites'] as $fn) {
        $rc |= (int)$fn();
    }
    return $rc;
}
