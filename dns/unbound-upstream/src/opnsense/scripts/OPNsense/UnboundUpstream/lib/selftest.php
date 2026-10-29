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
