<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Proves the selftest harness itself counts passes and failures.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';

uu_register_suite('harness', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $inner = ['fail' => 0, 'total' => 0];
    ob_start();
    uu_check($inner, 'a pass', true);
    uu_check($inner, 'a fail', false);
    $out = (string)ob_get_clean();
    uu_check($t, 'counts total', $inner['total'] === 2);
    uu_check($t, 'counts failures', $inner['fail'] === 1);
    uu_check($t, 'prints PASS and FAIL lines', str_contains($out, '[PASS] a pass') && str_contains($out, '[FAIL] a fail'));
    return uu_tally_report('harness', $t);
});
