<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Proves the selftest harness itself counts passes and failures.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/selftest.php';

wf_register_suite('harness', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $inner = ['fail' => 0, 'total' => 0];
    ob_start();
    wf_check($inner, 'a pass', true);
    wf_check($inner, 'a fail', false);
    $out = (string)ob_get_clean();
    wf_check($t, 'counts total', $inner['total'] === 2);
    wf_check($t, 'counts failures', $inner['fail'] === 1);
    wf_check($t, 'prints PASS and FAIL lines', str_contains($out, '[PASS] a pass') && str_contains($out, '[FAIL] a fail'));
    return wf_tally_report('harness', $t);
});
