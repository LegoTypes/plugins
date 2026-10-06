<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Runs every suite registered by tests/test_*.php. Exit 0 only when all pass.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/selftest.php';

foreach (glob(__DIR__ . '/test_*.php') ?: [] as $file) {
    require_once $file;
}
exit(wf_run_suites());
