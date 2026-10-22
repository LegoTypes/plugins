#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Log once when core stops matching the internals the plugin copies (wgct_core_contract()).
 * Run by wgct.sh reconcile. Changes nothing; the tunnel list shows the core-contract finding.
 * Silent while the plugin is disabled, as the finding is; one run at a time (the minute cron and a
 * queued reconcile can overlap), so a drift is logged once.
 */

require '/usr/local/opnsense/mvc/script/load_phalcon.php';
require_once __DIR__ . '/lib/apply.php';

if (!(new \OPNsense\WGClientTunnels\WGClientTunnels())->enabled->isEqual('1')) {
    exit(0);
}
$state = WGCT_RUN_DIR;
if (!wgct_state_dir($state)) {
    exit(0);
}
$lock = fopen($state . '/core_contract.lock', 'ce');
if ($lock === false || !flock($lock, LOCK_EX | LOCK_NB)) {
    exit(0);
}
wgct_core_contract_log(wgct_core_contract(), $state . '/core_contract.logged', 'wgct_log');
exit(0);
