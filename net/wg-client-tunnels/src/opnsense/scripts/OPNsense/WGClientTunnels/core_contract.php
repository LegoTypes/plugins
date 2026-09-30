#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Log once when core stops matching the internals the plugin copies (wgct_core_contract()).
 * Run by wgct.sh reconcile. Changes nothing; the tunnel list shows the core-contract finding.
 */

require_once __DIR__ . '/lib/apply.php';

openlog('wgct', LOG_PID, LOG_USER);
$state = getenv('WGCT_STATE_DIR') ?: '/var/run/wgclienttunnels';
if (!is_dir($state)) {
    mkdir($state, 0755, true);
}
wgct_core_contract_log(wgct_core_contract(), $state . '/core_contract.logged', 'syslog');
exit(0);
