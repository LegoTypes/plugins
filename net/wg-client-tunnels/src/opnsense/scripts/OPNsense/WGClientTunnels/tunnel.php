#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * WireGuard client tunnels from the command line (spec 2026-09-24 section
 * 6.4): list|status|reconcile|create|edit|remove|rebind|adopt|ensure-sentinel|
 * measure-mtu|apply [MODE] [--dry] [--json], and --selftest. See lib/cli.php. The
 * legacy includes are for Remove's interface_reset().
 */

require_once 'config.inc';
require_once 'util.inc';
require_once 'interfaces.inc';
require_once '/usr/local/opnsense/mvc/script/load_phalcon.php';
require_once __DIR__ . '/lib/cli.php';

exit(wgct_cli_main(array_slice($argv ?? [], 1)));
