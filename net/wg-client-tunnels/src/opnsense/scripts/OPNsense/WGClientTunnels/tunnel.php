#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * WireGuard upstream tunnels from the command line (spec 2026-09-24 section
 * 6.4): list|status|reconcile|create|edit|remove|rebind|adopt|ensure-sentinel|
 * measure-mtu|apply [MODE] [--dry] [--json], and --selftest. See lib/cli.php. The
 * legacy includes are for Remove's interface_reset().
 */

require_once 'config.inc';
require_once 'util.inc';
require_once 'interfaces.inc';
require_once '/usr/local/opnsense/mvc/script/load_phalcon.php';
if (!is_readable(__DIR__ . '/entry.php')) {
    exit(1);
}
require_once __DIR__ . '/entry.php';
/* a library that cannot load fails the command: a JSON failure for configd's callers, a line for a person, exit 1 */
$wgctJson = in_array('--json', $argv ?? [], true);
wgct_entry_load('tunnel.php', 'wgct-cli', ['cli.php'], function (string $error) use ($wgctJson): string {
    return $wgctJson ? (string)json_encode(['ok' => false, 'errors' => [$error]]) : 'tunnel.php: ' . $error;
}, 1);

exit(wgct_cli_main(array_slice($argv ?? [], 1)));
