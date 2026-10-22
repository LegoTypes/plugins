#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * WireGuard upstream tunnels from the command line (spec 2026-09-24 section
 * 6.4): list|status|reconcile|create|edit|remove|rebind|adopt|ensure-sentinel|
 * measure-mtu|apply [MODE]|release-holds [--dry] [--json], and --selftest. See
 * lib/cli.php. The legacy includes are for Remove's interface_reset().
 */

require_once 'config.inc';
require_once 'util.inc';
require_once 'interfaces.inc';
require_once '/usr/local/opnsense/mvc/script/load_phalcon.php';
$wgctArgs = array_slice($argv ?? [], 1);
$wgctJson = in_array('--json', $wgctArgs, true);
/* release-holds is the package removal's (spec 3.11): it exits 0 whatever happens, so pkg delete completes */
$wgctCommand = array_values(array_filter($wgctArgs, fn (string $a): bool => strncmp($a, '--', 2) !== 0))[0] ?? '';
$wgctFailExit = $wgctCommand === 'release-holds' ? 0 : 1;
if (!is_readable(__DIR__ . '/entry.php')) {
    exit($wgctFailExit);
}
require_once __DIR__ . '/entry.php';
/* a library that cannot load, or the removal marker, fails the command: a JSON failure for configd's callers, a
 * line for a person, exit 1; release-holds exits 0 and runs on while the marker exists, as the removal runs it */
wgct_entry_load('tunnel.php', 'wgct-cli', ['cli.php'], function (string $error) use ($wgctJson): string {
    return $wgctJson ? (string)json_encode(['ok' => false, 'errors' => [$error]]) : 'tunnel.php: ' . $error;
}, $wgctFailExit, $wgctCommand === 'release-holds');

exit(wgct_cli_main($wgctArgs));
