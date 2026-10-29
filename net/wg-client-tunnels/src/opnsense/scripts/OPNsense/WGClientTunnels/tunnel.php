#!/usr/local/bin/php
<?php

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
 * WireGuard upstream tunnels from the command line:
 * list|status|reconcile|create|edit|remove|rebind|adopt|ensure-sentinel|measure-mtu|apply [MODE]|release-holds [--dry]
 * [--json], and --selftest. See lib/cli.php. The legacy includes are for Remove's interface_reset().
 */

require_once 'config.inc';
require_once 'util.inc';
require_once 'interfaces.inc';
require_once '/usr/local/opnsense/mvc/script/load_phalcon.php';
$wgctArgs = array_slice($argv ?? [], 1);
$wgctJson = in_array('--json', $wgctArgs, true);
/* release-holds is the package removal's: it exits 0 whatever happens, so pkg delete completes */
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
