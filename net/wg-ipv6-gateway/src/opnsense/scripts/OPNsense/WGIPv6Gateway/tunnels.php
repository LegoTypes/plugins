#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * `tunnel.php list` under its old name, until the S4 rename (spec 6.4):
 *   tunnels.php [--json]    = tunnel.php [--json] list
 *   tunnels.php --selftest  = tunnel.php --selftest
 */

require_once '/usr/local/opnsense/mvc/script/load_phalcon.php';
require_once __DIR__ . '/lib/cli.php';

$args = array_slice($argv ?? [], 1);
exit(wgipv6_cli_main(in_array('--selftest', $args, true)
    ? ['--selftest']
    : array_merge(array_values(array_intersect($args, ['--json'])), ['list'])));
