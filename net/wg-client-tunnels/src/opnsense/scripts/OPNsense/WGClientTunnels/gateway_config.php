#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Prints a line protocol: `state|on` or `state|off` first, then `route|dev|addr|nexthop|gw4|gw6|monitor6` for
 * each tunnel whose IPv6 route set is configured (monitor6 empty when unmonitored) and `keep|dev` for each
 * blocked tunnel whose recorded routes are kept. Only wgct.sh reads it, and PHP diagnostics must go to
 * stderr (wgct.sh runs it with -d display_errors=stderr).
 */

require "/usr/local/opnsense/mvc/script/load_phalcon.php";
require_once __DIR__ . '/lib/tunnels.php';

$mdl = new OPNsense\WGClientTunnels\WGClientTunnels();
$enabled = $mdl->enabled->isEqual('1');
$ipv6Routes = $mdl->ipv6_routes->isEqual('1');
$derived = $enabled && $ipv6Routes
    ? wgct_derive(wgct_core_snapshot(), wgct_split_csv((string)$mdl->managed))
    : ['tunnels' => [], 'global' => []];
echo implode(PHP_EOL, wgct_route_lines($derived, $enabled, $ipv6Routes)) . PHP_EOL;
