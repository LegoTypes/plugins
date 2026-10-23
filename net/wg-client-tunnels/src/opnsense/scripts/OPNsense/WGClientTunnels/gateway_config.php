#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Prints a line protocol: `state|on` or `state|off` first, then `route|dev|addr|nexthop|gw4|gw6|monitor6` for
 * each tunnel whose IPv6 route set is configured (monitor6 empty when unmonitored) and `keep|dev` for each
 * blocked tunnel whose recorded routes are kept. While the plugin settings wait for their 3.1.0 migration the
 * first line is `state|pending` (ruling R37): the route set then changes nothing, and the route lines, from the
 * managed list 3.7_1 stored, are only for the status listing. Only wgct.sh reads it, and PHP diagnostics must go
 * to stderr (wgct.sh runs it with -d display_errors=stderr).
 */

require "/usr/local/opnsense/mvc/script/load_phalcon.php";
if (!is_readable(__DIR__ . '/entry.php')) {
    exit(0);
}
require_once __DIR__ . '/entry.php';
/* nothing on stdout when the library cannot load: wgct.sh then changes no route and notes the missing state line */
wgct_entry_load('gateway_config.php', 'wgct-routes', ['tunnels.php']);

$mdl = new OPNsense\WGClientTunnels\WGClientTunnels();
$enabled = $mdl->enabled->isEqual('1');
$ipv6Routes = $mdl->ipv6_routes->isEqual('1');
$derived = $enabled && $ipv6Routes
    ? wgct_derive(wgct_core_snapshot(), wgct_managed())
    : ['tunnels' => [], 'global' => []];
$lines = wgct_route_lines($derived, $enabled, $ipv6Routes);
echo implode(PHP_EOL, wgct_migration_pending() ? wgct_route_lines_pending($lines) : $lines) . PHP_EOL;
