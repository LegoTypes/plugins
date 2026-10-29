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
 * Prints a line protocol: `state|on`, `state|off` (IPv6 routes off) or `state|disabled` (the plugin off) first,
 * then `route|dev|addr|nexthop|gw4|gw6|monitor6` for each tunnel whose IPv6 route set is configured (monitor6
 * empty when unmonitored) and `keep|dev` for each blocked tunnel whose recorded routes are kept. While a
 * migration of the plugin's stored data is pending the first line is `state|pending`: the route set then changes
 * nothing, and the route lines, from the managed list the older version stored, are only for the status listing.
 * Only wgct.sh reads it, and PHP diagnostics must go to stderr (wgct.sh runs it with -d display_errors=stderr).
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
try {
    $derived = $enabled && $ipv6Routes
        ? wgct_derive(wgct_core_tunnel_snapshot(), wgct_managed())
        : ['tunnels' => [], 'global' => []];
} catch (\RuntimeException $e) {
    /* the managed list cannot be read (a pending migration's unreadable 3.7_1 list): nothing on stdout, so wgct.sh
       changes no route and logs this failure once */
    fwrite(STDERR, $e->getMessage() . PHP_EOL);
    exit(1);
}
$lines = wgct_route_lines($derived, $enabled, $ipv6Routes);
echo implode(PHP_EOL, wgct_migration_pending() ? wgct_route_lines_pending($lines) : $lines) . PHP_EOL;
