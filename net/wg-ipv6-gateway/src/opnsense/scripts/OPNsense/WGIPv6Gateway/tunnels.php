#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Managed WireGuard tunnels, derived from core config, with their findings.
 * Read-only.
 *
 * Usage: tunnels.php [--json] [--selftest]
 */

require_once __DIR__ . '/lib/tunnels.php';

if (in_array('--selftest', $argv ?? [], true)) {
    exit(wgipv6_tunnels_selftest());
}

require "/usr/local/opnsense/mvc/script/load_phalcon.php";

$mdl = new OPNsense\WGIPv6Gateway\WGIPv6Gateway();
$derived = wgipv6_derive(wgipv6_core_snapshot(), wgipv6_split_csv((string)$mdl->managed));

if (in_array('--json', $argv ?? [], true)) {
    echo json_encode($derived, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
    exit(0);
}
foreach ($derived['global'] as $f) {
    printf("GLOBAL %s: %s -- %s\n", $f['code'], $f['detail'], $f['fix']);
}
foreach ($derived['tunnels'] as $t) {
    printf(
        "%-18s %-5s %-6s endpoint %-22s WAN %-12s mtu %d gw4 %s gw6 %s%s%s\n",
        $t['name'] !== '' ? $t['name'] : $t['uuid'],
        $t['device'],
        (string)$t['interface'],
        $t['endpoint'],
        (string)$t['bound_wan'],
        $t['mtu'],
        (string)$t['gw4'],
        (string)$t['gw6'],
        $t['enabled'] ? '' : ' (disabled)',
        $t['enforceable'] ? '' : ' (not enforced)'
    );
    foreach ($t['findings'] as $f) {
        printf("    %s%s: %s -- %s\n", $f['blocking'] ? '[B] ' : '', $f['code'], $f['detail'], $f['fix']);
    }
}
