#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Emits the IPv6 route set of every managed tunnel, derived from core config,
 * for wgipv6gw.sh.
 */

require "/usr/local/opnsense/mvc/script/load_phalcon.php";
require_once __DIR__ . '/lib/tunnels.php';

function sanitizeField($value): string
{
    return str_replace(["|", "\r", "\n"], ' ', trim((string)$value));
}

$mdl = new OPNsense\WGIPv6Gateway\WGIPv6Gateway();
if ((string)$mdl->enabled !== '1' || (string)$mdl->ipv6_routes !== '1') {
    exit(0);
}

$derived = wgipv6_derive(wgipv6_core_snapshot(), wgipv6_split_csv((string)$mdl->managed));
foreach ($derived['tunnels'] as $t) {
    if (!$t['enabled'] || wgipv6_blocked($t) || $t['gw4'] === null || $t['gw6'] === null
        || $t['ipv6_address'] === null || (string)$t['ipv6_next_hop'] === '') {
        continue;
    }
    echo implode('|', [
        '1',
        sanitizeField($t['device']),
        sanitizeField($t['ipv6_address']),
        sanitizeField($t['ipv6_next_hop']),
        sanitizeField($t['gw4']),
        sanitizeField($t['gw6']),
    ]) . PHP_EOL;
}
