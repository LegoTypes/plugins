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
    require_once __DIR__ . '/lib/render.php';
    $tunnelsRc = wgipv6_tunnels_selftest();
    $renderRc = wgipv6_render_selftest();
    exit($tunnelsRc !== 0 || $renderRc !== 0 ? 1 : 0);
}

require "/usr/local/opnsense/mvc/script/load_phalcon.php";

$mdl = new OPNsense\WGIPv6Gateway\WGIPv6Gateway();
$mssClamp = (string)$mdl->mss_clamp === '1';
$derived = wgipv6_derive(wgipv6_core_snapshot(), wgipv6_split_csv((string)$mdl->managed));
foreach ($derived['tunnels'] as &$t) {
    $t['clamp'] = wgipv6_clamp_for($t, $mssClamp);
}
unset($t);

$renderLib = __DIR__ . '/lib/render.php';
if ((string)$mdl->enabled === '1' && is_readable($renderLib)) {
    require_once $renderLib;
    $rendered = wgipv6_read_rendered();
    if ($rendered === null || $rendered['failed']) {
        $derived['global'][] = wgipv6_finding(
            'render-failed',
            $rendered === null ? 'no render recorded since boot or deploy' : $rendered['error']
        );
    }
}

if (in_array('--json', $argv ?? [], true)) {
    echo json_encode($derived, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
    exit(0);
}
foreach ($derived['global'] as $f) {
    printf("GLOBAL %s: %s -- %s\n", $f['code'], $f['detail'], $f['fix']);
}
foreach ($derived['tunnels'] as $t) {
    $clamp = $t['clamp'] !== null
        ? sprintf(
            ' clamp v4 %s v6 %s',
            $t['clamp']['v4'] !== null ? $t['clamp']['v4'] : '-',
            $t['clamp']['v6'] !== null ? $t['clamp']['v6'] : '-'
        )
        : '';
    printf(
        "%-18s %-5s %-6s endpoint %-22s WAN %-12s mtu %d gw4 %s gw6 %s%s%s%s\n",
        $t['name'] !== '' ? $t['name'] : $t['uuid'],
        $t['device'],
        (string)$t['interface'],
        $t['endpoint'],
        (string)$t['bound_wan'],
        $t['mtu'],
        (string)$t['gw4'],
        (string)$t['gw6'],
        $t['enabled'] ? '' : ' (disabled)',
        $t['enforceable'] ? '' : ' (not enforced)',
        $clamp
    );
    foreach ($t['findings'] as $f) {
        printf("    %s%s: %s -- %s\n", $f['blocking'] ? '[B] ' : '', $f['code'], $f['detail'], $f['fix']);
    }
}
