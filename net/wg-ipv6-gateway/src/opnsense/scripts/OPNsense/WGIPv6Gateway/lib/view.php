<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The Tunnels view (spec 7), shared by `tunnel.php list|status` and the API:
 * managed tunnels derived from core with their clamps and findings (the
 * render-failed finding included), and the WireGuard instances the plugin
 * does not manage, for Adopt. A tunnel whose Create saved but whose apply
 * has not completed carries the apply-pending finding (ruling 20). Reads
 * config; writes nothing.
 */

require_once __DIR__ . '/tunnels.php';
require_once __DIR__ . '/apply.php';

/**
 * @return array{tunnels: list<array>, global: list<array>, unmanaged: list<array{uuid: string, name: string, device: string, enabled: bool, endpoint: string}>, held: list<string>, core: array}
 */
function wgipv6_tunnel_view(): array {
    $mdl = new \OPNsense\WGIPv6Gateway\WGIPv6Gateway();
    $core = wgipv6_core_snapshot();
    $managed = wgipv6_split_csv((string)$mdl->managed);
    $derived = wgipv6_derive($core, $managed);
    $mssClamp = (string)$mdl->mss_clamp === '1';
    $pending = wgipv6_read_apply_pending();
    $tunnels = [];
    foreach ($derived['tunnels'] as $t) {
        $t['clamp'] = wgipv6_clamp_for($t, $mssClamp);
        if (isset($pending[$t['uuid']])) {
            $t['findings'][] = wgipv6_finding('apply-pending', 'saved at ' . date('Y-m-d H:i', $pending[$t['uuid']]) . '; its apply has not completed');
        }
        $tunnels[] = $t;
    }
    $global = $derived['global'];
    $renderLib = __DIR__ . '/render.php';
    if ((string)$mdl->enabled === '1' && is_readable($renderLib)) {
        require_once $renderLib;
        $rendered = wgipv6_read_rendered();
        if ($rendered === null || $rendered['failed']) {
            $global[] = wgipv6_finding(
                'render-failed',
                $rendered === null ? 'no render recorded since boot or deploy, or the last filter reload could not run the plugin' : $rendered['error']
            );
        }
    }
    $unmanaged = [];
    foreach ($core['instances'] as $uuid => $inst) {
        if (in_array((string)$uuid, $managed, true)) {
            continue;
        }
        $endpoint = '';
        if (count($inst['peers']) === 1 && isset($core['peers'][$inst['peers'][0]])) {
            $peer = $core['peers'][$inst['peers'][0]];
            $endpoint = $peer['serveraddress'] . ($peer['serverport'] !== '' ? ':' . $peer['serverport'] : '');
        }
        $unmanaged[] = [
            'uuid' => (string)$uuid, 'name' => $inst['name'], 'device' => 'wg' . $inst['instance'],
            'enabled' => $inst['enabled'], 'endpoint' => $endpoint,
        ];
    }
    return ['tunnels' => $tunnels, 'global' => $global, 'unmanaged' => $unmanaged, 'held' => wgipv6_split_csv((string)$mdl->held), 'core' => $core];
}
