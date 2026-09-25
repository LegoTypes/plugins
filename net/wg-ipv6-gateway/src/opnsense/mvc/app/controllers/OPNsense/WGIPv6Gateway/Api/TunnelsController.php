<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 */

namespace OPNsense\WGIPv6Gateway\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * Read-only view of the managed tunnels, derived from core on every request.
 */
class TunnelsController extends ApiControllerBase
{
    public function searchAction()
    {
        require_once '/usr/local/opnsense/scripts/OPNsense/WGIPv6Gateway/lib/tunnels.php';
        $mdl = new \OPNsense\WGIPv6Gateway\WGIPv6Gateway();
        $core = wgipv6_core_snapshot();
        $derived = wgipv6_derive($core, wgipv6_split_csv((string)$mdl->managed));

        $status = [];
        $raw = json_decode((new Backend())->configdRun('interface gateways status'), true);
        if (is_array($raw)) {
            foreach ($raw as $key => $row) {
                $name = is_array($row) && isset($row['name']) ? (string)$row['name'] : (string)$key;
                $status[$name] = is_array($row) ? (string)($row['status'] ?? '') : '';
            }
        }
        $held = array_flip(wgipv6_split_csv((string)$mdl->held));
        foreach ($derived['tunnels'] as &$t) {
            $t['gw4_status'] = $t['gw4'] !== null ? ($status[$t['gw4']] ?? 'unknown') : null;
            $t['gw6_status'] = $t['gw6'] !== null ? ($status[$t['gw6']] ?? 'unknown') : null;
            $t['held'] = $t['gw4'] !== null && isset($held[$core['gateways'][$t['gw4']]['uuid']]);
        }
        unset($t);
        return ['status' => 'ok', 'tunnels' => $derived['tunnels'], 'global' => $derived['global']];
    }
}
