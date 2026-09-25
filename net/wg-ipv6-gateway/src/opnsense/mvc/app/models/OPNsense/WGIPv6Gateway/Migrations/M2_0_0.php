<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * 1.x -> 2.0.0: the per-gateway rows go; every tunnel is derived from core
 * config (spec 2026-09-24). run() reads the old rows from the raw config
 * before the model serializes (which drops them), adopts the instances they
 * point at, converts the legacy held file to gateway UUIDs, and turns every
 * behaviour on when the plugin was enabled. Differences between a row and
 * core are logged; core wins.
 */

namespace OPNsense\WGIPv6Gateway\Migrations;

use OPNsense\Base\BaseModelMigration;
use OPNsense\Core\Config;

class M2_0_0 extends BaseModelMigration
{
    public function run($model)
    {
        parent::run($model);
        require_once '/usr/local/opnsense/scripts/OPNsense/WGIPv6Gateway/lib/tunnels.php';

        $rows = [];
        $old = Config::getInstance()->object()->OPNsense->WGIPv6Gateway ?? null;
        if ($old !== null && isset($old->gateways->gateway)) {
            foreach ($old->gateways->gateway as $row) {
                $rows[] = [
                    'enabled' => (string)$row->enabled === '1',
                    'ipv4_gateway' => (string)$row->ipv4_gateway,
                    'ipv6_gw_address' => (string)$row->ipv6_gw_address,
                    'ipv6_address' => (string)$row->ipv6_address,
                ];
            }
        }
        $heldNames = [];
        $raw = @file_get_contents(WGIPV6_LEGACY_HELD_FILE);
        $decoded = $raw !== false ? json_decode($raw, true) : null;
        if (is_array($decoded)) {
            $heldNames = array_values(array_filter($decoded, 'is_string'));
        }

        $plan = wgipv6_migration_plan(wgipv6_core_snapshot(), $rows, $heldNames);
        $model->managed = implode(',', $plan['managed']);
        $model->held = implode(',', $plan['held']);
        $on = (string)$model->enabled === '1' ? '1' : '0';
        $model->health_mirror = $on;
        $model->ipv6_routes = $on;
        $model->default_guard = $on;
        foreach ($plan['notes'] as $note) {
            syslog(LOG_NOTICE, "[wgipv6gw-migrate] {$note}");
        }
        syslog(LOG_NOTICE, sprintf(
            '[wgipv6gw-migrate] 2.0.0: managing %d instance(s), %d held gateway(s)',
            count($plan['managed']),
            count($plan['held'])
        ));
    }
}
