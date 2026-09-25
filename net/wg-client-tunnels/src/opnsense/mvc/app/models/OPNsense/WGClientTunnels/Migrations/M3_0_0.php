<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * 2.x -> 3.0.0: up to 2.2 the plugin was os-wg-ipv6-gateway, with its
 * settings at //OPNsense/WGIPv6Gateway (spec 2026-09-24 section 8.4). run()
 * copies the switches, `managed` and `held` from that section; post()
 * removes it. Both land in the one save migrate.php (or convert_config() at
 * boot) makes.
 *
 * The removal waits for post(), which core calls only once this model has
 * serialized: run_migrations.php saves the config when any model migrated,
 * so a section removed in run() would be saved away with nothing in its
 * place if this model's serialize then failed. The mapping is
 * lib/migration.php, shared with `migrate.php --dry` and its self-test.
 */

namespace OPNsense\WGClientTunnels\Migrations;

use OPNsense\Base\BaseModelMigration;
use OPNsense\Core\Config;

class M3_0_0 extends BaseModelMigration
{
    private const LIB = '/usr/local/opnsense/scripts/OPNsense/WGClientTunnels/lib/migration.php';

    /**
     * @param \OPNsense\WGClientTunnels\WGClientTunnels $model
     */
    public function run($model)
    {
        try {
            parent::run($model);
            require_once self::LIB;
            $plan = wgct_legacy_settings(wgct_read_legacy_node(Config::getInstance()->object()));
            if ($plan['error'] !== null) {
                throw new \RuntimeException($plan['error']);
            }
            foreach ($plan['notes'] as $note) {
                syslog(LOG_NOTICE, "[wgct-migrate] {$note}");
            }
            if ($plan['values'] === null) {
                return;   // no old section: a fresh install keeps the defaults, everything off
            }
            foreach ($plan['values'] as $field => $value) {
                $model->$field = $value;
            }
            syslog(LOG_NOTICE, '[wgct-migrate] 3.0.0: ' . strtok(wgct_migration_summary($plan), "\n"));
        } catch (\Throwable $e) {
            /* BaseModel::runMigrations() catches only \Exception; convert_config()
             * runs every model's migrations at boot, so a \Error escaping here
             * would abort every model after ours. */
            throw new \Exception('WGClientTunnels 3.0.0 migration: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * @param \OPNsense\WGClientTunnels\WGClientTunnels $model
     */
    public function post($model)
    {
        try {
            require_once self::LIB;
            if (wgct_remove_legacy_node(Config::getInstance()->object())) {
                syslog(LOG_NOTICE, '[wgct-migrate] 3.0.0: removed the ' . WGCT_LEGACY_NODE . ' section');
            }
        } catch (\Throwable $e) {
            throw new \Exception('WGClientTunnels 3.0.0 migration, removing the old section: ' . $e->getMessage(), 0, $e);
        }
    }
}
