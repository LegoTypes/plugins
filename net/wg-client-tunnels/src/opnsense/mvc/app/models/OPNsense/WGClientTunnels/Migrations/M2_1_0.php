<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * 2.0.0 -> 2.1.0: switches for the rendered WAN pins, inner-source blocks and
 * MSS clamp. On for an enabled plugin (it replaces the site's stored pins),
 * off on a fresh install.
 */

namespace OPNsense\WGClientTunnels\Migrations;

use OPNsense\Base\BaseModelMigration;

class M2_1_0 extends BaseModelMigration
{
    public function run($model)
    {
        try {
            parent::run($model);
            $on = (string)$model->enabled === '1' ? '1' : '0';
            $model->wan_pins = $on;
            $model->inner_source = $on;
            $model->mss_clamp = $on;
        } catch (\Throwable $e) {
            /* BaseModel::runMigrations() catches only \Exception; convert_config()
             * runs every model's migrations at boot, so a \Error escaping here
             * would abort every model after ours. Wrap it so core logs it, marks
             * this migration failed, and moves on. */
            throw new \Exception('WGClientTunnels 2.1.0 migration: ' . $e->getMessage(), 0, $e);
        }
    }
}
