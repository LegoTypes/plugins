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
 */

namespace OPNsense\WGClientTunnels\Migrations;

use OPNsense\Base\BaseModelMigration;
use OPNsense\Core\Config;

/**
 * Engine 1.0.0 -> 1.1.0: 3.8's managed list, one comma-separated value, becomes the `tunnels` rows, one instance
 * per row, in the list's order. The 1.0.0 list is read from the raw config node by the reader the plugin uses while
 * this migration is pending (wgct_legacy_managed()), so the rows name what the pins named in that window. Core
 * serializes the model after run(), which drops the old node's text. A list that cannot be read throws: core then
 * logs it, migrates nothing and saves nothing, and the plugin keeps reading the 1.0.0 list, its pins held, until
 * run_migrations.php succeeds.
 */
class ENG1_1_0 extends BaseModelMigration
{
    /* the plugin's library, whose reader of the 1.0.0 list the migration shares */
    private const TUNNELS_LIB = '/usr/local/opnsense/scripts/OPNsense/WGClientTunnels/lib/tunnels.php';

    /**
     * @param \OPNsense\WGClientTunnels\Engine $model
     */
    public function run($model)
    {
        parent::run($model);
        $root = Config::getInstance()->object();
        if (!isset($root->OPNsense->WGClientTunnelsEngine->managed)) {
            /* no 1.0.0 list: a new install, or a 3.7_1 box whose settings migration writes the rows */
            return;
        }
        if (!is_readable(self::TUNNELS_LIB)) {
            throw new \RuntimeException(self::TUNNELS_LIB . ' cannot be read; the managed list stays where it is');
        }
        require_once self::TUNNELS_LIB;
        $model->setManaged(wgct_legacy_managed($root, 'WGClientTunnelsEngine', "the 1.0.0 engine's"));
    }
}
