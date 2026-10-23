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

namespace OPNsense\WGClientTunnels\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Base\UserException;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'wgclienttunnels';
    protected static $internalModelClass = '\OPNsense\WGClientTunnels\WGClientTunnels';

    /* the plugin's library: wgct_pending_refuses() */
    private const MIRROR_LIB = '/usr/local/opnsense/scripts/OPNsense/WGClientTunnels/lib/mirror.php';

    /**
     * Core's set, refused while the settings wait for their 3.1.0 migration (ruling R37): this model no longer
     * declares the managed list and the holds 3.7_1 stored in its node, so a save then would drop them before the
     * migration carries them over. Logged once per state, as every refused writer is.
     *
     * @throws UserException while the migration is pending
     */
    public function setAction()
    {
        if ($this->request->isPost()) {
            require_once self::MIRROR_LIB;
            if (wgct_pending_refuses('settings', 'wgct-action')) {
                throw new UserException(WGCT_MIGRATION_PENDING, gettext('WireGuard Upstream Tunnels'));
            }
        }
        return parent::setAction();
    }
}
