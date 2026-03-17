<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
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

namespace OPNsense\WGIPv6Gateway\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\WGIPv6Gateway\WGIPv6Gateway';
    protected static $internalServiceEnabled = 'enabled';
    protected static $internalServiceName = 'wgipv6gateway';

    /**
     * Reconfigure: ensure IPv6 gateway objects exist, then apply routes.
     */
    public function reconfigureAction()
    {
        // Create any missing IPv6 gateway objects in Routing model
        $settingsCtrl = new SettingsController();
        $settingsCtrl->ensureGatewayObjectsAction();

        // Apply route configuration via configd
        $backend = new Backend();
        $response = $backend->configdRun('wgipv6gateway configure_routes');
        return ['status' => 'ok'];
    }

    /**
     * Extend the base status with gateway detail from the status script.
     */
    public function statusAction()
    {
        $result = parent::statusAction();

        $backend = new Backend();
        $response = $backend->configdRun('wgipv6gateway status');
        // The status script outputs a "is running" line followed by JSON;
        // extract the JSON portion.
        if (preg_match('/(\{.*\})/s', $response, $matches)) {
            $data = json_decode($matches[1], true);
            if ($data !== null) {
                $result['gateways'] = $data['gateways'] ?? [];
            }
        }

        return $result;
    }
}
