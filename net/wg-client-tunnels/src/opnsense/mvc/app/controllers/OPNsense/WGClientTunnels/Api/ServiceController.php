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

namespace OPNsense\WGClientTunnels\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\WGClientTunnels\WGClientTunnels';
    protected static $internalServiceEnabled = 'enabled';
    protected static $internalServiceName = 'wgclienttunnels';

    /**
     * Reconfigure: re-assert the IPv6 routes of the managed tunnels.
     */
    public function reconfigureAction(): array
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        (new Backend())->configdRun('wgclienttunnels configure_routes');
        return ['status' => 'ok'];
    }

    /**
     * Create or repair the NO_DEFAULT4/NO_DEFAULT6 sentinel (spec 4.3); {dry: '1'} previews.
     */
    public function sentinelAction(): array
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        require_once '/usr/local/opnsense/scripts/OPNsense/WGClientTunnels/lib/apply.php';
        $dry = wgct_dry_flag($this->request->getPost('dry'));
        if ($dry === null) {
            return ['ok' => false, 'errors' => ['dry must be 1 (preview) or omitted/0 (run for real)']];
        }
        if (!$dry) {
            $this->throwReadOnly();
        }
        return wgct_configd_json($dry ? 'wgclienttunnels ensure_sentinel_dry' : 'wgclienttunnels ensure_sentinel', [], 300);
    }

    /**
     * Extend the base status with gateway detail from the status script.
     */
    public function statusAction()
    {
        $result = parent::statusAction();

        $backend = new Backend();
        $response = $backend->configdRun('wgclienttunnels status');
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
