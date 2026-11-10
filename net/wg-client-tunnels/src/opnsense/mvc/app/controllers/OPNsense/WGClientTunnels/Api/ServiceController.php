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

use OPNsense\Base\ApiMutableServiceControllerBase;

/**
 * The service API of the plugin. A read-only user (user-config-readonly) changes nothing through it: the four
 * stock actions that start, stop or reload the route set (start, stop, restart, reconfigure) each refuse such a
 * user before anything else, for any request method, and the sentinel action refuses such a user's POST (a request
 * that is no POST it answers as failed, for every user). status is open to every holder of the page's privilege.
 */
class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\WGClientTunnels\WGClientTunnels';
    protected static $internalServiceEnabled = 'enabled';
    protected static $internalServiceName = 'wgclienttunnels';

    /**
     * Apply reloads the route set in place; a restart would remove every tunnel's IPv6 address and routes
     */
    protected function reconfigureForceRestart(): bool
    {
        return false;
    }

    /**
     * Start the route set; refused for a read-only user.
     *
     * @return array
     */
    public function startAction(): array
    {
        $this->throwReadOnly();
        return parent::startAction();
    }

    /**
     * Stop: remove every tunnel's IPv6 address and routes and the footprint; refused for a read-only user.
     *
     * @return array
     */
    public function stopAction(): array
    {
        $this->throwReadOnly();
        return parent::stopAction();
    }

    /**
     * Stop, then start; refused for a read-only user.
     *
     * @return array
     */
    public function restartAction(): array
    {
        $this->throwReadOnly();
        return parent::restartAction();
    }

    /**
     * The page's Apply: core's reconfigure flow, which stops a disabled plugin, starts a stopped one and reloads a
     * running one; refused for a read-only user.
     *
     * @return array
     */
    public function reconfigureAction(): array
    {
        $this->throwReadOnly();
        return parent::reconfigureAction();
    }

    /**
     * Create or repair the NO_DEFAULT4/NO_DEFAULT6 sentinel; {dry: '1'} previews.
     */
    public function sentinelAction(): array
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed', 'result' => 'failed'];
        }
        $this->throwReadOnly();
        require_once '/usr/local/opnsense/scripts/OPNsense/WGClientTunnels/lib/apply.php';
        $dry = wgct_dry_flag($this->request->getPost('dry'));
        if ($dry === null) {
            return ['status' => 'failed', 'ok' => false, 'errors' => ['dry must be 1 (preview) or omitted/0 (run for real)']];
        }
        return wgct_configd_json($dry ? 'wgclienttunnels ensure_sentinel_dry' : 'wgclienttunnels ensure_sentinel', [], 300);
    }
}
