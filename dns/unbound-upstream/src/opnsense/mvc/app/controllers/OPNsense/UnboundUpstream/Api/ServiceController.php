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

namespace OPNsense\UnboundUpstream\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\UnboundUpstream\UnboundUpstream';
    protected static $internalServiceEnabled = 'enabled';
    protected static $internalServiceName = 'unboundupstream';

    /**
     * Reload the filter inside the stock flow, after stop and before start: the rendered rules (the block rule
     * and the per-member passes) go with a disable, and are loaded before an enabled evaluation installs the
     * resolver's route.
     */
    protected function invokeFirewallReload()
    {
        return true;
    }

    /**
     * Apply while enabled reloads (one evaluation, start when the minute job is missing) instead of stop + start:
     * stop leaves tunnel mode and drops the queries in flight, so a restart on each Apply would bounce household
     * DNS through the fallback forwarders. Disable still runs stop.
     */
    protected function reconfigureForceRestart()
    {
        return false;
    }

    /**
     * Start changes the running service, so a read-only user (user-config-readonly) is refused, before the request
     * method is looked at.
     *
     * @throws \OPNsense\Base\UserException for a read-only user
     * @throws \Exception when the configd action fails
     */
    public function startAction(): array
    {
        $this->throwReadOnly();
        return parent::startAction();
    }

    /**
     * Stop leaves tunnel mode, so a read-only user is refused, as for start.
     *
     * @throws \OPNsense\Base\UserException for a read-only user
     * @throws \Exception when the configd action fails
     */
    public function stopAction(): array
    {
        $this->throwReadOnly();
        return parent::stopAction();
    }

    /**
     * Restart runs the start action, so a read-only user is refused, as for start.
     *
     * @throws \OPNsense\Base\UserException for a read-only user
     * @throws \Exception when the configd action fails
     */
    public function restartAction(): array
    {
        $this->throwReadOnly();
        return parent::restartAction();
    }

    /**
     * Apply runs stop, start or one evaluation, whichever the saved settings and the running service call for, and
     * a filter reload, so a read-only user is refused, as for start.
     *
     * @throws \OPNsense\Base\UserException for a read-only user
     * @throws \Exception when a configd action fails
     * @throws \ReflectionException when the model cannot be instantiated
     */
    public function reconfigureAction(): array
    {
        $this->throwReadOnly();
        return parent::reconfigureAction();
    }

    /**
     * Status for the page and for a status poller: mode, member, live and configured forwarders, the route, the
     * rules, the checks, every member's verdict and the contract findings. It changes nothing and takes no
     * read-only guard, so a key that holds only the status privilege reads it.
     */
    public function stateAction(): array
    {
        $data = json_decode(trim((new Backend())->configdRun('unboundupstream state')), true);
        return is_array($data) ? $data : ['status' => 'failed'];
    }
}
