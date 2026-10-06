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

namespace OPNsense\WanFailover\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\WanFailover\WanFailover';
    protected static $internalServiceEnabled = 'enabled';
    protected static $internalServiceName = 'wanfailover';

    /**
     * Apply while enabled reloads (one evaluation) instead of stop + start: stop releases every hold, so a
     * restart on each Apply would put a held, lossy WAN back in service. Disable still runs stop.
     */
    protected function reconfigureForceRestart()
    {
        return false;
    }

    /**
     * Status for the page: per-WAN readings, held flags, pending failbacks, core-contract findings.
     */
    public function holdsAction(): array
    {
        $data = json_decode(trim((new Backend())->configdRun('wanfailover holds')), true);
        return is_array($data) ? $data : ['status' => 'failed'];
    }

    /**
     * Release every gateway the plugin holds, now.
     */
    public function releaseAction(): array
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $this->throwReadOnly();
        $result = trim((new Backend())->configdRun('wanfailover release'));
        return ['status' => $result === 'OK' ? 'ok' : 'failed'];
    }

    /**
     * End the failback delay for every pending failback, now.
     */
    public function failbacknowAction(): array
    {
        if (!$this->request->isPost()) {
            return ['status' => 'failed'];
        }
        $this->throwReadOnly();
        $result = trim((new Backend())->configdRun('wanfailover failback_now'));
        return ['status' => $result === 'OK' ? 'ok' : 'failed'];
    }
}
