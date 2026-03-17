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

function wgipv6gateway_services()
{
    $services = [];

    $mdl = new \OPNsense\WGIPv6Gateway\WGIPv6Gateway();
    if ((string)$mdl->enabled === '1') {
        $services[] = [
            'description' => gettext('WireGuard IPv6 Gateway'),
            'configd' => [
                'start' => ['wgipv6gateway start'],
                'stop' => ['wgipv6gateway stop'],
                'restart' => ['wgipv6gateway restart'],
            ],
            'nocheck' => true,
            'name' => 'wgipv6gateway',
        ];
    }

    return $services;
}

/**
 * Hook into WireGuard interface events to re-add IPv6 routes when tunnels restart.
 */
function wgipv6gateway_interface_newip($interface)
{
    $mdl = new \OPNsense\WGIPv6Gateway\WGIPv6Gateway();
    if ((string)$mdl->enabled !== '1') {
        return;
    }

    /* Only act on WireGuard interfaces */
    if (strpos($interface, 'wg') !== 0) {
        return;
    }

    /* Trigger route reconfiguration */
    configd_run('wgipv6gateway configure_routes');
}

function wgipv6gateway_xmlrpc_sync()
{
    $result = [];
    $result[] = [
        'description' => gettext('WireGuard IPv6 Gateway'),
        'section' => 'OPNsense.WGIPv6Gateway',
        'id' => 'wgipv6gateway',
    ];
    return $result;
}
