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
 * Register route reconciliation on the events that affect our host routes.
 *
 * Nothing in the base system creates these: system_interface_route() handles
 * far-gateway host routes for inet only and rejects any non-IPv4 gateway, so
 * the IPv6 side exists solely because this plugin adds it. That makes "bootup"
 * the load-bearing hook -- without it no route is ever created after a cold
 * start. "monitor" (end of system_routing_configure) and "newwanip" re-assert
 * the routes after gateway or addressing changes.
 */
function wgipv6gateway_configure()
{
    return [
        'bootup' => ['wgipv6gateway_configure_do'],
        'monitor' => ['wgipv6gateway_configure_do'],
        'newwanip' => ['wgipv6gateway_configure_do'],
    ];
}

/**
 * Re-add any missing IPv6 addresses and gateway host routes. Idempotent, so it
 * is safe to run on every event; only actual repairs are logged.
 *
 * Invoked directly rather than through configd because "monitor" fires from
 * inside a configd-run action, and re-entering configd there would deadlock.
 */
function wgipv6gateway_configure_do($verbose = false)
{
    $mdl = new \OPNsense\WGIPv6Gateway\WGIPv6Gateway();
    if ((string)$mdl->enabled !== '1') {
        return;
    }

    if ($verbose) {
        echo 'Configuring WireGuard IPv6 gateway routes...';
        flush();
    }

    mwexecf('/usr/local/opnsense/scripts/OPNsense/WGIPv6Gateway/wgipv6gw.sh reconcile');

    if ($verbose) {
        echo "done.\n";
    }
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
