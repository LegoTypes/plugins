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

function wgclienttunnels_services()
{
    $services = [];

    $mdl = new \OPNsense\WGClientTunnels\WGClientTunnels();
    if ((string)$mdl->enabled === '1') {
        $services[] = [
            'description' => gettext('WireGuard Upstream Tunnels'),
            'configd' => [
                'start' => ['wgclienttunnels start'],
                'stop' => ['wgclienttunnels stop'],
                'restart' => ['wgclienttunnels restart'],
            ],
            'nocheck' => true,
            'name' => 'wgclienttunnels',
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
function wgclienttunnels_configure()
{
    return [
        'bootup' => ['wgclienttunnels_configure_do'],
        'monitor' => ['wgclienttunnels_configure_do'],
        'newwanip' => ['wgclienttunnels_configure_do'],
    ];
}

/**
 * Re-add any missing IPv6 addresses and gateway host routes. Idempotent, so it
 * is safe to run on every event; only actual repairs are logged.
 *
 * Invoked directly rather than through configd because "monitor" fires from
 * inside a configd-run action, and re-entering configd there would deadlock.
 */
function wgclienttunnels_configure_do($verbose = false)
{
    $mdl = new \OPNsense\WGClientTunnels\WGClientTunnels();
    if ((string)$mdl->enabled !== '1') {
        return;
    }

    if ($verbose) {
        echo 'Configuring WireGuard upstream tunnel IPv6 routes...';
        flush();
    }

    mwexecf('/usr/local/opnsense/scripts/OPNsense/WGClientTunnels/wgct.sh reconcile');

    if ($verbose) {
        echo "done.\n";
    }
}

/**
 * Rendered enforcement: WAN pins, inner-source blocks and the MSS anchor,
 * derived from the managed tunnels at every filter reload (boot included).
 * lib/render.php catches every error, so a plugin fault never aborts core's
 * filter reload; it is reported as the render-failed finding instead.
 *
 * A require_once of a file that does not exist is a fatal E_COMPILE_ERROR,
 * not a \Throwable -- the try/catch below cannot catch it. During the deploy
 * swap window (plugin directories replaced while this .inc file, which core
 * loads separately, stays) or after a failed deploy, the library can be
 * briefly or permanently missing, and any filter reload (a gateway alarm,
 * boot) must not die because of it. is_readable() turns that into an
 * ordinary logged skip instead.
 *
 * Both failure branches drop the rendered record: nothing was rendered, so a
 * filter reload now leaves pf without the pins and anchor, and a record
 * still describing them would read as current. With it gone, the next
 * reconcile sees "no rendered record" and asks for a reload, and the Tunnels
 * tab shows render-failed.
 */
function wgclienttunnels_firewall($fw)
{
    $lib = '/usr/local/opnsense/scripts/OPNsense/WGClientTunnels/lib/render.php';
    if (!is_readable($lib) || !is_readable(dirname($lib) . '/tunnels.php')) {
        syslog(LOG_ERR, '[wgct-render] plugin library missing; rules not rendered');
        wgclienttunnels_forget_render();
        return;
    }
    try {
        require_once $lib;
        wgct_render_firewall($fw);
    } catch (\Throwable $e) {
        syslog(LOG_ERR, '[wgct-render] hook failed: ' . $e->getMessage());
        wgclienttunnels_forget_render();
    }
}

/**
 * Remove the rendered record. The path is a literal copy of render.php's
 * WGCT_RENDERED_FILE because render.php, which defines that constant, may
 * be the very file that is missing or failed to load. The record may not
 * exist; a failed unlink is ignored (the next successful render rewrites it).
 */
function wgclienttunnels_forget_render(): void
{
    $rendered = '/var/run/wgclienttunnels/rendered.json';
    if (is_file($rendered)) {
        unlink($rendered);
    }
}

function wgclienttunnels_xmlrpc_sync()
{
    $result = [];
    $result[] = [
        'description' => gettext('WireGuard Upstream Tunnels'),
        'section' => 'OPNsense.WGClientTunnels',
        'id' => 'wgclienttunnels',
    ];
    return $result;
}
