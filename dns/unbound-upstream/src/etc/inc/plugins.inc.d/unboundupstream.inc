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

/*
 * Hooks. plugins_scan() sorts the file names, so this file runs after unbound.inc: on unbound_start Unbound's
 * restart is already launched when the evaluate below is queued (spec 3.1). Every hook only queues
 * `configctl -d unboundupstream evaluate` and returns; none can throw into core.
 */

function unboundupstream_syslog()
{
    return ['unboundupstream' => ['facility' => ['unboundupstream']]];
}

function unboundupstream_configure()
{
    return [
        'bootup' => ['unboundupstream_queue'],
        'dns' => ['unboundupstream_queue'],
        'local' => ['unboundupstream_queue'],
        'newwanip' => ['unboundupstream_queue'],
        'unbound_start' => ['unboundupstream_queue'],
        'monitor' => ['unboundupstream_queue_monitor:2'],
    ];
}

/**
 * Queue one evaluation, detached.
 */
function unboundupstream_queue(bool $verbose = false): void
{
    try {
        if ($verbose) {
            echo 'Queueing the Unbound upstream evaluation...';
            flush();
        }
        exec('/usr/local/sbin/configctl -d unboundupstream evaluate > /dev/null 2>&1');
        if ($verbose) {
            echo "done.\n";
        }
    } catch (\Throwable $e) {
        syslog(LOG_ERR, 'unboundupstream: cannot queue an evaluation: ' . $e->getMessage());
    }
}

/**
 * The monitor hook: the gateways that changed go to the action as ONE comma-joined parameter.
 *
 * @param list<string> $gwnames
 */
function unboundupstream_queue_monitor(bool $verbose, array $gwnames): void
{
    try {
        if ($verbose) {
            echo 'Queueing the Unbound upstream evaluation...';
            flush();
        }
        $names = implode(',', array_map('strval', $gwnames));
        exec('/usr/local/sbin/configctl -d unboundupstream evaluate ' . escapeshellarg($names)
            . ' > /dev/null 2>&1');
        if ($verbose) {
            echo "done.\n";
        }
    } catch (\Throwable $e) {
        syslog(LOG_ERR, 'unboundupstream: cannot queue an evaluation: ' . $e->getMessage());
    }
}

function unboundupstream_cron()
{
    $jobs = [];
    try {
        $enabled = (new \OPNsense\UnboundUpstream\UnboundUpstream())->enabled->isEqual('1');
    } catch (\Throwable $e) {
        syslog(LOG_ERR, 'unboundupstream: cannot read its settings for cron: ' . $e->getMessage());
        $enabled = false;
    }
    if ($enabled) {
        /* every minute; generate_cron_job() defaults the minute to 0, so pass '*' */
        $jobs[]['autocron'] = ['/usr/local/sbin/configctl unboundupstream evaluate', '*'];
    }
    return $jobs;
}

/**
 * Rendered rules (spec 3.6b) at every filter reload. Failures render nothing and are logged through logger(1):
 * the hook runs inside core's filter reload and must not openlog() over core's ident.
 */
function unboundupstream_firewall($fw)
{
    $lib = '/usr/local/opnsense/scripts/OPNsense/UnboundUpstream/lib/render.php';
    try {
        if (!is_readable($lib)) {
            throw new \RuntimeException('plugin library missing; rules not rendered');
        }
        require_once $lib;
        uu_render_firewall($fw);
    } catch (\Throwable $e) {
        exec('/usr/bin/logger -t unboundupstream -p local4.err -- '
            . escapeshellarg('render hook failed: ' . str_replace("\n", '; ', $e->getMessage()))
            . ' > /dev/null 2>&1');
    }
}

function unboundupstream_services()
{
    $services = [];
    try {
        $enabled = (new \OPNsense\UnboundUpstream\UnboundUpstream())->enabled->isEqual('1');
    } catch (\Throwable $e) {
        $enabled = false;
    }
    if ($enabled) {
        $services[] = [
            'description' => gettext('Unbound upstream via gateway'),
            'configd' => [
                'start' => ['unboundupstream start'],
                'stop' => ['unboundupstream stop'],
                'restart' => ['unboundupstream restart'],
            ],
            'nocheck' => true,
            'name' => 'unboundupstream',
        ];
    }
    return $services;
}
