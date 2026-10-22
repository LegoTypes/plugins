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

function wgclienttunnels_services()
{
    $services = [];

    $mdl = new \OPNsense\WGClientTunnels\WGClientTunnels();
    if ($mdl->enabled->isEqual('1')) {
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
 * Invoked directly rather than through configd: "monitor" fires from inside
 * actions that hold the gateway lock (routes.alarm, replay_alarm), and a
 * configd action started from here that waits on that lock would stall until
 * its timeout. configd itself is threaded and would not deadlock.
 */
function wgclienttunnels_configure_do($verbose = false)
{
    $mdl = new \OPNsense\WGClientTunnels\WGClientTunnels();
    if (!$mdl->enabled->isEqual('1')) {
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
 * The paths are the production ones; wgclienttunnels_firewall_at() takes
 * them as parameters so tests/wgct_hook.php can use temporary ones.
 */
function wgclienttunnels_firewall($fw)
{
    wgclienttunnels_firewall_at('/usr/local/opnsense/scripts/OPNsense/WGClientTunnels/lib', '/var/db/wgclienttunnels/footprint.json', '/var/run/wgclienttunnels', $fw);
}

/**
 * The filter hook (spec 2026-10-20 section 3.1 part B). Never throws into core.
 *
 * While the package removal's marker ($runDir/removing, ruling R30) exists,
 * nothing is registered, read, written or logged: removing the package is
 * the user's configured removal of the pins. Otherwise:
 *
 * 1. The normal path: lib/render.php registers the rules it derives, and
 *    records them as the footprint (footprint.json) inside a filter reload.
 * 2. When the library is missing or throws while loading, or the render
 *    could not register its rules, the footprint is read here, with no
 *    library: the pins the plugin last put in place.
 * 3. A usable footprint's rules are registered at this hook's pin priority
 *    (the band core's Rules page groups, whatever a footprint from another
 *    version recorded), with the MSS anchor when the render did not get as
 *    far as registering it. The anchor's contents are not reloaded: pf keeps
 *    a named anchor's rules across a main ruleset load.
 * 4. A warning names the reason, once per distinct reason and outcome
 *    (fallback.logged), and fallback.json tells the views since when the
 *    footprint is enforced. A later successful render removes both and logs
 *    the recovery once.
 * 5. With no usable footprint nothing is registered, as before the
 *    footprint existed, and the same warning says there is none.
 *
 * During a deploy swap window (plugin directories replaced while this file,
 * which core loads separately, stays) or after a failed deploy the library
 * can be missing in whole or in part, and a filter reload (a gateway alarm,
 * boot) must not die of it. What holds: this hook checks the one file it
 * requires, render.php, for readability; every require in render.php's own
 * chain (tunnels.php, addr.php, selftest.php) checks its file the same way and
 * throws a \RuntimeException naming it ("plugin library file <name>
 * missing"), which the try/catch below turns into the fallback with the
 * reason "hook failed: <message>". So no file of the chain is ever required
 * unchecked, whatever PHP does with a failed require.
 *
 * core also calls this hook only to list rules for display
 * (list_non_mvc_rules.php, firewall_rule_lookup.php). Rules are registered
 * either way, so the Rules page shows what pf holds; state files, the
 * rendered record and the log change only inside a real filter reload.
 *
 * The literals here (the pin priority 99999, the anchor wgclienttunnels_mss,
 * the state paths) copy render.php's constants because the library may be
 * the thing that is missing; wgct_render_selftest() holds them equal.
 *
 * @param string                    $libDir    the plugin's lib/ directory
 * @param string                    $footprint the footprint file
 * @param string                    $runDir    the run directory (rendered.json, fallback.json, fallback.logged)
 * @param \OPNsense\Firewall\Plugin $fw        core's firewall plugin registry
 */
function wgclienttunnels_firewall_at(string $libDir, string $footprint, string $runDir, $fw): void
{
    if (is_file($runDir . '/removing')) {
        return;
    }
    $apply = wgclienttunnels_in_filter_reload(debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS));
    $entered = false;
    $registered = false;
    $reason = 'the render failed';
    try {
        if (!is_readable($libDir . '/render.php')) {
            $reason = 'plugin library missing';
        } else {
            require_once $libDir . '/render.php';
            $entered = true;
            $rendered = null;
            $registered = wgct_render_firewall($fw, null, true, $rendered, null, null, fn (): bool => $apply);
            if (!$registered && is_array($rendered) && is_string($rendered['error'] ?? null) && $rendered['error'] !== '') {
                $reason = $rendered['error'];
            }
        }
    } catch (\Throwable $e) {
        $reason = 'hook failed: ' . $e->getMessage();
    }
    try {
        if ($registered) {
            if ($apply) {
                wgclienttunnels_fallback_clear($runDir);
            }
        } else {
            wgclienttunnels_fallback($fw, $footprint, $runDir, $reason, $entered, $apply);
        }
    } catch (\Throwable $e) {
        wgclienttunnels_log('err', '[wgct-render] the footprint fallback failed: ' . $e->getMessage());
    }
}

/**
 * Steps 2-5 of wgclienttunnels_firewall_at().
 *
 * @param \OPNsense\Firewall\Plugin $fw
 * @param string                    $footprint the footprint file
 * @param string                    $runDir    the run directory
 * @param string                    $reason    why the render did not register its rules
 * @param bool                      $entered   the render ran, so it registered the MSS anchor already
 * @param bool                      $apply     inside a real filter reload
 */
function wgclienttunnels_fallback($fw, string $footprint, string $runDir, string $reason, bool $entered, bool $apply): void
{
    $record = wgclienttunnels_read_footprint($footprint);
    if ($record !== null) {
        if (!$entered) {
            $fw->registerAnchor('wgclienttunnels_mss', 'fw', 0, 'head');
        }
        foreach ($record['rules'] as $conf) {
            $fw->registerFilterRule(99999, $conf);
        }
    }
    if (!$apply) {
        return;
    }
    /* pf now holds the footprint or nothing, not what a rendered record describes. With no footprint, a failed
     * render's own record stays (it holds no pins), so render-failed shows its error. */
    if ($record !== null || !$entered) {
        wgclienttunnels_forget_render($runDir);
    }
    if ($record !== null) {
        $outcome = 'enforcing the footprint recorded at ' . date('Y-m-d H:i:s', $record['at']);
    } elseif (file_exists($footprint) || is_link($footprint)) {
        $outcome = 'no footprint (' . $footprint . ' is not a root-owned regular file of the expected shape), so no pins are enforced';
    } else {
        $outcome = 'no footprint, so no pins are enforced';
    }
    $message = '[wgct-render] render failed (' . $reason . '); ' . $outcome;
    $hash = md5($message);
    $logged = $runDir . '/fallback.logged';
    $fallback = $runDir . '/fallback.json';
    $changed = trim((string)wgclienttunnels_read_state_file($logged, 65536)) !== $hash;
    if ($changed) {
        wgclienttunnels_log('warning', $message);
        wgclienttunnels_write_state_file($logged, $hash . "\n");
    }
    if ($record === null) {
        if (file_exists($fallback) || is_link($fallback)) {
            @unlink($fallback);
        }
    } elseif ($changed || wgclienttunnels_read_fallback($fallback) === null) {
        wgclienttunnels_write_state_file($fallback, (string)json_encode(['at' => time(), 'reason' => $reason, 'footprint_at' => $record['at']], JSON_INVALID_UTF8_SUBSTITUTE));
    }
}

/**
 * A render succeeded inside a filter reload: the fallback is over. Logs the
 * recovery once, when a failure was reported.
 *
 * @param string $runDir the run directory
 */
function wgclienttunnels_fallback_clear(string $runDir): void
{
    $logged = $runDir . '/fallback.logged';
    $reported = file_exists($logged) || is_link($logged);
    foreach ([$runDir . '/fallback.json', $logged] as $file) {
        if (file_exists($file) || is_link($file)) {
            @unlink($file);
        }
    }
    if ($reported) {
        wgclienttunnels_log('notice', '[wgct-render] render recovered');
    }
}

/**
 * True iff the frames contain filter_configure_sync: a real filter reload,
 * not a rules-listing call. Pure over debug_backtrace()-shaped frames; also
 * render.php's default for its own check.
 *
 * @param array $frames
 * @return bool
 */
function wgclienttunnels_in_filter_reload(array $frames): bool
{
    foreach ($frames as $frame) {
        if (($frame['function'] ?? null) === 'filter_configure_sync') {
            return true;
        }
    }
    return false;
}

/**
 * The hook's own C3 reader, for when the library is missing: a regular file
 * (never a symlink), owned by root, no larger than $maxBytes; anything else
 * reads as absent.
 *
 * @param string $path
 * @param int    $maxBytes
 * @return string|null
 */
function wgclienttunnels_read_state_file(string $path, int $maxBytes): ?string
{
    clearstatcache(true, $path);
    if (is_link($path) || !is_file($path) || @fileowner($path) !== 0) {
        return null;
    }
    $size = @filesize($path);
    if ($size === false || $size > $maxBytes) {
        return null;
    }
    $content = @file_get_contents($path);
    return $content === false ? null : $content;
}

/**
 * The footprint (spec section 3.1 B-2), or null when there is none or it is
 * not exactly what a render writes: 'at' and 'priority' ints, 'anchor'
 * matching ^[a-z_]+$, 'rules' a list of block rules whose keys come from the
 * fixed set, whose values are strings or bools and whose label is 32 hex
 * digits, 'mss' a list of strings, and no other key. A footprint of any
 * other shape is never registered in part. The single reader: render.php
 * and freshness.php call it too.
 *
 * @param string $path
 * @return array|null
 */
function wgclienttunnels_read_footprint(string $path): ?array
{
    $raw = wgclienttunnels_read_state_file($path, 65536);
    $data = $raw !== null ? json_decode($raw, true) : null;
    if (!is_array($data)) {
        return null;
    }
    $keys = array_keys($data);
    sort($keys);
    if ($keys !== ['anchor', 'at', 'mss', 'priority', 'rules'] || !is_int($data['at']) || !is_int($data['priority'])
        || !is_string($data['anchor']) || preg_match('/^[a-z_]+$/', $data['anchor']) !== 1
        || !is_array($data['rules']) || !array_is_list($data['rules'])
        || !is_array($data['mss']) || !array_is_list($data['mss'])) {
        return null;
    }
    $ruleKeys = ['type', 'direction', 'quick', 'log', 'interface', 'interfacenot', 'ipprotocol', 'protocol', 'from',
                 'from_not', 'to', 'label', 'descr'];
    foreach ($data['rules'] as $rule) {
        if (!is_array($rule) || ($rule['type'] ?? null) !== 'block'
            || !is_string($rule['label'] ?? null) || preg_match('/^[0-9a-f]{32}$/', $rule['label']) !== 1) {
            return null;
        }
        foreach ($rule as $key => $value) {
            if (!in_array($key, $ruleKeys, true) || !(is_string($value) || is_bool($value))) {
                return null;
            }
        }
    }
    foreach ($data['mss'] as $line) {
        if (!is_string($line)) {
            return null;
        }
    }
    return $data;
}

/**
 * fallback.json ({at, reason, footprint_at}), or null when there is none or
 * it has another shape. The single reader: render.php's views call it too.
 *
 * @param string $path
 * @return array|null
 */
function wgclienttunnels_read_fallback(string $path): ?array
{
    $raw = wgclienttunnels_read_state_file($path, 65536);
    $data = $raw !== null ? json_decode($raw, true) : null;
    if (!is_array($data) || array_keys($data) !== ['at', 'reason', 'footprint_at']
        || !is_int($data['at']) || !is_string($data['reason']) || !is_int($data['footprint_at'])) {
        return null;
    }
    return $data;
}

/**
 * The hook's own atomic write, for when the library is missing: the
 * directory is made or tightened to root 0700 (never through a symlink), the
 * file is written 0600 (tempnam()) and renamed into place.
 *
 * @param string $path
 * @param string $data
 * @return bool
 */
function wgclienttunnels_write_state_file(string $path, string $data): bool
{
    $dir = dirname($path);
    if (is_link($dir) || (file_exists($dir) && !is_dir($dir))
        || (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) || !@chmod($dir, 0700)) {
        wgclienttunnels_log('err', '[wgct-render] could not create ' . $dir . ' as a 0700 directory');
        return false;
    }
    $tmp = @tempnam($dir, basename($path));
    if ($tmp === false || @file_put_contents($tmp, $data) === false || !@rename($tmp, $path)) {
        if ($tmp !== false) {
            @unlink($tmp);
        }
        wgclienttunnels_log('err', '[wgct-render] could not write ' . $path);
        return false;
    }
    return true;
}

/**
 * One line to core's WireGuard log, as the library's wgct_log() writes it,
 * for when the library is missing.
 *
 * @param string $level a syslog level name: err, warning, notice
 * @param string $message
 */
function wgclienttunnels_log(string $level, string $message): void
{
    $line = trim((string)preg_replace('/\s*\R\s*/', '; ', $message));
    exec('/usr/bin/logger -t wireguard -p user.' . $level . ' -- ' . escapeshellarg($line) . ' > /dev/null 2>&1');
}

/**
 * Remove the rendered record: with it gone, the next reconcile sees "no
 * rendered record" and asks for a filter reload. The record may not exist; a
 * failed unlink is ignored (the next successful render rewrites it).
 *
 * @param string $runDir the run directory
 */
function wgclienttunnels_forget_render(string $runDir): void
{
    $rendered = $runDir . '/rendered.json';
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
