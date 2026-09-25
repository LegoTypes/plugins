#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Keep the rendered enforcement current between filter reloads (spec 4.4,
 * 4.7). No event fires when a WireGuard instance or peer is saved, so the
 * reconcile (config syshook, monitor/newwanip hooks, minute cron) compares
 * what the hook last rendered with what is wanted now and acts on
 * wgipv6_freshness_plan()'s decision:
 *   - MSS lines differ (or the last render failed only at the anchor) ->
 *     reload the anchor directly (pfctl -a), no filter reload needed;
 *   - pins differ, there is no rendered record, the render otherwise failed,
 *     or the main ruleset failed to load since the last render -> ask
 *     configd for a filter reload, DETACHED: this may run inside configd's
 *     own config_changed action, and a synchronous configctl there could
 *     re-enter configd. The hook re-renders during that reload.
 * Repeated reload requests for the same wanted pins are rate-limited with
 * exponential back-off, and a persistently failing anchor load logs at most
 * once per distinct failure, so a render that keeps failing does not flood
 * configd or syslog every reconcile tick.
 * Writes no config. Usage: freshness.php [--dry]
 *
 * Never lets a \Throwable reach PHP's own error log / the GUI crash
 * reporter: the libraries are checked for readability the way the
 * plugins_firewall hook does before they are required, and everything after
 * the requires runs inside a try/catch(\Throwable).
 */

$wgipv6Lib = __DIR__ . '/lib/render.php';
$wgipv6TunnelsLib = __DIR__ . '/lib/tunnels.php';
if (!is_readable($wgipv6Lib) || !is_readable($wgipv6TunnelsLib)) {
    syslog(LOG_ERR, '[wgipv6gw-render] freshness: plugin library missing');
    exit(1);
}
require "/usr/local/opnsense/mvc/script/load_phalcon.php";
require_once $wgipv6Lib;

/* Where filter.inc leaves the error from a failed `pfctl -f /tmp/rules.debug`
 * before it restores the old ruleset (see filter.inc, ~line 399). */
const WGIPV6_RULES_DEBUG_ERROR = '/tmp/rules.debug.error';

try {
    $dry = in_array('--dry', $argv ?? [], true);

    $wanted = wgipv6_wanted_render();
    $rendered = wgipv6_read_rendered();

    /* Only counts as evidence of a failed main ruleset load when it is
     * present, non-empty, and at least as new as the render it would
     * invalidate (wgipv6_error_file_stale: same-second counts as stale --
     * the hook stamps 'at' from inside the same filter_configure_sync that
     * runs the pfctl call filter.inc is reacting to). */
    $errorMtime = null;
    if ($rendered !== null && is_file(WGIPV6_RULES_DEBUG_ERROR)) {
        $size = @filesize(WGIPV6_RULES_DEBUG_ERROR);
        $mtime = @filemtime(WGIPV6_RULES_DEBUG_ERROR);
        if ($size !== false && $size > 0 && $mtime !== false && wgipv6_error_file_stale($mtime, $rendered['at'])) {
            $errorMtime = $mtime;
        }
    }

    $fileState = wgipv6_read_freshness_state();
    $reloadState = $fileState['reload'] ?? null;
    $anchorFailHash = $fileState['anchor_fail_hash'] ?? null;

    $plan = wgipv6_freshness_plan($wanted, $rendered, $errorMtime, $reloadState, time());

    if ($dry) {
        printf(
            "reload: %s\nanchor: %s\nreason: %s\n",
            $plan['reload'] ? 'yes' : 'no',
            $plan['anchor'] ? 'yes' : 'no',
            $plan['reason']
        );
        exit(0);
    }

    /* A suppressed reload request (needed, but rate-limited) is the only
     * case where reload and anchor are both false yet $plan['state'] is not
     * null. Log it once, on the false -> true transition of 'notified', not
     * on every reconcile tick while the window lasts. */
    if (!$plan['reload'] && !$plan['anchor'] && $plan['state'] !== null) {
        $wasNotified = (bool)($reloadState['notified'] ?? false);
        $nowNotified = (bool)($plan['state']['notified'] ?? false);
        if (!$wasNotified && $nowNotified) {
            syslog(LOG_NOTICE, '[wgipv6gw-render] ' . $plan['reason']);
        }
    }

    $newAnchorFailHash = $anchorFailHash;

    if ($plan['anchor']) {
        /* Quiet: freshness.php does its own hash-deduplicated logging below,
         * since this retries every tick and would otherwise flood syslog for
         * a persistently failing anchor. */
        $success = wgipv6_load_mss_anchor($wanted['mss'], true);
        $logPlan = wgipv6_anchor_log_plan($anchorFailHash, $success, $wanted['mss']);
        $newAnchorFailHash = $logPlan['fail_hash'];
        if ($logPlan['log_error']) {
            syslog(LOG_ERR, '[wgipv6gw-render] MSS anchor load failed (see syslog)');
        }
        if ($logPlan['log_recovery']) {
            syslog(LOG_NOTICE, '[wgipv6gw-render] MSS anchor reloaded (' . count($wanted['mss']) . ' lines)');
        }
        if ($success && $rendered !== null) {
            /* Re-read just before writing: if a real filter reload already
             * re-rendered since we read $rendered above, its record is newer
             * and must not be clobbered with what we read at the start. */
            $latest = wgipv6_read_rendered();
            if ($latest !== null && $latest['at'] === $rendered['at']) {
                $rendered['mss'] = $wanted['mss'];
                $rendered['failed'] = false;
                $rendered['error'] = '';
                wgipv6_write_rendered($rendered);
            }
        }
    }

    $newReloadState = $reloadState;
    if ($plan['reload']) {
        exec('/usr/sbin/daemon -f /usr/local/sbin/configctl filter reload', $out, $rc);
        if ($rc === 0) {
            $newReloadState = $plan['state'];
            syslog(LOG_NOTICE, '[wgipv6gw-render] ' . $plan['reason'] . '; filter reload requested');
        } else {
            /* Do not record a request that never actually went out -- leave
             * the previous reload state untouched so the rate limit is
             * measured from the last request that actually succeeded. */
            syslog(LOG_ERR, '[wgipv6gw-render] filter reload request failed (exit ' . $rc . ')');
        }
    } else {
        $newReloadState = $plan['state'];
    }

    if ($newReloadState === null && $newAnchorFailHash === null) {
        wgipv6_write_freshness_state(null);
    } else {
        wgipv6_write_freshness_state(['reload' => $newReloadState, 'anchor_fail_hash' => $newAnchorFailHash]);
    }
} catch (\Throwable $e) {
    syslog(LOG_ERR, '[wgipv6gw-render] freshness failed: ' . $e->getMessage());
    exit(1);
}
