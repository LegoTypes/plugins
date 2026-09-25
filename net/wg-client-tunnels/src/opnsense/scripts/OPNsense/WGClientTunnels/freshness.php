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
 * what the hook last rendered -- and what pf actually holds -- with what is
 * wanted now and acts on wgct_freshness_plan()'s decision:
 *   - MSS lines differ, the live anchor's rule count differs from the
 *     render, or the last render failed only at the anchor -> reload the
 *     anchor directly (pfctl -a), no filter reload needed;
 *   - pins differ, there is no rendered record, the render otherwise failed,
 *     the main ruleset failed to load since the last render, or pf is missing
 *     labels the rendered pins produce -> ask configd for a filter reload,
 *     DETACHED: this may run inside configd's own config_changed action, and
 *     a synchronous configctl there could re-enter configd. The hook
 *     re-renders during that reload.
 * Repeated reload requests for the same wanted pins are rate-limited with
 * exponential back-off, and a persistently failing anchor load, pf
 * observation or run logs at most once per distinct failure, so a render
 * that keeps failing does not flood configd or syslog every reconcile tick.
 * Runs are serialized on WGCT_FRESHNESS_LOCK_FILE, so a stale run can never
 * act after a newer one.
 * Writes no config. Usage: freshness.php [--dry]
 *
 * Never lets a \Throwable reach PHP's own error log / the GUI crash
 * reporter: the libraries are checked for readability the way the
 * plugins_firewall hook does before they are required, and everything after
 * the requires runs inside a try/catch(\Throwable).
 */

$wgctLib = __DIR__ . '/lib/render.php';
$wgctTunnelsLib = __DIR__ . '/lib/tunnels.php';
if (!is_readable($wgctLib) || !is_readable($wgctTunnelsLib)) {
    syslog(LOG_ERR, '[wgipv6gw-render] freshness: plugin library missing');
    exit(1);
}
require "/usr/local/opnsense/mvc/script/load_phalcon.php";
require_once $wgctLib;

/* Where filter.inc leaves the error from a failed `pfctl -f /tmp/rules.debug`
 * before it restores the old ruleset (see filter.inc, ~line 399). */
const WGCT_RULES_DEBUG_ERROR = '/tmp/rules.debug.error';

$dry = in_array('--dry', $argv ?? [], true);

try {
    if (!$dry) {
        /* Held for the whole derive -> observe -> plan -> act sequence and
         * released when the process exits: two overlapping reconciles must
         * not interleave, or a run that derived before another one wrote
         * rendered.json could load its older MSS lines afterwards. Bounded,
         * because this can run inside configd's config_changed action; a
         * run that cannot get the lock leaves the work to the run holding
         * it. --dry only reads, so it never waits. */
        $lock = wgct_poll_lock(
            WGCT_FRESHNESS_LOCK_FILE,
            WGCT_FRESHNESS_LOCK_TIMEOUT_MS,
            WGCT_FRESHNESS_LOCK_POLL_MS
        );
        if ($lock === null) {
            syslog(LOG_NOTICE, '[wgipv6gw-render] freshness: another run holds the lock; skipped');
            exit(0);
        }
    }

    $wanted = wgct_wanted_render();
    $rendered = wgct_read_rendered();

    /* Only counts as evidence of a failed main ruleset load when it is
     * present, non-empty, and at least as new as the render it would
     * invalidate (wgct_error_file_stale: same-second counts as stale --
     * the hook stamps 'at' from inside the same filter_configure_sync that
     * runs the pfctl call filter.inc is reacting to). */
    $errorMtime = null;
    if ($rendered !== null && is_file(WGCT_RULES_DEBUG_ERROR)) {
        $size = @filesize(WGCT_RULES_DEBUG_ERROR);
        $mtime = @filemtime(WGCT_RULES_DEBUG_ERROR);
        if ($size !== false && $size > 0 && $mtime !== false && wgct_error_file_stale($mtime, $rendered['at'])) {
            $errorMtime = $mtime;
        }
    }

    /* What pf holds right now, not just what rendered.json says was
     * rendered: a filter reload while the hook could not render leaves pf
     * without the pins and anchor while the record still describes them.
     * stdout only (exec() never captures stderr); $live stays null when
     * either pfctl call fails, and the plan then rests on the record alone. */
    $live = null;
    $observeError = null;
    $anchorLines = [];
    exec('/sbin/pfctl -a ' . escapeshellarg(WGCT_MSS_ANCHOR) . ' -sr', $anchorLines, $anchorRc);
    if ($anchorRc !== 0) {
        $observeError = 'pfctl -a ' . WGCT_MSS_ANCHOR . ' -sr failed (exit ' . $anchorRc . ')';
    } else {
        $ruleLines = [];
        exec('/sbin/pfctl -sr', $ruleLines, $rulesRc);
        if ($rulesRc !== 0) {
            $observeError = 'pfctl -sr failed (exit ' . $rulesRc . ')';
        } else {
            $live = wgct_live_observation(
                $anchorLines,
                $ruleLines,
                $rendered !== null ? $rendered['pins'] : ['wan' => [], 'inner' => []]
            );
        }
    }

    /* Already normalised: a corrupt/malformed freshness.json reads back as
     * ['reload' => null, 'anchor_fail_hash' => null], not a TypeError. */
    $fileState = wgct_read_freshness_state();
    $reloadState = $fileState['reload'];
    $anchorFailHash = $fileState['anchor_fail_hash'];

    $plan = wgct_freshness_plan($wanted, $rendered, $errorMtime, $reloadState, time(), $live);

    if ($dry) {
        printf(
            "reload: %s\nanchor: %s\nreason: %s\nlive: %s\n",
            $plan['reload'] ? 'yes' : 'no',
            $plan['anchor'] ? 'yes' : 'no',
            $plan['reason'],
            $live !== null
                ? sprintf(
                    '%d MSS anchor rule(s), %d rendered pin label(s) missing from pf',
                    $live['anchor_count'],
                    $live['missing_labels']
                )
                : 'not observed (' . $observeError . ')'
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
        $success = wgct_load_mss_anchor($wanted['mss'], true);
        $logPlan = wgct_anchor_log_plan($anchorFailHash, $success, $wanted['mss']);
        $newAnchorFailHash = $logPlan['fail_hash'];
        if ($logPlan['log_error']) {
            syslog(LOG_ERR, '[wgipv6gw-render] MSS anchor load failed (see syslog)');
        }
        if ($logPlan['log_recovery']) {
            syslog(LOG_NOTICE, '[wgipv6gw-render] MSS anchor reloaded (' . count($wanted['mss']) . ' lines)');
        }
        if ($success && $rendered !== null) {
            /* Re-read just before writing and compare the whole record, not
             * just 'at': if anything else -- most likely a real filter
             * reload -- wrote a new rendered.json since we read $rendered at
             * the top of the script, that newer record must not be
             * clobbered with what this tick started from. */
            $latest = wgct_read_rendered();
            if ($latest !== null && $latest === $rendered) {
                $updated = $rendered;
                $updated['mss'] = $wanted['mss'];
                $updated['failed'] = false;
                $updated['error'] = '';
                wgct_write_rendered($updated);
            }
        }
    } elseif (!$plan['reload'] && $plan['state'] === null) {
        /* Plan is fully "current": if a prior anchor failure was pending,
         * something else (most likely a full filter reload) already fixed
         * it. Clear the remembered hash and report the recovery once, via
         * the same pure decision an actual anchor-retry success uses, so a
         * later, identical failure is reported again rather than staying
         * silent forever because of a hash recorded before the fix. */
        $logPlan = wgct_anchor_log_plan($anchorFailHash, true, $wanted['mss']);
        $newAnchorFailHash = $logPlan['fail_hash'];
        if ($logPlan['log_recovery']) {
            syslog(LOG_NOTICE, '[wgipv6gw-render] MSS anchor reloaded (' . count($wanted['mss']) . ' lines)');
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
        wgct_write_freshness_state(null);
    } else {
        wgct_write_freshness_state(['reload' => $newReloadState, 'anchor_fail_hash' => $newAnchorFailHash]);
    }

    /* A run that could not read pf still acted on the record, but reports
     * that (once per distinct failure); a clean run reports a recovery once. */
    wgct_report_freshness_outcome(
        $observeError !== null
            ? 'freshness: live pf state not observed (' . $observeError . '); decided from the rendered record alone'
            : null
    );
} catch (\Throwable $e) {
    $message = 'freshness failed: ' . $e->getMessage();
    if ($dry) {
        /* --dry writes nothing, the failure record included */
        fwrite(STDERR, $message . "\n");
        exit(1);
    }
    try {
        wgct_report_freshness_outcome($message);
    } catch (\Throwable $reportError) {
        syslog(LOG_ERR, '[wgipv6gw-render] ' . $message);
    }
    exit(1);
}
