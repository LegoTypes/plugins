#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 cayossarian
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
 *     DETACHED: this may run inside a configd action (the monitor hook's
 *     reconcile runs within routing configure), and a synchronous
 *     configctl there could re-enter configd. The hook
 *     re-renders during that reload.
 * While the hook enforces the footprint (no rendered record, fallback.json
 * present) the labels looked for in pf are the footprint's.
 * What pf holds is listed (pfctl -sr) only when pf's ruleset checksum or the
 * rendered pin labels differ from the last listing's (WGCT_OBSERVED_FILE),
 * or that listing counted a miss, not on every reconcile; a listing that a
 * filter reload cut short (an identical reload too) or straddled is never
 * used, and is listed again (spec 2026-10-19).
 * Repeated reload requests for the same wanted pins are rate-limited with
 * exponential back-off, and a persistently failing anchor load, pf
 * observation or run logs at most once per distinct failure, so a render
 * that keeps failing does not flood configd or syslog every reconcile tick.
 * Runs are serialized on WGCT_FRESHNESS_LOCK_FILE, so a stale run can never
 * act after a newer one.
 * Writes no config. Usage: freshness.php [--dry]
 *
 * Never lets a \Throwable reach PHP's own error log / the GUI crash
 * reporter: render.php is checked for readability before it is required, as
 * the plugins_firewall hook does; every file its chain requires is checked
 * the same way and throws, which the try/catch around the require logs; and
 * everything after it runs inside a try/catch(\Throwable).
 */

$wgctLib = __DIR__ . '/lib/render.php';
if (!is_readable($wgctLib)) {
    exec('/usr/bin/logger -t wireguard -p user.err -- ' . escapeshellarg('[wgct-render] freshness: plugin library missing') . ' > /dev/null 2>&1');
    exit(1);
}
require "/usr/local/opnsense/mvc/script/load_phalcon.php";
try {
    require_once $wgctLib;
} catch (\Throwable $e) {
    exec('/usr/bin/logger -t wireguard -p user.err -- ' . escapeshellarg('[wgct-render] freshness: ' . $e->getMessage()) . ' > /dev/null 2>&1');
    exit(1);
}

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
         * because this can run inside a configd action (the monitor hook); a
         * run that cannot get the lock leaves the work to the run holding
         * it. --dry only reads, so it never waits. */
        $lock = wgct_poll_lock(
            WGCT_FRESHNESS_LOCK_FILE,
            WGCT_FRESHNESS_LOCK_TIMEOUT_MS,
            WGCT_FRESHNESS_LOCK_POLL_MS
        );
        if ($lock === null) {
            wgct_log(LOG_NOTICE, '[wgct-render] freshness: another run holds the lock; skipped');
            exit(0);
        }
    }

    $wanted = wgct_wanted_render();
    $rendered = wgct_read_rendered();

    /* Only counts as evidence of a failed main ruleset load when it is a
     * root-owned regular file of the shape filter.inc leaves (non-empty,
     * at most 64 KiB, `pfctl` on the first line: wgct_read_state_file(),
     * wgct_rules_error_shape()), and at least as new as the render it would
     * invalidate (wgct_error_file_stale: same-second counts as stale --
     * the hook stamps 'at' from inside the same filter_configure_sync that
     * runs the pfctl call filter.inc is reacting to). */
    $errorMtime = null;
    if ($rendered !== null) {
        $errorText = wgct_read_state_file(WGCT_RULES_DEBUG_ERROR, WGCT_RULES_ERROR_MAX_BYTES);
        $mtime = $errorText !== null ? @filemtime(WGCT_RULES_DEBUG_ERROR) : false;
        if ($mtime !== false && wgct_rules_error_shape($errorText) && wgct_error_file_stale($mtime, $rendered['at'])) {
            $errorMtime = $mtime;
        }
    }

    /* What pf holds right now, not just what rendered.json says was
     * rendered: a filter reload while the hook could not render leaves pf
     * without the pins and anchor while the record still describes them.
     * Parsed from stdout only; $live stays null when a pfctl listing fails or
     * no listing can be trusted (below), and the plan then rests on the record
     * alone.
     *
     * The main ruleset changes only when it is loaded, and pf recomputes its
     * ruleset checksum over the rules' labels at every load (an identical
     * load keeps it), so `pfctl -sr` (seconds on a large ruleset) runs only
     * when the checksum or the rendered pin labels differ from observed.json's,
     * or the record counts a miss; otherwise missing_labels is the recorded 0.
     * A listing counts only when it is whole and the checksum read before it
     * equals the one after (wgct_observe_listing). Any load during it, an
     * identical one too, cuts it short: pfctl then prints
     * `pfctl: DIOCGETRULE: Device busy` and still exits 0, so its stderr is
     * kept apart and judged (wgct_pf_listing_usable); a load that changes the
     * ruleset also moves the checksum. A listing cut short or straddled is
     * listed once more; a second one leaves $live null and records nothing,
     * and is no failure ($observeTransient: a notice, the next run lists
     * again). An unreadable checksum lists as before (a cut listing is listed
     * once more there too) and records nothing. */
    $live = null;
    $liveFrom = null;
    /* The labels pf should hold: the rendered pins', or, while the hook enforces the footprint (no rendered
     * record, fallback.json present), the footprint's (spec 2026-10-20 section 3.1 part D). */
    $fallback = $rendered === null ? wgct_read_fallback() : null;
    $lookFor = wgct_rules_looked_for($rendered, $fallback, $fallback !== null ? wgct_read_footprint() : null);
    $labelsFrom = $rendered === null && $fallback !== null ? 'footprint' : 'rendered';
    $observeError = null;
    $observeTransient = false;
    /* Every pfctl call here goes through wgct_pfctl_run(): no shell, and
     * stderr kept apart from the lines. Only the rules listing judges its
     * stderr; the anchor listing's and the checksum reads' (pf's ALTQ notices
     * on a kernel without ALTQ, for -si) are dropped. The anchor holds a
     * handful of rules and its count only orders a cheap anchor load
     * (wgct_freshness_plan), so a cut anchor listing is not retried. */
    $anchorRun = wgct_pfctl_run(['-a', WGCT_MSS_ANCHOR, '-sr']);
    $anchorLines = $anchorRun['lines'];
    if ($anchorRun['rc'] !== 0) {
        $observeError = wgct_pfctl_failure('pfctl -a ' . WGCT_MSS_ANCHOR . ' -sr', $anchorRun);
    } else {
        $labelsHash = wgct_pin_labels_hash($lookFor);
        $checksumUnreadable = false;
        $readChecksum = function () use (&$checksumUnreadable): ?string {
            $run = wgct_pfctl_run(['-si', '-v']);
            $checksum = $run['rc'] === 0 ? wgct_pf_checksum($run['lines']) : null;
            $checksumUnreadable = $checksumUnreadable || $checksum === null;
            return $checksum;
        };
        /* a failed listing throws, which ends wgct_observe_listing without
         * another listing; caught below as the pfctl failure it is. A listing
         * cut short returns null. */
        $rulesFailure = null;
        $listRules = function () use (&$rulesFailure): ?array {
            $run = wgct_pfctl_run(['-sr']);
            if ($run['rc'] !== 0) {
                $rulesFailure = wgct_pfctl_failure('pfctl -sr', $run);
                throw new \RuntimeException($rulesFailure);
            }
            return wgct_pf_listing_usable($run['err']) ? $run['lines'] : null;
        };

        $before = $readChecksum();
        $reused = wgct_observed_reuse(wgct_read_observed(), $before, $labelsHash);
        try {
            if ($reused !== null) {
                $live = ['anchor_count' => wgct_anchor_rule_count($anchorLines), 'missing_labels' => $reused];
                $liveFrom = 'from the record';
            } elseif ($before === null) {
                $ruleLines = $listRules() ?? $listRules();
                if ($ruleLines === null) {
                    $unobserved = wgct_unobserved_listing(false);
                    $observeError = $unobserved['error'];
                    $observeTransient = $unobserved['transient'];
                } else {
                    $live = wgct_live_observation($anchorLines, $ruleLines, $lookFor);
                    $liveFrom = 'listed; checksum unreadable, nothing recorded';
                }
            } else {
                $observed = wgct_observe_listing($before, $readChecksum, $listRules);
                if ($observed === null) {
                    $unobserved = wgct_unobserved_listing($checksumUnreadable);
                    $observeError = $unobserved['error'];
                    $observeTransient = $unobserved['transient'];
                } else {
                    $live = wgct_live_observation($anchorLines, $observed['lines'], $lookFor);
                    $liveFrom = 'listed';
                    if (!$dry) {
                        wgct_write_observed([
                            'checksum' => $observed['checksum'],
                            'labels_hash' => $labelsHash,
                            'missing_labels' => $live['missing_labels'],
                        ]);
                    }
                }
            }
        } catch (\RuntimeException $e) {
            if ($rulesFailure === null) {
                throw $e;
            }
            $observeError = $rulesFailure;
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
                    '%d MSS anchor rule(s), %d %s pin label(s) missing from pf (%s)',
                    $live['anchor_count'],
                    $live['missing_labels'],
                    $labelsFrom,
                    $liveFrom
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
            wgct_log(LOG_NOTICE, '[wgct-render] ' . $plan['reason']);
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
            wgct_log(LOG_ERR, '[wgct-render] MSS anchor load failed (the line before names the reason)');
        }
        if ($logPlan['log_recovery']) {
            wgct_log(LOG_NOTICE, '[wgct-render] MSS anchor reloaded (' . count($wanted['mss']) . ' lines)');
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
            wgct_log(LOG_NOTICE, '[wgct-render] MSS anchor reloaded (' . count($wanted['mss']) . ' lines)');
        }
    }

    $newReloadState = $reloadState;
    if ($plan['reload']) {
        exec('/usr/sbin/daemon -f /usr/local/sbin/configctl filter reload', $out, $rc);
        if ($rc === 0) {
            $newReloadState = $plan['state'];
            wgct_log(LOG_NOTICE, '[wgct-render] ' . $plan['reason'] . '; filter reload requested');
        } else {
            /* Do not record a request that never actually went out -- leave
             * the previous reload state untouched so the rate limit is
             * measured from the last request that actually succeeded. */
            wgct_log(LOG_ERR, '[wgct-render] filter reload request failed (exit ' . $rc . ')');
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
     * that (once per distinct failure); a clean run reports a recovery once.
     * A run whose two listings a reload cut short or straddled is neither: it
     * logs a notice and leaves the failure record alone, so it neither reports
     * a recovery nor clears an earlier failure's hash. */
    if ($observeTransient) {
        wgct_log(LOG_NOTICE, '[wgct-render] freshness: a ruleset load ran during both listings; the next run lists again');
    } else {
        wgct_report_freshness_outcome(
            $observeError !== null
                ? 'freshness: live pf state not observed (' . $observeError . '); decided from the rendered record alone'
                : null
        );
    }
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
        wgct_log(LOG_ERR, '[wgct-render] ' . $message);
    }
    exit(1);
}
