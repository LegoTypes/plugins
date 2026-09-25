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
 * Repeated reload requests for the same wanted pins are rate-limited so a
 * render that keeps failing does not flood configd every reconcile tick.
 * Writes no config. Usage: freshness.php [--dry]
 */

require "/usr/local/opnsense/mvc/script/load_phalcon.php";
require_once __DIR__ . '/lib/render.php';

/* Where filter.inc leaves the error from a failed `pfctl -f /tmp/rules.debug`
 * before it restores the old ruleset (see filter.inc, ~line 399). */
const WGIPV6_RULES_DEBUG_ERROR = '/tmp/rules.debug.error';

$dry = in_array('--dry', $argv ?? [], true);

$wanted = wgipv6_wanted_render();
$rendered = wgipv6_read_rendered();

/* Only counts as evidence of a failed main ruleset load when it is present,
 * non-empty, and newer than the render it would invalidate. */
$errorMtime = null;
if ($rendered !== null && is_file(WGIPV6_RULES_DEBUG_ERROR)) {
    $size = @filesize(WGIPV6_RULES_DEBUG_ERROR);
    $mtime = @filemtime(WGIPV6_RULES_DEBUG_ERROR);
    if ($size !== false && $size > 0 && $mtime !== false && $mtime > $rendered['at']) {
        $errorMtime = $mtime;
    }
}

$state = wgipv6_read_freshness_state();
$plan = wgipv6_freshness_plan($wanted, $rendered, $errorMtime, $state, time());

if ($dry) {
    printf(
        "reload: %s\nanchor: %s\nreason: %s\n",
        $plan['reload'] ? 'yes' : 'no',
        $plan['anchor'] ? 'yes' : 'no',
        $plan['reason']
    );
    exit(0);
}

/* A suppressed reload request (needed, but rate-limited) is the only case
 * where reload and anchor are both false yet $plan['state'] is not null.
 * Log it once, on the false -> true transition of 'notified', not on every
 * reconcile tick while the window lasts. */
if (!$plan['reload'] && !$plan['anchor'] && $plan['state'] !== null) {
    $wasNotified = (bool)($state['notified'] ?? false);
    $nowNotified = (bool)($plan['state']['notified'] ?? false);
    if (!$wasNotified && $nowNotified) {
        syslog(LOG_NOTICE, '[wgipv6gw-render] ' . $plan['reason']);
    }
}

if ($plan['anchor']) {
    if (wgipv6_load_mss_anchor($wanted['mss'])) {
        $rendered['mss'] = $wanted['mss'];
        $rendered['failed'] = false;
        $rendered['error'] = '';
        wgipv6_write_rendered($rendered);
        syslog(LOG_NOTICE, '[wgipv6gw-render] MSS anchor reloaded (' . count($wanted['mss']) . ' lines)');
    }
}
if ($plan['reload']) {
    exec('/usr/sbin/daemon -f /usr/local/sbin/configctl filter reload');
    syslog(LOG_NOTICE, '[wgipv6gw-render] ' . $plan['reason'] . '; filter reload requested');
}

wgipv6_write_freshness_state($plan['state']);
