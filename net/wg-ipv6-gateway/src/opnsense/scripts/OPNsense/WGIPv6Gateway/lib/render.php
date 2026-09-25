<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Rendered enforcement (spec 2026-09-24 sections 4.4, 4.5): WAN pins and
 * inner-source blocks registered as filter rules, and the MSS clamp as match
 * rules in a head anchor, all derived from the managed tunnels at every filter
 * reload -- never stored in config. The hook records what it rendered in
 * WGIPV6_RENDERED_FILE; the reconcile (freshness.php) compares against it.
 *
 * core calls every *_firewall hook (this file's entry point) not only during
 * a real filter reload but also just to list rules for display
 * (scripts/filter/list_non_mvc_rules.php, www/firewall_rule_lookup.php).
 * wgipv6_in_filter_reload() tells the two apart from the call stack: rules
 * and the anchor are always registered (so they show up on the Rules page
 * either way), but pfctl and the rendered.json write only happen inside a
 * real filter_configure_sync.
 */

if (!is_readable(__DIR__ . '/tunnels.php')) {
    /* thrown during file inclusion, not a compile error: the hook's
     * require_once + try/catch around it can and does catch this. */
    throw new \RuntimeException('[wgipv6gw-render] tunnels.php library missing');
}
require_once __DIR__ . '/tunnels.php';

const WGIPV6_RENDERED_FILE = '/var/run/wgipv6gateway/rendered.json';

/* freshness.php's own small state: the last filter-reload request it made,
 * so repeated staleness (e.g. a render that keeps failing) does not flood
 * configd with reload requests every reconcile tick. */
const WGIPV6_FRESHNESS_STATE_FILE = '/var/run/wgipv6gateway/freshness.json';
const WGIPV6_RELOAD_SUPPRESS_SECONDS = 300;
const WGIPV6_RELOAD_MAX_WINDOW_SECONDS = 3600;

function wgipv6_wanted_render() {
    $mdl = new \OPNsense\WGIPv6Gateway\WGIPv6Gateway();
    $enabled = (string)$mdl->enabled === '1';
    if (!$enabled) {
        return ['enabled' => false, 'pins' => ['wan' => [], 'inner' => []], 'mss' => []];
    }
    $derived = wgipv6_derive(wgipv6_core_snapshot(), wgipv6_split_csv((string)$mdl->managed));
    return [
        'enabled' => true,
        'pins' => wgipv6_pin_set($derived, (string)$mdl->wan_pins === '1', (string)$mdl->inner_source === '1'),
        'mss' => wgipv6_mss_lines($derived, (string)$mdl->mss_clamp === '1'),
    ];
}

/**
 * @param array $lines
 * @param bool  $quiet when true, suppress the LOG_ERR on failure -- freshness.php
 *                       retries this every reconcile tick and does its own
 *                       hash-deduplicated logging (wgipv6_anchor_log_plan) so a
 *                       persistently failing anchor does not flood syslog.
 * @return bool
 */
function wgipv6_load_mss_anchor(array $lines, $quiet = false) {
    $proc = proc_open(
        ['/sbin/pfctl', '-a', WGIPV6_MSS_ANCHOR, '-f', '-'],
        [0 => ['pipe', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['pipe', 'w']],
        $pipes
    );
    if (!is_resource($proc)) {
        return false;
    }
    fwrite($pipes[0], implode("\n", $lines) . "\n");
    fclose($pipes[0]);
    $err = stream_get_contents($pipes[2]);
    fclose($pipes[2]);
    $rc = proc_close($proc);
    if ($rc !== 0 && !$quiet) {
        syslog(LOG_ERR, '[wgipv6gw-render] loading anchor ' . WGIPV6_MSS_ANCHOR . ' failed: ' . trim((string)$err));
    }
    return $rc === 0;
}

function wgipv6_read_rendered() {
    $raw = @file_get_contents(WGIPV6_RENDERED_FILE);
    $data = $raw !== false ? json_decode($raw, true) : null;
    return is_array($data) ? $data : null;
}

/**
 * Atomic write via a same-directory temp file. Never throws; every failure
 * (encode, temp file, write, rename) is logged and reported through the
 * return value instead.
 *
 * @param array $r the rendered record
 * @return bool
 */
function wgipv6_write_rendered(array $r) {
    $dir = dirname(WGIPV6_RENDERED_FILE);
    @mkdir($dir, 0755, true);
    $json = json_encode($r);
    if ($json === false) {
        syslog(LOG_ERR, '[wgipv6gw-render] could not encode the rendered record: ' . json_last_error_msg());
        return false;
    }
    $tmp = tempnam($dir, 'rendered');
    if ($tmp === false) {
        syslog(LOG_ERR, '[wgipv6gw-render] could not create a temp file in ' . $dir);
        return false;
    }
    if (file_put_contents($tmp, $json) === false) {
        syslog(LOG_ERR, '[wgipv6gw-render] could not write ' . $tmp);
        @unlink($tmp);
        return false;
    }
    if (!rename($tmp, WGIPV6_RENDERED_FILE)) {
        syslog(LOG_ERR, '[wgipv6gw-render] could not rename ' . $tmp . ' to ' . WGIPV6_RENDERED_FILE);
        @unlink($tmp);
        return false;
    }
    return true;
}

/**
 * Deterministic fingerprint of an array (a wanted pin set, or a set of MSS
 * lines), so freshness.php can tell "still waiting on the reload/anchor
 * retry I already asked for" apart from "what I'm waiting on moved while I
 * was waiting".
 *
 * @param array $x
 * @return string
 */
function wgipv6_hash_array(array $x) {
    return md5(json_encode($x));
}

/**
 * @param array $pins wgipv6_wanted_render()['pins'] or a rendered record's 'pins'
 * @return bool true iff there is at least one WAN pin or inner-source block
 */
function wgipv6_pins_nonempty(array $pins) {
    return !empty($pins['wan']) || !empty($pins['inner']);
}

/**
 * Whether /tmp/rules.debug.error (already confirmed present and non-empty by
 * the caller) counts as evidence that the render at $renderedAt never
 * actually reached pf. filter.inc stamps this file, then restores the old
 * ruleset, when `pfctl -f /tmp/rules.debug` fails; the hook stamps
 * rendered.json's 'at' from inside the same filter_configure_sync, usually
 * in the same second as the pfctl call, so the comparison must not require
 * the error file to be strictly newer.
 *
 * @param int $mtime      mtime of /tmp/rules.debug.error
 * @param int $renderedAt rendered.json's 'at'
 * @return bool
 */
function wgipv6_error_file_stale($mtime, $renderedAt) {
    return $mtime >= $renderedAt;
}

function wgipv6_read_freshness_state() {
    $raw = @file_get_contents(WGIPV6_FRESHNESS_STATE_FILE);
    $data = $raw !== false ? json_decode($raw, true) : null;
    return is_array($data) ? $data : null;
}

/**
 * Atomic write via a same-directory temp file, like wgipv6_write_rendered().
 * $s === null means there is nothing left worth remembering (current, or an
 * anchor-only retry that never touched the rate limit) -- the state file is
 * removed instead of written.
 *
 * @param array|null $s
 * @return bool
 */
function wgipv6_write_freshness_state($s) {
    if ($s === null) {
        @unlink(WGIPV6_FRESHNESS_STATE_FILE);
        return true;
    }
    $dir = dirname(WGIPV6_FRESHNESS_STATE_FILE);
    @mkdir($dir, 0755, true);
    $json = json_encode($s);
    if ($json === false) {
        syslog(LOG_ERR, '[wgipv6gw-render] could not encode the freshness state: ' . json_last_error_msg());
        return false;
    }
    $tmp = tempnam($dir, 'freshness');
    if ($tmp === false) {
        syslog(LOG_ERR, '[wgipv6gw-render] could not create a temp file in ' . $dir);
        return false;
    }
    if (file_put_contents($tmp, $json) === false) {
        syslog(LOG_ERR, '[wgipv6gw-render] could not write ' . $tmp);
        @unlink($tmp);
        return false;
    }
    if (!rename($tmp, WGIPV6_FRESHNESS_STATE_FILE)) {
        syslog(LOG_ERR, '[wgipv6gw-render] could not rename ' . $tmp . ' to ' . WGIPV6_FRESHNESS_STATE_FILE);
        @unlink($tmp);
        return false;
    }
    return true;
}

/**
 * The freshness decision (spec 4.4, 4.7; controller rulings 2026-09-24), pure
 * over its inputs so it is directly testable -- freshness.php only does I/O
 * around it: read rendered.json, stat /tmp/rules.debug.error (through
 * wgipv6_error_file_stale()), read freshness.json, call this, then act on
 * the plan and persist $plan['state'].
 *
 * Priority, most urgent first:
 *   1. no rendered record at all -> reload, but only if there is anything to
 *      render: a disabled/empty plugin with no record yet has nothing to
 *      enforce and must not spin on this forever
 *   2. rendered pins differ from wanted -> reload (this includes going from
 *      pins to none, e.g. the plugin was just disabled: the stale pins still
 *      need removing)
 *   3. /tmp/rules.debug.error is at least as new as the render (main ruleset
 *      load failed and the old ruleset was restored; the rendered pins may
 *      never have reached pf) -> reload, but only when the pins at stake are
 *      non-empty: an unrelated ruleset failure while this plugin renders
 *      nothing is not this plugin's problem to fix by reloading
 *   4. the render is marked failed for any other reason than the MSS anchor
 *      load specifically, again only when the pins are non-empty -> reload;
 *      an anchor-only failure retries just the anchor instead
 *   5. otherwise, MSS lines differ -> reload the anchor directly
 *   6. otherwise -> nothing to do
 * A filter reload re-renders both the pins and the anchor, so cases 1-4 never
 * also need a separate anchor step.
 *
 * Reload requests are rate-limited with exponential back-off: repeating the
 * same wanted-pins hash within the current window of the last request is
 * suppressed rather than asking configd again; the window starts at
 * WGIPV6_RELOAD_SUPPRESS_SECONDS and doubles (capped at
 * WGIPV6_RELOAD_MAX_WINDOW_SECONDS) each time a request repeats for the same
 * hash, so a render that keeps failing asks configd less and less often. A
 * change to the wanted-pins hash resets the window to the base. A negative
 * elapsed time (the clock stepped back) is never treated as "within the
 * window" -- it cannot be trusted, so the safer default is to allow the
 * request. $plan['state'] is what freshness.php should now persist as the
 * reload half of freshness.json (null clears it -- nothing left to
 * remember); the caller can tell a first suppression from a repeat by
 * comparing $state['notified'] (input) against $plan['state']['notified']
 * (output) -- false-to-true is the moment to log.
 *
 * @param array      $wanted     wgipv6_wanted_render()'s ['enabled','pins','mss']
 * @param array|null $rendered   wgipv6_read_rendered()'s record, or null
 * @param int|null   $errorMtime mtime of /tmp/rules.debug.error, or null
 *                                unless the caller has already established
 *                                the file exists, is non-empty, and
 *                                wgipv6_error_file_stale() of it and
 *                                $rendered['at'] is true
 * @param array|null $state      the reload half of the last freshness.json
 *                                record, or null
 * @param int        $now        current time
 * @return array ['reload' => bool, 'anchor' => bool, 'reason' => string, 'state' => array|null]
 */
function wgipv6_freshness_plan(array $wanted, ?array $rendered, ?int $errorMtime, ?array $state, int $now) {
    $anchorOnlyError = $rendered !== null && $rendered['failed']
        && strpos((string)($rendered['error'] ?? ''), 'MSS anchor load failed') === 0;

    if ($rendered === null) {
        $needReload = wgipv6_pins_nonempty($wanted['pins']);
        $reason = $needReload ? 'no rendered record' : 'nothing rendered yet';
    } elseif ($rendered['pins'] !== $wanted['pins']) {
        $needReload = true;
        $reason = 'pins changed';
    } elseif ($errorMtime !== null && wgipv6_pins_nonempty($rendered['pins'])) {
        $needReload = true;
        $reason = 'main ruleset load failed since the last render';
    } elseif ($rendered['failed'] && !$anchorOnlyError && wgipv6_pins_nonempty($rendered['pins'])) {
        $needReload = true;
        $reason = 'previous render failed';
    } else {
        $needReload = false;
        $reason = '';
    }

    if ($needReload) {
        $hash = wgipv6_hash_array($wanted['pins']);
        $sameHash = $state !== null && ($state['pins_hash'] ?? null) === $hash;
        $priorWindow = $sameHash
            ? (int)($state['window'] ?? WGIPV6_RELOAD_SUPPRESS_SECONDS)
            : WGIPV6_RELOAD_SUPPRESS_SECONDS;
        $elapsed = $sameHash ? $now - (int)($state['requested_at'] ?? 0) : null;
        $withinWindow = $sameHash && $elapsed !== null && $elapsed >= 0 && $elapsed < $priorWindow;
        if ($withinWindow) {
            return [
                'reload' => false,
                'anchor' => false,
                'reason' => $reason . '; filter reload suppressed (rate-limited)',
                'state' => [
                    'requested_at' => $state['requested_at'],
                    'pins_hash' => $hash,
                    'notified' => true,
                    'window' => $priorWindow,
                ],
            ];
        }
        $newWindow = $sameHash
            ? min($priorWindow * 2, WGIPV6_RELOAD_MAX_WINDOW_SECONDS)
            : WGIPV6_RELOAD_SUPPRESS_SECONDS;
        return [
            'reload' => true,
            'anchor' => false,
            'reason' => $reason,
            'state' => [
                'requested_at' => $now,
                'pins_hash' => $hash,
                'notified' => false,
                'window' => $newWindow,
            ],
        ];
    }

    if ($rendered === null) {
        /* disabled/empty and nothing was ever rendered: no anchor to check
         * against, nothing to do. */
        return ['reload' => false, 'anchor' => false, 'reason' => $reason, 'state' => null];
    }
    if ($anchorOnlyError) {
        return [
            'reload' => false,
            'anchor' => true,
            'reason' => 'anchor-only failure; retrying the MSS anchor load',
            'state' => null,
        ];
    }
    if ($rendered['mss'] !== $wanted['mss']) {
        return ['reload' => false, 'anchor' => true, 'reason' => 'MSS lines changed', 'state' => null];
    }
    return ['reload' => false, 'anchor' => false, 'reason' => 'current', 'state' => null];
}

/**
 * How freshness.php should log an MSS-anchor load attempt it just made,
 * hash-deduplicated so a retry that keeps failing for the same reason logs
 * LOG_ERR once (not every reconcile tick) and a recovery logs LOG_NOTICE
 * once. The retry itself (calling wgipv6_load_mss_anchor) always runs every
 * tick regardless of this decision -- only the logging is throttled.
 *
 * @param string|null $priorFailHash the anchor_fail_hash last persisted in
 *                                     freshness.json, or null
 * @param bool        $success       whether this tick's wgipv6_load_mss_anchor() call succeeded
 * @param array       $mssLines      the lines that were (re)loaded
 * @return array ['log_error' => bool, 'log_recovery' => bool, 'fail_hash' => string|null]
 *               fail_hash is what freshness.php should now persist as
 *               anchor_fail_hash (null clears it, on success).
 */
function wgipv6_anchor_log_plan($priorFailHash, $success, array $mssLines) {
    if ($success) {
        return ['log_error' => false, 'log_recovery' => $priorFailHash !== null, 'fail_hash' => null];
    }
    $hash = wgipv6_hash_array($mssLines);
    return ['log_error' => $priorFailHash !== $hash, 'log_recovery' => false, 'fail_hash' => $hash];
}

/**
 * True iff the call stack contains filter_configure_sync -- i.e. this is a
 * real filter reload, not a rules-listing call that only wants the hook to
 * enumerate rules for display. Pure over the frames debug_backtrace() gives
 * it, so it is directly testable with a fake frame list.
 *
 * @param array $frames debug_backtrace()-shaped frames
 * @return bool
 */
function wgipv6_in_filter_reload(array $frames) {
    foreach ($frames as $frame) {
        if (($frame['function'] ?? null) === 'filter_configure_sync') {
            return true;
        }
    }
    return false;
}

/**
 * The plugins_firewall hook body. Never throws.
 *
 * $wanted, $loader, $writer and $inReload are injectable so the self-test can
 * exercise every path without config, pf or the filesystem -- in particular,
 * $inReload lets a case force "inside a real filter reload" true or false
 * without a stand-in for core's filter_configure_sync (defining one globally
 * would collide with the real function in a process that has filter.inc
 * loaded, and risks triggering an actual reload).
 */
function wgipv6_render_firewall($fw, $wanted = null, $apply = true, &$rendered = null, $loader = null, $writer = null, $inReload = null) {
    $rendered = ['at' => time(), 'failed' => false, 'error' => '', 'enabled' => false,
                 'pins' => ['wan' => [], 'inner' => []], 'mss' => []];
    $loader = $loader ?? 'wgipv6_load_mss_anchor';
    $writer = $writer ?? 'wgipv6_write_rendered';
    $inReload = $inReload ?? function () {
        return wgipv6_in_filter_reload(debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS));
    };
    /* $apply already lets the self-test force pfctl/write off; it is also
     * gated on actually being inside a filter reload, so a rules-listing
     * call (list_non_mvc_rules.php, firewall_rule_lookup.php) that merely
     * enumerates rules for display never touches pf or rendered.json. */
    $apply = $apply && $inReload();
    try {
        /* register the anchor first: a later failure (derivation, malformed
         * pins) still leaves it in the ruleset, with whatever it last
         * loaded, instead of vanishing along with the rules. */
        $fw->registerAnchor(WGIPV6_MSS_ANCHOR, 'fw', 0, 'head');
        $w = $wanted !== null ? $wanted() : wgipv6_wanted_render();
        if ($w['enabled']) {
            foreach (wgipv6_pin_rules($w['pins']) as $conf) {
                $fw->registerFilterRule(WGIPV6_PIN_PRIORITY, $conf);
            }
        }
        $rendered['enabled'] = $w['enabled'];
        $rendered['pins'] = $w['enabled'] ? $w['pins'] : ['wan' => [], 'inner' => []];
        $rendered['mss'] = $w['enabled'] ? $w['mss'] : [];
        if ($apply && !$loader($rendered['mss'])) {
            $rendered['failed'] = true;
            $rendered['error'] = 'MSS anchor load failed (see syslog)';
        }
    } catch (\Throwable $e) {
        $rendered = ['at' => time(), 'failed' => true, 'error' => $e->getMessage(), 'enabled' => false,
                     'pins' => ['wan' => [], 'inner' => []], 'mss' => []];
        syslog(LOG_ERR, '[wgipv6gw-render] rules not rendered: ' . $e->getMessage());
    }
    if ($apply) {
        try {
            $writer($rendered);
        } catch (\Throwable $e) {
            syslog(LOG_ERR, '[wgipv6gw-render] could not write ' . WGIPV6_RENDERED_FILE . ': ' . $e->getMessage());
        }
    }
}

/**
 * Self-test for the render wrapper. No config, no pf, no /var/run.
 *
 * @return int exit code, 0 when every case passes
 */
function wgipv6_render_selftest() {
    $fail = 0;
    $total = 0;

    $makeFw = function () {
        return new class {
            public $rules = [];
            public $anchors = [];
            public function registerFilterRule($prio, $conf, $defaults = null) { $this->rules[] = [$prio, $conf]; }
            public function registerAnchor($name, $type = 'fw', $priority = 0, $placement = 'tail', $quick = false) { $this->anchors[] = [$name, $type, $placement]; }
        };
    };

    /* $inReload stubs stand in for "inside a real filter reload"; never
     * force it true without also stubbing $loader and $writer, or the case
     * would run the real pfctl call and/or write the real rendered.json. */
    $inReloadTrue = function () { return true; };

    $pins = ['wan' => [['wan_if' => 'opt1', 'family' => 'inet', 'endpoints' => ['198.51.100.10']]], 'inner' => ['opt11']];
    $mss = ['match on wg1 inet proto tcp all scrub (max-mss 1336)'];

    /* case 1: a wanted set with one WAN pin, one inner opt and MSS lines */
    $fw = $makeFw();
    $rendered = null;
    wgipv6_render_firewall($fw, function () use ($pins, $mss) {
        return ['enabled' => true, 'pins' => $pins, 'mss' => $mss];
    }, false, $rendered);
    $ok = count($fw->rules) === 2
        && $fw->rules[0][0] === WGIPV6_PIN_PRIORITY && $fw->rules[1][0] === WGIPV6_PIN_PRIORITY
        && $fw->anchors === [[WGIPV6_MSS_ANCHOR, 'fw', 'head']]
        && $rendered['failed'] === false && $rendered['enabled'] === true
        && $rendered['pins'] === $pins && $rendered['mss'] === $mss;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] render_firewall: enabled with pins and MSS => rules, anchor, rendered record\n", $ok ? 'PASS' : 'FAIL');

    /* case 2: $wanted throws => anchor is kept (registered before $wanted()
     * runs), no rules, failed with the message */
    $fw = $makeFw();
    $rendered = null;
    wgipv6_render_firewall($fw, function () {
        throw new \TypeError('boom');
    }, false, $rendered);
    $ok = $fw->rules === [] && $fw->anchors === [[WGIPV6_MSS_ANCHOR, 'fw', 'head']]
        && $rendered['failed'] === true && $rendered['error'] === 'boom';
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] render_firewall: \$wanted throws => no rules, anchor kept, failed recorded\n", $ok ? 'PASS' : 'FAIL');

    /* case 3: enabled => false => no rules, anchor still registered (harmless), empty MSS */
    $fw = $makeFw();
    $rendered = null;
    wgipv6_render_firewall($fw, function () {
        return ['enabled' => false, 'pins' => ['wan' => [], 'inner' => []], 'mss' => []];
    }, false, $rendered);
    $ok = $fw->rules === [] && $fw->anchors === [[WGIPV6_MSS_ANCHOR, 'fw', 'head']]
        && $rendered['failed'] === false && $rendered['enabled'] === false && $rendered['mss'] === [];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] render_firewall: disabled => no rules, anchor still registered, empty MSS\n", $ok ? 'PASS' : 'FAIL');

    /* case 4: malformed pins make wgipv6_pin_rules() throw building the
     * rules => anchor is still kept, no rules, failed */
    $fw = $makeFw();
    $rendered = null;
    $badPins = ['wan' => [['wan_if' => 'opt1', 'family' => 'inet', 'endpoints' => 'not-an-array']], 'inner' => []];
    wgipv6_render_firewall($fw, function () use ($badPins) {
        return ['enabled' => true, 'pins' => $badPins, 'mss' => []];
    }, false, $rendered);
    $ok = $fw->rules === [] && $fw->anchors === [[WGIPV6_MSS_ANCHOR, 'fw', 'head']] && $rendered['failed'] === true;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] render_firewall: malformed pins throw building rules => anchor kept, failed recorded\n", $ok ? 'PASS' : 'FAIL');

    /* case 5: apply=true but $inReload says no (the default would also say
     * no here, since the self-test itself is not inside a real filter
     * reload) => neither the loader nor the writer is invoked */
    $fw = $makeFw();
    $rendered = null;
    $loaderCalls = 0;
    $writerCalls = 0;
    $loader = function ($lines) use (&$loaderCalls) { $loaderCalls++; return true; };
    $writer = function ($r) use (&$writerCalls) { $writerCalls++; return true; };
    wgipv6_render_firewall($fw, function () use ($pins, $mss) {
        return ['enabled' => true, 'pins' => $pins, 'mss' => $mss];
    }, true, $rendered, $loader, $writer, function () { return false; });
    $ok = $loaderCalls === 0 && $writerCalls === 0 && $rendered['failed'] === false;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] render_firewall: apply=true, not in a filter reload => loader and writer not called\n", $ok ? 'PASS' : 'FAIL');

    /* case 6: inside a (stubbed) real filter reload, the loader fails =>
     * failed true, with pins/mss/rules kept. The writer is stubbed too, so
     * this case cannot reach the real wgipv6_write_rendered(). */
    $fw = $makeFw();
    $rendered = null;
    $loader = function ($lines) { return false; };
    $writer = function ($r) { return true; };
    wgipv6_render_firewall($fw, function () use ($pins, $mss) {
        return ['enabled' => true, 'pins' => $pins, 'mss' => $mss];
    }, true, $rendered, $loader, $writer, $inReloadTrue);
    $ok = $rendered['failed'] === true && $rendered['pins'] === $pins && $rendered['mss'] === $mss
        && count($fw->rules) === 2 && $fw->anchors === [[WGIPV6_MSS_ANCHOR, 'fw', 'head']];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] render_firewall: inside a filter reload, loader fails => failed true, pins/mss/rules kept\n", $ok ? 'PASS' : 'FAIL');

    /* case 7: inside a (stubbed) real filter reload, the writer throws =>
     * caught, no exception escapes. The loader is stubbed too, so this case
     * cannot reach the real pfctl. */
    $fw = $makeFw();
    $rendered = null;
    $loader = function ($lines) { return true; };
    $writer = function ($r) { throw new \RuntimeException('write boom'); };
    $escaped = null;
    try {
        wgipv6_render_firewall($fw, function () use ($pins, $mss) {
            return ['enabled' => true, 'pins' => $pins, 'mss' => $mss];
        }, true, $rendered, $loader, $writer, $inReloadTrue);
    } catch (\Throwable $e) {
        $escaped = $e;
    }
    $ok = $escaped === null && $rendered['failed'] === false && $rendered['pins'] === $pins;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] render_firewall: writer throws inside a filter reload => caught, no exception escapes\n", $ok ? 'PASS' : 'FAIL');

    /* wgipv6_in_filter_reload: pure helper over debug_backtrace-shaped frames */
    $ok = wgipv6_in_filter_reload([['function' => 'foo'], ['function' => 'filter_configure_sync'], ['function' => 'bar']]) === true;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] in_filter_reload: frame present => true\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgipv6_in_filter_reload([['function' => 'foo'], ['function' => 'bar']]) === false;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] in_filter_reload: frame absent => false\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgipv6_in_filter_reload([]) === false;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] in_filter_reload: no frames => false\n", $ok ? 'PASS' : 'FAIL');

    /* wgipv6_freshness_plan: pure over its five arguments, no I/O */
    $wanted = ['enabled' => true, 'pins' => $pins, 'mss' => $mss];
    $emptyPins = ['wan' => [], 'inner' => []];
    $wantedDisabled = ['enabled' => false, 'pins' => $emptyPins, 'mss' => []];
    $otherPins = ['wan' => [['wan_if' => 'opt2', 'family' => 'inet', 'endpoints' => ['198.51.100.20']]], 'inner' => []];
    $thirdPins = ['wan' => [['wan_if' => 'opt3', 'family' => 'inet', 'endpoints' => ['198.51.100.30']]], 'inner' => []];
    $otherMss = ['match on wg2 inet proto tcp all scrub (max-mss 1200)'];
    $current = ['at' => 1000, 'failed' => false, 'error' => '', 'enabled' => true, 'pins' => $pins, 'mss' => $mss];
    $currentEmpty = ['at' => 1000, 'failed' => false, 'error' => '', 'enabled' => false, 'pins' => $emptyPins, 'mss' => []];

    $p = wgipv6_freshness_plan($wanted, null, null, null, 1000);
    $ok = $p['reload'] === true && $p['anchor'] === false && $p['state'] !== null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: no rendered record, wanted has pins => reload\n", $ok ? 'PASS' : 'FAIL');

    $p = wgipv6_freshness_plan($wantedDisabled, null, null, null, 1000);
    $ok = $p['reload'] === false && $p['anchor'] === false && $p['state'] === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: no rendered record, wanted disabled/empty => nothing\n", $ok ? 'PASS' : 'FAIL');

    $r = $current;
    $r['pins'] = $otherPins;
    $p = wgipv6_freshness_plan($wanted, $r, null, null, 1000);
    $ok = $p['reload'] === true && $p['anchor'] === false;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: pins differ => reload\n", $ok ? 'PASS' : 'FAIL');

    $p = wgipv6_freshness_plan($wantedDisabled, $current, null, null, 1000);
    $ok = $p['reload'] === true && $p['anchor'] === false;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: wanted disabled but rendered still carries pins => reload (removes them)\n", $ok ? 'PASS' : 'FAIL');

    $r = $current;
    $r['mss'] = $otherMss;
    $p = wgipv6_freshness_plan($wanted, $r, null, null, 1000);
    $ok = $p['reload'] === false && $p['anchor'] === true && $p['state'] === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: mss only differs => anchor retry\n", $ok ? 'PASS' : 'FAIL');

    /* wgipv6_error_file_stale: pure boundary check, same-second counts as stale */
    $ok = wgipv6_error_file_stale(1000, 1000) === true;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] error_file_stale: equal seconds => stale\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgipv6_error_file_stale(999, 1000) === false;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] error_file_stale: one second earlier => not stale\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgipv6_error_file_stale(1001, 1000) === true;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] error_file_stale: one second later => stale\n", $ok ? 'PASS' : 'FAIL');

    $p = wgipv6_freshness_plan($wanted, $current, 1000, null, 1000);
    $ok = $p['reload'] === true && $p['anchor'] === false;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: rules.debug.error at the same second as the render => reload\n", $ok ? 'PASS' : 'FAIL');

    $p = wgipv6_freshness_plan($wanted, $current, 1500, null, 1600);
    $ok = $p['reload'] === true && $p['anchor'] === false;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: rules.debug.error newer than the render => reload\n", $ok ? 'PASS' : 'FAIL');

    $p = wgipv6_freshness_plan($wantedDisabled, $currentEmpty, 1500, null, 1600);
    $ok = $p['reload'] === false && $p['anchor'] === false && $p['state'] === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: rules.debug.error present but rendered/wanted pins are empty => nothing\n", $ok ? 'PASS' : 'FAIL');

    $r = $current;
    $r['failed'] = true;
    $r['error'] = 'MSS anchor load failed (see syslog)';
    $p = wgipv6_freshness_plan($wanted, $r, null, null, 1000);
    $ok = $p['reload'] === false && $p['anchor'] === true && $p['state'] === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: anchor-only failure (pins match) => anchor retry, no reload\n", $ok ? 'PASS' : 'FAIL');

    $r = $current;
    $r['failed'] = true;
    $r['error'] = 'boom, something else broke';
    $p = wgipv6_freshness_plan($wanted, $r, null, null, 1000);
    $ok = $p['reload'] === true && $p['anchor'] === false;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: failed for a non-anchor reason, pins non-empty => reload\n", $ok ? 'PASS' : 'FAIL');

    $r = $currentEmpty;
    $r['failed'] = true;
    $r['error'] = 'boom, something else broke';
    $p = wgipv6_freshness_plan($wantedDisabled, $r, null, null, 1000);
    $ok = $p['reload'] === false && $p['anchor'] === false;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: failed for a non-anchor reason, but pins empty => nothing\n", $ok ? 'PASS' : 'FAIL');

    /* rate limiting with exponential back-off */
    $r = $current;
    $r['pins'] = $otherPins;
    $p1 = wgipv6_freshness_plan($wanted, $r, null, null, 1000);
    $ok = $p1['reload'] === true && $p1['state']['notified'] === false && $p1['state']['window'] === WGIPV6_RELOAD_SUPPRESS_SECONDS;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: first reload request => state recorded, window = base, not yet notified\n", $ok ? 'PASS' : 'FAIL');

    $p2 = wgipv6_freshness_plan($wanted, $r, null, $p1['state'], 1010);
    $ok = $p2['reload'] === false && $p2['anchor'] === false
        && $p1['state']['notified'] === false && $p2['state']['notified'] === true
        && $p2['state']['requested_at'] === $p1['state']['requested_at']
        && $p2['state']['window'] === $p1['state']['window'];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: repeat within the window, same pins => suppressed, first-time notify, window unchanged\n", $ok ? 'PASS' : 'FAIL');

    $p3 = wgipv6_freshness_plan($wanted, $r, null, $p2['state'], 1020);
    $ok = $p3['reload'] === false && $p3['state']['notified'] === true;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: further repeat, already notified => suppressed quietly (no new notify transition)\n", $ok ? 'PASS' : 'FAIL');

    $now = 1000 + $p1['state']['window'];
    $p4 = wgipv6_freshness_plan($wanted, $r, null, $p1['state'], $now);
    $ok = $p4['reload'] === true && $p4['state']['window'] === 2 * WGIPV6_RELOAD_SUPPRESS_SECONDS;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: repeat after the window elapses, same hash => reload allowed, window doubles\n", $ok ? 'PASS' : 'FAIL');

    /* keep doubling until it hits the cap: 300 -> 600 -> 1200 -> 2400 -> 3600 -> 3600 */
    $state = $p4['state'];
    $now += $state['window'];
    $expected = [1200, 2400, 3600, 3600];
    $backoffOk = true;
    foreach ($expected as $want) {
        $pn = wgipv6_freshness_plan($wanted, $r, null, $state, $now);
        if ($pn['reload'] !== true || $pn['state']['window'] !== $want) {
            $backoffOk = false;
        }
        $state = $pn['state'];
        $now += $state['window'];
    }
    $fail += $backoffOk ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: back-off keeps doubling, capped at %d\n", $backoffOk ? 'PASS' : 'FAIL', WGIPV6_RELOAD_MAX_WINDOW_SECONDS);

    $wanted2 = ['enabled' => true, 'pins' => $thirdPins, 'mss' => $mss];
    $p5 = wgipv6_freshness_plan($wanted2, $r, null, $p1['state'], 1010);
    $ok = $p5['reload'] === true && $p5['state']['window'] === WGIPV6_RELOAD_SUPPRESS_SECONDS;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: repeat within the window but the wanted pins changed => reload allowed, window resets to base\n", $ok ? 'PASS' : 'FAIL');

    $backStepped = ['requested_at' => 5000, 'pins_hash' => wgipv6_hash_array($wanted['pins']), 'notified' => false, 'window' => 300];
    $p = wgipv6_freshness_plan($wanted, $r, null, $backStepped, 1000);
    $ok = $p['reload'] === true;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: negative elapsed (clock stepped back) => never suppressed\n", $ok ? 'PASS' : 'FAIL');

    $noRequestedAt = ['pins_hash' => wgipv6_hash_array($wanted['pins']), 'notified' => false, 'window' => 300];
    $p = wgipv6_freshness_plan($wanted, $r, null, $noRequestedAt, 1000);
    $ok = $p['reload'] === true;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: state missing requested_at => allowed\n", $ok ? 'PASS' : 'FAIL');

    $p = wgipv6_freshness_plan($wanted, $current, null, $p1['state'], 1010);
    $ok = $p['reload'] === false && $p['anchor'] === false && $p['reason'] === 'current' && $p['state'] === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: pins and mss both current => nothing, stale state cleared\n", $ok ? 'PASS' : 'FAIL');

    /* wgipv6_anchor_log_plan: pure, hash-deduplicated anchor logging decision */
    $mssHash = wgipv6_hash_array($mss);
    $otherMssHash = wgipv6_hash_array($otherMss);

    $lp = wgipv6_anchor_log_plan(null, false, $mss);
    $ok = $lp['log_error'] === true && $lp['log_recovery'] === false && $lp['fail_hash'] === $mssHash;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] anchor_log_plan: first failure => log_error, hash recorded\n", $ok ? 'PASS' : 'FAIL');

    $lp = wgipv6_anchor_log_plan($mssHash, false, $mss);
    $ok = $lp['log_error'] === false && $lp['log_recovery'] === false && $lp['fail_hash'] === $mssHash;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] anchor_log_plan: repeat failure, same hash => quiet\n", $ok ? 'PASS' : 'FAIL');

    $lp = wgipv6_anchor_log_plan($mssHash, false, $otherMss);
    $ok = $lp['log_error'] === true && $lp['fail_hash'] === $otherMssHash;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] anchor_log_plan: failure with different lines => logs again, hash updated\n", $ok ? 'PASS' : 'FAIL');

    $lp = wgipv6_anchor_log_plan($mssHash, true, $mss);
    $ok = $lp['log_error'] === false && $lp['log_recovery'] === true && $lp['fail_hash'] === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] anchor_log_plan: recovers after failing => log_recovery, hash cleared\n", $ok ? 'PASS' : 'FAIL');

    $lp = wgipv6_anchor_log_plan(null, true, $mss);
    $ok = $lp['log_error'] === false && $lp['log_recovery'] === false && $lp['fail_hash'] === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] anchor_log_plan: success with no prior failure => quiet\n", $ok ? 'PASS' : 'FAIL');

    printf("%d/%d passed\n", $total - $fail, $total);
    return $fail === 0 ? 0 : 1;
}
