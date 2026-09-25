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

function wgipv6_load_mss_anchor(array $lines) {
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
    if ($rc !== 0) {
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

    printf("%d/%d passed\n", $total - $fail, $total);
    return $fail === 0 ? 0 : 1;
}
