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
 */

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

function wgipv6_write_rendered(array $r) {
    @mkdir(dirname(WGIPV6_RENDERED_FILE), 0755, true);
    $tmp = WGIPV6_RENDERED_FILE . '.tmp';
    file_put_contents($tmp, json_encode($r));
    rename($tmp, WGIPV6_RENDERED_FILE);
}

/**
 * The plugins_firewall hook body. Never throws.
 */
function wgipv6_render_firewall($fw, $wanted = null, $apply = true, &$rendered = null) {
    $rendered = ['at' => time(), 'failed' => false, 'error' => '', 'enabled' => false,
                 'pins' => ['wan' => [], 'inner' => []], 'mss' => []];
    try {
        $w = $wanted !== null ? $wanted() : wgipv6_wanted_render();
        $fw->registerAnchor(WGIPV6_MSS_ANCHOR, 'fw', 0, 'head');
        if ($w['enabled']) {
            foreach (wgipv6_pin_rules($w['pins']) as $conf) {
                $fw->registerFilterRule(WGIPV6_PIN_PRIORITY, $conf);
            }
        }
        $rendered['enabled'] = $w['enabled'];
        $rendered['pins'] = $w['enabled'] ? $w['pins'] : ['wan' => [], 'inner' => []];
        $rendered['mss'] = $w['enabled'] ? $w['mss'] : [];
        if ($apply && !wgipv6_load_mss_anchor($rendered['mss'])) {
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
            wgipv6_write_rendered($rendered);
        } catch (\Throwable $e) {
            syslog(LOG_ERR, '[wgipv6gw-render] could not write ' . WGIPV6_RENDERED_FILE . ': ' . $e->getMessage());
        }
    }
}

class WgIpv6FakeFw
{
    public $rules = [];
    public $anchors = [];
    public function registerFilterRule($prio, $conf, $defaults = null) { $this->rules[] = [$prio, $conf]; }
    public function registerAnchor($name, $type = 'fw', $priority = 0, $placement = 'tail', $quick = false) { $this->anchors[] = [$name, $type, $placement]; }
}

/**
 * Self-test for the render wrapper. No config, no pf, no /var/run.
 *
 * @return int exit code, 0 when every case passes
 */
function wgipv6_render_selftest() {
    $fail = 0;
    $total = 0;

    /* case 1: a wanted set with one WAN pin, one inner opt and MSS lines */
    $pins = ['wan' => [['wan_if' => 'opt1', 'family' => 'inet', 'endpoints' => ['198.51.100.10']]], 'inner' => ['opt11']];
    $mss = ['match on wg1 inet proto tcp all scrub (max-mss 1336)'];
    $fw = new WgIpv6FakeFw();
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

    /* case 2: $wanted throws => no rules, no anchor, failed with the message */
    $fw = new WgIpv6FakeFw();
    $rendered = null;
    wgipv6_render_firewall($fw, function () {
        throw new \TypeError('boom');
    }, false, $rendered);
    $ok = $fw->rules === [] && $fw->anchors === []
        && $rendered['failed'] === true && $rendered['error'] === 'boom';
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] render_firewall: \$wanted throws => no rules, no anchor, failed recorded\n", $ok ? 'PASS' : 'FAIL');

    /* case 3: enabled => false => no rules, anchor still registered (harmless), empty MSS */
    $fw = new WgIpv6FakeFw();
    $rendered = null;
    wgipv6_render_firewall($fw, function () {
        return ['enabled' => false, 'pins' => ['wan' => [], 'inner' => []], 'mss' => []];
    }, false, $rendered);
    $ok = $fw->rules === [] && $fw->anchors === [[WGIPV6_MSS_ANCHOR, 'fw', 'head']]
        && $rendered['failed'] === false && $rendered['enabled'] === false && $rendered['mss'] === [];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] render_firewall: disabled => no rules, anchor still registered, empty MSS\n", $ok ? 'PASS' : 'FAIL');

    printf("%d/%d passed\n", $total - $fail, $total);
    return $fail === 0 ? 0 : 1;
}
