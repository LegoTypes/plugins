<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Reads the status page's template as text and holds three properties of its script: plain() is the exact inverse
 * of core's escaping with no HTML parser, the notice banner sets one text line per note, and the page reads the
 * count of hold records that were not this plugin's and the core drift only the package removal depends on.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/selftest.php';

wf_register_suite('view', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $path = __DIR__ . '/../src/opnsense/mvc/app/views/OPNsense/WanFailover/index.volt';
    $view = file_get_contents($path);
    if ($view === false) {
        wf_check($t, 'the status page template is readable', false);
        return wf_tally_report('view', $t);
    }

    $inverse = "return String(s === undefined || s === null ? '' : s)"
        . ".replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');";
    wf_check($t, '(v1) plain() is the exact inverse of core\'s escaping', str_contains($view, $inverse));
    wf_check($t, '(v1) no template code parses its input as HTML', !str_contains($view, '.html('));

    wf_check(
        $t,
        '(v2) the banner appends one text line per note',
        str_contains($view, "box.append(\$('<div/>').text(n));")
    );
    wf_check($t, '(v2) the notes are not run together', !str_contains($view, 'notes.join('));

    wf_check($t, '(v3) the page reads the count of foreign hold records', str_contains($view, 'data.foreign'));
    wf_check($t, '(v4) the page notes a drift that only the package removal\'s re-sync depends on',
        str_contains($view, '(data.contract || {}).removal'));
    wf_check($t, 'the page notes an unjudgeable WAN in one whole sentence',
        str_contains($view, "w.unjudgeable === 'monitor_disable'") && str_contains($view, "w.unjudgeable === 'disabled'")
        && str_contains($view, ".replace('%s', plain(w.name))")
        && str_contains($view, "lang._('%s is disabled: the plugin can never judge it, so it never backs a hold. Enable it "
            . "under System: Gateways: Configuration, or deselect it.')")
        && str_contains($view, "lang._('%s has gateway monitoring disabled: the plugin can never judge it, so it never backs "
            . "a hold. Enable monitoring under System: Gateways: Configuration, or deselect it.')"));

    wf_check($t, 'the page reads its status from service/wan_status',
        str_contains($view, "ajaxGet('/api/wanfailover/service/wan_status'"));
    wf_check($t, 'the page\'s Fail back now posts to service/failback_now',
        str_contains($view, 'data-endpoint="/api/wanfailover/service/failback_now"'));
    wf_check($t, 'the page calls no run-together endpoint',
        !str_contains($view, 'service/holds') && !str_contains($view, 'service/failbacknow'));
    $removalNote = strpos($view, '(data.contract || {}).removal');
    $namesNote = strpos($view, "\$.each((data.contract || {}).names || [], function (i, p) { notes.push(\"{{ lang._('Core "
        . "changed (a gateway name core accepts may read here as unresolved):') }} \" + plain(p)); });");
    wf_check($t, 'the page notes a names drift', $removalNote !== false && $namesNote !== false && $namesNote > $removalNote);

    return wf_tally_report('view', $t);
});
