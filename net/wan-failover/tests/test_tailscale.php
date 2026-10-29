<?php

declare(strict_types=1);

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

/*
 * Tailscale restart decision.
 */

require_once __DIR__ . '/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/tailscale.php';

wf_register_suite('tailscale', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $A = '203.0.113.1';
    $B = '198.51.100.254';

    $r = wf_tailscale_decide(wf_ts_new(), $A, 1000, 90, 300);
    wf_check($t, 'first observation records the default, no restart', !$r['restart'] && $r['ts']['default_gw'] === $A);
    $ts = $r['ts'];

    $r = wf_tailscale_decide($ts, $A, 1015, 90, 300);
    wf_check($t, 'unchanged default: no restart', !$r['restart']);

    $r = wf_tailscale_decide($ts, $B, 1030, 90, 300);
    wf_check($t, 'core-driven change, not yet stable: defer', !$r['restart'] && str_starts_with($r['reason'], 'defer'));
    $r2 = wf_tailscale_decide($r['ts'], $A, 1045, 90, 300);
    wf_check($t, 'flap back before stable: no restart', !$r2['restart'] && $r2['ts']['default_gw'] === $A);
    $r3 = wf_tailscale_decide($r['ts'], $B, 1120, 90, 300);
    wf_check($t, 'stable for 90 s: one restart', $r3['restart'] && $r3['ts']['default_gw'] === $B && $r3['ts']['restarted_at'] === 1120);

    $planned = $ts;
    $planned['expected_default'] = $B;
    $r = wf_tailscale_decide($planned, $B, 1030, 90, 300);
    wf_check($t, 'planner-caused change matching expected: immediate restart', $r['restart']);

    $cool = $r['ts'];
    $cool['expected_default'] = $A;
    $r = wf_tailscale_decide($cool, $A, 1100, 90, 300);
    wf_check($t, 'cooldown unmet: defer even for a planned change', !$r['restart'] && $r['reason'] === 'defer: cooldown');
    $r = wf_tailscale_decide($r['ts'], $A, 1331, 90, 300);
    wf_check($t, 'cooldown met later: restart', $r['restart']);

    $r = wf_tailscale_decide($ts, null, 1030, 90, 300);
    wf_check($t, 'no default route: lost, no restart', !$r['restart'] && $r['ts']['lost']);
    $r2 = wf_tailscale_decide($r['ts'], $A, 1040, 90, 300);
    wf_check($t, 'same default back after loss, not yet stable: defer', !$r2['restart']);
    $r3 = wf_tailscale_decide($r2['ts'], $A, 1131, 90, 300);
    wf_check($t, 'same default stable after loss: one restart', $r3['restart'] && !$r3['ts']['lost']);
    return wf_tally_report('tailscale', $t);
});
