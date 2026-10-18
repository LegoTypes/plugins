<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Choice, failback timers and probe outcomes (spec sections 3.3 and 3.5).
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/constants.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/choose.php';

/**
 * @return array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int, probe_failures: int}
 */
function uu_test_timer(int $counted = 0, ?int $failedUntil = null, ?int $lastAt = null): array
{
    return ['usable_since' => null, 'counted' => $counted, 'last_at' => $lastAt,
            'resolver_failed_until' => $failedUntil, 'probe_failures' => 0];
}

uu_register_suite('choose', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $tiers = [['wg-a'], ['wg-b']];
    $up = ['wg-a' => true, 'wg-b' => true];
    $delay = 120;
    $nd = ['wg-a' => false, 'wg-b' => false, 'wg-c' => false];

    $timers = ['wg-a' => uu_test_timer(120), 'wg-b' => uu_test_timer(500)];
    uu_check($t, 'tier 1 settled usable 120 s from fallback -> [wg-a, wg-b]',
        uu_candidates($tiers, $up, $nd, $timers, 1000, $delay, null) === ['wg-a', 'wg-b']);
    $timers = ['wg-a' => uu_test_timer(119), 'wg-b' => uu_test_timer(119)];
    uu_check($t, 'usable 119 s from fallback -> [] (stay in fallback)',
        uu_candidates($tiers, $up, $nd, $timers, 1000, $delay, null) === []);

    $timers = ['wg-a' => uu_test_timer(119), 'wg-b' => uu_test_timer(0)];
    uu_check($t, 'on tier 2, tier 1 back 119 s: stays on wg-b',
        uu_candidates($tiers, $up, $nd, $timers, 1000, $delay, 'wg-b') === ['wg-b']);
    $timers = ['wg-a' => uu_test_timer(120), 'wg-b' => uu_test_timer(0)];
    uu_check($t, 'on tier 2, tier 1 counted 120 s: wg-a first, wg-b after',
        uu_candidates($tiers, $up, $nd, $timers, 1000, $delay, 'wg-b') === ['wg-a', 'wg-b']);
    uu_check($t, 'wg-b down, wg-a usable with counted 0: [] (better tier needs the delay; fallback)',
        uu_candidates($tiers, ['wg-a' => true, 'wg-b' => false], ['wg-a' => false, 'wg-b' => true], ['wg-a' => uu_test_timer(0), 'wg-b' => uu_test_timer(0)],
            1000, $delay, 'wg-b') === []);
    uu_check($t, 'wg-a current and down, wg-b usable: moves to the worse tier without delay',
        uu_candidates($tiers, ['wg-a' => false, 'wg-b' => true], ['wg-a' => true, 'wg-b' => false],
            ['wg-a' => uu_test_timer(0), 'wg-b' => uu_test_timer(0)], 1000, $delay, 'wg-a') === ['wg-b']);
    $three = [['wg-a', 'wg-c'], ['wg-b']];
    $timers = ['wg-a' => uu_test_timer(0), 'wg-b' => uu_test_timer(0), 'wg-c' => uu_test_timer(0)];
    uu_check($t, 'current first within its own tier, then configured order, then worse tiers',
        uu_candidates($three, $up + ['wg-c' => true], $nd, $timers, 1000, $delay, 'wg-c') === ['wg-c', 'wg-a', 'wg-b']);

    $timers = ['wg-a' => uu_test_timer(500, 1100), 'wg-b' => uu_test_timer(500)];
    uu_check($t, 'resolver-failed member skipped until its mark expires',
        uu_candidates($tiers, $up, $nd, $timers, 1000, $delay, null) === ['wg-b']);
    uu_check($t, 'mark expired at now == until',
        uu_candidates($tiers, $up, $nd, $timers, 1100, $delay, null) === ['wg-a', 'wg-b']);
    $timers = ['wg-a' => uu_test_timer(0), 'wg-b' => uu_test_timer(0, 1100)];
    uu_check($t, 'current member resolver-failed is not eligible to stay',
        uu_candidates($tiers, $up, $nd, $timers, 1000, $delay, 'wg-b') === []);

    $timers = ['wg-a' => uu_test_timer(0), 'wg-b' => uu_test_timer(0)];
    uu_check($t, 'current young (not down, not usable_settled) stays first',
        uu_candidates($tiers, ['wg-a' => true, 'wg-b' => false], $nd, $timers, 1000, $delay, 'wg-b') === ['wg-b']);
    uu_check($t, 'current down is excluded',
        uu_candidates($tiers, ['wg-a' => false, 'wg-b' => false], ['wg-a' => false, 'wg-b' => true], $timers, 1000,
            $delay, 'wg-b') === []);
    $timers = ['wg-a' => uu_test_timer(500, 1100), 'wg-b' => uu_test_timer(0)];
    uu_check($t, 'better tier past the delay but resolver-failed: current stays',
        uu_candidates($tiers, $up, $nd, $timers, 1000, $delay, 'wg-b') === ['wg-b']);

    // Timer updates.
    $settled = ['wg-a' => 'settled', 'wg-b' => 'settled'];
    $none = ['wg-a' => false, 'wg-b' => false];
    $r = uu_timers_update([], $settled, $up, $none, 1000);
    uu_check($t, 'first reading creates the entry, counts 0, records last_at and usable_since',
        $r['wg-a']['counted'] === 0 && $r['wg-a']['last_at'] === 1000 && $r['wg-a']['usable_since'] === 1000);
    $r = uu_timers_update($r, $settled, $up, $none, 1060);
    uu_check($t, 'settled usable adds the elapsed time', $r['wg-a']['counted'] === 60);
    $r = uu_timers_update($r, ['wg-a' => 'young', 'wg-b' => 'settled'], $up, $none, 1120);
    uu_check($t, 'young reading pauses: neither counts nor resets', $r['wg-a']['counted'] === 60
        && $r['wg-b']['counted'] === 120);
    $r = uu_timers_update($r, $settled, $up, $none, 1180);
    uu_check($t, 'settled again after a young tick: the paused gap is not counted',
        $r['wg-a']['counted'] === 60 && $r['wg-b']['counted'] === 180);
    $r = uu_timers_update($r, $settled, $up, ['wg-a' => true, 'wg-b' => false], 1240);
    uu_check($t, 'down resets the timer', $r['wg-a']['counted'] === 0 && $r['wg-a']['usable_since'] === null
        && $r['wg-b']['counted'] === 240);
    $r = uu_timers_update($r, ['wg-a' => 'cached', 'wg-b' => 'none'], $up, $none, 1300);
    uu_check($t, 'cached and none pause', $r['wg-b']['counted'] === 240);

    $r = uu_timers_update(['wg-a' => uu_test_timer(50, 5000, 2000)], ['wg-a' => 'settled'], ['wg-a' => true],
        ['wg-a' => false], 1990);
    uu_check($t, 'negative delta adds 0 and resets nothing',
        $r['wg-a']['counted'] === 50 && $r['wg-a']['resolver_failed_until'] === 5000 && $r['wg-a']['last_at'] === 1990);
    $r = uu_timers_update(['wg-a' => uu_test_timer(10, null, 1000)], ['wg-a' => 'settled'], ['wg-a' => true],
        ['wg-a' => false], 1900);
    uu_check($t, 'a long settled gap (900 s) counts in full', $r['wg-a']['counted'] === 910);
    $r = uu_timers_update(['wg-a' => uu_test_timer(80, null, null)], ['wg-a' => 'young'], ['wg-a' => false],
        ['wg-a' => true], 1000);
    uu_check($t, 'down on a young tick still resets counted', $r['wg-a']['counted'] === 0);

    // Probe outcomes.
    uu_check($t, 'probe table: pass/pass ok', uu_probe_outcome(true, true, false) === 'ok');
    uu_check($t, 'probe table: pass/fail -> flush_infra', uu_probe_outcome(true, false, false) === 'flush_infra');
    uu_check($t, 'probe table: pass/fail after flush -> fail', uu_probe_outcome(true, false, true) === 'fail');
    uu_check($t, 'probe table: fail/* -> fail', uu_probe_outcome(false, true, false) === 'fail'
        && uu_probe_outcome(false, false, false) === 'fail' && uu_probe_outcome(false, null, false) === 'fail');
    uu_check($t, 'probe table: direct only (no through check) passes', uu_probe_outcome(true, null, false) === 'ok');

    return uu_tally_report('choose', $t);
});
