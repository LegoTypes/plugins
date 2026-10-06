<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Hold start and release decisions, spec section 3.3.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/judge.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/holds.php';

/** @return array{reading: string, judgement: array, held: bool, manual_down: bool, disabled: bool, core_down: bool, raw_loss: ?float, losslow: float, priority: int, no_rehold: bool} */
function wf_t_h(string $reading, ?string $judged, array $over = []): array
{
    $j = wf_judgement_new(0);
    $j['value'] = $judged;
    $j['last_settled_at'] = 1000;
    return array_merge([
        'reading' => $reading, 'judgement' => $j, 'held' => false, 'manual_down' => false, 'disabled' => false,
        'core_down' => false, 'raw_loss' => 0.0, 'losslow' => 10.0, 'priority' => 1, 'no_rehold' => false,
    ], $over);
}

wf_register_suite('holds', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $now = 1010;

    $p = wf_plan_holds(['PRIMARY_WAN' => wf_t_h(WF_CLEAN, WF_CLEAN), 'WAN2' => wf_t_h(WF_BAD, WF_BAD, ['priority' => 2])], $now, 120);
    wf_check($t, 'WAN2 over threshold with PRIMARY clean: hold WAN2', $p['hold'] === ['WAN2'] && $p['release'] === []);

    $p = wf_plan_holds(['PRIMARY_WAN' => wf_t_h(WF_MARGINAL, WF_MARGINAL, ['raw_loss' => 2.0]), 'WAN2' => wf_t_h(WF_BAD, WF_BAD, ['priority' => 2])], $now, 120);
    wf_check($t, 'marginal PRIMARY (2%) is a usable alternative: hold WAN2', $p['hold'] === ['WAN2']);

    $p = wf_plan_holds(['PRIMARY_WAN' => wf_t_h(WF_BAD, WF_BAD), 'WAN2' => wf_t_h(WF_BAD, WF_BAD, ['priority' => 2])], $now, 120);
    wf_check($t, 'both over threshold: nothing held', $p['hold'] === [] && $p['release'] === []);

    $p = wf_plan_holds(['PRIMARY_WAN' => wf_t_h(WF_UNKNOWN, WF_BAD), 'WAN2' => wf_t_h(WF_UNKNOWN, WF_BAD, ['priority' => 2])], $now, 120);
    wf_check($t, 'carried bad judgement with unknown reading never starts a hold (6a)', $p['hold'] === []);

    $p = wf_plan_holds(['PRIMARY_WAN' => wf_t_h(WF_CLEAN, WF_CLEAN, ['core_down' => true]), 'WAN2' => wf_t_h(WF_BAD, WF_BAD, ['priority' => 2])], $now, 120);
    wf_check($t, 'core-down (latency) PRIMARY is not an alternative', $p['hold'] === []);

    $stale = wf_t_h(WF_UNKNOWN, WF_CLEAN);
    $stale['judgement']['last_settled_at'] = 800;
    $p = wf_plan_holds(['PRIMARY_WAN' => $stale, 'WAN2' => wf_t_h(WF_BAD, WF_BAD, ['priority' => 2])], $now, 120);
    wf_check($t, 'alternative last settled 210 s ago (> fresh 120): no hold', $p['hold'] === []);

    $p = wf_plan_holds(['PRIMARY_WAN' => wf_t_h(WF_UNKNOWN, WF_CLEAN, ['raw_loss' => 40.0]), 'WAN2' => wf_t_h(WF_BAD, WF_BAD, ['priority' => 2])], $now, 120);
    wf_check($t, 'alternative young with raw loss 40% > losslow: no hold (N3)', $p['hold'] === []);

    $p = wf_plan_holds(['PRIMARY_WAN' => wf_t_h(WF_CLEAN, WF_CLEAN), 'WAN2' => wf_t_h(WF_MARGINAL, WF_MARGINAL, ['priority' => 2, 'held' => true, 'raw_loss' => 5.0])], $now, 120);
    wf_check($t, 'held WAN2 at 5% (marginal) stays held', $p['release'] === [] && $p['hold'] === []);

    $p = wf_plan_holds(['PRIMARY_WAN' => wf_t_h(WF_CLEAN, WF_CLEAN), 'WAN2' => wf_t_h(WF_CLEAN, WF_CLEAN, ['priority' => 2, 'held' => true])], $now, 120);
    wf_check($t, 'held WAN2 clean: released', $p['release'] === ['WAN2']);

    $p = wf_plan_holds(['PRIMARY_WAN' => wf_t_h(WF_BAD, WF_BAD), 'WAN2' => wf_t_h(WF_CLEAN, WF_CLEAN, ['priority' => 2, 'held' => true])], $now, 120);
    wf_check($t, 'swap (5a): WAN2 clean released, PRIMARY bad held, never both', $p['release'] === ['WAN2'] && $p['hold'] === ['PRIMARY_WAN']);

    $p = wf_plan_holds(['PRIMARY_WAN' => wf_t_h(WF_BAD, WF_BAD), 'WAN2' => wf_t_h(WF_BAD, WF_BAD, ['priority' => 2, 'held' => true, 'raw_loss' => 30.0])], $now, 120);
    wf_check($t, '5a variant: PRIMARY bad, WAN2 still bad: release WAN2 on invariant, hold none', $p['release'] === ['WAN2'] && $p['hold'] === []);

    $p = wf_plan_holds(['PRIMARY_WAN' => wf_t_h(WF_UNKNOWN, WF_CLEAN), 'WAN2' => wf_t_h(WF_BAD, WF_BAD, ['priority' => 2, 'held' => true])], $now, 120);
    wf_check($t, 'unknown alternative never releases (B1)', $p['release'] === []);

    $p = wf_plan_holds(['PRIMARY_WAN' => wf_t_h(WF_UNAVAILABLE, WF_BAD), 'WAN2' => wf_t_h(WF_BAD, WF_BAD, ['priority' => 2, 'held' => true])], $now, 120);
    wf_check($t, 'alternative unavailable (carrier loss): release', $p['release'] === ['WAN2']);

    $p = wf_plan_holds(['PRIMARY_WAN' => wf_t_h(WF_CLEAN, WF_CLEAN), 'WAN2' => wf_t_h(WF_UNAVAILABLE, WF_BAD, ['priority' => 2, 'manual_down' => true])], $now, 120);
    wf_check($t, 'manual force_down WAN is never held by us', $p['hold'] === []);

    $p = wf_plan_holds(['PRIMARY_WAN' => wf_t_h(WF_BAD, WF_BAD), 'WAN2' => wf_t_h(WF_UNAVAILABLE, WF_BAD, ['priority' => 2, 'manual_down' => true])], $now, 120);
    wf_check($t, 'manual force_down on WAN2 means PRIMARY cannot be held (10)', $p['hold'] === []);

    $p = wf_plan_holds(['PRIMARY_WAN' => wf_t_h(WF_CLEAN, WF_CLEAN), 'WAN2' => wf_t_h(WF_BAD, WF_BAD, ['priority' => 2, 'no_rehold' => true])], $now, 120);
    wf_check($t, 'no_rehold after a manual release blocks the hold (11)', $p['hold'] === []);

    $p = wf_plan_holds(['PRIMARY_WAN' => wf_t_h(WF_CLEAN, WF_CLEAN), 'WAN2' => wf_t_h(WF_UNAVAILABLE, WF_BAD, ['priority' => 2])], $now, 120);
    wf_check($t, 'hard down (carrier loss) while PRIMARY up: held (decision 3)', $p['hold'] === ['WAN2']);

    $p = wf_plan_holds(['WAN2' => wf_t_h(WF_BAD, WF_BAD, ['held' => true])], $now, 120);
    wf_check($t, 'a lone held WAN with no other WAN configured is released', $p['release'] === ['WAN2']);
    return wf_tally_report('holds', $t);
});
