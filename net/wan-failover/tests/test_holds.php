<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Hold start and release decisions.
 */

require_once __DIR__ . '/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/judge.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/holds.php';

/** @return array{reading: string, judgement: array, held: bool, manual_down: bool, disabled: bool, core_down: bool, raw_loss: ?float, losslow: float, rank: int, no_rehold: bool} */
function wf_t_h(string $reading, ?string $judged, array $over = []): array
{
    $j = wf_judgement_new(0);
    $j['value'] = $judged;
    $j['last_settled_at'] = 1000;
    return array_merge([
        'reading' => $reading, 'judgement' => $j, 'held' => false, 'manual_down' => false, 'disabled' => false,
        'core_down' => false, 'raw_loss' => 0.0, 'losslow' => 10.0, 'rank' => 1, 'no_rehold' => false,
    ], $over);
}

wf_register_suite('holds', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $now = 1010;

    $p = wf_plan_holds(['WAN_A' => wf_t_h(WF_CLEAN, WF_CLEAN), 'WAN_B' => wf_t_h(WF_BAD, WF_BAD, ['rank' => 2])], $now, 120);
    wf_check($t, 'WAN_B over threshold with WAN_A clean: hold WAN_B', $p['hold'] === ['WAN_B'] && $p['release'] === []);

    $p = wf_plan_holds(['WAN_A' => wf_t_h(WF_MARGINAL, WF_MARGINAL, ['raw_loss' => 2.0]), 'WAN_B' => wf_t_h(WF_BAD, WF_BAD, ['rank' => 2])], $now, 120);
    wf_check($t, 'marginal WAN_A (2%) is a usable alternative: hold WAN_B', $p['hold'] === ['WAN_B']);

    $p = wf_plan_holds(['WAN_A' => wf_t_h(WF_BAD, WF_BAD), 'WAN_B' => wf_t_h(WF_BAD, WF_BAD, ['rank' => 2])], $now, 120);
    wf_check($t, 'both over threshold: nothing held', $p['hold'] === [] && $p['release'] === []);

    $p = wf_plan_holds(['WAN_A' => wf_t_h(WF_UNKNOWN, WF_BAD), 'WAN_B' => wf_t_h(WF_UNKNOWN, WF_BAD, ['rank' => 2])], $now, 120);
    wf_check($t, 'carried bad judgement with unknown reading never starts a hold (6a)', $p['hold'] === []);

    $p = wf_plan_holds(['WAN_A' => wf_t_h(WF_CLEAN, WF_CLEAN, ['core_down' => true]), 'WAN_B' => wf_t_h(WF_BAD, WF_BAD, ['rank' => 2])], $now, 120);
    wf_check($t, 'core-down (latency) WAN_A is not an alternative', $p['hold'] === []);

    $stale = wf_t_h(WF_UNKNOWN, WF_CLEAN);
    $stale['judgement']['last_settled_at'] = 800;
    $p = wf_plan_holds(['WAN_A' => $stale, 'WAN_B' => wf_t_h(WF_BAD, WF_BAD, ['rank' => 2])], $now, 120);
    wf_check($t, 'alternative last settled 210 s ago (> fresh 120): no hold', $p['hold'] === []);

    $p = wf_plan_holds(['WAN_A' => wf_t_h(WF_UNKNOWN, WF_CLEAN, ['raw_loss' => 40.0]), 'WAN_B' => wf_t_h(WF_BAD, WF_BAD, ['rank' => 2])], $now, 120);
    wf_check($t, 'alternative young with raw loss 40% > losslow: no hold, as a lossy alternative backs none', $p['hold'] === []);

    $p = wf_plan_holds(['WAN_A' => wf_t_h(WF_CLEAN, WF_CLEAN), 'WAN_B' => wf_t_h(WF_MARGINAL, WF_MARGINAL, ['rank' => 2, 'held' => true, 'raw_loss' => 5.0])], $now, 120);
    wf_check($t, 'held WAN_B at 5% (marginal) stays held', $p['release'] === [] && $p['hold'] === []);

    $p = wf_plan_holds(['WAN_A' => wf_t_h(WF_CLEAN, WF_CLEAN), 'WAN_B' => wf_t_h(WF_CLEAN, WF_CLEAN, ['rank' => 2, 'held' => true])], $now, 120);
    wf_check($t, 'held WAN_B clean: released', $p['release'] === ['WAN_B']);

    $p = wf_plan_holds(['WAN_A' => wf_t_h(WF_BAD, WF_BAD), 'WAN_B' => wf_t_h(WF_CLEAN, WF_CLEAN, ['rank' => 2, 'held' => true])], $now, 120);
    wf_check($t, 'swap (5a): WAN_B clean released, WAN_A bad held, never both', $p['release'] === ['WAN_B'] && $p['hold'] === ['WAN_A']);

    $p = wf_plan_holds(['WAN_A' => wf_t_h(WF_BAD, WF_BAD), 'WAN_B' => wf_t_h(WF_BAD, WF_BAD, ['rank' => 2, 'held' => true, 'raw_loss' => 30.0])], $now, 120);
    wf_check($t, '5a variant: WAN_A bad, WAN_B still bad: release WAN_B on invariant, hold none', $p['release'] === ['WAN_B'] && $p['hold'] === []);

    $p = wf_plan_holds(['WAN_A' => wf_t_h(WF_UNKNOWN, WF_CLEAN), 'WAN_B' => wf_t_h(WF_BAD, WF_BAD, ['rank' => 2, 'held' => true])], $now, 120);
    wf_check($t, 'unknown alternative never releases: no positive evidence that it failed', $p['release'] === []);

    $p = wf_plan_holds(['WAN_A' => wf_t_h(WF_UNAVAILABLE, WF_BAD), 'WAN_B' => wf_t_h(WF_BAD, WF_BAD, ['rank' => 2, 'held' => true])], $now, 120);
    wf_check($t, 'alternative unavailable (carrier loss): release', $p['release'] === ['WAN_B']);

    $p = wf_plan_holds(['WAN_A' => wf_t_h(WF_CLEAN, WF_CLEAN), 'WAN_B' => wf_t_h(WF_UNAVAILABLE, WF_BAD, ['rank' => 2, 'manual_down' => true])], $now, 120);
    wf_check($t, 'manual force_down WAN is never held by us', $p['hold'] === []);

    $p = wf_plan_holds(['WAN_A' => wf_t_h(WF_BAD, WF_BAD), 'WAN_B' => wf_t_h(WF_UNAVAILABLE, WF_BAD, ['rank' => 2, 'manual_down' => true])], $now, 120);
    wf_check($t, 'manual force_down on WAN_B means WAN_A cannot be held (10)', $p['hold'] === []);

    $p = wf_plan_holds(['WAN_A' => wf_t_h(WF_CLEAN, WF_CLEAN), 'WAN_B' => wf_t_h(WF_BAD, WF_BAD, ['rank' => 2, 'no_rehold' => true])], $now, 120);
    wf_check($t, 'no_rehold after a manual release blocks the hold (11)', $p['hold'] === []);

    $p = wf_plan_holds(['WAN_A' => wf_t_h(WF_CLEAN, WF_CLEAN), 'WAN_B' => wf_t_h(WF_UNAVAILABLE, WF_BAD, ['rank' => 2])], $now, 120);
    wf_check($t, 'hard down (carrier loss) while WAN_A up: held (decision 3)', $p['hold'] === ['WAN_B']);

    $p = wf_plan_holds(['WAN_B' => wf_t_h(WF_BAD, WF_BAD, ['held' => true])], $now, 120);
    wf_check($t, 'a lone held WAN with no other WAN configured is released', $p['release'] === ['WAN_B']);
    $p = wf_plan_holds(['WAN_B' => wf_t_h(WF_BAD, WF_BAD, ['rank' => 1]), 'WAN_A' => wf_t_h(WF_BAD, WF_BAD, ['rank' => 2]),
        'WAN3' => wf_t_h(WF_CLEAN, WF_CLEAN, ['rank' => 3])], $now, 120);
    wf_check($t, 'holds start in core\'s default order (rank), not by name or priority', $p['hold'] === ['WAN_B', 'WAN_A']);
    return wf_tally_report('holds', $t);
});
