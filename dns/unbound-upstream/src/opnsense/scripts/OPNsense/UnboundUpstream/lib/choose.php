<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Candidate choice, failback timers and probe outcomes (spec 2026-10-17 sections 3.3 and 3.5). Pure.
 *
 * Timers = array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *                              probe_failures: int}>
 * A member's timer counts the seconds between two consecutive evaluations that both read it settled and usable.
 * last_at is the previous such evaluation; any other reading (young, cached, none, unusable) clears it, so the
 * gap is neither counted nor does it reset the count. A down verdict resets the count.
 */

require_once __DIR__ . '/constants.php';

/**
 * @return array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int, probe_failures: int}
 */
function uu_timer_new(): array
{
    return ['usable_since' => null, 'counted' => 0, 'last_at' => null, 'resolver_failed_until' => null,
            'probe_failures' => 0];
}

/**
 * @param array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *                            probe_failures: int}> $timers
 * @param array<string, string> $kinds reading kind per member (uu_reading_kind)
 * @param array<string, bool> $usable settled and usable per member (uu_usable_settled)
 * @param array<string, bool> $down member has a down verdict (uu_member_down !== null)
 * @return array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *                             probe_failures: int}>
 */
function uu_timers_update(array $timers, array $kinds, array $usable, array $down, int $now): array
{
    $backwards = false;
    foreach ($timers as $timer) {
        if ($timer['last_at'] !== null && $timer['last_at'] - $now > UU_CLOCK_BACK_SECONDS) {
            $backwards = true;
        }
    }
    $out = [];
    foreach ($kinds as $name => $kind) {
        $timer = $timers[$name] ?? uu_timer_new();
        if ($backwards) {
            $timer['counted'] = 0;
            $timer['usable_since'] = null;
            $timer['last_at'] = null;
            $timer['resolver_failed_until'] = null;
        }
        if ($down[$name] ?? false) {
            $timer['counted'] = 0;
            $timer['usable_since'] = null;
            $timer['last_at'] = null;
        } elseif ($kind === 'settled' && ($usable[$name] ?? false)) {
            if ($timer['last_at'] !== null) {
                $timer['counted'] += min(UU_TIMER_STEP_MAX, max(0, $now - $timer['last_at']));
            }
            $timer['usable_since'] = $timer['usable_since'] ?? $now;
            $timer['last_at'] = $now;
        } else {
            $timer['last_at'] = null;
        }
        $out[$name] = $timer;
    }
    return $out;
}

/**
 * Members in the order they should be tried; the first is the target, and the current member first means stay.
 *
 * @param list<list<string>> $tiers best tier first, configured order within a tier
 * @param array<string, bool> $usableSettled
 * @param array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *                            probe_failures: int}> $timers
 * @return list<string>
 */
function uu_candidates(array $tiers, array $usableSettled, array $timers, int $now, int $failbackDelay, ?string $current): array
{
    $currentTier = null;
    foreach ($tiers as $index => $tier) {
        if ($current !== null && in_array($current, $tier, true)) {
            $currentTier = $index;
        }
    }
    $out = [];
    foreach ($tiers as $index => $tier) {
        if ($currentTier !== null && in_array($current, $tier, true)) {
            $tier = array_merge([(string)$current], array_values(array_diff($tier, [(string)$current])));
        }
        foreach ($tier as $name) {
            $failedUntil = $timers[$name]['resolver_failed_until'] ?? null;
            if (!($usableSettled[$name] ?? false) || ($failedUntil !== null && $now < $failedUntil)) {
                continue;
            }
            $delayed = ($timers[$name]['counted'] ?? 0) >= $failbackDelay;
            $free = $currentTier !== null && ($index >= $currentTier);
            if ($free || $delayed) {
                $out[] = $name;
            }
        }
    }
    return $out;
}

/**
 * Spec 3.5 table: 'ok', 'flush_infra' (direct passes, Unbound fails, not yet flushed) or 'fail'.
 * A null through-Unbound result means the check did not run (candidate entry), so the direct probe decides.
 */
function uu_probe_outcome(bool $direct, ?bool $throughUnbound, bool $afterFlushInfra): string
{
    if (!$direct) {
        return 'fail';
    }
    if ($throughUnbound !== false) {
        return 'ok';
    }
    return $afterFlushInfra ? 'fail' : 'flush_infra';
}
