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
 *
 * Candidate choice, failback timers and probe outcomes. Pure.
 *
 * Timers = array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *                              probe_failures: int,
 *                                  last_down: ?array{at: int, reason: string}, resolver: string}>
 * A member's timer counts the seconds between two consecutive evaluations that both read it settled and usable.
 * last_at is the previous such evaluation; any other reading (young, cached, none, unusable) clears it, so the
 * gap is neither counted nor does it reset the count. A down verdict resets the count; when the member had been
 * counting, it also records last_down (wall-clock time and the verdict), which stays until the next such down.
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/address.php';

/**
 * @return array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int, probe_failures: int,
 *             last_down: ?array{at: int, reason: string}, resolver: string}
 */
function uu_timer_new(): array
{
    return ['usable_since' => null, 'counted' => 0, 'last_at' => null, 'resolver_failed_until' => null,
            'probe_failures' => 0, 'last_down' => null, 'resolver' => ''];
}

/**
 * @param array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *                            probe_failures: int,
 *                                last_down: ?array{at: int, reason: string}, resolver: string}> $timers
 * @param array<string, string> $kinds reading kind per member (uu_reading_kind)
 * @param array<string, bool> $usable settled and usable per member (uu_usable_settled)
 * @param array<string, string> $down the down verdict (uu_member_down) of every member that has one; the others are absent
 * @param int $now monotonic seconds (intdiv(hrtime(true), 1000000000)); the wall clock is never used, so an NTP
 *             step cannot move a timer or a resolver-failed mark
 * @param int $wall wall-clock seconds, for display only (a last_down record); no timer reads it
 * @return array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *                             probe_failures: int,
 *                                 last_down: ?array{at: int, reason: string}, resolver: string}>
 */
function uu_timers_update(array $timers, array $kinds, array $usable, array $down, int $now, int $wall): array
{
    $out = [];
    foreach ($kinds as $name => $kind) {
        $timer = $timers[$name] ?? uu_timer_new();
        if (isset($down[$name])) {
            if ($timer['counted'] > 0) {
                $timer['last_down'] = ['at' => $wall, 'reason' => $down[$name]];
            }
            $timer['counted'] = 0;
            $timer['usable_since'] = null;
            $timer['last_at'] = null;
        } elseif ($kind === 'settled' && ($usable[$name] ?? false)) {
            if ($timer['last_at'] !== null) {
                $timer['counted'] += max(0, $now - $timer['last_at']);
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
 * The timers once each member's resolver is known: a timer's resolver_failed_until and probe_failures are about the
 * address in its resolver field, so when the member's effective resolver is another address, those two reset for
 * that member alone and the field takes the new address. A timer with no address yet ('', a new one or one read from
 * a version 5 state file) takes the member's without a reset. A member absent from $resolvers is left as it is.
 *
 * @param array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *                            probe_failures: int,
 *                                last_down: ?array{at: int, reason: string}, resolver: string}> $timers
 * @param array<string, string> $resolvers each member's effective resolver, canonical, '' for none
 * @return array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *                             probe_failures: int,
 *                                 last_down: ?array{at: int, reason: string}, resolver: string}>
 */
function uu_timers_follow_resolvers(array $timers, array $resolvers): array
{
    foreach ($timers as $name => $timer) {
        if (!array_key_exists($name, $resolvers)) {
            continue;
        }
        $want = $resolvers[$name];
        if ($timer['resolver'] !== '' && !uu_ip_same($timer['resolver'], $want)) {
            $timer['resolver_failed_until'] = null;
            $timer['probe_failures'] = 0;
        }
        $timer['resolver'] = $want;
        $timers[$name] = $timer;
    }
    return $timers;
}

/**
 * Members in the order they should be tried; the first is the target, and the current member first means stay.
 *
 * @param list<list<string>> $tiers best tier first, configured order within a tier
 * @param array<string, bool> $usableSettled settled and usable per member; gates entering and returning only
 * @param array<string, bool> $down member has a down verdict; the current member stays while it is not down
 * @param array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *                            probe_failures: int,
 *                                last_down: ?array{at: int, reason: string}, resolver: string}> $timers
 * @return list<string>
 */
function uu_candidates(
    array $tiers,
    array $usableSettled,
    array $down,
    array $timers,
    int $now,
    int $failbackDelay,
    ?string $current
): array {
    $currentTier = null;
    foreach ($tiers as $index => $tier) {
        if ($current !== null && in_array($current, $tier, true)) {
            $currentTier = $index;
        }
    }
    $out = [];
    foreach ($tiers as $index => $tier) {
        if ($index === $currentTier) {
            $tier = array_merge([(string)$current], array_values(array_diff($tier, [(string)$current])));
        }
        foreach ($tier as $name) {
            $failedUntil = $timers[$name]['resolver_failed_until'] ?? null;
            if ($failedUntil !== null && $now < $failedUntil) {
                continue;
            }
            if ($name === $current) {
                if (!($down[$name] ?? false)) {
                    $out[] = $name;
                }
                continue;
            }
            if (!($usableSettled[$name] ?? false)) {
                continue;
            }
            $delayed = ($timers[$name]['counted'] ?? 0) >= $failbackDelay;
            if ($delayed || ($currentTier !== null && $index >= $currentTier)) {
                $out[] = $name;
            }
        }
    }
    return $out;
}

/**
 * Probe outcome: 'ok', 'flush_infra' (direct passes, Unbound fails, not yet flushed) or 'fail'.
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
