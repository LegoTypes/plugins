<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Readings and judgements (spec 2026-10-05 section 3.2). Pure.
 *
 * A reading classifies one tick's evidence for one WAN; a judgement is the
 * persisted view that survives routine dpinger restarts (unknown readings keep
 * it, bounded by unknown_max_seconds). Thresholds take a WAN down (bad); only a
 * settled zero-loss window (clean) brings a held one back.
 */

const WF_UNAVAILABLE = 'unavailable';
const WF_BAD = 'bad';
const WF_MARGINAL = 'marginal';
const WF_CLEAN = 'clean';
const WF_UNKNOWN = 'unknown';

/**
 * dpinger_status() prints "~" when stddev and loss are both exactly 0, so "~" on a dpinger that has run
 * a whole time_period is a perfect link, not a missing reading (review R3-10).
 *
 * @param array{loss: ?float, tilde: bool, sock_age: ?int, time_period: int} $w
 */
function wf_effective_loss(array $w): ?float
{
    if ($w['loss'] !== null) {
        return $w['loss'];
    }
    return $w['tilde'] && $w['sock_age'] !== null && $w['sock_age'] >= $w['time_period'] ? 0.0 : null;
}

/**
 * @param array{loss: ?float, tilde: bool, sock_age: ?int, time_period: int} $w
 */
function wf_settled(array $w): bool
{
    return $w['sock_age'] !== null && $w['sock_age'] >= $w['time_period'] && wf_effective_loss($w) !== null;
}

/**
 * @param array{disabled: bool, manual_down: bool, present: bool, tilde: bool, carrier: bool, has_ipv4: bool,
 *              loss: ?float, sock_age: ?int, losslow: float, losshigh: float,
 *              time_period: int, interval: int, loss_interval: int} $w
 */
function wf_reading(array $w, int $deadMinSeconds): string
{
    if ($w['disabled'] || $w['manual_down'] || !$w['carrier'] || !$w['has_ipv4']) {
        return WF_UNAVAILABLE;
    }
    $loss = wf_effective_loss($w);
    if (!$w['present'] || $loss === null || $w['sock_age'] === null) {
        return WF_UNKNOWN;
    }
    if ($loss >= 100.0 && $w['sock_age'] >= $deadMinSeconds) {
        return WF_UNAVAILABLE;
    }
    if (wf_settled($w)) {
        if ($loss > $w['losslow']) {
            return WF_BAD;
        }
        return $loss > 0.0 ? WF_MARGINAL : WF_CLEAN;
    }
    $interval = max(1, $w['interval']);
    $counted = intdiv(max(0, $w['sock_age'] - $w['loss_interval']), $interval);
    $lost = $loss / 100.0 * $counted;
    $needed = (int)ceil($w['losshigh'] / 100.0 * $w['time_period'] / $interval);
    return $lost + 1e-9 >= $needed ? WF_BAD : WF_UNKNOWN;
}

/**
 * @return array{value: ?string, since: int, last_settled_at: ?int, last_settled_loss: ?float, unknown_since: ?int, recovering: bool}
 */
function wf_judgement_new(int $now): array
{
    return ['value' => null, 'since' => $now, 'last_settled_at' => null, 'last_settled_loss' => null,
            'unknown_since' => null, 'recovering' => false];
}

/**
 * @param array{value: ?string, since: int, last_settled_at: ?int, last_settled_loss: ?float, unknown_since: ?int, recovering: bool} $j
 * @return array{value: ?string, since: int, last_settled_at: ?int, last_settled_loss: ?float, unknown_since: ?int, recovering: bool}
 */
function wf_judge(array $j, string $reading, bool $settled, ?float $loss, int $now, int $unknownMax): array
{
    $out = $j;
    if ($reading === WF_UNKNOWN) {
        $out['unknown_since'] = $j['unknown_since'] ?? $now;
        if ($now - $out['unknown_since'] > $unknownMax && $j['value'] !== WF_BAD) {
            $out['value'] = WF_BAD;
            $out['since'] = $now;
        }
    } else {
        $value = $reading === WF_UNAVAILABLE ? WF_BAD : $reading;
        if ($j['value'] !== $value) {
            $out['since'] = $now;
        }
        $out['value'] = $value;
        $out['unknown_since'] = null;
        if ($settled) {
            $out['last_settled_at'] = $now;
            $out['last_settled_loss'] = $loss;
        } elseif ($reading === WF_UNAVAILABLE) {
            $out['last_settled_loss'] = 100.0;
        }
    }
    if ($out['value'] === WF_BAD) {
        $out['recovering'] = true;
    }
    return $out;
}

/**
 * @param array{value: ?string} $j
 */
function wf_up(array $j): bool
{
    return $j['value'] === WF_CLEAN || $j['value'] === WF_MARGINAL;
}
