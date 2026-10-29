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
 * Readings and judgements. Pure.
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
 * dpinger_status() prints "~" when average, deviation and loss are all 0: a perfect link, or no data at
 * all (sends failing). Core then reports the gateway down in the second case, so "~" on a dpinger that
 * has run a whole time_period counts as 0% loss only while core does not call it down: a dead link would
 * otherwise read as a perfect one.
 *
 * @param array{loss: ?float, tilde: bool, status: string, sock_age: ?int, time_period: int} $w
 */
function wf_effective_loss(array $w): ?float
{
    if ($w['loss'] !== null) {
        return $w['loss'];
    }
    return $w['tilde'] && $w['status'] !== 'down' && $w['sock_age'] !== null && $w['sock_age'] >= $w['time_period'] ? 0.0 : null;
}

/**
 * @param array{loss: ?float, tilde: bool, status: string, sock_age: ?int, time_period: int} $w
 */
function wf_settled(array $w): bool
{
    return $w['sock_age'] !== null && $w['sock_age'] >= $w['time_period'] && wf_effective_loss($w) !== null;
}

/**
 * @param array{disabled: bool, manual_down: bool, present: bool, status: string, tilde: bool, carrier: bool, has_ipv4: bool,
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
    // lost probes are whole: dpinger prints loss rounded to 0.1 %, so 12 of 36 reads 33.3 % (11.988 probes)
    $lost = (int)round($loss / 100.0 * $counted);
    $needed = (int)ceil($w['losshigh'] / 100.0 * $w['time_period'] / $interval);
    return $lost >= $needed ? WF_BAD : WF_UNKNOWN;
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

/**
 * Why a WAN's gateway can never be judged, or null when it can: a disabled gateway reads unavailable, and one with
 * monitoring off has no dpinger, so while its link is up it reads unknown. Neither ever backs a hold of another WAN.
 * The settings model refuses a Save that adds one; the page and the log name one saved before.
 *
 * @param array{disabled: bool, monitor_disable: bool} $w
 * @return 'disabled'|'monitor_disable'|null disabled first
 */
function wf_unjudgeable(array $w): ?string
{
    if ($w['disabled']) {
        return 'disabled';
    }
    return $w['monitor_disable'] ? 'monitor_disable' : null;
}
