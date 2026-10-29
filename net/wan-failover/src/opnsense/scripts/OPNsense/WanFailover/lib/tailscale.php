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
 * Tailscale restart decision. Pure. tailscaled
 * restarts only when the IPv4 default gateway it runs on has changed and the
 * change is stable (or was caused by our own plan), or after the default was
 * lost and came back stable. Unmet conditions defer; nothing is skipped.
 */

/**
 * @return array{default_gw: ?string, restarted_at: ?int, cur_default: ?string, cur_since: ?int, lost: bool, expected_default: ?string}
 */
function wf_ts_new(): array
{
    return ['default_gw' => null, 'restarted_at' => null, 'cur_default' => null, 'cur_since' => null,
            'lost' => false, 'expected_default' => null];
}

/**
 * @param array{default_gw: ?string, restarted_at: ?int, cur_default: ?string, cur_since: ?int, lost: bool, expected_default: ?string} $ts
 * @return array{restart: bool, ts: array{default_gw: ?string, restarted_at: ?int, cur_default: ?string, cur_since: ?int, lost: bool, expected_default: ?string}, reason: string}
 */
function wf_tailscale_decide(array $ts, ?string $live, int $now, int $stableSeconds, int $cooldownSeconds): array
{
    if ($live !== $ts['cur_default'] || $ts['cur_since'] === null) {
        $ts['cur_default'] = $live;
        $ts['cur_since'] = $now;
    }
    if ($live === null) {
        $ts['lost'] = true;
        return ['restart' => false, 'ts' => $ts, 'reason' => 'no default route'];
    }
    if ($ts['default_gw'] === null) {
        $ts['default_gw'] = $live;
        $ts['expected_default'] = null;
        return ['restart' => false, 'ts' => $ts, 'reason' => 'first observation'];
    }
    if ($live === $ts['default_gw'] && !$ts['lost']) {
        $ts['expected_default'] = null;
        return ['restart' => false, 'ts' => $ts, 'reason' => 'unchanged'];
    }
    $stable = ($ts['expected_default'] !== null && $live === $ts['expected_default'])
        || max(0, $now - $ts['cur_since']) >= $stableSeconds;
    if (!$stable) {
        return ['restart' => false, 'ts' => $ts, 'reason' => 'defer: default not yet stable'];
    }
    if ($ts['restarted_at'] !== null && max(0, $now - $ts['restarted_at']) < $cooldownSeconds) {
        return ['restart' => false, 'ts' => $ts, 'reason' => 'defer: cooldown'];
    }
    $ts['default_gw'] = $live;
    $ts['restarted_at'] = $now;
    $ts['lost'] = false;
    $ts['expected_default'] = null;
    return ['restart' => true, 'ts' => $ts, 'reason' => 'default changed'];
}
