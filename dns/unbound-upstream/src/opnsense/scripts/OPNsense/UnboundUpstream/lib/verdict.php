<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Readings and verdicts (spec 2026-10-17 section 3.2). Pure.
 *
 * A reading is one tick's evidence for one member: settled (dpinger has run a whole time_period), young
 * (it has data but not a whole window), cached (no dpinger data, the watcher's cache entry stands in) or
 * none. A young window's status string is never a verdict by itself; only a counted-probe rule is.
 *
 * Member = array{name: string, interface: string, if: string, next_hop: string, disabled: bool,
 *                force_down: bool, monitor_disable: bool, monitor: string, time_period: int,
 *                interval: int, loss_interval: int, losshigh: int}
 * Probe  = array{status: string, loss: string, sock_age: ?int, cached: ?string}
 */

/**
 * The number out of dpinger's loss text ("25.0 %"); null for "~" or anything without a number.
 */
function uu_loss_value(string $loss): ?float
{
    $text = trim(str_replace('%', '', $loss));
    return is_numeric($text) ? (float)$text : null;
}

/**
 * @param array{name: string, interface: string, if: string, next_hop: string, disabled: bool, force_down: bool,
 *              monitor_disable: bool, monitor: string, time_period: int, interval: int, loss_interval: int, losshigh: int} $m
 * @param array{status: string, loss: string, sock_age: ?int, cached: ?string} $p
 */
function uu_reading_kind(array $m, array $p): string
{
    if (uu_loss_value($p['loss']) === null) {
        return $p['cached'] !== null ? 'cached' : 'none';
    }
    if ($p['sock_age'] === null) {
        return 'none';
    }
    return $p['sock_age'] >= $m['time_period'] ? 'settled' : 'young';
}

/**
 * Whether a gateway status string means the member cannot carry the resolver, for the member's trigger.
 */
function uu_status_unusable(string $status, string $trigger): bool
{
    if (str_contains($status, 'down')) {
        return true;
    }
    return match ($trigger) {
        'downloss' => str_contains($status, 'loss'),
        'downlatency' => str_contains($status, 'delay'),
        'downlosslatency' => str_contains($status, 'loss') || str_contains($status, 'delay'),
        default => false,
    };
}

/**
 * Probes dpinger has counted in its window, as os-wan-failover counts them, times the loss share.
 *
 * @param array{name: string, interface: string, if: string, next_hop: string, disabled: bool, force_down: bool,
 *              monitor_disable: bool, monitor: string, time_period: int, interval: int, loss_interval: int, losshigh: int} $m
 * @param array{status: string, loss: string, sock_age: ?int, cached: ?string} $p
 */
function uu_lost_probes(array $m, array $p): float
{
    $loss = uu_loss_value($p['loss']);
    if ($loss === null || $p['sock_age'] === null) {
        return 0.0;
    }
    $counted = intdiv(max(0, $p['sock_age'] - $m['loss_interval']), max(1, $m['interval']));
    return $loss / 100.0 * $counted;
}

/**
 * The reason a member is down, or null when there is no verdict (up, or too little evidence).
 *
 * @param array{name: string, interface: string, if: string, next_hop: string, disabled: bool, force_down: bool,
 *              monitor_disable: bool, monitor: string, time_period: int, interval: int, loss_interval: int, losshigh: int} $m
 * @param array{status: string, loss: string, sock_age: ?int, cached: ?string} $p
 */
function uu_member_down(array $m, array $p, string $trigger, bool $named): ?string
{
    if ($m['disabled']) {
        return 'disabled';
    }
    if ($m['force_down']) {
        return 'force_down';
    }
    if ($named && ($p['cached'] === 'down' || $p['cached'] === 'force_down')) {
        return 'watcher down';
    }
    $kind = uu_reading_kind($m, $p);
    if ($kind === 'cached' && $p['cached'] !== null && uu_status_unusable($p['cached'], $trigger)) {
        return 'cached ' . $p['cached'];
    }
    if ($kind === 'settled' && uu_status_unusable($p['status'], $trigger)) {
        return 'settled ' . $p['status'];
    }
    if ($kind !== 'young') {
        return null;
    }
    $loss = uu_loss_value($p['loss']);
    $interval = max(1, $m['interval']);
    $counted = intdiv(max(0, (int)$p['sock_age'] - $m['loss_interval']), $interval);
    if ($loss !== null && $loss >= 100.0 && $counted * $interval >= UU_DEAD_MIN_SECONDS) {
        return 'all lost ' . UU_DEAD_MIN_SECONDS . ' s';
    }
    $needed = (int)ceil($m['losshigh'] / 100.0 * $m['time_period'] / $interval);
    if (uu_lost_probes($m, $p) + 1e-9 >= $needed) {
        return 'lost ' . $needed . ' of losshigh';
    }
    return null;
}

/**
 * Only a settled, usable window qualifies a member for choice; cached, young and none never do.
 *
 * @param array{name: string, interface: string, if: string, next_hop: string, disabled: bool, force_down: bool,
 *              monitor_disable: bool, monitor: string, time_period: int, interval: int, loss_interval: int, losshigh: int} $m
 * @param array{status: string, loss: string, sock_age: ?int, cached: ?string} $p
 */
function uu_usable_settled(array $m, array $p, string $trigger): bool
{
    return !$m['disabled'] && !$m['force_down'] && uu_reading_kind($m, $p) === 'settled'
        && !uu_status_unusable($p['status'], $trigger);
}
