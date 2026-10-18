<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Core contract (spec 2026-10-17 section 3.10). Pure.
 *
 * Takes the snapshot's contract input and says whether tunnel mode may run. Every failure refuses tunnel mode
 * and is shown on the status page verbatim, so the strings are part of the interface. Notes are status-only.
 *
 * Contract = array{ok: bool, failures: list<string>, notes: list<string>}
 */

/**
 * @param array<string, mixed> $c unbound_hooks_registered, unbound_sorts_first, groups_have_tiers, status_fields,
 *     foreign_route, cacheflush, group_found: bool; resolver_is_monitor, resolver_in_static,
 *     unmonitored_members: list<string>; zone: Zone (zone.php); fib_sync_ms: ?int; members: int
 * @return array{ok: bool, failures: list<string>, notes: list<string>}
 */
function uu_contract(array $c): array
{
    $failures = [];
    $notes = [];

    if ($c['unbound_hooks_registered'] !== true) {
        $failures[] = 'unbound_start hook missing';
    }
    if ($c['unbound_sorts_first'] !== true) {
        $failures[] = 'unbound.inc no longer sorts before unboundupstream.inc';
    }
    if ($c['groups_have_tiers'] !== true) {
        $failures[] = 'gateway groups lack tiers';
    }
    if ($c['status_fields'] !== true) {
        $failures[] = 'gateway status lacks expected fields';
    }
    foreach ((array)$c['resolver_is_monitor'] as $gateway) {
        $failures[] = 'resolver is the monitor of ' . (string)$gateway;
    }
    foreach ((array)$c['resolver_in_static'] as $network) {
        $failures[] = 'resolver is inside static route ' . (string)$network;
    }
    foreach ((array)$c['unmonitored_members'] as $gateway) {
        $failures[] = 'member ' . (string)$gateway . ' is not monitored';
    }
    if ($c['foreign_route'] === true) {
        $failures[] = 'resolver route not ours';
    }

    $zone = (array)$c['zone'];
    if ($zone['shape'] === 'unrestorable') {
        $failures[] = 'root zone cannot be restored: ' . implode(', ', array_map('strval', (array)$zone['problems']));
    } elseif ($zone['shape'] === 'none') {
        $notes[] = 'no root zone: fallback is recursion over the WAN';
    } elseif ((array)$zone['addrs'] === []) {
        /* fallback would forward_add an empty list */
        $failures[] = 'root zone has no forward-addr';
    }

    if ($c['fib_sync_ms'] === null) {
        $failures[] = 'fib sync delay unreadable';
    }
    if ($c['cacheflush'] === true) {
        $notes[] = 'cacheflush on: restart escalation disabled';
    }
    if ($c['group_found'] !== true) {
        $failures[] = 'group not found';
    } elseif ((int)$c['members'] === 0) {
        $failures[] = 'group has no members';
    }

    return ['ok' => $failures === [], 'failures' => $failures, 'notes' => $notes];
}
