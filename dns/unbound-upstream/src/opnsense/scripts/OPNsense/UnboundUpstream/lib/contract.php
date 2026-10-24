<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
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
 * @param array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *     status_fields: bool, resolver_is_monitor: list<string>, resolver_in_static: list<string>,
 *     unmonitored_members: list<string>, foreign_route: bool, rules: array{state: string, problems: list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int, core_commands: list<string>} $c
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
    foreach ($c['resolver_is_monitor'] as $gateway) {
        $failures[] = 'resolver is the monitor of ' . $gateway;
    }
    foreach ($c['resolver_in_static'] as $network) {
        $failures[] = 'resolver is inside static route ' . $network;
    }
    foreach ($c['unmonitored_members'] as $gateway) {
        $failures[] = 'member ' . $gateway . ' is not monitored';
    }
    if ($c['foreign_route'] === true) {
        $failures[] = 'resolver route not ours';
    }
    /* section 3.6c: verifying (a status call after the ruleset changed) is no fault, the next evaluation lists */
    if ($c['rules']['state'] === 'verifying') {
        $notes[] = 'firewall rules are being verified (the ruleset changed)';
    } elseif ($c['rules']['state'] !== 'loaded') {
        foreach ($c['rules']['problems'] === [] ? ['not loaded'] : $c['rules']['problems'] as $problem) {
            $failures[] = 'firewall rules: ' . $problem;
        }
    }

    $zone = $c['zone'];
    if ($zone['shape'] === 'unrestorable') {
        $failures[] = 'root zone cannot be restored: ' . implode(', ', $zone['problems']);
    } elseif ($zone['shape'] === 'none') {
        $notes[] = 'no root zone: fallback is recursion over the WAN';
    } elseif ($zone['addrs'] === []) {
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
    } elseif ($c['members'] === 0) {
        $failures[] = 'group has no members';
    }
    /* a note, not a failure: a removal's fallback that no longer matches core fails closed (the loaded rules keep
     * the plugin's blocks until core's next reload), so refusing tunnel mode would buy nothing */
    foreach ($c['core_commands'] as $name) {
        $notes[] = "core command changed: $name (a removal that configd does not answer runs the old command)";
    }

    return ['ok' => $failures === [], 'failures' => $failures, 'notes' => $notes];
}
