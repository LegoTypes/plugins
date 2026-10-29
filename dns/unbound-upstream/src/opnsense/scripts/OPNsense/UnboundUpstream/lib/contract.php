<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Core contract. Pure.
 *
 * Takes the snapshot's contract input and says whether tunnel mode may run, and through which members. Every failure
 * refuses tunnel mode and is shown on the status page verbatim, so the strings are part of the interface. Notes are
 * status-only. excluded lists the members that are no candidate: one with no resolver, one with no next hop, and,
 * while the rest still have a candidate, one whose resolver has an address-scoped failure (it is a gateway's monitor,
 * lies in a static route, or has a route the plugin did not make).
 *
 * Contract = array{ok: bool, failures: list<string>, notes: list<string>, excluded: list<string>}
 */

require_once __DIR__ . '/address.php';

/**
 * The address-scoped failures in 1.3's words, each with the address it is about and the members whose effective
 * resolver it is: every monitor match, then every static route, then every foreign route, the last apart since the
 * contract lists it after the unmonitored members. While some member has a resolver, an address no member uses
 * excludes nobody and is left out; while none has one, every item is kept (with no members, the snapshot reads only
 * the Default's, as 1.3_2 read its one resolver whatever the group).
 *
 * @param array{monitors: array<string, list<string>>, statics: array<string, list<string>>, foreign: list<string>,
 *     member_resolvers: array<string, string>} $c
 * @param bool $anyResolver whether some member has a resolver (uu_contract() decides it once)
 * @return array{before: list<array{address: string, failure: string, members: list<string>}>,
 *     after: list<array{address: string, failure: string, members: list<string>}>}
 */
function uu_contract_scoped(array $c, bool $anyResolver): array
{
    $users = fn (string $address): array => array_map('strval', array_keys($c['member_resolvers'], $address, true));
    $before = [];
    foreach ($c['monitors'] as $address => $gateways) {
        foreach ($gateways as $gateway) {
            $before[] = ['address' => (string)$address, 'failure' => 'resolver is the monitor of ' . $gateway];
        }
    }
    foreach ($c['statics'] as $address => $networks) {
        foreach ($networks as $network) {
            $before[] = ['address' => (string)$address, 'failure' => 'resolver is inside static route ' . $network];
        }
    }
    $after = [];
    foreach ($c['foreign'] as $address) {
        $after[] = ['address' => $address, 'failure' => 'resolver route not ours'];
    }
    $with = function (array $items) use ($users, $anyResolver): array {
        $out = [];
        foreach ($items as $item) {
            $members = $users($item['address']);
            if ($members !== [] || !$anyResolver) {
                $out[] = $item + ['members' => $members];
            }
        }
        return $out;
    };
    return ['before' => $with($before), 'after' => $with($after)];
}

/**
 * @param array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *     status_fields: bool, monitors: array<string, list<string>>, statics: array<string, list<string>>,
 *     unmonitored_members: list<string>, foreign: list<string>, member_resolvers: array<string, string>,
 *     resolver_notes: list<string>, no_next_hop: list<string>, rules: array{state: string, problems: list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int, core_commands: list<string>,
 *     core_paths: list<string>, unbound_conf: ?array{do_ip4: bool, do_ip6: bool, outgoing_interface: bool},
 *     group_family: string, mixed_family: bool, family_mismatch: list<string>} $c
 *   monitors and statics are keyed by address (the gateways whose monitor it is, the static routes it lies in),
 *   foreign lists the addresses whose route the plugin did not make, member_resolvers is each member's effective
 *   resolver ('' for none), resolver_notes uu_member_resolvers()'s notes, no_next_hop the members whose gateway
 *   record has no address to route through, unbound_conf uu_unbound_conf_facts() of the generated unbound.conf (null:
 *   unreadable), group_family the group's family (uu_group_family()), mixed_family whether it has members of both,
 *   family_mismatch the effective resolvers of the other family (uu_family_mismatch()), core_paths the core files
 *   core no longer keeps where the plugin reads them (uu_core_paths_changed()), each a note. The whole-plugin failures
 *   these add refuse tunnel mode for every member: the configuration would not send the group's family, an outgoing
 *   interface is set, the group has both families, a resolver is of the other family, and Unbound's configured root
 *   zone names an effective resolver (compared as the planner compares a live root with it: bare, canonical)
 * @return array{ok: bool, failures: list<string>, notes: list<string>, excluded: list<string>}
 *   an address-scoped failure is a failure, in 1.3's words, when the members its addresses exclude are every member
 *   that has a resolver (or no member has one, and the failure is the Default's), with " (<address>)" appended only
 *   when the members have more than one address between them; otherwise each excluded member gets the note
 *   "<name> excluded: <failure>" and the others still run. excluded lists a member with no resolver or no next hop
 *   whatever else applies (with that note only), and a member with only an address-scoped failure while the others
 *   still have a candidate (not while the scoped failures refuse)
 */
function uu_contract(array $c): array
{
    $failures = [];
    $notes = [];

    $resolvers = array_filter($c['member_resolvers'], fn (string $address): bool => $address !== '');
    $scoped = uu_contract_scoped($c, $resolvers !== []);
    $scopedItems = array_merge($scoped['before'], $scoped['after']);
    $hit = [];
    foreach ($scopedItems as $item) {
        foreach ($item['members'] as $name) {
            $hit[$name] = true;
        }
    }
    /* with no member's resolver left, the items are the Default's: they refuse, as in 1.3 */
    $refused = $resolvers === [] ? $scopedItems !== [] : $hit !== [] && count($hit) === count($resolvers);
    $several = count(array_unique($resolvers)) > 1;
    $scopedFailures = fn (array $items): array => array_map(
        fn (array $item): string => $item['failure'] . ($several ? " ({$item['address']})" : ''), $items);

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
    if ($refused) {
        array_push($failures, ...$scopedFailures($scoped['before']));
    }
    foreach ($c['unmonitored_members'] as $gateway) {
        $failures[] = 'member ' . $gateway . ' is not monitored';
    }
    if ($refused) {
        array_push($failures, ...$scopedFailures($scoped['after']));
    }
    /* Verifying (a status call after the ruleset changed) is no fault, the next evaluation lists */
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

    /* Unbound's own root zone is the owner's forwarding, which the plugin cannot tell from its own. The addresses are
     * the members' effective resolvers (uu_plan_addresses()'s set whenever the group has members, canonical already;
     * a group with none is refused anyway); Save names the same conflicts of Unbound's settings through the same test */
    foreach (uu_root_forward_conflicts($zone['addrs'], $c['member_resolvers']) as $address => $members) {
        $failures[] = "Unbound's root zone forwards to $address, the resolver of " . implode(', ', $members)
            . ': the plugin cannot tell that forwarding from its own';
    }

    /* the generated configuration, read once: what it would not send, and a read that failed */
    $conf = $c['unbound_conf'];
    if ($conf === null) {
        $failures[] = 'unbound.conf unreadable';
    } else {
        if ($c['group_family'] === 'inet' && !$conf['do_ip4']) {
            $failures[] = "Unbound's generated configuration says do-ip4: no";
        }
        if ($c['group_family'] === 'inet6' && !$conf['do_ip6']) {
            $failures[] = "Unbound's generated configuration says do-ip6: no (IPv6 is not allowed in System: "
                . 'Settings: General)';
        }
        if ($conf['outgoing_interface']) {
            $failures[] = "Unbound's Outgoing Network Interfaces is set: its queries would not leave from the "
                . "tunnel's own address";
        }
    }
    if ($c['mixed_family']) {
        $failures[] = 'the group has IPv4 and IPv6 members';
    }
    foreach ($c['family_mismatch'] as $address) {
        $failures[] = 'resolver ' . $address . ($c['group_family'] === 'inet6' ? ' is IPv4 but the group is IPv6'
            : ' is IPv6 but the group is IPv4');
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
    /* a note, not a failure: each moved path already fails safe (no member settles, or Unbound reads as not
     * running), so the note names the cause */
    foreach ($c['core_paths'] as $text) {
        $notes[] = "core path changed: $text";
    }

    /* the members that are no candidate, in member order, each with its note (uu_member_resolvers() wrote the note
     * of a member with no resolver) */
    array_push($notes, ...$c['resolver_notes']);
    $excluded = [];
    foreach ($c['member_resolvers'] as $name => $address) {
        $name = (string)$name;
        if ($address === '') {
            $excluded[] = $name;
        } elseif (in_array($name, $c['no_next_hop'], true)) {
            $excluded[] = $name;
            $notes[] = "$name has no next hop: not a candidate";
        } elseif (!$refused && isset($hit[$name])) {
            $excluded[] = $name;
            foreach ($scopedItems as $item) {
                if (in_array($name, $item['members'], true)) {
                    $notes[] = "$name excluded: {$item['failure']}";
                }
            }
        }
    }

    return ['ok' => $failures === [], 'failures' => $failures, 'notes' => $notes, 'excluded' => $excluded];
}
