<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The planner. Pure: (snapshot, state) -> plan.
 *
 * Snapshot = array{now: int, wall: int, settings: array{enabled: bool, dry_run: bool, group: string, default: string,
 *                  rows: array<string, string>, failback_delay: int, probe_name: string},
 *                  trigger: string, tiers: list<list<string>>, family: string, members: array<string, Member>,
 *                  probes: array<string, Probe>, named: list<string>, stop: ?string,
 *                  unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *                  zone: Zone, routes: array<string, Route>, fib_sync_ms: ?int,
 *                  contract_input: ContractInput, rules: RulesCheck,
 *                  block_table: array{table: ?TableFacts, addresses: list<string>}}
 *   Route    = array{present: bool, gateway: string, interface: string, reject: bool, ours: bool}
 *   now is monotonic seconds; settings.default is the Default resolver, rows the per-member rows by gateway UUID; tiers
 *   come from the group (best first) and are empty when the group is gone; family is the group's (uu_group_family());
 *   members and probes are keyed by gateway name (Member and Probe: verdict.php; a Member also carries its gateway's
 *   ipprotocol and its effective resolver, '' for none); named lists the gateways the monitor hook passed; stop is why
 *   this run stops whatever the settings say (a UU_STOP_* cause), or null; live_root is null when unbound-control did
 *   not answer; routes is `route -n get <address>` for every planner address (uu_plan_addresses(): the effective
 *   resolvers, or the Default when the group has no member) and every address the state's map holds, each with
 *   interface the device it leaves by (compared with Member.if) and ours whether the plugin made it; Zone is
 *   zone.php's; ContractInput is uu_contract()'s input (contract.php). rules is uu_rules_check()'s answer
 *   (pfobserve.php; its state and problems are also ContractInput.rules, and record is the verification an evaluation
 *   saves), block_table the counting table's facts as pf printed them (table null: no such table); the caller turns it
 *   into uu_block_table_view() with the setting's addresses (uu_setting_addresses()).
 * Plan     = array{action: string, candidates: list<string>, reassert: bool, route_repair: bool,
 *                  escalate_restart: bool, state: State, reasons: list<string>, drain: list<string>}
 *   action: 'stop' (disabled, a stop cause, or Unbound not running), 'skip' (control channel silent), 'tunnel'
 *   (apply tries candidates in order; the first is the target; the current member first with its resolver changed is
 *   a switch in place), 'fallback' (leave tunnel mode, or in fallback restore a live root that names an address of
 *   the plugin's beside others, uu_plan_restore_due()) or 'none'.
 *   candidates is always the full choice list, so apply can move on when the current member fails its resolver
 *   checks; a member the contract excludes (no resolver, no next hop, an address-scoped failure) is never in it.
 *   reassert and route_repair are the reconcile and are only set with 'none': reassert when the live root is not
 *   the current member's resolver, route_repair when that resolver's route is not via the member, or another address
 *   the map holds (outside tunnel mode: any planner address, uu_plan_addresses(), or any the map holds) lacks its
 *   reject route while Unbound no longer forwards to it. drain lists the orphans due for their drain and delete
 *   (uu_plan_drain()); a stop and a skip have none.
 *   state carries the mode and member
 *   planned against (recovered from the live root and route when the state file was lost), the advanced timers,
 *   control_failures and control_silent_since; apply records switches and last_switch. escalate_restart is section
 *   3.10's restart for a silent control channel: a skip's in tunnel mode, and the one a stop other than a requested
 *   stop or the removal may run when it cannot restore, within the same bound, since the minute job repeats it.
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/address.php';
require_once __DIR__ . '/verdict.php';
require_once __DIR__ . '/choose.php';
require_once __DIR__ . '/state.php';
require_once __DIR__ . '/contract.php';
require_once __DIR__ . '/views.php';

/**
 * Whether the kernel route is the one tunnel mode through this member needs.
 *
 * @param array{present: bool, gateway: string, interface: string, reject: bool, ours: bool} $route
 * @param array{name: string, interface: string, if: string, next_hop: string, disabled: bool, force_down: bool,
 *              monitor_disable: bool, monitor: string, time_period: int, interval: int, loss_interval: int,
 *              losshigh: int} $m
 */
function uu_plan_route_via(array $route, array $m): bool
{
    return $route['present'] && $route['ours'] && !$route['reject']
        && uu_next_hop($route['gateway']) === uu_next_hop($m['next_hop']) && $route['interface'] === $m['if'];
}

/**
 * One member's standing, for a reason line.
 *
 * @param array<string, string> $verdicts down verdict per member that has one
 * @param array<string, string> $kinds reading kind per group member
 * @param array<string, bool> $usable
 * @param array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *                            probe_failures: int,
 *                                last_down: ?array{at: int, reason: string}, resolver: string}> $timers
 * @param list<string> $excluded the members the contract makes no candidate (uu_contract())
 */
function uu_plan_note(
    string $name,
    string $group,
    array $verdicts,
    array $kinds,
    array $usable,
    array $timers,
    int $now,
    array $excluded
): string {
    if (!isset($kinds[$name])) {
        return "$name not in group $group";
    }
    if (in_array($name, $excluded, true)) {
        return "$name not a candidate (see the contract's notes)";
    }
    if (isset($verdicts[$name])) {
        return "$name down: {$verdicts[$name]}";
    }
    $failedUntil = $timers[$name]['resolver_failed_until'] ?? null;
    if ($failedUntil !== null && $now < $failedUntil) {
        return sprintf('%s resolver-failed for %d s more', $name, $failedUntil - $now);
    }
    if ($usable[$name] ?? false) {
        return sprintf('%s usable and settled %d s', $name, $timers[$name]['counted'] ?? 0);
    }
    return "$name reading {$kinds[$name]}";
}

/**
 * @param list<string> $candidates
 * @param array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int,
 *         last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
 *     control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *         forwarded: bool, released_at: ?int}>,
 *     view: array{refuse: string, scope: string, nets: list<string>, problem: ?string}} $st
 * @param list<string> $reasons
 * @param list<string> $drain
 * @return array{action: string, candidates: list<string>, reassert: bool, route_repair: bool,
 *     escalate_restart: bool,
 *     state: array{version: int, mode: string, member: ?string,
 *         timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int,
 *         resolver_failed_until: ?int, probe_failures: int,
 *             last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
 *         control_silent_since: ?int, last_switch: ?array{at: int, from: string, to: string, reason: string},
 *         checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *         member: string}}, tls_applied: ?bool, blocked: ?int,
 *         addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *             forwarded: bool, released_at: ?int}>,
 *         view: array{refuse: string, scope: string, nets: list<string>, problem: ?string}},
 *     reasons: list<string>, drain: list<string>}
 */
function uu_plan_result(
    string $action,
    array $candidates,
    bool $reassert,
    bool $routeRepair,
    bool $escalate,
    array $st,
    array $reasons,
    array $drain
): array {
    return ['action' => $action, 'candidates' => $candidates, 'reassert' => $reassert,
            'route_repair' => $routeRepair, 'escalate_restart' => $escalate, 'state' => $st,
            'reasons' => $reasons, 'drain' => $drain];
}

/**
 * One more evaluation with Unbound's control channel silent: the count, the first such evaluation's
 * time, how long the channel has been silent, its reason line, and whether a restart is due: after
 * UU_ESCALATE_EVALUATIONS evaluations over at least UU_ESCALATE_MIN_SECONDS, so a fresh start is never restarted.
 *
 * @return array{failures: int, since: int, seconds: int, reason: string, due: bool}
 */
function uu_plan_silent(int $failures, ?int $since, int $now): array
{
    $failures++;
    $since = $since ?? $now;
    $seconds = max(0, $now - $since);
    return ['failures' => $failures, 'since' => $since, 'seconds' => $seconds,
            'reason' => sprintf('Unbound control channel silent (%d evaluations, %d s)', $failures, $seconds),
            'due' => $failures >= UU_ESCALATE_EVALUATIONS && $seconds >= UU_ESCALATE_MIN_SECONDS];
}

/**
 * Whether a stop with this cause restarts Unbound for a silent control channel at once: a requested stop and the
 * removal, which the minute job does not repeat. Every other cause (a disabled plugin's tick, a tick while the
 * removal marker exists, and any cause added later) waits for uu_plan_silent()'s bound.
 */
function uu_plan_restarts_at_once(?string $stop): bool
{
    return in_array($stop, [UU_STOP_REQUEST, UU_STOP_REMOVE], true);
}

/**
 * The cause of one evaluation's run. An evaluation with no cause that finds the removal marker is a tick of the
 * removal: it stops, as the ticks do, but only remove itself has the removal's restart and last resort, since the
 * package is still installed while the marker exists. A Save that changes a resolver is no stop: the planner switches
 * in place.
 *
 * @return array{run: ?string}
 */
function uu_plan_causes(?string $stop, bool $removing): array
{
    return ['run' => $stop === null && $removing ? UU_STOP_REMOVING : $stop];
}

/**
 * Why this evaluation stops whatever else it reads, or null when it does not. A requested stop while disabled is
 * a Save with enabled off, so it reads as the setting.
 *
 * @param array{settings: array{enabled: bool}, stop: ?string} $s
 */
function uu_plan_stop_reason(array $s): ?string
{
    $enabled = $s['settings']['enabled'];
    return match (true) {
        $s['stop'] === UU_STOP_REMOVE => 'the package is being removed',
        $s['stop'] === UU_STOP_REMOVING => 'the package is being removed: its removal marker exists',
        !$enabled => 'disabled in settings',
        $s['stop'] === UU_STOP_REQUEST => 'stopped on request (configctl unboundupstream stop)',
        $s['stop'] !== null => "stopped ({$s['stop']})",
        default => null,
    };
}

/**
 * Each member's effective resolver as the snapshot filled it, canonical, '' for none.
 *
 * @param array{members: array<string, array{resolver: string}>} $s
 * @return array<string, string>
 */
function uu_plan_resolvers(array $s): array
{
    $out = [];
    foreach ($s['members'] as $name => $m) {
        $out[(string)$name] = uu_member_resolver($s, (string)$name);
    }
    return $out;
}

/**
 * The address Unbound's live root names: A, canonical, when the live root is exactly [A] (its "@port" or "#name"
 * dropped, as the forwarded rule drops them) for an A among $addresses (every effective resolver and every address
 * the state's map holds); null otherwise, an unknown live root too.
 *
 * @param ?list<string> $liveRoot
 * @param list<string> $addresses
 */
function uu_plan_live_addr(?array $liveRoot, array $addresses): ?string
{
    if ($liveRoot === null || count($liveRoot) !== 1) {
        return null;
    }
    $live = uu_ip_canonical(uu_forwarder_addr($liveRoot[0]));
    foreach ($addresses as $address) {
        if ($live !== null && uu_ip_same($address, $live)) {
            return $live;
        }
    }
    return null;
}

/**
 * The address of the plugin's that Unbound's live root names when the live root is not Unbound's configured root zone,
 * so a restore is due: the first of $addresses (every planner address, uu_plan_addresses(), and every address the
 * state's map holds) that the live root names (uu_state_forwarded()); null when it names none, when it is exactly the
 * configured zone's forward-addr list (compared as sets: a zone that names the resolver itself is never restored
 * over, every minute, to itself) and for an unknown live root. One rule, which the planner's fallback and apply's
 * restore both take: a live root that is exactly [A] is due, and so is A beside another forwarder (an external
 * forward_add . A B).
 *
 * @param ?list<string> $live
 * @param list<string> $addresses
 * @param array{shape: string, addrs: list<string>, tls: bool, problems: list<string>} $zone
 */
function uu_plan_restore_due(?array $live, array $addresses, array $zone): ?string
{
    if ($live === null || uu_plan_live_configured($live, $zone)) {
        return null;
    }
    foreach ($addresses as $address) {
        if (uu_state_forwarded($live, $address, false)) {
            return $address;
        }
    }
    return null;
}

/**
 * Whether Unbound's live root is exactly its configured root zone's forward-addr list, compared as sets (@port and
 * #name dropped, canonical, uu_apply_same()): Unbound's own forwarders, whatever addresses they name. An unknown live
 * root never is. The one compare uu_plan_restore_due() and uu_plan_live_ours() share.
 *
 * @param ?list<string> $live
 * @param array{shape: string, addrs: list<string>, tls: bool, problems: list<string>} $zone
 */
function uu_plan_live_configured(?array $live, array $zone): bool
{
    return uu_apply_same($live, $zone['addrs']);
}

/**
 * The address the live root says the plugin put there, for inferring the mode when the state does not say tunnel:
 * uu_plan_live_addr()'s, except for a live root that is Unbound's configured root zone (uu_plan_live_configured()),
 * which is Unbound's own even when it is exactly [A], and gives null. Without it a configured root of [A] would read as
 * tunnel mode at every evaluation, and each would leave it again: a switch, its notification and its lines every
 * minute.
 *
 * @param ?list<string> $live
 * @param list<string> $addresses every planner address and every address the state's map holds
 * @param array{shape: string, addrs: list<string>, tls: bool, problems: list<string>} $zone
 */
function uu_plan_live_ours(?array $live, array $addresses, array $zone): ?string
{
    return uu_plan_live_configured($live, $zone) ? null : uu_plan_live_addr($live, $addresses);
}

/**
 * The snapshot's route for an address, absent when the snapshot did not read one.
 *
 * @param array{routes: array<string, array{present: bool, gateway: string, interface: string, reject: bool,
 *     ours: bool}>} $s
 * @return array{present: bool, gateway: string, interface: string, reject: bool, ours: bool}
 */
function uu_plan_route(array $s, string $address): array
{
    return $s['routes'][uu_ip_canonical($address) ?? $address]
        ?? ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false, 'ours' => false];
}

/**
 * Whether an address needs its reject route put back: its route is not the reject route, the plugin may touch it (a
 * route it did not make is never repaired), and Unbound no longer forwards to it. A reject route goes on an address
 * only while its forwarded is false, as this run's read settles it (uu_state_forwarded()): a read naming only others
 * clears a recorded true, a failed read keeps it, and an address with no entry was never forwarded to.
 *
 * @param array{present: bool, gateway: string, interface: string, reject: bool, ours: bool} $route
 * @param ?array{route: ?array{kind: string, next_hop: string, if: string}, forwarded: bool, released_at: ?int} $entry
 * @param ?list<string> $read the snapshot's live root read (uu_state_snapshot_read())
 */
function uu_plan_needs_reject(array $route, ?array $entry, ?array $read, string $address): bool
{
    if ($route['present'] && (!$route['ours'] || $route['reject'])) {
        return false;
    }
    return !uu_state_forwarded($read, $address, $entry['forwarded'] ?? false);
}

/**
 * Whether an address is an orphan Unbound's own configured root zone names: outside the planner's addresses ($kept,
 * uu_plan_addresses()), and named by a live root that is exactly the configured zone (uu_plan_live_configured()). The
 * owner's own forwarder then wins over the plugin's hold: Unbound forwards to it, so its reject route would leave every
 * lookup black, and no member will route it again. Such an orphan is released at once: drained behind its reject route
 * and deleted, its entry and block gone, as 1.3_2's stop did for its one address. The one exception to a drain needing
 * forwarded false; never a planner address, so the Default and every member's resolver stay fail-closed.
 *
 * @param ?list<string> $live
 * @param array{shape: string, addrs: list<string>, tls: bool, problems: list<string>} $zone
 * @param list<string> $kept
 */
function uu_plan_configured_orphan(?array $live, array $zone, string $address, array $kept): bool
{
    return !in_array($address, $kept, true) && uu_plan_live_configured($live, $zone)
        && uu_state_forwarded($live, $address, false);
}

/**
 * The orphans due for their drain: addresses outside the planner's addresses (uu_plan_addresses()) whose live route
 * is not one the plugin did not make (the drain deletes only its own), and either map entries released at least
 * UU_OLD_ADDRESS_HOLD seconds ago while Unbound no longer forwards to them as this run's read settles it
 * (uu_state_forwarded()), or named by Unbound's own configured root zone (uu_plan_configured_orphan()) and on its
 * reject route: one on a member route keeps it, its queries in the tunnel. A released entry is listed whatever its
 * route, since this run's route repair may put it on its reject route first; apply drains only those on their reject
 * route once that repair has run, so one whose reject route fails stays listed until it holds. The snapshot reads
 * routes only for the planner's addresses and the map's keys, so such an orphan is a map entry in practice; a lost
 * state leaves its route to the owner. Sorted.
 *
 * @param array{now: int, settings: array{default: string}, members: array<string, array{resolver: string}>,
 *     routes: array<string, array{present: bool, gateway: string, interface: string, reject: bool, ours: bool}>,
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>}} $s
 * @param array<string, array{route: ?array{kind: string, next_hop: string, if: string}, forwarded: bool,
 *     released_at: ?int}> $addresses the state's map
 * @param ?list<string> $read the snapshot's live root read (uu_state_snapshot_read())
 * @return list<string>
 */
function uu_plan_drain(array $s, array $addresses, ?array $read): array
{
    $kept = uu_plan_addresses($s);
    $drain = [];
    $candidates = array_unique(array_merge(array_map('strval', array_keys($addresses)),
        array_map('strval', array_keys($s['routes']))));
    foreach ($candidates as $address) {
        $entry = $addresses[$address] ?? null;
        $route = uu_plan_route($s, $address);
        $released = $entry['released_at'] ?? null;
        $held = $entry !== null && $released !== null && $s['now'] - $released >= UU_OLD_ADDRESS_HOLD
            && !uu_state_forwarded($read, $address, $entry['forwarded']);
        $named = $route['present'] && $route['ours'] && $route['reject']
            && uu_plan_configured_orphan($read, $s['zone'], $address, $kept);
        if (($held || $named) && !in_array($address, $kept, true) && !($route['present'] && !$route['ours'])) {
            $drain[] = $address;
        }
    }
    sort($drain, SORT_STRING);
    return $drain;
}

/**
 * The fail-closed view's share of an evaluation (spec 3.3, 3.4, 3.8): whether there is a view to act on, whether the
 * loaded view holds the refuse of ".", whether a stop keeps it, the daemon's zones and the records the mirror keeps
 * in the view, and why it cannot be armed. A view read that is not a loaded view's zones (silent, skipped, absent,
 * unsupported) leaves armed unknown, and a silent read is never acted on.
 *
 * @param array{stop: ?string, upgrade: bool,
 *     view: array{scope: string, nets: list<string>, notes: list<string>, acl: ?array{nodes: list<array{net: string,
 *         action: string}>, foreign: list<string>}, zones: ?array<string, string>, data: ?list<string>,
 *         loaded: string, view_zones: array<string, string>, view_data: list<string>, file: ?string,
 *         copy: ?string}} $s
 * @param array{view: array{refuse: string, scope: string, nets: list<string>, problem: ?string}} $st the state, which the view's share does not read
 * @return array{active: bool, armed: ?bool, keep: bool, zones: array<string, string>,
 *     mirror: array<string, list<string>>, problem: ?string}
 */
function uu_plan_view(array $s, array $st): array
{
    $view = $s['view'];
    $selected = $view['scope'] !== 'none';
    $loaded = $view['loaded'] === 'zones';
    $zones = $view['zones'];
    $data = $view['data'];
    $both = $zones !== null && $data !== null;
    $foreign = $view['acl']['foreign'] ?? [];
    $problem = match (true) {
        $selected && $view['loaded'] === 'unsupported' => 'Fail closed not armed: Unbound has no view support',
        $selected && $foreign !== [] => 'Fail closed not armed: a view the plugin does not own covers '
            . implode(', ', $foreign),
        $selected && $view['file'] !== null && $view['loaded'] === 'absent'
            => 'Fail closed not armed: restart Unbound to load the view',
        default => null,
    };
    return [
        'active' => $selected && $loaded,
        'armed' => $loaded ? ($view['view_zones']['.'] ?? null) === 'refuse' : null,
        'keep' => $s['upgrade'] || $s['stop'] === UU_STOP_REMOVING,
        'zones' => $both ? $zones : [],
        'mirror' => $both ? uu_view_mirror($zones, $data) : [],
        'problem' => $problem,
    ];
}

/**
 * The 1.4 plan: what the tunnel and the resolver need, before the view's sub-plan (uu_plan()) is added.
 *
 * @param array{now: int, wall: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, default: string,
 *         rows: array<string, string>, failback_delay: int, probe_name: string},
 *     trigger: string, tiers: list<list<string>>, family: string,
 *     members: array<string, array{name: string, interface: string, if: string, ipprotocol: string,
 *         resolver: string, next_hop: string, disabled: bool, force_down: bool, monitor_disable: bool,
 *         monitor: string, time_period: int, interval: int, loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>, stop: ?string,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     routes: array<string, array{present: bool, gateway: string, interface: string, reject: bool,
 *         ours: bool}>,
 *     route_flags: array<string, list<string>>,
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, monitors: array<string, list<string>>, statics: array<string, list<string>>,
 *         unmonitored_members: list<string>, foreign: list<string>, member_resolvers: array<string, string>,
 *         resolver_notes: list<string>, no_next_hop: list<string>,
 *         rules: array{state: string, problems: list<string>},
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int, core_commands: list<string>,
 *         unbound_conf: ?array{do_ip4: bool, do_ip6: bool, outgoing_interface: bool}, group_family: string,
 *         mixed_family: bool, family_mismatch: list<string>},
 *     rules: array{state: string, problems: list<string>, verified_at: ?int,
 *         record: ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>}},
 *     block_table: array{table: ?array{addresses: int, references: int, out_block: int}, addresses: list<string>},
 *     upgrade: bool,
 *     view: array{scope: string, nets: list<string>, notes: list<string>, acl: ?array{nodes: list<array{net: string,
 *         action: string}>, foreign: list<string>}, zones: ?array<string, string>, data: ?list<string>,
 *         loaded: string, view_zones: array<string, string>, view_data: list<string>, file: ?string,
 *         copy: ?string}} $s
 * @param array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int,
 *         last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
 *     control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *         forwarded: bool, released_at: ?int}>,
 *     view: array{refuse: string, scope: string, nets: list<string>, problem: ?string}} $st
 * @return array{action: string, candidates: list<string>, reassert: bool, route_repair: bool,
 *     escalate_restart: bool,
 *     state: array{version: int, mode: string, member: ?string,
 *         timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int,
 *         resolver_failed_until: ?int, probe_failures: int,
 *             last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
 *         control_silent_since: ?int, last_switch: ?array{at: int, from: string, to: string, reason: string},
 *         checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *         member: string}}, tls_applied: ?bool, blocked: ?int,
 *         addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *             forwarded: bool, released_at: ?int}>,
 *         view: array{refuse: string, scope: string, nets: list<string>, problem: ?string}},
 *     reasons: list<string>, drain: list<string>}
 */
function uu_plan_steps(array $s, array $st): array
{
    $now = $s['now'];
    $trigger = $s['trigger'];
    $group = $s['settings']['group'];
    $reasons = [];

    /* readings and verdicts for every group member; one without a gateway record or status cannot carry it */
    $kinds = [];
    $usable = [];
    $down = [];
    $verdicts = [];
    foreach ($s['tiers'] as $tier) {
        foreach ($tier as $name) {
            $m = $s['members'][$name] ?? null;
            $p = $s['probes'][$name] ?? null;
            if ($m === null || $p === null) {
                $kinds[$name] = 'none';
                $usable[$name] = false;
                $verdict = $m === null ? 'no gateway record' : 'no gateway status';
            } else {
                $kinds[$name] = uu_reading_kind($m, $p);
                $usable[$name] = uu_usable_settled($m, $p, $trigger);
                $verdict = uu_member_down($m, $p, $trigger, in_array($name, $s['named'], true));
            }
            $down[$name] = $verdict !== null;
            if ($verdict !== null) {
                $verdicts[$name] = $verdict;
            }
        }
    }
    $resolverOf = uu_plan_resolvers($s);
    /* the address each member's timer last followed: the resolver it had before a Save changed it */
    $followed = array_map(fn (array $timer): string => $timer['resolver'], $st['timers']);
    $st['timers'] = uu_timers_follow_resolvers(
        uu_timers_update($st['timers'], $kinds, $usable, $verdicts, $now, $s['wall']), $resolverOf);

    /* when the state file does not say tunnel, the live root decides the mode, unless it is Unbound's configured root
     * zone (uu_plan_live_ours()); with the control channel silent there is no live root, and our route via a member is
     * the evidence instead */
    $liveRoot = $s['unbound']['live_root'];
    $known = array_merge(uu_plan_addresses($s), array_map('strval', array_keys($st['addresses'])));
    $liveAddr = uu_plan_live_addr($liveRoot, $known);
    $inferred = uu_plan_live_ours($liveRoot, $known, $s['zone']);
    $current = $st['mode'] === 'tunnel' ? $st['member'] : null;
    if ($current === null && ($inferred !== null || $liveRoot === null)) {
        foreach (array_keys($kinds) as $name) {
            $m = $s['members'][$name] ?? null;
            $own = $resolverOf[$name] ?? '';
            if ($m !== null && $own !== '' && ($inferred === null || $own === $inferred)
                && uu_plan_route_via(uu_plan_route($s, $own), $m)) {
                $current = $name;
                break;
            }
        }
        if ($inferred !== null) {
            $reasons[] = $current === null
                ? 'live root is the resolver but our route is via no member: tunnel mode with no member'
                : "live root is the resolver and our route is via $current: tunnel mode on $current";
        } elseif ($current !== null) {
            $reasons[] = "live root unknown and our route is via $current: tunnel mode on $current";
        }
    }
    if ($current !== null || $inferred !== null) {
        $mode = 'tunnel';
    } elseif ($liveRoot === null) {
        $mode = $st['mode'];
    } else {
        $mode = 'fallback';
    }
    $st['mode'] = $mode;
    $st['member'] = $current;

    /* a member the contract makes no candidate keeps its place in the tiers, so leaving it is the same as leaving a
     * down member: a worse tier needs no failback delay */
    $contract = uu_contract($s['contract_input']);
    $candidates = array_values(array_filter(
        uu_candidates($s['tiers'], $usable, $down, $st['timers'], $now, $s['settings']['failback_delay'], $current),
        fn (string $name): bool => !in_array($name, $contract['excluded'], true)));

    $stopReason = uu_plan_stop_reason($s);
    if ($stopReason !== null) {
        $reasons[] = $stopReason;
        $escalate = false;
        if (!uu_plan_restarts_at_once($s['stop']) && $s['unbound']['enabled'] && $s['unbound']['pid_alive']
            && !$s['unbound']['control_ok']) {
            /* a stop that repeats (a disabled plugin's tick, which the minute job runs while a footprint remains, and
             * a tick while the removal marker exists) restarts Unbound for a silent channel only within the bound of
             * tunnel mode's escalation, never every minute */
            $silent = uu_plan_silent($st['control_failures'], $st['control_silent_since'], $now);
            $st['control_failures'] = $silent['failures'];
            $st['control_silent_since'] = $silent['since'];
            $reasons[] = $silent['reason'];
            if ($silent['due']) {
                $escalate = true;
                /* apply refuses the restart with cacheflush on (the cache is the user's), so the line does not
                 * promise it */
                $reasons[] = sprintf('control channel silent %d evaluations over %d s while stopping: %s',
                    $silent['failures'], $silent['seconds'], $s['contract_input']['cacheflush']
                    ? 'restart escalation disabled: cacheflush on' : 'restart Unbound when the stop cannot restore');
                $st['control_failures'] = 0;
                $st['control_silent_since'] = null;
            }
        } else {
            $st['control_failures'] = 0;
            $st['control_silent_since'] = null;
        }
        return uu_plan_result('stop', $candidates, false, false, $escalate, $st, $reasons, []);
    }
    if (!$s['unbound']['enabled'] || !$s['unbound']['pid_alive']) {
        /* the user stopped Unbound: a silent control channel is no fault and nothing escalates */
        $st['control_failures'] = 0;
        $st['control_silent_since'] = null;
        $reasons[] = 'Unbound not running: ' . ($s['unbound']['enabled'] ? 'no live pid' : 'disabled');
        return uu_plan_result('stop', $candidates, false, false, false, $st, $reasons, []);
    }
    if (!$s['unbound']['control_ok']) {
        $silent = uu_plan_silent($st['control_failures'], $st['control_silent_since'], $now);
        $st['control_failures'] = $silent['failures'];
        $st['control_silent_since'] = $silent['since'];
        $reasons[] = $silent['reason'];
        $escalate = false;
        if ($mode === 'tunnel' && $silent['due']) {
            if ($s['contract_input']['cacheflush']) {
                $reasons[] = 'restart escalation disabled: cacheflush on';
            } else {
                $escalate = true;
                $reasons[] = sprintf('control channel silent %d evaluations over %d s in tunnel mode: restart Unbound',
                    $silent['failures'], $silent['seconds']);
                /* the restart starts the count again, so a channel still silent after it waits as long again */
                $st['control_failures'] = 0;
                $st['control_silent_since'] = null;
            }
        }
        return uu_plan_result('skip', $candidates, false, false, $escalate, $st, $reasons, []);
    }
    $st['control_failures'] = 0;
    $st['control_silent_since'] = null;

    $read = uu_state_snapshot_read($s['unbound']);
    $drain = uu_plan_drain($s, $st['addresses'], $read);
    /* outside tunnel mode every planner address (uu_plan_addresses()) and every address the map holds needs its
     * reject route, and a live root that names one of them is restored first */
    $ours = array_values(array_unique($known));
    $rejectRepair = false;
    foreach ($ours as $address) {
        $rejectRepair = $rejectRepair
            || uu_plan_needs_reject(uu_plan_route($s, $address), $st['addresses'][$address] ?? null, $read, $address);
    }
    $named = $mode === 'fallback' ? uu_plan_restore_due($read, $ours, $s['zone']) : null;
    $restore = $named === null ? null : "live root names $named but is not Unbound's configured root zone: restore it";

    if (!$contract['ok']) {
        foreach ($contract['failures'] as $failure) {
            $ofGroup = in_array($failure, ['group not found', 'group has no members'], true);
            $reasons[] = 'contract: ' . $failure . ($ofGroup ? " ($group)" : '');
        }
        if ($mode === 'tunnel') {
            return uu_plan_result('fallback', $candidates, false, false, false, $st, $reasons, $drain);
        }
        if ($restore !== null) {
            $reasons[] = $restore;
            return uu_plan_result('fallback', $candidates, false, false, false, $st, $reasons, $drain);
        }
        return uu_plan_result('none', $candidates, false, $rejectRepair, false, $st, $reasons, $drain);
    }

    $note = fn (string $name): string => uu_plan_note($name, $group, $verdicts, $kinds, $usable, $st['timers'],
        $now, $contract['excluded']);
    $target = $candidates[0] ?? null;
    if ($target === null) {
        if ($mode === 'fallback' && $restore !== null) {
            $reasons[] = $restore;
            return uu_plan_result('fallback', $candidates, false, false, false, $st, $reasons, $drain);
        }
        if ($mode === 'fallback') {
            return uu_plan_result('none', $candidates, false, $rejectRepair, false, $st, $reasons, $drain);
        }
        $notes = array_map($note, array_keys($kinds));
        if ($current !== null && !isset($kinds[$current])) {
            array_unshift($notes, $note($current));
        }
        $reasons[] = 'no candidate, fallback: '
            . ($notes === [] ? "group $group has no members" : implode('; ', $notes)) . " (trigger $trigger)";
        return uu_plan_result('fallback', $candidates, false, false, false, $st, $reasons, $drain);
    }
    if ($target !== $current) {
        $from = $current === null
            ? "enter tunnel via $target: "
            : "leave $current for $target: " . $note($current) . '; ';
        $reasons[] = $from . $note($target) . " (trigger $trigger)";
        return uu_plan_result('tunnel', $candidates, false, false, false, $st, $reasons, $drain);
    }

    /* the current member is the target, so it has a resolver (a member with none is no candidate) */
    $resolver = $resolverOf[$current] ?? '';
    if ($liveAddr !== null && $liveAddr !== $resolver) {
        /* a Save changed the current member's resolver (its timer followed the live address), or the live root names
         * another address: a switch to the same member with its own resolver, never a stop first */
        $prev = $followed[$current] ?? '';
        $reasons[] = $prev !== '' && uu_ip_same($prev, $liveAddr)
            ? "resolver of $current changed from $liveAddr to $resolver: switching in place"
            : "live root is $liveAddr, not $current's resolver $resolver: switching in place";
        return uu_plan_result('tunnel', $candidates, false, false, false, $st, $reasons, $drain);
    }
    $m = $s['members'][$current] ?? null;
    $route = uu_plan_route($s, $resolver);
    $reassert = $liveAddr !== $resolver;
    /* never repair a route the plugin did not make; the contract refuses tunnel mode over it */
    $routeRepair = !($route['present'] && !$route['ours']) && ($m === null || !uu_plan_route_via($route, $m));
    if ($reassert) {
        $reasons[] = "live root is not the resolver: reassert $resolver via $current";
    }
    if ($routeRepair) {
        $reasons[] = "resolver route missing, elsewhere or reject: route via $current";
    }
    /* every other address the map holds needs its reject route, once Unbound no longer forwards to it */
    foreach ($st['addresses'] as $address => $entry) {
        $address = (string)$address;
        if ($address !== $resolver && uu_plan_needs_reject(uu_plan_route($s, $address), $entry, $read, $address)) {
            $routeRepair = true;
            $reasons[] = "route of $address is missing or not its reject route: reject $address locally";
        }
    }
    return uu_plan_result('none', $candidates, $reassert, $routeRepair, false, $st, $reasons, $drain);
}

/**
 * One evaluation's plan: the 1.4 plan (uu_plan_steps()) and the fail-closed view's share (uu_plan_view()).
 *
 * @param array{now: int, wall: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, default: string,
 *         rows: array<string, string>, failback_delay: int, probe_name: string},
 *     trigger: string, tiers: list<list<string>>, family: string,
 *     members: array<string, array{name: string, interface: string, if: string, ipprotocol: string,
 *         resolver: string, next_hop: string, disabled: bool, force_down: bool, monitor_disable: bool,
 *         monitor: string, time_period: int, interval: int, loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>, stop: ?string,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     routes: array<string, array{present: bool, gateway: string, interface: string, reject: bool,
 *         ours: bool}>,
 *     route_flags: array<string, list<string>>,
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, monitors: array<string, list<string>>, statics: array<string, list<string>>,
 *         unmonitored_members: list<string>, foreign: list<string>, member_resolvers: array<string, string>,
 *         resolver_notes: list<string>, no_next_hop: list<string>,
 *         rules: array{state: string, problems: list<string>},
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int, core_commands: list<string>,
 *         unbound_conf: ?array{do_ip4: bool, do_ip6: bool, outgoing_interface: bool}, group_family: string,
 *         mixed_family: bool, family_mismatch: list<string>},
 *     rules: array{state: string, problems: list<string>, verified_at: ?int,
 *         record: ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>}},
 *     block_table: array{table: ?array{addresses: int, references: int, out_block: int}, addresses: list<string>},
 *     upgrade: bool,
 *     view: array{scope: string, nets: list<string>, notes: list<string>, acl: ?array{nodes: list<array{net: string,
 *         action: string}>, foreign: list<string>}, zones: ?array<string, string>, data: ?list<string>,
 *         loaded: string, view_zones: array<string, string>, view_data: list<string>, file: ?string,
 *         copy: ?string}} $s
 * @param array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int,
 *         last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
 *     control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *         forwarded: bool, released_at: ?int}>,
 *     view: array{refuse: string, scope: string, nets: list<string>, problem: ?string}} $st
 * @return array{action: string, candidates: list<string>, reassert: bool, route_repair: bool,
 *     escalate_restart: bool,
 *     state: array{version: int, mode: string, member: ?string,
 *         timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int,
 *         resolver_failed_until: ?int, probe_failures: int,
 *             last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
 *         control_silent_since: ?int, last_switch: ?array{at: int, from: string, to: string, reason: string},
 *         checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *         member: string}}, tls_applied: ?bool, blocked: ?int,
 *         addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *             forwarded: bool, released_at: ?int}>,
 *         view: array{refuse: string, scope: string, nets: list<string>, problem: ?string}},
 *     reasons: list<string>, drain: list<string>,
 *     view: array{active: bool, armed: ?bool, keep: bool, zones: array<string, string>,
 *         mirror: array<string, list<string>>, problem: ?string}}
 */
function uu_plan(array $s, array $st): array
{
    return uu_plan_steps($s, $st) + ['view' => uu_plan_view($s, $st)];
}
