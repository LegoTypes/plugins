<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The planner (spec 2026-10-17 sections 3.2 to 3.4 and 3.10). Pure: (snapshot, state) -> plan.
 *
 * Snapshot = array{now: int, wall: int, settings: array{enabled: bool, dry_run: bool, group: string, resolver: string,
 *                  failback_delay: int, probe_name: string},
 *                  trigger: string, tiers: list<list<string>>, members: array<string, Member>,
 *                  probes: array<string, Probe>, named: list<string>, stop: ?string,
 *                  unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *                  zone: Zone, route: array{present: bool, gateway: string, interface: string, reject: bool,
 *                  ours: bool}, fib_sync_ms: ?int, contract_input: ContractInput, rules: RulesCheck,
 *                  block_table: array{table: ?TableFacts, addresses: list<string>}}
 *   now is monotonic seconds; tiers come from the group (best first) and are empty when the group is gone;
 *   members and probes are keyed by gateway name (Member and Probe: verdict.php); named lists the gateways the
 *   monitor hook passed; stop is why this run stops whatever the settings say (a UU_STOP_* cause), or null;
 *   live_root is null when unbound-control did not answer; route is `route -n get
 *   <resolver>`, interface the device it leaves by (compared with Member.if) and ours whether the plugin made
 *   it; Zone is zone.php's; ContractInput is uu_contract()'s input (contract.php). rules is uu_rules_check()'s
 *   answer (pfobserve.php; its state and problems are also ContractInput.rules, and record is the verification an
 *   evaluation saves), block_table the counting table's facts as pf printed them (table null: no such table);
 *   the caller turns it into uu_block_table_view()
 *   with the saved state's resolver, since the snapshot never reads the state file.
 * Plan     = array{action: string, candidates: list<string>, reassert: bool, route_repair: bool,
 *                  escalate_restart: bool, state: State, reasons: list<string>}
 *   action: 'stop' (disabled, a stop cause, or Unbound not running), 'skip' (control channel silent), 'tunnel'
 *   (apply tries candidates in order; the first is the target), 'fallback' (leave tunnel mode) or 'none'.
 *   candidates is always the full choice list, so apply can move on when the current member fails its resolver
 *   checks. reassert and route_repair are the section 3.4 reconcile and are only set with 'none'. state carries
 *   the mode and member
 *   planned against (recovered from the live root and route when the state file was lost), the advanced timers,
 *   control_failures and control_silent_since; apply records switches and last_switch. escalate_restart is section
 *   3.10's restart for a silent control channel: a skip's in tunnel mode, and the one a stop other than a requested
 *   stop or the removal may run when it cannot restore (rulings R52, R53).
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/verdict.php';
require_once __DIR__ . '/choose.php';
require_once __DIR__ . '/state.php';
require_once __DIR__ . '/contract.php';

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
    return $route['present'] && $route['ours'] && !$route['reject'] && $route['gateway'] === $m['next_hop']
        && $route['interface'] === $m['if'];
}

/**
 * One member's standing, for a reason line.
 *
 * @param array<string, string> $verdicts down verdict per member that has one
 * @param array<string, string> $kinds reading kind per group member
 * @param array<string, bool> $usable
 * @param array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *                            probe_failures: int,
 *                                last_down: ?array{at: int, reason: string}}> $timers
 */
function uu_plan_note(
    string $name,
    string $group,
    array $verdicts,
    array $kinds,
    array $usable,
    array $timers,
    int $now
): string {
    if (!isset($kinds[$name])) {
        return "$name not in group $group";
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
 *         last_down: ?array{at: int, reason: string}}>, control_failures: int, control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     route_installed: ?array{kind: string, next_hop: string, if: string}, resolver: ?string} $st
 * @param list<string> $reasons
 * @return array{action: string, candidates: list<string>, reassert: bool, route_repair: bool,
 *     escalate_restart: bool,
 *     state: array{version: int, mode: string, member: ?string,
 *         timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int,
 *         resolver_failed_until: ?int, probe_failures: int,
 *             last_down: ?array{at: int, reason: string}}>, control_failures: int,
 *         control_silent_since: ?int, last_switch: ?array{at: int, from: string, to: string, reason: string},
 *         checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *         member: string}}, tls_applied: ?bool, blocked: ?int,
 *         route_installed: ?array{kind: string, next_hop: string, if: string}, resolver: ?string},
 *     reasons: list<string>}
 */
function uu_plan_result(
    string $action,
    array $candidates,
    bool $reassert,
    bool $routeRepair,
    bool $escalate,
    array $st,
    array $reasons
): array {
    return ['action' => $action, 'candidates' => $candidates, 'reassert' => $reassert,
            'route_repair' => $routeRepair, 'escalate_restart' => $escalate, 'state' => $st,
            'reasons' => $reasons];
}

/**
 * One more evaluation with Unbound's control channel silent (section 3.10): the count, the first such evaluation's
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
 * Whether a stop with this cause restarts Unbound for a silent control channel at once (ruling R53): a requested
 * stop and the removal, which the minute job does not repeat. Every other cause (a disabled plugin's tick, the undo
 * of a replaced address, and any cause added later) waits for uu_plan_silent()'s bound.
 */
function uu_plan_restarts_at_once(?string $stop): bool
{
    return in_array($stop, [UU_STOP_REQUEST, UU_STOP_REMOVE], true);
}

/**
 * Why this evaluation stops whatever else it reads, or null when it does not. A requested stop while disabled is
 * a Save with enabled off, so it reads as the setting.
 *
 * @param array{settings: array{enabled: bool, resolver: string}, stop: ?string} $s
 */
function uu_plan_stop_reason(array $s): ?string
{
    $enabled = $s['settings']['enabled'];
    return match (true) {
        $s['stop'] === UU_STOP_REMOVE => 'the package is being removed',
        $s['stop'] === UU_STOP_RESOLVER => "the resolver setting changed: undoing {$s['settings']['resolver']}",
        !$enabled => 'disabled in settings',
        $s['stop'] === UU_STOP_REQUEST => 'stopped on request (configctl unboundupstream stop)',
        $s['stop'] !== null => "stopped ({$s['stop']})",
        default => null,
    };
}

/**
 * @param array{now: int, wall: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, failback_delay: int,
 *         probe_name: string},
 *     trigger: string, tiers: list<list<string>>,
 *     members: array<string, array{name: string, interface: string, if: string, next_hop: string, disabled: bool,
 *         force_down: bool, monitor_disable: bool, monitor: string, time_period: int, interval: int,
 *         loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>, stop: ?string,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool},
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, resolver_is_monitor: list<string>, resolver_in_static: list<string>,
 *         unmonitored_members: list<string>, foreign_route: bool, rules: array{state: string, problems: list<string>},
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int},
 *     rules: array{state: string, problems: list<string>, verified_at: ?int,
 *         record: ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>}},
 *     block_table: array{table: ?array{addresses: int, references: int, out_block: int}, addresses: list<string>}} $s
 * @param array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int,
 *         last_down: ?array{at: int, reason: string}}>, control_failures: int, control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     route_installed: ?array{kind: string, next_hop: string, if: string}, resolver: ?string} $st
 * @return array{action: string, candidates: list<string>, reassert: bool, route_repair: bool,
 *     escalate_restart: bool,
 *     state: array{version: int, mode: string, member: ?string,
 *         timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int,
 *         resolver_failed_until: ?int, probe_failures: int,
 *             last_down: ?array{at: int, reason: string}}>, control_failures: int,
 *         control_silent_since: ?int, last_switch: ?array{at: int, from: string, to: string, reason: string},
 *         checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *         member: string}}, tls_applied: ?bool, blocked: ?int,
 *         route_installed: ?array{kind: string, next_hop: string, if: string}, resolver: ?string},
 *     reasons: list<string>}
 */
function uu_plan(array $s, array $st): array
{
    $now = $s['now'];
    $trigger = $s['trigger'];
    $group = $s['settings']['group'];
    $resolver = $s['settings']['resolver'];
    $route = $s['route'];
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
    $st['timers'] = uu_timers_update($st['timers'], $kinds, $usable, $verdicts, $now, $s['wall']);

    /* when the state file does not say tunnel, the live root decides the mode (Review Focus 4); with the control
     * channel silent there is no live root, and our route via a member is the evidence instead */
    $liveRoot = $s['unbound']['live_root'];
    $liveIsResolver = $liveRoot === [$resolver];
    $current = $st['mode'] === 'tunnel' ? $st['member'] : null;
    if ($current === null && ($liveIsResolver || $liveRoot === null)) {
        foreach (array_keys($kinds) as $name) {
            $m = $s['members'][$name] ?? null;
            if ($m !== null && uu_plan_route_via($route, $m)) {
                $current = $name;
                break;
            }
        }
        if ($liveIsResolver) {
            $reasons[] = $current === null
                ? 'live root is the resolver but our route is via no member: tunnel mode with no member'
                : "live root is the resolver and our route is via $current: tunnel mode on $current";
        } elseif ($current !== null) {
            $reasons[] = "live root unknown and our route is via $current: tunnel mode on $current";
        }
    }
    if ($current !== null || $liveIsResolver) {
        $mode = 'tunnel';
    } elseif ($liveRoot === null) {
        $mode = $st['mode'];
    } else {
        $mode = 'fallback';
    }
    $st['mode'] = $mode;
    $st['member'] = $current;

    $candidates = uu_candidates($s['tiers'], $usable, $down, $st['timers'], $now, $s['settings']['failback_delay'],
        $current);

    $stopReason = uu_plan_stop_reason($s);
    if ($stopReason !== null) {
        $reasons[] = $stopReason;
        $escalate = false;
        if (!uu_plan_restarts_at_once($s['stop']) && $s['unbound']['enabled'] && $s['unbound']['pid_alive']
            && !$s['unbound']['control_ok']) {
            /* rulings R52 and R53: a stop that repeats (a disabled plugin's tick, which the minute job runs while a
             * footprint remains, and the undo of a replaced address) restarts Unbound for a silent channel only
             * within the bound of tunnel mode's escalation, never every minute */
            $silent = uu_plan_silent($st['control_failures'], $st['control_silent_since'], $now);
            $st['control_failures'] = $silent['failures'];
            $st['control_silent_since'] = $silent['since'];
            $reasons[] = $silent['reason'];
            if ($silent['due']) {
                $escalate = true;
                /* apply refuses the restart with cacheflush on (owner decision D2), so the line does not promise it */
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
        return uu_plan_result('stop', $candidates, false, false, $escalate, $st, $reasons);
    }
    if (!$s['unbound']['enabled'] || !$s['unbound']['pid_alive']) {
        /* the user stopped Unbound: a silent control channel is no fault and nothing escalates (Review Focus 3) */
        $st['control_failures'] = 0;
        $st['control_silent_since'] = null;
        $reasons[] = 'Unbound not running: ' . ($s['unbound']['enabled'] ? 'no live pid' : 'disabled');
        return uu_plan_result('stop', $candidates, false, false, false, $st, $reasons);
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
        return uu_plan_result('skip', $candidates, false, false, $escalate, $st, $reasons);
    }
    $st['control_failures'] = 0;
    $st['control_silent_since'] = null;

    /* never repair a route the plugin did not make; the contract refuses tunnel mode over it (Review Focus 1) */
    $foreign = $route['present'] && !$route['ours'];
    $rejectRepair = !$foreign && !($route['present'] && $route['reject']);

    $contract = uu_contract($s['contract_input']);
    if (!$contract['ok']) {
        foreach ($contract['failures'] as $failure) {
            $ofGroup = in_array($failure, ['group not found', 'group has no members'], true);
            $reasons[] = 'contract: ' . $failure . ($ofGroup ? " ($group)" : '');
        }
        if ($mode === 'tunnel') {
            return uu_plan_result('fallback', $candidates, false, false, false, $st, $reasons);
        }
        return uu_plan_result('none', $candidates, false, $rejectRepair, false, $st, $reasons);
    }

    $note = fn (string $name): string => uu_plan_note($name, $group, $verdicts, $kinds, $usable, $st['timers'],
        $now);
    $target = $candidates[0] ?? null;
    if ($target === null) {
        if ($mode === 'fallback') {
            return uu_plan_result('none', $candidates, false, $rejectRepair, false, $st, $reasons);
        }
        $notes = array_map($note, array_keys($kinds));
        if ($current !== null && !isset($kinds[$current])) {
            array_unshift($notes, $note($current));
        }
        $reasons[] = 'no candidate, fallback: '
            . ($notes === [] ? "group $group has no members" : implode('; ', $notes)) . " (trigger $trigger)";
        return uu_plan_result('fallback', $candidates, false, false, false, $st, $reasons);
    }
    if ($target !== $current) {
        $from = $current === null
            ? "enter tunnel via $target: "
            : "leave $current for $target: " . $note($current) . '; ';
        $reasons[] = $from . $note($target) . " (trigger $trigger)";
        return uu_plan_result('tunnel', $candidates, false, false, false, $st, $reasons);
    }

    $m = $s['members'][$current] ?? null;
    $reassert = !$liveIsResolver;
    $routeRepair = !$foreign && ($m === null || !uu_plan_route_via($route, $m));
    if ($reassert) {
        $reasons[] = "live root is not the resolver: reassert $resolver via $current";
    }
    if ($routeRepair) {
        $reasons[] = "resolver route missing, elsewhere or reject: route via $current";
    }
    return uu_plan_result('none', $candidates, $reassert, $routeRepair, false, $st, $reasons);
}
