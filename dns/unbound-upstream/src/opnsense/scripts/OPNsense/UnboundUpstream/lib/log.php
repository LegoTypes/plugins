<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Status and logging (spec 2026-10-17 section 3.8): syslog lines, the blocked-packet line, the rule counters and
 * the status document. Pure except uu_log() and uu_logger().
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/verdict.php';
require_once __DIR__ . '/choose.php';
require_once __DIR__ . '/contract.php';
require_once __DIR__ . '/render.php';

/**
 * Log from evaluate.php's own process as program unboundupstream at local4, which the plugin's syslog-ng filter
 * selects. Never from a hook: openlog() inside core's process would replace core's own syslog ident (uu_logger()).
 */
function uu_log(string $msg, int $prio = LOG_NOTICE): void
{
    static $open = false;
    if (!$open) {
        openlog('unboundupstream', LOG_PID, LOG_LOCAL4);
        $open = true;
    }
    syslog($prio, str_replace(["\r", "\n"], '; ', $msg));
}

/**
 * Log from inside core's process (configure and firewall hooks) through logger(1), so core's syslog ident and
 * connection stay as they are.
 *
 * @param string $level a syslog level name: err, warning, notice, info
 */
function uu_logger(string $msg, string $level = 'notice'): void
{
    exec('/usr/bin/logger -t unboundupstream -p ' . escapeshellarg('local4.' . $level) . ' -- '
        . escapeshellarg(str_replace(["\r", "\n"], '; ', $msg)) . ' > /dev/null 2>&1');
}

/**
 * Whether pf holds the plugin's rules: the block rule and a pass rule for every member interface that resolved
 * (an empty interface name has no rule). A filter reload without the plugin's files drops them (section 3.6).
 *
 * @param list<string> $interfaces the members' interface names (opt1, ...)
 */
function uu_rules_loaded(string $pfOut, array $interfaces): bool
{
    $counts = uu_pf_label_packets($pfOut);
    if (!isset($counts[uu_label_block()])) {
        return false;
    }
    foreach ($interfaces as $opt) {
        if ($opt !== '' && !isset($counts[uu_label_pass($opt)])) {
            return false;
        }
    }
    return true;
}

/**
 * `pfctl -vsr`: packets per rule label, summed over the rules one label expands to (a tcp/udp pass is two pf
 * rules). A labelled rule without a counter line counts 0, so its label still shows the rule is loaded.
 *
 * @return array<string, int>
 */
function uu_pf_label_packets(string $out): array
{
    $counts = [];
    $label = null;
    foreach (preg_split('/\R/', $out) ?: [] as $line) {
        if ($line === '') {
            continue;
        }
        if ($line[0] !== ' ' && $line[0] !== "\t") {
            $label = preg_match('/\blabel "([^"]*)"/', $line, $m) === 1 ? $m[1] : null;
            if ($label !== null) {
                $counts[$label] = $counts[$label] ?? 0;
            }
            continue;
        }
        if ($label !== null && preg_match('/\bPackets:\s*(\d+)/', $line, $m) === 1) {
            $counts[$label] += (int)$m[1];
        }
    }
    return $counts;
}

/**
 * The log line for the block rule's packet count, or null when there is nothing new. pf resets rule counters on
 * every filter reload, so a lower count starts again from the reload.
 */
function uu_blocked_line(?int $previous, ?int $now): ?string
{
    if ($now === null || $now === 0) {
        return null;
    }
    if ($previous === null || $now < $previous) {
        return sprintf('blocked %d resolver packets on a non-member path since the rules were loaded', $now);
    }
    if ($now === $previous) {
        return null;
    }
    return sprintf('blocked %d more resolver packets on a non-member path (%d since the rules were loaded)',
        $now - $previous, $now);
}

/**
 * The flags of `route -n get`'s answer.
 *
 * @return list<string>
 */
function uu_status_route_flags(string $out): array
{
    if (preg_match('/^\s*flags:\s*<([^>]*)>/m', $out, $m) !== 1) {
        return [];
    }
    return array_values(array_filter(explode(',', $m[1]), fn (string $flag): bool => $flag !== ''));
}

/**
 * The status page's document (section 3.8). The mode, member and timers are the plan's view of now (recovered
 * from the live root and route when the state file was lost); next is what the next evaluation would do and why.
 *
 * @param array{now: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, failback_delay: int,
 *         probe_name: string},
 *     trigger: string, tiers: list<list<string>>,
 *     members: array<string, array{name: string, interface: string, if: string, next_hop: string, disabled: bool,
 *         force_down: bool, monitor_disable: bool, monitor: string, time_period: int, interval: int,
 *         loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool},
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, resolver_is_monitor: list<string>, resolver_in_static: list<string>,
 *         unmonitored_members: list<string>, foreign_route: bool, rules_loaded: bool,
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int}} $s
 * @param array{action: string, candidates: list<string>, reassert: bool, route_repair: bool,
 *     escalate_restart: bool,
 *     state: array{version: int, mode: string, member: ?string,
 *         timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int,
 *         resolver_failed_until: ?int, probe_failures: int}>, control_failures: int,
 *         control_silent_since: ?int, last_switch: ?array{at: int, from: string, to: string, reason: string},
 *         checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *         member: string}}, tls_applied: ?bool, blocked: ?int,
 *         route_installed: ?array{kind: string, next_hop: string, if: string}, resolver: ?string},
 *     reasons: list<string>} $plan uu_plan() of the snapshot and the saved state
 * @param string $pfOut `pfctl -vsr`
 * @param string $routeOut `route -n get -inet <resolver>`
 * @return array{enabled: bool, dry_run: bool, mode: string, member: ?string, tier: ?int,
 *     unbound: array{enabled: bool, running: bool, control_ok: bool}, live_root: ?list<string>,
 *     configured_root: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     tls_applied: ?bool,
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool, flags: list<string>},
 *     rules_loaded: bool, blocked: ?int,
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *         member: string}},
 *     members: list<array{name: string, tier: int, kind: string, verdict: ?string, usable: bool, counted: int,
 *         resolver_failed_for: ?int, probe_failures: int}>,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     contract: array{ok: bool, failures: list<string>, notes: list<string>},
 *     next: array{action: string, reasons: list<string>}}
 */
function uu_status_doc(array $s, array $plan, string $pfOut, string $routeOut): array
{
    $st = $plan['state'];
    $tierOf = [];
    foreach ($s['tiers'] as $index => $tier) {
        foreach ($tier as $name) {
            $tierOf[$name] = $tierOf[$name] ?? $index + 1;
        }
    }
    $members = [];
    foreach ($tierOf as $name => $tier) {
        $m = $s['members'][$name] ?? null;
        $p = $s['probes'][$name] ?? null;
        $timer = $st['timers'][$name] ?? uu_timer_new();
        $until = $timer['resolver_failed_until'];
        $members[] = [
            'name' => $name,
            'tier' => $tier,
            'kind' => $m === null || $p === null ? 'none' : uu_reading_kind($m, $p),
            'verdict' => $m === null ? 'no gateway record'
                : ($p === null ? 'no gateway status' : uu_member_down($m, $p, $s['trigger'], false)),
            'usable' => $m !== null && $p !== null && uu_usable_settled($m, $p, $s['trigger']),
            'counted' => $timer['counted'],
            'resolver_failed_for' => $until !== null && $s['now'] < $until ? $until - $s['now'] : null,
            'probe_failures' => $timer['probe_failures'],
        ];
    }

    $counts = uu_pf_label_packets($pfOut);
    $loaded = uu_rules_loaded($pfOut, array_column($s['members'], 'interface'));

    return [
        'enabled' => $s['settings']['enabled'],
        'dry_run' => $s['settings']['dry_run'],
        'mode' => $st['mode'],
        'member' => $st['member'],
        'tier' => $st['member'] === null ? null : ($tierOf[$st['member']] ?? null),
        'unbound' => ['enabled' => $s['unbound']['enabled'], 'running' => $s['unbound']['pid_alive'],
                      'control_ok' => $s['unbound']['control_ok']],
        'live_root' => $s['unbound']['live_root'],
        'configured_root' => $s['zone'],
        'tls_applied' => $st['tls_applied'],
        'route' => $s['route'] + ['flags' => $s['route']['present'] ? uu_status_route_flags($routeOut) : []],
        'rules_loaded' => $loaded,
        'blocked' => $counts[uu_label_block()] ?? null,
        'checks' => $st['checks'],
        'members' => $members,
        'last_switch' => $st['last_switch'],
        'contract' => uu_contract($s['contract_input']),
        'next' => ['action' => $plan['action'], 'reasons' => $plan['reasons']],
    ];
}
