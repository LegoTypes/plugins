<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Status and logging (spec 2026-10-17 section 3.8): syslog lines, the blocked-packet line, durations and the status
 * document. Pure except uu_log() and uu_logger().
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/logline.php';
require_once __DIR__ . '/verdict.php';
require_once __DIR__ . '/choose.php';
require_once __DIR__ . '/contract.php';
require_once __DIR__ . '/render.php';

/**
 * Log from evaluate.php's own process as program UU_SYSLOG_IDENT at local4, which the plugin's syslog-ng filter
 * selects. Never from a hook: openlog() inside core's process would replace core's own syslog ident (uu_logger()).
 */
function uu_log(string $msg, int $prio = LOG_NOTICE): void
{
    static $open = false;
    if (!$open) {
        openlog(UU_SYSLOG_IDENT, LOG_PID, LOG_LOCAL4);
        $open = true;
    }
    syslog($prio, uu_log_text($msg));
}

/**
 * The log line for the counting table's blocked packets (its Out/Block count), or null when there is nothing new.
 * The table's counters survive filter reloads and reset only when the table is created again (the plugin disabled
 * and enabled, a boot), so a lower count starts again from then.
 */
function uu_blocked_line(?int $previous, ?int $now): ?string
{
    if ($now === null || $now === 0) {
        return null;
    }
    if ($previous === null || $now < $previous) {
        return sprintf('blocked %d resolver packets on a non-member path since the counting table was created',
            $now);
    }
    if ($now === $previous) {
        return null;
    }
    return sprintf(
        'blocked %d more resolver packets on a non-member path (%d since the counting table was created)',
        $now - $previous,
        $now
    );
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
 * A duration as text with its two largest units: "3 d 4 h", "11 h 22 min", "2 min 10 s", "59 s". The largest unit
 * is the largest that is not zero (a whole day is "1 d 0 h"); below a minute only seconds are shown.
 */
function uu_duration_text(int $seconds): string
{
    $seconds = max(0, $seconds);
    if ($seconds >= 86400) {
        return intdiv($seconds, 86400) . ' d ' . intdiv($seconds % 86400, 3600) . ' h';
    }
    if ($seconds >= 3600) {
        return intdiv($seconds, 3600) . ' h ' . intdiv($seconds % 3600, 60) . ' min';
    }
    if ($seconds >= 60) {
        return intdiv($seconds, 60) . ' min ' . ($seconds % 60) . ' s';
    }
    return $seconds . ' s';
}

/**
 * The status page's document (section 3.8). The mode, member and timers are the plan's view of now (recovered
 * from the live root and route when the state file was lost); next is what the next evaluation would do and why.
 *
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
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int, core_commands: list<string>},
 *     rules: array{state: string, problems: list<string>, verified_at: ?int,
 *         record: ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>}},
 *     block_table: array{table: ?array{addresses: int, references: int, out_block: int}, addresses: list<string>}} $s
 * @param array{action: string, candidates: list<string>, reassert: bool, route_repair: bool,
 *     escalate_restart: bool,
 *     state: array{version: int, mode: string, member: ?string,
 *         timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int,
 *         resolver_failed_until: ?int, probe_failures: int,
 *             last_down: ?array{at: int, reason: string}}>, control_failures: int,
 *         control_silent_since: ?int, last_switch: ?array{at: int, from: string, to: string, reason: string},
 *         checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *         member: string}}, tls_applied: ?bool, blocked: ?int,
 *         route_installed: ?array{kind: string, next_hop: string, if: string}, resolver: ?string},
 *     reasons: list<string>} $plan uu_plan() of the snapshot and the saved state
 * @param array{armed: bool, fill: bool, blocked: ?int} $blockTable uu_block_table_view() of the snapshot's
 *     block_table and the saved state's resolver
 * @param string $routeOut `route -n get -inet <resolver>`
 * @return array{enabled: bool, dry_run: bool, resolver: string, mode: string, member: ?string, tier: ?int,
 *     unbound: array{enabled: bool, running: bool, control_ok: bool}, live_root: ?list<string>,
 *     configured_root: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     tls_applied: ?bool,
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool, flags: list<string>},
 *     rules_loaded: bool, rules: array{state: string, problems: list<string>, verified_at: ?int},
 *     footprint: ?string, counter_armed: bool, blocked: ?int,
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *         member: string}},
 *     members: list<array{name: string, tier: int, kind: string, verdict: ?string, usable: bool,
 *         healthy_for: int, healthy_for_text: string, last_down: ?array{at: int, reason: string},
 *         resolver_failed_for: ?int, probe_failures: int}>,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     contract: array{ok: bool, failures: list<string>, notes: list<string>},
 *     next: array{action: string, reasons: list<string>}}
 */
function uu_status_doc(array $s, array $plan, array $blockTable, string $routeOut): array
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
            'healthy_for' => $timer['counted'],
            'healthy_for_text' => uu_duration_text($timer['counted']),
            'last_down' => $timer['last_down'],
            'resolver_failed_for' => $until !== null && $s['now'] < $until ? $until - $s['now'] : null,
            'probe_failures' => $timer['probe_failures'],
        ];
    }
    /* the address the footprint block is rendered for, as the render reads it: one the setting's rules do not
     * already cover */
    $setting = $s['settings']['enabled'] && $s['contract_input']['group_found'] ? $s['settings']['resolver'] : '';
    $footprint = uu_footprint_from_state($st, [], $setting)['footprint'];

    return [
        'enabled' => $s['settings']['enabled'],
        'dry_run' => $s['settings']['dry_run'],
        'resolver' => $s['settings']['resolver'],
        'mode' => $st['mode'],
        'member' => $st['member'],
        'tier' => $st['member'] === null ? null : ($tierOf[$st['member']] ?? null),
        'unbound' => ['enabled' => $s['unbound']['enabled'], 'running' => $s['unbound']['pid_alive'],
                      'control_ok' => $s['unbound']['control_ok']],
        'live_root' => $s['unbound']['live_root'],
        'configured_root' => $s['zone'],
        'tls_applied' => $st['tls_applied'],
        'route' => $s['route'] + ['flags' => $s['route']['present'] ? uu_status_route_flags($routeOut) : []],
        'rules_loaded' => $s['rules']['state'] === 'loaded',
        'rules' => ['state' => $s['rules']['state'], 'problems' => $s['rules']['problems'],
                    'verified_at' => $s['rules']['verified_at']],
        'footprint' => $footprint === null ? null : $footprint['resolver'],
        'counter_armed' => $blockTable['armed'],
        'blocked' => $blockTable['blocked'],
        'checks' => $st['checks'],
        'members' => $members,
        'last_switch' => $st['last_switch'],
        'contract' => uu_contract($s['contract_input']),
        'next' => ['action' => $plan['action'], 'reasons' => $plan['reasons']],
    ];
}
