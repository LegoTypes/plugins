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
 *
 * Status and logging: syslog lines, the blocked-packet line, durations and the status
 * document. Pure except uu_log() and uu_logger().
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/logline.php';
require_once __DIR__ . '/verdict.php';
require_once __DIR__ . '/choose.php';
require_once __DIR__ . '/contract.php';
require_once __DIR__ . '/planner.php';
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
 * The status's resolver: the active one. In tunnel mode the address Unbound's live root names (uu_plan_live_ours(),
 * over the planner's addresses and the state's map: none for Unbound's own configured root zone), else the current
 * member's resolver (the live root unknown, or not yet the member's); otherwise, and in tunnel mode with no member's to
 * name, the effective resolver of the first member in tier order that has one, else the Default, else ''. Canonical,
 * as `unbound-control forward` prints it, so Home Assistant's live_root == [resolver] holds; with one address it is the
 * Default in every mode.
 *
 * @param array{settings: array{default: string}, tiers: list<list<string>>,
 *     members: array<string, array{resolver: string}>,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>}} $s
 * @param array{state: array{mode: string, member: ?string, addresses: array<string, array{route: ?array{kind: string,
 *     next_hop: string, if: string}, forwarded: bool, released_at: ?int}>}} $plan uu_plan() of the snapshot
 */
function uu_status_active(array $s, array $plan): string
{
    $st = $plan['state'];
    $own = fn (string $name): string => uu_member_resolver($s, $name);
    if ($st['mode'] === 'tunnel') {
        $live = uu_plan_live_ours($s['unbound']['live_root'],
            array_merge(uu_plan_addresses($s), array_map('strval', array_keys($st['addresses']))), $s['zone']);
        $member = $st['member'] === null ? '' : $own($st['member']);
        if ($live !== null || $member !== '') {
            return $live ?? $member;
        }
    }
    foreach ($s['tiers'] as $tier) {
        foreach ($tier as $name) {
            if ($own($name) !== '') {
                return $own($name);
            }
        }
    }
    return uu_ip_canonical($s['settings']['default']) ?? '';
}

/**
 * The status page's document. The mode, member and timers are the plan's view of now (recovered
 * from the live root and route when the state file was lost); next is what the next evaluation would do and why.
 * With one address, the document without routes, addresses, fail_closed and each member's resolver is 1.3_2's status
 * key for key and value for value, so a poller such as Home Assistant reads it as it reads that one. route is the
 * active resolver's route; routes has each address of the state's map, and the active resolver when the map does not
 * hold it, with its route and whether the footprint block is rendered for it, and footprint is the first such address
 * in sorted order. A route's flags are the ones the snapshot's own read printed (route_flags), shown only for a present
 * route: the status runs no command of its own. The setting's addresses decide what is a footprint
 * (uu_setting_addresses(), as the render reads them). The contract is uu_contract()'s verdict: whether tunnel mode may
 * run, its failures and its notes, which name each member it excludes.
 *
 * @param array{now: int, wall: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, default: string,
 *         rows: array<string, string>, failback_delay: int, fail_closed: list<string>,
 *         fail_closed_networks: list<string>},
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
 *         core_paths: list<string>, unbound_conf: ?array{do_ip4: bool, do_ip6: bool, outgoing_interface: bool},
 *         group_family: string, mixed_family: bool, family_mismatch: list<string>},
 *     rules: array{state: string, problems: list<string>, verified_at: ?int,
 *         record: ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>}},
 *     block_table: array{table: ?array{addresses: int, references: int, out_block: int}, addresses: list<string>},
 *     view: array{loaded: string, view_zones: array<string, string>, notes: list<string>}} $s
 * @param array{action: string, candidates: list<string>, reassert: bool, route_repair: bool,
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
 *         view: array{refuse: string, scope: string, nets: list<string>, problem: ?string,
 *             restarted: ?string, unwritable: int}},
 *     reasons: list<string>, drain: list<string>} $plan uu_plan() of the snapshot and the saved state
 * @param array{armed: bool, fill: bool, blocked: ?int} $blockTable uu_block_table_view() of the snapshot's
 *     block_table and the setting's addresses
 * @return array{enabled: bool, dry_run: bool, resolver: string, mode: string, member: ?string, tier: ?int,
 *     unbound: array{enabled: bool, running: bool, control_ok: bool}, live_root: ?list<string>,
 *     configured_root: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     tls_applied: ?bool,
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool, flags: list<string>},
 *     routes: array<string, array{present: bool, gateway: string, interface: string, reject: bool, ours: bool,
 *         flags: list<string>, footprint: bool}>,
 *     rules_loaded: bool, rules: array{state: string, problems: list<string>, verified_at: ?int},
 *     footprint: ?string, addresses: list<string>, counter_armed: bool, blocked: ?int,
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *         member: string}},
 *     members: list<array{name: string, tier: int, resolver: string, kind: string, verdict: ?string, usable: bool,
 *         healthy_for: int, healthy_for_text: string, last_down: ?array{at: int, reason: string},
 *         resolver_failed_for: ?int, probe_failures: int}>,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     contract: array{ok: bool, failures: list<string>, notes: list<string>},
 *     next: array{action: string, reasons: list<string>},
 *     fail_closed: array{scope: string, interfaces: list<string>, networks: list<string>, nets: list<string>,
 *         refuse: string, problem: ?string, notes: list<string>, label: string}}
 */
function uu_status_doc(array $s, array $plan, array $blockTable): array
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
            'resolver' => $m === null ? '' : (uu_ip_canonical($m['resolver']) ?? ''),
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
    /* the addresses the footprint block is rendered for, as the render reads them: those the setting's rules do not
     * already cover */
    $footprints = array_column(uu_footprints_from_state($st, [], uu_setting_addresses($s))['footprints'], 'resolver');
    $routeOf = function (string $address) use ($s): array {
        $route = uu_plan_route($s, $address);
        return $route + ['flags' => $route['present'] ? ($s['route_flags'][$address] ?? []) : []];
    };
    $active = uu_status_active($s, $plan);
    $routed = uu_state_footprint($st);
    if ($active !== '' && !in_array($active, $routed, true)) {
        $routed[] = $active;
        sort($routed, SORT_STRING);
    }
    $routes = [];
    foreach ($routed as $address) {
        $routes[$address] = $routeOf($address) + ['footprint' => in_array($address, $footprints, true)];
    }
    $contract = uu_contract($s['contract_input']);

    return [
        'enabled' => $s['settings']['enabled'],
        'dry_run' => $s['settings']['dry_run'],
        'resolver' => $active,
        'mode' => $st['mode'],
        'member' => $st['member'],
        'tier' => $st['member'] === null ? null : ($tierOf[$st['member']] ?? null),
        'unbound' => ['enabled' => $s['unbound']['enabled'], 'running' => $s['unbound']['pid_alive'],
                      'control_ok' => $s['unbound']['control_ok']],
        'live_root' => $s['unbound']['live_root'],
        'configured_root' => $s['zone'],
        'tls_applied' => $st['tls_applied'],
        'route' => $routeOf($active),
        'routes' => $routes,
        'rules_loaded' => $s['rules']['state'] === 'loaded',
        'rules' => ['state' => $s['rules']['state'], 'problems' => $s['rules']['problems'],
                    'verified_at' => $s['rules']['verified_at']],
        'footprint' => $footprints[0] ?? null,
        'addresses' => uu_state_footprint($st),
        'counter_armed' => $blockTable['armed'],
        'blocked' => $blockTable['blocked'],
        'checks' => $st['checks'],
        'members' => $members,
        'last_switch' => $st['last_switch'],
        'contract' => ['ok' => $contract['ok'], 'failures' => $contract['failures'], 'notes' => $contract['notes']],
        'next' => ['action' => $plan['action'], 'reasons' => $plan['reasons']],
        'fail_closed' => uu_status_fail_closed($s, $st['view']),
    ];
}

/**
 * The status document's fail_closed: the state's record with the live refuse, the settings' selection, the notes
 * (the snapshot's, then a view whose zones Unbound answered in no known shape, then the records the view file could
 * not carry, which the reconcile copies into the view), and the label the page shows as it is
 * (uu_status_fail_closed_label()).
 *
 * @param array{settings: array{fail_closed: list<string>, fail_closed_networks: list<string>},
 *     view: array{loaded: string, view_zones: array<string, string>, notes: list<string>}} $s
 * @param array{refuse: string, scope: string, nets: list<string>, problem: ?string,
 *     restarted: ?string, unwritable: int} $view
 * @return array{scope: string, interfaces: list<string>, networks: list<string>, nets: list<string>,
 *     refuse: string, problem: ?string, notes: list<string>, label: string}
 */
function uu_status_fail_closed(array $s, array $view): array
{
    $notes = $s['view']['notes'];
    if ($s['view']['loaded'] === 'unreadable') {
        $notes[] = "Unbound's list of the view's zones could not be read";
    }
    if ($view['unwritable'] > 0) {
        $notes[] = $view['unwritable'] . ' local record(s) are not written into the view file; the next evaluation '
            . 'copies them into the view';
    }
    $fc = [
        'scope' => $view['scope'],
        'interfaces' => $s['settings']['fail_closed'],
        'networks' => $s['settings']['fail_closed_networks'],
        'nets' => $view['nets'],
        'refuse' => uu_status_refuse($s['view'], $view['refuse']),
        'problem' => $view['problem'],
        'notes' => $notes,
    ];
    return $fc + ['label' => uu_status_fail_closed_label($fc)];
}

/**
 * What the page's "Fail closed" row reads: off for no set; else the refused nets (every client, or "no net yet"
 * for a selection without one), then the state, then each note. A problem outranks the refuse: "Fail closed stuck: "
 * reads stuck, "Fail closed not armed: " not armed, any other view fault is shown as a fault; with no problem the
 * state is armed, lifted, or not loaded (no view loaded: Unbound down, or its start still to come).
 *
 * @param array{scope: string, nets: list<string>, refuse: string, problem: ?string, notes: list<string>} $fc
 */
function uu_status_fail_closed_label(array $fc): string
{
    if ($fc['scope'] === 'none') {
        return 'off';
    }
    $set = $fc['scope'] === 'all' ? 'every client' : ($fc['nets'] === [] ? 'no net yet' : implode(', ', $fc['nets']));
    if ($fc['problem'] === null) {
        $state = match ($fc['refuse']) {
            'armed' => 'armed',
            'none' => 'not loaded',
            default => 'lifted',
        };
    } elseif (preg_match('/^Fail closed( stuck| not armed)?: (.*)$/s', $fc['problem'], $m) === 1) {
        $state = ($m[1] === '' ? 'fault' : ltrim($m[1])) . ': ' . $m[2];
    } else {
        $state = 'fault: ' . $fc['problem'];
    }
    return implode('; ', array_merge(["$set: $state"], $fc['notes']));
}

/**
 * The view's refuse for status: the live read when the plugin's view is loaded (the refuse of "." in its zones),
 * else the state's record, which is all status knows while Unbound is down or does not answer.
 *
 * @param array{loaded: string, view_zones: array<string, string>} $view
 * @param string $recorded the state's refuse: armed, lifted or none
 */
function uu_status_refuse(array $view, string $recorded): string
{
    if ($view['loaded'] !== 'zones') {
        return $recorded;
    }
    return ($view['view_zones']['.'] ?? null) === 'refuse' ? 'armed' : ($recorded === 'none' ? 'none' : 'lifted');
}
