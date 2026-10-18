<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Apply order and failure handling with a recording Io (spec sections 3.4, 3.5, 3.7, 3.10 and the section 5
 * planner list). Plans come from the real planner, so each case also pins the planner input it depends on.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/apply.php';
require_once __DIR__ . '/test_planner.php';

/**
 * The planner's test snapshot with Unbound's live root as Unbound prints it: bare addresses, its own order.
 *
 * @return array{now: int,
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
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int}}
 */
function uu_test_apply_snapshot(): array
{
    $s = uu_test_snapshot();
    $s['unbound']['live_root'] = ['2001:db8::53', '192.0.2.53'];
    return $s;
}

/**
 * A recording Io over a fake kernel and Unbound that follow the calls. The device the last route call chose
 * decides the direct probe's result ('reject' for the reject route); forward_add and forward_remove set what
 * `forward` prints, bare and in reverse order, as Unbound prints its own order. Every call is also appended to
 * $all after a "-- case" marker, so the never-planned assertion sees every case and where each starts.
 *
 * @param array{now: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, failback_delay: int,
 *         probe_name: string},
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool}} $s
 * @param ArrayObject<int, string> $all
 * @param array{direct?: array<string, list<bool>>, unbound?: list<bool>, uc_fail?: list<string>,
 *     forward_out?: string, route_fail?: list<string>, restart?: bool, silent?: bool,
 *     restart_live?: list<string>, throw_on?: string} $o
 *   direct: per device, successive direct probe results (true when absent or used up); unbound: successive
 *   through-Unbound results (true when used up); uc_fail and route_fail: commands or verbs that fail once each,
 *   in order; forward_out: what `forward` prints instead of the fake's live root; silent: every unbound-control
 *   call times out (null) until a restart that sets restart_live as the live root; throw_on: the Io function
 *   that throws, after recording its call
 * @return array{io: array{route: callable(string, list<string>): bool, sleep_ms: callable(int): void,
 *     probe_direct: callable(string, string): bool, probe_unbound: callable(string): bool,
 *     uc: callable(list<string>): ?string, restart_unbound: callable(): bool, log: callable(string, int): void,
 *     save: callable(array): void},
 *     calls: ArrayObject<int, string>,
 *     saved: ArrayObject<string, array{route_installed: ?array{kind: string, next_hop: string, if: string}}>}
 *   saved holds the state the last save received under 'state'; saves are not in calls
 */
function uu_test_io(array $s, ArrayObject $all, array $o = []): array
{
    $calls = new ArrayObject();
    $all[] = '-- case';
    $record = function (string $call) use ($calls, $all): void {
        $calls[] = $call;
        $all[] = $call;
    };
    $route = $s['route'];
    $dev = new ArrayObject(['dev' => $route['present'] ? ($route['reject'] ? 'reject' : $route['interface']) : 'none']);
    $live = new ArrayObject(['live' => $s['unbound']['live_root']]);
    $direct = new ArrayObject($o['direct'] ?? []);
    $unbound = new ArrayObject($o['unbound'] ?? []);
    $ucFail = new ArrayObject($o['uc_fail'] ?? []);
    $routeFail = new ArrayObject($o['route_fail'] ?? []);
    $silent = new ArrayObject(['silent' => $o['silent'] ?? false]);
    $saved = new ArrayObject();
    $throwOn = $o['throw_on'] ?? '';
    $maybeThrow = function (string $fn) use ($throwOn): void {
        if ($fn === $throwOn) {
            throw new RuntimeException("test: $fn throws");
        }
    };
    $failOnce = function (ArrayObject $queue, string $what): bool {
        $list = $queue->getArrayCopy();
        $at = array_search($what, $list, true);
        if ($at === false) {
            return false;
        }
        unset($list[$at]);
        $queue->exchangeArray(array_values($list));
        return true;
    };
    $io = [
        'route' => function (string $verb, array $args) use ($record, $dev, $routeFail, $failOnce, $maybeThrow): bool {
            $record(trim("route $verb " . implode(' ', $args)));
            $maybeThrow('route');
            if ($failOnce($routeFail, $verb)) {
                return false;
            }
            if ($verb === 'delete') {
                $dev['dev'] = 'none';
            } elseif (in_array('-reject', $args, true)) {
                $dev['dev'] = 'reject';
            } else {
                $at = array_search('-ifp', $args, true);
                $dev['dev'] = $at === false ? 'unknown' : (string)($args[$at + 1] ?? 'unknown');
            }
            return true;
        },
        'sleep_ms' => function (int $ms) use ($record): void {
            $record("sleep $ms");
        },
        'probe_direct' => function (string $resolver, string $name) use ($record, $dev, $direct, $maybeThrow): bool {
            $record("probe_direct $resolver $name");
            $maybeThrow('probe_direct');
            $results = $direct[$dev['dev']] ?? [];
            if ($results === []) {
                return true;
            }
            $ok = (bool)array_shift($results);
            $direct[$dev['dev']] = $results;
            return $ok;
        },
        'probe_unbound' => function (string $name) use ($record, $unbound): bool {
            $record("probe_unbound $name");
            $results = $unbound->getArrayCopy();
            if ($results === []) {
                return true;
            }
            $ok = (bool)array_shift($results);
            $unbound->exchangeArray($results);
            return $ok;
        },
        'uc' => function (array $args) use ($record, $live, $ucFail, $failOnce, $o, $silent, $maybeThrow): ?string {
            $record('uc ' . implode(' ', $args));
            $maybeThrow('uc');
            if ($silent['silent']) {
                return null;
            }
            $cmd = (string)($args[0] ?? '');
            if ($failOnce($ucFail, $cmd)) {
                return 'error failed';
            }
            if ($cmd === 'forward') {
                if (isset($o['forward_out'])) {
                    return $o['forward_out'];
                }
                $now = $live['live'];
                return $now === null ? null : ($now === [] ? "off (using root hints)\n" : implode(' ', array_reverse($now)) . "\n");
            }
            if ($cmd === 'forward_add') {
                $dot = (int)array_search('.', $args, true);
                $live['live'] = array_values(array_map(fn (string $a): string => (string)preg_replace('/[@#].*$/', '', $a),
                    array_slice($args, $dot + 1)));
            } elseif ($cmd === 'forward_remove') {
                $live['live'] = [];
            }
            return "ok\n";
        },
        'restart_unbound' => function () use ($record, $o, $silent, $live): bool {
            $record('restart');
            if (isset($o['restart_live'])) {
                $silent['silent'] = false;
                $live['live'] = $o['restart_live'];
            }
            return $o['restart'] ?? true;
        },
        'log' => function (string $msg, int $prio) use ($record): void {
            $record("log $prio $msg");
        },
        'save' => function (array $state) use ($saved): void {
            $saved['state'] = $state;
        },
    ];
    return ['io' => $io, 'calls' => $calls, 'saved' => $saved];
}

/**
 * The recorded calls other than log lines.
 *
 * @param ArrayObject<int, string> $calls
 * @return list<string>
 */
function uu_test_acts(ArrayObject $calls): array
{
    return array_values(array_filter($calls->getArrayCopy(), fn (string $c): bool => !str_starts_with($c, 'log ')));
}

/**
 * Whether a log line at that priority contains every needle.
 *
 * @param ArrayObject<int, string> $calls
 */
function uu_test_logged(ArrayObject $calls, int $prio, string ...$needles): bool
{
    foreach ($calls as $call) {
        if (!str_starts_with($call, "log $prio ")) {
            continue;
        }
        $all = true;
        foreach ($needles as $needle) {
            $all = $all && str_contains($call, $needle);
        }
        if ($all) {
            return true;
        }
    }
    return false;
}

uu_register_suite('apply', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $all = new ArrayObject();
    $now = 10000;
    $usable = ['wg-a' => uu_test_timer(500, null, $now - 60), 'wg-b' => uu_test_timer(500, null, $now - 60)];
    $wait = 'sleep ' . (1000 + UU_FIB_SYNC_MARGIN_MS);
    $toWgA = 'route add -host 10.2.0.1 10.2.0.2 -ifp wg1';
    $changeToWgA = 'route change -host 10.2.0.1 10.2.0.2 -ifp wg1';
    $changeToWgB = 'route change -host 10.2.0.1 10.2.0.6 -ifp wg2';
    $probe = 'probe_direct 10.2.0.1 .';
    $through = ['uc flush_type . SOA', 'probe_unbound .'];
    $toResolver = 'uc forward_add . 10.2.0.1';
    $restoreDot = 'uc forward_add +t . 192.0.2.53@853#dns.example 2001:db8::53@853#dns.example';
    $reject = 'route change -host 10.2.0.1 127.0.0.1 -reject';
    $flushReq = 'uc flush_requestlist';
    $drain = 'sleep ' . (1000 + UU_FIB_SYNC_MARGIN_MS + UU_STOP_DRAIN_SECONDS * 1000);
    $settledDown = uu_test_probe('down', '100.0 %', 300);
    $before = time();

    // Entering tunnel mode from fallback.
    $s = uu_test_apply_snapshot();
    $p = uu_plan($s, uu_test_plan_state(null, $usable));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'entering: route, then sleep ≥ fib_sync+500, then probe — in that order',
        $p['action'] === 'tunnel' && $p['candidates'] === ['wg-a', 'wg-b']
        && uu_test_acts($r['calls']) === array_merge([$toWgA, $wait, $probe, $toResolver, 'uc flush_infra 10.2.0.1',
            'uc forward'], $through));
    uu_check($t, 'entering: state tunnel on wg-a, switch recorded with wall time, TLS flag off, checks recorded',
        $st['mode'] === 'tunnel' && $st['member'] === 'wg-a' && $st['tls_applied'] === false
        && $st['last_switch'] !== null && $st['last_switch']['from'] === 'fallback'
        && $st['last_switch']['to'] === 'wg-a' && $st['last_switch']['at'] >= $before
        && str_contains($st['last_switch']['reason'], 'enter tunnel via wg-a')
        && $st['checks']['direct'] !== null && $st['checks']['direct']['ok'] && $st['checks']['direct']['member'] === 'wg-a'
        && $st['checks']['unbound'] !== null && $st['checks']['unbound']['ok']
        && $st['timers']['wg-a']['probe_failures'] === 0
        && uu_test_logged($r['calls'], LOG_NOTICE, 'fallback', 'wg-a'));

    // Changing member: the live root is already the resolver.
    $s = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $s['members']['wg-a']['force_down'] = true;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'member change: route change, sleep, probe, flush_infra; no forward_add',
        $p['action'] === 'tunnel' && $p['candidates'] === ['wg-b']
        && uu_test_acts($r['calls']) === array_merge([$changeToWgB, $wait, $probe, 'uc flush_infra 10.2.0.1',
            'uc forward'], $through)
        && $st['mode'] === 'tunnel' && $st['member'] === 'wg-b' && $st['last_switch'] !== null
        && $st['last_switch']['from'] === 'wg-a' && $st['last_switch']['to'] === 'wg-b');

    // A candidate whose resolver fails the direct probe.
    $s = uu_test_apply_snapshot();
    $p = uu_plan($s, uu_test_plan_state(null, $usable));
    $r = uu_test_io($s, $all, ['direct' => ['wg1' => [false]]]);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'probe fails on wg-a, passes on wg-b → wg-b, wg-a marked failed',
        uu_test_acts($r['calls']) === array_merge([$toWgA, $wait, $probe, $changeToWgB, $wait, $probe, $toResolver,
            'uc flush_infra 10.2.0.1', 'uc forward'], $through)
        && $st['mode'] === 'tunnel' && $st['member'] === 'wg-b'
        && $st['timers']['wg-a']['resolver_failed_until'] === $now + 120
        && $st['timers']['wg-b']['resolver_failed_until'] === null
        && uu_test_logged($r['calls'], LOG_WARNING, 'wg-a', 'direct probe'));

    // Every candidate fails: fallback in the same evaluation.
    $s = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $s['probes']['wg-a'] = $settledDown;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($s, $all, ['direct' => ['wg2' => [false]]]);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'all probes fail → fallback: forward_add +t with the parsed addresses, then reject route',
        $p['action'] === 'tunnel' && $p['candidates'] === ['wg-b']
        && uu_test_acts($r['calls']) === [$changeToWgB, $wait, $probe, $restoreDot, 'uc forward', $reject]
        && $st['mode'] === 'fallback' && $st['member'] === null && $st['tls_applied'] === true
        && $st['timers']['wg-b']['resolver_failed_until'] === $now + 120
        && $st['last_switch'] !== null && $st['last_switch']['from'] === 'wg-a'
        && $st['last_switch']['to'] === 'fallback'
        && uu_test_logged($r['calls'], LOG_NOTICE, '+t'));

    $s = uu_test_apply_snapshot();
    $p = uu_plan($s, uu_test_plan_state(null, $usable));
    $r = uu_test_io($s, $all, ['direct' => ['wg1' => [false], 'wg2' => [false]]]);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'from fallback, every probe fails → the route goes back to reject; no forward_add, no switch',
        uu_test_acts($r['calls']) === [$toWgA, $wait, $probe, $changeToWgB, $wait, $probe, $reject]
        && $st['mode'] === 'fallback' && $st['member'] === null && $st['last_switch'] === null
        && $st['timers']['wg-a']['resolver_failed_until'] === $now + 120
        && $st['timers']['wg-b']['resolver_failed_until'] === $now + 120);

    // Route verbs.
    $s = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $s['members']['wg-a']['force_down'] = true;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($s, $all, ['route_fail' => ['change']]);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'route present → change, absent → add; never delete then add',
        uu_test_acts($r['calls'])[0] === $changeToWgB
        && uu_test_acts($r['calls'])[1] === 'route add -host 10.2.0.1 10.2.0.6 -ifp wg2'
        && uu_test_acts($r['calls'])[2] === $wait && $st['member'] === 'wg-b');

    // Stop.
    $s = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $s['settings']['enabled'] = false;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'stop with live root the resolver → forward_add +t then route delete; never a restart',
        $p['action'] === 'stop'
        && uu_test_acts($r['calls']) === [$restoreDot, 'uc forward', $reject, $flushReq, $drain, 'route delete -host 10.2.0.1']
        && $st['mode'] === 'fallback' && $st['member'] === null && $st['last_switch'] !== null
        && $st['last_switch']['to'] === 'fallback');
    uu_check($t, 'stop drains: restore, reject route, flush_requestlist, then fib_sync + 500 ms + UU_STOP_DRAIN_SECONDS (2500 ms), then delete',
        UU_STOP_DRAIN_SECONDS === 1 && $drain === 'sleep 2500');

    $r = uu_test_io($s, $all, ['uc_fail' => ['flush_requestlist']]);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'stop whose flush_requestlist fails → the reject route stays (a retry would leave by a WAN), recorded, logged',
        uu_test_acts($r['calls']) === [$restoreDot, 'uc forward', $reject, $flushReq]
        && $st['mode'] === 'fallback' && $st['route_installed'] === ['kind' => 'reject', 'next_hop' => '', 'if' => 'lo0']
        && uu_test_logged($r['calls'], LOG_ERR, 'flush_requestlist failed'));
    $r = uu_test_io($s, $all, ['route_fail' => ['change', 'add']]);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'stop whose reject route fails → the member route stays, never deleted, logged',
        uu_test_acts($r['calls']) === [$restoreDot, 'uc forward', $reject, 'route add -host 10.2.0.1 127.0.0.1 -reject']
        && uu_test_logged($r['calls'], LOG_ERR, 'no reject route'));

    $s = uu_test_apply_snapshot();
    $s['settings']['enabled'] = false;
    $p = uu_plan($s, uu_test_plan_state(null));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'stop with nothing of the plugin\'s live → no calls at all, not even a log line',
        $p['action'] === 'stop' && $r['calls']->getArrayCopy() === [] && $st === $p['state']);

    $s = uu_test_apply_snapshot();
    $s['settings']['enabled'] = false;
    $s['route'] = ['present' => true, 'gateway' => '', 'interface' => 'lo0', 'reject' => true, 'ours' => true];
    $p = uu_plan($s, uu_test_plan_state(null));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'stop in fallback → flush_requestlist (a recent fallback leaves retries), drain, our reject route deleted; forwarders untouched',
        uu_test_acts($r['calls']) === [$flushReq, $drain, 'route delete -host 10.2.0.1'] && $st['mode'] === 'fallback');

    $s = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $s['unbound'] = ['enabled' => true, 'pid_alive' => false, 'control_ok' => false, 'live_root' => null];
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'Unbound not running in tunnel mode → route deleted, no unbound-control call, fallback',
        $p['action'] === 'stop' && uu_test_acts($r['calls']) === ['route delete -host 10.2.0.1']
        && $st['mode'] === 'fallback' && $st['member'] === null
        && uu_test_logged($r['calls'], LOG_NOTICE, 'Unbound not running'));

    $s = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $s['settings']['enabled'] = false;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($s, $all, ['uc_fail' => ['forward_add']]);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'stop whose restore fails → the route stays (deleting it would send queries out a WAN), still tunnel',
        uu_test_acts($r['calls']) === [$restoreDot] && $st['mode'] === 'tunnel' && $st['member'] === 'wg-a'
        && uu_test_logged($r['calls'], LOG_ERR, 'route'));

    // Dry run.
    $s = uu_test_apply_snapshot();
    $s['settings']['dry_run'] = true;
    $p = uu_plan($s, uu_test_plan_state(null, $usable));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    $logs = $r['calls']->getArrayCopy();
    $dryOnly = $logs !== [];
    foreach ($logs as $call) {
        $dryOnly = $dryOnly && str_starts_with($call, 'log ') && str_contains($call, '[dry]');
    }
    uu_check($t, 'dry run → only log calls',
        $p['action'] === 'tunnel' && $dryOnly && $st === $p['state']
        && uu_test_logged($r['calls'], LOG_NOTICE, '[dry]', 'route -n add -host 10.2.0.1 10.2.0.2 -ifp wg1')
        && uu_test_logged($r['calls'], LOG_NOTICE, '[dry]', 'forward_add . 10.2.0.1'));

    $s = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $s['settings']['dry_run'] = true;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'dry run turned on in tunnel mode → the plugin\'s live changes are undone for real (stop)',
        uu_test_acts($r['calls']) === [$restoreDot, 'uc forward', $reject, $flushReq, $drain, 'route delete -host 10.2.0.1']
        && $st['mode'] === 'fallback' && uu_test_logged($r['calls'], LOG_NOTICE, 'dry run'));

    // Carry-forward obligations.
    $s = uu_test_apply_snapshot();
    $s['unbound']['live_root'] = ['10.2.0.1'];
    $p = uu_plan($s, uu_test_plan_state(null, $usable));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'tunnel entry with the live root already the resolver (state lost) → no forward_add',
        $p['action'] === 'tunnel' && $p['state']['mode'] === 'tunnel' && $p['state']['member'] === null
        && uu_test_acts($r['calls']) === array_merge([$toWgA, $wait, $probe, 'uc flush_infra 10.2.0.1', 'uc forward'],
            $through)
        && $st['mode'] === 'tunnel' && $st['member'] === 'wg-a' && $st['last_switch'] !== null
        && $st['last_switch']['from'] === 'tunnel' && $st['tls_applied'] === null);

    $s = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $s['route'] = ['present' => true, 'gateway' => '192.0.2.99', 'interface' => 'igc0', 'reject' => false,
                   'ours' => false];
    $s['contract_input']['foreign_route'] = true;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'fallback with a foreign route → forwarders restored, no reject route over it',
        $p['action'] === 'fallback' && uu_test_acts($r['calls']) === [$restoreDot, 'uc forward']
        && $st['mode'] === 'fallback' && uu_test_logged($r['calls'], LOG_WARNING, 'not ours'));

    $s = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $s['probes']['wg-a'] = $settledDown;
    $s['probes']['wg-b'] = $settledDown;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($s, $all, ['forward_out' => "2001:db8::53 192.0.2.53 2001:db8::53\n"]);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'confirm compares sets of bare addresses: another order, no @port#name, a repeat → confirmed',
        $p['action'] === 'fallback' && uu_test_acts($r['calls']) === [$restoreDot, 'uc forward', $reject]
        && $st['mode'] === 'fallback');
    $r = uu_test_io($s, $all, ['forward_out' => "198.51.100.9\n"]);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'confirm mismatch → no reject route (it would black-hole every query), still tunnel, logged',
        uu_test_acts($r['calls']) === [$restoreDot, 'uc forward'] && $st['mode'] === 'tunnel'
        && $st['member'] === 'wg-a' && uu_test_logged($r['calls'], LOG_ERR, '198.51.100.9'));
    $r = uu_test_io($s, $all, ['uc_fail' => ['forward_add']]);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'restore refused by Unbound → no reject route, still tunnel, logged as an error',
        uu_test_acts($r['calls']) === [$restoreDot] && $st['mode'] === 'tunnel'
        && uu_test_logged($r['calls'], LOG_ERR, 'forward_add'));

    $s = uu_test_apply_snapshot();
    $s['contract_input']['unbound_sorts_first'] = false;
    $p = uu_plan($s, uu_test_plan_state(null, $usable));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'the action decides, not the candidates: a contract failure in fallback with candidates → only the reject route',
        $p['action'] === 'none' && $p['candidates'] !== [] && $p['route_repair']
        && uu_test_acts($r['calls']) === ['route add -host 10.2.0.1 127.0.0.1 -reject'] && $st['mode'] === 'fallback');

    $s = uu_test_apply_snapshot();
    $p = uu_plan($s, uu_test_plan_state(null, $usable));
    $r = uu_test_io($s, $all, ['uc_fail' => ['forward_add']]);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'entry forward_add refused → no other candidate, fallback restores (the add may have landed), reject',
        uu_test_acts($r['calls']) === [$toWgA, $wait, $probe, $toResolver, $restoreDot, 'uc forward',
            'route change -host 10.2.0.1 127.0.0.1 -reject']
        && $st['mode'] === 'fallback' && $st['timers']['wg-a']['resolver_failed_until'] === null);

    // The route the plugin installed (ruling R22): recognised by the state's record when no member matches.
    $memberRecord = ['kind' => 'member', 'next_hop' => '10.2.0.2', 'if' => 'wg1'];
    $rejectRecord = ['kind' => 'reject', 'next_hop' => '', 'if' => 'lo0'];
    $s = uu_test_apply_snapshot();
    $p = uu_plan($s, uu_test_plan_state(null, $usable));
    $st = uu_apply($p, $s, uu_test_io($s, $all)['io']);
    uu_check($t, 'a route add or change via a member is recorded in the state', $st['route_installed'] === $memberRecord);
    $s = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $s['probes']['wg-a'] = $settledDown;
    $s['probes']['wg-b'] = $settledDown;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $st = uu_apply($p, $s, uu_test_io($s, $all)['io']);
    uu_check($t, 'the reject route is recorded as kind reject on lo0', $st['route_installed'] === $rejectRecord);
    $s = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $s['settings']['enabled'] = false;
    $recorded = uu_test_plan_state('wg-a', $usable);
    $recorded['route_installed'] = $memberRecord;
    $p = uu_plan($s, $recorded);
    $st = uu_apply($p, $s, uu_test_io($s, $all)['io']);
    uu_check($t, 'a successful route delete clears the record', $st['route_installed'] === null);
    $r = uu_test_io($s, $all, ['route_fail' => ['delete']]);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'a failed route delete keeps the record (of the reject route the drain put in place)',
        $st['route_installed'] === $rejectRecord);

    $gone = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $gone['tiers'] = [];
    $gone['members'] = [];
    $gone['probes'] = [];
    $gone['route']['ours'] = false;
    $gone['contract_input']['group_found'] = false;
    $gone['contract_input']['members'] = 0;
    $gone['contract_input']['foreign_route'] = true;
    $adopted = uu_route_adopt($gone, $memberRecord);
    uu_check($t, 'a live route equal to the recorded one is ours, and no longer a foreign-route contract failure',
        $adopted['route']['ours'] && !$adopted['contract_input']['foreign_route']
        && uu_route_adopt($gone, null) === $gone);
    $p = uu_plan($adopted, $recorded);
    $r = uu_test_io($adopted, $all);
    $st = uu_apply($p, $adopted, $r['io']);
    uu_check($t, 'group deleted in tunnel mode with our recorded route → fallback replaces it with the reject route',
        $p['action'] === 'fallback' && uu_test_acts($r['calls']) === [$restoreDot, 'uc forward', $reject]
        && $st['mode'] === 'fallback' && $st['route_installed'] === $rejectRecord);
    $off = $adopted;
    $off['settings']['enabled'] = false;
    $p = uu_plan($off, $recorded);
    $r = uu_test_io($off, $all);
    $st = uu_apply($p, $off, $r['io']);
    uu_check($t, 'group deleted in tunnel mode, then stop → our recorded route deleted',
        $p['action'] === 'stop'
        && uu_test_acts($r['calls']) === [$restoreDot, 'uc forward', $reject, $flushReq, $drain, 'route delete -host 10.2.0.1']
        && $st['mode'] === 'fallback' && $st['route_installed'] === null);

    $other = $memberRecord;
    $other['next_hop'] = '10.2.0.9';
    $foreign = uu_route_adopt($gone, $other);
    $p = uu_plan($foreign, $recorded);
    $r = uu_test_io($foreign, $all);
    $st = uu_apply($p, $foreign, $r['io']);
    uu_check($t, 'a route matching neither the record nor a member stays foreign and untouched',
        $foreign === $gone && $p['action'] === 'fallback' && uu_test_acts($r['calls']) === [$restoreDot, 'uc forward']
        && $st['route_installed'] === $memberRecord);
    $off = $foreign;
    $off['settings']['enabled'] = false;
    $p = uu_plan($off, $recorded);
    $r = uu_test_io($off, $all);
    uu_apply($p, $off, $r['io']);
    uu_check($t, 'stop never deletes that foreign route',
        $p['action'] === 'stop' && uu_test_acts($r['calls']) === [$restoreDot, 'uc forward']);
    $rejectLive = $gone;
    $rejectLive['route'] = ['present' => true, 'gateway' => '', 'interface' => 'lo0', 'reject' => true,
                            'ours' => false];
    uu_check($t, 'a member route is not adopted by a reject record, nor a reject route by a member record',
        uu_route_adopt($gone, $rejectRecord) === $gone && uu_route_adopt($rejectLive, $memberRecord) === $rejectLive
        && uu_route_adopt($rejectLive, $rejectRecord)['route']['ours']);
    $absent = $gone;
    $absent['route'] = ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false, 'ours' => false];
    uu_check($t, 'no live route: nothing to adopt', uu_route_adopt($absent, $memberRecord) === $absent);

    // Per-evaluation checks while staying on wg-a.
    $s = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'staying: direct and through-Unbound checks, no sleep without a route change, nothing else',
        $p['action'] === 'none' && !$p['reassert'] && !$p['route_repair']
        && uu_test_acts($r['calls']) === array_merge([$probe], $through)
        && $st['member'] === 'wg-a' && $st['last_switch'] === null && $st['timers']['wg-a']['probe_failures'] === 0
        && $st['checks']['unbound'] !== null && $st['checks']['unbound']['ok']);

    $r = uu_test_io($s, $all, ['unbound' => [false, true]]);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'direct passes, through-Unbound fails → flush_infra, recheck passes, no failure counted',
        uu_test_acts($r['calls']) === array_merge([$probe], $through, ['uc flush_infra 10.2.0.1'], $through)
        && $st['member'] === 'wg-a' && $st['timers']['wg-a']['probe_failures'] === 0);

    $r = uu_test_io($s, $all, ['unbound' => [false, false]]);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'through-Unbound fails again after flush_infra → one failure, no member change',
        uu_test_acts($r['calls']) === array_merge([$probe], $through, ['uc flush_infra 10.2.0.1'], $through)
        && $st['member'] === 'wg-a' && $st['timers']['wg-a']['probe_failures'] === 1
        && $st['checks']['unbound'] !== null && !$st['checks']['unbound']['ok']
        && uu_test_logged($r['calls'], LOG_WARNING, 'wg-a', '1 of 2'));

    $once = $usable;
    $once['wg-a']['probe_failures'] = 1;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $once));
    $r = uu_test_io($s, $all, ['direct' => ['wg1' => [false]]]);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'direct fails a second time on wg-a → wg-a resolver-failed, wg-b in the same evaluation',
        $p['candidates'] === ['wg-a', 'wg-b']
        && uu_test_acts($r['calls']) === array_merge([$probe, $changeToWgB, $wait, $probe, 'uc flush_infra 10.2.0.1',
            'uc forward'], $through)
        && $st['member'] === 'wg-b' && $st['timers']['wg-a']['resolver_failed_until'] === $now + 120
        && $st['timers']['wg-a']['probe_failures'] === 0 && $st['checks']['direct'] !== null
        && $st['checks']['direct']['member'] === 'wg-b');

    $s2 = $s;
    $s2['probes']['wg-b'] = $settledDown;
    $p = uu_plan($s2, uu_test_plan_state('wg-a', $once));
    $r = uu_test_io($s2, $all, ['direct' => ['wg1' => [false]]]);
    $st = uu_apply($p, $s2, $r['io']);
    uu_check($t, 'direct fails a second time on wg-a with no other candidate → fallback',
        $p['candidates'] === ['wg-a'] && uu_test_acts($r['calls']) === [$probe, $restoreDot, 'uc forward', $reject]
        && $st['mode'] === 'fallback' && $st['timers']['wg-a']['resolver_failed_until'] === $now + 120);

    // Reconcile.
    $s = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $s['unbound']['live_root'] = ['192.0.2.53', '2001:db8::53'];
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'tunnel mode, Unbound restarted on its configured root → reassert, then the checks',
        $p['reassert'] && !$p['route_repair']
        && uu_test_acts($r['calls']) === array_merge([$toResolver, 'uc flush_infra 10.2.0.1', 'uc forward', $probe],
            $through)
        && $st['member'] === 'wg-a' && $st['last_switch'] === null && $st['tls_applied'] === false);

    $s = uu_test_apply_snapshot();
    $s['unbound']['live_root'] = ['10.2.0.1'];
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'tunnel mode, route gone (wireguard restart) → route add via wg-a, sleep, then the checks',
        $p['route_repair'] && uu_test_acts($r['calls']) === array_merge([$toWgA, $wait, $probe], $through)
        && $st['member'] === 'wg-a');

    $s = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $s['route']['reject'] = true;
    $s['route']['interface'] = 'lo0';
    $s['route']['gateway'] = '';
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'tunnel mode, our reject route in place → route change to wg-a, never delete and add',
        $p['route_repair'] && uu_test_acts($r['calls']) === array_merge([$changeToWgA, $wait, $probe], $through));

    $s = uu_test_apply_snapshot();
    $p = uu_plan($s, uu_test_plan_state(null));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'fallback, no candidate, route absent → reject route added, nothing else',
        $p['action'] === 'none' && uu_test_acts($r['calls']) === ['route add -host 10.2.0.1 127.0.0.1 -reject']
        && $st['mode'] === 'fallback');

    // Root-zone shapes.
    $s = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $s['probes']['wg-a'] = $settledDown;
    $s['probes']['wg-b'] = $settledDown;
    $s['zone'] = ['shape' => 'none', 'addrs' => [], 'tls' => false, 'problems' => []];
    $s['contract_input']['zone'] = $s['zone'];
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'no . zone configured → forward_remove ., confirmed by "off (using root hints)", reject route',
        $p['action'] === 'fallback' && uu_test_acts($r['calls']) === ['uc forward_remove .', 'uc forward', $reject]
        && $st['mode'] === 'fallback' && $st['tls_applied'] === false);

    $s['zone'] = uu_root_zone([uu_test_fixture('dot_plain.conf')]);
    $s['contract_input']['zone'] = $s['zone'];
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'configured root without TLS → forward_add without +t',
        uu_test_acts($r['calls']) === ['uc forward_add . 198.51.100.53@53 203.0.113.53', 'uc forward', $reject]
        && $st['tls_applied'] === false && uu_test_logged($r['calls'], LOG_NOTICE, 'without +t'));

    $s['zone'] = ['shape' => 'unrestorable', 'addrs' => ['192.0.2.53'], 'tls' => false,
                  'problems' => ['forward-first']];
    $s['contract_input']['zone'] = $s['zone'];
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'an unrestorable configured zone is never re-added: no call, still tunnel, logged as an error',
        $p['action'] === 'fallback' && uu_test_acts($r['calls']) === [] && $st['mode'] === 'tunnel'
        && uu_test_logged($r['calls'], LOG_ERR, 'forward-first'));

    // The control channel.
    $s = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $s['unbound']['control_ok'] = false;
    $s['unbound']['live_root'] = null;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable, 2, $now - 200));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'escalation → restart_unbound, logged at warning, state stays tunnel for the reassert after it',
        $p['action'] === 'skip' && $p['escalate_restart'] && uu_test_acts($r['calls']) === ['restart']
        && uu_test_logged($r['calls'], LOG_WARNING, 'restart') && $st['mode'] === 'tunnel');
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'a silent control channel without escalation → nothing but a warning',
        $p['action'] === 'skip' && !$p['escalate_restart'] && uu_test_acts($r['calls']) === []
        && uu_test_logged($r['calls'], LOG_WARNING, 'silent'));

    // Stop with a silent control channel (ruling R24) and saving mid-apply (ruling R26).
    $silentTunnel = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $silentTunnel['unbound']['control_ok'] = false;
    $silentTunnel['unbound']['live_root'] = null;
    $silentStop = $silentTunnel;
    $silentStop['settings']['enabled'] = false;
    $p = uu_plan($silentStop, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($silentStop, $all, ['silent' => true, 'restart_live' => ['192.0.2.53', '2001:db8::53']]);
    $st = uu_apply($p, $silentStop, $r['io']);
    uu_check($t, 'stop in tunnel mode with a silent channel → restart, the configured root confirmed, then reject, drain, delete',
        $p['action'] === 'stop'
        && uu_test_acts($r['calls']) === [$restoreDot, 'restart', 'uc forward', $reject, $flushReq, $drain, 'route delete -host 10.2.0.1']
        && $st['mode'] === 'fallback' && $st['route_installed'] === null
        && uu_test_logged($r['calls'], LOG_WARNING, 'restart'));
    $r = uu_test_io($silentStop, $all, ['silent' => true]);
    $st = uu_apply($p, $silentStop, $r['io']);
    $after = array_slice(uu_test_acts($r['calls']), 2);
    $polls = true;
    foreach ($after as $i => $call) {
        $polls = $polls && $call === ($i % 2 === 0 ? 'uc forward' : 'sleep 1000');
    }
    uu_check($t, 'still silent after the restart → polled for UU_CONTROL_WAIT_SECONDS, the route stays, still tunnel',
        array_slice(uu_test_acts($r['calls']), 0, 2) === [$restoreDot, 'restart'] && $polls
        && count(array_filter($after, fn (string $c): bool => $c === 'uc forward')) === UU_CONTROL_WAIT_SECONDS
        && $st['mode'] === 'tunnel' && $st['member'] === 'wg-a' && uu_test_logged($r['calls'], LOG_ERR, 'route stays'));
    $flush = $silentStop;
    $flush['contract_input']['cacheflush'] = true;
    $p = uu_plan($flush, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($flush, $all, ['silent' => true, 'restart_live' => ['192.0.2.53']]);
    $st = uu_apply($p, $flush, $r['io']);
    uu_check($t, 'stop with a silent channel and cacheflush on → no restart, the route stays, logged as an error',
        uu_test_acts($r['calls']) === [$restoreDot] && $st['mode'] === 'tunnel'
        && uu_test_logged($r['calls'], LOG_ERR, 'cacheflush'));
    $disabled = $silentStop;
    $disabled['settings']['enabled'] = true;
    $disabled['unbound']['enabled'] = false;
    $p = uu_plan($disabled, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($disabled, $all, ['silent' => true, 'restart_live' => ['192.0.2.53']]);
    $st = uu_apply($p, $disabled, $r['io']);
    uu_check($t, 'stop, Unbound disabled by the user with its pid alive, silent channel → no restart, the route stays, logged',
        $p['action'] === 'stop' && uu_test_acts($r['calls']) === [$restoreDot] && $st['mode'] === 'tunnel'
        && $st['member'] === 'wg-a' && uu_test_logged($r['calls'], LOG_ERR, 'disabled', 'no restart')
        && uu_test_logged($r['calls'], LOG_ERR, 'route stays'));
    $r = uu_test_io($silentStop, $all, ['silent' => true, 'restart_live' => ['192.0.2.53', '2001:db8::53']]);
    uu_apply(uu_plan($silentStop, uu_test_plan_state('wg-a', $usable)), $silentStop, $r['io']);
    uu_check($t, 'after the restart the log says what was checked: the live root is no longer the resolver',
        uu_test_logged($r['calls'], LOG_WARNING, 'no longer forwards to the resolver'));
    $p = uu_plan($silentStop, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($silentStop, $all, ['uc_fail' => ['forward_add']]);
    $st = uu_apply($p, $silentStop, $r['io']);
    uu_check($t, 'stop whose restore Unbound refuses (an answer, not silence) → no restart', !in_array('restart', uu_test_acts($r['calls']), true));

    $dryEscalate = $silentTunnel;
    $dryEscalate['settings']['dry_run'] = true;
    $p = uu_plan($dryEscalate, uu_test_plan_state('wg-a', $usable, 2, $now - 200));
    $r = uu_test_io($dryEscalate, $all);
    $st = uu_apply($p, $dryEscalate, $r['io']);
    uu_check($t, 'dry run with an escalating skip → the restart runs for real, no stop',
        $p['action'] === 'skip' && $p['escalate_restart'] && uu_test_acts($r['calls']) === ['restart']
        && $st['mode'] === 'tunnel' && !uu_test_logged($r['calls'], LOG_NOTICE, 'undoing'));
    $p = uu_plan($dryEscalate, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($dryEscalate, $all);
    uu_apply($p, $dryEscalate, $r['io']);
    uu_check($t, 'dry run with a silent channel and no escalation → no call, no stop',
        $p['action'] === 'skip' && uu_test_acts($r['calls']) === []);

    $s = uu_test_apply_snapshot();
    $p = uu_plan($s, uu_test_plan_state(null, $usable));
    $r = uu_test_io($s, $all, ['throw_on' => 'probe_direct']);
    $thrown = false;
    try {
        uu_apply($p, $s, $r['io']);
    } catch (RuntimeException $e) {
        $thrown = $e->getMessage() === 'test: probe_direct throws';
    }
    uu_check($t, 'an Io that throws after a route change → the exception escapes and the saved state has the new route',
        $thrown && isset($r['saved']['state']) && $r['saved']['state']['route_installed'] === $memberRecord);
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'the state is saved after each successful change (the last save is the returned state)',
        isset($r['saved']['state']) && $r['saved']['state'] === $st);

    // Never planned, across every case above; flush_requestlist only behind the reject route (ruling R29: stop).
    $forbidden = ['flush', 'flush_zone', 'flush_bogus', 'flush_negative', 'reload', 'reload_keep_cache',
                  'fast_reload'];
    $clean = count($all) > 0;
    $previous = '';
    foreach ($all as $call) {
        if ($call === '-- case') {
            $previous = '';
            continue;
        }
        if (str_starts_with($call, 'uc ')) {
            $words = explode(' ', substr($call, 3));
            /* behind the reject route: just after it was installed, or first in a case that starts on it */
            $clean = $clean && !in_array($words[0], $forbidden, true)
                && ($words[0] !== 'flush_type' || $words === ['flush_type', '.', 'SOA'])
                && ($words[0] !== 'flush_requestlist' || $previous === '' || str_ends_with($previous, ' -reject'));
        }
        if (!str_starts_with($call, 'log ')) {
            $clean = $clean && !(str_starts_with($previous, 'route delete') && str_starts_with($call, 'route add'));
            $previous = $call;
        }
    }
    uu_check($t, 'no recorded call is ever flush, flush_zone, flush_bogus, flush_negative, reload, reload_keep_cache or fast_reload; flush_type only "<probe> SOA"; flush_requestlist only behind the reject route (every case above)',
        $clean);

    // drill output.
    $ok = ";; ->>HEADER<<- opcode: QUERY, rcode: NOERROR, id: 4242\n"
        . ";; flags: qr rd ra ad ; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1 \n";
    uu_check($t, 'drill: NOERROR with ad passes', uu_drill_passed($ok));
    uu_check($t, 'drill: NOERROR without ad fails (the resolver no longer validates)',
        !uu_drill_passed(str_replace(' ad ;', ' ;', $ok)));
    uu_check($t, 'drill: SERVFAIL fails, even with ad', !uu_drill_passed(str_replace('NOERROR', 'SERVFAIL', $ok)));
    uu_check($t, 'drill: no output (timeout) fails', !uu_drill_passed(''));
    uu_check($t, 'drill: "ad" only inside another word (a name) is not the flag',
        !uu_drill_passed(";; ->>HEADER<<- opcode: QUERY, rcode: NOERROR, id: 1\n;; flags: qr rd ra ; QUERY: 1\nbad.example.\n"));

    uu_check($t, 'bare addresses: @port and #name stripped, IPv6 canonical, sorted, unique',
        uu_apply_bare(['2001:DB8:0::53@853#dns.example', '192.0.2.53@853', '192.0.2.53']) === ['192.0.2.53', '2001:db8::53']);

    return uu_tally_report('apply', $t);
});
