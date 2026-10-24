<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Apply order and failure handling with a recording Io (spec sections 3.4, 3.5, 3.7, 3.10 and the section 5
 * planner list). Plans come from the real planner, so each case also pins the planner input it depends on. The
 * removal's core commands (spec -04 section 3.2, C6) run through a recording runner.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/apply.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/corecmd.php';
require_once __DIR__ . '/test_planner.php';
require_once __DIR__ . '/scratch.php';

/**
 * The planner's test snapshot with Unbound's live root as Unbound prints it: bare addresses, its own order.
 *
 * @return array{now: int, wall: int,
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
 *     block_table: array{table: ?array{addresses: int, references: int, out_block: int}, addresses: list<string>}}
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
 * $all after a "-- case" marker, so the never-planned assertions see every case and where each starts.
 *
 * @param array{now: int, wall: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, failback_delay: int,
 *         probe_name: string},
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool}} $s
 * @param ArrayObject<int, string> $all
 * @param array{direct?: array<string, list<bool>>, unbound?: list<bool>, uc_fail?: list<string>,
 *     forward_out?: string, route_fail?: list<string>, restart?: bool, silent?: bool,
 *     restart_live?: list<string>, throw_on?: string, restarts?: bool} $o
 *   direct: per device, successive direct probe results (true when absent or used up); unbound: successive
 *   through-Unbound results (true when used up); uc_fail and route_fail: commands or verbs that fail once each,
 *   in order; forward_out: what `forward` prints instead of the fake's live root; silent: every unbound-control
 *   call times out (null) until a restart that sets restart_live as the live root; throw_on: the Io function
 *   that throws, after recording its call; restarts: the case expects a restart (the sweep at the end allows one
 *   nowhere else)
 * @return array{io: array{route: callable(string, list<string>): bool, sleep_ms: callable(int): void,
 *     probe_direct: callable(string, string): bool, probe_unbound: callable(string): bool,
 *     uc: callable(list<string>): ?string, restart_unbound: callable(): bool, log: callable(string, int): void,
 *     save: callable(array): void},
 *     calls: ArrayObject<int, string>,
 *     saved: ArrayObject<string, array{route_installed: ?array{kind: string, next_hop: string, if: string},
 *         resolver: ?string}>}
 *   saved holds the state the last save received under 'state'; saves are not in calls
 */
function uu_test_io(array $s, ArrayObject $all, array $o = []): array
{
    $calls = new ArrayObject();
    $route = $s['route'];
    /* the sweep at the end allows a first flush_requestlist only in a case that starts on the reject route, and a
     * restart only in a case that expects one */
    $all[] = '-- case' . ($route['present'] && $route['reject'] ? ' on reject' : '')
        . (($o['restarts'] ?? false) ? ' restarts' : '');
    $record = function (string $call) use ($calls, $all): void {
        $calls[] = $call;
        $all[] = $call;
    };
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
 * A recording runner for core's commands and a recording log: each command line and each log line ("log <prio>
 * <msg>") goes to calls in order; a command line exits with the status and prints the output of the first prefix in
 * codes it starts with, else exits 0 printing "OK" (configd's answer to a script action that ran).
 *
 * @param array<string, array{0: int, 1: string}> $codes prefix => [exit status, output]
 * @return array{run: callable(string): array{rc: int, out: string}, log: callable(string, int): void,
 *     calls: ArrayObject<int, string>}
 */
function uu_test_runner(array $codes = []): array
{
    $calls = new ArrayObject();
    $run = function (string $cmdline) use ($calls, $codes): array {
        $calls[] = $cmdline;
        foreach ($codes as $prefix => [$rc, $out]) {
            if (str_starts_with($cmdline, $prefix)) {
                return ['rc' => $rc, 'out' => $out];
            }
        }
        return ['rc' => 0, 'out' => "OK\n"];
    };
    $log = function (string $msg, int $prio) use ($calls): void {
        $calls[] = "log $prio $msg";
    };
    return ['run' => $run, 'log' => $log, 'calls' => $calls];
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
    uu_check($t, 'entering: the state records the resolver its route and forwarders refer to (ruling R31)',
        $st['resolver'] === '10.2.0.1' && $r['saved']['state']['resolver'] === '10.2.0.1');

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
    uu_check($t, 'a finished stop clears the recorded resolver: nothing refers to it any more',
        $st['resolver'] === null && $r['saved']['state']['resolver'] === null);
    uu_check($t, 'stop drains: restore, reject route, flush_requestlist, then fib_sync + 500 ms + UU_STOP_DRAIN_SECONDS (2500 ms), then delete',
        UU_STOP_DRAIN_SECONDS === 1 && $drain === 'sleep 2500');

    $r = uu_test_io($s, $all, ['uc_fail' => ['flush_requestlist']]);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'stop whose flush_requestlist fails → the reject route stays (a retry would leave by a WAN), recorded, logged',
        uu_test_acts($r['calls']) === [$restoreDot, 'uc forward', $reject, $flushReq]
        && $st['mode'] === 'fallback' && $st['route_installed'] === ['kind' => 'reject', 'next_hop' => '', 'if' => 'lo0']
        && $st['resolver'] === '10.2.0.1'
        && uu_test_logged($r['calls'], LOG_ERR, 'flush_requestlist failed'));
    $wgARecord = ['kind' => 'member', 'next_hop' => '10.2.0.2', 'if' => 'wg1'];
    $recordedWgA = uu_test_plan_state('wg-a', $usable);
    $recordedWgA['route_installed'] = $wgARecord;
    $r = uu_test_io($s, $all, ['route_fail' => ['change', 'add']]);
    $st = uu_apply(uu_plan($s, $recordedWgA), $s, $r['io']);
    uu_check($t, 'stop whose reject route fails → the member route stays, never deleted, its record kept, logged',
        uu_test_acts($r['calls']) === [$restoreDot, 'uc forward', $reject, 'route add -host 10.2.0.1 127.0.0.1 -reject']
        && $st['mode'] === 'fallback' && $st['route_installed'] === $wgARecord
        && uu_test_logged($r['calls'], LOG_ERR, 'no reject route'));

    $gap = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $gap['settings']['enabled'] = false;
    $gap['route'] = ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false, 'ours' => false];
    $p = uu_plan($gap, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($gap, $all);
    $st = uu_apply($p, $gap, $r['io']);
    uu_check($t, 'stop in tunnel mode with the route missing (a route-loss window) → reject route added, flush, drain, delete',
        $p['action'] === 'stop'
        && uu_test_acts($r['calls']) === [$restoreDot, 'uc forward', 'route add -host 10.2.0.1 127.0.0.1 -reject',
            $flushReq, $drain, 'route delete -host 10.2.0.1']
        && $st['mode'] === 'fallback' && $st['route_installed'] === null);

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

    /* the re-review's N1: a route record that outlived its route (the kernel deleted it) must not pin the address */
    $s = uu_test_apply_snapshot();
    $s['settings']['enabled'] = false;
    $stale = uu_test_plan_state(null);
    $stale['route_installed'] = ['kind' => 'member', 'next_hop' => '10.2.0.2', 'if' => 'wg1'];
    $stale['resolver'] = '10.2.0.1';
    $p = uu_plan($s, $stale);
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'stop in fallback with a stale route record and no route → no calls, the resolver no longer recorded',
        $p['action'] === 'stop' && uu_test_acts($r['calls']) === [] && $st['resolver'] === null);

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

    /* ruling R44: with the zone configuration unreadable, neither a fallback nor a stop guesses: no forward_remove .
     * (Unbound would recurse over the WAN in place of the configured forwarders), no forward_add, the route kept */
    $runs = null;
    try {
        $s = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
        $s['probes']['wg-a'] = $settledDown;
        $s['probes']['wg-b'] = $settledDown;
        $s['zone'] = uu_root_zone(null);
        $s['contract_input']['zone'] = $s['zone'];
        $runs = [];
        foreach ([false, true] as $stop) {
            $s['settings']['enabled'] = !$stop;
            $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
            $r = uu_test_io($s, $all);
            $runs[] = [$p, $r, uu_apply($p, $s, $r['io'])];
        }
    } catch (\Throwable $e) {
        printf("  threw %s: %s\n", get_class($e), $e->getMessage());
    }
    foreach (['fallback' => 0, 'stop' => 1] as $action => $i) {
        uu_check($t, "zone configuration unreadable, $action: no forwarders call and no route call, still tunnel, "
            . 'logged as an error naming it',
            $runs !== null && $runs[$i][0]['action'] === $action && uu_test_acts($runs[$i][1]['calls']) === []
            && $runs[$i][2]['mode'] === 'tunnel'
            && uu_test_logged($runs[$i][1]['calls'], LOG_ERR, 'configuration unreadable'));
    }

    // The control channel.
    $s = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $s['unbound']['control_ok'] = false;
    $s['unbound']['live_root'] = null;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable, 2, $now - 200));
    $r = uu_test_io($s, $all, ['restarts' => true]);
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
    /* a disabled plugin's tick restarts only once the planner's bound is reached (ruling R52): this state is one
     * silent evaluation short of it */
    $atBound = uu_test_plan_state('wg-a', $usable, UU_ESCALATE_EVALUATIONS - 1, $now - UU_ESCALATE_MIN_SECONDS);
    $p = uu_plan($silentStop, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($silentStop, $all, ['silent' => true, 'restart_live' => ['192.0.2.53', '2001:db8::53']]);
    $st = uu_apply($p, $silentStop, $r['io']);
    uu_check($t, '(R52) a disabled tick with a silent channel short of the bound → the restore tried, no restart, the route stays, still tunnel',
        $p['action'] === 'stop' && !$p['escalate_restart'] && uu_test_acts($r['calls']) === [$restoreDot]
        && $st['mode'] === 'tunnel' && $st['member'] === 'wg-a'
        && $st['resolver'] === $silentStop['settings']['resolver'] && uu_test_logged($r['calls'], LOG_ERR, 'route stays'));
    $p = uu_plan($silentStop, $atBound);
    $r = uu_test_io($silentStop, $all, ['silent' => true, 'restart_live' => ['192.0.2.53', '2001:db8::53'],
        'restarts' => true]);
    $st = uu_apply($p, $silentStop, $r['io']);
    uu_check($t, 'stop in tunnel mode with a silent channel at the bound → restart, the configured root confirmed, then reject, drain, delete',
        $p['action'] === 'stop'
        && uu_test_acts($r['calls']) === [$restoreDot, 'restart', 'uc forward', $reject, $flushReq, $drain, 'route delete -host 10.2.0.1']
        && $st['mode'] === 'fallback' && $st['route_installed'] === null
        && uu_test_logged($r['calls'], LOG_WARNING, 'restart'));
    $r = uu_test_io($silentStop, $all, ['silent' => true, 'restarts' => true]);
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
    $p = uu_plan($flush, $atBound);
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
    $r = uu_test_io($silentStop, $all, ['silent' => true, 'restart_live' => ['192.0.2.53', '2001:db8::53'],
        'restarts' => true]);
    uu_apply(uu_plan($silentStop, $atBound), $silentStop, $r['io']);
    uu_check($t, 'after the restart the log says what was checked: the live root is no longer the resolver',
        uu_test_logged($r['calls'], LOG_WARNING, 'no longer forwards to the resolver'));

    // Ruling R53: only a requested stop and the removal restart at once for a silent channel; every other stop waits
    // for the bound, the undo of a replaced address included.
    $silentTail = [$restoreDot, 'restart', 'uc forward', $reject, $flushReq, $drain,
        'route delete -host ' . $silentTunnel['settings']['resolver']];
    $silentRoot = ['192.0.2.53', '2001:db8::53'];
    /* disabled, footprint A, setting B: each tick first undoes A, as UU_STOP_RESOLVER, on the same counter */
    $undo = $silentStop;
    $undo['stop'] = UU_STOP_RESOLVER;
    $acts = [];
    $st = uu_test_plan_state('wg-a', $usable);
    foreach ([0, 60, UU_ESCALATE_MIN_SECONDS] as $i => $offset) {
        $undo['now'] = $now + $offset;
        $p = uu_plan($undo, $st);
        $r = uu_test_io($undo, $all, ['silent' => true, 'restart_live' => $silentRoot, 'restarts' => $i === 2]);
        $st = uu_apply($p, $undo, $r['io']);
        $acts[] = uu_test_acts($r['calls']);
    }
    uu_check($t, '(R53) disabled, footprint A, setting B, silent channel: the undo restarts on no tick before the third, at 120 s, then the tail',
        $acts[0] === [$restoreDot] && $acts[1] === [$restoreDot] && $acts[2] === $silentTail
        && $st['mode'] === 'fallback' && $st['resolver'] === null);
    $undoOn = $silentTunnel;
    $undoOn['stop'] = UU_STOP_RESOLVER;
    $p = uu_plan($undoOn, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($undoOn, $all, ['silent' => true, 'restart_live' => $silentRoot]);
    $st = uu_apply($p, $undoOn, $r['io']);
    uu_check($t, '(R53) the undo of a replaced address, silent channel, fresh count → no restart, the route stays',
        uu_test_acts($r['calls']) === [$restoreDot] && $st['mode'] === 'tunnel'
        && uu_test_logged($r['calls'], LOG_ERR, 'route stays'));
    $p = uu_plan($undoOn, $atBound);
    $r = uu_test_io($undoOn, $all, ['silent' => true, 'restart_live' => $silentRoot, 'restarts' => true]);
    $st = uu_apply($p, $undoOn, $r['io']);
    uu_check($t, '(R53) the same at the bound → restart, the configured root confirmed, then the tail',
        uu_test_acts($r['calls']) === $silentTail && $st['mode'] === 'fallback');
    foreach ([UU_STOP_REQUEST => 'a requested stop', UU_STOP_REMOVE => 'the removal'] as $cause => $what) {
        $immediate = $silentTunnel;
        $immediate['stop'] = $cause;
        $p = uu_plan($immediate, uu_test_plan_state('wg-a', $usable));
        $r = uu_test_io($immediate, $all, ['silent' => true, 'restart_live' => $silentRoot, 'restarts' => true]);
        $st = uu_apply($p, $immediate, $r['io']);
        uu_check($t, "(R53) $what, silent channel, fresh count → restart at once, then the tail",
            !$p['escalate_restart'] && uu_test_acts($r['calls']) === $silentTail && $st['mode'] === 'fallback');
    }
    $p = uu_plan($silentStop, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($silentStop, $all, ['uc_fail' => ['forward_add']]);
    $st = uu_apply($p, $silentStop, $r['io']);
    uu_check($t, 'stop whose restore Unbound refuses (an answer, not silence) → no restart', !in_array('restart', uu_test_acts($r['calls']), true));

    $dryEscalate = $silentTunnel;
    $dryEscalate['settings']['dry_run'] = true;
    $p = uu_plan($dryEscalate, uu_test_plan_state('wg-a', $usable, 2, $now - 200));
    $r = uu_test_io($dryEscalate, $all, ['restarts' => true]);
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

    // A stop that cannot restore (spec -04 section 3.2, ruling R3): a requested stop and a removal restart Unbound
    // on any restore failure; a removal that still cannot restore leaves the reject route.
    $fp = uu_test_apply_snapshot();
    $fp['settings']['resolver'] = '192.0.2.1';
    $fp = uu_test_in_tunnel($fp, 'wg-a');
    $fpRoot = ['192.0.2.53', '2001:db8::53'];
    $fpReject = 'route change -host 192.0.2.1 127.0.0.1 -reject';
    $fpTail = [$fpReject, $flushReq, $drain, 'route delete -host 192.0.2.1'];
    $fpRefused = ['uc_fail' => ['forward_add'], 'restart_live' => $fpRoot];
    $stopAs = function (array $s, ?string $cause, array $o) use ($all, $usable): array {
        $s['stop'] = $cause;
        $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
        $r = uu_test_io($s, $all, $o);
        $st = uu_apply($p, $s, $r['io']);
        return ['action' => $p['action'], 'calls' => $r['calls'], 'acts' => uu_test_acts($r['calls']), 'st' => $st,
                'saved' => $r['saved']];
    };
    $cleared = fn (array $st): bool => $st['mode'] === 'fallback' && $st['member'] === null
        && $st['resolver'] === null && $st['route_installed'] === null;
    $lastResort = fn (array $run): bool => !in_array('route delete -host 192.0.2.1', $run['acts'], true)
        && $run['st']['resolver'] === '192.0.2.1' && $run['saved']['state']['resolver'] === '192.0.2.1'
        && $run['st']['route_installed'] === $rejectRecord
        && uu_test_logged($run['calls'], LOG_ERR, 'being removed', '192.0.2.1', 'rejected locally',
            'configctl unbound restart');

    $run = $stopAs($fp, UU_STOP_REQUEST, $fpRefused + ['restarts' => true]);
    uu_check($t, '(a1) requested stop, forward_add refused, cacheflush off → restart, the configured root confirmed once, then reject, flush, drain, delete',
        $run['action'] === 'stop' && $run['acts'] === array_merge([$restoreDot, 'restart', 'uc forward'], $fpTail)
        && $cleared($run['st'])
        && uu_test_logged($run['calls'], LOG_WARNING, 'only a restart brings back its configured root zone'));

    $unrestorable = $fp;
    $unrestorable['zone'] = ['shape' => 'unrestorable', 'addrs' => ['192.0.2.53'], 'tls' => false,
                             'problems' => ['second . zone']];
    $unrestorable['contract_input']['zone'] = $unrestorable['zone'];
    $run = $stopAs($unrestorable, UU_STOP_REQUEST, ['restart_live' => $fpRoot, 'restarts' => true]);
    uu_check($t, '(a2) requested stop with the zone unrestorable → no forward_add, restart at once, then the same tail',
        $run['action'] === 'stop' && $run['acts'] === array_merge(['restart', 'uc forward'], $fpTail)
        && $cleared($run['st']) && uu_test_logged($run['calls'], LOG_ERR, 'second . zone'));
    /* ruling R44: an unreadable zone configuration is unrestorable, so these stops restart at once as well */
    $unreadable = $fp;
    $unreadable['zone'] = uu_root_zone(null);
    $unreadable['contract_input']['zone'] = $unreadable['zone'];
    foreach ([UU_STOP_REQUEST => 'requested stop', UU_STOP_REMOVE => 'removal'] as $cause => $what) {
        $run = $stopAs($unreadable, $cause, ['restart_live' => $fpRoot, 'restarts' => true]);
        uu_check($t, "(a2, R44) $what with the zone configuration unreadable → restart at once, then the same tail",
            $run['action'] === 'stop' && $run['acts'] === array_merge(['restart', 'uc forward'], $fpTail)
            && $cleared($run['st']) && uu_test_logged($run['calls'], LOG_ERR, 'configuration unreadable'));
    }

    $keeps = $fp;
    $keeps['settings']['enabled'] = false;
    $keeps['contract_input']['cacheflush'] = true;
    $run = $stopAs($keeps, UU_STOP_REQUEST, $fpRefused);
    $warned = array_values(array_filter($run['calls']->getArrayCopy(),
        fn (string $c): bool => str_starts_with($c, 'log ' . LOG_WARNING . ' ')));
    uu_check($t, '(a3) requested stop disabling the plugin, cacheflush on, restore refused → no restart, no route call, still tunnel, the resolver recorded, one warning that its block stays',
        $run['action'] === 'stop' && $run['acts'] === [$restoreDot] && $run['st']['mode'] === 'tunnel'
        && $run['st']['member'] === 'wg-a' && $run['st']['resolver'] === '192.0.2.1' && count($warned) === 1
        && str_contains($warned[0], '192.0.2.1') && str_contains($warned[0], 'block stays'));
    $keepsOn = $keeps;
    $keepsOn['settings']['enabled'] = true;
    foreach (["a disabled plugin's tick" => [$keeps, null],
              'a requested stop with the plugin enabled' => [$keepsOn, UU_STOP_REQUEST]] as $what => [$case, $cause]) {
        $run = $stopAs($case, $cause, $fpRefused);
        uu_check($t, "(a3, R3) $what, cacheflush on, restore refused → no restart, the route stays, no footprint warning",
            $run['action'] === 'stop' && $run['acts'] === [$restoreDot] && $run['st']['resolver'] === '192.0.2.1'
            && !uu_test_logged($run['calls'], LOG_WARNING, 'block stays'));
    }

    $flushOn = $fp;
    $flushOn['contract_input']['cacheflush'] = true;
    $run = $stopAs($flushOn, UU_STOP_REMOVE, $fpRefused + ['restarts' => true]);
    uu_check($t, '(a4) removal, cacheflush on, restore refused → restart anyway (owner decision D2), then the tail',
        $run['action'] === 'stop' && $run['acts'] === array_merge([$restoreDot, 'restart', 'uc forward'], $fpTail)
        && $cleared($run['st']));

    $run = $stopAs($fp, UU_STOP_REMOVE, ['uc_fail' => ['forward_add'], 'restart' => false, 'restarts' => true]);
    uu_check($t, '(a5) removal whose restart fails → the reject route over the member route as the last resort, never a delete, the resolver still recorded, logged',
        $run['action'] === 'stop' && $run['acts'] === [$restoreDot, 'restart', $fpReject] && $lastResort($run));
    $fpGap = $fp;
    $fpGap['route'] = ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false, 'ours' => false];
    $run = $stopAs($fpGap, UU_STOP_REMOVE, ['uc_fail' => ['forward_add'], 'restart' => false, 'restarts' => true]);
    uu_check($t, '(a5) the same with the route missing (a route-loss window) → the reject route added',
        $run['acts'] === [$restoreDot, 'restart', 'route add -host 192.0.2.1 127.0.0.1 -reject'] && $lastResort($run));
    /* nothing changed, so nothing was saved mid-run: the returned state is what evaluate.php saves */
    $noReject = fn (array $run): bool => !in_array('route delete -host 192.0.2.1', $run['acts'], true)
        && $run['st']['resolver'] === '192.0.2.1' && $run['st']['route_installed'] !== $rejectRecord
        && !uu_test_logged($run['calls'], LOG_ERR, 'rejected locally')
        && uu_test_logged($run['calls'], LOG_ERR, 'being removed', '192.0.2.1', 'could not be made a reject route',
            'configctl unbound restart');
    $run = $stopAs($fp, UU_STOP_REMOVE, ['uc_fail' => ['forward_add'], 'restart' => false,
                                         'route_fail' => ['change', 'add'], 'restarts' => true]);
    uu_check($t, '(a5) removal whose restart fails and whose reject route cannot be made → the member route kept, never deleted, the resolver recorded, an error naming the removal and the remedy',
        $run['acts'] === [$restoreDot, 'restart', $fpReject, 'route add -host 192.0.2.1 127.0.0.1 -reject']
        && $noReject($run));
    $fpForeign = $fp;
    $fpForeign['route'] = ['present' => true, 'gateway' => '192.0.2.99', 'interface' => 'igc0', 'reject' => false,
                           'ours' => false];
    $run = $stopAs($fpForeign, UU_STOP_REMOVE, ['uc_fail' => ['forward_add'], 'restart' => false,
                                                'restarts' => true]);
    uu_check($t, '(a5) removal whose restart fails with a foreign route → no reject route over it, never deleted, the resolver recorded, an error naming the removal and the remedy',
        $run['acts'] === [$restoreDot, 'restart'] && $noReject($run)
        && uu_test_logged($run['calls'], LOG_WARNING, 'not ours'));

    $run = $stopAs($fp, UU_STOP_REMOVE, ['uc_fail' => ['forward_add'], 'forward_out' => "192.0.2.1\n",
                                         'restarts' => true]);
    uu_check($t, '(a6) removal, `forward` still the resolver after the restart → the same last resort',
        $run['acts'] === [$restoreDot, 'restart', 'uc forward', $fpReject] && $lastResort($run)
        && uu_test_logged($run['calls'], LOG_ERR, 'still forwards to the resolver'));
    $run = $stopAs($fp, UU_STOP_REQUEST, ['forward_out' => "192.0.2.1\n", 'restarts' => true]);
    uu_check($t, '(a6) requested stop whose restore does not confirm → restart; still the resolver after it → the route stays, no reject route (it would black-hole every query)',
        $run['acts'] === [$restoreDot, 'uc forward', 'restart', 'uc forward'] && $run['st']['mode'] === 'tunnel'
        && $run['st']['resolver'] === '192.0.2.1' && uu_test_logged($run['calls'], LOG_ERR, 'route stays'));

    $run = $stopAs($fp, UU_STOP_RESOLVER, $fpRefused);
    uu_check($t, '(a7) resolver-change stop, restore refused with the channel answering → no restart (1.2_1), the route stays',
        $run['action'] === 'stop' && $run['acts'] === [$restoreDot] && $run['st']['mode'] === 'tunnel'
        && $run['st']['resolver'] === '192.0.2.1');

    $userOff = $fp;
    $userOff['unbound']['enabled'] = false;
    $run = $stopAs($userOff, UU_STOP_REMOVE, $fpRefused);
    uu_check($t, '(a8) removal in tunnel mode with Unbound disabled in its settings, restore refused → no restart, the reject route, the error line',
        $run['action'] === 'stop' && $run['acts'] === [$restoreDot, $fpReject] && $lastResort($run)
        && uu_test_logged($run['calls'], LOG_ERR, 'disabled in its settings', 'no restart'));

    $fpOff = $fp;
    $fpOff['settings']['enabled'] = false;
    $run = $stopAs($fpOff, UU_STOP_REQUEST, []);
    uu_check($t, '(a9) requested stop that restores → the tail, the resolver cleared, no footprint warning',
        $run['acts'] === array_merge([$restoreDot, 'uc forward'], $fpTail) && $cleared($run['st'])
        && !uu_test_logged($run['calls'], LOG_WARNING, 'block stays'));

    // Ruling R50: the undo of a replaced address runs under the requested stop's cause. Setting B, footprint A
    // (192.0.2.1), the zone unrestorable: the undo of A is a stop of A's snapshot.
    $r50 = null;
    $ok = uu_try_case(function () use ($stopAs, $unrestorable, &$r50): bool {
        $r50 = $stopAs($unrestorable, uu_plan_causes(UU_STOP_REMOVE, true)['undo'],
            ['restart' => false, 'restarts' => true]);
        return true;
    });
    uu_check($t, '(R50) a removal with setting B, footprint A and the zone unrestorable → the undo of A restarts at once, then, still not restored, the reject route over A\'s route, never a delete, the removal line',
        $ok && $r50 !== null && $r50['action'] === 'stop' && $r50['acts'] === ['restart', $fpReject]
        && $lastResort($r50));
    $ok = uu_try_case(function () use ($stopAs, $unrestorable, $fpRoot, &$r50): bool {
        $r50 = $stopAs($unrestorable, uu_plan_causes(UU_STOP_REQUEST, false)['undo'],
            ['restart_live' => $fpRoot, 'restarts' => true]);
        return true;
    });
    uu_check($t, '(R50) the same under a requested stop → the undo of A restarts at once, the configured root confirmed, then the tail, A cleared',
        $ok && $r50 !== null && $r50['acts'] === array_merge(['restart', 'uc forward'], $fpTail)
        && $cleared($r50['st']));

    // Ruling R51: a tick while the removal marker exists is a stop with the ticks' rules: a restart only for a silent
    // channel at section 3.10's bound, no cacheflush override, never the reject route. remove itself keeps both
    // (a4 to a8 above).
    $tick = null;
    $ok = uu_try_case(function () use ($stopAs, $fp, $fpRefused, &$tick): bool {
        $tick = $stopAs($fp, uu_plan_causes(null, true)['run'], $fpRefused);
        return true;
    });
    uu_check($t, '(R51) a tick while the removal marker exists, restore refused, channel answering → no restart, no reject route, the route stays, the resolver recorded',
        $ok && $tick !== null && $tick['action'] === 'stop' && $tick['acts'] === [$restoreDot]
        && $tick['st']['mode'] === 'tunnel' && $tick['st']['resolver'] === '192.0.2.1'
        && !uu_test_logged($tick['calls'], LOG_ERR, 'rejected locally')
        && uu_test_logged($tick['calls'], LOG_ERR, 'route stays'));
    $acts = [];
    $ok = uu_try_case(function () use ($silentTunnel, $usable, $now, $all, $silentRoot, &$acts): bool {
        $marker = $silentTunnel;
        $marker['stop'] = uu_plan_causes(null, true)['run'];
        $st = uu_test_plan_state('wg-a', $usable);
        foreach ([0, 60, UU_ESCALATE_MIN_SECONDS] as $i => $offset) {
            $marker['now'] = $now + $offset;
            $p = uu_plan($marker, $st);
            $r = uu_test_io($marker, $all, ['silent' => true, 'restart_live' => $silentRoot, 'restarts' => $i === 2]);
            $st = uu_apply($p, $marker, $r['io']);
            $acts[] = uu_test_acts($r['calls']);
        }
        return $st['mode'] === 'fallback' && $st['resolver'] === null;
    });
    uu_check($t, '(R51, R53) a tick while the removal marker exists, silent channel → no restart before the third tick, at 120 s, then one restart and the tail',
        $ok && count($acts) === 3 && $acts[0] === [$restoreDot] && $acts[1] === [$restoreDot]
        && $acts[2] === $silentTail);
    $ok = uu_try_case(function () use ($silentTunnel, $atBound, $all, &$tick): bool {
        $marker = $silentTunnel;
        $marker['stop'] = uu_plan_causes(null, true)['run'];
        $p = uu_plan($marker, $atBound);
        $r = uu_test_io($marker, $all, ['silent' => true, 'restart' => false, 'restarts' => true]);
        $tick = ['p' => $p, 'calls' => $r['calls'], 'st' => uu_apply($p, $marker, $r['io'])];
        return true;
    });
    uu_check($t, '(R51) the same tick at the bound whose restart fails → never the reject route: the route stays, still tunnel',
        $ok && $tick !== null && $tick['p']['escalate_restart']
        && uu_test_acts($tick['calls']) === [$restoreDot, 'restart']
        && $tick['st']['mode'] === 'tunnel' && !uu_test_logged($tick['calls'], LOG_ERR, 'rejected locally')
        && uu_test_logged($tick['calls'], LOG_ERR, 'route stays'));
    $ok = uu_try_case(function () use ($silentTunnel, $atBound, $all, $silentRoot, &$tick): bool {
        $marker = $silentTunnel;
        $marker['stop'] = uu_plan_causes(null, true)['run'];
        $marker['contract_input']['cacheflush'] = true;
        $p = uu_plan($marker, $atBound);
        $r = uu_test_io($marker, $all, ['silent' => true, 'restart_live' => $silentRoot]);
        $tick = ['p' => $p, 'calls' => $r['calls'], 'st' => uu_apply($p, $marker, $r['io'])];
        return true;
    });
    uu_check($t, '(R51) the same tick at the bound with cacheflush on → no restart (only remove itself overrides cacheflush), the route stays',
        $ok && $tick !== null && uu_test_acts($tick['calls']) === [$restoreDot] && $tick['st']['mode'] === 'tunnel'
        && uu_test_logged($tick['calls'], LOG_ERR, 'cacheflush'));

    // A removal's core commands (rulings R4, R5, R55; C6): through configd when configctl exits 0 within
    // UU_CONFIGD_TIMEOUT_SECONDS with the reply OK, else core's own script.
    $ctlReload = '/usr/bin/timeout 30 /usr/local/sbin/configctl filter reload';
    $ctlCron = '/usr/bin/timeout 30 /usr/local/sbin/configctl cron restart';
    $ctlUnbound = '/usr/bin/timeout 30 /usr/local/sbin/configctl unbound restart';
    $ctl = '/usr/bin/timeout ';
    /* for a runner: [what uu_core_command() returned for filter reload, then for cron restart, the calls] */
    $core = function (array $codes): ?array {
        $out = null;
        $ok = uu_try_case(function () use ($codes, &$out): bool {
            $r = uu_test_runner($codes);
            $out = [uu_core_command('filter reload', UU_CORE_FILTER_RELOAD, $r['run']),
                    uu_core_command('cron restart', UU_CORE_CRON_RESTART, $r['run']), $r['calls']->getArrayCopy()];
            return true;
        });
        return $ok ? $out : null;
    };
    $field = fn (?array $out, int $i, string $key): mixed => is_array($out[$i] ?? null)
        ? ($out[$i][$key] ?? null) : null;
    $paths = fn (?array $out): array => [$field($out, 0, 'path'), $field($out, 1, 'path')];
    $out = $core([$ctl => [1, '']]);
    uu_check($t, '(d1) configd not answering (exit 1) → direct for each, core\'s own command right after its configctl line',
        $paths($out) === ['direct', 'direct']
        && $out[2] === [$ctlReload, '/usr/local/etc/rc.filter_configure', $ctlCron,
            '/usr/local/sbin/pluginctl -s cron restart']
        && $field($out, 0, 'configd') === 'did not answer (configctl exit 1)');
    $out = $core([$ctl => [124, '']]);
    uu_check($t, '(d1) configctl timed out (exit 124) → direct, said as a timeout',
        $paths($out) === ['direct', 'direct'] && $out[2][1] === UU_CORE_FILTER_RELOAD
        && $field($out, 0, 'configd') === 'did not answer within 30 s (configctl exit 124)');
    $out = $core([]);
    uu_check($t, '(d2) configd answering OK → configd for each, only the two configctl lines',
        $paths($out) === ['configd', 'configd'] && $out[2] === [$ctlReload, $ctlCron]);
    $out = $core(['/' => [1, '']]);
    uu_check($t, '(d3) configd and core\'s script both failing → failed, with the script\'s exit status',
        $paths($out) === ['failed', 'failed'] && $out[2] === [$ctlReload, UU_CORE_FILTER_RELOAD, $ctlCron,
            UU_CORE_CRON_RESTART] && $field($out, 0, 'rc') === 1);
    $replies = [
        'an error reply' => ["Error (1)\n", "answered 'Error (1)'"],
        'no reply' => ['', 'answered nothing'],
        'Action not found' => ["Action not found\n", "answered 'Action not found'"],
        'a reply of several lines' => ["Execute error\nmore\n", "answered 'Execute error'"],
    ];
    foreach ($replies as $what => [$reply, $said]) {
        $out = $core([$ctl => [0, $reply]]);
        uu_check($t, "(R55) configctl exiting 0 with $what → direct for each, configd's reply named by its first line",
            $paths($out) === ['direct', 'direct'] && $out[2] === [$ctlReload, UU_CORE_FILTER_RELOAD, $ctlCron,
                UU_CORE_CRON_RESTART] && $field($out, 0, 'configd') === $said);
    }
    $out = $core([$ctl => [0, "  OK  \n"]]);
    uu_check($t, '(R55) OK with blanks around it is OK', $paths($out) === ['configd', 'configd']);
    $out = $core([$ctl => [0, "Error \x1b[31mred\x07" . str_repeat('x', 300) . "\n"]]);
    uu_check($t, '(R55) a reply\'s first line is cleaned of control bytes and cut short',
        is_string($field($out, 0, 'configd')) && preg_match('/[\x00-\x1f\x7f]/', $field($out, 0, 'configd')) === 0
        && strlen($field($out, 0, 'configd')) <= 150);

    $removal = function (array $codes): ?ArrayObject {
        $calls = null;
        $ok = uu_try_case(function () use ($codes, &$calls): bool {
            $r = uu_test_runner($codes);
            uu_remove_core_commands($r['run'], $r['log']);
            $calls = $r['calls'];
            return true;
        });
        return $ok ? $calls : null;
    };
    $calls = $removal([]);
    uu_check($t, '(R4) remove after its stop, configd answering OK → the filter reload, then the cron restart, through configd, each logged',
        $calls !== null && uu_test_acts($calls) === [$ctlReload, $ctlCron]
        && uu_test_logged($calls, LOG_NOTICE, 'filter reload', 'through configd')
        && uu_test_logged($calls, LOG_NOTICE, 'cron restart', 'through configd'));
    $calls = $removal([$ctl => [255, '']]);
    uu_check($t, '(R4, M4) remove after its stop, no configd socket (exit 255) → core\'s two scripts directly, each logged with configctl\'s exit and the command it ran, no "30 s"',
        $calls !== null && uu_test_acts($calls) === [$ctlReload, '/usr/local/etc/rc.filter_configure', $ctlCron,
            '/usr/local/sbin/pluginctl -s cron restart']
        && uu_test_logged($calls, LOG_WARNING, 'filter reload', 'did not answer (configctl exit 255)',
            '/usr/local/etc/rc.filter_configure', 'ran directly')
        && uu_test_logged($calls, LOG_WARNING, 'cron restart', 'did not answer (configctl exit 255)',
            '/usr/local/sbin/pluginctl -s cron restart')
        && !uu_test_logged($calls, LOG_WARNING, '30 s'));
    $calls = $removal([$ctl => [0, "Error (1)\n"]]);
    uu_check($t, '(R55) remove after its stop, configd answering Error (1) → core\'s two scripts directly, the reply named, never "through configd"',
        $calls !== null && uu_test_acts($calls) === [$ctlReload, '/usr/local/etc/rc.filter_configure', $ctlCron,
            '/usr/local/sbin/pluginctl -s cron restart']
        && uu_test_logged($calls, LOG_WARNING, 'filter reload', "answered 'Error (1)'", 'ran directly')
        && !uu_test_logged($calls, LOG_NOTICE, 'through configd')
        && !uu_test_logged($calls, LOG_WARNING, 'through configd'));
    $calls = $removal(['/' => [1, '']]);
    uu_check($t, '(R4) remove after its stop, both failing → an error for each, with both exits, saying what is left',
        $calls !== null && uu_test_logged($calls, LOG_ERR, 'filter reload', 'configctl exit 1', 'exited 1', 'until')
        && uu_test_logged($calls, LOG_ERR, 'cron restart', 'configctl exit 1', 'exited 1', 'until'));

    // Rulings R54 and R56: a removal whose run directory cannot be trusted, or whose removal marker cannot be made,
    // takes no lock, reads no state, has core restart Unbound and says in one error what ran, that it is not
    // confirmed, and the remedy.
    $refusal = function (string $problem, array $codes): ?array {
        $out = null;
        $ok = uu_try_case(function () use ($problem, $codes, &$out): bool {
            $r = uu_test_runner($codes);
            $prepare = function () use ($problem): void {
                throw new RuntimeException($problem);
            };
            $out = ['rc' => uu_remove_prepare($prepare, $r['run'], $r['log']), 'calls' => $r['calls']];
            return true;
        });
        return $ok ? $out : null;
    };
    $oneError = function (?array $out): ?string {
        if ($out === null) {
            return null;
        }
        $lines = array_values(array_filter($out['calls']->getArrayCopy(),
            fn (string $c): bool => str_starts_with($c, 'log ')));
        return count($lines) === 1 && str_starts_with($lines[0], 'log ' . LOG_ERR . ' ') ? $lines[0] : null;
    };
    $has = function (?string $line, string ...$needles): bool {
        foreach ($needles as $needle) {
            if ($line === null || !str_contains($line, $needle)) {
                return false;
            }
        }
        return true;
    };
    $link = UU_RUN_DIR . ' is a symbolic link';
    $out = $refusal($link, []);
    $line = $oneError($out);
    uu_check($t, '(R54, M1) remove with an untrusted run dir → exit 1, core\'s restart through configd, one error naming the run dir and the removal, saying the restart ran but is not confirmed, with the remedy',
        $out !== null && $out['rc'] === 1 && uu_test_acts($out['calls']) === [$ctlUnbound]
        && $has($line, UU_RUN_DIR, 'symbolic link', 'being removed', 'ran through configd', 'not confirmed',
            'configctl unbound restart', 'route delete -host')
        && !$has($line, 'not restarted') && !$has($line, 'onto its configured root zone'));
    $out = $refusal($link, [$ctl => [1, '']]);
    $line = $oneError($out);
    uu_check($t, '(R54, M1) the same with configd not answering → core\'s own restart run directly, and the line says so, not confirmed',
        $out !== null && $out['rc'] === 1
        && uu_test_acts($out['calls']) === [$ctlUnbound, '/usr/local/sbin/pluginctl -c unbound_start']
        && $has($line, UU_RUN_DIR, 'did not answer (configctl exit 1)', '/usr/local/sbin/pluginctl -c unbound_start',
            'ran directly', 'not confirmed', 'configctl unbound restart') && !$has($line, 'not restarted'));
    $out = $refusal($link, [$ctl => [0, "Error (1)\n"]]);
    $line = $oneError($out);
    uu_check($t, '(R54, R55) the same with configd answering Error (1) → core\'s own restart run directly, the reply named, never "through configd"',
        $out !== null && uu_test_acts($out['calls']) === [$ctlUnbound, '/usr/local/sbin/pluginctl -c unbound_start']
        && $has($line, "answered 'Error (1)'", 'ran directly') && !$has($line, 'through configd'));
    $out = $refusal($link, [$ctl => [0, '']]);
    $line = $oneError($out);
    uu_check($t, '(R54, R55) the same with no reply → core\'s own restart run directly',
        $out !== null && uu_test_acts($out['calls']) === [$ctlUnbound, '/usr/local/sbin/pluginctl -c unbound_start']
        && $has($line, 'answered nothing', 'ran directly'));
    $out = $refusal($link, ['/' => [1, '']]);
    $line = $oneError($out);
    uu_check($t, '(R54) the same with both failing → the line says Unbound was not restarted, and to run configctl unbound restart',
        $out !== null && $out['rc'] === 1
        && $has($line, UU_RUN_DIR, 'not restarted', 'exited 1', 'configctl unbound restart'));
    $out = $refusal('cannot create ' . UU_RUN_DIR . '/removing', []);
    $line = $oneError($out);
    uu_check($t, '(R56) remove whose removal marker cannot be made → the same path: core\'s restart, one error naming the marker, exit 1',
        $out !== null && $out['rc'] === 1 && uu_test_acts($out['calls']) === [$ctlUnbound]
        && $has($line, 'cannot create ' . UU_RUN_DIR . '/removing', 'being removed', 'not confirmed'));
    /* the preparation returning is a trusted run dir with the marker in place */
    $prepared = function (): void {
    };
    $out = null;
    $ok = uu_try_case(function () use ($prepared, &$out): bool {
        $r = uu_test_runner();
        $out = ['rc' => uu_remove_prepare($prepared, $r['run'], $r['log']), 'calls' => $r['calls']];
        return true;
    });
    uu_check($t, '(R54) a trusted run dir with the marker made → null (the removal goes on), nothing run, nothing logged',
        $ok && $out !== null && $out['rc'] === null && count($out['calls']) === 0);

    // Task 10 M2: the lock-timeout error names the address the state records, else says <resolver>.
    $named = null;
    $generic = null;
    $ok = uu_try_case(function () use (&$named, &$generic): bool {
        $named = uu_remove_timeout_text('192.0.2.1');
        $generic = uu_remove_timeout_text(null);
        return true;
    });
    uu_check($t, '(M2) remove\'s lock-timeout remedy: route delete -host with the recorded address, else <resolver>',
        $ok && $has($named, 'being removed', '192.0.2.1', 'configctl unbound restart', 'route delete -host 192.0.2.1')
        && $has($generic, 'being removed', 'route delete -host <resolver>'));

    // Never planned, across every case above; flush_requestlist only behind the reject route (ruling R29: stop).
    $forbidden = ['flush', 'flush_zone', 'flush_bogus', 'flush_negative', 'reload', 'reload_keep_cache',
                  'fast_reload'];
    $clean = count($all) > 0;
    $previous = '';
    $onReject = false;
    $restartsExpected = false;
    $restartsOk = true;
    $restarts = 0;
    foreach ($all as $call) {
        if (str_starts_with($call, '-- case')) {
            $previous = '';
            $onReject = str_contains($call, ' on reject');
            $restartsExpected = str_contains($call, ' restarts');
            continue;
        }
        if ($call === 'restart') {
            $restarts++;
            $restartsOk = $restartsOk && $restartsExpected;
        }
        if (str_starts_with($call, 'uc ')) {
            $words = explode(' ', substr($call, 3));
            /* behind the reject route: just after it was installed, or first in a case that starts on it */
            $clean = $clean && !in_array($words[0], $forbidden, true)
                && ($words[0] !== 'flush_type' || $words === ['flush_type', '.', 'SOA'])
                && ($words[0] !== 'flush_requestlist' || ($previous === '' && $onReject)
                    || str_ends_with($previous, ' -reject'));
        }
        if (!str_starts_with($call, 'log ')) {
            $clean = $clean && !(str_starts_with($previous, 'route delete') && str_starts_with($call, 'route add'));
            $previous = $call;
        }
    }
    uu_check($t, 'no recorded call is ever flush, flush_zone, flush_bogus, flush_negative, reload, reload_keep_cache or fast_reload; flush_type only "<probe> SOA"; flush_requestlist only behind the reject route (every case above)',
        $clean);
    uu_check($t, '(a10) a restart only in the cases that expect one: a requested stop or a removal that cannot restore, a silent channel, the section 3.10 escalation (every case above)',
        $restartsOk && $restarts > 0);

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
