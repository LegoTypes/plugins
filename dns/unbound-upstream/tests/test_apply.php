<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Apply order and failure handling with a recording Io. Plans come from the real planner, so each case also pins the
 * planner input it depends on. The removal's core commands run through a recording runner.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/apply.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/corecmd.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/notify.php';
require_once __DIR__ . '/test_planner.php';
require_once __DIR__ . '/scratch.php';

/**
 * The planner's test snapshot with Unbound's live root as Unbound prints it: bare addresses, its own order.
 *
 * @return array{now: int, wall: int,
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
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, monitors: array<string, list<string>>, statics: array<string, list<string>>,
 *         unmonitored_members: list<string>, foreign: list<string>, member_resolvers: array<string, string>,
 *         resolver_notes: list<string>, no_next_hop: list<string>,
 *         rules: array{state: string, problems: list<string>},
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
 * A recording Io over a fake kernel and Unbound that follow the calls. Each address has a device, the one its last
 * route call chose (keyed by the argument after -host, canonical; 'reject' for the reject route, 'none' once deleted
 * or never routed), and the device of the probed address decides the direct probe's result; forward_add and
 * forward_remove set what `forward` prints, bare and in reverse order, as Unbound prints its own order. Every call is
 * also appended to $all after a "-- case" marker, which names the addresses that start on their reject route, so the
 * never-planned assertions see every case and where each starts.
 *
 * @param array{now: int, wall: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, default: string,
 *         rows: array<string, string>, failback_delay: int, probe_name: string},
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     routes: array<string, array{present: bool, gateway: string, interface: string, reject: bool,
 *         ours: bool}>} $s
 * @param ArrayObject<int, string> $all
 * @param array{direct?: array<string, list<bool>>, unbound?: list<bool>, uc_fail?: list<string>,
 *     uc_lost?: list<string>, forward_out?: string, route_fail?: list<string>, restart?: bool, silent?: bool,
 *     restart_live?: list<string>, throw_on?: string, restarts?: bool} $o
 *   direct: per device, successive direct probe results (true when absent or used up); unbound: successive
 *   through-Unbound results (true when used up); uc_fail and route_fail: commands or verbs that fail once each,
 *   in order (a route_fail entry "<verb> <address>" fails only that address's call); uc_lost: commands that take
 *   effect but whose reply is lost once each (null, as a timeout); forward_out: what `forward` prints instead of the
 *   fake's live root; silent: every unbound-control call times out (null) until a restart that sets restart_live as
 *   the live root; throw_on: the Io function that throws, after recording its call; restarts: the case expects a
 *   restart (the sweep at the end allows one nowhere else)
 * @return array{io: array{route: callable(string, list<string>): bool, sleep_ms: callable(int): void,
 *     probe_direct: callable(string, string): bool, probe_unbound: callable(string): bool,
 *     uc: callable(list<string>): ?string, restart_unbound: callable(): bool, log: callable(string, int): void,
 *     save: callable(array): void},
 *     calls: ArrayObject<int, string>,
 *     saved: ArrayObject<string, array{addresses: array<string, array{route: ?array{kind: string, next_hop: string,
 *         if: string}, forwarded: bool, released_at: ?int}>}>}
 *   saved holds the state the last save received under 'state'; saves are not in calls
 */
function uu_test_io(array $s, ArrayObject $all, array $o = []): array
{
    $calls = new ArrayObject();
    $dev = new ArrayObject();
    $onReject = [];
    foreach ($s['routes'] as $address => $route) {
        $dev[(string)$address] = $route['present'] ? ($route['reject'] ? 'reject' : $route['interface']) : 'none';
        if ($route['present'] && $route['reject']) {
            $onReject[] = (string)$address;
        }
    }
    /* the sweep at the end allows flush_requestlist only while an address is on its reject route, and a restart only
     * in a case that expects one */
    $all[] = '-- case' . (($o['restarts'] ?? false) ? ' restarts' : '')
        . ($onReject === [] ? '' : ' on reject ' . implode(',', $onReject));
    $record = function (string $call) use ($calls, $all): void {
        $calls[] = $call;
        $all[] = $call;
    };
    $live = new ArrayObject(['live' => $s['unbound']['live_root']]);
    $direct = new ArrayObject($o['direct'] ?? []);
    $unbound = new ArrayObject($o['unbound'] ?? []);
    $ucFail = new ArrayObject($o['uc_fail'] ?? []);
    $ucLost = new ArrayObject($o['uc_lost'] ?? []);
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
        'route' => function (string $verb, array $args) use ($record, $dev, $routeFail, $failOnce, $maybeThrow,
                                                             $all): bool {
            $record(trim("route $verb " . implode(' ', $args)));
            $maybeThrow('route');
            $at = array_search('-host', $args, true);
            $host = $at === false ? '' : (string)($args[$at + 1] ?? '');
            $host = uu_ip_canonical($host) ?? $host;
            if ($failOnce($routeFail, $verb) || $failOnce($routeFail, "$verb $host")) {
                /* for the sweep only: the kernel kept the route the call would have changed */
                $all[] = '-- route failed';
                return false;
            }
            if ($verb === 'delete') {
                $dev[$host] = 'none';
            } elseif (in_array('-reject', $args, true)) {
                $dev[$host] = 'reject';
            } else {
                $at = array_search('-ifp', $args, true);
                $dev[$host] = $at === false ? 'unknown' : (string)($args[$at + 1] ?? 'unknown');
            }
            return true;
        },
        'sleep_ms' => function (int $ms) use ($record): void {
            $record("sleep $ms");
        },
        'probe_direct' => function (string $resolver, string $name) use ($record, $dev, $direct, $maybeThrow): bool {
            $record("probe_direct $resolver $name");
            $maybeThrow('probe_direct');
            $device = (string)($dev[uu_ip_canonical($resolver) ?? $resolver] ?? 'none');
            $results = $direct[$device] ?? [];
            if ($results === []) {
                return true;
            }
            $ok = (bool)array_shift($results);
            $direct[$device] = $results;
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
        'uc' => function (array $args) use ($record, $live, $ucFail, $ucLost, $failOnce, $o, $silent,
                                            $maybeThrow): ?string {
            $record('uc ' . implode(' ', $args));
            $maybeThrow('uc');
            if ($silent['silent']) {
                return null;
            }
            $cmd = (string)($args[0] ?? '');
            $lost = $failOnce($ucLost, $cmd);
            if (!$lost && $failOnce($ucFail, $cmd)) {
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
            return $lost ? null : "ok\n";
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
 * The route record the state holds for an address; null when the map has no entry for it or the entry has none.
 *
 * @param array{addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *     forwarded: bool, released_at: ?int}>} $st
 * @return ?array{kind: string, next_hop: string, if: string}
 */
function uu_test_record(array $st, string $address = '10.2.0.1'): ?array
{
    return $st['addresses'][$address]['route'] ?? null;
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
    $toWgA = 'route add -inet -host 10.2.0.1 10.2.0.2 -ifp wg1';
    $changeToWgA = 'route change -inet -host 10.2.0.1 10.2.0.2 -ifp wg1';
    $changeToWgB = 'route change -inet -host 10.2.0.1 10.2.0.6 -ifp wg2';
    $probe = 'probe_direct 10.2.0.1 .';
    $through = ['uc flush_type . SOA', 'probe_unbound .'];
    $toResolver = 'uc forward_add . 10.2.0.1';
    $restoreDot = 'uc forward_add +t . 192.0.2.53@853#dns.example 2001:db8::53@853#dns.example';
    $reject = 'route change -inet -host 10.2.0.1 127.0.0.1 -reject';
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
    uu_check($t, 'entering: the state records the resolver its route and forwarders refer to',
        uu_state_footprint($st) === ['10.2.0.1'] && uu_state_footprint($r['saved']['state']) === ['10.2.0.1']);

    // (t6) One IPv6 resolver on an IPv6 member: the route, the forwarder and the checks follow the address's family.
    $v6 = '2001:db8:a::53';
    $v6Snapshot = function (string $hop, string $dev) use ($v6): array {
        $s6 = uu_test_apply_snapshot();
        $s6['tiers'] = [['wg-a6']];
        $s6['members'] = ['wg-a6' => ['name' => 'wg-a6', 'interface' => 'opt3', 'if' => $dev, 'next_hop' => $hop]
            + $s6['members']['wg-a']];
        $s6['probes'] = ['wg-a6' => $s6['probes']['wg-a']];
        $s6['block_table']['addresses'] = [$v6];
        return uu_test_default($s6, $v6);
    };
    $usable6 = ['wg-a6' => uu_test_timer(500, null, $now - 60)];
    $s6 = $v6Snapshot('fd00::3:2', 'wg3');
    $p = uu_plan($s6, uu_test_plan_state(null, $usable6));
    $r = uu_test_io($s6, $all);
    $st = uu_apply($p, $s6, $r['io']);
    uu_check($t, '(t6) entering on an IPv6 resolver: route add -inet6, sleep, probe, forward_add, flush_infra, forward',
        $p['action'] === 'tunnel' && $p['candidates'] === ['wg-a6']
        && uu_test_acts($r['calls']) === array_merge(['route add -inet6 -host ' . $v6 . ' fd00::3:2 -ifp wg3', $wait,
            'probe_direct ' . $v6 . ' .', 'uc forward_add . ' . $v6, 'uc flush_infra ' . $v6, 'uc forward'], $through)
        && $st['mode'] === 'tunnel' && $st['member'] === 'wg-a6' && uu_state_footprint($st) === [$v6]
        && uu_test_record($st, $v6) === ['kind' => 'member', 'next_hop' => 'fd00::3:2', 'if' => 'wg3']
        && uu_test_logged($r['calls'], LOG_NOTICE, 'route: ' . $v6 . ' via wg-a6 (fd00::3:2 on wg3)')
        && uu_test_logged($r['calls'], LOG_NOTICE, 'forwarders: . -> ' . $v6 . ', plain DNS inside the tunnel (no +t)'));
    $reject6 = 'route change -inet6 -host ' . $v6 . ' ::1 -reject';
    $s6 = uu_test_in_tunnel($v6Snapshot('fd00::3:2', 'wg3'), 'wg-a6');
    $s6['members']['wg-a6']['force_down'] = true;
    $p = uu_plan($s6, uu_test_plan_state('wg-a6', $usable6, 0, null, $v6, $s6));
    $r = uu_test_io($s6, $all);
    $st = uu_apply($p, $s6, $r['io']);
    uu_check($t, '(t6) fallback on an IPv6 resolver: the reject route is ::1 on -inet6, changed in place',
        $p['action'] === 'fallback' && uu_test_acts($r['calls']) === [$restoreDot, 'uc forward', $reject6]
        && $st['mode'] === 'fallback'
        && uu_test_record($st, $v6) === ['kind' => 'reject', 'next_hop' => '', 'if' => 'lo0']
        && uu_test_logged($r['calls'], LOG_NOTICE, 'route: ' . $v6 . ' rejected locally'));
    $s6 = uu_test_in_tunnel($v6Snapshot('fd00::3:2', 'wg3'), 'wg-a6');
    $s6['settings']['enabled'] = false;
    $p = uu_plan($s6, uu_test_plan_state('wg-a6', $usable6, 0, null, $v6, $s6));
    $r = uu_test_io($s6, $all);
    $st = uu_apply($p, $s6, $r['io']);
    uu_check($t, '(t6) stop on an IPv6 resolver ends in route delete -inet6 -host, and the record is cleared',
        $p['action'] === 'stop' && uu_test_acts($r['calls']) === [$restoreDot, 'uc forward', $reject6, $flushReq, $drain,
            'route delete -inet6 -host ' . $v6]
        && uu_state_footprint($st) === [] && uu_test_record($st, $v6) === null
        && uu_test_logged($r['calls'], LOG_NOTICE, 'route: ' . $v6 . ' deleted'));

    // (t7) A link-local next hop: route(8) gets it scoped to the device, and the route read back matches it.
    $s6 = $v6Snapshot('fe80::1', 'gif0');
    $p = uu_plan($s6, uu_test_plan_state(null, $usable6));
    $r = uu_test_io($s6, $all);
    $st = uu_apply($p, $s6, $r['io']);
    uu_check($t, '(t7) a link-local next hop is passed as fe80::1%gif0, and recorded as the member\'s own next hop',
        uu_test_acts($r['calls'])[0] === 'route add -inet6 -host ' . $v6 . ' fe80::1%gif0 -ifp gif0'
        && uu_test_record($st, $v6) === ['kind' => 'member', 'next_hop' => 'fe80::1', 'if' => 'gif0']
        && uu_test_logged($r['calls'], LOG_NOTICE, 'route: ' . $v6 . ' via wg-a6 (fe80::1 on gif0)'));
    $viaGif = ['present' => true, 'gateway' => 'fe80::1%gif0', 'interface' => 'gif0', 'reject' => false, 'ours' => true];
    uu_check($t, '(t7) the route read back with its scope is the member\'s route; another next hop or device is not',
        uu_try_case(fn (): bool => uu_plan_route_via($viaGif, $s6['members']['wg-a6'])
            && uu_plan_route_via(['gateway' => 'FE80:0::1%gif0'] + $viaGif, $s6['members']['wg-a6'])
            && !uu_plan_route_via(['gateway' => 'fe80::2%gif0'] + $viaGif, $s6['members']['wg-a6'])
            && !uu_plan_route_via(['interface' => 'gif1'] + $viaGif, $s6['members']['wg-a6'])));
    $s6 = uu_test_in_tunnel($v6Snapshot('fd00::3:2', 'wg3'), 'wg-a6');
    $s6 = uu_test_route($s6, ['gateway' => 'FD00:0::3:2'] + $s6['routes'][$v6]);
    $p = uu_plan($s6, uu_test_plan_state('wg-a6', $usable6, 0, null, $v6, $s6));
    $r = uu_test_io($s6, $all);
    uu_apply($p, $s6, $r['io']);
    uu_check($t, '(t7) a route whose next hop is the member\'s in another spelling is left alone: no route call',
        $p['action'] === 'none' && !$p['route_repair']
        && array_filter(uu_test_acts($r['calls']), fn (string $c): bool => str_starts_with($c, 'route ')) === []);

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
        && uu_test_acts($r['calls'])[1] === 'route add -inet -host 10.2.0.1 10.2.0.6 -ifp wg2'
        && uu_test_acts($r['calls'])[2] === $wait && $st['member'] === 'wg-b');

    // Stop.
    $s = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $s['settings']['enabled'] = false;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'stop with live root the resolver → forward_add +t then route delete; never a restart',
        $p['action'] === 'stop'
        && uu_test_acts($r['calls']) === [$restoreDot, 'uc forward', $reject, $flushReq, $drain, 'route delete -inet -host 10.2.0.1']
        && $st['mode'] === 'fallback' && $st['member'] === null && $st['last_switch'] !== null
        && $st['last_switch']['to'] === 'fallback');
    uu_check($t, 'a finished stop clears the recorded resolver: nothing refers to it any more',
        uu_state_footprint($st) === [] && uu_state_footprint($r['saved']['state']) === []);
    uu_check($t, 'stop drains: restore, reject route, flush_requestlist, then fib_sync + 500 ms + UU_STOP_DRAIN_SECONDS (2500 ms), then delete',
        UU_STOP_DRAIN_SECONDS === 1 && $drain === 'sleep 2500');

    $r = uu_test_io($s, $all, ['uc_fail' => ['flush_requestlist']]);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'stop whose flush_requestlist fails → the reject route stays (a retry would leave by a WAN), recorded, logged',
        uu_test_acts($r['calls']) === [$restoreDot, 'uc forward', $reject, $flushReq]
        && $st['mode'] === 'fallback' && uu_test_record($st) === ['kind' => 'reject', 'next_hop' => '', 'if' => 'lo0']
        && uu_state_footprint($st) === ['10.2.0.1']
        && uu_test_logged($r['calls'], LOG_ERR, 'flush_requestlist failed'));
    $wgARecord = ['kind' => 'member', 'next_hop' => '10.2.0.2', 'if' => 'wg1'];
    $recordedWgA = uu_test_plan_state('wg-a', $usable);
    $recordedWgA['addresses'] = ['10.2.0.1' => ['route' => $wgARecord, 'forwarded' => true, 'released_at' => null]];
    $r = uu_test_io($s, $all, ['route_fail' => ['change', 'add']]);
    $st = uu_apply(uu_plan($s, $recordedWgA), $s, $r['io']);
    uu_check($t, 'stop whose reject route fails → the member route stays, never deleted, its record kept, logged',
        uu_test_acts($r['calls']) === [$restoreDot, 'uc forward', $reject, 'route add -inet -host 10.2.0.1 127.0.0.1 -reject']
        && $st['mode'] === 'fallback' && uu_test_record($st) === $wgARecord
        && uu_test_logged($r['calls'], LOG_ERR, 'no reject route'));

    $gap = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $gap['settings']['enabled'] = false;
    $gap = uu_test_route($gap, ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false,
                                'ours' => false]);
    $p = uu_plan($gap, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($gap, $all);
    $st = uu_apply($p, $gap, $r['io']);
    uu_check($t, 'stop in tunnel mode with the route missing (a route-loss window) → reject route added, flush, drain, delete',
        $p['action'] === 'stop'
        && uu_test_acts($r['calls']) === [$restoreDot, 'uc forward', 'route add -inet -host 10.2.0.1 127.0.0.1 -reject',
            $flushReq, $drain, 'route delete -inet -host 10.2.0.1']
        && $st['mode'] === 'fallback' && uu_test_record($st) === null);

    $s = uu_test_apply_snapshot();
    $s['settings']['enabled'] = false;
    $p = uu_plan($s, uu_test_plan_state(null));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'stop with nothing of the plugin\'s live → no calls at all, not even a log line',
        $p['action'] === 'stop' && $r['calls']->getArrayCopy() === [] && $st === $p['state']);

    $s = uu_test_apply_snapshot();
    $s['settings']['enabled'] = false;
    $s = uu_test_route($s, ['present' => true, 'gateway' => '', 'interface' => 'lo0', 'reject' => true,
                            'ours' => true]);
    $p = uu_plan($s, uu_test_plan_state(null));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'stop in fallback → flush_requestlist (a recent fallback leaves retries), drain, our reject route deleted; forwarders untouched',
        uu_test_acts($r['calls']) === [$flushReq, $drain, 'route delete -inet -host 10.2.0.1'] && $st['mode'] === 'fallback');

    /* a route record that outlived its route (the kernel deleted it) must not pin the address */
    $s = uu_test_apply_snapshot();
    $s['settings']['enabled'] = false;
    $stale = uu_test_plan_state(null);
    $stale['addresses'] = ['10.2.0.1' => ['route' => ['kind' => 'member', 'next_hop' => '10.2.0.2', 'if' => 'wg1'],
                                          'forwarded' => false, 'released_at' => null]];
    $p = uu_plan($s, $stale);
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'stop in fallback with a stale route record and no route → no calls, the resolver no longer recorded',
        $p['action'] === 'stop' && uu_test_acts($r['calls']) === [] && uu_state_footprint($st) === []);

    $s = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $s['unbound'] = ['enabled' => true, 'pid_alive' => false, 'control_ok' => false, 'live_root' => null];
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'Unbound not running in tunnel mode → route deleted, no unbound-control call, fallback',
        $p['action'] === 'stop' && uu_test_acts($r['calls']) === ['route delete -inet -host 10.2.0.1']
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
        && uu_test_logged($r['calls'], LOG_NOTICE, '[dry]', 'route -n add -inet -host 10.2.0.1 10.2.0.2 -ifp wg1')
        && uu_test_logged($r['calls'], LOG_NOTICE, '[dry]', 'forward_add . 10.2.0.1'));

    $s = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $s['settings']['dry_run'] = true;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'dry run turned on in tunnel mode → the plugin\'s live changes are undone for real (stop)',
        uu_test_acts($r['calls']) === [$restoreDot, 'uc forward', $reject, $flushReq, $drain, 'route delete -inet -host 10.2.0.1']
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
    $s = uu_test_route($s, ['present' => true, 'gateway' => '192.0.2.99', 'interface' => 'igc0', 'reject' => false,
                            'ours' => false]);
    $s['contract_input']['foreign'] = ['10.2.0.1'];
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
        && uu_test_acts($r['calls']) === ['route add -inet -host 10.2.0.1 127.0.0.1 -reject'] && $st['mode'] === 'fallback');

    $s = uu_test_apply_snapshot();
    $p = uu_plan($s, uu_test_plan_state(null, $usable));
    $r = uu_test_io($s, $all, ['uc_fail' => ['forward_add']]);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'entry forward_add refused → no other candidate, fallback restores (the add may have landed), reject',
        uu_test_acts($r['calls']) === [$toWgA, $wait, $probe, $toResolver, $restoreDot, 'uc forward',
            'route change -inet -host 10.2.0.1 127.0.0.1 -reject']
        && $st['mode'] === 'fallback' && $st['timers']['wg-a']['resolver_failed_until'] === null);

    // The route the plugin installed: recognised by the state's record when no member matches.
    $memberRecord = ['kind' => 'member', 'next_hop' => '10.2.0.2', 'if' => 'wg1'];
    $rejectRecord = ['kind' => 'reject', 'next_hop' => '', 'if' => 'lo0'];
    $s = uu_test_apply_snapshot();
    $p = uu_plan($s, uu_test_plan_state(null, $usable));
    $st = uu_apply($p, $s, uu_test_io($s, $all)['io']);
    uu_check($t, 'a route add or change via a member is recorded in the state', uu_test_record($st) === $memberRecord);
    $s = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $s['probes']['wg-a'] = $settledDown;
    $s['probes']['wg-b'] = $settledDown;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $st = uu_apply($p, $s, uu_test_io($s, $all)['io']);
    uu_check($t, 'the reject route is recorded as kind reject on lo0', uu_test_record($st) === $rejectRecord);
    $s = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $s['settings']['enabled'] = false;
    $recorded = uu_test_plan_state('wg-a', $usable);
    $recorded['addresses'] = ['10.2.0.1' => ['route' => $memberRecord, 'forwarded' => true, 'released_at' => null]];
    $p = uu_plan($s, $recorded);
    $st = uu_apply($p, $s, uu_test_io($s, $all)['io']);
    uu_check($t, 'a successful route delete clears the record', uu_test_record($st) === null);
    $r = uu_test_io($s, $all, ['route_fail' => ['delete']]);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'a failed route delete keeps the record (of the reject route the drain put in place)',
        uu_test_record($st) === $rejectRecord);

    $gone = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $gone['tiers'] = [];
    $gone['members'] = [];
    $gone['probes'] = [];
    $gone = uu_test_route($gone, ['ours' => false] + $gone['routes']['10.2.0.1']);
    $gone['contract_input']['group_found'] = false;
    $gone['contract_input']['members'] = 0;
    $gone['contract_input']['foreign'] = ['10.2.0.1'];
    /* the state's map holding a route record for the resolver, or nothing */
    $map = fn (?array $record): array => $record === null ? []
        : ['10.2.0.1' => ['route' => $record, 'forwarded' => true, 'released_at' => null]];
    $adopted = uu_route_adopt($gone, $map($memberRecord));
    uu_check($t, 'a live route equal to the recorded one is ours, and no longer a foreign-route contract failure',
        $adopted['routes']['10.2.0.1']['ours'] && $adopted['contract_input']['foreign'] === []
        && uu_route_adopt($gone, $map(null)) === $gone);
    $p = uu_plan($adopted, $recorded);
    $r = uu_test_io($adopted, $all);
    $st = uu_apply($p, $adopted, $r['io']);
    uu_check($t, 'group deleted in tunnel mode with our recorded route → fallback replaces it with the reject route',
        $p['action'] === 'fallback' && uu_test_acts($r['calls']) === [$restoreDot, 'uc forward', $reject]
        && $st['mode'] === 'fallback' && uu_test_record($st) === $rejectRecord);
    $off = $adopted;
    $off['settings']['enabled'] = false;
    $p = uu_plan($off, $recorded);
    $r = uu_test_io($off, $all);
    $st = uu_apply($p, $off, $r['io']);
    uu_check($t, 'group deleted in tunnel mode, then stop → our recorded route deleted',
        $p['action'] === 'stop'
        && uu_test_acts($r['calls']) === [$restoreDot, 'uc forward', $reject, $flushReq, $drain, 'route delete -inet -host 10.2.0.1']
        && $st['mode'] === 'fallback' && uu_test_record($st) === null);

    $other = $memberRecord;
    $other['next_hop'] = '10.2.0.9';
    $foreign = uu_route_adopt($gone, $map($other));
    $p = uu_plan($foreign, $recorded);
    $r = uu_test_io($foreign, $all);
    $st = uu_apply($p, $foreign, $r['io']);
    uu_check($t, 'a route matching neither the record nor a member stays foreign and untouched',
        $foreign === $gone && $p['action'] === 'fallback' && uu_test_acts($r['calls']) === [$restoreDot, 'uc forward']
        && $st['addresses'] === []);
    $off = $foreign;
    $off['settings']['enabled'] = false;
    $p = uu_plan($off, $recorded);
    $r = uu_test_io($off, $all);
    uu_apply($p, $off, $r['io']);
    uu_check($t, 'stop never deletes that foreign route',
        $p['action'] === 'stop' && uu_test_acts($r['calls']) === [$restoreDot, 'uc forward']);
    $rejectLive = $gone;
    $rejectLive = uu_test_route($rejectLive, ['present' => true, 'gateway' => '', 'interface' => 'lo0',
                                              'reject' => true, 'ours' => false]);
    uu_check($t, 'a member route is not adopted by a reject record, nor a reject route by a member record',
        uu_route_adopt($gone, $map($rejectRecord)) === $gone
        && uu_route_adopt($rejectLive, $map($memberRecord)) === $rejectLive
        && uu_route_adopt($rejectLive, $map($rejectRecord))['routes']['10.2.0.1']['ours']);
    $absent = $gone;
    $absent = uu_test_route($absent, ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false,
                                      'ours' => false]);
    uu_check($t, 'no live route: nothing to adopt', uu_route_adopt($absent, $map($memberRecord)) === $absent);

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
    $s = uu_test_route($s, ['reject' => true, 'interface' => 'lo0', 'gateway' => ''] + $s['routes']['10.2.0.1']);
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
        $p['action'] === 'none' && uu_test_acts($r['calls']) === ['route add -inet -host 10.2.0.1 127.0.0.1 -reject']
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

    /* with the zone configuration unreadable, neither a fallback nor a stop guesses: no forward_remove .
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

    // Stop with a silent control channel and saving mid-apply.
    $silentTunnel = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $silentTunnel['unbound']['control_ok'] = false;
    $silentTunnel['unbound']['live_root'] = null;
    $silentStop = $silentTunnel;
    $silentStop['settings']['enabled'] = false;
    /* a disabled plugin's tick restarts only once the planner's bound is reached: this state is one
     * silent evaluation short of it */
    $atBound = uu_test_plan_state('wg-a', $usable, UU_ESCALATE_EVALUATIONS - 1, $now - UU_ESCALATE_MIN_SECONDS);
    $p = uu_plan($silentStop, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($silentStop, $all, ['silent' => true, 'restart_live' => ['192.0.2.53', '2001:db8::53']]);
    $st = uu_apply($p, $silentStop, $r['io']);
    uu_check($t, 'a disabled tick with a silent channel short of the bound → the restore tried, no restart, the route stays, still tunnel',
        $p['action'] === 'stop' && !$p['escalate_restart'] && uu_test_acts($r['calls']) === [$restoreDot]
        && $st['mode'] === 'tunnel' && $st['member'] === 'wg-a'
        && uu_state_footprint($st) === [$silentStop['settings']['default']] && uu_test_logged($r['calls'], LOG_ERR, 'route stays'));
    $p = uu_plan($silentStop, $atBound);
    $r = uu_test_io($silentStop, $all, ['silent' => true, 'restart_live' => ['192.0.2.53', '2001:db8::53'],
        'restarts' => true]);
    $st = uu_apply($p, $silentStop, $r['io']);
    uu_check($t, 'stop in tunnel mode with a silent channel at the bound → restart, the configured root confirmed, then reject, drain, delete',
        $p['action'] === 'stop'
        && uu_test_acts($r['calls']) === [$restoreDot, 'restart', 'uc forward', $reject, $flushReq, $drain, 'route delete -inet -host 10.2.0.1']
        && $st['mode'] === 'fallback' && uu_test_record($st) === null
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

    // Only a requested stop and the removal restart at once for a silent channel; every other stop waits
    // for the bound.
    $silentTail = [$restoreDot, 'restart', 'uc forward', $reject, $flushReq, $drain,
        'route delete -inet -host ' . $silentTunnel['settings']['default']];
    $silentRoot = ['192.0.2.53', '2001:db8::53'];
    foreach ([UU_STOP_REQUEST => 'a requested stop', UU_STOP_REMOVE => 'the removal'] as $cause => $what) {
        $immediate = $silentTunnel;
        $immediate['stop'] = $cause;
        $p = uu_plan($immediate, uu_test_plan_state('wg-a', $usable));
        $r = uu_test_io($immediate, $all, ['silent' => true, 'restart_live' => $silentRoot, 'restarts' => true]);
        $st = uu_apply($p, $immediate, $r['io']);
        uu_check($t, "$what, silent channel, fresh count → restart at once, then the tail",
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
        $thrown && isset($r['saved']['state']) && uu_test_record($r['saved']['state']) === $memberRecord);
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, 'the state is saved after each successful change (the last save is the returned state)',
        isset($r['saved']['state']) && $r['saved']['state'] === $st);

    // A stop that cannot restore: a requested stop and a removal restart Unbound
    // on any restore failure; a removal that still cannot restore leaves the reject route.
    $fp = uu_test_apply_snapshot();
    $fp = uu_test_default($fp, '192.0.2.1');
    $fp = uu_test_in_tunnel($fp, 'wg-a');
    $fpRoot = ['192.0.2.53', '2001:db8::53'];
    $fpReject = 'route change -inet -host 192.0.2.1 127.0.0.1 -reject';
    $fpTail = [$fpReject, $flushReq, $drain, 'route delete -inet -host 192.0.2.1'];
    $fpRefused = ['uc_fail' => ['forward_add'], 'restart_live' => $fpRoot];
    $stopAs = function (array $s, ?string $cause, array $o) use ($all, $usable): array {
        $s['stop'] = $cause;
        $p = uu_plan($s, uu_test_plan_state('wg-a', $usable, 0, null, $s['settings']['default']));
        $r = uu_test_io($s, $all, $o);
        $st = uu_apply($p, $s, $r['io']);
        return ['action' => $p['action'], 'calls' => $r['calls'], 'acts' => uu_test_acts($r['calls']), 'st' => $st,
                'saved' => $r['saved']];
    };
    $cleared = fn (array $st): bool => $st['mode'] === 'fallback' && $st['member'] === null
        && uu_state_footprint($st) === [] && uu_test_record($st) === null;
    $lastResort = fn (array $run): bool => !in_array('route delete -inet -host 192.0.2.1', $run['acts'], true)
        && uu_state_footprint($run['st']) === ['192.0.2.1'] && uu_state_footprint($run['saved']['state']) === ['192.0.2.1']
        && uu_test_record($run['st'], '192.0.2.1') === $rejectRecord
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
    /* an unreadable zone configuration is unrestorable, so these stops restart at once as well (a library
     * whose uu_root_zone() takes no null throws here, and the cases after these still run) */
    $unreadable = null;
    try {
        $unreadable = $fp;
        $unreadable['zone'] = uu_root_zone(null);
        $unreadable['contract_input']['zone'] = $unreadable['zone'];
    } catch (\Throwable $e) {
        printf("  threw %s: %s\n", get_class($e), $e->getMessage());
        $unreadable = null;
    }
    foreach ([UU_STOP_REQUEST => 'requested stop', UU_STOP_REMOVE => 'removal'] as $cause => $what) {
        $run = $unreadable === null ? null
            : $stopAs($unreadable, $cause, ['restart_live' => $fpRoot, 'restarts' => true]);
        uu_check($t, "(a2) $what with the zone configuration unreadable → restart at once, then the same tail",
            $run !== null && $run['action'] === 'stop'
            && $run['acts'] === array_merge(['restart', 'uc forward'], $fpTail) && $cleared($run['st'])
            && uu_test_logged($run['calls'], LOG_ERR, 'configuration unreadable'));
    }

    $keeps = $fp;
    $keeps['settings']['enabled'] = false;
    $keeps['contract_input']['cacheflush'] = true;
    $run = $stopAs($keeps, UU_STOP_REQUEST, $fpRefused);
    $warned = array_values(array_filter($run['calls']->getArrayCopy(),
        fn (string $c): bool => str_starts_with($c, 'log ' . LOG_WARNING . ' ')));
    uu_check($t, '(a3) requested stop disabling the plugin, cacheflush on, restore refused → no restart, no route call, still tunnel, the resolver recorded, one warning that its block stays',
        $run['action'] === 'stop' && $run['acts'] === [$restoreDot] && $run['st']['mode'] === 'tunnel'
        && $run['st']['member'] === 'wg-a' && uu_state_footprint($run['st']) === ['192.0.2.1'] && count($warned) === 1
        && str_contains($warned[0], '192.0.2.1') && str_contains($warned[0], 'block stays'));
    $keepsOn = $keeps;
    $keepsOn['settings']['enabled'] = true;
    foreach (["a disabled plugin's tick" => [$keeps, null],
              'a requested stop with the plugin enabled' => [$keepsOn, UU_STOP_REQUEST]] as $what => [$case, $cause]) {
        $run = $stopAs($case, $cause, $fpRefused);
        uu_check($t, "(a3) $what, cacheflush on, restore refused → no restart, the route stays, no footprint warning",
            $run['action'] === 'stop' && $run['acts'] === [$restoreDot] && uu_state_footprint($run['st']) === ['192.0.2.1']
            && !uu_test_logged($run['calls'], LOG_WARNING, 'block stays'));
    }

    $flushOn = $fp;
    $flushOn['contract_input']['cacheflush'] = true;
    $run = $stopAs($flushOn, UU_STOP_REMOVE, $fpRefused + ['restarts' => true]);
    uu_check($t, '(a4) removal, cacheflush on, restore refused → restart anyway (by design), then the tail',
        $run['action'] === 'stop' && $run['acts'] === array_merge([$restoreDot, 'restart', 'uc forward'], $fpTail)
        && $cleared($run['st']));

    $run = $stopAs($fp, UU_STOP_REMOVE, ['uc_fail' => ['forward_add'], 'restart' => false, 'restarts' => true]);
    uu_check($t, '(a5) removal whose restart fails → the reject route over the member route as the last resort, never a delete, the resolver still recorded, logged',
        $run['action'] === 'stop' && $run['acts'] === [$restoreDot, 'restart', $fpReject] && $lastResort($run));
    uu_check($t, '(a5) the removal\'s last-resort remedy names the IPv4 delete exactly as before',
        uu_test_logged($run['calls'], LOG_ERR, 'being removed', 'configctl unbound restart, then route delete -host '
            . '192.0.2.1')
        && !uu_test_logged($run['calls'], LOG_ERR, '-inet6'));
    $fp6 = uu_test_in_tunnel($v6Snapshot('fd00::3:2', 'wg3'), 'wg-a6');
    $fp6['stop'] = UU_STOP_REMOVE;
    $p = uu_plan($fp6, uu_test_plan_state('wg-a6', $usable6, 0, null, $v6, $fp6));
    $r = uu_test_io($fp6, $all, ['uc_fail' => ['forward_add'], 'restart' => false, 'restarts' => true]);
    uu_apply($p, $fp6, $r['io']);
    uu_check($t, '(a5) the same for an IPv6 resolver → the remedy names route delete -inet6 -host, the form route(8) takes',
        uu_test_logged($r['calls'], LOG_ERR, 'being removed', 'rejected locally',
            'configctl unbound restart, then route delete -inet6 -host ' . $v6)
        && !uu_test_logged($r['calls'], LOG_ERR, 'route delete -host'));
    $fpGap = $fp;
    $fpGap = uu_test_route($fpGap, ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false,
                                    'ours' => false]);
    $run = $stopAs($fpGap, UU_STOP_REMOVE, ['uc_fail' => ['forward_add'], 'restart' => false, 'restarts' => true]);
    uu_check($t, '(a5) the same with the route missing (a route-loss window) → the reject route added',
        $run['acts'] === [$restoreDot, 'restart', 'route add -inet -host 192.0.2.1 127.0.0.1 -reject'] && $lastResort($run));
    /* nothing changed, so nothing was saved mid-run: the returned state is what evaluate.php saves */
    $noReject = fn (array $run): bool => !in_array('route delete -inet -host 192.0.2.1', $run['acts'], true)
        && uu_state_footprint($run['st']) === ['192.0.2.1'] && uu_test_record($run['st'], '192.0.2.1') !== $rejectRecord
        && !uu_test_logged($run['calls'], LOG_ERR, 'rejected locally')
        && uu_test_logged($run['calls'], LOG_ERR, 'being removed', '192.0.2.1', 'could not be made a reject route',
            'configctl unbound restart');
    $run = $stopAs($fp, UU_STOP_REMOVE, ['uc_fail' => ['forward_add'], 'restart' => false,
                                         'route_fail' => ['change', 'add'], 'restarts' => true]);
    uu_check($t, '(a5) removal whose restart fails and whose reject route cannot be made → the member route kept, never deleted, the resolver recorded, an error naming the removal and the remedy',
        $run['acts'] === [$restoreDot, 'restart', $fpReject, 'route add -inet -host 192.0.2.1 127.0.0.1 -reject']
        && $noReject($run));
    $fpForeign = $fp;
    $fpForeign = uu_test_route($fpForeign, ['present' => true, 'gateway' => '192.0.2.99', 'interface' => 'igc0',
                                            'reject' => false, 'ours' => false]);
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
        && uu_state_footprint($run['st']) === ['192.0.2.1'] && uu_test_logged($run['calls'], LOG_ERR, 'route stays'));

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

    // A tick while the removal marker exists is a stop with the ticks' rules: a restart only for a silent
    // channel at the bound, no cacheflush override, never the reject route. remove itself keeps both
    // (a4 to a8 above).
    $tick = null;
    $ok = uu_try_case(function () use ($stopAs, $fp, $fpRefused, &$tick): bool {
        $tick = $stopAs($fp, uu_plan_causes(null, true)['run'], $fpRefused);
        return true;
    });
    uu_check($t, 'a tick while the removal marker exists, restore refused, channel answering → no restart, no reject route, the route stays, the resolver recorded',
        $ok && $tick !== null && $tick['action'] === 'stop' && $tick['acts'] === [$restoreDot]
        && $tick['st']['mode'] === 'tunnel' && uu_state_footprint($tick['st']) === ['192.0.2.1']
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
        return $st['mode'] === 'fallback' && uu_state_footprint($st) === [];
    });
    uu_check($t, 'a tick while the removal marker exists, silent channel → no restart before the third tick, at 120 s, then one restart and the tail',
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
    uu_check($t, 'the same tick at the bound whose restart fails → never the reject route: the route stays, still tunnel',
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
    uu_check($t, 'the same tick at the bound with cacheflush on → no restart (only remove itself overrides cacheflush), the route stays',
        $ok && $tick !== null && uu_test_acts($tick['calls']) === [$restoreDot] && $tick['st']['mode'] === 'tunnel'
        && uu_test_logged($tick['calls'], LOG_ERR, 'cacheflush'));

    // A removal's core commands: through configd when configctl exits 0 within
    // UU_CONFIGD_TIMEOUT_SECONDS with the reply OK, else core's own script.
    /* configctl's stdout is read (timeout bounds it); core's own command writes to /dev/null, so a child it leaves
     * running cannot hold the runner's pipe open */
    $ctlReload = '/usr/bin/timeout 30 /usr/local/sbin/configctl filter reload 2> /dev/null';
    $ctlCron = '/usr/bin/timeout 30 /usr/local/sbin/configctl cron restart 2> /dev/null';
    $ctlUnbound = '/usr/bin/timeout 30 /usr/local/sbin/configctl unbound restart 2> /dev/null';
    $dReload = '/usr/local/etc/rc.filter_configure > /dev/null 2>&1';
    $dCron = '/usr/local/sbin/pluginctl -s cron restart > /dev/null 2>&1';
    $dUnbound = '/usr/local/sbin/pluginctl -c unbound_start > /dev/null 2>&1';
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
        && $out[2] === [$ctlReload, $dReload, $ctlCron, $dCron]
        && $field($out, 0, 'configd') === 'did not answer (configctl exit 1)');
    $out = $core([$ctl => [124, '']]);
    uu_check($t, '(d1) configctl timed out (exit 124) → direct, said as a timeout',
        $paths($out) === ['direct', 'direct'] && $out[2][1] === $dReload
        && $field($out, 0, 'configd') === 'did not answer within 30 s (configctl exit 124)');
    $out = $core([]);
    uu_check($t, '(d2) configd answering OK → configd for each, only the two configctl lines',
        $paths($out) === ['configd', 'configd'] && $out[2] === [$ctlReload, $ctlCron]);
    $out = $core(['/' => [1, '']]);
    uu_check($t, '(d3) configd and core\'s script both failing → failed, with the script\'s exit status',
        $paths($out) === ['failed', 'failed'] && $out[2] === [$ctlReload, $dReload, $ctlCron, $dCron]
        && $field($out, 0, 'rc') === 1);
    $out = $core([$ctl => [1, '']]);
    uu_check($t, 'core\'s own command runs with its output to /dev/null, configctl with only its stderr there',
        is_array($out[2] ?? null) && count($out[2]) === 4
        && str_ends_with($out[2][1], ' > /dev/null 2>&1') && str_ends_with($out[2][3], ' > /dev/null 2>&1')
        && str_ends_with($out[2][0], ' 2> /dev/null') && !str_contains($out[2][0], '>/dev/null 2>&1')
        && !str_contains($out[2][0], '> /dev/null 2>&1'));
    $replies = [
        'an error reply' => ["Error (1)\n", "answered 'Error (1)'"],
        'no reply' => ['', 'answered nothing'],
        'Action not found' => ["Action not found\n", "answered 'Action not found'"],
        'a reply of several lines' => ["Execute error\nmore\n", "answered 'Execute error'"],
    ];
    foreach ($replies as $what => [$reply, $said]) {
        $out = $core([$ctl => [0, $reply]]);
        uu_check($t, "configctl exiting 0 with $what → direct for each, configd's reply named by its first line",
            $paths($out) === ['direct', 'direct'] && $out[2] === [$ctlReload, $dReload, $ctlCron, $dCron]
            && $field($out, 0, 'configd') === $said);
    }
    $out = $core([$ctl => [0, "  OK  \n"]]);
    uu_check($t, 'OK with blanks around it is OK', $paths($out) === ['configd', 'configd']);
    $out = $core([$ctl => [0, "Error \x1b[31mred\x07" . str_repeat('x', 300) . "\n"]]);
    uu_check($t, 'a reply\'s first line is cleaned of control bytes and cut short',
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
    uu_check($t, 'remove after its stop, configd answering OK → the filter reload, then the cron restart, through configd, each logged',
        $calls !== null && uu_test_acts($calls) === [$ctlReload, $ctlCron]
        && uu_test_logged($calls, LOG_NOTICE, 'filter reload', 'through configd')
        && uu_test_logged($calls, LOG_NOTICE, 'cron restart', 'through configd'));
    $calls = $removal([$ctl => [255, '']]);
    uu_check($t, 'remove after its stop, no configd socket (exit 255) → core\'s two scripts directly, each logged with configctl\'s exit and the command it ran, no "30 s"',
        $calls !== null && uu_test_acts($calls) === [$ctlReload, $dReload, $ctlCron, $dCron]
        && uu_test_logged($calls, LOG_WARNING, 'filter reload', 'did not answer (configctl exit 255)',
            '/usr/local/etc/rc.filter_configure', 'ran directly')
        && uu_test_logged($calls, LOG_WARNING, 'cron restart', 'did not answer (configctl exit 255)',
            '/usr/local/sbin/pluginctl -s cron restart')
        && !uu_test_logged($calls, LOG_WARNING, '30 s'));
    $calls = $removal([$ctl => [0, "Error (1)\n"]]);
    uu_check($t, 'remove after its stop, configd answering Error (1) → core\'s two scripts directly, the reply named, never "through configd"',
        $calls !== null && uu_test_acts($calls) === [$ctlReload, $dReload, $ctlCron, $dCron]
        && uu_test_logged($calls, LOG_WARNING, 'filter reload', "answered 'Error (1)'", 'ran directly')
        && !uu_test_logged($calls, LOG_NOTICE, 'through configd')
        && !uu_test_logged($calls, LOG_WARNING, 'through configd'));
    $calls = $removal(['/' => [1, '']]);
    uu_check($t, 'remove after its stop, both failing → an error for each, with both exits, saying what is left',
        $calls !== null && uu_test_logged($calls, LOG_ERR, 'filter reload', 'configctl exit 1', 'exited 1', 'until')
        && uu_test_logged($calls, LOG_ERR, 'cron restart', 'configctl exit 1', 'exited 1', 'until'));

    // A removal whose run directory cannot be trusted, or whose removal marker cannot be made,
    // takes no lock, reads no state, has core restart Unbound and says in one error what ran, that it is not
    // confirmed, and the remedy.
    $refusal = function (string $problem, array $codes): ?array {
        $out = null;
        $ok = uu_try_case(function () use ($problem, $codes, &$out): bool {
            $r = uu_test_runner($codes);
            $trust = function () use ($problem): void {
                throw new RuntimeException($problem);
            };
            $mark = function (): void {
                throw new LogicException('test: the marker is not made after a refused run dir');
            };
            $out = ['rc' => uu_remove_prepare($trust, $mark, $r['run'], $r['log']), 'calls' => $r['calls']];
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
    uu_check($t, 'remove with an untrusted run dir → exit 1, core\'s restart through configd, one error naming the run dir and the removal, saying the restart ran but is not confirmed, with the remedy',
        $out !== null && $out['rc'] === 1 && uu_test_acts($out['calls']) === [$ctlUnbound]
        && $has($line, UU_RUN_DIR, 'symbolic link', 'being removed', 'ran through configd', 'not confirmed',
            'configctl unbound restart', 'route delete -host')
        && !$has($line, 'not restarted') && !$has($line, 'onto its configured root zone'));
    $out = $refusal($link, [$ctl => [1, '']]);
    $line = $oneError($out);
    uu_check($t, 'the same with configd not answering → core\'s own restart run directly, and the line says so, not confirmed',
        $out !== null && $out['rc'] === 1
        && uu_test_acts($out['calls']) === [$ctlUnbound, $dUnbound]
        && $has($line, UU_RUN_DIR, 'did not answer (configctl exit 1)', '/usr/local/sbin/pluginctl -c unbound_start',
            'ran directly', 'not confirmed', 'configctl unbound restart') && !$has($line, 'not restarted'));
    $out = $refusal($link, [$ctl => [0, "Error (1)\n"]]);
    $line = $oneError($out);
    uu_check($t, 'the same with configd answering Error (1) → core\'s own restart run directly, the reply named, never "through configd"',
        $out !== null && uu_test_acts($out['calls']) === [$ctlUnbound, $dUnbound]
        && $has($line, "answered 'Error (1)'", 'ran directly') && !$has($line, 'through configd'));
    $out = $refusal($link, [$ctl => [0, '']]);
    $line = $oneError($out);
    uu_check($t, 'the same with no reply → core\'s own restart run directly',
        $out !== null && uu_test_acts($out['calls']) === [$ctlUnbound, $dUnbound]
        && $has($line, 'answered nothing', 'ran directly'));
    $out = $refusal($link, ['/' => [1, '']]);
    $line = $oneError($out);
    uu_check($t, 'the same with both failing → the line says Unbound was not restarted, and to run configctl unbound restart',
        $out !== null && $out['rc'] === 1
        && $has($line, UU_RUN_DIR, 'not restarted', 'exited 1', 'configctl unbound restart'));
    /* a trusted run dir whose removal marker cannot be made still has its lock and state: the removal's own stop */
    $out = null;
    $ok = uu_try_case(function () use (&$out): bool {
        $r = uu_test_runner();
        $mark = function (): void {
            throw new RuntimeException('cannot create ' . UU_RUN_DIR . '/removing');
        };
        $out = ['rc' => uu_remove_prepare(function (): void {
        }, $mark, $r['run'], $r['log']), 'calls' => $r['calls']];
        return true;
    });
    $line = $oneError($out);
    uu_check($t, 'remove whose removal marker cannot be made in a trusted run dir → no restart, one error naming the marker and the window, the removal goes on under the lock (null)',
        $ok && $out !== null && $out['rc'] === null && uu_test_acts($out['calls']) === []
        && $has($line, 'cannot create ' . UU_RUN_DIR . '/removing', 'being removed', 'stop runs as usual',
            'configctl unbound restart', 'route delete -host')
        && !$has($line, 'ran through configd'));
    /* the preparation returning is a trusted run dir with the marker in place */
    $prepared = function (): void {
    };
    $out = null;
    $ok = uu_try_case(function () use ($prepared, &$out): bool {
        $r = uu_test_runner();
        $out = ['rc' => uu_remove_prepare($prepared, $prepared, $r['run'], $r['log']), 'calls' => $r['calls']];
        return true;
    });
    uu_check($t, 'a trusted run dir with the marker made → null (the removal goes on), nothing run, nothing logged',
        $ok && $out !== null && $out['rc'] === null && count($out['calls']) === 0);

    // A removal whose stop throws before it acts: the stateless restart, then the core commands, exit 1.
    $runRemove = function (callable $evaluate, array $codes = []): ?array {
        $out = null;
        $ok = uu_try_case(function () use ($evaluate, $codes, &$out): bool {
            $r = uu_test_runner($codes);
            $out = ['rc' => uu_remove_run($evaluate, $r['run'], $r['log']), 'calls' => $r['calls']];
            return true;
        });
        return $ok ? $out : null;
    };
    $errors = fn (?array $out): array => $out === null ? [] : array_values(array_filter(
        $out['calls']->getArrayCopy(), fn (string $c): bool => str_starts_with($c, 'log ' . LOG_ERR . ' ')));
    $out = $runRemove(function (): int {
        throw new RuntimeException('settings: model unreadable');
    });
    $errs = $errors($out);
    uu_check($t, 'a removal whose stop throws → Unbound restarted, then the filter reload, then the cron restart, one error naming the failure, exit 1',
        $out !== null && $out['rc'] === 1 && uu_test_acts($out['calls']) === [$ctlUnbound, $ctlReload, $ctlCron]
        && count($errs) === 1 && $has($errs[0], 'being removed', 'its stop failed (settings: model unreadable',
            'ran through configd', 'not confirmed', 'configctl unbound restart', 'route delete -host'));
    $out = $runRemove(function (): int {
        throw new RuntimeException('snapshot failed');
    }, [$ctl => [1, '']]);
    uu_check($t, 'the same with configd not answering → core\'s own restart, reload and cron run directly, in that order',
        $out !== null && $out['rc'] === 1
        && uu_test_acts($out['calls']) === [$ctlUnbound, $dUnbound, $ctlReload, $dReload, $ctlCron, $dCron]);
    $out = $runRemove(fn (): int => 0);
    uu_check($t, 'a removal whose stop returns → no restart, the filter reload and the cron restart, its exit status, no error',
        $out !== null && $out['rc'] === 0 && uu_test_acts($out['calls']) === [$ctlReload, $ctlCron]
        && $errors($out) === []);
    $out = $runRemove(fn (): int => 1);
    uu_check($t, 'a removal whose stop returns 1 (it ended with what it logged) → no restart, the two commands, exit 1',
        $out !== null && $out['rc'] === 1 && uu_test_acts($out['calls']) === [$ctlReload, $ctlCron]);

    // Every stop's Unbound restart and the escalation: core's restart through configd, else core's own command.
    /* Unbound's pid as successive reads give it (the last one repeats), each read and each wait recorded as "pid" and
     * "sleep MS" among the calls */
    $restart = function (array $codes, array $pids = [4242]): ?array {
        $out = null;
        $ok = uu_try_case(function () use ($codes, $pids, &$out): bool {
            $r = uu_test_runner($codes);
            $calls = $r['calls'];
            $left = new ArrayObject($pids);
            $pid = function () use ($calls, $left): ?int {
                $calls[] = 'pid';
                $list = $left->getArrayCopy();
                $value = count($list) > 1 ? array_shift($list) : $list[0];
                $left->exchangeArray($list);
                return $value;
            };
            $sleep = function (int $ms) use ($calls): void {
                $calls[] = "sleep $ms";
            };
            $out = ['ok' => uu_unbound_restart($r['run'], $r['log'], $pid, $sleep), 'calls' => $calls];
            return true;
        });
        return $ok ? $out : null;
    };
    $count = fn (?array $out, string $what): int => $out === null ? -1
        : count(array_filter($out['calls']->getArrayCopy(), fn (string $c): bool => $c === $what));
    $out = $restart([]);
    uu_check($t, 'Unbound restart, configd answering OK → true, only configctl unbound restart (timeout-bounded), logged through configd',
        $out !== null && $out['ok'] === true && uu_test_acts($out['calls']) === ['pid', $ctlUnbound]
        && uu_test_logged($out['calls'], LOG_NOTICE, 'unbound restart through configd'));
    uu_check($t, 'Unbound restart, configd answering OK → no wait for the pid: read once before, never after',
        $count($out, 'pid') === 1 && $count($out, 'sleep 1000') === 0);
    $out = $restart([$ctl => [0, '']]);
    uu_check($t, 'Unbound restart, configctl exiting 0 with no reply → core\'s own restart directly, true, the path logged',
        $out !== null && $out['ok'] === true && uu_test_acts($out['calls']) === ['pid', $ctlUnbound, $dUnbound]
        && uu_test_logged($out['calls'], LOG_WARNING, 'answered nothing', '/usr/local/sbin/pluginctl -c unbound_start',
            'ran directly'));
    /* configctl's timeout leaves configd's restart running: Unbound's pid tells whether it happened, so core's own
     * restart never races it */
    $waited = array_merge(['pid', $ctlUnbound], array_merge(['pid'], ...array_fill(0, UU_CONTROL_WAIT_SECONDS - 1,
        ['sleep 1000', 'pid'])));
    $out = $restart([$ctl => [124, '']], [4242]);
    uu_check($t, 'Unbound restart, configctl timed out and the pid unchanged through UU_CONTROL_WAIT_SECONDS → core\'s own restart directly, true',
        $out !== null && $out['ok'] === true && uu_test_acts($out['calls']) === array_merge($waited, [$dUnbound])
        && uu_test_logged($out['calls'], LOG_WARNING, 'within 30 s', 'ran directly'));
    $out = $restart([$ctl => [124, '']], [4242, 4242, 5151]);
    uu_check($t, 'Unbound restart, configctl timed out and the pid changed within the wait → configd\'s restart happened: no direct command, true, logged through configd',
        $out !== null && $out['ok'] === true
        && uu_test_acts($out['calls']) === ['pid', $ctlUnbound, 'pid', 'sleep 1000', 'pid']
        && uu_test_logged($out['calls'], LOG_NOTICE, 'unbound restart through configd', 'within 30 s',
            'took effect', "pid changed")
        && !uu_test_logged($out['calls'], LOG_WARNING, 'ran directly'));
    $out = $restart([$ctl => [124, '']], [null]);
    uu_check($t, 'Unbound restart, configctl timed out and the pid unreadable throughout → core\'s own restart directly, true',
        $out !== null && $out['ok'] === true && uu_test_acts($out['calls']) === array_merge($waited, [$dUnbound]));
    $out = $restart([$ctl => [124, '']], [null, 5151]);
    uu_check($t, 'Unbound restart, configctl timed out with no pid before and one after (configd started it) → no direct command',
        $out !== null && $out['ok'] === true && uu_test_acts($out['calls']) === ['pid', $ctlUnbound, 'pid']);
    $out = $restart(['/' => [1, '']]);
    uu_check($t, 'Unbound restart, both failing → false, one error with both exits',
        $out !== null && $out['ok'] === false
        && uu_test_logged($out['calls'], LOG_ERR, 'unbound restart failed', 'configctl exit 1', 'exited 1'));
    /* the restart a removal's stop runs, through the same runner: both failing never reads as restarted */
    $composed = null;
    $ok = uu_try_case(function () use ($fp, $usable, $all, &$composed): bool {
        $s = $fp;
        $s['zone'] = uu_root_zone(null);
        $s['contract_input']['zone'] = $s['zone'];
        $s['stop'] = UU_STOP_REMOVE;
        $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
        $io = uu_test_io($s, $all, ['restarts' => true]);
        $r = uu_test_runner(['/' => [1, '']]);
        $calls = $io['calls'];
        $log = $io['io']['log'];
        $io['io']['restart_unbound'] = function () use ($r, $log, $all, $calls): bool {
            $all[] = 'restart';
            $calls[] = 'restart';
            return uu_unbound_restart($r['run'], $log);
        };
        $composed = ['st' => uu_apply($p, $s, $io['io']), 'calls' => $calls->getArrayCopy()];
        return true;
    });
    $restarted = $composed === null ? [] : array_filter($composed['calls'],
        fn (string $c): bool => str_starts_with($c, 'log ') && str_contains($c, 'Unbound restarted'));
    uu_check($t, 'a removal\'s stop whose Unbound restart fails both ways → no "restarted" line, the failure logged, the reject route as the last resort',
        $ok && $composed !== null && in_array('restart', $composed['calls'], true) && $restarted === []
        && uu_test_logged(new ArrayObject($composed['calls']), LOG_ERR, 'unbound restart failed', 'exited 1')
        && in_array($fpReject, $composed['calls'], true)
        && !in_array('route delete -inet -host 192.0.2.1', $composed['calls'], true)
        && uu_test_logged(new ArrayObject($composed['calls']), LOG_ERR, 'being removed', 'rejected locally'));

    // The footprint's filter reload: queued only when configctl -d answers with a job id, else core's reload.
    $ctlQueue = '/usr/bin/timeout 30 /usr/local/sbin/configctl -d filter reload 2> /dev/null';
    $job = "c18b2884-b530-40e4-ae7f-761324e280f5\n";
    $queue = function (array $codes): ?ArrayObject {
        $calls = null;
        $ok = uu_try_case(function () use ($codes, &$calls): bool {
            $r = uu_test_runner($codes);
            uu_footprint_reload('the address the plugin last used changed from 192.0.2.1 to none', $r['run'],
                $r['log']);
            $calls = $r['calls'];
            return true;
        });
        return $ok ? $calls : null;
    };
    $calls = $queue([$ctl => [0, $job]]);
    uu_check($t, 'footprint reload, configctl -d answering a job id → queued, only the configctl -d line, logged as queued',
        $calls !== null && uu_test_acts($calls) === [$ctlQueue]
        && uu_test_logged($calls, LOG_NOTICE, 'changed from 192.0.2.1 to none', 'filter reload queued'));
    $notQueued = ['exit 0 with no reply' => [0, ''], 'exit 0 with OK, not a job id' => [0, "OK\n"],
                  'exit 0 with an error' => [0, "Execute error\n"], 'no socket (exit 255)' => [255, '']];
    foreach ($notQueued as $what => $code) {
        $calls = $queue([$ctl => $code]);
        uu_check($t, "footprint reload, configctl -d $what → core's own reload directly, never \"queued\"",
            $calls !== null && uu_test_acts($calls) === [$ctlQueue, $dReload]
            && uu_test_logged($calls, LOG_WARNING, 'changed from 192.0.2.1 to none', 'rc.filter_configure',
                'ran directly')
            && !uu_test_logged($calls, LOG_NOTICE, 'queued'));
    }
    $calls = $queue(['/' => [1, '']]);
    uu_check($t, 'footprint reload, both failing → one error, the rules follow at the next filter reload',
        $calls !== null && uu_test_logged($calls, LOG_ERR, 'the filter reload failed', 'configctl exit 1', 'exited 1',
            'next filter reload') && !uu_test_logged($calls, LOG_NOTICE, 'queued'));
    $out = null;
    $ok = uu_try_case(function () use (&$out): bool {
        $r = uu_test_runner([$ctl => [0, "C18B2884-B530-40E4-AE7F-761324E280F5x\n"]]);
        $out = uu_core_command('filter reload', UU_CORE_FILTER_RELOAD, $r['run'], true)['path'];
        return true;
    });
    uu_check($t, 'a detached reply that is a job id with anything after it is no job id',
        $ok && $out === 'direct');

    // The lock-timeout error names the address the state records, else says <resolver>.
    $named = null;
    $generic = null;
    $ok = uu_try_case(function () use (&$named, &$generic): bool {
        $named = uu_remove_timeout_text(['192.0.2.1']);
        $generic = uu_remove_timeout_text([]);
        return true;
    });
    uu_check($t, 'remove\'s lock-timeout remedy: route delete -host with the recorded address, else <resolver>',
        $ok && $has($named, 'being removed', '192.0.2.1', 'configctl unbound restart', 'route delete -host 192.0.2.1')
        && $has($generic, 'being removed', 'route delete -host <resolver>'));

    // The remedy reads the state when the wait runs out, so it names the address recorded then.
    $remedy = function (callable $write): ?string {
        $text = null;
        $ok = uu_scratch_case(function (string $dir) use ($write, &$text): bool {
            $path = "$dir/state.json";
            $write($path);
            $text = uu_remove_timeout_remedy($path);
            return true;
        });
        return $ok ? $text : null;
    };
    $recording = function (string $address): callable {
        return function (string $path) use ($address): void {
            $st = uu_state_new();
            $st['addresses'] = [$address => ['route' => null, 'forwarded' => true, 'released_at' => null]];
            uu_state_save($path, $st);
        };
    };
    /* writes nothing: the state file is missing */
    $noFile = function (string $path): void {
    };
    $both = null;
    $ok = uu_scratch_case(function (string $dir) use ($recording, &$both): bool {
        $path = "$dir/state.json";
        $recording('192.0.2.1')($path);
        $first = uu_remove_timeout_remedy($path);
        $recording('192.0.2.9')($path);
        $both = [$first, uu_remove_timeout_remedy($path)];
        return true;
    });
    uu_check($t, 'the lock-timeout remedy names the address the state records when it is built, read again each time',
        $ok && $both !== null && $has($both[0], 'route delete -host 192.0.2.1')
        && $has($both[1], 'route delete -host 192.0.2.9') && !$has($both[1], '192.0.2.1'));
    uu_check($t, 'the lock-timeout text names route delete -inet6 -host for an IPv6 address, and the IPv4 form unchanged',
        uu_try_case(fn (): bool => str_ends_with(uu_remove_timeout_text(['2001:db8:a::53']),
                'configctl unbound restart, then route delete -inet6 -host 2001:db8:a::53')
            && str_ends_with(uu_remove_timeout_text(['192.0.2.1']), 'configctl unbound restart, then route delete -host '
                . '192.0.2.1')
            && str_ends_with(uu_remove_timeout_text([]), 'then route delete -host <resolver>')));
    uu_check($t, 'no footprint recorded, a state that is not JSON, or no state file → the generic <resolver>',
        $has($remedy(fn (string $path) => uu_state_save($path, uu_state_new())), 'route delete -host <resolver>')
        && $has($remedy(fn (string $path) => file_put_contents($path, 'not json')), 'route delete -host <resolver>')
        && $has($remedy($noFile), 'route delete -host <resolver>'));

    // The map's entries: forwarded is true once forward_add is sent, in tunnel mode and on any live root read naming the
    // address; it turns false only on a read in this run that succeeded and lists something else.
    $entry = fn (?array $route, bool $forwarded, ?int $released = null): array
        => ['route' => $route, 'forwarded' => $forwarded, 'released_at' => $released];
    $forwardedOf = fn (array $st, string $address = '10.2.0.1'): ?bool => $st['addresses'][$address]['forwarded'] ?? null;

    $s = uu_test_apply_snapshot();
    $p = uu_plan($s, uu_test_plan_state(null, $usable));
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, '(f1) entering tunnel mode records the address: the member route, forwarded true, not released',
        $st['addresses'] === ['10.2.0.1' => $entry($memberRecord, true)]
        && $r['saved']['state']['addresses'] === $st['addresses']);

    $p = uu_plan($s, uu_test_plan_state(null, $usable));
    $r = uu_test_io($s, $all, ['uc_fail' => ['forward_add', 'forward_add']]);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, '(f2) forward_add sent and refused, and the restore refused too: forwarded stays true, no reject route, '
        . 'the member route kept',
        $st['mode'] === 'fallback' && $forwardedOf($st) === true && uu_test_record($st) === $memberRecord
        && uu_test_acts($r['calls']) === [$toWgA, $wait, $probe, $toResolver, $restoreDot]
        && uu_test_logged($r['calls'], LOG_ERR, 'fallback incomplete'));

    $s = uu_test_apply_snapshot();
    $s['settings']['enabled'] = false;
    $s['unbound']['live_root'] = ['10.2.0.1'];
    $p = uu_plan($s, uu_test_plan_state(null));
    $r = uu_test_io($s, $all, ['uc_fail' => ['forward_add']]);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, '(f3) a live root that is exactly the resolver is tunnel mode with no member: the stop that cannot '
        . 'restore leaves the address recorded forwarded',
        $p['action'] === 'stop' && $st['addresses'] === ['10.2.0.1' => $entry(null, true)]
        && uu_test_acts($r['calls']) === [$restoreDot]);
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, '(f3) …and the restore that the next read confirms drops it again',
        $st['addresses'] === []);

    $down = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $down['probes']['wg-a'] = $settledDown;
    $down['probes']['wg-b'] = $settledDown;
    $recorded = uu_test_plan_state('wg-a', $usable);
    $recorded['addresses'] = ['10.2.0.1' => $entry($memberRecord, true, 7)];
    $external = $down;
    $external['unbound']['live_root'] = ['192.0.2.53', '2001:db8::53'];
    $p = uu_plan($external, $recorded);
    $r = uu_test_io($external, $all);
    $st = uu_apply($p, $external, $r['io']);
    uu_check($t, '(f4) Unbound restarted by someone else (the live root is the configured list): fallback installs the '
        . 'reject route at once, forwarded false from the read, released_at cleared (a member\'s resolver)',
        $p['action'] === 'fallback' && uu_test_acts($r['calls']) === [$reject]
        && $st['mode'] === 'fallback' && $st['addresses'] === ['10.2.0.1' => $entry($rejectRecord, false)]);

    $p = uu_plan($down, $recorded);
    $r = uu_test_io($down, $all);
    $st = uu_apply($p, $down, $r['io']);
    uu_check($t, '(f4) …but with the live root still the resolver, the restore comes first and the reject route after '
        . 'it, forwarded false once the read confirms',
        uu_test_acts($r['calls']) === [$restoreDot, 'uc forward', $reject]
        && $st['addresses'] === ['10.2.0.1' => $entry($rejectRecord, false)]);

    $repair = uu_test_apply_snapshot();
    $repair['probes']['wg-a'] = $settledDown;
    $repair['probes']['wg-b'] = $settledDown;
    $stale = uu_test_plan_state(null, $usable);
    $stale['addresses'] = ['10.2.0.1' => $entry($rejectRecord, true)];
    $p = uu_plan($repair, $stale);
    $r = uu_test_io($repair, $all);
    $st = uu_apply($p, $repair, $r['io']);
    uu_check($t, '(f5) fallback mode\'s route repair after an external restart: the reject route is added at once, and '
        . 'the stale forwarded flag is false from the run\'s read',
        $p['action'] === 'none' && $p['route_repair']
        && uu_test_acts($r['calls']) === ['route add -inet -host 10.2.0.1 127.0.0.1 -reject']
        && $st['addresses'] === ['10.2.0.1' => $entry($rejectRecord, false)]);

    $silentFp = uu_test_apply_snapshot();
    $silentFp['unbound'] = ['enabled' => true, 'pid_alive' => true, 'control_ok' => false, 'live_root' => null];
    $silentFp = uu_test_route($silentFp, ['present' => true, 'gateway' => '', 'interface' => 'lo0', 'reject' => true,
                                          'ours' => true]);
    $keep = uu_test_plan_state(null, $usable);
    $keep['addresses'] = ['10.2.0.1' => $entry($rejectRecord, true), '192.0.2.77' => $entry(null, true, 9000)];
    $p = uu_plan($silentFp, $keep);
    $r = uu_test_io($silentFp, $all, ['silent' => true]);
    $st = uu_apply($p, $silentFp, $r['io']);
    uu_check($t, '(f6) a live root that could not be read (a silent channel) clears no forwarded flag, and touches '
        . 'no entry',
        $p['action'] === 'skip' && $st['addresses'] === $keep['addresses']);

    $unparsed = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $unparsed['settings']['enabled'] = false;
    $inTunnel = uu_test_plan_state('wg-a', $usable);
    $inTunnel['addresses'] = ['10.2.0.1' => $entry($memberRecord, true)];
    $p = uu_plan($unparsed, $inTunnel);
    $r = uu_test_io($unparsed, $all, ['forward_out' => "not an address\n"]);
    $st = uu_apply($p, $unparsed, $r['io']);
    uu_check($t, '(f6) a forward read that cannot be parsed clears nothing: the stop that could not confirm the restore '
        . 'leaves the address forwarded, the route in place',
        $p['action'] === 'stop' && uu_test_acts($r['calls']) === [$restoreDot, 'uc forward']
        && $forwardedOf($st) === true && uu_test_record($st) === $memberRecord
        && uu_test_logged($r['calls'], LOG_ERR, 'live root is unknown'));

    $others = $external;
    $others['unbound']['live_root'] = ['192.0.2.78'];
    $mapped = uu_test_plan_state(null, $usable);
    $mapped['addresses'] = [
        '192.0.2.77' => $entry(null, true, 9000),
        '192.0.2.78' => $entry($rejectRecord, false, 4),
    ];
    $others = uu_test_route($others, ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false,
                                      'ours' => false]);
    /* 192.0.2.77 keeps a reject route of the plugin's, so its entry stays once the read clears its forwarded */
    $others = uu_test_route($others, ['present' => true, 'gateway' => '', 'interface' => 'lo0', 'reject' => true,
                                      'ours' => true], '192.0.2.77');
    $others['probes']['wg-a'] = $settledDown;
    $others['probes']['wg-b'] = $settledDown;
    $p = uu_plan($others, $mapped);
    $r = uu_test_io($others, $all, ['throw_on' => 'uc']);
    $thrown = false;
    try {
        uu_apply($p, $others, $r['io']);
    } catch (RuntimeException $e) {
        $thrown = $e->getMessage() === 'test: uc throws';
    }
    uu_check($t, '(f7) every recorded address is recomputed from the run\'s read before any call: an address the root '
        . 'no longer names turns false, one it names turns true, released_at kept (as saved when the first call, the '
        . 'restore, throws)',
        $thrown && uu_test_acts($r['calls']) === [$restoreDot]
        && $r['saved']['state']['addresses'] === ['192.0.2.77' => $entry(null, false, 9000),
            '192.0.2.78' => $entry($rejectRecord, true, 4)]);

    $s = uu_test_apply_snapshot();
    $s['settings']['enabled'] = false;
    $s['unbound'] = ['enabled' => true, 'pid_alive' => true, 'control_ok' => false, 'live_root' => null];
    $stale = uu_test_plan_state(null);
    $stale['addresses'] = ['10.2.0.1' => $entry(null, true)];
    $p = uu_plan($s, $stale);
    $r = uu_test_io($s, $all, ['silent' => true]);
    $st = uu_apply($p, $s, $r['io']);
    $acts = uu_test_acts($r['calls']);
    uu_check($t, '(f8) a stop over a silent channel with a stale forwarded true tries the restore, never the reject route, '
        . 'and keeps the entry',
        $p['action'] === 'stop' && count($acts) === 1 && str_starts_with($acts[0], 'uc forward_')
        && $st['addresses'] === ['10.2.0.1' => $entry(null, true)]);

    $s = uu_test_apply_snapshot();
    $s['settings']['enabled'] = false;
    $s['unbound']['live_root'] = ['10.2.0.1', '192.0.2.53'];
    $p = uu_plan($s, uu_test_plan_state(null));
    $r = uu_test_io($s, $all, ['uc_fail' => ['forward_add']]);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, '(f9) a live root naming the resolver among others records it forwarded (the stop\'s restore refused)',
        $p['action'] === 'stop' && uu_test_acts($r['calls']) === [$restoreDot]
        && $st['addresses'] === ['10.2.0.1' => $entry(null, true)]);

    $empty = $down;
    $empty['unbound']['live_root'] = [];
    $recorded = uu_test_plan_state('wg-a', $usable);
    $recorded['addresses'] = ['10.2.0.1' => $entry($memberRecord, true, 7)];
    $p = uu_plan($empty, $recorded);
    $st = uu_apply($p, $empty, uu_test_io($empty, $all)['io']);
    uu_check($t, '(f10) an empty live root (Unbound recursing) is a read that clears forwarded',
        $p['action'] === 'fallback' && $st['addresses'] === ['10.2.0.1' => $entry($rejectRecord, false)]);

    $named = uu_test_apply_snapshot();
    $named['unbound']['live_root'] = ['192.0.2.78', '192.0.2.53'];
    $named['probes']['wg-a'] = $settledDown;
    $named['probes']['wg-b'] = $settledDown;
    $recorded = uu_test_plan_state(null, $usable);
    $recorded['addresses'] = ['192.0.2.78' => $entry($rejectRecord, false, 4)];
    $p = uu_plan($named, $recorded);
    $st = uu_apply($p, $named, uu_test_io($named, $all, ['uc_fail' => ['forward_add']])['io']);
    uu_check($t, '(f11) another recorded address named among others turns forwarded true (the restore it is due '
        . 'refused)',
        $p['action'] === 'fallback' && ($st['addresses']['192.0.2.78'] ?? null) === $entry($rejectRecord, true, 4));

    $s = uu_test_apply_snapshot();
    $s['settings']['enabled'] = false;
    $two = uu_test_plan_state(null, $usable);
    $two['addresses'] = ['10.2.0.1' => $entry(null, false), '192.0.2.77' => $entry(null, true, 9000)];
    $p = uu_plan($s, $two);
    $r = uu_test_io($s, $all);
    $st = uu_apply($p, $s, $r['io']);
    uu_check($t, '(f12) every entry is recomputed from the read: the resolver\'s own and another address\'s both leave '
        . 'once neither a route of the plugin\'s nor the live root refers to them',
        $p['action'] === 'stop' && uu_test_acts($r['calls']) === [] && $st['addresses'] === []);

    $dead = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
    $dead['unbound'] = ['enabled' => true, 'pid_alive' => false, 'control_ok' => false, 'live_root' => null];
    $p = uu_plan($dead, uu_test_plan_state('wg-a', $usable));
    $r = uu_test_io($dead, $all);
    $st = uu_apply($p, $dead, $r['io']);
    $dead = uu_test_route($dead, ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false,
                                  'ours' => false]);
    $p2 = uu_plan($dead, $st);
    $r2 = uu_test_io($dead, $all);
    $st2 = uu_apply($p2, $dead, $r2['io']);
    uu_check($t, '(p1) tunnel mode, Unbound not running: the route is deleted, fallback, nothing recorded; the next '
        . 'tick calls nothing and records nothing',
        $p['action'] === 'stop' && uu_test_acts($r['calls']) === ['route delete -inet -host 10.2.0.1']
        && $st['mode'] === 'fallback' && $st['addresses'] === []
        && uu_test_acts($r2['calls']) === [] && $st2['addresses'] === []);

    $unknown = uu_test_apply_snapshot();
    $unknown['probes']['wg-a'] = $settledDown;
    $unknown['probes']['wg-b'] = $settledDown;
    $held = uu_test_plan_state(null, $usable);
    $held['addresses'] = ['10.2.0.1' => $entry($rejectRecord, false)];
    $p = uu_plan($unknown, $held);
    $r = uu_test_io($unknown, $all, ['route_fail' => ['add']]);
    $st = uu_apply($p, $unknown, $r['io']);
    uu_check($t, '(m5) a reject route that cannot be added over a route the snapshot missed keeps the entry and its '
        . 'record, and is not retried as a change',
        $p['route_repair'] && uu_test_acts($r['calls']) === ['route add -inet -host 10.2.0.1 127.0.0.1 -reject']
        && $st['addresses'] === ['10.2.0.1' => $entry($rejectRecord, false)]);
    $nothing = uu_test_plan_state(null, $usable);
    $p = uu_plan($unknown, $nothing);
    $r = uu_test_io($unknown, $all, ['route_fail' => ['add']]);
    $st = uu_apply($p, $unknown, $r['io']);
    uu_check($t, '(m5) …and a failed add with no entry before creates none',
        $st['addresses'] === []);

    uu_check($t, 'the remove-timeout text for several addresses names each, comma-joined, and one delete command each',
        uu_try_case(fn (): bool => uu_remove_timeout_text(['192.0.2.1', '2001:db8:a::53'])
            === 'the package is being removed while Unbound may still forward to 192.0.2.1, 2001:db8:a::53 over the '
            . 'plugin\'s route: once it is removed, run configctl unbound restart, then route delete -host '
            . '192.0.2.1; route delete -inet6 -host 2001:db8:a::53'));

    /* (a12) an external Unbound restart on 1.3_2's one-address setup, from the state 1.3_2 wrote: 1.3_2's own code,
     * run on this input, logged exactly these lines (the reject route then read "route change -host", before the
     * family argument) */
    $v5 = ['version' => 5, 'mode' => 'tunnel', 'member' => 'wg-a',
           'timers' => ['wg-a' => array_diff_key($usable['wg-a'], ['resolver' => true]),
                        'wg-b' => array_diff_key($usable['wg-b'], ['resolver' => true])],
           'control_failures' => 0, 'control_silent_since' => null, 'last_switch' => null,
           'checks' => ['direct' => null, 'unbound' => null], 'tls_applied' => false, 'blocked' => null,
           'route_installed' => $memberRecord, 'resolver' => '10.2.0.1'];
    $noCandidate = 'no candidate, fallback: wg-a down: settled down; wg-b down: settled down (trigger downloss)';
    $lines132 = [
        'external' => ['log ' . LOG_NOTICE . ' ' . $noCandidate,
                       'log ' . LOG_NOTICE . ' route: 10.2.0.1 rejected locally',
                       'log ' . LOG_NOTICE . ' switch wg-a -> fallback: ' . $noCandidate],
        'unknown' => ['log ' . LOG_WARNING . ' Unbound control channel silent (1 evaluations, 0 s)'],
    ];
    foreach (['external' => ['192.0.2.53', '2001:db8::53'], 'unknown' => null] as $what => $liveRoot) {
        $run = null;
        $ok = uu_try_case(function () use ($v5, $liveRoot, $settledDown, $all, &$run): bool {
            $converted = uu_state_from_v5($v5);
            $s = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
            $s['probes']['wg-a'] = $settledDown;
            $s['probes']['wg-b'] = $settledDown;
            $s['unbound']['live_root'] = $liveRoot;
            $s['unbound']['control_ok'] = $liveRoot !== null;
            $p = uu_plan($s, $converted ?? uu_state_new());
            $r = uu_test_io($s, $all);
            $run = ['converted' => $converted, 'p' => $p, 'calls' => $r['calls'], 'st' => uu_apply($p, $s, $r['io'])];
            return true;
        });
        $logs = $run === null ? [] : array_values(array_filter($run['calls']->getArrayCopy(),
            fn (string $c): bool => str_starts_with($c, 'log ')));
        uu_check($t, $what === 'external'
            ? '(a12) a converted 1.3_2 state, forwarded, the snapshot\'s live root the configured DoT list: fallback '
                . 'rejects at once (no forward_add +t, no forward read), every log line as 1.3_2 logs it'
            : '(a12) the same with the live root unknown (a silent channel): no reject route, 1.3_2\'s one line',
            $ok && $run !== null && $run['converted'] !== null
            && $run['converted']['addresses'] === ['10.2.0.1' => $entry($memberRecord, true)]
            && uu_test_acts($run['calls']) === ($liveRoot === null ? [] : [$reject])
            && $logs === $lines132[$what]
            && $run['st']['addresses'] === ['10.2.0.1' => $liveRoot === null ? $entry($memberRecord, true)
                : $entry($rejectRecord, false)]);
    }

    /* (a19) the one-address path's failure lines: a fallback whose restore is refused, a disabled plugin's tick whose
     * restore is refused, a stop whose reject route fails and one whose flush_requestlist fails each end in their error
     * line exactly as 1.3_2 logs it, and keep the resolver recorded for the next evaluation */
    $outcomes = null;
    $ok = uu_try_case(function () use ($usable, $settledDown, $all, &$outcomes): bool {
        /* the run's recorded addresses and its last error line */
        $outcome = function (array $s, array $st, array $o) use ($all): array {
            $r = uu_test_io($s, $all, $o);
            $out = uu_apply(uu_plan($s, $st), $s, $r['io']);
            $errors = array_values(array_filter($r['calls']->getArrayCopy(),
                fn (string $c): bool => str_starts_with($c, 'log ' . LOG_ERR . ' ')));
            return [uu_state_footprint($out), substr((string)end($errors), strlen('log ' . LOG_ERR . ' '))];
        };
        $down = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
        $down['probes']['wg-a'] = $settledDown;
        $down['probes']['wg-b'] = $settledDown;
        $off = uu_test_in_tunnel(uu_test_apply_snapshot(), 'wg-a');
        $off['settings']['enabled'] = false;
        $onA = uu_test_plan_state('wg-a', $usable);
        $outcomes = [$outcome($down, $onA, ['uc_fail' => ['forward_add']]),
                     $outcome($off, $onA, ['uc_fail' => ['forward_add']]),
                     $outcome($off, $onA, ['route_fail' => ['change', 'add']]),
                     $outcome($off, $onA, ['uc_fail' => ['flush_requestlist']])];
        return true;
    });
    $one = ['10.2.0.1'];
    uu_check($t, '(a19) one address: a fallback whose restore is refused, a disabled plugin\'s tick whose restore is '
        . 'refused, a stop whose reject route fails and one whose flush_requestlist fails each end in their error line '
        . 'as 1.3_2 logs it, the resolver still recorded',
        $ok && $outcomes === [
            [$one, 'fallback incomplete: Unbound may still forward to the resolver, so no reject route; the next '
                . 'evaluation tries again'],
            [$one, 'stop: Unbound may still forward to the resolver, so its route stays (without it the queries would '
                . 'follow the default route)'],
            [$one, "stop: no reject route, so the resolver's route stays: Unbound may still retry the resolver"],
            [$one, 'stop: unbound-control flush_requestlist failed, so the reject route stays: Unbound may still retry '
                . 'the resolver']]);

    // A resolver per member, in each family: a switch to a member with another resolver rejects the previous address
    // in place; an address no member uses any more (an orphan) is released, held, then drained and deleted.
    $families = [
        'IPv6' => ['a' => '2001:db8:a::53', 'b' => '2001:db8:b::53', 'c' => '2001:db8:c::53', 'typo' => '2001:db8:a::5',
                   'hop_a' => 'fd00::3:2', 'if_a' => 'wg3', 'hop_b' => 'fd00::4:2', 'if_b' => 'wg4', 'arg' => '-inet6',
                   'lo' => '::1', 'hop_c' => 'fd00::5:2', 'if_c' => 'wg5', 'first' => '2001:db8:9::53'],
        'IPv4' => ['a' => '198.51.100.10', 'b' => '198.51.100.20', 'c' => '198.51.100.30', 'typo' => '198.51.100.1',
                   'hop_a' => '10.2.0.2', 'if_a' => 'wg1', 'hop_b' => '10.2.0.6', 'if_b' => 'wg2', 'arg' => '-inet',
                   'lo' => '127.0.0.1', 'hop_c' => '10.2.0.10', 'if_c' => 'wg5', 'first' => '192.0.2.30'],
    ];
    /* the apply snapshot in the family: wg-a's resolver $wgA (the Default), wg-b's $wgB (its own row when it
     * differs) */
    $perMember = function (array $f, string $wgA, string $wgB): array {
        $s = uu_test_default(uu_test_apply_snapshot(), $wgA);
        foreach (['wg-a' => ['hop_a', 'if_a'], 'wg-b' => ['hop_b', 'if_b']] as $name => [$hop, $if]) {
            $s['members'][$name]['next_hop'] = $f[$hop];
            $s['members'][$name]['if'] = $f[$if];
        }
        return $wgB === $wgA ? $s : uu_test_resolver($s, 'wg-b', $wgB);
    };
    $via = fn (array $f, string $member): array => ['present' => true,
        'gateway' => $f[$member === 'wg-a' ? 'hop_a' : 'hop_b'],
        'interface' => $f[$member === 'wg-a' ? 'if_a' : 'if_b'], 'reject' => false, 'ours' => true];
    $viaRecord = fn (array $f, string $member): array => ['kind' => 'member',
        'next_hop' => $f[$member === 'wg-a' ? 'hop_a' : 'hop_b'], 'if' => $f[$member === 'wg-a' ? 'if_a' : 'if_b']];
    $rejected = ['present' => true, 'gateway' => '', 'interface' => 'lo0', 'reject' => true, 'ours' => true];
    $rejectOf = fn (array $f, string $address): string => "route change {$f['arg']} -host $address {$f['lo']} -reject";
    $deleteOf = fn (array $f, string $address): string => "route delete {$f['arg']} -host $address";
    /* the index of the first log line that is exactly the message at notice, -1 when there is none */
    $lineAt = function (ArrayObject $calls, string $msg): int {
        $at = array_search('log ' . LOG_NOTICE . ' ' . $msg, $calls->getArrayCopy(), true);
        return $at === false ? -1 : (int)$at;
    };
    /* a run of the plan against the fake Io: the plan, the calls, the acts, the state it returns, the state last
     * saved */
    $applyRun = function (array $s, array $st, array $o = []) use ($all): array {
        $p = uu_plan($s, $st);
        $r = uu_test_io($s, $all, $o);
        $out = uu_apply($p, $s, $r['io']);
        return ['p' => $p, 'calls' => $r['calls'], 'acts' => uu_test_acts($r['calls']), 'st' => $out,
                'saved' => $r['saved']];
    };
    /* a run's error lines, as the log received them */
    $errorsOf = fn (array $run): array => array_values(array_filter($run['calls']->getArrayCopy(),
        fn (string $c): bool => str_starts_with($c, 'log ' . LOG_ERR . ' ')));
    $with = function (array $st, array $addresses): array {
        $st['addresses'] = $addresses;
        return $st;
    };

    foreach ($families as $family => $f) {
        [$a, $b, $c, $typo] = [$f['a'], $f['b'], $f['c'], $f['typo']];

        $run = null;
        $ok = uu_try_case(function () use ($perMember, $f, $a, $usable, $applyRun, &$run): bool {
            $s = uu_test_in_tunnel($perMember($f, $a, $a), 'wg-a');
            $s['members']['wg-a']['force_down'] = true;
            $run = $applyRun($s, uu_test_plan_state('wg-a', $usable, 0, null, $a, $s));
            return true;
        });
        uu_check($t, "(a1) $family, members sharing one address, change of member: route change, sleep, the direct "
            . 'probe, flush_infra, forward; no forward_add and no other route',
            $ok && $run !== null && $run['p']['action'] === 'tunnel'
            && $run['acts'] === array_merge(["route change {$f['arg']} -host $a {$f['hop_b']} -ifp {$f['if_b']}", $wait,
                "probe_direct $a .", "uc flush_infra $a", 'uc forward'], $through)
            && $run['st']['member'] === 'wg-b'
            && $run['st']['addresses'] === [$a => $entry($viaRecord($f, 'wg-b'), true)]);

        $run = null;
        $ok = uu_try_case(function () use ($perMember, $f, $a, $b, $usable, $applyRun, &$run): bool {
            $s = uu_test_in_tunnel($perMember($f, $a, $b), 'wg-a');
            $s['members']['wg-a']['force_down'] = true;
            $run = $applyRun($s, uu_test_plan_state('wg-a', $usable, 0, null, $a, $s));
            return true;
        });
        uu_check($t, "(a2) $family, wg-a down, wg-b has its own resolver: B routed, probed, forward_add, flush_infra, "
            . 'confirmed, then A changed to its reject route in place; B forwarded, A held as wg-a\'s',
            $ok && $run !== null && $run['p']['action'] === 'tunnel'
            && $run['acts'] === array_merge(["route add {$f['arg']} -host $b {$f['hop_b']} -ifp {$f['if_b']}", $wait,
                "probe_direct $b .", "uc forward_add . $b", "uc flush_infra $b", 'uc forward', $rejectOf($f, $a)],
                $through)
            && $lineAt($run['calls'], "forwarders: . -> $b, plain DNS inside the tunnel (no +t)") >= 0
            && $lineAt($run['calls'], "forwarders: . -> $b, plain DNS inside the tunnel (no +t)")
                < $lineAt($run['calls'], "route: $a rejected locally (previous member's resolver)")
            && $run['st']['member'] === 'wg-b'
            && $run['st']['addresses'] === [$a => $entry($rejectRecord, false),
                $b => $entry($viaRecord($f, 'wg-b'), true)]
            && $run['saved']['state']['addresses'] === $run['st']['addresses']);

        /* the same where A is no member's resolver any more: both members use B */
        $runs = null;
        $ok = uu_try_case(function () use ($perMember, $f, $a, $b, $usable, $applyRun, $via, $rejected, &$runs): bool {
            $s = $perMember($f, $b, $b);
            $s['unbound']['live_root'] = [$a];
            $s = uu_test_route($s, $via($f, 'wg-a'), $a);
            $s['members']['wg-a']['force_down'] = true;
            $first = $applyRun($s, uu_test_plan_state('wg-a', $usable, 0, null, $a, $s));
            $later = uu_test_in_tunnel($perMember($f, $b, $b), 'wg-b');
            $later['members']['wg-a']['force_down'] = true;
            $later = uu_test_route($later, $rejected, $a);
            $runs = [$first];
            foreach ([59, 60] as $offset) {
                $later['now'] = $s['now'] + $offset;
                $runs[] = $applyRun($later, $runs[count($runs) - 1]['st']);
            }
            return true;
        });
        uu_check($t, "(a3) $family, A no member's resolver: rejected in place and released at the switch",
            $ok && $runs !== null && in_array($rejectOf($f, $a), $runs[0]['acts'], true)
            && $runs[0]['st']['addresses'][$a] === $entry($rejectRecord, false, $now));
        uu_check($t, "(a3) $family, …a run 59 s later deletes nothing; one 60 s later runs flush_requestlist, the "
            . 'drain (fib_sync + 500 ms + 1 s), then the delete, and A leaves the map',
            $ok && $runs !== null && $runs[1]['p']['drain'] === [] && !in_array($flushReq, $runs[1]['acts'], true)
            && $runs[1]['st']['addresses'][$a] === $entry($rejectRecord, false, $now)
            && $runs[2]['p']['drain'] === [$a]
            && array_slice($runs[2]['acts'], -3) === [$flushReq, $drain, $deleteOf($f, $a)]
            && array_keys($runs[2]['st']['addresses']) === [$b]
            && uu_test_logged($runs[2]['calls'], LOG_NOTICE, "route: $a deleted"));

        $runs = null;
        $ok = uu_try_case(function () use ($perMember, $f, $a, $b, $usable, $applyRun, $with, $entry, $rejected,
                                           $rejectRecord, $viaRecord, $now, &$runs): bool {
            $s = uu_test_in_tunnel($perMember($f, $b, $b), 'wg-b');
            $s['members']['wg-a']['force_down'] = true;
            $s = uu_test_route($s, $rejected, $a);
            $s['now'] = $now + 60;
            $st = $with(uu_test_plan_state('wg-b', $usable, 0, null, $b, $s),
                [$a => $entry($rejectRecord, false, $now), $b => $entry($viaRecord($f, 'wg-b'), true)]);
            $failed = $applyRun($s, $st, ['uc_fail' => ['flush_requestlist']]);
            $s['now'] = $now + 61;
            $runs = [$failed, $applyRun($s, $failed['st'])];
            return true;
        });
        uu_check($t, "(a4) $family, no delete before a successful flush_requestlist and drain: the flush fails, A "
            . 'keeps its reject route, record and hold, one error names it, B stays switched in; the next run drains '
            . 'and deletes it',
            $ok && $runs !== null && $runs[0]['p']['drain'] === [$a]
            && array_slice($runs[0]['acts'], -1) === [$flushReq]
            && array_filter($runs[0]['acts'], fn (string $c): bool => str_starts_with($c, 'route ')) === []
            && $runs[0]['st']['addresses'] === [$a => $entry($rejectRecord, false, $now),
                $b => $entry($viaRecord($f, 'wg-b'), true)]
            && $errorsOf($runs[0]) === ['log ' . LOG_ERR . " route: draining $a failed (unbound-control "
                . 'flush_requestlist), so its reject route stays']
            && $runs[0]['st']['member'] === 'wg-b'
            && array_slice($runs[1]['acts'], -3) === [$flushReq, $drain, $deleteOf($f, $a)]
            && $runs[1]['st']['addresses'] === [$b => $entry($viaRecord($f, 'wg-b'), true)]
            && $runs[1]['st']['member'] === 'wg-b' && $errorsOf($runs[1]) === []);

        $runs = null;
        $ok = uu_try_case(function () use ($perMember, $f, $a, $b, $usable, $applyRun, $via, &$runs): bool {
            $s = uu_test_in_tunnel($perMember($f, $a, $b), 'wg-a');
            $s['members']['wg-a']['force_down'] = true;
            $first = $applyRun($s, uu_test_plan_state('wg-a', $usable, 0, null, $a, $s),
                ['uc_lost' => ['forward_add'], 'uc_fail' => ['forward_add']]);
            $next = $s;
            $next['unbound']['live_root'] = [$b];
            $next = uu_test_route($next, $via($f, 'wg-b'), $b);
            $runs = [$first, $applyRun($next, $first['st'])];
            return true;
        });
        uu_check($t, "(a5) $family, forward_add sent and its reply lost, the restore refused: A keeps its member "
            . 'route, both addresses recorded forwarded',
            $ok && $runs !== null
            && $runs[0]['acts'] === ["route add {$f['arg']} -host $b {$f['hop_b']} -ifp {$f['if_b']}", $wait,
                "probe_direct $b .", "uc forward_add . $b", $restoreDot]
            && $runs[0]['st']['addresses'][$a] === $entry($viaRecord($f, 'wg-a'), true)
            && $runs[0]['st']['addresses'][$b] === $entry($viaRecord($f, 'wg-b'), true));
        uu_check($t, "(a5) $family, …the next run confirms B without a forward_add, then rejects A",
            $ok && $runs !== null && !in_array("uc forward_add . $b", $runs[1]['acts'], true)
            && array_slice($runs[1]['acts'], 0, 4) === ["probe_direct $b .", "uc flush_infra $b", 'uc forward',
                $rejectOf($f, $a)]
            && $runs[1]['st']['member'] === 'wg-b'
            && $runs[1]['st']['addresses'][$a] === $entry($rejectRecord, false));

        $run = null;
        $ok = uu_try_case(function () use ($perMember, $f, $a, $b, $usable, $applyRun, $with, $entry, $via,
                                           $viaRecord, &$run): bool {
            $s = uu_test_in_tunnel($perMember($f, $a, $b), 'wg-b');
            $s = uu_test_route($s, $via($f, 'wg-a'), $a);
            $s['settings']['enabled'] = false;
            $st = $with(uu_test_plan_state('wg-b', $usable, 0, null, $b, $s),
                [$a => $entry($viaRecord($f, 'wg-a'), false), $b => $entry($viaRecord($f, 'wg-b'), true)]);
            $run = $applyRun($s, $st);
            return true;
        });
        uu_check($t, "(a6) $family, a stop with two entries: one restore, both reject routes, one flush_requestlist, "
            . 'one drain, both deleted, the map empty',
            $ok && $run !== null && $run['p']['action'] === 'stop'
            && $run['acts'] === [$restoreDot, 'uc forward', $rejectOf($f, $a), $rejectOf($f, $b), $flushReq, $drain,
                $deleteOf($f, $a), $deleteOf($f, $b)]
            && $run['st']['addresses'] === [] && $run['st']['mode'] === 'fallback');

        $run = null;
        $ok = uu_try_case(function () use ($perMember, $f, $a, $b, $usable, $applyRun, $with, $entry, $via,
                                           $viaRecord, $settledDown, &$run): bool {
            $s = uu_test_in_tunnel($perMember($f, $b, $b), 'wg-b');
            $s = uu_test_route($s, $via($f, 'wg-a'), $a);
            $s['probes']['wg-a'] = $settledDown;
            $s['probes']['wg-b'] = $settledDown;
            $st = $with(uu_test_plan_state('wg-b', $usable, 0, null, $b, $s),
                [$a => $entry($viaRecord($f, 'wg-a'), false), $b => $entry($viaRecord($f, 'wg-b'), true)]);
            $run = $applyRun($s, $st);
            return true;
        });
        uu_check($t, "(a7) $family, fallback rejects every entry after the restore; the orphan gets released_at, the "
            . 'member\'s resolver does not',
            $ok && $run !== null && $run['p']['action'] === 'fallback'
            && $run['acts'] === [$restoreDot, 'uc forward', $rejectOf($f, $a), $rejectOf($f, $b)]
            && $run['st']['addresses'] === [$a => $entry($rejectRecord, false, $now),
                $b => $entry($rejectRecord, false)]);

        $run = null;
        $ok = uu_try_case(function () use ($perMember, $f, $a, $b, $c, $usable, $applyRun, $via, &$run): bool {
            $s = $perMember($f, $c, $b);
            $s['unbound']['live_root'] = [$a];
            $s = uu_test_route($s, $via($f, 'wg-a'), $a);
            $timers = $usable;
            $timers['wg-a']['resolver'] = $a;
            $run = $applyRun($s, uu_test_plan_state('wg-a', $timers, 0, null, $a, $s));
            return true;
        });
        uu_check($t, "(a8) $family, a Save changes the active member's resolver: switched in place on the same member, "
            . 'no switch recorded or logged, the forwarders line and the previous address rejected',
            $ok && $run !== null && $run['p']['action'] === 'tunnel' && $run['p']['candidates'][0] === 'wg-a'
            && $run['acts'] === array_merge(["route add {$f['arg']} -host $c {$f['hop_a']} -ifp {$f['if_a']}", $wait,
                "probe_direct $c .", "uc forward_add . $c", "uc flush_infra $c", 'uc forward', $rejectOf($f, $a)],
                $through)
            && $run['st']['mode'] === 'tunnel' && $run['st']['member'] === 'wg-a' && $run['st']['last_switch'] === null
            && !uu_test_logged($run['calls'], LOG_NOTICE, 'switch ')
            && $lineAt($run['calls'], "forwarders: . -> $c, plain DNS inside the tunnel (no +t)") >= 0
            && $lineAt($run['calls'], "route: $a rejected locally (previous member's resolver)") >= 0
            && $run['st']['addresses'][$a] === $entry($rejectRecord, false, $now));

        $runs = null;
        $ok = uu_try_case(function () use ($perMember, $f, $a, $typo, $usable, $applyRun, $rejected, $via,
                                           &$runs): bool {
            $s = uu_test_in_tunnel($perMember($f, $typo, $typo), 'wg-a');
            $s['unbound']['live_root'] = [$a];
            $s = uu_test_route($s, ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false,
                                    'ours' => false], $typo);
            $s = uu_test_route($s, $via($f, 'wg-a'), $a);
            $timers = $usable;
            $timers['wg-a']['resolver'] = $a;
            $timers['wg-b']['resolver'] = $a;
            $typoRun = $applyRun($s, uu_test_plan_state('wg-a', $timers, 0, null, $a, $s),
                ['direct' => [$f['if_a'] => [false], $f['if_b'] => [false]]]);
            $fixed = $perMember($f, $a, $a);
            $fixed = uu_test_route($fixed, $rejected, $a);
            $fixed = uu_test_route($fixed, $rejected, $typo);
            $fixed['now'] = $s['now'] + 30;
            $runs = [$typoRun, $applyRun($fixed, $typoRun['st'])];
            return true;
        });
        uu_check($t, "(a10) $family, a Save typo fails the direct probe on every member: fallback, A keeps its member "
            . 'route until the restore is confirmed, then both get their reject route and A is released',
            $ok && $runs !== null && $runs[0]['p']['action'] === 'tunnel'
            && $runs[0]['acts'] === ["route add {$f['arg']} -host $typo {$f['hop_a']} -ifp {$f['if_a']}", $wait,
                "probe_direct $typo .", "route change {$f['arg']} -host $typo {$f['hop_b']} -ifp {$f['if_b']}", $wait,
                "probe_direct $typo .", $restoreDot, 'uc forward', $rejectOf($f, $typo), $rejectOf($f, $a)]
            && $runs[0]['st']['mode'] === 'fallback'
            && $runs[0]['st']['addresses'] === [$typo => $entry($rejectRecord, false),
                $a => $entry($rejectRecord, false, $now)]);
        uu_check($t, "(a9) $family, the typo fixed within a minute: A, an orphan in its hold, is re-used by route "
            . 'change from its reject route, never a delete and add, and its released_at clears; the typo is released',
            $ok && $runs !== null && $runs[1]['p']['action'] === 'tunnel'
            && $runs[1]['acts'][0] === "route change {$f['arg']} -host $a {$f['hop_a']} -ifp {$f['if_a']}"
            && array_filter($runs[1]['acts'], fn (string $c): bool => str_starts_with($c, 'route delete')
                || str_starts_with($c, 'route add')) === []
            && $runs[1]['st']['member'] === 'wg-a'
            && $runs[1]['st']['addresses'] === [$typo => $entry($rejectRecord, false, $now + 30),
                $a => $entry($viaRecord($f, 'wg-a'), true)]);

        $run = null;
        $ok = uu_try_case(function () use ($perMember, $f, $a, $b, $c, $usable, $applyRun, $with, $entry, $via,
                                           $viaRecord, &$run): bool {
            $s = uu_test_in_tunnel($perMember($f, $a, $b), 'wg-b');
            $s = uu_test_route($s, $via($f, 'wg-a'), $a);
            /* a third member on its own resolver, never routed: the last resort leaves it alone */
            $s['tiers'][] = ['wg-c'];
            $s['members']['wg-c'] = ['name' => 'wg-c', 'interface' => 'opt5', 'if' => $f['if_c'],
                                     'next_hop' => $f['hop_c']] + $s['members']['wg-a'];
            $s['probes']['wg-c'] = $s['probes']['wg-a'];
            $s = uu_test_resolver($s, 'wg-c', $c);
            $s['stop'] = UU_STOP_REMOVE;
            $st = $with(uu_test_plan_state('wg-b', $usable, 0, null, $b, $s),
                [$a => $entry($viaRecord($f, 'wg-a'), false), $b => $entry($viaRecord($f, 'wg-b'), true)]);
            $run = $applyRun($s, $st, ['uc_fail' => ['forward_add'], 'restart' => false, 'restarts' => true]);
            return true;
        });
        $removed = $run === null ? [] : array_values(array_filter($run['calls']->getArrayCopy(), fn (string $c): bool
            => str_starts_with($c, 'log ' . LOG_ERR . ' ') && str_contains($c, 'being removed')));
        uu_check($t, "(a13) $family, a removal with two entries whose restore and restart fail: both changed to their "
            . 'reject route, nothing deleted, one error naming both with the remedy for each; a third member\'s '
            . 'resolver, never routed, untouched',
            $ok && $run !== null
            && $run['acts'] === [$restoreDot, 'restart', $rejectOf($f, $a), $rejectOf($f, $b)]
            && $run['st']['addresses'] === [$a => $entry($rejectRecord, false), $b => $entry($rejectRecord, true)]
            && $removed === ['log ' . LOG_ERR . ' stop: the package is being removed while Unbound may still forward '
                . "to $a, $b, so its queries to $a, $b are rejected locally until Unbound restarts: run configctl "
                . 'unbound restart, then ' . uu_route_delete_text($a) . '; ' . uu_route_delete_text($b)]);

        /* a failed reject route over the previous address, an orphan: it keeps its member route, its entry and its
         * hold, one error names it, the new address is switched in all the same, and the next run's route repair
         * puts the reject route on */
        $runs = null;
        $ok = uu_try_case(function () use ($perMember, $f, $a, $b, $usable, $applyRun, $via, &$runs): bool {
            $s = $perMember($f, $b, $b);
            $s['unbound']['live_root'] = [$a];
            $s = uu_test_route($s, $via($f, 'wg-a'), $a);
            $s['members']['wg-a']['force_down'] = true;
            $first = $applyRun($s, uu_test_plan_state('wg-a', $usable, 0, null, $a, $s),
                ['route_fail' => ["change $a", "add $a"]]);
            $next = uu_test_in_tunnel($perMember($f, $b, $b), 'wg-b');
            $next['members']['wg-a']['force_down'] = true;
            $next = uu_test_route($next, $via($f, 'wg-a'), $a);
            $next['now'] = $s['now'] + 1;
            $runs = [$first, $applyRun($next, $first['st'])];
            return true;
        });
        uu_check($t, "(a15) $family, the previous address's reject route fails: A keeps its member route, record and "
            . 'hold, one error names it, B is switched in; the next run repairs it to its reject route',
            $ok && $runs !== null && $runs[0]['st']['member'] === 'wg-b'
            && in_array($rejectOf($f, $a), $runs[0]['acts'], true)
            && $runs[0]['st']['addresses'] === [$a => $entry($viaRecord($f, 'wg-a'), false, $now),
                $b => $entry($viaRecord($f, 'wg-b'), true)]
            && $errorsOf($runs[0]) === ['log ' . LOG_ERR . " route: the reject route for $a failed"]
            && $runs[1]['p']['route_repair'] && $runs[1]['acts'][0] === $rejectOf($f, $a)
            && $runs[1]['st']['member'] === 'wg-b'
            && $runs[1]['st']['addresses'] === [$a => $entry($rejectRecord, false, $now),
                $b => $entry($viaRecord($f, 'wg-b'), true)]
            && $errorsOf($runs[1]) === []);

        $run = null;
        $ok = uu_try_case(function () use ($perMember, $f, $a, $b, $usable, $applyRun, $with, $entry, $via,
                                           $viaRecord, $now, &$run): bool {
            $s = uu_test_in_tunnel($perMember($f, $b, $b), 'wg-b');
            $s['members']['wg-a']['force_down'] = true;
            $s = uu_test_route($s, $via($f, 'wg-a'), $a);
            $st = $with(uu_test_plan_state('wg-b', $usable, 0, null, $b, $s),
                [$a => $entry($viaRecord($f, 'wg-a'), false, $now - 60), $b => $entry($viaRecord($f, 'wg-b'), true)]);
            $run = $applyRun($s, $st, ['route_fail' => ["change $a", "add $a"]]);
            return true;
        });
        uu_check($t, "(a16) $family, an orphan due for its drain but still on a member route (its reject route fails "
            . 'again): the route repair tries the reject route, and nothing is flushed or deleted',
            $ok && $run !== null && $run['p']['action'] === 'none' && $run['p']['route_repair']
            && $run['p']['drain'] === [$a]
            && $run['acts'] === array_merge([$rejectOf($f, $a), "route add {$f['arg']} -host $a {$f['lo']} -reject",
                "probe_direct $b ."], $through)
            && $run['st']['addresses'][$a] === $entry($viaRecord($f, 'wg-a'), false, $now - 60));

        $runs = null;
        $ok = uu_try_case(function () use ($perMember, $f, $a, $b, $usable, $applyRun, $with, $entry, $rejected,
                                           $rejectRecord, $viaRecord, $now, &$runs): bool {
            $s = uu_test_in_tunnel($perMember($f, $b, $b), 'wg-b');
            $s['members']['wg-a']['force_down'] = true;
            $s = uu_test_route($s, $rejected, $a);
            $s['now'] = $now + 60;
            $st = $with(uu_test_plan_state('wg-b', $usable, 0, null, $b, $s),
                [$a => $entry($rejectRecord, false, $now), $b => $entry($viaRecord($f, 'wg-b'), true)]);
            $failed = $applyRun($s, $st, ['route_fail' => ['delete']]);
            $s['now'] = $now + 61;
            $runs = [$failed, $applyRun($s, $failed['st'])];
            return true;
        });
        uu_check($t, "(a17) $family, the drain's delete fails: A keeps its reject route, record and hold, one error "
            . 'names it, B stays switched in; the next run drains and deletes it',
            $ok && $runs !== null && array_slice($runs[0]['acts'], -3) === [$flushReq, $drain, $deleteOf($f, $a)]
            && $runs[0]['st']['addresses'] === [$a => $entry($rejectRecord, false, $now),
                $b => $entry($viaRecord($f, 'wg-b'), true)]
            && $errorsOf($runs[0]) === ['log ' . LOG_ERR . " route: deleting the route of $a failed"]
            && $runs[0]['st']['member'] === 'wg-b'
            && array_slice($runs[1]['acts'], -3) === [$flushReq, $drain, $deleteOf($f, $a)]
            && $runs[1]['st']['addresses'] === [$b => $entry($viaRecord($f, 'wg-b'), true)]
            && $errorsOf($runs[1]) === []);

        /* a fallback whose restore is refused, with B switched in and A an orphan in its hold on a member route */
        $runs = null;
        $ok = uu_try_case(function () use ($perMember, $f, $a, $b, $usable, $applyRun, $with, $entry, $via,
                                           $viaRecord, $settledDown, $now, &$runs): bool {
            $s = uu_test_in_tunnel($perMember($f, $b, $b), 'wg-b');
            $s = uu_test_route($s, $via($f, 'wg-a'), $a);
            $s['probes']['wg-a'] = $settledDown;
            $s['probes']['wg-b'] = $settledDown;
            $st = $with(uu_test_plan_state('wg-b', $usable, 0, null, $b, $s),
                [$a => $entry($viaRecord($f, 'wg-a'), false, $now - 10), $b => $entry($viaRecord($f, 'wg-b'), true)]);
            $failed = $applyRun($s, $st, ['uc_fail' => ['forward_add']]);
            $runs = [$failed, $applyRun($s, $failed['st'])];
            return true;
        });
        uu_check($t, "(a18) $family, a fallback whose restore is refused: no reject route anywhere, one error names B, "
            . 'A and B keep their member routes, records and A its hold, still tunnel on wg-b; the next run restores, '
            . 'then rejects both',
            $ok && $runs !== null && $runs[0]['p']['action'] === 'fallback' && $runs[0]['acts'] === [$restoreDot]
            && $runs[0]['st']['mode'] === 'tunnel' && $runs[0]['st']['member'] === 'wg-b'
            && $runs[0]['st']['addresses'] === [$a => $entry($viaRecord($f, 'wg-a'), false, $now - 10),
                $b => $entry($viaRecord($f, 'wg-b'), true)]
            && array_slice($errorsOf($runs[0]), -1) === ['log ' . LOG_ERR . ' fallback incomplete: Unbound may still '
                . "forward to the resolver ($b), so no reject route; the next evaluation tries again"]
            && $runs[1]['acts'] === [$restoreDot, 'uc forward', $rejectOf($f, $a), $rejectOf($f, $b)]
            && $runs[1]['st']['mode'] === 'fallback'
            && $runs[1]['st']['addresses'] === [$a => $entry($rejectRecord, false, $now - 10),
                $b => $entry($rejectRecord, false)]
            && $errorsOf($runs[1]) === []);

        $runs = null;
        $ok = uu_try_case(function () use ($perMember, $f, $a, $b, $usable, $applyRun, $with, $entry, $via,
                                           $viaRecord, &$runs): bool {
            $s = uu_test_in_tunnel($perMember($f, $a, $b), 'wg-b');
            $s = uu_test_route($s, $via($f, 'wg-a'), $a);
            $s['settings']['enabled'] = false;
            $st = $with(uu_test_plan_state('wg-b', $usable, 0, null, $b, $s),
                [$a => $entry($viaRecord($f, 'wg-a'), false), $b => $entry($viaRecord($f, 'wg-b'), true)]);
            $refused = $applyRun($s, $st, ['uc_fail' => ['forward_add']]);
            $runs = [$applyRun($s, $st, ['uc_fail' => ['flush_requestlist']]), $refused,
                     $applyRun($s, $refused['st'])];
            return true;
        });
        uu_check($t, "(a20) $family, a disabled plugin's stop with two entries: its flush_requestlist fails, so both "
            . 'keep their reject route, one error names both; its restore refused, both keep their member route and '
            . 'record, one error names both, and the next tick restores, then drains and deletes both',
            $ok && $runs !== null
            && $runs[0]['acts'] === [$restoreDot, 'uc forward', $rejectOf($f, $a), $rejectOf($f, $b), $flushReq]
            && $runs[0]['st']['addresses'] === [$a => $entry($rejectRecord, false), $b => $entry($rejectRecord, false)]
            && $errorsOf($runs[0]) === ['log ' . LOG_ERR . ' stop: unbound-control flush_requestlist failed, so the '
                . "reject route stays: Unbound may still retry the resolver ($a, $b)"]
            && $runs[1]['acts'] === [$restoreDot]
            && $runs[1]['st']['addresses'] === [$a => $entry($viaRecord($f, 'wg-a'), false),
                $b => $entry($viaRecord($f, 'wg-b'), true)]
            && array_slice($errorsOf($runs[1]), -1) === ['log ' . LOG_ERR . " stop: Unbound may still forward to the "
                . "resolver ($a, $b), so its route stays (without it the queries would follow the default route)"]
            && $runs[2]['acts'] === [$restoreDot, 'uc forward', $rejectOf($f, $a), $rejectOf($f, $b), $flushReq,
                $drain, $deleteOf($f, $a), $deleteOf($f, $b)]
            && $runs[2]['st']['addresses'] === [] && $errorsOf($runs[2]) === []);

        /* (a21) the Save typo with the restore refused: A, the old live root and an orphan now, keeps its member
         * route, forwarded and not yet released; the next run's restore confirms the configured root, and A is released
         * then */
        $runs = null;
        $ok = uu_try_case(function () use ($perMember, $f, $a, $typo, $usable, $applyRun, $via, &$runs): bool {
            $s = $perMember($f, $typo, $typo);
            $s['unbound']['live_root'] = [$a];
            $s = uu_test_route($s, $via($f, 'wg-a'), $a);
            $failed = $applyRun($s, uu_test_plan_state('wg-a', $usable, 0, null, $a, $s),
                ['direct' => [$f['if_a'] => [false], $f['if_b'] => [false]], 'uc_fail' => ['forward_add']]);
            $next = uu_test_route($s, $via($f, 'wg-b'), $typo);
            $next['now'] = $s['now'] + 30;
            $runs = [$failed, $applyRun($next, $failed['st'])];
            return true;
        });
        uu_check($t, "(a21) $family, the Save typo with the restore refused: no reject route, A keeps its member "
            . 'route, forwarded, not released, and the fallback line names it; the next run restores, rejects both and '
            . 'releases A at that run\'s time',
            $ok && $runs !== null && array_slice($runs[0]['acts'], -1) === [$restoreDot]
            && array_filter($runs[0]['acts'], fn (string $c): bool => str_ends_with($c, ' -reject')) === []
            && $runs[0]['st']['addresses'][$a] === $entry($viaRecord($f, 'wg-a'), true)
            && array_slice($errorsOf($runs[0]), -1) === ['log ' . LOG_ERR . ' fallback incomplete: Unbound may still '
                . "forward to the resolver ($a), so no reject route; the next evaluation tries again"]
            && $runs[1]['p']['action'] === 'fallback'
            && $runs[1]['acts'] === [$restoreDot, 'uc forward', $rejectOf($f, $typo), $rejectOf($f, $a)]
            && $runs[1]['st']['addresses'] === [$typo => $entry($rejectRecord, false),
                $a => $entry($rejectRecord, false, $now + 30)]);

        /* (a22) tunnel mode's route repair of an orphan whose route went: the reject route is added, the entry and its
         * hold kept for the drain, its line with no reason (Unbound was not on it) */
        $run = null;
        $ok = uu_try_case(function () use ($perMember, $f, $a, $b, $usable, $applyRun, $with, $entry, $viaRecord,
                                           $now, &$run): bool {
            $s = uu_test_in_tunnel($perMember($f, $b, $b), 'wg-b');
            $s['members']['wg-a']['force_down'] = true;
            $s = uu_test_route($s, ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false,
                                    'ours' => false], $a);
            $st = $with(uu_test_plan_state('wg-b', $usable, 0, null, $b, $s),
                [$a => $entry($viaRecord($f, 'wg-a'), false, $now - 10), $b => $entry($viaRecord($f, 'wg-b'), true)]);
            $run = $applyRun($s, $st);
            return true;
        });
        uu_check($t, "(a22) $family, tunnel mode's route repair of an orphan whose route is gone: its reject route "
            . 'added, the entry kept with its hold, the line exactly "route: A rejected locally"',
            $ok && $run !== null && $run['p']['route_repair']
            && $run['acts'] === array_merge(["route add {$f['arg']} -host $a {$f['lo']} -reject", "probe_direct $b ."],
                $through)
            && $run['st']['addresses'] === [$a => $entry($rejectRecord, false, $now - 10),
                $b => $entry($viaRecord($f, 'wg-b'), true)]
            && $lineAt($run['calls'], "route: $a rejected locally") >= 0
            && !uu_test_logged($run['calls'], LOG_NOTICE, 'previous member'));

        /* (a23) a switch after an external restart: the record says A was forwarded, the snapshot's read says not, so
         * A is not the previous member's resolver in its line */
        $run = null;
        $ok = uu_try_case(function () use ($perMember, $f, $a, $b, $usable, $applyRun, &$run): bool {
            $s = uu_test_in_tunnel($perMember($f, $a, $b), 'wg-a');
            $s['members']['wg-a']['force_down'] = true;
            $s['unbound']['live_root'] = $s['zone']['addrs'];
            $run = $applyRun($s, uu_test_plan_state('wg-a', $usable, 0, null, $a, $s));
            return true;
        });
        uu_check($t, "(a23) $family, a switch to wg-b after an external restart onto the configured root: A's reject "
            . 'line has no "previous member\'s resolver"',
            $ok && $run !== null && $run['st']['member'] === 'wg-b'
            && in_array("uc forward_add . $b", $run['acts'], true) && in_array($rejectOf($f, $a), $run['acts'], true)
            && $lineAt($run['calls'], "route: $a rejected locally") >= 0
            && !uu_test_logged($run['calls'], LOG_NOTICE, 'previous member'));

        /* (a24) two orphans due in one run: one flush_requestlist, one drain, then each delete */
        $run = null;
        $ok = uu_try_case(function () use ($perMember, $f, $a, $b, $c, $usable, $applyRun, $with, $entry, $rejected,
                                           $rejectRecord, $viaRecord, $now, &$run): bool {
            $s = uu_test_in_tunnel($perMember($f, $b, $b), 'wg-b');
            $s['members']['wg-a']['force_down'] = true;
            $s = uu_test_route(uu_test_route($s, $rejected, $a), $rejected, $c);
            $s['now'] = $now + 60;
            $st = $with(uu_test_plan_state('wg-b', $usable, 0, null, $b, $s),
                [$a => $entry($rejectRecord, false, $now), $b => $entry($viaRecord($f, 'wg-b'), true),
                 $c => $entry($rejectRecord, false, $now)]);
            $run = $applyRun($s, $st);
            return true;
        });
        uu_check($t, "(a24) $family, two orphans due in one run: one flush_requestlist, one drain, then each delete; "
            . 'only the member\'s resolver stays in the map',
            $ok && $run !== null && $run['p']['drain'] === [$a, $c]
            && array_slice($run['acts'], -4) === [$flushReq, $drain, $deleteOf($f, $a), $deleteOf($f, $c)]
            && count(array_filter($run['acts'], fn (string $x): bool => $x === $flushReq)) === 1
            && $run['st']['addresses'] === [$b => $entry($viaRecord($f, 'wg-b'), true)]);

        // Unbound's live root naming the resolver beside a configured forwarder B (an external forward_add . A B).
        $zoneOf = fn (array $addrs): array => ['shape' => 'one', 'addrs' => $addrs, 'tls' => false, 'problems' => []];
        $named = function (array $configured, ?string $stop, bool $enabled) use ($perMember, $f, $a, $b, $via,
                                                                                 $settledDown, $zoneOf): array {
            $s = $perMember($f, $a, $a);
            $s['zone'] = $zoneOf($configured);
            $s['contract_input']['zone'] = $s['zone'];
            $s['unbound']['live_root'] = [$a, $b];
            $s = uu_test_route($s, $via($f, 'wg-a'), $a);
            $s['probes']['wg-a'] = $settledDown;
            $s['probes']['wg-b'] = $settledDown;
            $s['stop'] = $stop;
            $s['settings']['enabled'] = $enabled;
            return $s;
        };
        $inFallback = fn (array $s): array => $with(uu_test_plan_state(null, $usable),
            [$a => $entry($viaRecord($f, 'wg-a'), true)]);
        foreach (['fallback' => [null, true], 'a requested stop' => [UU_STOP_REQUEST, false],
                  'the removal' => [UU_STOP_REMOVE, true]] as $what => [$stop, $enabled]) {
            $runs = null;
            $ok = uu_try_case(function () use ($named, $b, $stop, $enabled, $applyRun, $inFallback, $rejected, $a,
                                               &$runs): bool {
                $s = $named([$b], $stop, $enabled);
                $first = $applyRun($s, $inFallback($s));
                $next = $s;
                $next['unbound']['live_root'] = [$b];
                $next = uu_test_route($next, $first['st']['addresses'] === [] ? ['present' => false, 'gateway' => '',
                    'interface' => '', 'reject' => false, 'ours' => false] : $rejected, $a);
                $runs = [$first, $applyRun($next, $first['st'])];
                return true;
            });
            $tail = $stop === null ? [$rejectOf($f, $a)] : [$rejectOf($f, $a), $flushReq, $drain, $deleteOf($f, $a)];
            uu_check($t, "(b1) $family, configured [B], live [A, B], $what: one restore, confirmed [B], then A's "
                . 'reject route' . ($stop === null ? ', forwarded false' : ', the drain and the delete') . '; no '
                . 'restore on the next run',
                $ok && $runs !== null
                && $runs[0]['acts'] === array_merge(["uc forward_add . $b", 'uc forward'], $tail)
                && $runs[0]['st']['addresses'] === ($stop === null ? [$a => $entry($rejectRecord, false)] : [])
                && $runs[1]['acts'] === []);
        }
        foreach (['fallback' => [null, true], 'a requested stop' => [UU_STOP_REQUEST, false],
                  'the removal' => [UU_STOP_REMOVE, true]] as $what => [$stop, $enabled]) {
            $runs = null;
            $ok = uu_try_case(function () use ($named, $a, $b, $stop, $enabled, $applyRun, $inFallback, &$runs): bool {
                $s = $named([$a, $b], $stop, $enabled);
                $first = $applyRun($s, $inFallback($s));
                $runs = [$first, $applyRun($s, $first['st'])];
                return true;
            });
            uu_check($t, "(b2) $family, configured [A, B], live [A, B], $what: no restore, no reject route and no "
                . 'delete while the root names A, the entry kept forwarded, and not a line on either run',
                $ok && $runs !== null && $runs[0]['calls']->getArrayCopy() === []
                && $runs[1]['calls']->getArrayCopy() === []
                && $runs[0]['st']['addresses'] === [$a => $entry($viaRecord($f, 'wg-a'), true)]
                && $runs[1]['st']['addresses'] === [$a => $entry($viaRecord($f, 'wg-a'), true)]);
        }
        foreach (['fallback' => [null, true], 'a requested stop' => [UU_STOP_REQUEST, false],
                  'the removal' => [UU_STOP_REMOVE, true]] as $what => [$stop, $enabled]) {
            $runs = null;
            $ok = uu_try_case(function () use ($named, $a, $b, $stop, $enabled, $applyRun, $usable, $settledDown,
                                               &$runs): bool {
                $s = $named([$a, $b], $stop, $enabled);
                $s = uu_test_in_tunnel($s, 'wg-a');
                $first = $applyRun($s, uu_test_plan_state('wg-a', $usable, 0, null, $a, $s));
                $next = $s;
                $next['unbound']['live_root'] = [$a, $b];
                $runs = [$first, $applyRun($next, $first['st'])];
                return true;
            });
            uu_check($t, "(b2) $family, the same from tunnel mode on A, $what: the restore to [A, B], then no reject "
                . 'route over A, fallback, the entry kept forwarded, no error' . ($stop === null ? '' : ', one warning '
                . 'that its route stays') . ($stop === UU_STOP_REMOVE ? ', with the delete to run once the package is '
                . 'removed' : '') . '; the next run calls nothing and logs nothing',
                $ok && $runs !== null && $runs[0]['acts'] === ["uc forward_add . $a $b", 'uc forward']
                && $runs[0]['st']['mode'] === 'fallback'
                && !in_array(true, array_map(fn (string $c): bool => str_starts_with($c, 'log ' . LOG_ERR . ' '),
                    $runs[0]['calls']->getArrayCopy()), true)
                && ($stop === null) === !uu_test_logged($runs[0]['calls'], LOG_WARNING,
                    "stop: Unbound's configured root zone names $a, so its route stays")
                && ($stop === UU_STOP_REMOVE) === uu_test_logged($runs[0]['calls'], LOG_WARNING, "stop: Unbound's "
                    . "configured root zone names $a, so its route stays (without it the queries would follow the "
                    . 'default route); once the package is removed, run ' . uu_route_delete_text($a)
                    . " when Unbound's configured root zone no longer names it")
                && $runs[0]['st']['addresses'] === [$a => $entry($viaRecord($f, 'wg-a'), true)]
                && $runs[1]['calls']->getArrayCopy() === []);
        }

        /* (b3) a requested stop from tunnel mode on A after A's route went, the configured zone [A, B]: the restore,
         * then nothing to reject or delete and no route to name; A's entry stays, forwarded */
        $run = null;
        $ok = uu_try_case(function () use ($named, $a, $b, $usable, $applyRun, &$run): bool {
            $s = uu_test_in_tunnel($named([$a, $b], UU_STOP_REQUEST, false), 'wg-a');
            $s = uu_test_route($s, ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false,
                                    'ours' => false], $a);
            $run = $applyRun($s, uu_test_plan_state('wg-a', $usable, 0, null, $a, $s));
            return true;
        });
        uu_check($t, "(b3) $family, a requested stop with the configured zone [A, B] and A's route gone: the restore, "
            . 'no route call, no warning naming a route, A recorded forwarded with no route',
            $ok && $run !== null && $run['acts'] === ["uc forward_add . $a $b", 'uc forward']
            && !uu_test_logged($run['calls'], LOG_WARNING, 'so its route stays')
            && $run['st']['addresses'] === [$a => $entry($viaRecord($f, 'wg-a'), true)]);

        /* (a25) dry run while Unbound's configured root zone names A and the plugin's member route to it stays: two
         * ticks, neither undoing anything nor logging a line */
        $runs = null;
        $ok = uu_try_case(function () use ($named, $a, $b, $applyRun, $inFallback, &$runs): bool {
            $s = $named([$a, $b], null, true);
            $s['settings']['dry_run'] = true;
            $first = $applyRun($s, $inFallback($s));
            $runs = [$first, $applyRun($s, $first['st'])];
            return true;
        });
        uu_check($t, "(a25) $family, dry run with configured [A, B], live [A, B] and A's member route kept: no undo, "
            . 'no line, on either tick',
            $ok && $runs !== null && $runs[0]['calls']->getArrayCopy() === []
            && $runs[1]['calls']->getArrayCopy() === []);

        /* (i1) Unbound's configured root zone is exactly [A], the resolver: its live root [A] is Unbound's own and no
         * tunnel mode, so a disabled plugin's stop and the no-candidate fallback leave tunnel mode once, then nothing
         * repeats: no line, no call, no new switch, no notification; with a candidate the entry needs no forward_add */
        $configuredA = function (?string $stop, bool $enabled, bool $down) use ($named, $a, $settledDown): array {
            $s = uu_test_in_tunnel($named([$a], $stop, $enabled), 'wg-a');
            if (!$down) {
                $s['probes']['wg-a'] = uu_test_probe('none', '0.0 %', 300);
                $s['probes']['wg-b'] = uu_test_probe('none', '0.0 %', 300);
            }
            return $s;
        };
        foreach (["a disabled plugin's stop" => [null, false, true], 'no candidate' => [null, true, true]]
                 as $what => [$stop, $enabled, $down]) {
            $runs = null;
            $ok = uu_try_case(function () use ($configuredA, $stop, $enabled, $down, $a, $usable, $applyRun,
                                               &$runs): bool {
                $s = $configuredA($stop, $enabled, $down);
                $first = $applyRun($s, uu_test_plan_state('wg-a', $usable, 0, null, $a, $s));
                $second = $applyRun($s, $first['st']);
                $runs = [$first, $second, $applyRun($s, $second['st'])];
                return true;
            });
            uu_check($t, "(i1) $family, configured root [A], $what: the first tick leaves tunnel mode once (A's route "
                . 'and entry kept, never rejected); the second and third call nothing, log nothing and switch nothing',
                $ok && $runs !== null && $runs[0]['st']['mode'] === 'fallback'
                && array_filter($runs[0]['acts'], fn (string $c): bool => str_starts_with($c, 'route ')) === []
                && $runs[0]['st']['addresses'] === [$a => $entry($viaRecord($f, 'wg-a'), true)]
                && uu_notify_due(null, $runs[0]['st']['last_switch'])
                && $runs[1]['p']['state']['mode'] === 'fallback' && $runs[1]['calls']->getArrayCopy() === []
                && $runs[2]['calls']->getArrayCopy() === []
                && !uu_notify_due($runs[0]['st']['last_switch'], $runs[1]['st']['last_switch'])
                && !uu_notify_due($runs[1]['st']['last_switch'], $runs[2]['st']['last_switch'])
                && $runs[2]['st']['addresses'] === [$a => $entry($viaRecord($f, 'wg-a'), true)]);
        }
        $runs = null;
        $ok = uu_try_case(function () use ($configuredA, $a, $usable, $applyRun, $inFallback, &$runs): bool {
            $s = $configuredA(null, true, false);
            $first = $applyRun($s, $inFallback($s));
            $runs = [$first, $applyRun($s, $first['st'])];
            return true;
        });
        uu_check($t, "(i1) $family, configured root [A], from fallback with a candidate: one entry with no "
            . 'forward_add (flush_infra and forward), tunnel mode on wg-a; the next tick only checks',
            $ok && $runs !== null && $runs[0]['p']['action'] === 'tunnel'
            && $runs[0]['acts'] === array_merge(["probe_direct $a .", "uc flush_infra $a", 'uc forward'], $through)
            && $runs[0]['st']['mode'] === 'tunnel' && $runs[0]['st']['member'] === 'wg-a'
            && $runs[1]['p']['action'] === 'none' && !$runs[1]['p']['reassert']
            && $runs[1]['acts'] === array_merge(["probe_direct $a ."], $through)
            && !uu_notify_due($runs[0]['st']['last_switch'], $runs[1]['st']['last_switch']));

        /* (a26) tunnel mode's route repair reaching rejectOthers() with no checkpoint before it: wg-a's own resolver F,
         * which sorts first, on a member route of the plugin's but not in the map (a lost state), and A in the map with
         * its route gone; F's reject route saves the state, and A is still rejected after it, its hold kept */
        $run = null;
        $ok = uu_try_case(function () use ($perMember, $f, $a, $b, $usable, $applyRun, $with, $entry, $via,
                                           $viaRecord, $now, &$run): bool {
            $s = uu_test_in_tunnel($perMember($f, $f['first'], $b), 'wg-b');
            $s['members']['wg-a']['force_down'] = true;
            $s = uu_test_route($s, $via($f, 'wg-a'), $f['first']);
            $s = uu_test_route($s, ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false,
                                    'ours' => false], $a);
            $st = $with(uu_test_plan_state('wg-b', $usable, 0, null, $b, $s),
                [$a => $entry($viaRecord($f, 'wg-a'), false, $now - 10), $b => $entry($viaRecord($f, 'wg-b'), true)]);
            $run = $applyRun($s, $st);
            return true;
        });
        uu_check($t, "(a26) $family, route repair with an unrecorded routed resolver sorting first and a route-less "
            . 'orphan: both get their reject route, the orphan keeps its hold',
            $ok && $run !== null && $run['p']['action'] === 'none' && $run['p']['route_repair']
            && $run['acts'] === array_merge([$rejectOf($f, $f['first']),
                "route add {$f['arg']} -host $a {$f['lo']} -reject", "probe_direct $b ."], $through)
            && $run['st']['addresses'] === [$f['first'] => $entry($rejectRecord, false),
                $a => $entry($rejectRecord, false, $now - 10), $b => $entry($viaRecord($f, 'wg-b'), true)]);

        /* (a27) a switch whose route change saves the state while a route-less orphan is in the map: the orphan still
         * gets its reject route and keeps its hold */
        $run = null;
        $ok = uu_try_case(function () use ($perMember, $f, $a, $b, $c, $usable, $applyRun, $with, $entry, $rejected,
                                           $rejectRecord, $viaRecord, $now, &$run): bool {
            $s = uu_test_in_tunnel($perMember($f, $a, $b), 'wg-a');
            $s['members']['wg-a']['force_down'] = true;
            $s = uu_test_route($s, $rejected, $b);
            $st = $with(uu_test_plan_state('wg-a', $usable, 0, null, $a, $s),
                [$a => $entry($viaRecord($f, 'wg-a'), true), $b => $entry($rejectRecord, false),
                 $c => $entry($viaRecord($f, 'wg-a'), false, $now - 10)]);
            $run = $applyRun($s, $st);
            return true;
        });
        uu_check($t, "(a27) $family, a switch to wg-b whose route change saves the state, with a route-less orphan C "
            . 'in the map: C gets its reject route after A, its hold kept',
            $ok && $run !== null && $run['st']['member'] === 'wg-b'
            && $run['acts'][0] === "route change {$f['arg']} -host $b {$f['hop_b']} -ifp {$f['if_b']}"
            && in_array("route add {$f['arg']} -host $c {$f['lo']} -reject", $run['acts'], true)
            && $run['st']['addresses'] === [$a => $entry($rejectRecord, false),
                $b => $entry($viaRecord($f, 'wg-b'), true), $c => $entry($rejectRecord, false, $now - 10)]);

        /* (c1)-(c4) an orphan that Unbound's own configured root zone names: the owner's forwarder wins over the
         * hold */
        $configuredOrphan = function (bool $enabled, bool $fromTunnel) use ($perMember, $f, $a, $c, $settledDown,
                                                                            $zoneOf, $via, $rejected): array {
            $s = $perMember($f, $c, $c);
            $s['zone'] = $zoneOf([$a]);
            $s['contract_input']['zone'] = $s['zone'];
            $s = uu_test_route($s, $rejected, $a);
            $s = uu_test_route($s, $fromTunnel ? $via($f, 'wg-b') : $rejected, $c);
            $s['unbound']['live_root'] = $fromTunnel ? [$c] : [$a];
            $s['probes']['wg-a'] = $settledDown;
            $s['probes']['wg-b'] = $settledDown;
            $s['settings']['enabled'] = $enabled;
            return $s;
        };
        /* the snapshot of the run after: Unbound on [A], A's route as given, C on its reject route */
        $after = function (array $s, bool $aRouted) use ($a, $c, $rejected): array {
            $s['unbound']['live_root'] = [$a];
            $s = uu_test_route($s, $aRouted ? $rejected : ['present' => false, 'gateway' => '', 'interface' => '',
                'reject' => false, 'ours' => false], $a);
            return uu_test_route($s, $rejected, $c);
        };
        $onB = fn (array $s): array => $with(uu_test_plan_state('wg-b', $usable, 0, null, $c, $s),
            [$a => $entry($rejectRecord, false, $now - 10), $c => $entry($viaRecord($f, 'wg-b'), true)]);
        $runs = null;
        $ok = uu_try_case(function () use ($configuredOrphan, $after, $onB, $applyRun, &$runs): bool {
            $s = $configuredOrphan(true, true);
            $first = $applyRun($s, $onB($s));
            $runs = [$first, $applyRun($after($s, false), $first['st'])];
            return true;
        });
        uu_check($t, "(c1) $family, configured root [A], A an orphan in its hold after a switch to C, both members "
            . 'down: the restore puts Unbound on [A], then A is drained and deleted in the same run, C rejected; the '
            . 'next tick is silent',
            $ok && $runs !== null && $runs[0]['p']['action'] === 'fallback'
            && $runs[0]['acts'] === ["uc forward_add . $a", 'uc forward', $rejectOf($f, $c), $flushReq, $drain,
                $deleteOf($f, $a)]
            && $runs[0]['st']['addresses'] === [$c => $entry($rejectRecord, false)] && $errorsOf($runs[0]) === []
            && !uu_test_logged($runs[0]['calls'], LOG_WARNING, 'stays')
            && $runs[1]['calls']->getArrayCopy() === []);
        $runs = null;
        $ok = uu_try_case(function () use ($configuredOrphan, $after, $onB, $applyRun, $with, $entry, $rejectRecord,
                                           $usable, $a, $c, $now, &$runs): bool {
            $s = $configuredOrphan(false, true);
            $first = $applyRun($s, $onB($s));
            /* a disabled plugin's tick that finds A on its reject route under the configured zone, in fallback */
            $quiet = $configuredOrphan(false, false);
            $fallback = $with(uu_test_plan_state(null, $usable), [$a => $entry($rejectRecord, false, $now - 10),
                $c => $entry($rejectRecord, false)]);
            $tick = $applyRun($quiet, $fallback);
            /* the stop deleted both routes */
            $next = uu_test_route($after($s, false), ['present' => false, 'gateway' => '', 'interface' => '',
                'reject' => false, 'ours' => false], $c);
            $runs = [$first, $applyRun($next, $first['st']), $tick];
            return true;
        });
        uu_check($t, "(c2) $family, the same with the plugin disabled: the stop restores [A], releases A behind its "
            . 'reject route with C (one flush, one drain), the map empties, no line says a route stays; the next tick '
            . 'is silent; a disabled tick in fallback that finds A so releases it too',
            $ok && $runs !== null && $runs[0]['p']['action'] === 'stop'
            && $runs[0]['acts'] === ["uc forward_add . $a", 'uc forward', $rejectOf($f, $c), $flushReq, $drain,
                $deleteOf($f, $a), $deleteOf($f, $c)]
            && $runs[0]['st']['addresses'] === [] && !uu_test_logged($runs[0]['calls'], LOG_WARNING, 'stays')
            && $runs[1]['calls']->getArrayCopy() === []
            && $runs[2]['acts'] === [$flushReq, $drain, $deleteOf($f, $a), $deleteOf($f, $c)]
            && $runs[2]['st']['addresses'] === []);
        $runs = null;
        $ok = uu_try_case(function () use ($configuredOrphan, $after, $onB, $applyRun, &$runs): bool {
            $s = $configuredOrphan(true, true);
            $first = $applyRun($s, $onB($s), ['uc_fail' => ['flush_requestlist']]);
            $runs = [$first, $applyRun($after($s, true), $first['st'])];
            return true;
        });
        uu_check($t, "(c3) $family, the same with the flush failing: A keeps its reject route, record and hold, one "
            . 'error names it; the next run drains and deletes it',
            $ok && $runs !== null
            && $runs[0]['acts'] === ["uc forward_add . $a", 'uc forward', $rejectOf($f, $c), $flushReq]
            && $runs[0]['st']['addresses'] === [$a => $entry($rejectRecord, true, $now - 10),
                $c => $entry($rejectRecord, false)]
            && $errorsOf($runs[0]) === ['log ' . LOG_ERR . " route: draining $a failed (unbound-control "
                . 'flush_requestlist), so its reject route stays']
            && $runs[1]['p']['drain'] === [$a] && $runs[1]['acts'] === [$flushReq, $drain, $deleteOf($f, $a)]
            && $runs[1]['st']['addresses'] === [$c => $entry($rejectRecord, false)]);
        $runs = null;
        $ok = uu_try_case(function () use ($perMember, $f, $a, $b, $usable, $applyRun, $with, $entry, $rejected,
                                           $rejectRecord, $viaRecord, $zoneOf, $settledDown, &$runs): bool {
            $s = uu_test_in_tunnel($perMember($f, $a, $b), 'wg-b');
            $s['zone'] = $zoneOf([$a]);
            $s['contract_input']['zone'] = $s['zone'];
            $s = uu_test_route($s, $rejected, $a);
            $s['probes']['wg-a'] = $settledDown;
            $s['probes']['wg-b'] = $settledDown;
            $s['settings']['enabled'] = false;
            $first = $applyRun($s, $with(uu_test_plan_state('wg-b', $usable, 0, null, $b, $s),
                [$a => $entry($rejectRecord, false), $b => $entry($viaRecord($f, 'wg-b'), true)]));
            $next = uu_test_route($s, ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false,
                                       'ours' => false], $b);
            $next['unbound']['live_root'] = [$a];
            /* enabled, with wg-b's idle resolver on its reject route as fallback leaves it */
            $enabled = uu_test_route($next, $rejected, $b);
            $enabled['settings']['enabled'] = true;
            $runs = [$first, $applyRun($next, $first['st']), $applyRun($enabled, $first['st'])];
            return true;
        });
        uu_check($t, "(c4) $family, wg-a's own resolver A under the configured root [A]: a disabled stop restores [A], "
            . 'releases B, keeps A on its reject route and says what is true; neither the next disabled tick nor an '
            . 'enabled one with no candidate releases A, and both are silent',
            $ok && $runs !== null
            && $runs[0]['acts'] === ["uc forward_add . $a", 'uc forward', $rejectOf($f, $b), $flushReq, $drain,
                $deleteOf($f, $b)]
            && $runs[0]['st']['addresses'] === [$a => $entry($rejectRecord, true)]
            && uu_test_logged($runs[0]['calls'], LOG_WARNING, "stop: Unbound's configured root zone names $a, which "
                . "stays closed as one of the plugin's resolvers: its reject route stays, and Unbound's queries to it "
                . 'are rejected locally')
            && !uu_test_logged($runs[0]['calls'], LOG_WARNING, 'default route')
            && $runs[1]['calls']->getArrayCopy() === [] && $runs[2]['calls']->getArrayCopy() === []
            && $runs[2]['p']['drain'] === [] && $runs[2]['st']['addresses'][$a] === $entry($rejectRecord, true));
        /* (c6) a disabled plugin's tick in fallback with only the orphan left, on its reject route under the configured
         * root [A]: the stop releases it */
        $run = null;
        $ok = uu_try_case(function () use ($configuredOrphan, $applyRun, $with, $entry, $rejectRecord, $usable, $a, $c,
                                           $now, &$run): bool {
            $s = uu_test_route($configuredOrphan(false, false), ['present' => false, 'gateway' => '', 'interface' => '',
                'reject' => false, 'ours' => false], $c);
            $run = $applyRun($s, $with(uu_test_plan_state(null, $usable),
                [$a => $entry($rejectRecord, true, $now - 10)]));
            return true;
        });
        uu_check($t, "(c6) $family, a disabled tick in fallback with only the orphan A on its reject route under the "
            . 'configured root [A]: the stop drains and deletes it, the map empties',
            $ok && $run !== null && $run['p']['action'] === 'stop'
            && $run['acts'] === [$flushReq, $drain, $deleteOf($f, $a)] && $run['st']['addresses'] === []);
        /* (c7) an orphan the configured root [A] names but on a member route (its queries in the tunnel): neither the
         * plan nor apply drains it, and nothing repeats */
        $runs = null;
        $ok = uu_try_case(function () use ($configuredOrphan, $applyRun, $with, $entry, $rejectRecord, $viaRecord, $via,
                                           $usable, $f, $a, $c, &$runs): bool {
            $s = uu_test_route($configuredOrphan(true, false), $via($f, 'wg-a'), $a);
            $st = $with(uu_test_plan_state(null, $usable), [$a => $entry($viaRecord($f, 'wg-a'), true),
                $c => $entry($rejectRecord, false)]);
            $first = $applyRun($s, $st);
            $runs = [$first, $applyRun($s, $first['st'])];
            return true;
        });
        uu_check($t, "(c7) $family, an orphan the configured root [A] names on a member route: no drain planned, no "
            . 'call, its route and entry kept, on both ticks',
            $ok && $runs !== null && $runs[0]['p']['drain'] === [] && $runs[0]['calls']->getArrayCopy() === []
            && $runs[1]['calls']->getArrayCopy() === []
            && $runs[1]['st']['addresses'][$a] === $entry($viaRecord($f, 'wg-a'), true));

        /* (c8) an external restart has put Unbound on its configured root [A] while A, an orphan, is in its hold on its
         * reject route: dry run undoes that for real (one flush, then the delete) and only previews after it; a live
         * run drains it once and then calls nothing */
        foreach (['dry run' => true, 'a live run' => false] as $what => $dry) {
            $runs = null;
            $ok = uu_try_case(function () use ($configuredOrphan, $applyRun, $with, $entry, $rejectRecord, $usable, $a,
                                               $c, $now, $dry, &$runs): bool {
                $gone = ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false, 'ours' => false];
                $s = $configuredOrphan(true, false);
                $s['settings']['dry_run'] = $dry;
                $map = [$a => $entry($rejectRecord, false, $now - 10), $c => $entry($rejectRecord, false)];
                if ($dry) {
                    /* A's reject route is the only route of the plugin's: nothing else makes the run undo for real */
                    $s = uu_test_route($s, $gone, $c);
                    unset($map[$c]);
                }
                $first = $applyRun($s, $with(uu_test_plan_state(null, $usable), $map));
                $runs = [$first, $applyRun(uu_test_route($s, $gone, $a), $first['st'])];
                return true;
            });
            $dryOnly = fn (array $run): bool => array_filter($run['calls']->getArrayCopy(), fn (string $x): bool
                => !str_starts_with($x, 'log ') || !str_contains($x, '[dry]')) === [];
            uu_check($t, "(c8) $family, $what after an external restart onto the configured root [A], A an orphan on "
                . 'its reject route: one flush, a drain, A deleted, the map without it; the next tick '
                . ($dry ? 'only previews' : 'calls nothing'),
                $ok && $runs !== null
                && ($dry ? $runs[0]['acts'] === [$flushReq, $drain, $deleteOf($f, $a)]
                    && $runs[0]['st']['addresses'] === [] && $dryOnly($runs[1])
                    : $runs[0]['acts'] === [$flushReq, $drain, $deleteOf($f, $a)]
                    && $runs[0]['st']['addresses'] === [$c => $entry($rejectRecord, false)]
                    && $runs[1]['calls']->getArrayCopy() === []));
        }

        /* (a28) a switch after a lost state while the live root is [A], wg-a's own resolver, its route gone: A enters
         * the map from the read alone, and still gets its reject route once Unbound is confirmed on B */
        $run = null;
        $ok = uu_try_case(function () use ($perMember, $f, $a, $b, $usable, $applyRun, &$run): bool {
            $s = $perMember($f, $a, $b);
            $s['unbound']['live_root'] = [$a];
            $s['members']['wg-a']['force_down'] = true;
            $run = $applyRun($s, uu_test_plan_state(null, $usable));
            return true;
        });
        uu_check($t, "(a28) $family, a lost state, the live root [A] with A's route gone, a switch to wg-b: A gets its "
            . 'reject route and keeps its entry',
            $ok && $run !== null && $run['st']['member'] === 'wg-b'
            && in_array("route add {$f['arg']} -host $a {$f['lo']} -reject", $run['acts'], true)
            && ($run['st']['addresses'][$a] ?? null) === $entry($rejectRecord, false));

        /* (c5) the planner's rule alone: A on a reject route of the plugin's under the configured root [A] with no
         * entry for it is listed and drained (a real snapshot after a lost state never reads A's route) */
        $run = null;
        $ok = uu_try_case(function () use ($configuredOrphan, $applyRun, $usable, &$run): bool {
            $s = $configuredOrphan(true, false);
            $run = $applyRun($s, uu_test_plan_state(null, $usable));
            return true;
        });
        uu_check($t, "(c5) $family, the planner's rule: configured root [A], A on a reject route of the plugin's with "
            . 'no entry: the plan drains it, and it is drained and deleted in that run; C stays on its reject route',
            $ok && $run !== null && $run['p']['action'] === 'none' && $run['p']['drain'] === [$a]
            && $run['acts'] === [$flushReq, $drain, $deleteOf($f, $a)]
            && $run['st']['addresses'] === [$c => $entry(null, false)]);
    }

    // Never planned, across every case above; flush_requestlist only behind reject routes.
    $forbidden = ['flush', 'flush_zone', 'flush_bogus', 'flush_negative', 'reload', 'reload_keep_cache',
                  'fast_reload'];
    $clean = count($all) > 0;
    $previous = '';
    /* the addresses on their reject route at this point of the case, as its marker and its route calls say, and
     * before the last route call (a failed call changes nothing) */
    $onReject = [];
    $beforeRoute = [];
    /* a flush_requestlist ran in this case: every route deleted after it must be on its reject route then */
    $flushed = false;
    $restartsExpected = false;
    $restartsOk = true;
    $restarts = 0;
    foreach ($all as $call) {
        if (str_starts_with($call, '-- case')) {
            $previous = '';
            $onReject = preg_match('/ on reject (\S+)/', $call, $m) === 1 ? array_fill_keys(explode(',', $m[1]), true)
                : [];
            $flushed = false;
            $restartsExpected = str_contains($call, ' restarts');
            continue;
        }
        if ($call === 'restart') {
            $restarts++;
            $restartsOk = $restartsOk && $restartsExpected;
        }
        if ($call === '-- route failed') {
            $onReject = $beforeRoute;
            continue;
        }
        if (preg_match('/^route (\S+) .*-host (\S+)/', $call, $m) === 1) {
            $host = uu_ip_canonical($m[2]) ?? $m[2];
            $clean = $clean && ($m[1] !== 'delete' || !$flushed || isset($onReject[$host]));
            $beforeRoute = $onReject;
            if ($m[1] !== 'delete' && str_ends_with($call, ' -reject')) {
                $onReject[$host] = true;
            } else {
                unset($onReject[$host]);
            }
        }
        if (str_starts_with($call, 'uc ')) {
            $words = explode(' ', substr($call, 3));
            /* behind reject routes: a stop's or a drain's, so some address is on its reject route */
            $clean = $clean && !in_array($words[0], $forbidden, true)
                && ($words[0] !== 'flush_type' || $words === ['flush_type', '.', 'SOA'])
                && ($words[0] !== 'flush_requestlist' || $onReject !== []);
            $flushed = $flushed || $words[0] === 'flush_requestlist';
        }
        if (!str_starts_with($call, 'log ')) {
            $clean = $clean && !(str_starts_with($previous, 'route delete') && str_starts_with($call, 'route add'));
            $previous = $call;
        }
    }
    uu_check($t, 'no recorded call is ever flush, flush_zone, flush_bogus, flush_negative, reload, reload_keep_cache or fast_reload; flush_type only "<probe> SOA"; flush_requestlist only behind the reject route (every case above)',
        $clean);
    uu_check($t, '(a10) a restart only in the cases that expect one: a requested stop or a removal that cannot restore, a silent channel, the escalation (every case above)',
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
