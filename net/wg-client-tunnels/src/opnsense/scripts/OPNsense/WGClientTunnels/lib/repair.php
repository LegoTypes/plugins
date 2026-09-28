<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The IPv6 monitor repair's decisions (spec 2026-09-28 section 3.4.3): which tunnels to watch, whether one
 * needs a dpinger start, the back-off, and the order of one tick. Pure: monitor_repair.php does the reading,
 * the starting and the logging.
 */

require_once __DIR__ . '/tunnels.php';
require_once __DIR__ . '/actions.php';
require_once __DIR__ . '/selftest.php';

/* at most WGCT_REPAIR_MAX dpinger starts per gateway per WGCT_REPAIR_WINDOW seconds: each start SIGHUPs
 * core's watcher, so a dpinger that dies on start must not be restarted every minute */
const WGCT_REPAIR_MAX = 3;
const WGCT_REPAIR_WINDOW = 600;
/* how long one tick waits for the started dpingers' pidfiles (daemon -f writes them after pluginctl returns) */
const WGCT_REPAIR_POLL_SECONDS = 10;
const WGCT_REPAIR_POLL_USEC = 250000;

/**
 * The tunnels whose IPv6 monitor the repair watches: managed, enabled, unblocked, with an enabled,
 * monitored IPv6 gateway and an IPv6 tunnel address. Pure.
 *
 * @param array $derived wgct_derive()
 * @param array $core    wgct_core_snapshot()
 * @return list<array{gw6: string, device: string, interface: string, address: string, monitor: string}>
 */
function wgct_repair_watch(array $derived, array $core): array {
    $out = [];
    foreach ($derived['tunnels'] as $t) {
        if (!$t['enabled'] || wgct_blocked($t) || $t['monitor6_mode'] !== 'monitored' || $t['interface'] === null
            || $t['ipv6_address'] === null || !empty($core['gateways'][$t['gw6']]['disabled'])) {
            continue;
        }
        $out[] = ['gw6' => $t['gw6'], 'device' => $t['device'], 'interface' => $t['interface'],
                  'address' => explode('/', $t['ipv6_address'])[0], 'monitor' => $t['monitor6']];
    }
    return $out;
}

/**
 * Whether a watched gateway needs a dpinger start now (spec 3.4.3 step 2). Pure.
 *
 * @param array $w       a wgct_repair_watch() row
 * @param array $probe   pid_live: its pidfile names a live process; routed: interfaces_routed_address6()
 *                       (dpinger's own gate: not tentative, deprecated or detached), null when none;
 *                       duplicated: ifconfig marks the address duplicated; route_dev: the device the
 *                       monitor's host route leaves by, null without one
 * @param bool  $allowed the back-off allows a start
 * @return array{candidate: bool, why: string}
 */
function wgct_repair_judge(array $w, array $probe, bool $allowed): array {
    if ($probe['pid_live']) {
        return ['candidate' => false, 'why' => 'running'];
    }
    if ($probe['duplicated']) {
        return ['candidate' => false, 'why' => 'duplicated'];
    }
    if ($probe['routed'] === null || !wgct_ip_equal($probe['routed'], $w['address'])) {
        return ['candidate' => false, 'why' => 'address not usable'];
    }
    if ($probe['route_dev'] !== $w['device']) {
        return ['candidate' => false, 'why' => 'no monitor route'];
    }
    if (!$allowed) {
        return ['candidate' => false, 'why' => 'back-off'];
    }
    return ['candidate' => true, 'why' => ''];
}

/**
 * @param array  $state the repair state (attempts, noted, duplicated)
 * @param string $gw    the IPv6 gateway
 * @param int    $now   unix time
 * @return bool fewer than WGCT_REPAIR_MAX starts of $gw in the last WGCT_REPAIR_WINDOW seconds. Pure.
 */
function wgct_repair_allows(array $state, string $gw, int $now): bool {
    $recent = array_filter($state['attempts'][$gw] ?? [], fn (mixed $at): bool => is_int($at) && $now - $at < WGCT_REPAIR_WINDOW);
    return count($recent) < WGCT_REPAIR_MAX;
}

/**
 * @param array  $state the repair state
 * @param string $gw    the IPv6 gateway started
 * @param int    $now   unix time
 * @return array the state with this start added and every gateway's expired starts dropped. Pure.
 */
function wgct_repair_record(array $state, string $gw, int $now): array {
    $attempts = [];
    foreach ($state['attempts'] ?? [] as $name => $times) {
        $keep = array_values(array_filter(is_array($times) ? $times : [],
            fn (mixed $at): bool => is_int($at) && $now - $at < WGCT_REPAIR_WINDOW));
        if ($keep !== []) {
            $attempts[(string)$name] = $keep;
        }
    }
    $attempts[$gw][] = $now;
    $state['attempts'] = $attempts;
    return $state;
}

/**
 * @param array  $state the repair state
 * @param string $gw    the IPv6 gateway in back-off
 * @param int    $now   unix time
 * @return bool whether to log the back-off now: once per WGCT_REPAIR_WINDOW. Pure.
 */
function wgct_repair_note_due(array $state, string $gw, int $now): bool {
    return $now - (int)($state['noted'][$gw] ?? 0) >= WGCT_REPAIR_WINDOW;
}

/**
 * The log lines for the started gateways: success is a live pidfile, never pluginctl's output, which says
 * "has been started" even when core skipped the gateway. Pure.
 *
 * @param array<string, bool>   $live   gateway => pidfile live after the poll
 * @param array<string, string> $output gateway => pluginctl's captured output
 * @return list<string>
 */
function wgct_repair_outcome(array $live, array $output): array {
    $lines = [];
    foreach ($live as $gw => $ok) {
        $lines[] = $ok ? "started dpinger for {$gw}"
            : "dpinger for {$gw} did not start: " . trim((string)preg_replace('/\s+/', ' ', $output[$gw] ?? ''));
    }
    return $lines;
}

/**
 * @param list<string> $lines   `ifconfig wgN inet6` output
 * @param string       $address the tunnel's inner IPv6 address
 * @return bool whether that address is marked duplicated (core's parser does not record the flag). Pure.
 */
function wgct_repair_is_duplicated(array $lines, string $address): bool {
    foreach ($lines as $line) {
        if (preg_match('/^\s*inet6\s+(\S+)\s.*\bduplicated\b/', $line, $m) === 1
            && wgct_ip_equal(explode('%', $m[1])[0], $address)) {
            return true;
        }
    }
    return false;
}

/**
 * @param list<string> $lines `route -n get -inet6 <ip>` output
 * @param string       $ip    the monitor
 * @return string|null the device a host route to exactly $ip leaves by; null for a network or default route. Pure.
 */
function wgct_repair_route_dev(array $lines, string $ip): ?string {
    $dst = null;
    $dev = null;
    foreach ($lines as $line) {
        if (preg_match('/^\s*destination:\s*(\S+)/', $line, $m) === 1) {
            $dst = $m[1];
        } elseif (preg_match('/^\s*interface:\s*(\S+)/', $line, $m) === 1) {
            $dev = $m[1];
        }
    }
    return $dst !== null && wgct_canon_ip($dst) !== null && wgct_ip_equal($dst, $ip) ? $dev : null;
}

/**
 * One repair tick over its candidates (spec 3.4.3 steps 4-6). The gateway status is taken before the gateway
 * lock; the lock is taken at most once, never waited for; each candidate's pidfile is re-checked under it
 * (a concurrent core reconfigure may have started it); every start happens before one shared poll, so the
 * lock is held about WGCT_REPAIR_POLL_SECONDS whatever the number of candidates; the replay after release
 * names no gateway of its own (naming one would force a full alarm reconfigure that restarts the dpinger
 * just started), so only alarms dropped while the lock was held are replayed. Pure: every effect is $io's.
 *
 * @param list<string> $candidates IPv6 gateways wgct_repair_judge() accepted
 * @param array        $io         status(): ?array, lock(): bool, unlock(): void, live(string): bool,
 *                                 start(string): string (its output), sleep(int usec): void, clock(): float,
 *                                 replay(list<string> $ours, ?array $before): void
 * @return array{skipped: bool, started: list<string>, lines: list<string>}
 */
function wgct_repair_run(array $candidates, array $io): array {
    $result = ['skipped' => false, 'started' => [], 'lines' => []];
    if ($candidates === []) {
        return $result;
    }
    $before = ($io['status'])();
    if (!($io['lock'])()) {
        $result['skipped'] = true;
        return $result;
    }
    $output = [];
    foreach ($candidates as $gw) {
        if (($io['live'])($gw)) {
            continue;
        }
        $output[$gw] = ($io['start'])($gw);
        $result['started'][] = $gw;
    }
    $live = array_fill_keys($result['started'], false);
    $deadline = ($io['clock'])() + WGCT_REPAIR_POLL_SECONDS;
    while ($live !== []) {
        foreach ($live as $gw => $ok) {
            if (!$ok) {
                $live[$gw] = ($io['live'])((string)$gw);
            }
        }
        if (!in_array(false, $live, true) || ($io['clock'])() >= $deadline) {
            break;
        }
        ($io['sleep'])(WGCT_REPAIR_POLL_USEC);
    }
    ($io['unlock'])();
    ($io['replay'])([], $before);
    $result['lines'] = wgct_repair_outcome($live, $output);
    return $result;
}

/**
 * Self-tests for the repair. Pure.
 *
 * @return int exit code, 0 when every case passes
 */
function wgct_repair_selftest(): int {
    $t = ['fail' => 0, 'total' => 0];
    $core = wgct_actions_fixture()['core'];
    $managed = ['i-a', 'i-b', 'i-d'];
    $w = wgct_repair_watch(wgct_derive($core, $managed), $core);
    wgct_check($t, 'repair: (a) watch lists each enabled, unblocked tunnel with an enabled, monitored IPv6 gateway',
        $w === [['gw6' => 'tun_a-ipv6', 'device' => 'wg1', 'interface' => 'opt11', 'address' => 'fd00::1:1', 'monitor' => '2001:db8:ffff::9']]);
    $c1 = $core;
    $c1['gateways']['tun_a-ipv6']['disabled'] = true;
    $c2 = $core;
    $c2['gateways']['tun_a-ipv6']['monitor_disable'] = true;
    $c3 = $core;
    $c3['interfaces']['opt11']['enable'] = false;
    wgct_check($t, 'repair: (b) a disabled or unmonitored IPv6 gateway, or a blocked tunnel, is not watched',
        wgct_repair_watch(wgct_derive($c1, $managed), $c1) === [] && wgct_repair_watch(wgct_derive($c2, $managed), $c2) === []
        && wgct_repair_watch(wgct_derive($c3, $managed), $c3) === []);

    $row = $w[0];
    $ok = ['pid_live' => false, 'routed' => 'fd00::1:1', 'duplicated' => false, 'route_dev' => 'wg1'];
    foreach ([
        ['(c) running', ['pid_live' => true] + $ok, true, false, 'running'],
        ['(d) duplicated', ['duplicated' => true] + $ok, true, false, 'duplicated'],
        ['(e) address still tentative (no routed address)', ['routed' => null] + $ok, true, false, 'address not usable'],
        ['(f) another routed address', ['routed' => 'fd00::9:1'] + $ok, true, false, 'address not usable'],
        ['(g) no monitor route via the device', ['route_dev' => 'igc1'] + $ok, true, false, 'no monitor route'],
        ['(h) back-off', $ok, false, false, 'back-off'],
        ['(i) missing, usable, routed, allowed', $ok, true, true, ''],
    ] as [$desc, $probe, $allowed, $cand, $why]) {
        wgct_check($t, "repair: judge {$desc}", wgct_repair_judge($row, $probe, $allowed) === ['candidate' => $cand, 'why' => $why]);
    }

    $now = 10000;
    $st = ['attempts' => ['g' => [$now - 700, $now - 300, $now - 200, $now - 100]], 'noted' => [], 'duplicated' => []];
    wgct_check($t, 'repair: (j) three attempts inside ten minutes block a fourth; older ones do not count',
        !wgct_repair_allows($st, 'g', $now) && wgct_repair_allows($st, 'g', $now + 301) && wgct_repair_allows($st, 'other', $now));
    $r = wgct_repair_record(['attempts' => ['g' => [$now - 700, $now - 10], 'h' => [$now - 900]], 'noted' => [], 'duplicated' => []], 'g', $now);
    wgct_check($t, 'repair: (k) recording drops every gateway\'s expired attempts and adds this one',
        $r['attempts'] === ['g' => [$now - 10, $now]]);
    wgct_check($t, 'repair: (l) the back-off is noted once per window',
        wgct_repair_note_due(['noted' => []], 'g', $now) && !wgct_repair_note_due(['noted' => ['g' => $now - 10]], 'g', $now)
        && wgct_repair_note_due(['noted' => ['g' => $now - 600]], 'g', $now));
    wgct_check($t, 'repair: (m) the outcome is judged by the pidfile, never by pluginctl\'s text',
        wgct_repair_outcome(['g' => true, 'h' => false], ['g' => 'x', 'h' => "Service `dpinger[h]' has been started.\n"])
        === ['started dpinger for g', "dpinger for h did not start: Service `dpinger[h]' has been started."]);
    wgct_check($t, 'repair: (n) ifconfig marks the tunnel address duplicated, and only that address',
        wgct_repair_is_duplicated(["\tinet6 fd00::1:1 prefixlen 128 duplicated", "\tinet6 fd00::1:5 prefixlen 128"], 'fd00::1:1')
        && !wgct_repair_is_duplicated(["\tinet6 fd00::1:1 prefixlen 128 tentative"], 'fd00::1:1')
        && !wgct_repair_is_duplicated(["\tinet6 fd00::1:10 prefixlen 128 duplicated"], 'fd00::1:1'));
    wgct_check($t, 'repair: (o) route get names the device only for a host route to exactly that address',
        wgct_repair_route_dev(['   route to: 2001:db8:ffff::9', 'destination: 2001:db8:ffff::9', '  interface: wg1'], '2001:db8:ffff::9') === 'wg1'
        && wgct_repair_route_dev(['destination: default', '  interface: igc1'], '2001:db8:ffff::9') === null);

    /* one tick, with every effect faked and traced: liveAfter[gw] = how many live() calls answer false first */
    $io = function (array $liveAfter, bool $lockFree, array &$trace): array {
        $clock = 0.0;
        $polls = [];
        return [
            'status' => function () use (&$trace): ?array { $trace[] = 'status'; return ['g1' => 'down']; },
            'lock' => function () use (&$trace, $lockFree): bool { $trace[] = 'lock'; return $lockFree; },
            'unlock' => function () use (&$trace): void { $trace[] = 'unlock'; },
            'live' => function (string $gw) use (&$trace, &$polls, $liveAfter): bool {
                $polls[$gw] = ($polls[$gw] ?? 0) + 1;
                $trace[] = "live:{$gw}";
                return isset($liveAfter[$gw]) && $polls[$gw] > $liveAfter[$gw];
            },
            'start' => function (string $gw) use (&$trace): string { $trace[] = "start:{$gw}"; return "out {$gw}"; },
            'sleep' => function (int $usec) use (&$trace, &$clock): void { $trace[] = 'sleep'; $clock += $usec / 1e6; },
            'clock' => function () use (&$clock): float { return $clock; },
            'replay' => function (array $ours, ?array $before) use (&$trace): void {
                $trace[] = 'replay:' . json_encode($ours) . ':' . json_encode($before);
            },
        ];
    };
    $replay = 'replay:[]:{"g1":"down"}';
    $trace = [];
    $r = wgct_repair_run([], $io([], true, $trace));
    wgct_check($t, 'repair: (p) no candidates => nothing read, locked or replayed',
        $trace === [] && $r === ['skipped' => false, 'started' => [], 'lines' => []]);
    $trace = [];
    $r = wgct_repair_run(['g1'], $io([], false, $trace));
    wgct_check($t, 'repair: (q) gateway lock held => status taken first, then the tick skips without a start or a replay',
        $trace === ['status', 'lock'] && $r['skipped'] === true && $r['started'] === []);
    $trace = [];
    $r = wgct_repair_run(['g1'], $io(['g1' => 2], true, $trace));
    wgct_check($t, 'repair: (r) status before the lock; start; poll until live; release; then replay with no gateways of its own',
        $trace === ['status', 'lock', 'live:g1', 'start:g1', 'live:g1', 'sleep', 'live:g1', 'unlock', $replay]
        && $r['lines'] === ['started dpinger for g1']);
    $trace = [];
    $r = wgct_repair_run(['g1'], $io(['g1' => 0], true, $trace));
    wgct_check($t, 'repair: (s) a dpinger started meanwhile (the re-check under the lock) is not started again',
        $trace === ['status', 'lock', 'live:g1', 'unlock', $replay] && $r['started'] === [] && $r['lines'] === []);
    $trace = [];
    $r = wgct_repair_run(['g1'], $io([], true, $trace));
    wgct_check($t, 'repair: (t) a dpinger that never appears => polled for 10 s, then reported with pluginctl\'s output',
        $r['lines'] === ['dpinger for g1 did not start: out g1'] && count(array_keys($trace, 'sleep', true)) === 40
        && array_slice($trace, -2) === ['unlock', $replay]);
    $trace = [];
    $r = wgct_repair_run(['g1', 'g2'], $io(['g1' => 1, 'g2' => 1], true, $trace));
    wgct_check($t, 'repair: (u) every candidate is started before one shared poll',
        $trace === ['status', 'lock', 'live:g1', 'start:g1', 'live:g2', 'start:g2', 'live:g1', 'live:g2', 'unlock', $replay]
        && $r['started'] === ['g1', 'g2']);

    return wgct_tally_report('repair', $t);
}
