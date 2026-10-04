<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The IPv6 prime's decisions (spec 2026-10-03): a provider such as Proton sends every IPv6 reply of a peer to one
 * client address it learns from the peer's non-ICMP traffic, and dpinger's echo requests never teach it. A tunnel
 * whose IPv6 gateway is down gets no LAN traffic, so after a fresh session nothing would ever teach it. When a
 * tunnel's IPv6 gateway is down while its WireGuard session is up, prime.php sends one TCP connect from the
 * tunnel's own IPv6 address to its IPv6 monitor. Pure: prime.php does the reading, the connecting and the logging.
 */

require_once __DIR__ . '/tunnels.php';
require_once __DIR__ . '/repair.php';
require_once __DIR__ . '/selftest.php';

/* a healthy path answers within a few probes: an IPv6 dpinger this old that still reads down is really down */
const WGCT_PRIME_MIN_AGE = 20;
/* the wait after the first prime is longer than dpinger's 80 s window, so a prime that worked has shown it */
const WGCT_PRIME_BASE = 120;
const WGCT_PRIME_CAP = 1800;
/* every monitor in use is a DNS resolver; a refused or timed-out connect has still sent its SYN */
const WGCT_PRIME_PORT = 53;
const WGCT_PRIME_TIMEOUT = 3;
/* WireGuard's REJECT_AFTER_TIME: a session with no handshake for longer has its keys refused, so the tunnel is
 * down whatever either address family reports; dpinger's probes keep a live session re-keying every 2 minutes */
const WGCT_PRIME_SESSION = 180;
const WGCT_PRIME_DOWN = ['down', 'loss', 'delay+loss'];
const WGCT_PRIME_UP = ['none', 'delay'];

/**
 * Whether a watched tunnel needs a prime now (spec section 3.2). Pure.
 *
 * @param array $w       a wgct_repair_watch() row
 * @param array $probe   status6: the IPv6 gateway's status as core reports it, null when absent; handshake_age:
 *                       wgct_prime_handshake_age(); age6: seconds since the IPv6 dpinger socket was created, null
 *                       without one; routed: interfaces_routed_address6() (not tentative, deprecated or detached),
 *                       null when none; duplicated: ifconfig marks the address duplicated; route_dev: the device the
 *                       monitor's host route leaves by, null without one. Fields past the first that decides may be
 *                       absent: the caller probes a tunnel only as far as its IPv6 status makes worth it
 * @param bool  $allowed the back-off allows a prime
 * @return array{candidate: bool, why: string}
 */
function wgct_prime_judge(array $w, array $probe, bool $allowed): array {
    $status6 = $probe['status6'];
    if (in_array($status6, WGCT_PRIME_UP, true)) {
        return ['candidate' => false, 'why' => 'ipv6 up'];
    }
    if ($status6 === 'force_down') {
        return ['candidate' => false, 'why' => 'ipv6 held down'];
    }
    if (!in_array($status6, WGCT_PRIME_DOWN, true)) {
        return ['candidate' => false, 'why' => 'ipv6 status unknown'];
    }
    if ($probe['handshake_age'] === null || $probe['handshake_age'] > WGCT_PRIME_SESSION) {
        return ['candidate' => false, 'why' => 'tunnel down'];
    }
    if ($probe['age6'] === null || $probe['age6'] < WGCT_PRIME_MIN_AGE) {
        return ['candidate' => false, 'why' => 'settling'];
    }
    /* a source the kernel would not use (tentative, duplicated, gone) cannot be bound, and binding anything else
     * would teach the provider the wrong address */
    if ($probe['duplicated'] || $probe['routed'] === null || !wgct_ip_equal($probe['routed'], $w['address'])) {
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
 * @param int $count primes sent so far
 * @return int seconds to wait after the last of them: none before the first, then WGCT_PRIME_BASE doubling up to
 *             WGCT_PRIME_CAP. Pure.
 */
function wgct_prime_wait(int $count): int {
    if ($count <= 0) {
        return 0;
    }
    /* 2^5 * 120 is already past the cap; stop doubling there so a long outage cannot overflow */
    return min(WGCT_PRIME_BASE * (2 ** min($count - 1, 5)), WGCT_PRIME_CAP);
}

/**
 * @param array  $state wgct_prime_state()
 * @param string $gw6   the IPv6 gateway
 * @param int    $now   unix time
 * @return bool whether the back-off allows a prime now; a clock stepped back allows it, since a prime is harmless
 *              and a gateway must never be stuck behind a future timestamp. Pure.
 */
function wgct_prime_allows(array $state, string $gw6, int $now): bool {
    $e = $state[$gw6] ?? null;
    if ($e === null) {
        return true;
    }
    $elapsed = $now - $e['last'];
    return $elapsed < 0 || $elapsed >= wgct_prime_wait($e['count']);
}

/**
 * @param array  $state wgct_prime_state()
 * @param string $gw6   the IPv6 gateway primed
 * @param int    $now   unix time
 * @return array{state: array, capped_now: bool} the state with this prime counted; capped_now is true for the one
 *               prime whose wait first reaches WGCT_PRIME_CAP, so the caller logs that once. Pure.
 */
function wgct_prime_record(array $state, string $gw6, int $now): array {
    $count = ($state[$gw6]['count'] ?? 0) + 1;
    $wasCapped = $state[$gw6]['capped'] ?? false;
    $capped = $wasCapped || wgct_prime_wait($count) >= WGCT_PRIME_CAP;
    $state[$gw6] = ['count' => $count, 'last' => $now, 'capped' => $capped];
    return ['state' => $state, 'capped_now' => $capped && !$wasCapped];
}

/**
 * Drop the entries that are done: a gateway that reads up again (one "recovered" line each), one no longer
 * watched, and one reset because its session ended or it is held down (both silently: the next session's first
 * prime must not wait out the last outage's back-off). Without gateway status nothing changes. Pure.
 *
 * @param array      $state  wgct_prime_state()
 * @param array      $watch  wgct_repair_watch()
 * @param array|null $status gateway name => status, null when unavailable
 * @param array      $resets wgct_prime_resets()
 * @return array{state: array, lines: list<string>}
 */
function wgct_prime_settle(array $state, array $watch, ?array $status, array $resets = []): array {
    if ($status === null) {
        return ['state' => $state, 'lines' => []];
    }
    $watched = array_fill_keys(array_column($watch, 'gw6'), true);
    $lines = [];
    foreach ($state as $gw6 => $e) {
        if (!isset($watched[$gw6])) {
            unset($state[$gw6]);
        } elseif (in_array($status[$gw6] ?? null, WGCT_PRIME_UP, true)) {
            $lines[] = "{$gw6} recovered after {$e['count']} prime(s)";
            unset($state[$gw6]);
        } elseif (isset($resets[$gw6])) {
            unset($state[$gw6]);
        }
    }
    return ['state' => $state, 'lines' => $lines];
}

/**
 * The prime state as read back from prime.json: gateway => {count >= 1, last, capped}; anything else is dropped,
 * so a hand-edited or truncated file only costs a back-off reset. A gateway name may be all digits, which PHP
 * keys as an int. Pure.
 *
 * @param mixed $raw json_decode() of the file
 * @return array<int|string, array{count: int, last: int, capped: bool}>
 */
function wgct_prime_state(mixed $raw): array {
    $state = [];
    foreach (is_array($raw) ? $raw : [] as $gw6 => $e) {
        if ((is_string($gw6) || is_int($gw6)) && is_array($e) && is_int($e['count'] ?? null) && $e['count'] >= 1 && is_int($e['last'] ?? null)) {
            $state[$gw6] = ['count' => $e['count'], 'last' => $e['last'], 'capped' => ($e['capped'] ?? false) === true];
        }
    }
    return $state;
}

/**
 * @param bool   $connected the connect succeeded
 * @param int    $errno     the socket error number (FreeBSD: 60 ETIMEDOUT, 61 ECONNREFUSED)
 * @param string $errstr    its error text
 * @return string the outcome as logged. Pure.
 */
function wgct_prime_outcome(bool $connected, int $errno, string $errstr): string {
    if ($connected) {
        return 'connected';
    }
    $text = trim($errstr);
    if ($errno === 61 || stripos($text, 'refused') !== false) {
        return 'refused';
    }
    if ($errno === 60 || stripos($text, 'timed out') !== false) {
        return 'timed out';
    }
    return 'failed: ' . ($text !== '' ? $text : ($errno !== 0 ? "error {$errno}" : 'unknown error'));
}

/**
 * @param array  $w            a wgct_repair_watch() row
 * @param int    $handshakeAge seconds since the tunnel's latest handshake
 * @param string $outcome      wgct_prime_outcome()
 * @param int    $n            which prime of this outage this was
 * @return string the log line for one prime. Pure.
 */
function wgct_prime_line(array $w, int $handshakeAge, string $outcome, int $n): string {
    return "{$w['gw6']} down while {$w['device']} is up (handshake {$handshakeAge} s ago): TCP from {$w['address']} to "
        . "[{$w['monitor']}]:" . WGCT_PRIME_PORT . " {$outcome} (prime {$n})";
}

/**
 * @param list<string> $lines `wg show <device> latest-handshakes` output: "<public key>\t<unix time>" per peer,
 *                            0 for a peer that never completed one
 * @param int          $now   unix time
 * @return int|null seconds since the newest handshake of any peer (a future stamp reads 0), null when there is
 *                  none. Pure.
 */
function wgct_prime_handshake_age(array $lines, int $now): ?int {
    $newest = 0;
    foreach ($lines as $line) {
        if (preg_match('/^\S+\t(\d+)$/', trim((string)$line), $m) === 1) {
            $newest = max($newest, (int)$m[1]);
        }
    }
    return $newest > 0 ? max(0, $now - $newest) : null;
}

/**
 * The gateways whose back-off starts over: held down (a mirror release reconfigures and restarts the session), or
 * down with no live session. A live session, an up gateway or an unknown status keeps its entry. Pure.
 *
 * @param array<string, array> $probes gateway => its judge probe (status6 and handshake_age read)
 * @return array<string, true>
 */
function wgct_prime_resets(array $probes): array {
    $resets = [];
    foreach ($probes as $gw6 => $p) {
        $sessionGone = $p['handshake_age'] === null || $p['handshake_age'] > WGCT_PRIME_SESSION;
        if ($p['status6'] === 'force_down' || (in_array($p['status6'], WGCT_PRIME_DOWN, true) && $sessionGone)) {
            $resets[$gw6] = true;
        }
    }
    return $resets;
}

/**
 * @param array  $w     a wgct_repair_watch() row
 * @param string $error socket_strerror() of the failed bind
 * @return string the log line for a prime not sent because its source would not bind. Pure.
 */
function wgct_prime_bind_line(array $w, string $error): string {
    return "{$w['gw6']}: cannot bind {$w['address']} (" . trim($error) . '); no prime sent';
}

/**
 * @return int exit code, 0 when every case passed
 */
function wgct_prime_selftest(): int {
    $t = ['fail' => 0, 'total' => 0];
    $core = wgct_actions_fixture()['core'];
    $row = wgct_repair_watch(wgct_derive($core, ['i-a', 'i-b', 'i-d']), $core)[0];

    $hs = ['Az021MwJA2cczjrXE+NtxVsQaVq2apEkmccB6iE7RzU=' . "\t1000", 'Bq0d+kX1iLqvH5wB1oC8yQ2bC9eYx4mWq7hJr2sTzQk=' . "\t1150", ''];
    wgct_check($t, 'prime: (a) handshake age is the newest peer handshake; none or never (0) is null',
        wgct_prime_handshake_age($hs, 1200) === 50
        && wgct_prime_handshake_age(['Az021MwJA2cczjrXE+NtxVsQaVq2apEkmccB6iE7RzU=' . "\t0"], 1200) === null
        && wgct_prime_handshake_age([], 1200) === null && wgct_prime_handshake_age(['garbage'], 1200) === null);
    wgct_check($t, 'prime: (b) a handshake stamped in the future reads as just now, not negative',
        wgct_prime_handshake_age(['Az021MwJA2cczjrXE+NtxVsQaVq2apEkmccB6iE7RzU=' . "\t1300"], 1200) === 0);

    $ok = ['status6' => 'down', 'handshake_age' => 30, 'age6' => 20, 'routed' => 'fd00::1:1', 'duplicated' => false,
           'route_dev' => 'wg1'];
    foreach ([
        ['(c) IPv6 up', ['status6' => 'none'] + $ok, true, false, 'ipv6 up'],
        ['(d) IPv6 only delayed is up', ['status6' => 'delay'] + $ok, true, false, 'ipv6 up'],
        ['(e) IPv6 held down', ['status6' => 'force_down'] + $ok, true, false, 'ipv6 held down'],
        ['(f) IPv6 status unknown', ['status6' => null] + $ok, true, false, 'ipv6 status unknown'],
        ['(g) session never handshaked', ['handshake_age' => null] + $ok, true, false, 'tunnel down'],
        ['(h) last handshake 181 s ago (keys rejected after 180 s)', ['handshake_age' => 181] + $ok, true, false, 'tunnel down'],
        ['(i) dpinger 19 s old', ['age6' => 19] + $ok, true, false, 'settling'],
        ['(j) no dpinger socket', ['age6' => null] + $ok, true, false, 'settling'],
        ['(j2) address still tentative (no routed address)', ['routed' => null] + $ok, true, false, 'address not usable'],
        ['(j3) another routed address', ['routed' => 'fd00::9:1'] + $ok, true, false, 'address not usable'],
        ['(j4) address duplicated', ['duplicated' => true] + $ok, true, false, 'address not usable'],
        ['(k) monitor route on another device', ['route_dev' => 'igc1'] + $ok, true, false, 'no monitor route'],
        ['(l) no monitor route', ['route_dev' => null] + $ok, true, false, 'no monitor route'],
        ['(m) back-off', $ok, false, false, 'back-off'],
        ['(n) IPv6 down 20 s, session live, routed, allowed', $ok, true, true, ''],
        ['(o) handshake exactly 180 s ago still counts as live', ['handshake_age' => 180] + $ok, true, true, ''],
        ['(p) IPv6 loss', ['status6' => 'loss'] + $ok, true, true, ''],
        ['(q) IPv6 delay+loss', ['status6' => 'delay+loss'] + $ok, true, true, ''],
    ] as [$desc, $probe, $allowed, $cand, $why]) {
        wgct_check($t, "prime: judge {$desc}", wgct_prime_judge($row, $probe, $allowed) === ['candidate' => $cand, 'why' => $why]);
    }

    wgct_check($t, 'prime: (r) wait schedule 0, 120, 240, 480, 960, then capped at 1800',
        array_map('wgct_prime_wait', [0, 1, 2, 3, 4, 5, 6, 40]) === [0, 120, 240, 480, 960, 1800, 1800, 1800]);
    $s1 = ['tun_a-ipv6' => ['count' => 1, 'last' => 1000, 'capped' => false]];
    wgct_check($t, 'prime: (s) allowed with no entry, refused 119 s after the first prime, allowed at 120 s',
        wgct_prime_allows([], 'tun_a-ipv6', 1000) && !wgct_prime_allows($s1, 'tun_a-ipv6', 1119)
        && wgct_prime_allows($s1, 'tun_a-ipv6', 1120));
    wgct_check($t, 'prime: (t) a clock stepped back allows (priming is harmless; never stuck)',
        wgct_prime_allows($s1, 'tun_a-ipv6', 900));
    $s2 = ['tun_a-ipv6' => ['count' => 2, 'last' => 1000, 'capped' => false]];
    wgct_check($t, 'prime: (t2) after the second prime: refused at 239 s, allowed at 240 s',
        !wgct_prime_allows($s2, 'tun_a-ipv6', 1239) && wgct_prime_allows($s2, 'tun_a-ipv6', 1240));

    $r = wgct_prime_record([], 'tun_a-ipv6', 1000);
    wgct_check($t, 'prime: (u) the first record counts 1 at now, not capped',
        $r === ['state' => ['tun_a-ipv6' => ['count' => 1, 'last' => 1000, 'capped' => false]], 'capped_now' => false]);
    $s4 = ['tun_a-ipv6' => ['count' => 4, 'last' => 1000, 'capped' => false]];
    $r5 = wgct_prime_record($s4, 'tun_a-ipv6', 2000);
    $r6 = wgct_prime_record($r5['state'], 'tun_a-ipv6', 4000);
    wgct_check($t, 'prime: (v) the record that reaches the cap says so once, the next does not',
        $r5['capped_now'] === true && $r5['state']['tun_a-ipv6'] === ['count' => 5, 'last' => 2000, 'capped' => true]
        && $r6['capped_now'] === false && $r6['state']['tun_a-ipv6']['count'] === 6);

    $two = ['tun_a-ipv6' => ['count' => 2, 'last' => 1000, 'capped' => false],
            'gone-ipv6' => ['count' => 1, 'last' => 1000, 'capped' => false]];
    $r = wgct_prime_settle($two, [$row], ['tun_a-ipv6' => 'none']);
    wgct_check($t, 'prime: (w) settle drops a recovered gateway with one line, and forgets one no longer watched',
        $r === ['state' => [], 'lines' => ['tun_a-ipv6 recovered after 2 prime(s)']]);
    $r = wgct_prime_settle($two, [$row], ['tun_a-ipv6' => 'down']);
    wgct_check($t, 'prime: (x) settle keeps a gateway still down',
        $r === ['state' => ['tun_a-ipv6' => $two['tun_a-ipv6']], 'lines' => []]);
    wgct_check($t, 'prime: (y) settle without gateway status changes nothing',
        wgct_prime_settle($two, [$row], null) === ['state' => $two, 'lines' => []]);
    wgct_check($t, 'prime: (y2) settle counts a gateway that is only delayed as recovered',
        wgct_prime_settle($two, [$row], ['tun_a-ipv6' => 'delay'])['lines'] === ['tun_a-ipv6 recovered after 2 prime(s)']);
    wgct_check($t, 'prime: (y3) settle keeps a watched gateway missing from the status',
        wgct_prime_settle($two, [$row], ['other' => 'none'])['state'] === ['tun_a-ipv6' => $two['tun_a-ipv6']]);
    wgct_check($t, 'prime: (y4) settle drops a reset gateway silently: a new session starts its back-off over',
        wgct_prime_settle($two, [$row], ['tun_a-ipv6' => 'down'], ['tun_a-ipv6' => true]) === ['state' => [], 'lines' => []]);

    $probes = [
        'a' => ['status6' => 'force_down', 'handshake_age' => null],
        'b' => ['status6' => 'down', 'handshake_age' => null],
        'c' => ['status6' => 'down', 'handshake_age' => 181],
        'd' => ['status6' => 'down', 'handshake_age' => 30],
        'e' => ['status6' => 'none', 'handshake_age' => null],
        'f' => ['status6' => null, 'handshake_age' => null],
    ];
    wgct_check($t, 'prime: (y5) resets: held down, or down with the session gone; not a live session, an up gateway or an unknown status',
        wgct_prime_resets($probes) === ['a' => true, 'b' => true, 'c' => true]);

    wgct_check($t, 'prime: (z) state keeps well-formed entries (an all-digit gateway name too) and drops the rest',
        wgct_prime_state(['a' => ['count' => 2, 'last' => 5, 'capped' => true], 'b' => ['count' => 0, 'last' => 5],
                          'c' => ['count' => '2', 'last' => 5], 'd' => 'x', 7 => ['count' => 1, 'last' => 1]])
            === ['a' => ['count' => 2, 'last' => 5, 'capped' => true], 7 => ['count' => 1, 'last' => 1, 'capped' => false]]
        && wgct_prime_state(null) === [] && wgct_prime_state('garbage') === []);

    wgct_check($t, 'prime: (aa) outcome text: connected, refused, timed out, other failures',
        wgct_prime_outcome(true, 0, '') === 'connected'
        && wgct_prime_outcome(false, 61, 'Connection refused') === 'refused'
        && wgct_prime_outcome(false, 60, 'Operation timed out') === 'timed out'
        && wgct_prime_outcome(false, 0, 'Connection timed out') === 'timed out'
        && wgct_prime_outcome(false, 49, "Can't assign requested address\n") === "failed: Can't assign requested address"
        && wgct_prime_outcome(false, 0, '') === 'failed: unknown error');
    wgct_check($t, 'prime: (bb) the log line names the gateway, the tunnel and its handshake, the source, the monitor, the outcome and the count',
        wgct_prime_line($row, 42, 'refused', 2)
            === 'tun_a-ipv6 down while wg1 is up (handshake 42 s ago): TCP from fd00::1:1 to [2001:db8:ffff::9]:53 refused (prime 2)');

    wgct_check($t, 'prime: (cc) a failed bind sends nothing and says so',
        wgct_prime_bind_line($row, "Can't assign requested address\n")
            === "tun_a-ipv6: cannot bind fd00::1:1 (Can't assign requested address); no prime sent");

    return wgct_tally_report('prime', $t);
}
