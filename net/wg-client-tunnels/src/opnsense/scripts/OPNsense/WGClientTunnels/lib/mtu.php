<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The tunnel MTU for Create (spec 6.1), ported from add_proton_tunnel.php: a
 * bisecting DF ping from the bound WAN's own address to the endpoint, path
 * MTU minus the WireGuard overhead for the endpoint's family (60 bytes over
 * IPv4, 80 over IPv6), clamped to 1280-1420. A WAN's path is not always
 * 1500: a cellular WAN measured 1436, and a tunnel left at 1420 there
 * dropped every large packet. Takes up to
 * ~30 s and holds no lock; the page runs it as its own keyless action before
 * Create, and a CLI Create without an MTU runs it before locking anything.
 */

use OPNsense\Core\Config;

require_once __DIR__ . '/tunnels.php';
require_once __DIR__ . '/wgconf.php';
require_once __DIR__ . '/selftest.php';

/* ICMP echo header plus the IP header, per family */
const WGCT_PING_HEADER = ['inet' => 28, 'inet6' => 48];
/* the ICMP payload of a full 1500-byte packet, per family */
const WGCT_PING_MAX_PAYLOAD = ['inet' => 1472, 'inet6' => 1452];

/**
 * WireGuard's outer overhead: IP header + 8 UDP + 32 WireGuard (spec 2026-09-27 section 3.6).
 */
function wgct_wg_overhead(string $family): int {
    return $family === 'inet6' ? 80 : 60;
}

/**
 * Largest path MTU $fits accepts, by bisection. Pure given $fits.
 *
 * @param callable(int): bool $fits whether an ICMP payload of that size crosses with DF set
 * @return int|null the path MTU, or null when even the 1280 floor does not cross
 */
function wgct_path_mtu(callable $fits, string $family = 'inet'): ?int {
    $h = WGCT_PING_HEADER[$family];
    $lo = WGCT_TUNNEL_MTU_MIN - $h;
    if (!$fits($lo)) {
        return null;
    }
    $hi = WGCT_PING_MAX_PAYLOAD[$family];
    if ($fits($hi)) {
        return $hi + $h;
    }
    while ($hi - $lo > 1) {
        $mid = intdiv($lo + $hi, 2);
        if ($fits($mid)) {
            $lo = $mid;
        } else {
            $hi = $mid;
        }
    }
    return $lo + $h;
}

/**
 * @param int|null $pathMtu wgct_path_mtu(), null when the endpoint did not answer
 * @return int the tunnel MTU: path minus overhead, clamped; 1420 without a measurement
 */
function wgct_tunnel_mtu(?int $pathMtu, string $family = 'inet'): int {
    if ($pathMtu === null) {
        return WGCT_TUNNEL_MTU_MAX;
    }
    return min(WGCT_TUNNEL_MTU_MAX, max(WGCT_TUNNEL_MTU_MIN, $pathMtu - wgct_wg_overhead($family)));
}

/**
 * @return int the number of leading bits two IPv6 addresses share
 */
function wgct_common_prefix6(string $a, string $b): int {
    $x = inet_pton($a);
    $y = inet_pton($b);
    if ($x === false || $y === false || strlen($x) !== 16 || strlen($y) !== 16) {
        return 0;
    }
    $bits = 0;
    for ($i = 0; $i < 16; $i++) {
        $d = ord($x[$i]) ^ ord($y[$i]);
        if ($d === 0) {
            $bits += 8;
            continue;
        }
        while (($d & 0x80) === 0) {
            $bits++;
            $d <<= 1;
        }
        break;
    }
    return $bits;
}

/**
 * The IPv6 source for probing an endpoint, from `ifconfig -L <dev> inet6`:
 * a global address, not deprecated, tentative, detached, duplicated or
 * temporary; the longest prefix shared with the endpoint, then the longest
 * preferred lifetime, a static address's being infinite (spec 2026-09-27
 * section 3.6). Pure.
 */
function wgct_pick_source6(string $ifconfigOut, string $endpoint): ?string {
    $best = null;
    $bestKey = null;
    foreach (preg_split('/\R/', $ifconfigOut) ?: [] as $line) {
        if (preg_match('/^\s*inet6\s+(\S+)(.*)$/', $line, $m) !== 1) {
            continue;
        }
        $addr = explode('%', $m[1])[0];
        $rest = ' ' . $m[2] . ' ';
        if (!wgct_is_global6($addr)) {
            continue;
        }
        foreach (['deprecated', 'tentative', 'detached', 'duplicated', 'temporary'] as $flag) {
            if (str_contains($rest, " {$flag} ")) {
                continue 2;
            }
        }
        /* no pltime: a static address, whose infinite lifetimes `ifconfig -L` does not print */
        $pl = preg_match('/\spltime\s+(\d+|infty)\s/', $rest, $p) === 1 ? ($p[1] === 'infty' ? PHP_INT_MAX : (int)$p[1]) : PHP_INT_MAX;
        $key = [wgct_common_prefix6($addr, $endpoint), $pl];
        if ($bestKey === null || $key > $bestKey) {
            $best = wgct_canon_ip($addr);
            $bestKey = $key;
        }
    }
    return $best;
}

/**
 * @return string|null the note for an IPv6 path too small for the tunnel minimum
 */
function wgct_small_path_note(?int $pathMtu, string $family): ?string {
    if ($family !== 'inet6' || $pathMtu === null || $pathMtu >= WGCT_TUNNEL_MTU_MIN + 80) {
        return null;
    }
    return "path MTU {$pathMtu}: the tunnel stays at the 1280 minimum and its packets will be fragmented";
}

/**
 * @param string $device an interface device
 * @return string|null its first IPv4 address
 */
function wgct_ifconfig_ipv4(string $device): ?string {
    $proc = proc_open(
        ['/sbin/ifconfig', $device, 'inet'],
        [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']],
        $pipes
    );
    if (!is_resource($proc)) {
        return null;
    }
    $out = (string)stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    proc_close($proc);
    return preg_match('/^\s*inet (\d+\.\d+\.\d+\.\d+)/m', $out, $m) === 1 ? $m[1] : null;
}

/**
 * The address a WAN gateway's traffic leaves from. Reads the config tree
 * directly (every gateway_item anywhere, as the retired script did), so no
 * model cache is involved.
 *
 * @param string $wanName  a gateway name
 * @param string $family   'inet' or 'inet6'
 * @param string $endpoint the peer endpoint, used to pick among several IPv6 addresses
 * @return string|null
 */
function wgct_wan_source_ip(string $wanName, string $family = 'inet', string $endpoint = ''): ?string {
    $root = Config::getInstance()->object();
    $items = $root->xpath('//gateway_item');
    foreach (is_array($items) ? $items : [] as $gw) {
        if ((string)$gw->name !== $wanName) {
            continue;
        }
        $if = (string)$gw->interface;
        $device = isset($root->interfaces->{$if}) ? (string)$root->interfaces->{$if}->if : '';
        if ($device === '') {
            return null;
        }
        if ($family !== 'inet6') {
            return wgct_ifconfig_ipv4($device);
        }
        $proc = proc_open(
            ['/sbin/ifconfig', '-L', $device, 'inet6'],
            [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']],
            $pipes
        );
        if (!is_resource($proc)) {
            return null;
        }
        $out = (string)stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        proc_close($proc);
        return wgct_pick_source6($out, $endpoint);
    }
    return null;
}

/**
 * @return bool two DF pings of $payload bytes from $src reach $dst
 */
function wgct_ping_fits(string $src, string $dst, int $payload, string $family = 'inet'): bool {
    $argv = $family === 'inet6'
        ? ['/sbin/ping6', '-u', '-D', '-q', '-c', '2', '-t', '3', '-S', $src, '-s', (string)$payload, $dst]
        : ['/sbin/ping', '-D', '-q', '-c', '2', '-t', '3', '-S', $src, '-s', (string)$payload, $dst];
    $proc = proc_open(
        $argv,
        [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
        $pipes
    );
    return is_resource($proc) && proc_close($proc) === 0;
}

/**
 * @param string $wanName    the WAN gateway the tunnel will be bound to
 * @param string $endpointIp the peer's IPv4 or global IPv6 endpoint
 * @return array{ok: bool, mtu: int, path_mtu: ?int, source: string, why: string, errors: list<string>}
 */
function wgct_measure_mtu(string $wanName, string $endpointIp): array {
    $result = ['ok' => false, 'mtu' => WGCT_TUNNEL_MTU_MAX, 'path_mtu' => null, 'source' => '', 'why' => '', 'errors' => []];
    $family = wgct_ip_family($endpointIp);
    if (wgct_endpoint_ip($endpointIp) === null) {
        $result['errors'][] = 'the endpoint must be an IPv4 or global IPv6 address';
        return $result;
    }
    $src = wgct_wan_source_ip($wanName, $family, $endpointIp);
    if ($src === null) {
        $result['errors'][] = $family === 'inet6'
            ? "no global IPv6 address on {$wanName}'s interface (a WAN with only a delegated prefix has none); enter the MTU"
            : "no IPv4 address found for {$wanName}; is that WAN up?";
        return $result;
    }
    $path = wgct_path_mtu(fn (int $payload): bool => wgct_ping_fits($src, $endpointIp, $payload, $family), $family);
    $result['ok'] = true;
    $result['source'] = $src;
    $result['path_mtu'] = $path;
    $result['mtu'] = wgct_tunnel_mtu($path, $family);
    $result['why'] = $path === null
        ? "{$endpointIp} did not answer sized probes from {$src}; using " . WGCT_TUNNEL_MTU_MAX
        : sprintf('%s path MTU %d (measured from %s) minus %d overhead', $wanName, $path, $src, wgct_wg_overhead($family));
    $note = wgct_small_path_note($path, $family);
    if ($note !== null) {
        $result['why'] .= '; ' . $note;
    }
    return $result;
}

/**
 * Self-tests for the bisection and the clamp. Pure: the probe is simulated.
 *
 * @return int exit code, 0 when every case passes
 */
function wgct_mtu_selftest(): int {
    $t = ['fail' => 0, 'total' => 0];
    $calls = 0;
    $path = function (int $limit) use (&$calls): callable {
        return function (int $payload) use ($limit, &$calls): bool {
            $calls++;
            return $payload + 28 <= $limit;
        };
    };
    wgct_check($t, 'mtu: a 1500-byte path => 1500, tunnel 1420',
        wgct_path_mtu($path(1500)) === 1500 && wgct_tunnel_mtu(1500) === 1420);
    $calls = 0;
    $m = wgct_path_mtu($path(1436));
    wgct_check($t, 'mtu: a 1436-byte path => 1436, tunnel 1376, in at most 10 probes',
        $m === 1436 && wgct_tunnel_mtu($m) === 1376 && $calls <= 10);
    wgct_check($t, 'mtu: exactly the 1280 floor => 1280, tunnel 1280',
        wgct_path_mtu($path(1280)) === 1280 && wgct_tunnel_mtu(1280) === 1280);
    wgct_check($t, 'mtu: one byte above the floor => 1281', wgct_path_mtu($path(1281)) === 1281);
    wgct_check($t, 'mtu: below the floor (no answer) => null, tunnel falls back to 1420',
        wgct_path_mtu($path(1279)) === null && wgct_tunnel_mtu(null) === 1420);
    wgct_check($t, 'mtu: a 1350-byte path => tunnel 1290', wgct_path_mtu($path(1350)) === 1350 && wgct_tunnel_mtu(1350) === 1290);
    wgct_check($t, 'mtu: the tunnel MTU is never below 1280', wgct_tunnel_mtu(1300) === 1280);
    wgct_check($t, 'mtu: the tunnel MTU is never above 1420', wgct_tunnel_mtu(9000) === 1420);
    $path6 = fn (int $limit): callable => fn (int $payload): bool => $payload + 48 <= $limit;
    wgct_check($t, 'mtu (a): IPv6 1500-byte path => 1500, tunnel 1420',
        wgct_path_mtu($path6(1500), 'inet6') === 1500 && wgct_tunnel_mtu(1500, 'inet6') === 1420);
    wgct_check($t, 'mtu (b): IPv6 1456-byte path => 1456, tunnel 1376 (same as IPv4 1436)',
        wgct_path_mtu($path6(1456), 'inet6') === 1456 && wgct_tunnel_mtu(1456, 'inet6') === 1376 && wgct_tunnel_mtu(1436, 'inet') === 1376);
    wgct_check($t, 'mtu (c): IPv6 floor 1280 => 1280; below it => null',
        wgct_path_mtu($path6(1280), 'inet6') === 1280 && wgct_path_mtu($path6(1279), 'inet6') === null);
    wgct_check($t, 'mtu (d): overhead 60 for IPv4, 80 for IPv6', wgct_wg_overhead('inet') === 60 && wgct_wg_overhead('inet6') === 80);
    $ifc = "\tinet6 fe80::a1%igc2 prefixlen 64 scopeid 0x3\n"
        . "\tinet6 fd00:0:0:1::a1 prefixlen 64 autoconf pltime 3600 vltime 3600\n"
        . "\tinet6 2001:db8:40:1::a1 prefixlen 64 autoconf pltime 1800 vltime 1800\n"
        . "\tinet6 2001:db8:40:1::aaaa prefixlen 64 autoconf deprecated pltime 0 vltime 900\n"
        . "\tinet6 2001:db8:40:1::bbbb prefixlen 64 autoconf temporary pltime 3000 vltime 3000\n";
    wgct_check($t, 'mtu (e): source = the global address, never the longer-lived ULA, a deprecated or a temporary one',
        wgct_pick_source6($ifc, '2001:db8:99::10') === '2001:db8:40:1::a1');
    wgct_check($t, 'mtu (f): no global address => null',
        wgct_pick_source6("\tinet6 fe80::1%igc2 prefixlen 64 scopeid 0x3\n\tinet6 fd00:0:0:1::1 prefixlen 64 pltime 3600 vltime 3600\n", '2001:db8::10') === null);
    wgct_check($t, 'mtu (g): among global addresses, the longest prefix shared with the endpoint wins',
        wgct_pick_source6("\tinet6 2001:db8:40::1 prefixlen 64 pltime 9000 vltime 9000\n\tinet6 2001:db8:99::1 prefixlen 64 pltime 100 vltime 100\n", '2001:db8:99::10') === '2001:db8:99::1');
    wgct_check($t, 'mtu (g2): the same shared prefix, a static address (no lifetimes printed) beats an expiring one',
        wgct_pick_source6("\tinet6 2001:db8:40:1::c1 prefixlen 64 autoconf pltime 100 vltime 100\n\tinet6 2001:db8:40:1::c2 prefixlen 64\n", '2001:db8:99::10') === '2001:db8:40:1::c2');
    wgct_check($t, 'mtu (h): an IPv6 path below 1360 gets a note; IPv4 never does',
        str_contains((string)wgct_small_path_note(1340, 'inet6'), 'stays at the 1280 minimum')
        && wgct_small_path_note(1400, 'inet6') === null && wgct_small_path_note(1300, 'inet') === null);
    return wgct_tally_report('mtu', $t);
}
