<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The tunnel MTU for Create (spec 6.1), ported from add_proton_tunnel.php: a
 * bisecting DF ping from the bound WAN's own address to the endpoint, path
 * MTU minus 60 bytes of WireGuard-over-IPv4 overhead, clamped to 1280-1420.
 * A WAN's path is not always 1500: a cellular WAN measured 1436, and a
 * tunnel left at 1420 there dropped every large packet. Takes up to
 * ~30 s and holds no lock; the page runs it as its own keyless action before
 * Create, and a CLI Create without an MTU runs it before locking anything.
 */

use OPNsense\Core\Config;

require_once __DIR__ . '/tunnels.php';
require_once __DIR__ . '/wgconf.php';
require_once __DIR__ . '/selftest.php';

/* 20 IPv4 + 8 UDP + 32 WireGuard */
const WGIPV6_WG_OVERHEAD = 60;
/* the ICMP payload of a full 1500-byte packet */
const WGIPV6_PING_MAX_PAYLOAD = 1472;

/**
 * Largest path MTU $fits accepts, by bisection. Pure given $fits.
 *
 * @param callable(int): bool $fits whether an ICMP payload of that size crosses with DF set
 * @return int|null the path MTU, or null when even the 1280 floor does not cross
 */
function wgipv6_path_mtu(callable $fits): ?int {
    $lo = WGIPV6_TUNNEL_MTU_MIN - 28;
    if (!$fits($lo)) {
        return null;
    }
    $hi = WGIPV6_PING_MAX_PAYLOAD;
    if ($fits($hi)) {
        return $hi + 28;
    }
    while ($hi - $lo > 1) {
        $mid = intdiv($lo + $hi, 2);
        if ($fits($mid)) {
            $lo = $mid;
        } else {
            $hi = $mid;
        }
    }
    return $lo + 28;
}

/**
 * @param int|null $pathMtu wgipv6_path_mtu(), null when the endpoint did not answer
 * @return int the tunnel MTU: path minus overhead, clamped; 1420 without a measurement
 */
function wgipv6_tunnel_mtu(?int $pathMtu): int {
    if ($pathMtu === null) {
        return WGIPV6_TUNNEL_MTU_MAX;
    }
    return min(WGIPV6_TUNNEL_MTU_MAX, max(WGIPV6_TUNNEL_MTU_MIN, $pathMtu - WGIPV6_WG_OVERHEAD));
}

/**
 * @param string $device an interface device
 * @return string|null its first IPv4 address
 */
function wgipv6_ifconfig_ipv4(string $device): ?string {
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
 * @param string $wanName a gateway name
 * @return string|null
 */
function wgipv6_wan_source_ip(string $wanName): ?string {
    $root = Config::getInstance()->object();
    $items = $root->xpath('//gateway_item');
    foreach (is_array($items) ? $items : [] as $gw) {
        if ((string)$gw->name !== $wanName) {
            continue;
        }
        $if = (string)$gw->interface;
        $device = isset($root->interfaces->{$if}) ? (string)$root->interfaces->{$if}->if : '';
        return $device === '' ? null : wgipv6_ifconfig_ipv4($device);
    }
    return null;
}

/**
 * @return bool two DF pings of $payload bytes from $src reach $dst
 */
function wgipv6_ping_fits(string $src, string $dst, int $payload): bool {
    $proc = proc_open(
        ['/sbin/ping', '-D', '-q', '-c', '2', '-t', '3', '-S', $src, '-s', (string)$payload, $dst],
        [0 => ['file', '/dev/null', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['file', '/dev/null', 'w']],
        $pipes
    );
    return is_resource($proc) && proc_close($proc) === 0;
}

/**
 * @param string $wanName    the WAN gateway the tunnel will be bound to
 * @param string $endpointIp the peer's IPv4 endpoint
 * @return array{ok: bool, mtu: int, path_mtu: ?int, source: string, why: string, errors: list<string>}
 */
function wgipv6_measure_mtu(string $wanName, string $endpointIp): array {
    $result = ['ok' => false, 'mtu' => WGIPV6_TUNNEL_MTU_MAX, 'path_mtu' => null, 'source' => '', 'why' => '', 'errors' => []];
    if (filter_var($endpointIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
        $result['errors'][] = 'the endpoint must be an IPv4 address';
        return $result;
    }
    $src = wgipv6_wan_source_ip($wanName);
    if ($src === null) {
        $result['errors'][] = "no IPv4 address found for {$wanName}; is that WAN up?";
        return $result;
    }
    $path = wgipv6_path_mtu(fn (int $payload): bool => wgipv6_ping_fits($src, $endpointIp, $payload));
    $result['ok'] = true;
    $result['source'] = $src;
    $result['path_mtu'] = $path;
    $result['mtu'] = wgipv6_tunnel_mtu($path);
    $result['why'] = $path === null
        ? "{$endpointIp} did not answer sized probes from {$src}; using " . WGIPV6_TUNNEL_MTU_MAX
        : sprintf('%s path MTU %d (measured from %s) minus %d overhead', $wanName, $path, $src, WGIPV6_WG_OVERHEAD);
    return $result;
}

/**
 * Self-tests for the bisection and the clamp. Pure: the probe is simulated.
 *
 * @return int exit code, 0 when every case passes
 */
function wgipv6_mtu_selftest(): int {
    $t = ['fail' => 0, 'total' => 0];
    $calls = 0;
    $path = function (int $limit) use (&$calls): callable {
        return function (int $payload) use ($limit, &$calls): bool {
            $calls++;
            return $payload + 28 <= $limit;
        };
    };
    wgipv6_check($t, 'mtu: a 1500-byte path => 1500, tunnel 1420',
        wgipv6_path_mtu($path(1500)) === 1500 && wgipv6_tunnel_mtu(1500) === 1420);
    $calls = 0;
    $m = wgipv6_path_mtu($path(1436));
    wgipv6_check($t, 'mtu: a 1436-byte path => 1436, tunnel 1376, in at most 10 probes',
        $m === 1436 && wgipv6_tunnel_mtu($m) === 1376 && $calls <= 10);
    wgipv6_check($t, 'mtu: exactly the 1280 floor => 1280, tunnel 1280',
        wgipv6_path_mtu($path(1280)) === 1280 && wgipv6_tunnel_mtu(1280) === 1280);
    wgipv6_check($t, 'mtu: one byte above the floor => 1281', wgipv6_path_mtu($path(1281)) === 1281);
    wgipv6_check($t, 'mtu: below the floor (no answer) => null, tunnel falls back to 1420',
        wgipv6_path_mtu($path(1279)) === null && wgipv6_tunnel_mtu(null) === 1420);
    wgipv6_check($t, 'mtu: a 1350-byte path => tunnel 1290', wgipv6_path_mtu($path(1350)) === 1350 && wgipv6_tunnel_mtu(1350) === 1290);
    wgipv6_check($t, 'mtu: the tunnel MTU is never below 1280', wgipv6_tunnel_mtu(1300) === 1280);
    wgipv6_check($t, 'mtu: the tunnel MTU is never above 1420', wgipv6_tunnel_mtu(9000) === 1420);
    return wgipv6_tally_report('mtu', $t);
}
