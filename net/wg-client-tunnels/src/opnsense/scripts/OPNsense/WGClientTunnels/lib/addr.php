<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Address helpers for derivation, the planners and the views (spec
 * 2026-09-27 section 2). Every endpoint, route network and peer server
 * address the plugin compares goes through these, so a value typed by hand
 * in another notation still matches. Pure.
 */

require_once __DIR__ . '/selftest.php';

/**
 * @return string|null the canonical text of an IP address, null when $ip is not one
 */
function wgct_canon_ip(string $ip): ?string {
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
        return null;
    }
    $bin = inet_pton($ip);
    $out = $bin === false ? false : inet_ntop($bin);
    return $out === false ? null : $out;
}

/**
 * @return string|null 'inet', 'inet6', or null when $ip is not an IP address
 */
function wgct_ip_family(string $ip): ?string {
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
        return 'inet';
    }
    return filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? 'inet6' : null;
}

/**
 * A global IPv6 address: inside 2000::/3 (spec 2). Admits 2001:db8::/32;
 * excludes link-local, ULA, multicast, loopback, unspecified and IPv4-mapped.
 */
function wgct_is_global6(string $ip): bool {
    if (wgct_ip_family($ip) !== 'inet6') {
        return false;
    }
    $bin = inet_pton($ip);
    return $bin !== false && (ord($bin[0]) & 0xE0) === 0x20;
}

/**
 * @return string|null the canonical endpoint when it is IPv4 or global IPv6, else null
 */
function wgct_endpoint_ip(string $raw): ?string {
    $ip = wgct_canon_ip($raw);
    if ($ip === null) {
        return null;
    }
    return wgct_ip_family($ip) === 'inet' || wgct_is_global6($ip) ? $ip : null;
}

/**
 * @return string "ip:port", "[ip6]:port", or the host alone without a port
 */
function wgct_format_endpoint(string $ip, string $port): string {
    $host = wgct_ip_family($ip) === 'inet6' ? "[{$ip}]" : $ip;
    return $port === '' ? $host : "{$host}:{$port}";
}

/**
 * @return array{ip: string, family: string}|null a /32 IPv4 or /128 IPv6 route network, canonical
 */
function wgct_host_route(string $network): ?array {
    $slash = strrpos($network, '/');
    if ($slash === false) {
        return null;
    }
    $ip = wgct_canon_ip(substr($network, 0, $slash));
    $bits = substr($network, $slash + 1);
    if ($ip === null) {
        return null;
    }
    $family = wgct_ip_family($ip);
    if (($family === 'inet' && $bits === '32') || ($family === 'inet6' && $bits === '128')) {
        return ['ip' => $ip, 'family' => $family];
    }
    return null;
}

/**
 * @return string the host route network for an address: ip/32 or ip/128
 */
function wgct_host_network(string $ip): string {
    return $ip . (wgct_ip_family($ip) === 'inet6' ? '/128' : '/32');
}

function wgct_addr_selftest(): int {
    $t = ['fail' => 0, 'total' => 0];
    wgct_check($t, 'addr: canonical IPv4 is unchanged; IPv6 is compressed and lower case',
        wgct_canon_ip('198.51.100.10') === '198.51.100.10' && wgct_canon_ip('2001:DB8:0:0:0:0:0:10') === '2001:db8::10'
        && wgct_canon_ip('2001:0db8::0010') === '2001:db8::10');
    wgct_check($t, 'addr: a hostname or an empty string is not an address',
        wgct_canon_ip('vpn.example.net') === null && wgct_canon_ip('') === null);
    wgct_check($t, 'addr: family of IPv4, IPv6, other',
        wgct_ip_family('198.51.100.10') === 'inet' && wgct_ip_family('2001:db8::10') === 'inet6' && wgct_ip_family('vpn.example.net') === null);
    wgct_check($t, 'addr: global IPv6 is 2000::/3 only',
        wgct_is_global6('2001:db8::10') && wgct_is_global6('3fff::1')
        && !wgct_is_global6('fe80::1') && !wgct_is_global6('fd00::1') && !wgct_is_global6('::ffff:198.51.100.10')
        && !wgct_is_global6('ff02::1') && !wgct_is_global6('::1') && !wgct_is_global6('198.51.100.10'));
    wgct_check($t, 'addr: a supported endpoint is IPv4 or global IPv6, canonical',
        wgct_endpoint_ip('198.51.100.10') === '198.51.100.10' && wgct_endpoint_ip('2001:DB8::10') === '2001:db8::10'
        && wgct_endpoint_ip('fd00::1') === null && wgct_endpoint_ip('vpn.example.net') === null);
    wgct_check($t, 'addr: endpoint text brackets IPv6 only',
        wgct_format_endpoint('198.51.100.10', '51820') === '198.51.100.10:51820' && wgct_format_endpoint('198.51.100.10', '') === '198.51.100.10'
        && wgct_format_endpoint('2001:db8::10', '51820') === '[2001:db8::10]:51820');
    wgct_check($t, 'addr: host routes are /32 IPv4 and /128 IPv6, canonical',
        wgct_host_route('198.51.100.10/32') === ['ip' => '198.51.100.10', 'family' => 'inet']
        && wgct_host_route('2001:DB8:0::10/128') === ['ip' => '2001:db8::10', 'family' => 'inet6']
        && wgct_host_route('fe80::1/128') === ['ip' => 'fe80::1', 'family' => 'inet6']);
    wgct_check($t, 'addr: networks that are not host routes',
        wgct_host_route('2001:db8::/32') === null && wgct_host_route('198.51.100.0/24') === null
        && wgct_host_route('198.51.100.10') === null && wgct_host_route('198.51.100.10/128') === null);
    wgct_check($t, 'addr: host route rejects a missing bits part, a missing IP part, non-numeric bits, and a zone id',
        wgct_host_route('198.51.100.10/') === null && wgct_host_route('/32') === null
        && wgct_host_route('198.51.100.10/abc') === null && wgct_host_route('fe80::1%igc1/128') === null);
    wgct_check($t, 'addr: host network per family',
        wgct_host_network('198.51.100.10') === '198.51.100.10/32' && wgct_host_network('2001:db8::10') === '2001:db8::10/128');
    return wgct_tally_report('addr', $t);
}
