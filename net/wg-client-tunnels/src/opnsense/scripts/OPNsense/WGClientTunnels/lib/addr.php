<?php

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
 * Address helpers for derivation, the planners and the views. Every endpoint, route network and peer server
 * address the plugin compares goes through these, so a value typed by hand
 * in another notation still matches. Pure.
 */

/* checked first, as every require in the filter hook's chain is (render.php) */
if (!is_readable(__DIR__ . '/selftest.php')) {
    throw new \RuntimeException('plugin library file selftest.php missing');
}
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
 * @return string|null the canonical text of an IP address with an IPv6 zone kept as given (`FE80::0001%wg1` gives
 *                     `fe80::1%wg1`), null when the part before `%` is no IP or the zone is empty or not a device name
 */
function wgct_canon_ip_zoned(string $ip): ?string {
    $at = strpos($ip, '%');
    if ($at === false) {
        return wgct_canon_ip($ip);
    }
    $bare = wgct_canon_ip(substr($ip, 0, $at));
    $zone = substr($ip, $at + 1);
    if ($bare === null || wgct_ip_family($bare) !== 'inet6' || preg_match('/^[A-Za-z0-9_.]+$/D', $zone) !== 1) {
        return null;
    }
    return $bare . '%' . $zone;
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
 * @return string|null 'inet' or 'inet6' by the part of $cidr before the first `/` (the whole text when it has none),
 *                     null when that part is not an IP address
 */
function wgct_cidr_family(string $cidr): ?string {
    $slash = strpos($cidr, '/');
    return wgct_ip_family($slash === false ? $cidr : substr($cidr, 0, $slash));
}

/**
 * A global IPv6 address: inside 2000::/3. Admits 2001:db8::/32;
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

/**
 * Whether $ip lies inside $network ("address/bits"), comparing the leading bits of the packed addresses.
 * Different families, a missing or out-of-range prefix length, or a non-address never match. Pure.
 *
 * @param string $ip      an address
 * @param string $network "address/bits"
 * @return bool
 */
function wgct_in_network(string $ip, string $network): bool {
    [$net, $bits] = array_pad(explode('/', $network, 2), 2, '');
    $a = @inet_pton($ip);
    $n = @inet_pton($net);
    if ($a === false || $n === false || strlen($a) !== strlen($n) || !ctype_digit($bits) || (int)$bits > strlen($a) * 8) {
        return false;
    }
    $bits = (int)$bits;
    $whole = intdiv($bits, 8);
    if (substr($a, 0, $whole) !== substr($n, 0, $whole)) {
        return false;
    }
    $rest = $bits % 8;
    if ($rest === 0) {
        return true;
    }
    $mask = (0xff << (8 - $rest)) & 0xff;
    return (ord($a[$whole]) & $mask) === (ord($n[$whole]) & $mask);
}

/**
 * @return string|null the network of "address/bits" with its host bits cleared, canonical (`2001:DB8:1::5/64` gives
 *                     `2001:db8:1::/64`), null when the address is no IP or the prefix length is missing or out of range
 */
function wgct_cidr_network(string $cidr): ?string {
    [$ip, $bits] = array_pad(explode('/', $cidr, 2), 2, '');
    $bin = wgct_canon_ip($ip) !== null ? inet_pton($ip) : false;
    if ($bin === false || !ctype_digit($bits) || (int)$bits > strlen($bin) * 8) {
        return null;
    }
    $keep = (int)$bits;
    $net = '';
    foreach (str_split($bin) as $i => $byte) {
        $own = max(0, min(8, $keep - 8 * $i));
        $net .= chr(ord($byte) & ((0xff << (8 - $own)) & 0xff));
    }
    $text = inet_ntop($net);
    return $text === false ? null : "{$text}/{$keep}";
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
    wgct_check($t, 'addr: in_network by prefix, both families, never across families or with bad bits',
        wgct_in_network('2001:db8:1:1::abcd', '2001:db8:1:1::1/64') && !wgct_in_network('2001:db8:1:2::1', '2001:db8:1:1::1/64')
        && wgct_in_network('2001:db8:2:1ff::5', '2001:db8:2:100::/56') && wgct_in_network('2001:db8::10', '2001:db8::10/128')
        && wgct_in_network('198.51.100.7', '198.51.100.0/24') && !wgct_in_network('198.51.100.7', '2001:db8::/32')
        && !wgct_in_network('2001:db8::1', '2001:db8::/129') && !wgct_in_network('2001:db8::1', '2001:db8::') && !wgct_in_network('x', '::/0'));
    wgct_check($t, 'addr: a zoned address keeps its zone, canonical',
        wgct_canon_ip_zoned('FE80::0001%wg1') === 'fe80::1%wg1' && wgct_canon_ip_zoned('2001:DB8::0050') === '2001:db8::50'
        && wgct_canon_ip_zoned('192.0.2.1') === '192.0.2.1' && wgct_canon_ip_zoned('x%wg1') === null);
    wgct_check($t, 'addr: family of a network from parsing',
        wgct_cidr_family('2001:DB8::0050/128') === 'inet6' && wgct_cidr_family('2001:db8::50') === 'inet6'
        && wgct_cidr_family('192.0.2.2/32') === 'inet' && wgct_cidr_family('::ffff:192.0.2.2/128') === 'inet6'
        && wgct_cidr_family('host:name/1') === null && wgct_cidr_family('') === null);
    wgct_check($t, 'addr: the network of an address and prefix length, host bits cleared, canonical',
        wgct_cidr_network('192.0.2.5/24') === '192.0.2.0/24' && wgct_cidr_network('2001:DB8:1::5/64') === '2001:db8:1::/64'
        && wgct_cidr_network('2001:db8:2:1ff::5/56') === '2001:db8:2:100::/56' && wgct_cidr_network('192.0.2.77/26') === '192.0.2.64/26' && wgct_cidr_network('198.51.100.7/32') === '198.51.100.7/32'
        && wgct_cidr_network('198.51.100.7/0') === '0.0.0.0/0' && wgct_cidr_network('198.51.100.7/33') === null
        && wgct_cidr_network('198.51.100.7') === null && wgct_cidr_network('fe80::1%wg1/64') === null && wgct_cidr_network('x/8') === null);
    return wgct_tally_report('addr', $t);
}
