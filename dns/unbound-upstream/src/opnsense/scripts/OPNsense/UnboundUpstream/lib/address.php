<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The one address type: the resolver, a member's next hop and every address the scripts compare are an IPv4 or an
 * IPv6 address with a family, compared in canonical form (inet_ntop of inet_pton, so 2001:DB8:0:0::53 and
 * 2001:db8::53 are one address). Pure and standalone: it requires nothing, so the hook can load it beside state.php.
 * The ranges uu_ip_problem() refuses are the model's (UnboundUpstream::resolverProblems()), case for case.
 */

/**
 * The family of an address: 'inet', 'inet6', or null for anything else: an empty string, a prefix, a scoped address
 * (%wg0), a host name, an address with white space around it, and an IPv4-mapped IPv6 address (::ffff:0:0/96), which
 * Unbound and pf would read as IPv4.
 */
function uu_ip_family(string $addr): ?string
{
    if (filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
        return 'inet';
    }
    if (filter_var($addr, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) === false) {
        return null;
    }
    $packed = inet_pton($addr);
    return $packed === false || str_starts_with($packed, str_repeat("\0", 10) . "\xff\xff") ? null : 'inet6';
}

/** The address as Unbound and pf print it (lower case, the shortest IPv6 form); null when it has no family. */
function uu_ip_canonical(string $addr): ?string
{
    if (uu_ip_family($addr) === null) {
        return null;
    }
    $packed = inet_pton($addr);
    $text = $packed === false ? false : inet_ntop($packed);
    return $text === false ? null : strtolower($text);
}

/** Whether two strings are the same address; never for a string with no family. */
function uu_ip_same(string $a, string $b): bool
{
    $canonical = uu_ip_canonical($a);
    return $canonical !== null && $canonical === uu_ip_canonical($b);
}

/**
 * Why an address cannot be a resolver: 'not an address' (no family, see uu_ip_family()), 'link-local' (169.254.0.0/16,
 * fe80::/10), 'multicast' (exactly 224.0.0.0/4 and ff00::/8), 'unspecified' (0.0.0.0, ::), 'loopback' (127.0.0.0/8,
 * ::1), or null. 240.0.0.0/4 and 255.255.255.255 are left to the model's other checks.
 */
function uu_ip_problem(string $addr): ?string
{
    $family = uu_ip_family($addr);
    $packed = $family === null ? false : inet_pton($addr);
    if ($packed === false) {
        return 'not an address';
    }
    if ($family === 'inet') {
        $first = ord($packed[0]);
        return match (true) {
            $packed === "\0\0\0\0" => 'unspecified',
            $first === 127 => 'loopback',
            $first === 169 && ord($packed[1]) === 254 => 'link-local',
            $first >= 224 && $first <= 239 => 'multicast',
            default => null,
        };
    }
    return match (true) {
        $packed === str_repeat("\0", 16) => 'unspecified',
        $packed === str_repeat("\0", 15) . "\x01" => 'loopback',
        ord($packed[0]) === 0xfe && (ord($packed[1]) & 0xc0) === 0x80 => 'link-local',
        ord($packed[0]) === 0xff => 'multicast',
        default => null,
    };
}

/**
 * A next hop for comparing: canonical, with a %scope dropped (route(8) prints a link-local hop as fe80::1%gif0). A
 * string that is no address (empty, dynamic) comes back as it is.
 */
function uu_next_hop(string $hop): string
{
    return uu_ip_canonical(explode('%', $hop, 2)[0]) ?? $hop;
}

/**
 * The next hop as route(8) takes it: a link-local IPv6 hop needs its device, <hop>%<if>; any other hop is unchanged.
 */
function uu_route_hop(string $hop, string $if): string
{
    $bare = explode('%', $hop, 2)[0];
    if (uu_ip_family($bare) === 'inet6' && uu_ip_problem($bare) === 'link-local') {
        return uu_next_hop($bare) . '%' . $if;
    }
    return $hop;
}

/** The address-family argument of route(8) for 'inet' or 'inet6'. */
function uu_family_arg(string $family): string
{
    return $family === 'inet6' ? '-inet6' : '-inet';
}
