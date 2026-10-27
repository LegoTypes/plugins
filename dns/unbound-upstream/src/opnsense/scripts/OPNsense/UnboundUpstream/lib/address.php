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
 * The ranges uu_ip_problem() refuses are the model's (UnboundUpstream::resolverProblems()), case for case. Each
 * member's effective resolver and the group's family are decided here too, from plain arrays, and forwarder lists
 * are compared as sets (uu_apply_same()).
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
 * ::1), or null. 240.0.0.0/4 and 255.255.255.255 are not refused, as in the model.
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
 * Why a setting's resolver is refused, as the sentence "the resolver is ..." finishes it: 'not an IPv4 or IPv6 address'
 * for a value with no family, else uu_ip_problem()'s word; null when the address may be a resolver. The one decision
 * the settings check, the render's reader and the hook share.
 */
function uu_resolver_refusal(string $addr): ?string
{
    $problem = uu_ip_problem($addr);
    return $problem === 'not an address' ? 'not an IPv4 or IPv6 address' : $problem;
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
 * Whether a gateway record's next hop is an address a host route can go through (a link-local one with its %scope
 * too); never an empty or 'dynamic' gateway, which leaves the member with no route to its resolver.
 */
function uu_next_hop_routable(string $hop): bool
{
    return uu_ip_family(explode('%', $hop, 2)[0]) !== null;
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

/**
 * The `route delete` command that undoes a host route to an address, as the remedy texts print it: the IPv4 form has
 * no family argument (as it always read); an IPv6 address needs -inet6, which route(8) otherwise refuses. A string
 * with no family, a placeholder, gets the IPv4 form.
 */
function uu_route_delete_text(string $addr): string
{
    return 'route delete ' . (uu_ip_family($addr) === 'inet6' ? '-inet6 ' : '') . '-host ' . $addr;
}

/**
 * The arguments of `route -n get` for a resolver: the family argument and the quoted address; null for a string with
 * no family.
 */
function uu_route_get_args(string $resolver): ?string
{
    $family = uu_ip_family($resolver);
    return $family === null ? null : uu_family_arg($family) . ' ' . escapeshellarg($resolver);
}

/** The address-family argument of route(8) for 'inet' or 'inet6'. */
function uu_family_arg(string $family): string
{
    return $family === 'inet6' ? '-inet6' : '-inet';
}

/**
 * Each member's effective resolver: its own row's address, else the Default, else '' (none: never a candidate). A row
 * is keyed by its gateway's UUID, which the Gateways model resolves to a name; a row whose UUID names no gateway, or
 * a gateway that is not a member, changes nothing and gets a note, as does a member left with no resolver.
 *
 * @param list<string> $members the group's member names, in tier order
 * @param array<string, string> $rows gateway UUID => canonical address (uu_settings_clean())
 * @param array<string, string> $names gateway UUID => gateway name, for every gateway the Gateways model holds
 * @param string $default the Default resolver, canonical, or ''
 * @return array{resolvers: array<string, string>, notes: list<string>}
 */
function uu_member_resolvers(array $members, array $rows, array $names, string $default): array
{
    $notes = [];
    $own = [];
    foreach ($rows as $uuid => $address) {
        $name = $names[$uuid] ?? null;
        if ($name === null) {
            $notes[] = "row for gateway $uuid ignored: no such gateway";
        } elseif (!in_array($name, $members, true)) {
            $notes[] = "row for $name ignored: not a member of the group";
        } else {
            $own[$name] = $address;
        }
    }
    $resolvers = [];
    foreach ($members as $name) {
        $resolvers[$name] = $own[$name] ?? $default;
        if ($resolvers[$name] === '') {
            $notes[] = "$name has no resolver: not a candidate";
        }
    }
    return ['resolvers' => $resolvers, 'notes' => $notes];
}

/**
 * The group's address family, as core reads a group's (GatewayGroups::getGroupIPProto(): its first gateway's): the
 * ipprotocol of the first member in tier order that has 'inet' or 'inet6', '' with none; mixed when another member has
 * the other family. The script-side counterpart of the model's groupFamily().
 *
 * @param array<string, array{ipprotocol: string}> $members member records by name
 * @param list<list<string>> $tiers best tier first
 * @return array{family: string, mixed: bool}
 */
function uu_group_family(array $members, array $tiers): array
{
    $family = '';
    $mixed = false;
    foreach ($tiers as $tier) {
        foreach ($tier as $name) {
            $proto = $members[$name]['ipprotocol'] ?? '';
            if ($proto !== 'inet' && $proto !== 'inet6') {
                continue;
            }
            if ($family === '') {
                $family = $proto;
            } elseif ($proto !== $family) {
                $mixed = true;
            }
        }
    }
    return ['family' => $family, 'mixed' => $mixed];
}

/**
 * The setting's addresses: the members' effective resolvers, which decide what is a footprint, what the rules render
 * and what the counting table holds; none while the plugin is disabled or its group is not found, so a disabled
 * plugin's recorded addresses stay footprints. Canonical, each once, sorted. The one home of this rule; the planner's
 * own set is uu_plan_addresses(), which keeps the Default when the group is gone.
 *
 * @param array{settings: array{enabled: bool}, contract_input: array{group_found: bool},
 *     members: array<string, array{resolver: string}>} $s the Snapshot (planner.php), or the same fields
 * @return list<string>
 */
function uu_setting_addresses(array $s): array
{
    if (!$s['settings']['enabled'] || !$s['contract_input']['group_found']) {
        return [];
    }
    $addresses = [];
    foreach ($s['members'] as $m) {
        $address = uu_ip_canonical($m['resolver']);
        if ($address !== null) {
            $addresses[$address] = true;
        }
    }
    $addresses = array_map('strval', array_keys($addresses));
    sort($addresses, SORT_STRING);
    return $addresses;
}

/**
 * The planner's addresses: what the plugin must keep fail-closed whatever the setting, as 1.3_2 kept its one resolver
 * whatever the group. They are the members' effective resolvers, or, when the snapshot has no member (the group is
 * not found, or has none), the Default when it is an address. Canonical, each once, sorted. The one home of this set:
 * the snapshot reads the route, the monitors and the static routes of these addresses (and their foreign routes are
 * the contract's), and the planner takes from it the addresses the live root may name, those that keep their reject
 * route outside tunnel mode, and those never drained. An orphan is an address the state holds outside this set, so
 * its release (released_at) is judged against it too. Distinct from uu_setting_addresses(), which is empty while the
 * plugin is disabled or the group is not found.
 *
 * @param array{settings: array{default: string}, members: array<string, array{resolver: string}>} $s the Snapshot
 *     (planner.php), or the same fields
 * @return list<string>
 */
function uu_plan_addresses(array $s): array
{
    if ($s['members'] === []) {
        $default = uu_ip_canonical($s['settings']['default']);
        return $default === null ? [] : [$default];
    }
    $addresses = [];
    foreach ($s['members'] as $m) {
        $address = uu_ip_canonical($m['resolver']);
        if ($address !== null) {
            $addresses[$address] = true;
        }
    }
    $addresses = array_map('strval', array_keys($addresses));
    sort($addresses, SORT_STRING);
    return $addresses;
}

/**
 * Addresses as `unbound-control forward` prints them, for comparing as sets: "@port" and "#name" dropped, IPv6 in
 * its canonical form, sorted, each once. With uu_apply_same(), the one comparison of forwarder lists that apply and
 * the planner share.
 *
 * @param list<string> $addrs
 * @return list<string>
 */
function uu_apply_bare(array $addrs): array
{
    $out = [];
    foreach ($addrs as $addr) {
        $ip = (string)preg_replace('/[@#].*$/', '', $addr);
        if (filter_var($ip, FILTER_VALIDATE_IP) !== false) {
            $packed = inet_pton($ip);
            $text = $packed === false ? false : inet_ntop($packed);
            $ip = $text === false ? $ip : $text;
        }
        $out[] = strtolower($ip);
    }
    $out = array_values(array_unique($out));
    sort($out);
    return $out;
}

/**
 * Whether the live root forwarders are the wanted ones; an unknown live root never is.
 *
 * @param ?list<string> $live
 * @param list<string> $want
 */
function uu_apply_same(?array $live, array $want): bool
{
    return $live !== null && uu_apply_bare($live) === uu_apply_bare($want);
}
