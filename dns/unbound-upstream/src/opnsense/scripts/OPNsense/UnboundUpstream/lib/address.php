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
 * The settings model (UnboundUpstream, through views.php) and the scripts share these ranges and tests: what
 * uu_ip_problem() refuses, the loopback networks, and the network and static-route tests, so Save and the run decide
 * alike. Each member's effective resolver and the group's family are decided here too, from plain arrays, and
 * forwarder lists are compared as sets (uu_apply_same()).
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
 * A network as Unbound masks a netblock: the packed address with its host bits cleared and the prefix length. A bare
 * address is a host route (/32, /128). Null for anything but an address (IPv4-mapped IPv6 included, which is an IPv6
 * netblock here) with an optional whole-number prefix no longer than its family allows: a scoped address, white
 * space, a host name, an empty or repeated prefix.
 *
 * @return ?array{packed: string, prefix: int}
 */
function uu_net_parse(string $net): ?array
{
    $parts = explode('/', $net);
    if (count($parts) > 2 || filter_var($parts[0], FILTER_VALIDATE_IP) === false) {
        return null;
    }
    $packed = inet_pton($parts[0]);
    if ($packed === false) {
        return null;
    }
    $bits = strlen($packed) * 8;
    $prefix = $bits;
    if (count($parts) === 2) {
        if (preg_match('/^(0|[1-9]\d{0,2})$/D', $parts[1]) !== 1 || (int)$parts[1] > $bits) {
            return null;
        }
        $prefix = (int)$parts[1];
    }
    return ['packed' => uu_net_mask($packed, $prefix), 'prefix' => $prefix];
}

/** The packed address with every bit past $prefix cleared. */
function uu_net_mask(string $packed, int $prefix): string
{
    $out = '';
    for ($i = 0; $i < strlen($packed); $i++) {
        $keep = max(0, min(8, $prefix - 8 * $i));
        $out .= chr(ord($packed[$i]) & ((0xFF << (8 - $keep)) & 0xFF));
    }
    return $out;
}

/** The network in canonical CIDR (host bits cleared, the shortest IPv6 form, lower case); null as uu_net_parse(). */
function uu_net_canonical(string $net): ?string
{
    $parsed = uu_net_parse($net);
    $text = $parsed === null ? false : inet_ntop($parsed['packed']);
    return $parsed === null || $text === false ? null : strtolower($text) . '/' . $parsed['prefix'];
}

/** Whether $outer holds all of $inner (itself included); never across families, never for a string that is no network. */
function uu_net_contains(string $outer, string $inner): bool
{
    $o = uu_net_parse($outer);
    $i = uu_net_parse($inner);
    return $o !== null && $i !== null && strlen($o['packed']) === strlen($i['packed']) && $o['prefix'] <= $i['prefix']
        && uu_net_mask($i['packed'], $o['prefix']) === $o['packed'];
}

/**
 * The networks Unbound's own loopback nodes cover. Save refuses a listed network that overlaps one (the firewall's
 * own lookups would be refused); the view puts no node within one.
 */
const UU_LOOPBACK_NETS = ['127.0.0.0/8', '::1/128', '::ffff:127.0.0.0/104'];

/**
 * Whether two networks share an address: both parse (uu_net_parse()), are of one family, and one holds the other;
 * never across families, never for a string that is no network.
 */
function uu_net_overlaps(string $a, string $b): bool
{
    return uu_net_contains($a, $b) || uu_net_contains($b, $a);
}

/** Whether a network overlaps any of UU_LOOPBACK_NETS. */
function uu_net_touches_loopback(string $net): bool
{
    foreach (UU_LOOPBACK_NETS as $loopback) {
        if (uu_net_overlaps($loopback, $net)) {
            return true;
        }
    }
    return false;
}

/** The digits a listed fail-closed network's length may have, as the settings check and the run both read it. */
const UU_NET_LENGTH_DIGITS = 3;

/**
 * A stored "address/length" entry, split as its reader reads it: the length is digits only, at most $digits of them
 * (null: any number, as core's Util::isSubnet() reads a static route's), taken as a number, so 192.0.2.0/024 is
 * ['addr' => '192.0.2.0', 'len' => 24]. Null for anything else: no '/' or more than one, an empty or signed length,
 * white space in the length. The address is left as written, white space included, and the length is not held to the
 * family: the caller reads both (uu_net_parse(), uu_ip_canonical()).
 *
 * @return ?array{addr: string, len: int}
 */
function uu_net_entry(string $entry, ?int $digits): ?array
{
    $parts = explode('/', $entry);
    $pattern = $digits === null ? '/^\d+$/D' : '/^\d{1,' . $digits . '}$/D';
    if (count($parts) !== 2 || preg_match($pattern, $parts[1]) !== 1) {
        return null;
    }
    return ['addr' => $parts[0], 'len' => (int)$parts[1]];
}

/**
 * Whether an address lies in a static route's network, in the address's own family: "addr/n", its length read as core
 * reads a route's (uu_net_entry() with any number of digits, so 192.0.2.0/024 is 192.0.2.0/24), host bits masked; or
 * a bare network, which is a host of its parsed family (/32 or /128). Never for another family, a string with no
 * family (see uu_ip_family()) or a malformed network.
 */
function uu_in_static(string $addr, string $network): bool
{
    $entry = str_contains($network, '/') ? uu_net_entry($network, null) : null;
    $cidr = $entry === null ? $network : $entry['addr'] . '/' . $entry['len'];
    return uu_ip_family($addr) !== null && uu_net_contains($cidr, $addr);
}

/**
 * Why an address cannot be a resolver: 'not an address' (no family, see uu_ip_family()), 'link-local' (169.254.0.0/16,
 * fe80::/10), 'multicast' (exactly 224.0.0.0/4 and ff00::/8), 'unspecified' (0.0.0.0, ::), 'loopback' (127.0.0.0/8,
 * ::1), or null. 240.0.0.0/4 and 255.255.255.255 are not refused; the settings model and the scripts share these
 * ranges.
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
 * The per-member rows as the scripts use them, checked again where they are used (a restored configuration bypasses
 * the model's masks): gateway UUID => canonical address. A row whose gateway is not a UUID or whose address is refused
 * (uu_resolver_refusal()) is dropped, as is a second row for one gateway, each with one problem that never quotes the
 * value. The one rule the settings and the render share.
 *
 * @param list<array{gateway: string, address: string}> $raw
 * @return array{rows: array<string, string>, problems: list<string>}
 */
function uu_rows_clean(array $raw): array
{
    $rows = [];
    $problems = [];
    foreach ($raw as $row) {
        $address = uu_resolver_refusal($row['address']) === null ? uu_ip_canonical($row['address']) : null;
        if ($address === null || preg_match('/^[0-9a-f-]{36}$/D', $row['gateway']) !== 1) {
            $problems[] = 'settings: a per-member resolver row is not a gateway id and an IPv4 or IPv6 address; '
                . 'ignored';
        } elseif (isset($rows[$row['gateway']])) {
            $problems[] = 'settings: two per-member resolver rows name one gateway; the second is ignored';
        } else {
            $rows[$row['gateway']] = $address;
        }
    }
    return ['rows' => $rows, 'problems' => $problems];
}

/**
 * Each gateway's name by its UUID, from gatewaysIndexedByName(true)'s records (core's Gateways model gives each
 * configured gateway its uuid); a dynamic gateway's record has none and is left out, so no row can name it.
 *
 * @param array<array-key, array<string, mixed>> $records
 * @return array<string, string>
 */
function uu_gateway_names(array $records): array
{
    $names = [];
    foreach ($records as $name => $gw) {
        $uuid = (string)($gw['uuid'] ?? '');
        if ($uuid !== '') {
            $names[$uuid] = (string)$name;
        }
    }
    return $names;
}

/**
 * Each member's effective resolver: its own row's address, else the Default, else '' (none: never a candidate). A row
 * is keyed by its gateway's UUID, which the Gateways model resolves to a name; a row whose UUID names no gateway, or
 * a gateway that is not a member, changes nothing and gets a note, as does a member left with no resolver.
 *
 * @param list<string> $members the group's member names, in tier order
 * @param array<string, string> $rows gateway UUID => canonical address (uu_rows_clean())
 * @param array<string, string> $names gateway UUID => gateway name, for every gateway the Gateways model holds
 *     (uu_gateway_names())
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
 * The addresses of a family other than the group's, in the order given: the resolvers the contract refuses by address.
 * A group of no family (none found, or no member with a family) has none to mismatch, and neither has a group of both
 * (its "family" is only its first member's, so a mismatch would name a member's correct resolver; the contract refuses
 * the mix itself).
 *
 * @param array{family: string, mixed: bool} $group uu_group_family()
 * @param list<string> $addresses canonical
 * @return list<string>
 */
function uu_family_mismatch(array $group, array $addresses): array
{
    if ($group['family'] === '' || $group['mixed']) {
        return [];
    }
    return array_values(array_filter($addresses,
        fn (string $address): bool => uu_ip_family($address) !== $group['family']));
}

/**
 * The setting's addresses: the planner's addresses (uu_plan_addresses(): the members' effective resolvers, or the
 * Default when the group has no member) while the plugin is enabled and its group is found, as 1.3_2 rendered its
 * resolver; none otherwise, so a disabled plugin's recorded addresses stay footprints. They decide what is a
 * footprint, what the rules render and what the counting table holds. The one home of this rule.
 *
 * @param array{settings: array{enabled: bool, default: string}, contract_input: array{group_found: bool},
 *     members: array<string, array{resolver: string}>} $s the Snapshot (planner.php), or the same fields
 * @return list<string>
 */
function uu_setting_addresses(array $s): array
{
    return $s['settings']['enabled'] && $s['contract_input']['group_found'] ? uu_plan_addresses($s) : [];
}

/**
 * The planner's addresses: what the plugin must keep fail-closed whatever the setting, as 1.3_2 kept its one resolver
 * whatever the group. They are the members' effective resolvers, or, when the snapshot has no member (the group is
 * not found, or has none), the Default when it is an address. Canonical, each once, sorted. The one home of this set:
 * the snapshot reads the route, the monitors and the static routes of these addresses (and their foreign routes are
 * the contract's), and the planner takes from it the addresses the live root may name, those that keep their reject
 * route outside tunnel mode, and those never drained. An orphan is an address the state holds outside this set, so
 * its release (released_at) is judged against it too. uu_setting_addresses() is this set while the plugin is enabled
 * and its group is found, and empty otherwise.
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
 * A member's effective resolver, canonical; '' for a member with none or not in the snapshot. The one reading of it
 * that the planner, apply and the status share.
 *
 * @param array{members: array<string, array{resolver: string}>} $s
 */
function uu_member_resolver(array $s, string $name): string
{
    return uu_ip_canonical($s['members'][$name]['resolver'] ?? '') ?? '';
}

/**
 * The address of one forwarder as `unbound-control forward` prints it: "@port" and "#name" dropped. The one place
 * that strip is made: the forwarded rule, the planner's live address and the forwarder-list comparison all take it.
 */
function uu_forwarder_addr(string $forwarder): string
{
    return (string)preg_replace('/[@#].*$/', '', $forwarder);
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
        $ip = uu_forwarder_addr($addr);
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
 * The root forwarders that are a member's effective resolver, each with the names of the members whose resolver it
 * is, in member order: the owner's forwarding of the root zone, which the plugin cannot tell from its own. Both sides
 * are compared bare and canonical (uu_apply_bare()), as the planner compares a live root with the resolvers, and keyed
 * in uu_apply_bare()'s order. A member with no resolver ('') is no address a forwarder can name. The one test the
 * contract and the settings check share.
 *
 * @param list<string> $rootAddrs the root zone's forwarders, "@port" and "#name" allowed
 * @param array<string, string> $memberResolvers member name => effective resolver, '' for none (uu_member_resolvers())
 * @return array<string, list<string>> forwarder, bare and canonical => the members whose resolver it is
 */
function uu_root_forward_conflicts(array $rootAddrs, array $memberResolvers): array
{
    $effective = [];
    foreach ($memberResolvers as $name => $address) {
        if ($address !== '') {
            $effective[uu_apply_bare([$address])[0]][] = (string)$name;
        }
    }
    $conflicts = [];
    foreach (uu_apply_bare($rootAddrs) as $address) {
        if (isset($effective[$address])) {
            $conflicts[$address] = $effective[$address];
        }
    }
    return $conflicts;
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

const UU_NOTIFY_URL_MASK = '/^https?:\/\/[^\s\/?#]+(\/\S*)?$/'; /* the URL shape the settings and the run share */

/** Whether the URL is an http or https URL; 'D' keeps a trailing newline out, which the mask's own $ would let through. */
function uu_notify_url_ok(string $url): bool
{
    return preg_match(UU_NOTIFY_URL_MASK . 'D', $url) === 1;
}
