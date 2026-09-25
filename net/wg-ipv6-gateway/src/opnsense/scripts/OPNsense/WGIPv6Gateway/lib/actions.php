<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The action planners (spec 2026-09-24 section 6): Create, Rebind, Adopt,
 * Remove and the default-route sentinel. Each is a pure function from a
 * snapshot of core config -- wgipv6_action_snapshot() in writer.php, or the
 * fixture below -- to the exact objects to write, a change list, and the
 * reasons it cannot proceed. Nothing here reads config or holds a key.
 *
 * Conventions the plugin owns (spec 6.1): instance N is the lowest free from
 * 1; listen port 51820+N; IPv4 far gateway 10.2.0.(3+N); IPv6 next hop
 * fd00::N:2 and, with unique addressing, tunnel address fd00::N:1/128. "Free"
 * means all of those are unused, so a clash skips to the next N.
 */

require_once __DIR__ . '/tunnels.php';
require_once __DIR__ . '/refs.php';
require_once __DIR__ . '/wgconf.php';
require_once __DIR__ . '/selftest.php';

/* the far gateway 10.2.0.(3+N) must stay inside the /24 */
const WGIPV6_INSTANCE_MAX = 251;
const WGIPV6_PORT_BASE = 51820;
/* the gateway fields a template tunnel supplies; fargw, monitor_disable,
 * force_down and defaultgw are always set as spec 6.1 says */
const WGIPV6_GATEWAY_COPY_FIELDS = [
    'monitor_noroute', 'monitor_killstates', 'monitor_killstates_priority', 'priority', 'weight',
    'latencylow', 'latencyhigh', 'losslow', 'losshigh', 'interval', 'time_period', 'loss_interval', 'data_length', 'nosync',
];
/* snatrules fields a copied rule does not take from its template (volatile, or its own) */
const WGIPV6_SNAT_SKIP_FIELDS = ['interface', 'sequence', 'sort_order', 'prio_group', 'audit'];
const WGIPV6_SENTINELS = ['inet' => 'NO_DEFAULT4', 'inet6' => 'NO_DEFAULT6'];
const WGIPV6_SENTINEL_PRIORITY = '254';
const WGIPV6_SENTINEL_IF_DESCR = 'NODEFAULT';
const WGIPV6_SENTINEL_LOOPBACK_DESCR = 'no-default sentinel';
const WGIPV6_SENTINEL_GW_DESCR = 'Sentinel: blocks non-native gateways from the default route (never carries traffic)';

/**
 * The one result shape every action returns (CLI JSON, configd output, API).
 * Create's errors are keyed by request field (WGIPV6_CREATE_FIELDS or
 * 'general'); the other actions' are a list. After a save, a failed apply
 * step adds the key 'apply'.
 *
 * @param array $over keys to set
 * @return array{ok: bool, saved: bool, dry: bool, errors: array, changes: list<string>, uuid: string, gateways: list<string>, steps: list<array{0: string, 1: list<string>}>, route_todos: array<string, string>, reset_interface: ?string, apply: list<array{action: string, result: string}>, after: array}
 */
function wgipv6_result(array $over = []): array {
    return $over + [
        'ok' => false, 'saved' => false, 'dry' => false, 'errors' => [], 'changes' => [], 'uuid' => '',
        'gateways' => [], 'steps' => [], 'route_todos' => [], 'reset_interface' => null, 'apply' => [], 'after' => [],
    ];
}

/**
 * @return bool both are IP addresses of the same value (any notation)
 */
function wgipv6_ip_equal(string $a, string $b): bool {
    if (filter_var($a, FILTER_VALIDATE_IP) === false || filter_var($b, FILTER_VALIDATE_IP) === false) {
        return false;
    }
    return inet_pton($a) === inet_pton($b);
}

/**
 * @param string $ip   an address
 * @param array  $list addresses or CIDRs (the prefix is ignored)
 * @return bool
 */
function wgipv6_ip_in(string $ip, array $list): bool {
    foreach ($list as $candidate) {
        if (is_string($candidate) && wgipv6_ip_equal($ip, explode('/', $candidate)[0])) {
            return true;
        }
    }
    return false;
}

/**
 * @param array $core wgipv6_core_snapshot()
 * @return array<string, true> wgN device names of every WireGuard instance
 */
function wgipv6_wg_devices(array $core): array {
    $out = [];
    foreach ($core['instances'] as $inst) {
        $out['wg' . $inst['instance']] = true;
    }
    return $out;
}

/**
 * @param array  $core wgipv6_core_snapshot()
 * @param string $wan  a gateway name
 * @return string|null why it cannot carry a tunnel's endpoint route, or null
 */
function wgipv6_wan_error(array $core, string $wan): ?string {
    $g = $core['gateways'][$wan] ?? null;
    if ($g === null) {
        return "no gateway named {$wan}";
    }
    if (in_array($wan, WGIPV6_SENTINELS, true)) {
        return "{$wan} is a no-default sentinel";
    }
    if ($g['ipprotocol'] !== 'inet') {
        return "{$wan} is not an IPv4 gateway";
    }
    if (isset(wgipv6_wg_devices($core)[$core['interfaces'][$g['interface']]['if'] ?? ''])) {
        return "{$wan} is on a WireGuard interface";
    }
    return null;
}

/**
 * @param array  $core        wgipv6_core_snapshot()
 * @param array  $ports       instance uuid => listen port
 * @param bool   $ipv6        whether fd00::N:1 and fd00::N:2 must be free too
 * @param string $ipv4Address the new tunnel's own IPv4 address
 * @return int|null the lowest free N from 1, or null when none is left
 */
function wgipv6_pick_instance(array $core, array $ports, bool $ipv6, string $ipv4Address): ?int {
    $usedN = [];
    $tunnelIps = [];
    foreach ($core['instances'] as $inst) {
        $usedN[(string)$inst['instance']] = true;
        foreach ($inst['tunneladdress'] as $address) {
            $tunnelIps[] = $address;
        }
    }
    $usedPorts = [];
    foreach ($ports as $port) {
        $usedPorts[(string)$port] = true;
    }
    $gatewayIps = [];
    foreach ($core['gateways'] as $g) {
        if ($g['gateway'] !== '') {
            $gatewayIps[] = $g['gateway'];
        }
    }
    $taken = fn (string $ip): bool => wgipv6_ip_in($ip, $gatewayIps) || wgipv6_ip_in($ip, $tunnelIps);
    for ($n = 1; $n <= WGIPV6_INSTANCE_MAX; $n++) {
        $far4 = '10.2.0.' . (3 + $n);
        if (isset($usedN[(string)$n]) || isset($usedPorts[(string)(WGIPV6_PORT_BASE + $n)])
            || $taken($far4) || wgipv6_ip_equal($far4, $ipv4Address)) {
            continue;
        }
        if ($ipv6 && ($taken("fd00::{$n}:1") || $taken("fd00::{$n}:2"))) {
            continue;
        }
        return $n;
    }
    return null;
}

/**
 * @param array $interfaces config interface key => anything
 * @return string the lowest free optN from opt1 (core's own rule)
 */
function wgipv6_pick_opt(array $interfaces): string {
    $i = 1;
    while (isset($interfaces['opt' . $i])) {
        $i++;
    }
    return 'opt' . $i;
}

/**
 * @return string the tunnel name without the characters core's interface description refuses
 */
function wgipv6_interface_descr(string $name): string {
    return (string)preg_replace('/[^a-zA-Z0-9]/', '', $name);
}

/**
 * @return string the address in one canonical text form, so two spellings
 *                of one IPv6 address compare equal; anything else unchanged
 */
function wgipv6_canonical_ip(string $ip): string {
    if (filter_var($ip, FILTER_VALIDATE_IP) === false) {
        return $ip;
    }
    $packed = inet_pton($ip);
    $text = $packed !== false ? inet_ntop($packed) : false;
    return $text !== false ? strtolower($text) : $ip;
}

/**
 * Every IPv6 tunnel address on any WireGuard instance, managed or not,
 * enabled or not: FreeBSD refuses one IPv6 address on two interfaces (ruling 3).
 *
 * @param array $core wgipv6_core_snapshot()
 * @return array<string, string> canonical address => instance name
 */
function wgipv6_instance_ipv6(array $core): array {
    $out = [];
    foreach ($core['instances'] as $inst) {
        foreach ($inst['tunneladdress'] as $address) {
            $ip = explode('/', $address)[0];
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
                $out[wgipv6_canonical_ip($ip)] = $inst['name'];
            }
        }
    }
    return $out;
}

/**
 * Does any managed tunnel follow the fd00::N:1 convention for its own wgN?
 * Then new tunnels default to it too (ruling 3). Pure.
 *
 * @param array $derived wgipv6_derive()
 * @return bool
 */
function wgipv6_unique_convention(array $derived): bool {
    foreach ($derived['tunnels'] as $t) {
        if ($t['ipv6_address'] !== null && preg_match('/^wg(\d+)$/', $t['device'], $m) === 1
            && wgipv6_ip_equal(explode('/', $t['ipv6_address'])[0], "fd00::{$m[1]}:1")) {
            return true;
        }
    }
    return false;
}

/**
 * @return bool a config interface key that names a real interface net
 *              (not an interface group or other virtual entry such as `wireguard`)
 */
function wgipv6_is_nat_interface_key(string $key): bool {
    return preg_match('/^(wan|lan|opt\d+)$/', $key) === 1;
}

/**
 * Everything Create will write, or why it cannot (spec 6.1). Pure.
 *
 * @param array $snap the action snapshot (see Task 3 Interfaces)
 * @param array $req  wgipv6_create_request()['req'] with 'mtu' set
 * @param array $conf wgipv6_parse_wgquick()['public']
 * @return array see Task 3 Interfaces
 */
function wgipv6_plan_create(array $snap, array $req, array $conf): array {
    $core = $snap['core'];
    $e = [];
    $plan = [
        'errors' => [], 'changes' => [], 'n' => 0, 'device' => '', 'opt' => '', 'descr' => '', 'unique' => false, 'ipv6' => false,
        'instance' => [], 'peer' => [], 'gateways' => [], 'route' => ['action' => 'none', 'uuid' => '', 'fields' => []], 'nat' => [],
    ];
    $name = $req['name'];
    $name6 = $name . '-ipv6';
    $derived = wgipv6_derive($core, $snap['managed']);

    /* the name: instance, peer and both gateways carry it, the interface a cleaned copy */
    foreach ([$name, $name6] as $gwName) {
        if (isset($core['gateways'][$gwName])) {
            $e['name'] = "a gateway named {$gwName} already exists";
        }
    }
    foreach ($core['instances'] as $inst) {
        if ($inst['name'] === $name) {
            $e['name'] = "a WireGuard instance named {$name} already exists";
        }
    }
    foreach ($core['peers'] as $peer) {
        if ($peer['name'] === $name) {
            $e['name'] = "a WireGuard peer named {$name} already exists";
        }
    }
    $descr = wgipv6_interface_descr($name);
    $taken = array_map('strtolower', array_merge(
        array_map('strval', array_keys($core['interfaces'])),
        array_column($core['interfaces'], 'descr'),
        $snap['ifgroup_names']
    ));
    if ($descr === '' || ctype_digit($descr)) {
        $e['name'] = 'the interface description (the name without "-" and "_") needs a letter';
    } elseif (in_array(strtolower($descr), $taken, true)) {
        $e['name'] = "the interface description {$descr} is already an interface or interface group name";
    }

    /* the WAN, and the endpoint route that binds the tunnel to it */
    $wanError = wgipv6_wan_error($core, $req['wan']);
    if ($wanError !== null) {
        $e['wan'] = $wanError;
    }
    $endpoint = $conf['endpoint_ip'];
    $network = $endpoint . '/32';
    $same = array_filter($core['routes'], fn (array $r): bool => $r['network'] === $network);
    if (count($same) > 1) {
        $e['wan'] = "several routes to {$network} exist; keep one on System > Routes first";
    } elseif (count($same) === 1) {
        $routeUuid = (string)array_key_first($same);
        $existing = $same[$routeUuid];
        if ($existing['enabled'] && $existing['gateway'] !== $req['wan']) {
            $e['wan'] = "{$network} is already routed via {$existing['gateway']}";
        } elseif ($existing['enabled']) {
            $plan['route'] = ['action' => 'keep', 'uuid' => $routeUuid, 'fields' => []];
        } else {
            $plan['route'] = ['action' => 'update', 'uuid' => $routeUuid, 'fields' => ['gateway' => $req['wan'], 'enabled' => '1']];
        }
    } else {
        $plan['route'] = ['action' => 'add', 'uuid' => '', 'fields' => [
            'network' => $network, 'gateway' => $req['wan'], 'descr' => 'wireguard - ' . $name, 'enabled' => '1',
        ]];
    }

    /* the monitor IP is used for nothing else (R2) */
    $monitor = $req['monitor'];
    $uses = [];
    foreach ($core['gateways'] as $gwName => $g) {
        if ($g['monitor'] !== '' && wgipv6_ip_equal($g['monitor'], $monitor)) {
            $uses[] = "the monitor of {$gwName}";
        }
        if ($g['gateway'] !== '' && wgipv6_ip_equal($g['gateway'], $monitor)) {
            $uses[] = "the address of {$gwName}";
        }
    }
    if (wgipv6_ip_in($monitor, array_merge($core['dns_servers'], $core['forwarders']))) {
        $uses[] = 'a system DNS server or Unbound forwarder';
    }
    if (wgipv6_ip_in($monitor, array_merge([$endpoint], array_column($core['peers'], 'serveraddress')))) {
        $uses[] = 'a WireGuard endpoint';
    }
    if ($uses !== []) {
        $e['monitor'] = "{$monitor} is already " . implode(', ', array_unique($uses)) . '; a tunnel needs a monitor IP nothing else uses';
    }

    /* the template tunnel, by uuid or name, among the managed ones */
    $tpl = null;
    if ($req['template'] !== '') {
        foreach ($derived['tunnels'] as $t) {
            if ($t['uuid'] === $req['template'] || ($t['name'] !== '' && $t['name'] === $req['template'])) {
                $tpl = $t;
            }
        }
        if ($tpl === null) {
            $e['template'] = 'not a managed tunnel';
        } elseif ($tpl['interface'] === null || $tpl['gw4'] === null) {
            $e['template'] = "{$tpl['name']} has no interface or IPv4 gateway to copy from";
            $tpl = null;
        }
    }

    /* addresses: IPv4 from the config; IPv6 from the config or fd00::N:1 (rulings 3 and 4) */
    $v4 = $conf['addresses']['inet'][0] ?? '';
    $v6conf = $conf['addresses']['inet6'];
    $ipv6 = $req['ipv6'] ?? ($v6conf !== []);
    if ($ipv6 && $v6conf === []) {
        $e['ipv6'] = 'the provider assigned no IPv6 address to this peer (the config has no IPv6 Address); IPv6 must be off';
    }
    $instanceV6 = wgipv6_instance_ipv6($core);
    $sharedBy = null;
    foreach ($v6conf as $address) {
        $canonical = wgipv6_canonical_ip(explode('/', $address)[0]);
        if ($sharedBy === null && isset($instanceV6[$canonical])) {
            $sharedBy = [$address, $instanceV6[$canonical]];
        }
    }
    $convention = wgipv6_unique_convention($derived);
    $unique = $ipv6 && ($req['unique'] ?? ($sharedBy !== null || $convention));
    $uniqueWhy = $req['unique'] !== null ? 'as requested'
        : ($sharedBy !== null ? "default: {$sharedBy[0]} is already on instance {$sharedBy[1]}"
            : 'default: the managed tunnels use the fd00::N:1 convention');
    $v6addr = '';
    if ($ipv6 && !$unique && $v6conf !== []) {
        if (count($v6conf) !== 1) {
            $e['unique'] = 'the config has several IPv6 addresses; turn on unique addressing';
        } else {
            $v6addr = $v6conf[0];
            foreach ($core['instances'] as $inst) {
                if (wgipv6_ip_in(explode('/', $v6addr)[0], $inst['tunneladdress'])) {
                    $e['unique'] = "{$v6addr} is already on instance {$inst['name']} (FreeBSD refuses one IPv6 address on two interfaces); turn on unique addressing";
                }
            }
        }
    }

    /* NAT sources, used only without a template; the IPv6 list only with IPv6 on */
    $sources = ['inet' => $req['nat']['inet'], 'inet6' => $ipv6 ? $req['nat']['inet6'] : []];
    if ($req['template'] === '') {
        $known = array_merge(
            array_values(array_filter(array_map('strval', array_keys($core['interfaces'])), 'wgipv6_is_nat_interface_key')),
            $snap['aliases']
        );
        foreach (['inet' => 'nat4', 'inet6' => 'nat6'] as $family => $field) {
            $unknown = array_values(array_diff($sources[$family], $known));
            if ($unknown !== []) {
                $e[$field] = 'not an interface or alias: ' . implode(', ', $unknown);
            }
        }
    }

    $n = wgipv6_pick_instance($core, $snap['ports'], $ipv6, explode('/', $v4)[0]);
    if ($n === null) {
        $e['general'] = sprintf('no free instance number from 1 to %d (its instance number, listen port, far gateway and fd00::N addresses must all be unused)', WGIPV6_INSTANCE_MAX);
    }
    if ($e !== [] || $n === null) {
        $plan['errors'] = $e;
        return $plan;
    }

    /* the objects */
    $opt = wgipv6_pick_opt($core['interfaces']);
    $device = 'wg' . $n;
    $far4 = '10.2.0.' . (3 + $n);
    $next6 = "fd00::{$n}:2";
    $addr6 = $ipv6 ? ($unique ? "fd00::{$n}:1/128" : $v6addr) : '';
    $plan['n'] = $n;
    $plan['device'] = $device;
    $plan['opt'] = $opt;
    $plan['descr'] = $descr;
    $plan['unique'] = $unique;
    $plan['ipv6'] = $ipv6;
    $plan['instance'] = [
        'enabled' => '1', 'name' => $name, 'instance' => (string)$n, 'port' => (string)(WGIPV6_PORT_BASE + $n),
        'mtu' => (string)$req['mtu'], 'tunneladdress' => $addr6 !== '' ? "{$v4},{$addr6}" : $v4,
        'disableroutes' => '1', 'gateway' => $far4, 'debug' => '0',
    ];
    $plan['peer'] = [
        'enabled' => '1', 'name' => $name, 'pubkey' => $conf['peer_pubkey'],
        'tunneladdress' => $ipv6 ? '0.0.0.0/0,::/0' : '0.0.0.0/0',
        'serveraddress' => $endpoint, 'serverport' => $conf['endpoint_port'], 'keepalive' => WGIPV6_KEEPALIVE,
    ];
    $copy = function (?string $gwName) use ($snap): array {
        $fields = $gwName !== null ? ($snap['gateway_fields'][$gwName] ?? []) : [];
        return array_intersect_key($fields, array_flip(WGIPV6_GATEWAY_COPY_FIELDS));
    };
    $plan['gateways'][] = ['name' => $name, 'fields' => array_merge($copy($tpl['gw4'] ?? null), [
        'disabled' => '0', 'name' => $name, 'descr' => "{$name} (IPv4 tunnel)", 'interface' => $opt, 'ipprotocol' => 'inet',
        'gateway' => $far4, 'monitor' => $monitor, 'defaultgw' => '0', 'fargw' => '1', 'monitor_disable' => '0', 'force_down' => '0',
    ])];
    if ($ipv6) {
        $plan['gateways'][] = ['name' => $name6, 'fields' => array_merge($copy($tpl['gw6'] ?? null), [
            'disabled' => '0', 'name' => $name6, 'descr' => "{$name6} (follows {$name})", 'interface' => $opt, 'ipprotocol' => 'inet6',
            'gateway' => $next6, 'monitor' => '', 'defaultgw' => '0', 'fargw' => '1', 'monitor_disable' => '1', 'force_down' => '1',
        ])];
    }
    if ($tpl !== null) {
        $rules = array_filter($snap['snat_rules'], fn (array $r): bool => $r['interface'] === $tpl['interface'] && $r['enabled'] === '1'
            && ($r['ipprotocol'] === 'inet' || ($ipv6 && $r['ipprotocol'] === 'inet6')));
        uasort($rules, fn (array $a, array $b): int => (int)$a['sequence'] <=> (int)$b['sequence']);
        foreach ($rules as $r) {
            $plan['nat'][] = $r['fields'];
        }
    } else {
        foreach (['inet', 'inet6'] as $family) {
            foreach ($sources[$family] as $source) {
                $plan['nat'][] = [
                    'enabled' => '1', 'ipprotocol' => $family, 'source_net' => $source, 'destination_net' => 'any',
                    'target' => '', 'description' => "{$name}: outbound NAT from {$source}",
                ];
            }
        }
    }

    /* the change list */
    $c = [sprintf(
        'wireguard instance %s: %s, listen port %d, tunnel addresses %s, far gateway %s, mtu %d',
        $name, $device, WGIPV6_PORT_BASE + $n, $plan['instance']['tunneladdress'], $far4, $req['mtu']
    )];
    if ($ipv6) {
        $c[] = $unique
            ? "unique addressing: {$addr6} ({$uniqueWhy}; the provider must accept and translate it)"
            : "IPv6 address from the config: {$addr6} (unique addressing off, {$uniqueWhy})";
    } else {
        $c[] = 'IPv6 off: no IPv6 gateway, IPv4-only allowed IPs';
    }
    $c[] = sprintf('wireguard peer %s -> %s:%s%s', $name, $endpoint, $conf['endpoint_port'], $conf['has_psk'] ? ', with a preshared key' : '');
    $c[] = "interface {$opt} ({$descr}) -> {$device}, enabled";
    foreach ($plan['gateways'] as $g) {
        $c[] = $g['fields']['force_down'] === '1'
            ? "gateway {$g['name']} {$g['fields']['gateway']} on {$opt}, starts forced down (the health mirror releases it)"
            : "gateway {$g['name']} {$g['fields']['gateway']} on {$opt}, monitor {$monitor}";
    }
    $c[] = match ($plan['route']['action']) {
        'add' => "static route {$network} via {$req['wan']}",
        'update' => "static route {$network}: enabled, via {$req['wan']}",
        default => "static route {$network} via {$req['wan']} exists already; kept",
    };
    foreach ($plan['nat'] as $r) {
        $c[] = sprintf(
            'outbound NAT on %s %s from %s to %s%s',
            $opt, $r['ipprotocol'] ?? 'inet', $r['source_net'] ?? 'any',
            ($r['destination_not'] ?? '0') === '1' ? '!' : '', $r['destination_net'] ?? 'any'
        );
    }
    foreach (['inet' => 'IPv4', 'inet6' => 'IPv6'] as $family => $label) {
        $wanted = $family === 'inet' || $ipv6;
        if ($wanted && array_filter($plan['nat'], fn (array $r): bool => ($r['ipprotocol'] ?? 'inet') === $family) === []) {
            $c[] = "WARNING nat-missing: no {$label} outbound NAT; the inner-source block drops everything a LAN sends into this tunnel";
        }
    }
    if (!$snap['wireguard_enabled']) {
        $c[] = 'WARNING WireGuard is disabled (VPN > WireGuard > Settings); the tunnel starts once it is enabled';
    }
    $c[] = 'the plugin manages the new instance';
    $plan['changes'] = $c;
    return $plan;
}

/**
 * Rebind an unbound tunnel (spec 6.2). Pure.
 *
 * @param array  $snap      the action snapshot
 * @param string $uuid      the managed instance
 * @param string $wan       the WAN gateway to bind to
 * @param string $staleUuid a stale-route candidate to delete, or ''
 * @return array see Task 3 Interfaces
 */
function wgipv6_plan_rebind(array $snap, string $uuid, string $wan, string $staleUuid): array {
    $core = $snap['core'];
    $plan = ['errors' => [], 'changes' => [], 'route' => ['action' => 'none', 'uuid' => '', 'fields' => []], 'delete' => null, 'gateways' => []];
    if (!in_array($uuid, $snap['managed'], true)) {
        $plan['errors'][] = 'not a managed tunnel';
        return $plan;
    }
    $t = wgipv6_derive($core, [$uuid])['tunnels'][0];
    if ($t['endpoint_ip'] === null || !in_array('unbound', array_column($t['findings'], 'code'), true)) {
        $plan['errors'][] = ($t['name'] !== '' ? $t['name'] : $uuid) . ' is not unbound; a bound tunnel changes WAN on System > Routes';
        return $plan;
    }
    $wanError = wgipv6_wan_error($core, $wan);
    if ($wanError !== null) {
        $plan['errors'][] = $wanError;
    }
    $stale = wgipv6_stale_candidates($core);
    if ($staleUuid !== '' && !isset($stale[$staleUuid])) {
        $plan['errors'][] = 'the route to delete is not a stale endpoint route';
    }
    $network = $t['endpoint_ip'] . '/32';
    $same = array_filter($core['routes'], fn (array $r): bool => $r['network'] === $network);
    if (count($same) > 1) {
        $plan['errors'][] = "several routes to {$network} exist; keep one on System > Routes first";
    }
    if ($plan['errors'] !== []) {
        return $plan;
    }
    if (count($same) === 1) {
        $plan['route'] = ['action' => 'update', 'uuid' => (string)array_key_first($same), 'fields' => ['gateway' => $wan, 'enabled' => '1']];
        $plan['changes'][] = "static route {$network}: enabled, via {$wan}";
    } else {
        $plan['route'] = ['action' => 'add', 'uuid' => '', 'fields' => [
            'network' => $network, 'gateway' => $wan, 'descr' => 'wireguard - ' . $t['name'], 'enabled' => '1',
        ]];
        $plan['changes'][] = "static route {$network} via {$wan}";
    }
    if ($staleUuid !== '') {
        $plan['delete'] = ['uuid' => $staleUuid, 'network' => $stale[$staleUuid]['ip'] . '/32'];
        $plan['changes'][] = "delete the stale route {$stale[$staleUuid]['ip']}/32 via {$stale[$staleUuid]['gateway']}, and its kernel route";
    }
    $plan['gateways'] = array_values(array_filter([$t['gw4'], $t['gw6']], fn (?string $g): bool => $g !== null));
    return $plan;
}

/**
 * Adopt an existing WireGuard instance (spec 7): add its uuid to the managed list. Pure.
 *
 * @return array{errors: list<string>, changes: list<string>, managed: list<string>}
 */
function wgipv6_plan_adopt(array $snap, string $uuid): array {
    $core = $snap['core'];
    $plan = ['errors' => [], 'changes' => [], 'managed' => $snap['managed']];
    $inst = $core['instances'][$uuid] ?? null;
    if ($inst === null) {
        $plan['errors'][] = 'no WireGuard instance with this uuid';
    } elseif (in_array($uuid, $snap['managed'], true)) {
        $plan['errors'][] = "{$inst['name']} is already managed";
    } else {
        $plan['managed'][] = $uuid;
        $codes = array_column(wgipv6_derive($core, [$uuid])['tunnels'][0]['findings'], 'code');
        $plan['changes'][] = "manage {$inst['name']} (wg{$inst['instance']})";
        $plan['changes'][] = $codes === [] ? 'no findings once managed' : 'findings once managed: ' . implode(', ', $codes);
    }
    return $plan;
}

/**
 * Remove a managed tunnel (spec 6.3), or say why not. Pure.
 *
 * @param array  $snap the action snapshot
 * @param array  $refs wgipv6_refs_snapshot()
 * @param string $uuid the managed instance
 * @return array see Task 3 Interfaces
 */
function wgipv6_plan_remove(array $snap, array $refs, string $uuid): array {
    $core = $snap['core'];
    $plan = [
        'errors' => [], 'changes' => [], 'instance' => null, 'peers' => [], 'opt' => null, 'gateways' => [],
        'gateway_names' => [], 'routes' => [], 'snat' => [], 'managed' => $snap['managed'], 'held' => $snap['held'],
    ];
    if (!in_array($uuid, $snap['managed'], true)) {
        $plan['errors'][] = 'not a managed tunnel; adopt it first, or remove it on VPN > WireGuard';
        return $plan;
    }
    $plan['managed'] = array_values(array_diff($snap['managed'], [$uuid]));
    $inst = $core['instances'][$uuid] ?? null;
    if ($inst === null) {
        $plan['changes'][] = "drop {$uuid} from the managed list (its WireGuard instance is already gone)";
        return $plan;
    }
    $plan['instance'] = $uuid;
    $device = 'wg' . $inst['instance'];

    /* its peers, which must be its alone */
    $otherPeers = [];
    foreach ($core['instances'] as $otherUuid => $other) {
        if ((string)$otherUuid !== $uuid) {
            foreach ($other['peers'] as $peerUuid) {
                $otherPeers[$peerUuid] = $other['name'];
            }
        }
    }
    foreach ($inst['peers'] as $peerUuid) {
        if (isset($otherPeers[$peerUuid])) {
            $plan['errors'][] = sprintf('peer %s is also a peer of instance %s', $core['peers'][$peerUuid]['name'] ?? $peerUuid, $otherPeers[$peerUuid]);
        } elseif (isset($core['peers'][$peerUuid])) {
            $plan['peers'][] = $peerUuid;
        }
    }

    /* its interface, and every gateway and outbound NAT rule on it */
    foreach ($core['interfaces'] as $key => $if) {
        if ($if['if'] === $device) {
            $plan['opt'] = (string)$key;
        }
    }
    $opt = $plan['opt'];
    if ($opt !== null) {
        foreach ($core['gateways'] as $gwName => $g) {
            if ($g['interface'] === $opt) {
                $plan['gateway_names'][] = (string)$gwName;
                $plan['gateways'][] = $g['uuid'];
            }
        }
        foreach ($snap['snat_rules'] as $ruleUuid => $r) {
            if ($r['interface'] === $opt) {
                $plan['snat'][] = (string)$ruleUuid;
            }
        }
    }

    /* its endpoint routes, unless another instance's peer uses the same endpoint */
    $mine = [];
    foreach ($plan['peers'] as $peerUuid) {
        $mine[] = $core['peers'][$peerUuid]['serveraddress'];
    }
    $theirs = [];
    foreach (array_keys($otherPeers) as $peerUuid) {
        if (isset($core['peers'][$peerUuid])) {
            $theirs[] = $core['peers'][$peerUuid]['serveraddress'];
        }
    }
    $kept = [];
    foreach ($core['routes'] as $routeUuid => $r) {
        foreach ($mine as $ip) {
            if ($ip === '' || $r['network'] !== $ip . '/32') {
                continue;
            }
            if (in_array($ip, $theirs, true)) {
                $kept[] = "KEEP static route {$r['network']}: another instance's peer uses {$ip}";
            } else {
                $plan['routes'][(string)$routeUuid] = $r['network'];
            }
        }
    }

    /* nothing else may reference it (spec 6.3) */
    $own = array_merge(
        array_map(fn (int|string $u): string => 'route:' . $u, array_keys($plan['routes'])),
        array_map(fn (string $u): string => 'snat:' . $u, $plan['snat']),
        $opt !== null ? ['if:' . $opt] : []
    );
    $plan['errors'] = array_merge($plan['errors'], wgipv6_remove_refusals($refs, $plan['gateway_names'], $opt ?? '', $own));
    $plan['held'] = array_values(array_diff($snap['held'], $plan['gateways']));

    $c = ["wireguard instance {$inst['name']} ({$device})"];
    foreach ($plan['peers'] as $peerUuid) {
        $c[] = 'wireguard peer ' . $core['peers'][$peerUuid]['name'];
    }
    if ($opt !== null) {
        $c[] = "interface {$opt} ({$core['interfaces'][$opt]['descr']}) and its device";
    }
    foreach ($plan['gateway_names'] as $gwName) {
        $c[] = "gateway {$gwName}";
    }
    foreach ($plan['routes'] as $network) {
        $c[] = "static route {$network}, and its kernel route";
    }
    if ($plan['snat'] !== []) {
        $c[] = count($plan['snat']) . " outbound NAT rule(s) on {$opt}";
    }
    $c[] = 'the plugin stops managing it' . (count($plan['held']) !== count($snap['held']) ? '; its gateways leave the held set' : '');
    $plan['changes'] = array_merge($c, $kept);
    return $plan;
}

/**
 * The no-default sentinel (spec 4.3; port of setup_default_sentinel.php):
 * NO_DEFAULT4/NO_DEFAULT6, address-less gateways at priority 254 on a
 * loopback assigned with "Dynamic gateway policy". Pure.
 *
 * @param array  $interfaces key => ['if', 'descr', 'gateway_interface', 'ipaddr', 'ipaddrv6']
 * @param array  $gateways   name => the sentinel field set (plus 'priority') as strings
 * @param string $device        the sentinel loopback, e.g. lo1
 * @param bool   $loopbackAdded the writer is creating that loopback in this save
 * @return array see Task 3 Interfaces; 'steps' holds only the applies that
 *               match what changed (ruling 19): `interface reconfigure` restarts
 *               DNS and DHCP (interface_configure with $reload), so it runs
 *               only for a new or changed assignment
 */
function wgipv6_plan_sentinel(array $interfaces, array $gateways, string $device, bool $loopbackAdded): array {
    $plan = ['errors' => [], 'changes' => [], 'opt' => '', 'assignment' => 'keep', 'gateways' => [], 'steps' => []];
    $opt = null;
    foreach ($interfaces as $key => $if) {
        if ($if['if'] === $device) {
            $opt = (string)$key;
        }
    }
    if ($opt === null) {
        $opt = wgipv6_pick_opt($interfaces);
        $plan['assignment'] = 'add';
        $plan['changes'][] = "interface {$opt} (" . WGIPV6_SENTINEL_IF_DESCR . ") -> {$device}, dynamic gateway policy";
    } else {
        if ($interfaces[$opt]['gateway_interface'] === '') {
            $plan['assignment'] = 'policy';
            $plan['changes'][] = "interface {$opt}: dynamic gateway policy on";
        }
        foreach (['ipaddr', 'ipaddrv6'] as $field) {
            if ($interfaces[$opt][$field] !== '') {
                $plan['errors'][] = "{$opt} has {$field} set; a sentinel must be address-less";
            }
        }
    }
    $plan['opt'] = $opt;
    foreach ($gateways as $gwName => $g) {
        if (($g['priority'] ?? '') === WGIPV6_SENTINEL_PRIORITY && !in_array((string)$gwName, WGIPV6_SENTINELS, true)) {
            $plan['errors'][] = "gateway {$gwName} already uses priority " . WGIPV6_SENTINEL_PRIORITY . '; only the sentinels may';
        }
    }
    foreach (WGIPV6_SENTINELS as $family => $gwName) {
        $want = [
            'disabled' => '0', 'name' => $gwName, 'descr' => WGIPV6_SENTINEL_GW_DESCR, 'interface' => $opt, 'ipprotocol' => $family,
            'gateway' => '', 'defaultgw' => '0', 'monitor_disable' => '1', 'monitor_killstates' => '0', 'force_down' => '0',
            'priority' => WGIPV6_SENTINEL_PRIORITY,
        ];
        $have = $gateways[$gwName] ?? null;
        if ($have === null) {
            $plan['gateways'][$gwName] = ['action' => 'add', 'set' => $want];
            $plan['changes'][] = "gateway {$gwName} ({$family}, priority " . WGIPV6_SENTINEL_PRIORITY . ", no address) on {$opt}";
            continue;
        }
        $set = [];
        foreach ($want as $field => $value) {
            $old = (string)($have[$field] ?? '');
            if ($old !== $value) {
                $set[$field] = $value;
                $plan['changes'][] = sprintf('gateway %s: %s %s -> %s', $gwName, $field, $old === '' ? '(empty)' : $old, $value === '' ? '(empty)' : $value);
            }
        }
        $plan['gateways'][$gwName] = ['action' => $set === [] ? 'keep' : 'update', 'set' => $set];
    }

    /* the applies that match what changed; a description is cosmetic and needs none */
    $routing = false;
    foreach ($plan['gateways'] as $g) {
        if ($g['action'] === 'add' || array_diff(array_keys($g['set']), ['descr']) !== []) {
            $routing = true;
        }
    }
    if ($loopbackAdded) {
        $plan['steps'][] = ['interface loopback configure', []];
    }
    if ($plan['assignment'] !== 'keep') {
        $plan['steps'][] = ['interface reconfigure', [$opt]];
    }
    if ($routing) {
        $plan['steps'][] = ['interface routes configure', []];   // ends with filter_configure_sync (facts C.6)
    }
    return $plan;
}

/**
 * A synthetic action snapshot: three managed tunnels on wg1/wg2/wg4, an
 * unmanaged site-to-site instance on wg7, two WANs, the sentinels, and a
 * template NAT set whose sequence order differs from its config order.
 * Documentation addresses only.
 *
 * @return array the wgipv6_action_snapshot() shape
 */
function wgipv6_actions_fixture(): array {
    $gw = fn (string $uuid, string $if, string $family, string $address, string $monitor = ''): array => [
        'uuid' => $uuid, 'interface' => $if, 'ipprotocol' => $family, 'gateway' => $address, 'monitor' => $monitor,
        'disabled' => false, 'force_down' => false, 'losshigh' => '20', 'losslow' => '10', 'time_period' => '80',
    ];
    $if = fn (string $device, string $descr): array => ['if' => $device, 'enable' => true, 'mtu' => '', 'mss' => '', 'descr' => $descr];
    $rule = fn (string $iface, string $family, string $seq, string $source, string $dst = 'any', string $not = '0', string $descr = '', string $enabled = '1'): array => [
        'interface' => $iface, 'ipprotocol' => $family, 'enabled' => $enabled, 'sequence' => $seq,
        'fields' => [
            'enabled' => $enabled, 'nonat' => '0', 'ipprotocol' => $family, 'protocol' => 'any', 'source_net' => $source,
            'source_not' => '0', 'destination_net' => $dst, 'destination_not' => $not, 'target' => '', 'description' => $descr,
        ],
    ];
    $thresholds = fn (array $o): array => array_merge(array_fill_keys(WGIPV6_GATEWAY_COPY_FIELDS, ''), $o);
    $snat = [
        's-a1' => $rule('opt11', 'inet', '20', 'opt3'),
        's-a2' => $rule('opt11', 'inet', '10', 'TailscaleNetworks', 'LocalNetworks', '1', 'tailnet via tunnel'),
        's-a3' => $rule('opt11', 'inet6', '30', 'opt3', 'any', '0', 'IPv6 via tunnel'),
        's-a4' => $rule('opt11', 'inet', '40', 'lan', 'any', '0', 'disabled rule', '0'),
        's-b1' => $rule('opt12', 'inet', '50', 'opt3'),
        's-d1' => $rule('opt14', 'inet', '60', 'opt3'),
    ];
    $core = [
        'instances' => [
            'i-a' => ['name' => 'tun_a', 'enabled' => true, 'instance' => '1', 'mtu' => '1420', 'tunneladdress' => ['10.2.0.2/32', 'fd00::1:1/128'], 'peers' => ['p-a']],
            'i-b' => ['name' => 'tun_b', 'enabled' => true, 'instance' => '2', 'mtu' => '1420', 'tunneladdress' => ['10.2.0.2/32'], 'peers' => ['p-b']],
            'i-d' => ['name' => 'tun_d', 'enabled' => true, 'instance' => '4', 'mtu' => '1376', 'tunneladdress' => ['10.2.0.2/32'], 'peers' => ['p-d']],
            'i-x' => ['name' => 'site_x', 'enabled' => true, 'instance' => '7', 'mtu' => '', 'tunneladdress' => ['192.0.2.33/32'], 'peers' => ['p-x']],
        ],
        'peers' => [
            'p-a' => ['name' => 'tun_a', 'serveraddress' => '198.51.100.10', 'serverport' => '51820'],
            'p-b' => ['name' => 'tun_b', 'serveraddress' => '198.51.100.11', 'serverport' => '51820'],
            'p-d' => ['name' => 'tun_d', 'serveraddress' => '198.51.100.13', 'serverport' => '51820'],
            'p-x' => ['name' => 'site_x', 'serveraddress' => '203.0.113.200', 'serverport' => '51820'],
        ],
        'interfaces' => [
            'wan' => $if('igc0', 'WAN'), 'lan' => $if('igc1', 'LAN'), 'opt1' => $if('igc2', 'WANA'), 'opt2' => $if('igc3', 'WANB'),
            'opt3' => $if('vlan0.3', 'LANA'), 'opt10' => $if('lo1', 'NODEFAULT'),
            'opt11' => $if('wg1', 'tuna'), 'opt12' => $if('wg2', 'tunb'), 'opt14' => $if('wg4', 'tund'),
            /* a virtual entry, as core keeps for the WireGuard interface group: never a NAT source */
            'wireguard' => $if('', 'WireGuard'),
        ],
        'routes' => [
            'r-a' => ['network' => '198.51.100.10/32', 'gateway' => 'WAN_A', 'enabled' => true],
            'r-b' => ['network' => '198.51.100.11/32', 'gateway' => 'WAN_B', 'enabled' => true],
            'r-d' => ['network' => '198.51.100.13/32', 'gateway' => 'WAN_A', 'enabled' => true],
        ],
        'gateways' => [
            'WAN_A' => $gw('g-wa', 'opt1', 'inet', '192.0.2.1'),
            'WAN_B' => $gw('g-wb', 'opt2', 'inet', '198.51.100.1'),
            'tun_a' => $gw('g-a4', 'opt11', 'inet', '10.2.0.4', '203.0.113.9'),
            'tun_a-ipv6' => $gw('g-a6', 'opt11', 'inet6', 'fd00::1:2'),
            'tun_b' => $gw('g-b4', 'opt12', 'inet', '10.2.0.5', '203.0.113.10'),
            'tun_d' => $gw('g-d4', 'opt14', 'inet', '10.2.0.7', '203.0.113.11'),
            'NO_DEFAULT4' => $gw('g-n4', 'opt10', 'inet', ''),
            'NO_DEFAULT6' => $gw('g-n6', 'opt10', 'inet6', ''),
        ],
        'snat' => [],
        'groups' => ['grp_a' => ['tun_a', 'tun_b']],
        'dns_servers' => ['203.0.113.53'],
        'forwarders' => ['203.0.113.54'],
    ];
    foreach ($snat as $r) {
        if ($r['enabled'] === '1') {
            $core['snat'][] = ['interface' => $r['interface'], 'ipprotocol' => $r['ipprotocol'], 'source' => $r['fields']['source_net']];
        }
    }
    return [
        'core' => $core,
        'managed' => ['i-a', 'i-b', 'i-d'],
        'held' => ['g-d4'],
        'ports' => ['i-a' => '51821', 'i-b' => '51822', 'i-d' => '51824', 'i-x' => '51827'],
        'gateway_fields' => [
            'tun_a' => $thresholds(['monitor_killstates' => '1', 'priority' => '255', 'weight' => '1', 'latencylow' => '900',
                                    'latencyhigh' => '1600', 'losslow' => '10', 'losshigh' => '20', 'time_period' => '80']),
            'tun_a-ipv6' => $thresholds(['monitor_killstates' => '1', 'losslow' => '10', 'losshigh' => '20', 'time_period' => '80']),
        ],
        'snat_rules' => $snat,
        'aliases' => ['TailscaleNetworks', 'LocalNetworks'],
        'ifgroup_names' => ['LANGRP'],
        'wireguard_enabled' => true,
    ];
}

/**
 * Self-tests for the planners. Pure.
 *
 * @return int exit code, 0 when every case passes
 */
function wgipv6_actions_selftest(): int {
    $t = ['fail' => 0, 'total' => 0];
    $snap = wgipv6_actions_fixture();
    $req = ['name' => 'tun_c', 'wan' => 'WAN_A', 'monitor' => '203.0.113.12', 'ipv6' => true, 'unique' => null, 'mtu' => 1376,
            'template' => 'i-a', 'nat' => ['inet' => [], 'inet6' => []]];
    $conf = ['addresses' => ['inet' => ['10.2.0.2/32'], 'inet6' => ['fd00::1:1/128']], 'peer_pubkey' => base64_encode(str_repeat('B', 32)),
             'endpoint_ip' => '198.51.100.12', 'endpoint_port' => '51820', 'has_psk' => false];
    $has = fn (array $lines, string $needle): bool => array_filter($lines, fn (string $l): bool => strpos($l, $needle) !== false) !== [];
    $err = fn (array $plan, string $field): bool => isset($plan['errors'][$field]);
    $gwRow = fn (string $address): array => ['uuid' => 'g-o', 'interface' => 'opt2', 'ipprotocol' => 'inet', 'gateway' => $address, 'monitor' => '',
                                            'disabled' => false, 'force_down' => false, 'losshigh' => '', 'losslow' => '', 'time_period' => ''];

    /* ---- create ---- */
    $p = wgipv6_plan_create($snap, $req, $conf);
    wgipv6_check($t, 'create: template, config IPv6 shared with a managed tunnel => wg3 on opt4, unique addressing on',
        $p['errors'] === [] && $p['n'] === 3 && $p['device'] === 'wg3' && $p['opt'] === 'opt4' && $p['descr'] === 'tunc' && $p['unique'] === true
        && $p['instance']['tunneladdress'] === '10.2.0.2/32,fd00::3:1/128' && $p['instance']['gateway'] === '10.2.0.6'
        && $p['instance']['port'] === '51823' && $p['instance']['mtu'] === '1376' && $p['instance']['disableroutes'] === '1'
        && !isset($p['instance']['privkey']));
    wgipv6_check($t, 'create: the peer allows both families, keepalive 25, no key material but the peer public key',
        $p['peer']['tunneladdress'] === '0.0.0.0/0,::/0' && $p['peer']['keepalive'] === '25' && $p['peer']['serveraddress'] === '198.51.100.12'
        && $p['peer']['serverport'] === '51820' && !isset($p['peer']['psk']));
    $g4 = $p['gateways'][0]['fields'] ?? [];
    $g6 = $p['gateways'][1]['fields'] ?? [];
    wgipv6_check($t, 'create: gateways take the template thresholds and the spec behaviour fields',
        count($p['gateways']) === 2 && $p['gateways'][0]['name'] === 'tun_c' && $p['gateways'][1]['name'] === 'tun_c-ipv6'
        && $g4['gateway'] === '10.2.0.6' && $g4['interface'] === 'opt4' && $g4['monitor'] === '203.0.113.12' && $g4['latencylow'] === '900'
        && $g4['fargw'] === '1' && $g4['monitor_disable'] === '0' && $g4['force_down'] === '0' && $g4['defaultgw'] === '0'
        && $g6['gateway'] === 'fd00::3:2' && $g6['ipprotocol'] === 'inet6' && $g6['fargw'] === '1' && $g6['monitor_disable'] === '1'
        && $g6['force_down'] === '1' && $g6['losshigh'] === '20');
    wgipv6_check($t, 'create: the endpoint route is added via the bound WAN',
        $p['route'] === ['action' => 'add', 'uuid' => '', 'fields' => ['network' => '198.51.100.12/32', 'gateway' => 'WAN_A', 'descr' => 'wireguard - tun_c', 'enabled' => '1']]);
    wgipv6_check($t, 'create: template NAT copied whole (destination and description kept), enabled rules only, in sequence order',
        count($p['nat']) === 3 && $p['nat'][0]['source_net'] === 'TailscaleNetworks' && $p['nat'][0]['destination_net'] === 'LocalNetworks'
        && $p['nat'][0]['destination_not'] === '1' && $p['nat'][0]['description'] === 'tailnet via tunnel'
        && $p['nat'][1]['source_net'] === 'opt3' && $p['nat'][2]['ipprotocol'] === 'inet6'
        && !isset($p['nat'][0]['interface']) && !isset($p['nat'][0]['sequence']));
    wgipv6_check($t, 'create: the change list names unique addressing and raises no NAT warning',
        $has($p['changes'], 'unique addressing: fd00::3:1/128') && !$has($p['changes'], 'nat-missing'));

    /* unique addressing default (ruling 3): the fixture's tun_a is fd00::1:1 on wg1, so the convention is in use */
    $c = $conf;
    $c['addresses']['inet6'] = ['2001:db8::2:2/128'];
    $p = wgipv6_plan_create($snap, $req, $c);
    wgipv6_check($t, 'create: unshared config address, managed tunnels use fd00::N:1 => unique addressing on by default',
        $p['errors'] === [] && $p['unique'] === true && $p['instance']['tunneladdress'] === '10.2.0.2/32,fd00::3:1/128'
        && $has($p['changes'], 'the managed tunnels use the fd00::N:1 convention'));
    $noConvention = $snap;
    $noConvention['core']['instances']['i-a']['tunneladdress'] = ['10.2.0.2/32', '2001:db8:a::1/128'];
    $noConvention['core']['gateways']['tun_a-ipv6']['gateway'] = '2001:db8:a::2';
    $p = wgipv6_plan_create($noConvention, $req, $c);
    wgipv6_check($t, 'create: no convention in use, config address on no instance => off, the config address is used, next hop still fd00::3:2',
        $p['errors'] === [] && $p['unique'] === false && $p['instance']['tunneladdress'] === '10.2.0.2/32,2001:db8::2:2/128'
        && $p['gateways'][1]['fields']['gateway'] === 'fd00::3:2');
    $s = $noConvention;
    $s['core']['instances']['i-x']['tunneladdress'][] = '2001:DB8:0::2:2/128';
    $p = wgipv6_plan_create($s, $req, $c);
    wgipv6_check($t, 'create: config address already on an unmanaged instance (other spelling) => on by default',
        $p['errors'] === [] && $p['unique'] === true && $has($p['changes'], '2001:db8::2:2/128 is already on instance site_x'));
    $p = wgipv6_plan_create($snap, ['unique' => false] + $req, $c);
    wgipv6_check($t, 'create: convention in use but unique addressing explicitly off => allowed, the config address is used',
        $p['errors'] === [] && $p['unique'] === false && $p['instance']['tunneladdress'] === '10.2.0.2/32,2001:db8::2:2/128');

    $p = wgipv6_plan_create($snap, ['unique' => false] + $req, $conf);
    wgipv6_check($t, 'create: unique addressing off with an address already on an instance => refused', $err($p, 'unique'));

    /* a config without IPv6 (ruling 4) */
    $c = $conf;
    $c['addresses']['inet6'] = [];
    wgipv6_check($t, 'create: IPv6 requested but the config has no IPv6 address => refused on ipv6',
        $err(wgipv6_plan_create($snap, $req, $c), 'ipv6'));
    $p = wgipv6_plan_create($snap, ['ipv6' => null] + $req, $c);
    wgipv6_check($t, 'create: IPv6 unset and no IPv6 address in the config => IPv6 off, one gateway, IPv4-only peer',
        $p['errors'] === [] && $p['ipv6'] === false && count($p['gateways']) === 1 && $p['peer']['tunneladdress'] === '0.0.0.0/0'
        && $p['instance']['tunneladdress'] === '10.2.0.2/32');

    $p = wgipv6_plan_create($snap, ['ipv6' => false] + $req, $conf);
    wgipv6_check($t, 'create: IPv6 off => one gateway, IPv4-only peer and address, IPv4 NAT only',
        $p['errors'] === [] && count($p['gateways']) === 1 && $p['peer']['tunneladdress'] === '0.0.0.0/0'
        && $p['instance']['tunneladdress'] === '10.2.0.2/32' && count($p['nat']) === 2);

    $s = $snap;
    $s['ports']['i-x'] = '51823';
    wgipv6_check($t, 'create: listen port 51823 taken by another instance => N skips to 5', wgipv6_plan_create($s, $req, $conf)['n'] === 5);
    $s = $snap;
    $s['core']['gateways']['other'] = $gwRow('10.2.0.6');
    wgipv6_check($t, 'create: far gateway 10.2.0.6 taken by a gateway => N skips to 5', wgipv6_plan_create($s, $req, $conf)['n'] === 5);
    $s = $snap;
    $s['core']['instances']['i-x']['tunneladdress'] = ['10.2.0.6/32'];
    wgipv6_check($t, 'create: 10.2.0.6 is another instance\'s tunnel address => N skips to 5', wgipv6_plan_create($s, $req, $conf)['n'] === 5);
    $s = $snap;
    foreach (range(1, WGIPV6_INSTANCE_MAX) as $n) {
        $s['core']['instances']["f-{$n}"] = ['name' => "f{$n}", 'enabled' => false, 'instance' => (string)$n, 'mtu' => '', 'tunneladdress' => [], 'peers' => []];
    }
    wgipv6_check($t, 'create: every instance number 1..251 used => refused', $err(wgipv6_plan_create($s, $req, $conf), 'general'));

    foreach ([
        ['a gateway named tun_a exists', ['name' => 'tun_a'], 'name'],
        ['description LANA is an interface description', ['name' => 'LAN-A'], 'name'],
        ['description of digits only', ['name' => '1-2'], 'name'],
        ['WAN on a WireGuard interface', ['wan' => 'tun_a'], 'wan'],
        ['WAN is a sentinel', ['wan' => 'NO_DEFAULT4'], 'wan'],
        ['WAN does not exist', ['wan' => 'NOPE'], 'wan'],
        ['monitor is another gateway\'s monitor', ['monitor' => '203.0.113.9'], 'monitor'],
        ['monitor is a DNS server', ['monitor' => '203.0.113.53'], 'monitor'],
        ['monitor is the endpoint', ['monitor' => '198.51.100.12'], 'monitor'],
        ['template is not managed', ['template' => 'i-x'], 'template'],
    ] as [$desc, $over, $field]) {
        wgipv6_check($t, "create: {$desc} => {$field} refused", $err(wgipv6_plan_create($snap, $over + $req, $conf), $field));
    }

    $c = $conf;
    $c['endpoint_ip'] = '198.51.100.11';
    wgipv6_check($t, 'create: endpoint already routed via another WAN => wan refused', $err(wgipv6_plan_create($snap, $req, $c), 'wan'));
    $c['endpoint_ip'] = '198.51.100.13';
    $p = wgipv6_plan_create($snap, $req, $c);
    wgipv6_check($t, 'create: endpoint already routed via the same WAN => the route is kept, not duplicated',
        $p['errors'] === [] && $p['route'] === ['action' => 'keep', 'uuid' => 'r-d', 'fields' => []]);
    $s = $snap;
    $s['core']['routes']['r-z'] = ['network' => '198.51.100.12/32', 'gateway' => 'WAN_B', 'enabled' => false];
    $p = wgipv6_plan_create($s, $req, $conf);
    wgipv6_check($t, 'create: a disabled route to the endpoint => enabled and re-pointed',
        $p['route'] === ['action' => 'update', 'uuid' => 'r-z', 'fields' => ['gateway' => 'WAN_A', 'enabled' => '1']]);

    $noTpl = ['template' => '', 'nat' => ['inet' => ['opt3', 'TailscaleNetworks'], 'inet6' => ['opt3']]] + $req;
    $p = wgipv6_plan_create($snap, $noTpl, $conf);
    wgipv6_check($t, 'create: no template => one NAT rule per source and family, destination any, target the interface address',
        $p['errors'] === [] && count($p['nat']) === 3
        && $p['nat'][0] === ['enabled' => '1', 'ipprotocol' => 'inet', 'source_net' => 'opt3', 'destination_net' => 'any', 'target' => '', 'description' => 'tun_c: outbound NAT from opt3']
        && $p['nat'][2]['ipprotocol'] === 'inet6');
    wgipv6_check($t, 'create: no template => gateways get the spec behaviour fields and core\'s default thresholds',
        $p['gateways'][0]['fields']['fargw'] === '1' && $p['gateways'][0]['fields']['monitor_disable'] === '0'
        && !isset($p['gateways'][0]['fields']['latencylow']));
    $p = wgipv6_plan_create($snap, ['nat' => ['inet' => [], 'inet6' => []]] + $noTpl, $conf);
    wgipv6_check($t, 'create: no template, no NAT sources => allowed, with nat-missing warnings for both families',
        $p['errors'] === [] && $has($p['changes'], 'WARNING nat-missing: no IPv4') && $has($p['changes'], 'WARNING nat-missing: no IPv6'));
    wgipv6_check($t, 'create: an unknown NAT source => nat4 refused',
        $err(wgipv6_plan_create($snap, ['nat' => ['inet' => ['bogus'], 'inet6' => []]] + $noTpl, $conf), 'nat4'));
    wgipv6_check($t, 'create: a virtual interface key (wireguard group) is not a NAT source => nat4 refused',
        $err(wgipv6_plan_create($snap, ['nat' => ['inet' => ['wireguard'], 'inet6' => []]] + $noTpl, $conf), 'nat4'));
    $p = wgipv6_plan_create($snap, ['ipv6' => false] + $noTpl, $conf);
    wgipv6_check($t, 'create: IPv6 off ignores the IPv6 NAT sources', $p['errors'] === [] && count($p['nat']) === 2);
    $s = $snap;
    $s['wireguard_enabled'] = false;
    wgipv6_check($t, 'create: WireGuard disabled => a warning, not a refusal',
        $has(wgipv6_plan_create($s, $req, $conf)['changes'], 'WARNING WireGuard is disabled'));

    /* ---- rebind ---- */
    $moved = $snap;
    $moved['core']['peers']['p-a']['serveraddress'] = '198.51.100.20';
    $p = wgipv6_plan_rebind($moved, 'i-a', 'WAN_B', 'r-a');
    wgipv6_check($t, 'rebind: unbound tunnel => route to the new endpoint, the stale route deleted with its kernel route',
        $p['errors'] === [] && $p['route']['action'] === 'add' && $p['route']['fields']['network'] === '198.51.100.20/32'
        && $p['route']['fields']['gateway'] === 'WAN_B' && $p['delete'] === ['uuid' => 'r-a', 'network' => '198.51.100.10/32']
        && $p['gateways'] === ['tun_a', 'tun_a-ipv6']);
    wgipv6_check($t, 'rebind: no stale route chosen => nothing deleted', wgipv6_plan_rebind($moved, 'i-a', 'WAN_B', '')['delete'] === null);
    wgipv6_check($t, 'rebind: a live binding route is not a stale candidate => refused', wgipv6_plan_rebind($moved, 'i-a', 'WAN_B', 'r-b')['errors'] !== []);
    wgipv6_check($t, 'rebind: a bound tunnel => refused', wgipv6_plan_rebind($snap, 'i-a', 'WAN_B', '')['errors'] !== []);
    $s = $moved;
    $s['core']['routes']['r-z'] = ['network' => '198.51.100.20/32', 'gateway' => 'WAN_A', 'enabled' => false];
    wgipv6_check($t, 'rebind: a disabled route to the endpoint => updated in place',
        wgipv6_plan_rebind($s, 'i-a', 'WAN_B', '')['route'] === ['action' => 'update', 'uuid' => 'r-z', 'fields' => ['gateway' => 'WAN_B', 'enabled' => '1']]);
    wgipv6_check($t, 'rebind: WAN on a WireGuard interface => refused', wgipv6_plan_rebind($moved, 'i-a', 'tun_b', '')['errors'] !== []);
    wgipv6_check($t, 'rebind: an unmanaged instance => refused', wgipv6_plan_rebind($moved, 'i-x', 'WAN_B', '')['errors'] !== []);
    $s = $snap;
    $s['core']['routes']['r-w'] = ['network' => '198.51.100.99/32', 'gateway' => 'tun_a', 'enabled' => true];
    wgipv6_check($t, 'binding: enabled /32 routes via a non-WireGuard gateway only', array_keys(wgipv6_binding_routes($s['core'])) === ['r-a', 'r-b', 'r-d']);
    wgipv6_check($t, 'binding: the stale candidate is the route to the old endpoint',
        wgipv6_stale_candidates($moved['core']) === ['r-a' => ['ip' => '198.51.100.10', 'gateway' => 'WAN_A']]);
    $s = $moved;
    $s['core']['routes']['r-a2'] = ['network' => '198.51.100.10/32', 'gateway' => 'WAN_B', 'enabled' => true];
    $stale = array_values(array_filter(
        wgipv6_derive($s['core'], ['i-a'])['tunnels'][0]['findings'],
        fn (array $f): bool => $f['code'] === 'stale-route'
    ));
    wgipv6_check($t, 'binding: two routes to one stale IP => one stale-route entry, the last route winning (text as before the refactor)',
        count($stale) === 1 && $stale[0]['detail'] === '198.51.100.10/32 via WAN_B');

    /* ---- adopt ---- */
    $p = wgipv6_plan_adopt($snap, 'i-x');
    wgipv6_check($t, 'adopt: an unmanaged instance joins the managed list; its findings are previewed',
        $p['errors'] === [] && $p['managed'] === ['i-a', 'i-b', 'i-d', 'i-x'] && $p['changes'][0] === 'manage site_x (wg7)'
        && $has($p['changes'], 'findings once managed'));
    wgipv6_check($t, 'adopt: already managed => refused', wgipv6_plan_adopt($snap, 'i-a')['errors'] !== []);
    wgipv6_check($t, 'adopt: no such instance => refused', wgipv6_plan_adopt($snap, 'i-nope')['errors'] !== []);

    /* ---- remove ---- */
    $group = [['id' => 'group:grp_a', 'what' => 'gateway group grp_a', 'gateways' => ['tun_a', 'tun_b'], 'interfaces' => []]];
    wgipv6_check($t, 'remove: a gateway group lists it => refused, and the refusal says why',
        wgipv6_plan_remove($snap, $group, 'i-a')['errors'] === ['gateway group grp_a uses gateway tun_a']);
    $p = wgipv6_plan_remove($snap, [], 'i-d');
    wgipv6_check($t, 'remove: an unreferenced tunnel => peer, instance, interface, its gateways, endpoint route, NAT, managed and held entries',
        $p['errors'] === [] && $p['instance'] === 'i-d' && $p['peers'] === ['p-d'] && $p['opt'] === 'opt14'
        && $p['gateways'] === ['g-d4'] && $p['gateway_names'] === ['tun_d'] && $p['routes'] === ['r-d' => '198.51.100.13/32']
        && $p['snat'] === ['s-d1'] && $p['managed'] === ['i-a', 'i-b'] && $p['held'] === []);
    $s = $snap;
    $s['core']['peers']['p-x']['serveraddress'] = '198.51.100.13';
    $p = wgipv6_plan_remove($s, [], 'i-d');
    wgipv6_check($t, 'remove: another instance\'s peer uses the same endpoint => the route is kept',
        $p['errors'] === [] && $p['routes'] === [] && $has($p['changes'], 'KEEP static route 198.51.100.13/32'));
    $s = $snap;
    $s['core']['instances']['i-x']['peers'] = ['p-x', 'p-d'];
    wgipv6_check($t, 'remove: its peer is also another instance\'s peer => refused',
        in_array('peer tun_d is also a peer of instance site_x', wgipv6_plan_remove($s, [], 'i-d')['errors'], true));
    $s = $snap;
    $s['managed'][] = 'i-gone';
    $p = wgipv6_plan_remove($s, [], 'i-gone');
    wgipv6_check($t, 'remove: instance already deleted => only the managed entry goes',
        $p['errors'] === [] && $p['instance'] === null && $p['managed'] === ['i-a', 'i-b', 'i-d']);
    wgipv6_check($t, 'remove: an unmanaged instance => refused', wgipv6_plan_remove($snap, [], 'i-x')['errors'] !== []);
    $ownRefs = [
        ['id' => 'snat:s-d1', 'what' => 'outbound NAT rule', 'gateways' => [], 'interfaces' => ['opt14']],
        ['id' => 'route:r-d', 'what' => 'static route', 'gateways' => ['WAN_A'], 'interfaces' => []],
        ['id' => 'if:opt14', 'what' => 'interface opt14', 'gateways' => ['tun_d'], 'interfaces' => []],
    ];
    wgipv6_check($t, 'remove: its own NAT rule, endpoint route and interface do not refuse it', wgipv6_plan_remove($snap, $ownRefs, 'i-d')['errors'] === []);

    /* ---- sentinel ---- */
    $want = fn (string $family, string $name, string $opt): array => [
        'disabled' => '0', 'name' => $name, 'descr' => WGIPV6_SENTINEL_GW_DESCR, 'interface' => $opt, 'ipprotocol' => $family,
        'gateway' => '', 'defaultgw' => '0', 'monitor_disable' => '1', 'monitor_killstates' => '0', 'force_down' => '0', 'priority' => '254',
    ];
    $ifs = [
        'wan' => ['if' => 'igc0', 'descr' => 'WAN', 'gateway_interface' => '', 'ipaddr' => 'dhcp', 'ipaddrv6' => ''],
        'opt1' => ['if' => 'igc1', 'descr' => 'LANA', 'gateway_interface' => '', 'ipaddr' => '192.0.2.1', 'ipaddrv6' => ''],
    ];
    $gws = ['WAN_A' => ['disabled' => '0', 'name' => 'WAN_A', 'descr' => '', 'interface' => 'wan', 'ipprotocol' => 'inet', 'gateway' => '198.51.100.1',
                        'defaultgw' => '1', 'monitor_disable' => '0', 'monitor_killstates' => '0', 'force_down' => '0', 'priority' => '255']];
    $p = wgipv6_plan_sentinel($ifs, $gws, 'lo1', true);
    wgipv6_check($t, 'sentinel: blank slate => lo1 assigned on opt2 with dynamic gateway policy, both sentinels added',
        $p['errors'] === [] && $p['assignment'] === 'add' && $p['opt'] === 'opt2'
        && $p['gateways']['NO_DEFAULT4'] === ['action' => 'add', 'set' => $want('inet', 'NO_DEFAULT4', 'opt2')]
        && $p['gateways']['NO_DEFAULT6'] === ['action' => 'add', 'set' => $want('inet6', 'NO_DEFAULT6', 'opt2')]);
    wgipv6_check($t, 'sentinel: blank slate => loopback, interface and routing applies, in that order',
        $p['steps'] === [['interface loopback configure', []], ['interface reconfigure', ['opt2']], ['interface routes configure', []]]);
    $ifs2 = $ifs + ['opt10' => ['if' => 'lo1', 'descr' => 'NODEFAULT', 'gateway_interface' => '1', 'ipaddr' => '', 'ipaddrv6' => '']];
    $gws2 = $gws + ['NO_DEFAULT4' => $want('inet', 'NO_DEFAULT4', 'opt10'), 'NO_DEFAULT6' => $want('inet6', 'NO_DEFAULT6', 'opt10')];
    $p = wgipv6_plan_sentinel($ifs2, $gws2, 'lo1', false);
    wgipv6_check($t, 'sentinel: already right => nothing to change, nothing to apply',
        $p['errors'] === [] && $p['changes'] === [] && $p['steps'] === [] && $p['assignment'] === 'keep' && $p['opt'] === 'opt10'
        && $p['gateways']['NO_DEFAULT4']['action'] === 'keep' && $p['gateways']['NO_DEFAULT6']['action'] === 'keep');
    $x = $ifs2;
    $x['opt10']['gateway_interface'] = '';
    $p = wgipv6_plan_sentinel($x, $gws2, 'lo1', false);
    wgipv6_check($t, 'sentinel: dynamic gateway policy missing => set', $p['assignment'] === 'policy');
    wgipv6_check($t, 'sentinel: policy only => the interface apply alone', $p['steps'] === [['interface reconfigure', ['opt10']]]);
    $x = $ifs2;
    $x['opt10']['ipaddr'] = '192.0.2.9';
    wgipv6_check($t, 'sentinel: the loopback has an address => refused', wgipv6_plan_sentinel($x, $gws2, 'lo1', false)['errors'] !== []);
    $y = $gws2;
    $y['WAN_A']['priority'] = '254';
    wgipv6_check($t, 'sentinel: another gateway uses priority 254 => refused',
        in_array('gateway WAN_A already uses priority 254; only the sentinels may', wgipv6_plan_sentinel($ifs2, $y, 'lo1', false)['errors'], true));
    $y = $gws2;
    $y['NO_DEFAULT6']['descr'] = 'old';
    $p = wgipv6_plan_sentinel($ifs2, $y, 'lo1', false);
    wgipv6_check($t, 'sentinel: a drifted field => updated alone',
        $p['gateways']['NO_DEFAULT6'] === ['action' => 'update', 'set' => ['descr' => WGIPV6_SENTINEL_GW_DESCR]]);
    wgipv6_check($t, 'sentinel: a description-only drift => saved with no apply at all (never an interface reconfigure)', $p['steps'] === []);
    $y = $gws2;
    $y['NO_DEFAULT4']['monitor_disable'] = '0';
    wgipv6_check($t, 'sentinel: a routing field drifted => the routing apply alone',
        wgipv6_plan_sentinel($ifs2, $y, 'lo1', false)['steps'] === [['interface routes configure', []]]);

    return wgipv6_tally_report('actions', $t);
}
