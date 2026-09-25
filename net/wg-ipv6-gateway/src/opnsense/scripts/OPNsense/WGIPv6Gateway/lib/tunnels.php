<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Tunnel derivation (spec 2026-09-24 section 3). Core config is the only
 * source of truth: a managed tunnel is assembled from its WireGuard instance
 * and peer, the interface assignment of its device, the /32 route to its
 * endpoint, the gateways on its interface, outbound NAT and the gateway
 * groups, every time it is needed. The plugin stores only which instances it
 * manages. wgipv6_core_snapshot() reads config through models; every other
 * function here is pure over that snapshot.
 */

use OPNsense\Core\Config;

/* WireGuard's MTU when neither the instance nor the interface sets one. */
const WGIPV6_DEFAULT_MTU = 1420;

/* finding code => [blocking, where it is fixed] (spec section 3.4) */
const WGIPV6_FINDINGS = [
    'instance-missing' => [true, 'the managed WireGuard instance was deleted; recreating it, or removing the tunnel with the tunnel removal script, clears this'],
    'not-assigned' => [true, 'Interfaces > Assignments: assign the wgN device'],
    'interface-disabled' => [true, "Interfaces > the tunnel's interface: enable it"],
    'not-single-peer' => [true, 'VPN > WireGuard > Instances: exactly one peer'],
    'endpoint-unsupported' => [true, 'VPN > WireGuard > Peers: an IPv4 endpoint address'],
    'ambiguous-gateway' => [true, 'System > Gateways: one gateway per family on the tunnel interface'],
    'unbound' => [false, 'System > Routes: a /32 route to the endpoint via its WAN gateway'],
    'stale-route' => [false, 'System > Routes: re-point or remove the old endpoint route'],
    'wan-unavailable' => [false, 'System > Gateways / Interfaces: enable the bound WAN'],
    'ipv6-incomplete' => [false, 'Instances and System > Gateways: IPv6 tunnel address and IPv6 gateway together'],
    'mtu-override' => [false, 'Interfaces > wgN: clear MTU or match the instance MTU'],
    'mtu-too-small' => [false, "VPN > WireGuard > Instances (or Interfaces > the tunnel's interface): the MTU is too small to clamp TCP MSS; set it to at least 1280"],
    'legacy-mss' => [false, "Interfaces > the tunnel's interface: an MSS value is set by hand"],
    'nat-missing' => [false, 'Firewall > NAT > Source NAT: rules on the tunnel interface'],
    'monitor-shared' => [false, 'System > Gateways: a monitor IP nothing else uses'],
    'sentinel-missing' => [false, 'System > Gateways: the NO_DEFAULT4 and NO_DEFAULT6 gateways are missing (setup_default_sentinel.php creates them)'],
    'render-failed' => [false, 'Firewall > Log Files > General: the plugin could not build its firewall rules at the last reload; they are missing until the next reload succeeds'],
];

/* the priority reserved for the WAN pin and inner-source block rules */
const WGIPV6_PIN_PRIORITY = 100000;

/* the pf anchor name for the MSS clamp lines */
const WGIPV6_MSS_ANCHOR = 'wgipv6gateway_mss';

/**
 * @param string $code   key of WGIPV6_FINDINGS
 * @param string $detail what was found
 * @return array ['code', 'blocking', 'detail', 'fix']
 */
function wgipv6_finding($code, $detail) {
    [$blocking, $fix] = WGIPV6_FINDINGS[$code];
    return ['code' => $code, 'blocking' => $blocking, 'detail' => $detail, 'fix' => $fix];
}

/**
 * A tunnel with a blocking finding is shown but skipped by every behaviour.
 *
 * @param array $tunnel derived record
 * @return bool
 */
function wgipv6_blocked(array $tunnel) {
    foreach ($tunnel['findings'] as $f) {
        if ($f['blocking']) {
            return true;
        }
    }
    return false;
}

/**
 * @param string $value comma-separated list
 * @return array trimmed, non-empty items
 */
function wgipv6_split_csv($value) {
    return array_values(array_filter(array_map('trim', explode(',', (string)$value)), 'strlen'));
}

/**
 * Everything the derivation reads from core config, through models.
 *
 * @return array see wgipv6_derive()
 */
function wgipv6_core_snapshot() {
    $root = Config::getInstance()->object();
    $core = [
        'instances' => [], 'peers' => [], 'interfaces' => [], 'routes' => [], 'gateways' => [],
        'snat' => [], 'groups' => [], 'dns_servers' => [], 'forwarders' => [],
    ];
    foreach ((new \OPNsense\Wireguard\Server())->servers->server->iterateItems() as $uuid => $s) {
        $core['instances'][$uuid] = [
            'name' => (string)$s->name,
            'enabled' => (string)$s->enabled === '1',
            'instance' => (string)$s->instance,
            'mtu' => (string)$s->mtu,
            'tunneladdress' => wgipv6_split_csv((string)$s->tunneladdress),
            'peers' => wgipv6_split_csv((string)$s->peers),
        ];
    }
    foreach ((new \OPNsense\Wireguard\Client())->clients->client->iterateItems() as $uuid => $c) {
        $core['peers'][$uuid] = [
            'name' => (string)$c->name,
            'serveraddress' => (string)$c->serveraddress,
            'serverport' => (string)$c->serverport,
        ];
    }
    foreach ($root->interfaces->children() as $opt => $if) {
        $core['interfaces'][$opt] = [
            'if' => (string)$if->if,
            'enable' => isset($if->enable) && (string)$if->enable !== '0',
            'mtu' => (string)$if->mtu,
            'mss' => (string)$if->mss,
            'descr' => (string)$if->descr,
        ];
    }
    foreach ((new \OPNsense\Routes\Route())->route->iterateItems() as $uuid => $r) {
        $core['routes'][$uuid] = [
            'network' => (string)$r->network,
            'gateway' => (string)$r->gateway,
            'enabled' => (string)$r->enabled === '1',
        ];
    }
    foreach ((new \OPNsense\Routing\Gateways())->gateway_item->iterateItems() as $uuid => $g) {
        $core['gateways'][(string)$g->name] = [
            'uuid' => $uuid,
            'interface' => (string)$g->interface,
            'ipprotocol' => (string)$g->ipprotocol,
            'gateway' => (string)$g->gateway,
            'monitor' => (string)$g->monitor,
            'disabled' => (string)$g->disabled === '1',
            'force_down' => (string)$g->force_down === '1',
            'losshigh' => (string)$g->losshigh,
            'losslow' => (string)$g->losslow,
            'time_period' => (string)$g->time_period,
        ];
    }
    foreach ((new \OPNsense\Firewall\Filter())->snatrules->rule->iterateItems() as $rule) {
        if ((string)$rule->enabled === '1') {
            $core['snat'][] = [
                'interface' => (string)$rule->interface,
                'ipprotocol' => (string)$rule->ipprotocol,
                'source' => (string)$rule->source_net,
            ];
        }
    }
    foreach ((new \OPNsense\Routing\GatewayGroups())->gateway_group->iterateItems() as $grp) {
        $members = [];
        foreach (['item', 'item2', 'item3', 'item4', 'item5'] as $tier) {
            $members = array_merge($members, wgipv6_split_csv((string)$grp->$tier));
        }
        $core['groups'][(string)$grp->name] = $members;
    }
    foreach ($root->system->dnsserver as $dns) {
        if ((string)$dns !== '') {
            $core['dns_servers'][] = (string)$dns;
        }
    }
    foreach ((new \OPNsense\Unbound\Unbound())->dots->dot->iterateItems() as $dot) {
        if ((string)$dot->enabled === '1' && (string)$dot->server !== '') {
            $core['forwarders'][] = (string)$dot->server;
        }
    }
    return $core;
}

/**
 * Derive every managed tunnel and the findings. Pure.
 *
 * @param array $core    wgipv6_core_snapshot()
 * @param array $managed WireGuard instance UUIDs the plugin manages, in order
 * @return array ['tunnels' => [record, ...], 'global' => [finding, ...]]
 */
function wgipv6_derive(array $core, array $managed) {
    $ctx = ['opt_by_device' => [], 'gw_by_if' => [], 'binding_routes' => [], 'stale_routes' => [],
            'monitor_users' => [], 'resolvers' => array_merge($core['dns_servers'], $core['forwarders'])];
    foreach ($core['interfaces'] as $opt => $if) {
        if ($if['if'] !== '') {
            $ctx['opt_by_device'][$if['if']] = $opt;
        }
    }
    $wgDevices = [];
    foreach ($core['instances'] as $inst) {
        $wgDevices['wg' . $inst['instance']] = true;
    }
    foreach ($core['gateways'] as $name => $g) {
        $ctx['gw_by_if'][$g['interface']][$g['ipprotocol']][] = $name;
        if ($g['monitor'] !== '') {
            $ctx['monitor_users'][$g['monitor']][] = $name;
        }
    }
    /* enabled /32 routes whose gateway is not on a WireGuard device: the only kind that binds a tunnel */
    foreach ($core['routes'] as $r) {
        if (!$r['enabled'] || substr($r['network'], -3) !== '/32') {
            continue;
        }
        if (filter_var(substr($r['network'], 0, -3), FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            continue;
        }
        $g = $core['gateways'][$r['gateway']] ?? null;
        $dev = $g !== null ? ($core['interfaces'][$g['interface']]['if'] ?? '') : '';
        if (!isset($wgDevices[$dev])) {
            $ctx['binding_routes'][substr($r['network'], 0, -3)] = $r['gateway'];
        }
    }
    $endpoints = [];
    foreach ($core['peers'] as $p) {
        $endpoints[$p['serveraddress']] = true;
    }
    foreach ($ctx['binding_routes'] as $ip => $gwName) {
        if (!isset($endpoints[$ip])) {
            $ctx['stale_routes'][] = "{$ip}/32 via {$gwName}";
        }
    }

    $tunnels = [];
    foreach ($managed as $uuid) {
        $tunnels[] = wgipv6_derive_one($core, $uuid, $ctx);
    }
    $global = [];
    if (!empty($managed) && (!isset($core['gateways']['NO_DEFAULT4']) || !isset($core['gateways']['NO_DEFAULT6']))) {
        $global[] = wgipv6_finding('sentinel-missing', 'NO_DEFAULT4 and NO_DEFAULT6 keep tunnels out of the default-gateway election');
    }
    return ['tunnels' => $tunnels, 'global' => $global];
}

/**
 * One managed tunnel. Pure.
 *
 * @param array  $core wgipv6_core_snapshot()
 * @param string $uuid WireGuard instance UUID
 * @param array  $ctx  indexes built by wgipv6_derive()
 * @return array derived record
 */
function wgipv6_derive_one(array $core, $uuid, array $ctx) {
    $t = [
        'uuid' => $uuid, 'name' => '', 'enabled' => false, 'device' => '', 'interface' => null,
        'interface_descr' => '', 'endpoint' => '', 'endpoint_ip' => null, 'bound_wan' => null, 'wan_interface' => null,
        'mtu' => WGIPV6_DEFAULT_MTU, 'mss' => '',
        'gw4' => null, 'monitor' => '', 'gw6' => null, 'ipv6_address' => null, 'ipv6_next_hop' => null,
        'nat' => ['inet' => [], 'inet6' => []], 'groups' => [], 'findings' => [], 'enforceable' => false,
    ];
    $inst = $core['instances'][$uuid] ?? null;
    if ($inst === null) {
        $t['findings'][] = wgipv6_finding('instance-missing', "no WireGuard instance {$uuid}");
        return $t;
    }
    $t['name'] = $inst['name'];
    $t['enabled'] = $inst['enabled'];
    $t['device'] = 'wg' . $inst['instance'];

    /* peer, endpoint and the WAN binding */
    if (count($inst['peers']) !== 1) {
        $t['findings'][] = wgipv6_finding('not-single-peer', count($inst['peers']) . ' peers');
    } else {
        $peer = $core['peers'][$inst['peers'][0]] ?? null;
        $ip = $peer !== null ? $peer['serveraddress'] : '';
        $t['endpoint'] = $ip . ($peer !== null && $peer['serverport'] !== '' ? ':' . $peer['serverport'] : '');
        $isValidV4 = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
        $t['endpoint_ip'] = $isValidV4 ? $ip : null;
        if (!$isValidV4) {
            $t['findings'][] = wgipv6_finding('endpoint-unsupported', $ip === '' ? 'no endpoint' : "{$ip} is not an IPv4 address");
        } elseif (!isset($ctx['binding_routes'][$ip])) {
            $t['findings'][] = wgipv6_finding('unbound', "no enabled /32 route to {$ip} via a WAN gateway");
            if (!empty($ctx['stale_routes'])) {
                $t['findings'][] = wgipv6_finding('stale-route', implode(', ', $ctx['stale_routes']));
            }
        } else {
            $wan = $ctx['binding_routes'][$ip];
            $t['bound_wan'] = $wan;
            $wanGw = $core['gateways'][$wan] ?? null;
            $wanIf = $wanGw !== null ? ($core['interfaces'][$wanGw['interface']] ?? null) : null;
            /* fail closed: only pin to an interface we can actually resolve and that is up */
            $t['wan_interface'] = ($wanGw !== null && $wanIf !== null && $wanIf['enable']) ? $wanGw['interface'] : null;
            if ($wanGw === null) {
                $t['findings'][] = wgipv6_finding('wan-unavailable', "the route names unknown gateway {$wan}");
            } elseif ($wanGw['disabled'] || $wanIf === null || !$wanIf['enable']) {
                $t['findings'][] = wgipv6_finding('wan-unavailable', "{$wan} or its interface is disabled");
            }
        }
    }

    /* everything else hangs off the interface assignment */
    $opt = $ctx['opt_by_device'][$t['device']] ?? null;
    if ($opt === null) {
        $t['findings'][] = wgipv6_finding('not-assigned', "{$t['device']} has no interface assignment");
        return $t;
    }
    $t['interface'] = $opt;
    $if = $core['interfaces'][$opt];
    $t['interface_descr'] = $if['descr'];
    /* core maps only enabled interfaces for the filter (filter.lib.inc), so a
     * rule on a disabled one is rendered commented out: its pins could never
     * reach pf and freshness would request reloads for them forever */
    if (!$if['enable']) {
        $t['findings'][] = wgipv6_finding('interface-disabled', "{$opt} ({$t['device']}) is disabled");
    }

    /* MTU: the interface value wins when set (core applies it after WireGuard starts) */
    $instMtu = $inst['mtu'] !== '' ? (int)$inst['mtu'] : WGIPV6_DEFAULT_MTU;
    $t['mtu'] = $instMtu;
    if ($if['mtu'] !== '' && (int)$if['mtu'] !== $instMtu) {
        $t['mtu'] = (int)$if['mtu'];
        $t['findings'][] = wgipv6_finding('mtu-override', "interface MTU {$if['mtu']} overrides instance MTU {$instMtu}");
    }
    $t['mss'] = $if['mss'];
    if ($if['mss'] !== '') {
        $t['findings'][] = wgipv6_finding('legacy-mss', "interface MSS {$if['mss']}");
    }

    /* the one gateway per family on the interface */
    foreach (['inet' => 'gw4', 'inet6' => 'gw6'] as $family => $key) {
        $names = $ctx['gw_by_if'][$opt][$family] ?? [];
        if (count($names) > 1) {
            $t['findings'][] = wgipv6_finding('ambiguous-gateway', "{$family}: " . implode(', ', $names));
        } elseif (count($names) === 1) {
            $t[$key] = $names[0];
        }
    }
    if ($t['gw4'] !== null) {
        $t['monitor'] = $core['gateways'][$t['gw4']]['monitor'];
    }

    /* IPv6: the instance's tunnel address, the gateway's next hop */
    $v6 = array_values(array_filter($inst['tunneladdress'], function ($a) {
        return strpos($a, ':') !== false;
    }));
    if (count($v6) === 1) {
        $t['ipv6_address'] = $v6[0];
    }
    if ($t['gw6'] !== null) {
        $t['ipv6_next_hop'] = $core['gateways'][$t['gw6']]['gateway'];
    }
    if (count($v6) > 1) {
        $t['findings'][] = wgipv6_finding('ipv6-incomplete', count($v6) . ' IPv6 tunnel addresses');
    } elseif (($t['gw6'] !== null) !== ($t['ipv6_address'] !== null)) {
        $t['findings'][] = wgipv6_finding(
            'ipv6-incomplete',
            $t['gw6'] !== null ? "{$t['gw6']} but no IPv6 tunnel address" : "{$t['ipv6_address']} but no IPv6 gateway"
        );
    }

    /* MSS clamping needs at least the IPv4 minimum, and the IPv6 minimum when there is an IPv6 address (R8) */
    if ($t['mtu'] < 576) {
        $t['findings'][] = wgipv6_finding('mtu-too-small', "mtu {$t['mtu']} is below the IPv4 minimum 576");
    } elseif ($t['mtu'] < 1280 && $t['ipv6_address'] !== null) {
        $t['findings'][] = wgipv6_finding('mtu-too-small', "mtu {$t['mtu']} is below the IPv6 minimum 1280");
    }

    /* outbound NAT on the interface */
    foreach ($core['snat'] as $rule) {
        if (!in_array($opt, wgipv6_split_csv($rule['interface']), true)) {
            continue;
        }
        foreach (['inet', 'inet6'] as $family) {
            if ($rule['ipprotocol'] === $family || $rule['ipprotocol'] === 'inet46') {
                $t['nat'][$family][] = $rule['source'];
            }
        }
    }
    if ($t['gw4'] !== null && empty($t['nat']['inet'])) {
        $t['findings'][] = wgipv6_finding('nat-missing', 'no IPv4 outbound NAT on ' . $opt);
    }
    if ($t['gw6'] !== null && empty($t['nat']['inet6'])) {
        $t['findings'][] = wgipv6_finding('nat-missing', 'no IPv6 outbound NAT on ' . $opt);
    }

    /* the monitor IP must be used for nothing else (R2) */
    if ($t['monitor'] !== '') {
        $others = array_values(array_diff($ctx['monitor_users'][$t['monitor']] ?? [], [$t['gw4']]));
        if (!empty($others)) {
            $t['findings'][] = wgipv6_finding('monitor-shared', "{$t['monitor']} is also monitored by " . implode(', ', $others));
        } elseif (in_array($t['monitor'], $ctx['resolvers'], true)) {
            $t['findings'][] = wgipv6_finding('monitor-shared', "{$t['monitor']} is a system DNS server or Unbound forwarder");
        }
    }

    foreach ($core['groups'] as $group => $members) {
        if (in_array($t['gw4'], $members, true) || in_array($t['gw6'], $members, true)) {
            $t['groups'][] = $group;
        }
    }
    $t['enforceable'] = $t['enabled'] && $t['bound_wan'] !== null && !wgipv6_blocked($t);
    return $t;
}

/**
 * The health mirror's inputs: pass 1 needs an enforceable (bound) tunnel,
 * pass 2 only an enabled, unblocked tunnel with both gateways (spec 3.3).
 *
 * @param array $derived wgipv6_derive()
 * @return array ['underlays' => [gw4 => WAN gateway], 'pairs' => [gw4 => gw6]]
 */
function wgipv6_mirror_inputs(array $derived) {
    $underlays = [];
    $pairs = [];
    foreach ($derived['tunnels'] as $t) {
        if (!$t['enabled'] || wgipv6_blocked($t) || $t['gw4'] === null) {
            continue;
        }
        if ($t['enforceable']) {
            $underlays[$t['gw4']] = $t['bound_wan'];
        }
        if ($t['gw6'] !== null) {
            $pairs[$t['gw4']] = $t['gw6'];
        }
    }
    return ['underlays' => $underlays, 'pairs' => $pairs];
}

/* where the health mirror kept its held set before model 2.0.0 */
const WGIPV6_LEGACY_HELD_FILE = '/var/db/wgipv6gateway/underlay_held.json';

/**
 * Model 1.x -> 2.0.0: which instances to manage and which gateways are held,
 * from the old per-gateway rows. Pure. Core wins where a row disagrees.
 *
 * @param array $core      wgipv6_core_snapshot()
 * @param array $rows      old rows: ['enabled' => bool, 'ipv4_gateway' => uuid,
 *                         'ipv6_gw_address' => string, 'ipv6_address' => string]
 * @param array $heldNames IPv4 tunnel gateway names from the legacy held file
 * @return array ['managed' => uuid[], 'held' => uuid[], 'notes' => string[]]
 */
function wgipv6_migration_plan(array $core, array $rows, array $heldNames) {
    $nameByUuid = [];
    foreach ($core['gateways'] as $name => $g) {
        $nameByUuid[$g['uuid']] = $name;
    }
    $instanceByDevice = [];
    foreach ($core['instances'] as $uuid => $inst) {
        $instanceByDevice['wg' . $inst['instance']] = $uuid;
    }
    $managed = [];
    $notes = [];
    $adopted = [];      // row index => gw4 name
    foreach ($rows as $i => $row) {
        $gw4 = $nameByUuid[$row['ipv4_gateway']] ?? null;
        if (!$row['enabled']) {
            $notes[] = 'row for ' . ($gw4 ?? $row['ipv4_gateway']) . ' was disabled; not adopted';
            continue;
        }
        if ($gw4 === null) {
            $notes[] = "row points at missing gateway {$row['ipv4_gateway']}; not adopted";
            continue;
        }
        $opt = $core['gateways'][$gw4]['interface'];
        $uuid = $instanceByDevice[$core['interfaces'][$opt]['if'] ?? ''] ?? null;
        if ($uuid === null) {
            $notes[] = "{$gw4} is not on a WireGuard instance's interface; not adopted";
            continue;
        }
        if (!in_array($uuid, $managed, true)) {
            $managed[] = $uuid;
        }
        $adopted[$i] = $gw4;
    }
    $byGw4 = [];
    foreach (wgipv6_derive($core, $managed)['tunnels'] as $t) {
        if ($t['gw4'] !== null) {
            $byGw4[$t['gw4']] = $t;
        }
    }
    foreach ($adopted as $i => $gw4) {
        $t = $byGw4[$gw4] ?? null;
        foreach (['ipv6_gw_address' => 'ipv6_next_hop', 'ipv6_address' => 'ipv6_address'] as $rowKey => $tKey) {
            $want = $t !== null ? (string)$t[$tKey] : '';
            if ($rows[$i][$rowKey] !== '' && $rows[$i][$rowKey] !== $want) {
                $notes[] = "{$gw4}: row {$rowKey} {$rows[$i][$rowKey]} differs from core '{$want}' (core wins)";
            }
        }
    }
    $held = [];
    foreach ($heldNames as $name) {
        if (isset($core['gateways'][$name])) {
            $held[] = $core['gateways'][$name]['uuid'];
        } else {
            $notes[] = "held gateway {$name} no longer exists; dropped";
        }
    }
    return ['managed' => $managed, 'held' => $held, 'notes' => $notes];
}

/**
 * What the WAN pins (R1) and inner-source blocks (R7) cover. Pure; canonical
 * order so two sets compare with ===. A bound tunnel whose WAN cannot be
 * resolved to an enabled interface (wan_interface null) still gets a WAN
 * entry, with wan_if '' -- fail closed, so the handshake is blocked on every
 * interface rather than left unpinned.
 *
 * @param array $derived     wgipv6_derive()
 * @param bool  $wanPins     the wan_pins switch
 * @param bool  $innerSource the inner_source switch
 * @return array ['wan' => [['wan_if', 'family', 'endpoints'] ...], 'inner' => opt keys]
 */
function wgipv6_pin_set(array $derived, $wanPins, $innerSource) {
    $wan = [];
    $inner = [];
    foreach ($derived['tunnels'] as $t) {
        if (!$t['enforceable'] || $t['interface'] === null) {
            continue;
        }
        if ($innerSource) {
            $inner[] = $t['interface'];
        }
        if ($wanPins) {
            $ip = $t['endpoint_ip'];
            $family = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? 'inet6' : 'inet';
            $wanIf = $t['wan_interface'] ?? '';
            $wan[$wanIf . '|' . $family][] = $ip;
        }
    }
    ksort($wan);
    $wanOut = [];
    foreach ($wan as $key => $eps) {
        [$wanIf, $family] = explode('|', $key);
        $eps = array_values(array_unique($eps));
        sort($eps);
        $wanOut[] = ['wan_if' => $wanIf, 'family' => $family, 'endpoints' => $eps];
    }
    $inner = array_values(array_unique($inner));
    sort($inner);
    return ['wan' => $wanOut, 'inner' => $inner];
}

/**
 * registerFilterRule() confs for a pin set, in a stable order. Labels are
 * md5 hashes: core's live log (scripts/filter/read_log.py) only resolves a
 * rule id back to its description when the label is at least 32 hex
 * characters, and a hash stays stable across endpoint changes.
 *
 * @param array $pinSet wgipv6_pin_set()
 * @return array list of rule confs
 */
function wgipv6_pin_rules(array $pinSet) {
    $rules = [];
    foreach ($pinSet['wan'] as $w) {
        if ($w['wan_if'] === '') {
            /* the bound WAN could not be resolved: block the handshake everywhere instead of leaving it unpinned */
            $rules[] = [
                'type' => 'block', 'direction' => 'out', 'quick' => true, 'log' => true,
                'ipprotocol' => $w['family'], 'protocol' => 'udp', 'to' => implode(',', $w['endpoints']),
                'label' => md5('wgipv6gw-pin-wan-anywhere-' . $w['family']),
                'descr' => "WireGuard IPv6 Gateway: this tunnel's bound WAN is unavailable, so its handshakes leave by no interface",
            ];
            continue;
        }
        $rules[] = [
            'type' => 'block', 'direction' => 'out', 'quick' => true, 'log' => true,
            'interface' => $w['wan_if'], 'interfacenot' => true, 'ipprotocol' => $w['family'],
            'protocol' => 'udp', 'to' => implode(',', $w['endpoints']),
            'label' => md5('wgipv6gw-pin-wan-' . $w['wan_if'] . '-' . $w['family']),
            'descr' => 'WireGuard IPv6 Gateway: tunnels bound to this WAN never leave by another interface',
        ];
    }
    foreach ($pinSet['inner'] as $opt) {
        $rules[] = [
            'type' => 'block', 'direction' => 'out', 'quick' => true, 'log' => true,
            'interface' => $opt, 'ipprotocol' => 'inet46', 'from' => '(self)', 'from_not' => true,
            'label' => md5('wgipv6gw-pin-inner-' . $opt),
            'descr' => 'WireGuard IPv6 Gateway: only firewall-sourced (NATed) traffic may enter the tunnel',
        ];
    }
    return $rules;
}

/**
 * The MSS anchor's contents (R8): both directions, because the segment size a
 * LAN host uses is set by the SYN-ACK arriving inbound on the tunnel. A
 * max-mss below the family's minimum would make pfctl reject the whole
 * anchor, so a tunnel too small to clamp safely (mtu-too-small) is skipped
 * for that family instead.
 *
 * @param array $derived  wgipv6_derive()
 * @param bool  $mssClamp the mss_clamp switch
 * @return array sorted pf lines
 */
function wgipv6_mss_lines(array $derived, $mssClamp) {
    $lines = [];
    if (!$mssClamp) {
        return $lines;
    }
    foreach ($derived['tunnels'] as $t) {
        if (!$t['enforceable'] || $t['device'] === '') {
            continue;
        }
        if ($t['mtu'] >= 576) {
            $lines[] = sprintf('match on %s inet proto tcp all scrub (max-mss %d)', $t['device'], $t['mtu'] - 40);
        }
        if ($t['ipv6_address'] !== null && $t['mtu'] >= 1280) {
            $lines[] = sprintf('match on %s inet6 proto tcp all scrub (max-mss %d)', $t['device'], $t['mtu'] - 60);
        }
    }
    sort($lines);
    return $lines;
}

/**
 * The MSS clamp values shown in the GUI/CLI for one tunnel, mirroring
 * wgipv6_mss_lines()'s limits exactly: v4 only when the MTU is at least 576,
 * v6 only when the tunnel has an IPv6 address and the MTU is at least 1280.
 * Null altogether -- not an array of two nulls -- when the clamp switch is
 * off or the tunnel is not enforceable, since nothing would be rendered for
 * it either way.
 *
 * @param array $t        derived tunnel record
 * @param bool  $mssClamp the mss_clamp switch
 * @return array|null ['v4' => int|null, 'v6' => int|null], or null
 */
function wgipv6_clamp_for(array $t, bool $mssClamp): ?array {
    if (!$mssClamp || !$t['enforceable']) {
        return null;
    }
    return [
        'v4' => $t['mtu'] >= 576 ? $t['mtu'] - 40 : null,
        'v6' => ($t['ipv6_address'] !== null && $t['mtu'] >= 1280) ? $t['mtu'] - 60 : null,
    ];
}

/**
 * Self-tests for the derivation. No config, no processes.
 *
 * @return int exit code, 0 when every case passes
 */
function wgipv6_tunnels_selftest() {
    $gw = function (array $o = []) {
        return $o + [
            'uuid' => 'u-' . bin2hex(random_bytes(4)), 'interface' => 'opt1', 'ipprotocol' => 'inet',
            'gateway' => '', 'monitor' => '', 'disabled' => false, 'force_down' => false,
            'losshigh' => '', 'losslow' => '', 'time_period' => '',
        ];
    };
    $base = function () use ($gw) {
        return [
            'instances' => [
                'i-a' => ['name' => 'tun_a', 'enabled' => true, 'instance' => '1', 'mtu' => '1376',
                          'tunneladdress' => ['10.2.0.2/32', 'fd00::1:1/128'], 'peers' => ['p-a']],
            ],
            'peers' => ['p-a' => ['name' => 'tun_a', 'serveraddress' => '198.51.100.10', 'serverport' => '51820']],
            'interfaces' => [
                'wan' => ['if' => 'igc1', 'enable' => true, 'mtu' => '', 'mss' => '', 'descr' => ''],
                'opt1' => ['if' => 'igc2', 'enable' => true, 'mtu' => '', 'mss' => '', 'descr' => ''],
                'opt11' => ['if' => 'wg1', 'enable' => true, 'mtu' => '', 'mss' => '', 'descr' => ''],
            ],
            'routes' => ['r-a' => ['network' => '198.51.100.10/32', 'gateway' => 'WAN_A', 'enabled' => true]],
            'gateways' => [
                'WAN_A' => $gw(['interface' => 'opt1', 'gateway' => '192.0.2.1']),
                'tun_a' => $gw(['interface' => 'opt11', 'gateway' => '10.2.0.4', 'monitor' => '203.0.113.9']),
                'tun_a-ipv6' => $gw(['interface' => 'opt11', 'ipprotocol' => 'inet6', 'gateway' => 'fd00::1:2']),
                'NO_DEFAULT4' => $gw(['interface' => 'opt10']),
                'NO_DEFAULT6' => $gw(['interface' => 'opt10', 'ipprotocol' => 'inet6']),
            ],
            'snat' => [
                ['interface' => 'opt11', 'ipprotocol' => 'inet', 'source' => 'opt3'],
                ['interface' => 'opt11', 'ipprotocol' => 'inet6', 'source' => 'opt3'],
            ],
            'groups' => ['grp_a' => ['tun_a', 'WAN_A'], 'grp_b' => ['WAN_A']],
            'dns_servers' => ['203.0.113.53'],
            'forwarders' => ['203.0.113.54'],
        ];
    };
    $codes = function (array $t) {
        $c = array_map(function ($f) { return $f['code']; }, $t['findings']);
        sort($c);
        return $c;
    };
    $cases = [
        // description, mutate(core), managed, expected codes, expected enforceable
        ['healthy tunnel => no findings, enforceable', function ($c) { return $c; }, ['i-a'], [], true],
        ['instance deleted => instance-missing (blocking)', function ($c) { return $c; }, ['i-gone'], ['instance-missing'], false],
        ['disabled instance => no finding, not enforceable',
            function ($c) { $c['instances']['i-a']['enabled'] = false; return $c; }, ['i-a'], [], false],
        ['two peers => not-single-peer',
            function ($c) { $c['instances']['i-a']['peers'][] = 'p-b'; return $c; }, ['i-a'], ['not-single-peer'], false],
        ['hostname endpoint => endpoint-unsupported',
            function ($c) { $c['peers']['p-a']['serveraddress'] = 'vpn.example.net'; return $c; }, ['i-a'], ['endpoint-unsupported'], false],
        ['endpoint edited, old route left => unbound + stale-route',
            function ($c) { $c['peers']['p-a']['serveraddress'] = '198.51.100.20'; return $c; }, ['i-a'], ['stale-route', 'unbound'], false],
        ['route disabled => unbound only (no stale candidate)',
            function ($c) { $c['routes']['r-a']['enabled'] = false; return $c; }, ['i-a'], ['unbound'], false],
        ['bound WAN gateway disabled => wan-unavailable, still enforceable',
            function ($c) { $c['gateways']['WAN_A']['disabled'] = true; return $c; }, ['i-a'], ['wan-unavailable'], true],
        ['device not assigned => not-assigned',
            function ($c) { unset($c['interfaces']['opt11']); return $c; }, ['i-a'], ['not-assigned'], false],
        ['tunnel interface disabled => interface-disabled, not enforceable',
            function ($c) { $c['interfaces']['opt11']['enable'] = false; return $c; }, ['i-a'], ['interface-disabled'], false],
        ['two IPv4 gateways on the interface => ambiguous-gateway',
            function ($c) use ($gw) { $c['gateways']['tun_a_2'] = $gw(['interface' => 'opt11']); return $c; }, ['i-a'], ['ambiguous-gateway'], false],
        ['IPv6 gateway without IPv6 address => ipv6-incomplete',
            function ($c) { $c['instances']['i-a']['tunneladdress'] = ['10.2.0.2/32']; return $c; }, ['i-a'], ['ipv6-incomplete'], true],
        ['interface MTU differs => mtu-override',
            function ($c) { $c['interfaces']['opt11']['mtu'] = '1300'; return $c; }, ['i-a'], ['mtu-override'], true],
        ['interface MSS set => legacy-mss',
            function ($c) { $c['interfaces']['opt11']['mss'] = '1376'; return $c; }, ['i-a'], ['legacy-mss'], true],
        ['no IPv6 NAT => nat-missing',
            function ($c) { array_pop($c['snat']); return $c; }, ['i-a'], ['nat-missing'], true],
        ['monitor is a system DNS server => monitor-shared',
            function ($c) { $c['gateways']['tun_a']['monitor'] = '203.0.113.53'; return $c; }, ['i-a'], ['monitor-shared'], true],
        ['monitor shared with another gateway => monitor-shared',
            function ($c) { $c['gateways']['WAN_A']['monitor'] = '203.0.113.9'; return $c; }, ['i-a'], ['monitor-shared'], true],
        ['route via the tunnel device itself is excluded (spec 3.1) => unbound, no stale-route',
            function ($c) {
                $c['routes']['r-a']['enabled'] = false;
                $c['routes']['r-b'] = ['network' => '198.51.100.10/32', 'gateway' => 'tun_a', 'enabled' => true];
                return $c;
            }, ['i-a'], ['unbound'], false],
        ['no IPv4 outbound NAT => nat-missing, enforceable',
            function ($c) { $c['snat'] = [$c['snat'][1]]; return $c; }, ['i-a'], ['nat-missing'], true],
        ['IPv6 gateway removed, IPv6 address kept => ipv6-incomplete, enforceable',
            function ($c) { unset($c['gateways']['tun_a-ipv6']); return $c; }, ['i-a'], ['ipv6-incomplete'], true],
        ['two IPv6 tunnel addresses => ipv6-incomplete, enforceable',
            function ($c) { $c['instances']['i-a']['tunneladdress'][] = 'fd00::1:3/128'; return $c; }, ['i-a'], ['ipv6-incomplete'], true],
        ['bound WAN interface disabled => wan-unavailable, enforceable',
            function ($c) { $c['interfaces']['opt1']['enable'] = false; return $c; }, ['i-a'], ['wan-unavailable'], true],
        ['zero peers => not-single-peer',
            function ($c) { $c['instances']['i-a']['peers'] = []; return $c; }, ['i-a'], ['not-single-peer'], false],
        ['IPv6 endpoint => endpoint-unsupported',
            function ($c) { $c['peers']['p-a']['serveraddress'] = '2001:db8::10'; return $c; }, ['i-a'], ['endpoint-unsupported'], false],
    ];
    $fail = 0;
    $total = 0;
    foreach ($cases as [$desc, $mutate, $managed, $expCodes, $expEnf]) {
        $d = wgipv6_derive($mutate($base()), $managed);
        $t = $d['tunnels'][0];
        sort($expCodes);
        $ok = $codes($t) === $expCodes && $t['enforceable'] === $expEnf;
        $fail += $ok ? 0 : 1;
        $total++;
        printf("[%s] derive: %s\n", $ok ? 'PASS' : 'FAIL', $desc);
        if (!$ok) {
            printf("       codes %s enforceable %s\n", json_encode($codes($t)), var_export($t['enforceable'], true));
        }
    }

    /* wan-unavailable via an unknown gateway name on the route: bound_wan is still set to it */
    $c = $base();
    $c['routes']['r-a']['gateway'] = 'NOPE';
    $t = wgipv6_derive($c, ['i-a'])['tunnels'][0];
    $ok = $codes($t) === ['wan-unavailable'] && $t['enforceable'] === true && $t['bound_wan'] === 'NOPE'
        && $t['wan_interface'] === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] derive: unknown gateway name on the route => wan-unavailable, bound_wan is the route's gateway, wan_interface fails closed\n", $ok ? 'PASS' : 'FAIL');

    /* interface MTU equal to the instance MTU => no override finding, mtu is the instance's */
    $c = $base();
    $c['interfaces']['opt11']['mtu'] = '1376';
    $t = wgipv6_derive($c, ['i-a'])['tunnels'][0];
    $ok = $codes($t) === [] && $t['enforceable'] === true && $t['mtu'] === 1376;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] derive: interface MTU equal to instance MTU => no finding, mtu 1376\n", $ok ? 'PASS' : 'FAIL');

    /* neither instance nor interface sets an MTU => the WireGuard default */
    $c = $base();
    $c['instances']['i-a']['mtu'] = '';
    $t = wgipv6_derive($c, ['i-a'])['tunnels'][0];
    $ok = $codes($t) === [] && $t['enforceable'] === true && $t['mtu'] === 1420;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] derive: no instance or interface MTU => default 1420\n", $ok ? 'PASS' : 'FAIL');

    /* an IPv6-looking "/32" network string must never become a binding or stale-route candidate */
    $c = $base();
    $c['peers']['p-a']['serveraddress'] = '198.51.100.20';
    $c['routes']['r-c'] = ['network' => '2001:db8::/32', 'gateway' => 'WAN_A', 'enabled' => true];
    $t = wgipv6_derive($c, ['i-a'])['tunnels'][0];
    $staleDetail = '';
    foreach ($t['findings'] as $f) {
        if ($f['code'] === 'stale-route') {
            $staleDetail = $f['detail'];
        }
    }
    $ok = $codes($t) === ['stale-route', 'unbound'] && $t['enforceable'] === false && strpos($staleDetail, '2001:db8') === false;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] derive: non-IPv4 \"/32\" network string is not a binding-route candidate\n", $ok ? 'PASS' : 'FAIL');

    /* record fields on the healthy tunnel */
    $t = wgipv6_derive($base(), ['i-a'])['tunnels'][0];
    $ok = $t['device'] === 'wg1' && $t['interface'] === 'opt11' && $t['bound_wan'] === 'WAN_A'
        && $t['wan_interface'] === 'opt1' && $t['endpoint'] === '198.51.100.10:51820'
        && $t['endpoint_ip'] === '198.51.100.10' && $t['mtu'] === 1376 && $t['gw4'] === 'tun_a'
        && $t['gw6'] === 'tun_a-ipv6' && $t['ipv6_address'] === 'fd00::1:1/128'
        && $t['ipv6_next_hop'] === 'fd00::1:2' && $t['nat'] === ['inet' => ['opt3'], 'inet6' => ['opt3']]
        && $t['groups'] === ['grp_a'] && $t['monitor'] === '203.0.113.9';
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] derive: healthy record fields\n", $ok ? 'PASS' : 'FAIL');

    /* global finding */
    $c = $base();
    unset($c['gateways']['NO_DEFAULT6']);
    $g = wgipv6_derive($c, ['i-a'])['global'];
    $ok = count($g) === 1 && $g[0]['code'] === 'sentinel-missing';
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] derive: missing sentinel => sentinel-missing\n", $ok ? 'PASS' : 'FAIL');
    $ok = wgipv6_derive($c, [])['global'] === [];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] derive: no managed tunnels => no sentinel finding\n", $ok ? 'PASS' : 'FAIL');

    /* mirror inputs */
    $in = wgipv6_mirror_inputs(wgipv6_derive($base(), ['i-a']));
    $ok = $in === ['underlays' => ['tun_a' => 'WAN_A'], 'pairs' => ['tun_a' => 'tun_a-ipv6']];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] mirror inputs: healthy tunnel => underlay + pair\n", $ok ? 'PASS' : 'FAIL');
    $c = $base();
    $c['routes']['r-a']['enabled'] = false;
    $in = wgipv6_mirror_inputs(wgipv6_derive($c, ['i-a']));
    $ok = $in === ['underlays' => [], 'pairs' => ['tun_a' => 'tun_a-ipv6']];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] mirror inputs: unbound => no underlay, pair kept (pass 2 only)\n", $ok ? 'PASS' : 'FAIL');
    $c = $base();
    $c['instances']['i-a']['enabled'] = false;
    $in = wgipv6_mirror_inputs(wgipv6_derive($c, ['i-a']));
    $ok = $in === ['underlays' => [], 'pairs' => []];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] mirror inputs: disabled instance => ignored\n", $ok ? 'PASS' : 'FAIL');

    /* migration plan: old rows -> managed instances, held names -> gateway uuids */
    $c = $base();
    $c['gateways']['tun_a']['uuid'] = 'g-tun-a';
    $rows = [
        ['enabled' => true, 'ipv4_gateway' => 'g-tun-a', 'ipv6_gw_address' => 'fd00::1:2', 'ipv6_address' => 'fd00::1:1/128'],
        ['enabled' => false, 'ipv4_gateway' => 'g-tun-a', 'ipv6_gw_address' => '', 'ipv6_address' => ''],
        ['enabled' => true, 'ipv4_gateway' => 'g-missing', 'ipv6_gw_address' => '', 'ipv6_address' => ''],
    ];
    $mp = wgipv6_migration_plan($c, $rows, ['tun_a', 'gone_gw']);
    $ok = $mp['managed'] === ['i-a'] && $mp['held'] === ['g-tun-a'] && count($mp['notes']) === 3;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] migration: adopt enabled row, note disabled row, missing gateway and vanished held name\n", $ok ? 'PASS' : 'FAIL');
    if (!$ok) {
        printf("       %s\n", json_encode($mp));
    }
    $rows = [['enabled' => true, 'ipv4_gateway' => 'g-tun-a', 'ipv6_gw_address' => 'fd00::9:2', 'ipv6_address' => 'fd00::1:1/128']];
    $mp = wgipv6_migration_plan($c, $rows, []);
    $ok = $mp['managed'] === ['i-a'] && count($mp['notes']) === 1 && strpos($mp['notes'][0], 'core wins') !== false;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] migration: row disagreeing with core is adopted, noted, core wins\n", $ok ? 'PASS' : 'FAIL');

    /* renderers */
    $d = wgipv6_derive($base(), ['i-a']);
    $ok = $d['tunnels'][0]['wan_interface'] === 'opt1';
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: record carries the bound WAN's interface\n", $ok ? 'PASS' : 'FAIL');

    $ps = wgipv6_pin_set($d, true, true);
    $ok = $ps === ['wan' => [['wan_if' => 'opt1', 'family' => 'inet', 'endpoints' => ['198.51.100.10']]], 'inner' => ['opt11']];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: pin set for one bound tunnel\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgipv6_pin_set($d, false, false) === ['wan' => [], 'inner' => []];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: switches off => empty pin set\n", $ok ? 'PASS' : 'FAIL');

    $c = $base();
    $c['routes']['r-a']['enabled'] = false;
    $ok = wgipv6_pin_set(wgipv6_derive($c, ['i-a']), true, true) === ['wan' => [], 'inner' => []];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: unbound tunnel is not pinned\n", $ok ? 'PASS' : 'FAIL');

    $rules = wgipv6_pin_rules($ps);
    $wanRule = $rules[0];
    $innerRule = $rules[1];
    $labelRe = '/^[0-9a-f]{32}$/';
    $ok = count($rules) === 2
        && $wanRule['type'] === 'block' && $wanRule['direction'] === 'out' && $wanRule['quick'] === true && $wanRule['log'] === true
        && $wanRule['interface'] === 'opt1' && $wanRule['interfacenot'] === true && $wanRule['ipprotocol'] === 'inet'
        && $wanRule['protocol'] === 'udp' && $wanRule['to'] === '198.51.100.10'
        && preg_match($labelRe, $wanRule['label']) === 1 && $wanRule['label'] === md5('wgipv6gw-pin-wan-opt1-inet')
        && $innerRule['type'] === 'block' && $innerRule['direction'] === 'out' && $innerRule['quick'] === true && $innerRule['log'] === true
        && $innerRule['interface'] === 'opt11' && $innerRule['ipprotocol'] === 'inet46'
        && $innerRule['from'] === '(self)' && $innerRule['from_not'] === true
        && preg_match($labelRe, $innerRule['label']) === 1 && $innerRule['label'] === md5('wgipv6gw-pin-inner-opt11');
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: filter rule confs for the WAN pin and the inner-source block\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgipv6_mss_lines($d, true) === [
        'match on wg1 inet proto tcp all scrub (max-mss 1336)',
        'match on wg1 inet6 proto tcp all scrub (max-mss 1316)',
    ];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: MSS lines both families, both directions\n", $ok ? 'PASS' : 'FAIL');

    $c = $base();
    $c['instances']['i-a']['tunneladdress'] = ['10.2.0.2/32'];
    unset($c['gateways']['tun_a-ipv6']);
    $ok = wgipv6_mss_lines(wgipv6_derive($c, ['i-a']), true) === ['match on wg1 inet proto tcp all scrub (max-mss 1336)']
        && wgipv6_mss_lines($d, false) === [];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: IPv4-only tunnel => one line; clamp off => none\n", $ok ? 'PASS' : 'FAIL');

    /* a disabled WAN gateway (but its interface still up) is not "unresolvable": wan_interface stays set */
    $c = $base();
    $c['gateways']['WAN_A']['disabled'] = true;
    $ok = wgipv6_derive($c, ['i-a'])['tunnels'][0]['wan_interface'] === 'opt1';
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: WAN gateway disabled but its interface is up => wan_interface still resolvable\n", $ok ? 'PASS' : 'FAIL');

    /* fail closed: unknown gateway on the bound route => interface-less WAN pin */
    $c = $base();
    $c['routes']['r-a']['gateway'] = 'NOPE';
    $dUnknown = wgipv6_derive($c, ['i-a']);
    $ok = $dUnknown['tunnels'][0]['wan_interface'] === null;
    $psUnknown = wgipv6_pin_set($dUnknown, true, true);
    $ok = $ok && $psUnknown === ['wan' => [['wan_if' => '', 'family' => 'inet', 'endpoints' => ['198.51.100.10']]], 'inner' => ['opt11']];
    $rulesUnknown = wgipv6_pin_rules($psUnknown);
    $wanRuleUnknown = $rulesUnknown[0];
    $ok = $ok && count($rulesUnknown) === 2
        && !array_key_exists('interface', $wanRuleUnknown) && !array_key_exists('interfacenot', $wanRuleUnknown)
        && $wanRuleUnknown['type'] === 'block' && $wanRuleUnknown['direction'] === 'out' && $wanRuleUnknown['quick'] === true
        && $wanRuleUnknown['log'] === true && $wanRuleUnknown['ipprotocol'] === 'inet' && $wanRuleUnknown['protocol'] === 'udp'
        && $wanRuleUnknown['to'] === '198.51.100.10' && $wanRuleUnknown['label'] === md5('wgipv6gw-pin-wan-anywhere-inet');
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: unknown gateway on the bound route => interface-less WAN pin, fail closed\n", $ok ? 'PASS' : 'FAIL');

    /* fail closed: bound WAN interface disabled => interface-less WAN pin */
    $c = $base();
    $c['interfaces']['opt1']['enable'] = false;
    $dDisabled = wgipv6_derive($c, ['i-a']);
    $ok = $dDisabled['tunnels'][0]['wan_interface'] === null && $dDisabled['tunnels'][0]['enforceable'] === true;
    $psDisabled = wgipv6_pin_set($dDisabled, true, true);
    $ok = $ok && $psDisabled === ['wan' => [['wan_if' => '', 'family' => 'inet', 'endpoints' => ['198.51.100.10']]], 'inner' => ['opt11']];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: bound WAN interface disabled => interface-less WAN pin, fail closed\n", $ok ? 'PASS' : 'FAIL');

    /* two enforceable tunnels bound to the same WAN, distinct endpoints => merged and sorted */
    $c = $base();
    $c['instances']['i-b'] = ['name' => 'tun_b', 'enabled' => true, 'instance' => '2', 'mtu' => '1420',
                              'tunneladdress' => ['10.3.0.2/32'], 'peers' => ['p-b']];
    $c['peers']['p-b'] = ['name' => 'tun_b', 'serveraddress' => '198.51.100.30', 'serverport' => '51821'];
    $c['interfaces']['opt12'] = ['if' => 'wg2', 'enable' => true, 'mtu' => '', 'mss' => '', 'descr' => ''];
    $c['routes']['r-b'] = ['network' => '198.51.100.30/32', 'gateway' => 'WAN_A', 'enabled' => true];
    $ps2 = wgipv6_pin_set(wgipv6_derive($c, ['i-a', 'i-b']), true, true);
    $ok = $ps2 === ['wan' => [['wan_if' => 'opt1', 'family' => 'inet', 'endpoints' => ['198.51.100.10', '198.51.100.30']]],
                    'inner' => ['opt11', 'opt12']];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: two tunnels on the same WAN => endpoints merged and sorted, inner opts sorted\n", $ok ? 'PASS' : 'FAIL');

    /* two enforceable tunnels sharing the same endpoint => the endpoint is de-duplicated */
    $c = $base();
    $c['instances']['i-b'] = ['name' => 'tun_b', 'enabled' => true, 'instance' => '2', 'mtu' => '1420',
                              'tunneladdress' => ['10.3.0.2/32'], 'peers' => ['p-b']];
    $c['peers']['p-b'] = ['name' => 'tun_b', 'serveraddress' => '198.51.100.10', 'serverport' => '51821'];
    $c['interfaces']['opt12'] = ['if' => 'wg2', 'enable' => true, 'mtu' => '', 'mss' => '', 'descr' => ''];
    $ps3 = wgipv6_pin_set(wgipv6_derive($c, ['i-a', 'i-b']), true, true);
    $ok = $ps3 === ['wan' => [['wan_if' => 'opt1', 'family' => 'inet', 'endpoints' => ['198.51.100.10']]],
                    'inner' => ['opt11', 'opt12']];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: two tunnels sharing an endpoint => the endpoint is de-duplicated\n", $ok ? 'PASS' : 'FAIL');

    /* an interface MTU override feeds the MSS lines too */
    $c = $base();
    $c['interfaces']['opt11']['mtu'] = '1300';
    $ok = wgipv6_mss_lines(wgipv6_derive($c, ['i-a']), true) === [
        'match on wg1 inet proto tcp all scrub (max-mss 1260)',
        'match on wg1 inet6 proto tcp all scrub (max-mss 1240)',
    ];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: mtu-override MTU feeds the MSS lines\n", $ok ? 'PASS' : 'FAIL');

    /* MTU below the IPv4 minimum => no MSS lines at all, mtu-too-small raised */
    $c = $base();
    $c['instances']['i-a']['mtu'] = '500';
    $d5 = wgipv6_derive($c, ['i-a']);
    $t5 = $d5['tunnels'][0];
    $codes5 = array_map(function ($f) { return $f['code']; }, $t5['findings']);
    $ok = in_array('mtu-too-small', $codes5, true) && $t5['enforceable'] === true
        && wgipv6_mss_lines($d5, true) === [];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: MTU below the IPv4 minimum => no MSS lines, mtu-too-small raised\n", $ok ? 'PASS' : 'FAIL');

    /* MTU below the IPv6 minimum but above the IPv4 one, with an IPv6 address => only the IPv4 line, mtu-too-small raised */
    $c = $base();
    $c['instances']['i-a']['mtu'] = '1000';
    $d6 = wgipv6_derive($c, ['i-a']);
    $t6 = $d6['tunnels'][0];
    $codes6 = array_map(function ($f) { return $f['code']; }, $t6['findings']);
    $ok = in_array('mtu-too-small', $codes6, true)
        && wgipv6_mss_lines($d6, true) === ['match on wg1 inet proto tcp all scrub (max-mss 960)'];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: MTU below the IPv6 minimum, IPv6 address present => only the IPv4 MSS line, mtu-too-small raised\n", $ok ? 'PASS' : 'FAIL');

    /* wgipv6_clamp_for: the per-tunnel clamp shown in the GUI/CLI, mirroring wgipv6_mss_lines() */
    $ok = wgipv6_clamp_for($d['tunnels'][0], true) === ['v4' => 1336, 'v6' => 1316];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] clamp_for: healthy tunnel, clamp on => v4 and v6 clamps\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgipv6_clamp_for($d['tunnels'][0], false) === null;
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] clamp_for: healthy tunnel, clamp off => null\n", $ok ? 'PASS' : 'FAIL');

    $cDisabled = $base();
    $cDisabled['instances']['i-a']['enabled'] = false;
    $tDisabled = wgipv6_derive($cDisabled, ['i-a'])['tunnels'][0];
    $ok = wgipv6_clamp_for($tDisabled, true) === null;
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] clamp_for: not enforceable, clamp on => null\n", $ok ? 'PASS' : 'FAIL');

    $cV4Only = $base();
    $cV4Only['instances']['i-a']['tunneladdress'] = ['10.2.0.2/32'];
    unset($cV4Only['gateways']['tun_a-ipv6']);
    $tV4Only = wgipv6_derive($cV4Only, ['i-a'])['tunnels'][0];
    $ok = wgipv6_clamp_for($tV4Only, true) === ['v4' => 1336, 'v6' => null];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] clamp_for: IPv4-only tunnel, clamp on => v4 clamp, v6 omitted\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgipv6_clamp_for($t5, true) === ['v4' => null, 'v6' => null];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] clamp_for: MTU below the IPv4 minimum => clamp present but both families null\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgipv6_clamp_for($t6, true) === ['v4' => 960, 'v6' => null];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] clamp_for: MTU below the IPv6 minimum, IPv6 address present => v4 clamp only\n", $ok ? 'PASS' : 'FAIL');

    printf("%d/%d passed\n", $total - $fail, $total);
    return $fail === 0 ? 0 : 1;
}
