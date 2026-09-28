<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Tunnel derivation (spec 2026-09-24 section 3). Core config is the only
 * source of truth: a managed tunnel is assembled from its WireGuard instance
 * and peer, the interface assignment of its device, the /32 or /128 route to
 * its endpoint, the gateways on its interface, outbound NAT and the gateway
 * groups, every time it is needed. The plugin stores only which instances it
 * manages. wgct_core_snapshot() reads config through models; every other
 * function here is pure over that snapshot.
 */

use OPNsense\Core\Config;

require_once __DIR__ . '/addr.php';

/* WireGuard's MTU when neither the instance nor the interface sets one. */
const WGCT_DEFAULT_MTU = 1420;

/* finding code => [blocking, where it is fixed] (spec section 3.4) */
const WGCT_FINDINGS = [
    'instance-missing' => [true, 'the managed WireGuard instance was deleted; Remove in the tunnel list (tunnel.php remove) drops it from the managed list'],
    'not-assigned' => [true, 'Interfaces > Assignments: assign the wgN device'],
    'interface-disabled' => [true, "Interfaces > the tunnel's interface: enable it"],
    'not-single-peer' => [true, 'VPN > WireGuard > Instances: exactly one peer'],
    'endpoint-unsupported' => [true, 'VPN > WireGuard > Peers: an IPv4 or global IPv6 server address (typed bare, without brackets)'],
    'ambiguous-gateway' => [true, 'System > Gateways: one gateway per family on the tunnel interface'],
    'unbound' => [false, 'Rebind in the tunnel list (tunnel.php rebind), or System > Routes: a /32 (IPv4) or /128 (IPv6) route to the endpoint via a WAN gateway'],
    'stale-route' => [false, 'Rebind in the tunnel list offers to delete it with its kernel route; or re-point or remove it on System > Routes'],
    'wan-unavailable' => [false, 'System > Gateways, Interfaces: enable the bound gateway and its interface, or bind to a saved, enabled gateway of the endpoint\'s family'],
    'ipv6-incomplete' => [false, 'Instances and System > Gateways: IPv6 tunnel address and IPv6 gateway together'],
    'mtu-override' => [false, 'Interfaces > wgN: clear MTU or match the instance MTU'],
    'mtu-too-small' => [false, "VPN > WireGuard > Instances (or Interfaces > the tunnel's interface): the MTU is too small to clamp TCP MSS; set it to at least 1280"],
    'legacy-mss' => [false, "Interfaces > the tunnel's interface: an MSS value is set by hand"],
    'nat-missing' => [false, 'Firewall > NAT > Source NAT: rules on the tunnel interface (Create adds them from a template tunnel or the NAT sources)'],
    'monitor-shared' => [false, 'System > Gateways: a monitor IP nothing else uses'],
    'ipv6-unmonitored' => [false, 'Edit the tunnel: set an IPv6 monitor'],
    'ipv6-monitor-config' => [false, 'Edit the tunnel and save its IPv6 monitor again (it resets the monitor route setting and copies the IPv4 thresholds)'],
    'sentinel-missing' => [false, 'Settings > Check default-route exclusion (tunnel.php ensure-sentinel) creates the NO_DEFAULT4 and NO_DEFAULT6 gateways that keep the tunnels out of the default route'],
    'render-failed' => [false, 'Firewall > Log Files > General: the plugin could not build its firewall rules at the last reload; they are missing until the next reload succeeds'],
    'apply-pending' => [false, 'Apply in the tunnel list (tunnel.php apply UUID) runs the apply the saved change still needs: Create or Edit saved this tunnel but its apply did not complete'],
];

/*
 * The priority of the WAN pin and inner-source block rules: the top of core's early automatic band
 * (sort_order "0nnnnn", after core's own early rules at 1, 5 and 10000 and before every floating rule
 * at 200000), so pf evaluates them where it did at 100000 while core's Rules page files them under
 * "Automatically generated rules". At 100000 the rows fell in band 1, which the page has no group for,
 * and it showed no rules at all.
 */
const WGCT_PIN_PRIORITY = 99999;

/* the pf anchor name for the MSS clamp lines */
const WGCT_MSS_ANCHOR = 'wgclienttunnels_mss';

/**
 * @param string $code   key of WGCT_FINDINGS
 * @param string $detail what was found
 * @param ?string $fix   overrides the table's fix text, when the finding needs a more specific hint
 * @return array ['code', 'blocking', 'detail', 'fix']
 */
function wgct_finding($code, $detail, ?string $fix = null) {
    [$blocking, $tableFix] = WGCT_FINDINGS[$code];
    return ['code' => $code, 'blocking' => $blocking, 'detail' => $detail, 'fix' => $fix ?? $tableFix];
}

/**
 * A tunnel with a blocking finding is shown but skipped by every behaviour.
 *
 * @param array $tunnel derived record
 * @return bool
 */
function wgct_blocked(array $tunnel) {
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
function wgct_split_csv($value) {
    return array_values(array_filter(array_map('trim', explode(',', (string)$value)), 'strlen'));
}

/**
 * Every element at $path below $root, in document order. Pure. A missing step
 * yields an empty list (SimpleXML iterates a missing child zero times), so
 * optional sections -- legacy <filter>, <nat><outbound> -- need no isset().
 *
 * @param \SimpleXMLElement $root the config root, or any element
 * @param string            ...$path child element names
 * @return list<\SimpleXMLElement>
 */
function wgct_xml_list(\SimpleXMLElement $root, string ...$path): array {
    $nodes = [$root];
    foreach ($path as $step) {
        $next = [];
        foreach ($nodes as $node) {
            foreach ($node->{$step} as $child) {
                $next[] = $child;
            }
        }
        $nodes = $next;
    }
    return $nodes;
}

/**
 * Everything the derivation reads from core config, through models.
 *
 * @return array see wgct_derive()
 */
function wgct_core_snapshot() {
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
            'tunneladdress' => wgct_split_csv((string)$s->tunneladdress),
            'peers' => wgct_split_csv((string)$s->peers),
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
            'ipaddrv6' => (string)$if->ipaddrv6,
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
            'monitor_disable' => (string)$g->monitor_disable === '1',
            'monitor_noroute' => (string)$g->monitor_noroute === '1',
            'latencylow' => (string)$g->latencylow,
            'latencyhigh' => (string)$g->latencyhigh,
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
            $members = array_merge($members, wgct_split_csv((string)$grp->$tier));
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
    /* the plugin's route switch (the monitor routes, spec 3.5) and core's dpinger defaults, read once here so
     * the derivation stays pure */
    $core['ipv6_routes'] = (string)(new \OPNsense\WGClientTunnels\WGClientTunnels())->ipv6_routes === '1';
    $core['dpinger_defaults'] = \OPNsense\Routing\FieldTypes\GatewayField::getDpingerDefaults();
    return $core;
}

/**
 * Derive every managed tunnel and the findings. Pure.
 *
 * @param array $core    wgct_core_snapshot()
 * @param array $managed WireGuard instance UUIDs the plugin manages, in order
 * @return array ['tunnels' => [record, ...], 'global' => [finding, ...]]
 */
function wgct_derive(array $core, array $managed) {
    $canon = fn (string $a): string => wgct_canon_ip($a) ?? $a;
    $ctx = ['opt_by_device' => [], 'gw_by_if' => [], 'binding_routes' => [], 'stale_routes' => [],
            'monitor_users' => [], 'resolvers' => array_map($canon, array_merge($core['dns_servers'], $core['forwarders']))];
    foreach ($core['interfaces'] as $opt => $if) {
        if ($if['if'] !== '') {
            $ctx['opt_by_device'][$if['if']] = $opt;
        }
    }
    foreach ($core['gateways'] as $name => $g) {
        $ctx['gw_by_if'][$g['interface']][$g['ipprotocol']][] = $name;
        if ($g['monitor'] !== '') {
            $ctx['monitor_users'][$canon($g['monitor'])][] = $name;
        }
    }
    foreach (wgct_binding_routes($core) as $b) {
        $ctx['binding_routes'][$b['family']][$b['ip']] = $b['gateway'];
    }
    /* one entry per IP and family, the last route's gateway winning */
    $stale = ['inet' => [], 'inet6' => []];
    foreach (wgct_stale_candidates($core) as $b) {
        $stale[$b['family']][$b['ip']] = wgct_host_network($b['ip']) . " via {$b['gateway']}";
    }
    $ctx['stale_routes'] = ['inet' => array_values($stale['inet']), 'inet6' => array_values($stale['inet6'])];

    $tunnels = [];
    foreach ($managed as $uuid) {
        $tunnels[] = wgct_derive_one($core, $uuid, $ctx);
    }
    $global = [];
    if (!empty($managed) && (!isset($core['gateways']['NO_DEFAULT4']) || !isset($core['gateways']['NO_DEFAULT6']))) {
        $global[] = wgct_finding('sentinel-missing', 'NO_DEFAULT4 and NO_DEFAULT6 keep tunnels out of the default-gateway election');
    }
    return ['tunnels' => $tunnels, 'global' => $global];
}

/**
 * @param array $core wgct_core_snapshot()
 * @return array<string, true> wgN device names of every WireGuard instance
 */
function wgct_wg_devices(array $core): array {
    $out = [];
    foreach ($core['instances'] as $inst) {
        $out['wg' . $inst['instance']] = true;
    }
    return $out;
}

/**
 * The routes that can bind a tunnel (spec 2.2): enabled /32 IPv4 and /128
 * global IPv6 routes whose gateway is not on a WireGuard device. Pure.
 * Derivation and Rebind both use this, so they cannot disagree on what a
 * binding is.
 *
 * @param array $core wgct_core_snapshot()
 * @return array<string, array{ip: string, gateway: string, family: string}> route uuid => binding
 */
function wgct_binding_routes(array $core): array {
    $wgDevices = wgct_wg_devices($core);
    $out = [];
    foreach ($core['routes'] as $uuid => $r) {
        $host = $r['enabled'] ? wgct_host_route($r['network']) : null;
        if ($host === null || ($host['family'] === 'inet6' && !wgct_is_global6($host['ip']))) {
            continue;
        }
        $g = $core['gateways'][$r['gateway']] ?? null;
        $dev = $g !== null ? ($core['interfaces'][$g['interface']]['if'] ?? '') : '';
        if (!isset($wgDevices[$dev])) {
            $out[(string)$uuid] = ['ip' => $host['ip'], 'gateway' => $r['gateway'], 'family' => $host['family']];
        }
    }
    return $out;
}

/**
 * stale-route candidates (spec 3.4): binding routes to an address that is no
 * peer's endpoint. Pure.
 *
 * @param array $core wgct_core_snapshot()
 * @return array<string, array{ip: string, gateway: string, family: string}> route uuid => binding
 */
function wgct_stale_candidates(array $core): array {
    $endpoints = [];
    foreach ($core['peers'] as $p) {
        $endpoints[wgct_canon_ip($p['serveraddress']) ?? $p['serveraddress']] = true;
    }
    return array_filter(wgct_binding_routes($core), fn (array $b): bool => !isset($endpoints[$b['ip']]));
}

/**
 * One managed tunnel. Pure.
 *
 * @param array  $core wgct_core_snapshot()
 * @param string $uuid WireGuard instance UUID
 * @param array  $ctx  indexes built by wgct_derive()
 * @return array derived record
 */
function wgct_derive_one(array $core, $uuid, array $ctx) {
    $t = [
        'uuid' => $uuid, 'name' => '', 'enabled' => false, 'device' => '', 'interface' => null,
        'interface_descr' => '', 'endpoint' => '', 'endpoint_ip' => null, 'endpoint_family' => null, 'bound_wan' => null, 'wan_interface' => null,
        'mtu' => WGCT_DEFAULT_MTU, 'mss' => '',
        'gw4' => null, 'monitor' => '', 'monitor6' => '', 'monitor6_mode' => null, 'gw6' => null, 'ipv6_address' => null, 'ipv6_next_hop' => null,
        'nat' => ['inet' => [], 'inet6' => []], 'groups' => [], 'findings' => [], 'enforceable' => false,
    ];
    $inst = $core['instances'][$uuid] ?? null;
    if ($inst === null) {
        $t['findings'][] = wgct_finding('instance-missing', "no WireGuard instance {$uuid}");
        return $t;
    }
    $t['name'] = $inst['name'];
    $t['enabled'] = $inst['enabled'];
    $t['device'] = 'wg' . $inst['instance'];

    /* peer, endpoint and the WAN binding */
    if (count($inst['peers']) !== 1) {
        $t['findings'][] = wgct_finding('not-single-peer', count($inst['peers']) . ' peers');
    } else {
        $peer = $core['peers'][$inst['peers'][0]] ?? null;
        $raw = $peer !== null ? $peer['serveraddress'] : '';
        $port = $peer !== null ? $peer['serverport'] : '';
        $ip = wgct_endpoint_ip($raw);
        $family = $ip !== null ? wgct_ip_family($ip) : null;
        /* the canonical address when supported; else the raw value, an IPv6 one still in brackets (a link-local
         * or other non-global address), a hostname or empty one as it is */
        $t['endpoint'] = wgct_format_endpoint($ip ?? $raw, $port);
        $t['endpoint_ip'] = $ip;
        $t['endpoint_family'] = $family;
        if ($ip === null) {
            $t['findings'][] = wgct_finding('endpoint-unsupported', $raw === '' ? 'no endpoint'
                : (wgct_ip_family($raw) === 'inet6' ? "{$raw} is not a global IPv6 address" : "{$raw} is not an IPv4 or IPv6 address"));
        } elseif (!isset($ctx['binding_routes'][$family][$ip])) {
            $t['findings'][] = wgct_finding('unbound', 'no enabled ' . ($family === 'inet6' ? '/128' : '/32') . " route to {$ip} via a WAN gateway");
            if (!empty($ctx['stale_routes'][$family])) {
                $t['findings'][] = wgct_finding('stale-route', implode(', ', $ctx['stale_routes'][$family]));
            }
        } else {
            $wan = $ctx['binding_routes'][$family][$ip];
            $t['bound_wan'] = $wan;
            $wanGw = $core['gateways'][$wan] ?? null;
            $wanIf = $wanGw !== null ? ($core['interfaces'][$wanGw['interface']] ?? null) : null;
            /* an IPv6 endpoint needs an IPv6 gateway that is not a 6rd/6to4 tunnel; IPv4 keeps core's rule (RFC 5549) */
            $unusable = null;
            if ($wanGw !== null && $family === 'inet6' && $wanGw['ipprotocol'] !== 'inet6') {
                $unusable = "{$wan} is IPv4; an IPv6 endpoint needs an IPv6 gateway";
            } elseif ($wanGw !== null && $family === 'inet6' && in_array($wanIf['ipaddrv6'] ?? '', ['6rd', '6to4'], true)) {
                $unusable = "{$wan} is on a 6rd/6to4 WAN; IPv6 over 6rd/6to4 is not supported as a binding";
            }
            /* fail closed: only pin to an interface we can actually resolve, that is up, and that can carry the endpoint */
            $t['wan_interface'] = ($wanGw !== null && $wanIf !== null && $wanIf['enable'] && $unusable === null) ? $wanGw['interface'] : null;
            if ($wanGw === null) {
                $t['findings'][] = wgct_finding('wan-unavailable', "{$wan} is not a saved gateway; save it once on System > Gateways");
            } elseif ($unusable !== null) {
                $t['findings'][] = wgct_finding('wan-unavailable', $unusable);
            } elseif ($wanGw['disabled'] || $wanIf === null || !$wanIf['enable']) {
                $t['findings'][] = wgct_finding('wan-unavailable', "{$wan} or its interface is disabled");
            }
        }
    }

    /* everything else hangs off the interface assignment */
    $opt = $ctx['opt_by_device'][$t['device']] ?? null;
    if ($opt === null) {
        $t['findings'][] = wgct_finding('not-assigned', "{$t['device']} has no interface assignment");
        return $t;
    }
    $t['interface'] = $opt;
    $if = $core['interfaces'][$opt];
    $t['interface_descr'] = $if['descr'];
    /* core maps only enabled interfaces for the filter (filter.lib.inc), so a
     * rule on a disabled one is rendered commented out: its pins could never
     * reach pf and freshness would request reloads for them forever */
    if (!$if['enable']) {
        $t['findings'][] = wgct_finding('interface-disabled', "{$opt} ({$t['device']}) is disabled");
    }

    /* MTU: the interface value wins when set (core applies it after WireGuard starts) */
    $instMtu = $inst['mtu'] !== '' ? (int)$inst['mtu'] : WGCT_DEFAULT_MTU;
    $t['mtu'] = $instMtu;
    if ($if['mtu'] !== '' && (int)$if['mtu'] !== $instMtu) {
        $t['mtu'] = (int)$if['mtu'];
        $t['findings'][] = wgct_finding('mtu-override', "interface MTU {$if['mtu']} overrides instance MTU {$instMtu}");
    }
    $t['mss'] = $if['mss'];
    if ($if['mss'] !== '') {
        $t['findings'][] = wgct_finding('legacy-mss', "interface MSS {$if['mss']}");
    }

    /* the one gateway per family on the interface */
    foreach (['inet' => 'gw4', 'inet6' => 'gw6'] as $family => $key) {
        $names = $ctx['gw_by_if'][$opt][$family] ?? [];
        if (count($names) > 1) {
            $t['findings'][] = wgct_finding('ambiguous-gateway', "{$family}: " . implode(', ', $names));
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
    /* the IPv6 gateway's own monitor (R3, spec 3.5) */
    if ($t['gw6'] !== null) {
        $g6 = $core['gateways'][$t['gw6']];
        $t['monitor6_mode'] = !empty($g6['monitor_disable']) ? 'off' : ($g6['monitor'] === '' ? 'empty' : 'monitored');
        $t['monitor6'] = $t['monitor6_mode'] === 'monitored' ? (wgct_canon_ip($g6['monitor']) ?? $g6['monitor']) : '';
    }
    if (count($v6) > 1) {
        $t['findings'][] = wgct_finding('ipv6-incomplete', count($v6) . ' IPv6 tunnel addresses');
    } elseif (($t['gw6'] !== null) !== ($t['ipv6_address'] !== null)) {
        $t['findings'][] = wgct_finding(
            'ipv6-incomplete',
            $t['gw6'] !== null ? "{$t['gw6']} but no IPv6 tunnel address" : "{$t['ipv6_address']} but no IPv6 gateway"
        );
    }

    /* MSS clamping needs at least the IPv4 minimum, and the IPv6 minimum when there is an IPv6 address (R8) */
    if ($t['mtu'] < 576) {
        $t['findings'][] = wgct_finding('mtu-too-small', "mtu {$t['mtu']} is below the IPv4 minimum 576");
    } elseif ($t['mtu'] < 1280 && $t['ipv6_address'] !== null) {
        $t['findings'][] = wgct_finding('mtu-too-small', "mtu {$t['mtu']} is below the IPv6 minimum 1280");
    }

    /* outbound NAT on the interface */
    foreach ($core['snat'] as $rule) {
        if (!in_array($opt, wgct_split_csv($rule['interface']), true)) {
            continue;
        }
        foreach (['inet', 'inet6'] as $family) {
            if ($rule['ipprotocol'] === $family || $rule['ipprotocol'] === 'inet46') {
                $t['nat'][$family][] = $rule['source'];
            }
        }
    }
    if ($t['gw4'] !== null && empty($t['nat']['inet'])) {
        $t['findings'][] = wgct_finding('nat-missing', 'no IPv4 outbound NAT on ' . $opt);
    }
    if ($t['gw6'] !== null && empty($t['nat']['inet6'])) {
        $t['findings'][] = wgct_finding('nat-missing', 'no IPv6 outbound NAT on ' . $opt);
    }

    /* each monitor IP must be used for nothing else (R2, and R3 for the IPv6 one) */
    foreach ([[$t['monitor'], $t['gw4']], [$t['monitor6'], $t['gw6']]] as [$m, $own]) {
        if ($m === '') {
            continue;
        }
        $key = wgct_canon_ip($m) ?? $m;
        $others = array_values(array_diff($ctx['monitor_users'][$key] ?? [], [$own]));
        if (!empty($others)) {
            $t['findings'][] = wgct_finding('monitor-shared', "{$m} is also monitored by " . implode(', ', $others));
        } elseif (in_array($key, $ctx['resolvers'], true)) {
            $t['findings'][] = wgct_finding('monitor-shared', "{$m} is a system DNS server or Unbound forwarder");
        }
    }

    /* the IPv6 gateway's monitor state (spec 3.5) */
    if ($t['monitor6_mode'] === 'off') {
        $t['findings'][] = wgct_finding('ipv6-unmonitored', "{$t['gw6']}: IPv6 health follows the IPv4 tunnel only");
    } elseif ($t['monitor6_mode'] === 'empty') {
        $t['findings'][] = wgct_finding('ipv6-unmonitored',
            "{$t['gw6']}: monitoring on with no monitor IP: core pings the next hop, which never answers, so the gateway reads down");
    } elseif ($t['monitor6_mode'] === 'monitored') {
        $why = wgct_monitor6_repair_reasons($core, $t);
        $routesOff = !($core['ipv6_routes'] ?? true);
        if ($routesOff) {
            $why[] = 'the monitor routes are not maintained; a tunnel restart leaves this gateway unmeasured and reading down';
        }
        if ($why !== []) {
            $t['findings'][] = wgct_finding('ipv6-monitor-config', "{$t['gw6']}: " . implode('; ', $why),
                $routesOff && count($why) === 1 ? 'Settings: turn on IPv6 addresses and routes' : null);
        }
    }

    foreach ($core['groups'] as $group => $members) {
        if (in_array($t['gw4'], $members, true) || in_array($t['gw6'], $members, true)) {
            $t['groups'][] = $group;
        }
    }
    $t['enforceable'] = $t['enabled'] && $t['bound_wan'] !== null && !wgct_blocked($t);
    return $t;
}

/**
 * Why a monitored IPv6 gateway needs Edit's re-save (spec 3.5, 3.7): core may route its monitor, or its
 * thresholds are tighter than its IPv4 gateway's. The routes switch is not a reason: Edit cannot fix it. Pure.
 *
 * @param array $core wgct_core_snapshot()
 * @param array $t    a derived record with a gw6
 * @return list<string>
 */
function wgct_monitor6_repair_reasons(array $core, array $t): array {
    $g6 = $core['gateways'][$t['gw6']] ?? null;
    if ($g6 === null) {
        return [];
    }
    $why = [];
    if (empty($g6['monitor_noroute'])) {
        $why[] = 'core would route its monitor (monitor_noroute off)';
    }
    $g4 = $t['gw4'] !== null ? ($core['gateways'][$t['gw4']] ?? null) : null;
    if ($g4 !== null) {
        $defaults = $core['dpinger_defaults'] ?? [];
        foreach (['latencyhigh', 'losshigh'] as $field) {
            $v4 = wgct_threshold((string)($g4[$field] ?? ''), $defaults[$field] ?? null);
            $v6 = wgct_threshold((string)($g6[$field] ?? ''), $defaults[$field] ?? null);
            if ($v4 !== null && $v6 !== null && $v6 < $v4) {
                $why[] = "{$field} {$v6} is below {$t['gw4']}'s {$v4}";
            }
        }
    }
    return $why;
}

/**
 * A gateway threshold as a number: the value, or core's default when it is empty. Pure.
 *
 * @param string              $value   the stored value ('' when unset)
 * @param int|string|null     $default core's default, null when unknown
 * @return int|null null when unset with no default, or not a whole number
 */
function wgct_threshold(string $value, int|string|null $default): ?int {
    if ($value !== '') {
        return ctype_digit($value) ? (int)$value : null;
    }
    return $default === null ? null : (int)$default;
}

/**
 * The health mirror's inputs: pass 1 needs an enforceable (bound) tunnel,
 * pass 2 only an enabled, unblocked tunnel with both gateways (spec 3.3).
 *
 * @param array $derived wgct_derive()
 * @return array ['underlays' => [gw4 => WAN gateway], 'pairs' => [gw4 => gw6]]
 */
function wgct_mirror_inputs(array $derived) {
    $underlays = [];
    $pairs = [];
    foreach ($derived['tunnels'] as $t) {
        if (!$t['enabled'] || wgct_blocked($t) || $t['gw4'] === null) {
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

/**
 * gateway_config.php's output (spec 3.4.1), read by wgct.sh's route set and status: `state|on` or
 * `state|off`, then one `route` line per tunnel the route set configures and one `keep` line per managed
 * tunnel that is blocked (its recorded routes are kept, never deleted, while the finding stands). A tunnel
 * with no IPv6 or a disabled instance gets no line. Pure.
 *
 * @param array $derived    wgct_derive()
 * @param bool  $enabled    the plugin's Enable switch
 * @param bool  $ipv6Routes the "IPv6 addresses and routes" switch
 * @return list<string>
 */
function wgct_route_lines(array $derived, bool $enabled, bool $ipv6Routes): array {
    if (!$enabled || !$ipv6Routes) {
        return ['state|off'];
    }
    $clean = fn (mixed $v): string => str_replace(['|', "\r", "\n"], ' ', trim((string)$v));
    $lines = ['state|on'];
    foreach ($derived['tunnels'] as $t) {
        if ($t['device'] === '') {
            continue;
        }
        if (wgct_blocked($t)) {
            $lines[] = 'keep|' . $clean($t['device']);
            continue;
        }
        if (!$t['enabled'] || $t['gw4'] === null || $t['gw6'] === null || $t['ipv6_address'] === null
            || (string)$t['ipv6_next_hop'] === '') {
            continue;
        }
        $lines[] = implode('|', array_map($clean,
            ['route', $t['device'], $t['ipv6_address'], $t['ipv6_next_hop'], $t['gw4'], $t['gw6'], $t['monitor6']]));
    }
    return $lines;
}

/**
 * What the WAN pins (R1) and inner-source blocks (R7) cover. Pure; canonical
 * order so two sets compare with ===. A bound tunnel whose WAN cannot be
 * resolved to an enabled interface (wan_interface null) still gets a WAN
 * entry, with wan_if '' -- fail closed, so the handshake is blocked on every
 * interface rather than left unpinned.
 *
 * @param array $derived     wgct_derive()
 * @param bool  $wanPins     the wan_pins switch
 * @param bool  $innerSource the inner_source switch
 * @return array ['wan' => [['wan_if', 'family', 'endpoints'] ...], 'inner' => opt keys]
 */
function wgct_pin_set(array $derived, $wanPins, $innerSource) {
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
 * @param array $pinSet wgct_pin_set()
 * @return array list of rule confs
 */
function wgct_pin_rules(array $pinSet) {
    $rules = [];
    foreach ($pinSet['wan'] as $w) {
        if ($w['wan_if'] === '') {
            /* the bound WAN could not be resolved: block the handshake everywhere instead of leaving it unpinned */
            $rules[] = [
                'type' => 'block', 'direction' => 'out', 'quick' => true, 'log' => true,
                'ipprotocol' => $w['family'], 'protocol' => 'udp', 'to' => implode(',', $w['endpoints']),
                'label' => md5('wgct-pin-wan-anywhere-' . $w['family']),
                'descr' => "WireGuard Upstream Tunnels: this tunnel's bound WAN is unavailable, so its handshakes leave by no interface",
            ];
            continue;
        }
        $rules[] = [
            'type' => 'block', 'direction' => 'out', 'quick' => true, 'log' => true,
            'interface' => $w['wan_if'], 'interfacenot' => true, 'ipprotocol' => $w['family'],
            'protocol' => 'udp', 'to' => implode(',', $w['endpoints']),
            'label' => md5('wgct-pin-wan-' . $w['wan_if'] . '-' . $w['family']),
            'descr' => 'WireGuard Upstream Tunnels: tunnels bound to this WAN never leave by another interface',
        ];
    }
    foreach ($pinSet['inner'] as $opt) {
        $rules[] = [
            'type' => 'block', 'direction' => 'out', 'quick' => true, 'log' => true,
            'interface' => $opt, 'ipprotocol' => 'inet46', 'from' => '(self)', 'from_not' => true,
            'label' => md5('wgct-pin-inner-' . $opt),
            'descr' => 'WireGuard Upstream Tunnels: only firewall-sourced (NATed) traffic may enter the tunnel',
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
 * @param array $derived  wgct_derive()
 * @param bool  $mssClamp the mss_clamp switch
 * @return array sorted pf lines
 */
function wgct_mss_lines(array $derived, $mssClamp) {
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
 * wgct_mss_lines()'s limits exactly: v4 only when the MTU is at least 576,
 * v6 only when the tunnel has an IPv6 address and the MTU is at least 1280.
 * Null altogether -- not an array of two nulls -- when the clamp switch is
 * off or the tunnel is not enforceable, since nothing would be rendered for
 * it either way.
 *
 * @param array $t        derived tunnel record
 * @param bool  $mssClamp the mss_clamp switch
 * @return array|null ['v4' => int|null, 'v6' => int|null], or null
 */
function wgct_clamp_for(array $t, bool $mssClamp): ?array {
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
function wgct_tunnels_selftest() {
    $gw = function (array $o = []) {
        return $o + [
            'uuid' => 'u-' . bin2hex(random_bytes(4)), 'interface' => 'opt1', 'ipprotocol' => 'inet',
            'gateway' => '', 'monitor' => '', 'disabled' => false, 'force_down' => false,
            'losshigh' => '', 'losslow' => '', 'time_period' => '', 'monitor_disable' => false,
            'monitor_noroute' => false, 'latencylow' => '', 'latencyhigh' => '',
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
                'WAN_A6' => $gw(['interface' => 'opt1', 'ipprotocol' => 'inet6', 'gateway' => 'fe80::1']),
                'tun_a' => $gw(['interface' => 'opt11', 'gateway' => '10.2.0.4', 'monitor' => '203.0.113.9']),
                'tun_a-ipv6' => $gw(['interface' => 'opt11', 'ipprotocol' => 'inet6', 'gateway' => 'fd00::1:2',
                                     'monitor' => '2001:db8:ffff::9', 'monitor_noroute' => true]),
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
            'ipv6_routes' => true,
            'dpinger_defaults' => ['latencylow' => 200, 'latencyhigh' => 500, 'losslow' => 10, 'losshigh' => 20],
        ];
    };
    $codes = function (array $t) {
        $c = array_map(function ($f) { return $f['code']; }, $t['findings']);
        sort($c);
        return $c;
    };
    /* the tunnel moved to an IPv6 endpoint bound by a /128 via WAN_A6; $net and $gwName override the route */
    $v6 = function (array $c, string $net = '2001:db8:0::10/128', string $gwName = 'WAN_A6') {
        $c['peers']['p-a']['serveraddress'] = '2001:DB8::10';
        $c['routes']['r-a'] = ['network' => $net, 'gateway' => $gwName, 'enabled' => true];
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
        ['(a) IPv6 endpoint, non-canonical, /128 via an IPv6 WAN gateway => no findings, enforceable',
            function ($c) use ($v6) { return $v6($c); }, ['i-a'], [], true],
        ['(b) link-local IPv6 endpoint => endpoint-unsupported',
            function ($c) { $c['peers']['p-a']['serveraddress'] = 'fe80::10'; return $c; }, ['i-a'], ['endpoint-unsupported'], false],
        ['(c) IPv6 endpoint with no /128 route => unbound, and no IPv4 stale candidate offered',
            function ($c) { $c['peers']['p-a']['serveraddress'] = '2001:db8::10'; return $c; }, ['i-a'], ['unbound'], false],
        ['(d) IPv6 endpoint, /128 via an IPv4 gateway => wan-unavailable, enforceable (fails closed)',
            function ($c) use ($v6) { return $v6($c, '2001:db8::10/128', 'WAN_A'); }, ['i-a'], ['wan-unavailable'], true],
        ['(e) IPv6 endpoint via a gateway on a 6rd WAN => wan-unavailable',
            function ($c) use ($v6) { $c['interfaces']['opt1']['ipaddrv6'] = '6rd'; return $v6($c); }, ['i-a'], ['wan-unavailable'], true],
        ['(f) IPv4 gateway on a 6rd WAN binds as today',
            function ($c) { $c['interfaces']['opt1']['ipaddrv6'] = '6rd'; return $c; }, ['i-a'], [], true],
        ['(g) IPv6 endpoint, /128 via an unsaved gateway => wan-unavailable',
            function ($c) use ($v6) { return $v6($c, '2001:db8::10/128', 'WAN_DHCP6'); }, ['i-a'], ['wan-unavailable'], true],
        ['(h) IPv6 gateway with monitoring off => ipv6-unmonitored, enforceable',
            function ($c) { $c['gateways']['tun_a-ipv6']['monitor_disable'] = true; $c['gateways']['tun_a-ipv6']['monitor'] = ''; return $c; },
            ['i-a'], ['ipv6-unmonitored'], true],
        ['(i) IPv6 gateway monitoring on with no monitor => ipv6-unmonitored',
            function ($c) { $c['gateways']['tun_a-ipv6']['monitor'] = ''; return $c; }, ['i-a'], ['ipv6-unmonitored'], true],
        ['(j) monitored IPv6 gateway with monitor_noroute off => ipv6-monitor-config',
            function ($c) { $c['gateways']['tun_a-ipv6']['monitor_noroute'] = false; return $c; }, ['i-a'], ['ipv6-monitor-config'], true],
        ['(k) IPv6 latencyhigh (empty = default 500) below the IPv4 gateway\'s 1600 => ipv6-monitor-config',
            function ($c) { $c['gateways']['tun_a']['latencyhigh'] = '1600'; return $c; }, ['i-a'], ['ipv6-monitor-config'], true],
        ['(l) IPv6 losshigh below the IPv4 gateway\'s => ipv6-monitor-config',
            function ($c) { $c['gateways']['tun_a']['losshigh'] = '20'; $c['gateways']['tun_a-ipv6']['losshigh'] = '10'; return $c; },
            ['i-a'], ['ipv6-monitor-config'], true],
        ['(m) IPv6 addresses and routes switched off => ipv6-monitor-config',
            function ($c) { $c['ipv6_routes'] = false; return $c; }, ['i-a'], ['ipv6-monitor-config'], true],
        ['(n) IPv6 monitor shared with another gateway, spelled differently => monitor-shared',
            function ($c) { $c['gateways']['WAN_A6']['monitor'] = '2001:DB8:FFFF:0::9'; return $c; }, ['i-a'], ['monitor-shared'], true],
    ];
    $fail = 0;
    $total = 0;
    foreach ($cases as [$desc, $mutate, $managed, $expCodes, $expEnf]) {
        $d = wgct_derive($mutate($base()), $managed);
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
    $t = wgct_derive($c, ['i-a'])['tunnels'][0];
    $ok = $codes($t) === ['wan-unavailable'] && $t['enforceable'] === true && $t['bound_wan'] === 'NOPE'
        && $t['wan_interface'] === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] derive: unknown gateway name on the route => wan-unavailable, bound_wan is the route's gateway, wan_interface fails closed\n", $ok ? 'PASS' : 'FAIL');

    /* (b) an unsupported IPv6 endpoint is still shown in brackets; a hostname as it is */
    $c = $base();
    $c['peers']['p-a']['serveraddress'] = 'fe80::10';
    $t = wgct_derive($c, ['i-a'])['tunnels'][0];
    $c['peers']['p-a']['serveraddress'] = 'vpn.example.net';
    $h = wgct_derive($c, ['i-a'])['tunnels'][0];
    $ok = $t['endpoint'] === '[fe80::10]:51820' && $t['endpoint_ip'] === null && $h['endpoint'] === 'vpn.example.net:51820';
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] derive: (b) a link-local IPv6 endpoint is shown as [fe80::10]:51820, a hostname unbracketed\n", $ok ? 'PASS' : 'FAIL');

    /* interface MTU equal to the instance MTU => no override finding, mtu is the instance's */
    $c = $base();
    $c['interfaces']['opt11']['mtu'] = '1376';
    $t = wgct_derive($c, ['i-a'])['tunnels'][0];
    $ok = $codes($t) === [] && $t['enforceable'] === true && $t['mtu'] === 1376;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] derive: interface MTU equal to instance MTU => no finding, mtu 1376\n", $ok ? 'PASS' : 'FAIL');

    /* neither instance nor interface sets an MTU => the WireGuard default */
    $c = $base();
    $c['instances']['i-a']['mtu'] = '';
    $t = wgct_derive($c, ['i-a'])['tunnels'][0];
    $ok = $codes($t) === [] && $t['enforceable'] === true && $t['mtu'] === 1420;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] derive: no instance or interface MTU => default 1420\n", $ok ? 'PASS' : 'FAIL');

    /* an IPv6-looking "/32" network string must never become a binding or stale-route candidate */
    $c = $base();
    $c['peers']['p-a']['serveraddress'] = '198.51.100.20';
    $c['routes']['r-c'] = ['network' => '2001:db8::/32', 'gateway' => 'WAN_A', 'enabled' => true];
    $t = wgct_derive($c, ['i-a'])['tunnels'][0];
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
    $t = wgct_derive($base(), ['i-a'])['tunnels'][0];
    $ok = $t['device'] === 'wg1' && $t['interface'] === 'opt11' && $t['bound_wan'] === 'WAN_A'
        && $t['wan_interface'] === 'opt1' && $t['endpoint'] === '198.51.100.10:51820'
        && $t['endpoint_ip'] === '198.51.100.10' && $t['mtu'] === 1376 && $t['gw4'] === 'tun_a'
        && $t['gw6'] === 'tun_a-ipv6' && $t['ipv6_address'] === 'fd00::1:1/128'
        && $t['ipv6_next_hop'] === 'fd00::1:2' && $t['nat'] === ['inet' => ['opt3'], 'inet6' => ['opt3']]
        && $t['groups'] === ['grp_a'] && $t['monitor'] === '203.0.113.9' && $t['endpoint_family'] === 'inet';
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] derive: healthy record fields\n", $ok ? 'PASS' : 'FAIL');

    $detail = function (array $t, string $code): string {
        foreach ($t['findings'] as $f) {
            if ($f['code'] === $code) {
                return $f['detail'] . ' | ' . $f['fix'];
            }
        }
        return '';
    };
    /* (h) record fields of an IPv6-endpoint tunnel */
    $t6 = wgct_derive($v6($base()), ['i-a'])['tunnels'][0];
    $ok = $t6['endpoint'] === '[2001:db8::10]:51820' && $t6['endpoint_ip'] === '2001:db8::10'
        && $t6['endpoint_family'] === 'inet6' && $t6['bound_wan'] === 'WAN_A6' && $t6['wan_interface'] === 'opt1';
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] derive: IPv6 endpoint record fields\n", $ok ? 'PASS' : 'FAIL');

    /* (i) wrong-family gateway: bound, unresolvable, the anywhere pin in inet6 */
    $dm = wgct_derive($v6($base(), '2001:db8::10/128', 'WAN_A'), ['i-a']);
    $tm = $dm['tunnels'][0];
    $ok = $tm['bound_wan'] === 'WAN_A' && $tm['wan_interface'] === null
        && str_contains($detail($tm, 'wan-unavailable'), 'an IPv6 endpoint needs an IPv6 gateway')
        && wgct_pin_set($dm, true, false)['wan'] === [['wan_if' => '', 'family' => 'inet6', 'endpoints' => ['2001:db8::10']]];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] derive: wrong-family gateway fails closed with the inet6 anywhere pin\n", $ok ? 'PASS' : 'FAIL');

    /* (j) unsaved gateway: the save hint */
    $tu = wgct_derive($v6($base(), '2001:db8::10/128', 'WAN_DHCP6'), ['i-a'])['tunnels'][0];
    $ok = $tu['wan_interface'] === null
        && str_contains($detail($tu, 'wan-unavailable'), 'WAN_DHCP6 is not a saved gateway; save it once on System > Gateways');
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] derive: a route via an unsaved gateway names the fix\n", $ok ? 'PASS' : 'FAIL');

    /* (k) an IPv4 tunnel's stale candidates never include a /128 */
    $c = $base();
    $c['peers']['p-a']['serveraddress'] = '198.51.100.20';
    $c['routes']['r-x'] = ['network' => '2001:db8::99/128', 'gateway' => 'WAN_A6', 'enabled' => true];
    $tk = wgct_derive($c, ['i-a'])['tunnels'][0];
    $ok = str_contains($detail($tk, 'stale-route'), '198.51.100.10/32 via WAN_A') && !str_contains($detail($tk, 'stale-route'), '2001:db8::99');
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] derive: stale candidates are filtered by the tunnel's family\n", $ok ? 'PASS' : 'FAIL');

    /* (l) unbound IPv6 endpoint's fix is now Rebind */
    $tl = wgct_derive((function ($c) { $c['peers']['p-a']['serveraddress'] = '2001:db8::10'; return $c; })($base()), ['i-a'])['tunnels'][0];
    $ok = str_contains($detail($tl, 'unbound'), 'no enabled /128 route to 2001:db8::10')
        && str_contains($detail($tl, 'unbound'), 'Rebind in the tunnel list');
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] derive: unbound IPv6 endpoint names the /128 route and Rebind\n", $ok ? 'PASS' : 'FAIL');

    /* (m) the pin set and rule for an IPv6 endpoint */
    $d6 = wgct_derive($v6($base()), ['i-a']);
    $ps6 = wgct_pin_set($d6, true, false);
    $r6 = wgct_pin_rules($ps6)[0];
    $ok = $ps6['wan'] === [['wan_if' => 'opt1', 'family' => 'inet6', 'endpoints' => ['2001:db8::10']]]
        && $r6['ipprotocol'] === 'inet6' && $r6['to'] === '2001:db8::10' && $r6['label'] === md5('wgct-pin-wan-opt1-inet6');
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: an IPv6 endpoint is pinned in inet6 on its WAN\n", $ok ? 'PASS' : 'FAIL');

    /* (n) the mirror follows the IPv6 bound gateway */
    $ok = wgct_mirror_inputs($d6)['underlays'] === ['tun_a' => 'WAN_A6'];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] mirror inputs: an IPv6-endpoint tunnel's underlay is its IPv6 gateway\n", $ok ? 'PASS' : 'FAIL');

    /* global finding */
    $c = $base();
    unset($c['gateways']['NO_DEFAULT6']);
    $g = wgct_derive($c, ['i-a'])['global'];
    $ok = count($g) === 1 && $g[0]['code'] === 'sentinel-missing';
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] derive: missing sentinel => sentinel-missing\n", $ok ? 'PASS' : 'FAIL');
    $ok = wgct_derive($c, [])['global'] === [];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] derive: no managed tunnels => no sentinel finding\n", $ok ? 'PASS' : 'FAIL');

    /* mirror inputs */
    $in = wgct_mirror_inputs(wgct_derive($base(), ['i-a']));
    $ok = $in === ['underlays' => ['tun_a' => 'WAN_A'], 'pairs' => ['tun_a' => 'tun_a-ipv6']];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] mirror inputs: healthy tunnel => underlay + pair\n", $ok ? 'PASS' : 'FAIL');
    $c = $base();
    $c['routes']['r-a']['enabled'] = false;
    $in = wgct_mirror_inputs(wgct_derive($c, ['i-a']));
    $ok = $in === ['underlays' => [], 'pairs' => ['tun_a' => 'tun_a-ipv6']];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] mirror inputs: unbound => no underlay, pair kept (pass 2 only)\n", $ok ? 'PASS' : 'FAIL');
    $c = $base();
    $c['instances']['i-a']['enabled'] = false;
    $in = wgct_mirror_inputs(wgct_derive($c, ['i-a']));
    $ok = $in === ['underlays' => [], 'pairs' => []];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] mirror inputs: disabled instance => ignored\n", $ok ? 'PASS' : 'FAIL');

    /* renderers */
    $d = wgct_derive($base(), ['i-a']);
    $ok = $d['tunnels'][0]['wan_interface'] === 'opt1';
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: record carries the bound WAN's interface\n", $ok ? 'PASS' : 'FAIL');

    $ps = wgct_pin_set($d, true, true);
    $ok = $ps === ['wan' => [['wan_if' => 'opt1', 'family' => 'inet', 'endpoints' => ['198.51.100.10']]], 'inner' => ['opt11']];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: pin set for one bound tunnel\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgct_pin_set($d, false, false) === ['wan' => [], 'inner' => []];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: switches off => empty pin set\n", $ok ? 'PASS' : 'FAIL');

    $c = $base();
    $c['routes']['r-a']['enabled'] = false;
    $ok = wgct_pin_set(wgct_derive($c, ['i-a']), true, true) === ['wan' => [], 'inner' => []];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: unbound tunnel is not pinned\n", $ok ? 'PASS' : 'FAIL');

    $rules = wgct_pin_rules($ps);
    $wanRule = $rules[0];
    $innerRule = $rules[1];
    $labelRe = '/^[0-9a-f]{32}$/';
    $ok = count($rules) === 2
        && $wanRule['type'] === 'block' && $wanRule['direction'] === 'out' && $wanRule['quick'] === true && $wanRule['log'] === true
        && $wanRule['interface'] === 'opt1' && $wanRule['interfacenot'] === true && $wanRule['ipprotocol'] === 'inet'
        && $wanRule['protocol'] === 'udp' && $wanRule['to'] === '198.51.100.10'
        && preg_match($labelRe, $wanRule['label']) === 1 && $wanRule['label'] === md5('wgct-pin-wan-opt1-inet')
        && $innerRule['type'] === 'block' && $innerRule['direction'] === 'out' && $innerRule['quick'] === true && $innerRule['log'] === true
        && $innerRule['interface'] === 'opt11' && $innerRule['ipprotocol'] === 'inet46'
        && $innerRule['from'] === '(self)' && $innerRule['from_not'] === true
        && preg_match($labelRe, $innerRule['label']) === 1 && $innerRule['label'] === md5('wgct-pin-inner-opt11');
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: filter rule confs for the WAN pin and the inner-source block\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgct_mss_lines($d, true) === [
        'match on wg1 inet proto tcp all scrub (max-mss 1336)',
        'match on wg1 inet6 proto tcp all scrub (max-mss 1316)',
    ];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: MSS lines both families, both directions\n", $ok ? 'PASS' : 'FAIL');

    $c = $base();
    $c['instances']['i-a']['tunneladdress'] = ['10.2.0.2/32'];
    unset($c['gateways']['tun_a-ipv6']);
    $ok = wgct_mss_lines(wgct_derive($c, ['i-a']), true) === ['match on wg1 inet proto tcp all scrub (max-mss 1336)']
        && wgct_mss_lines($d, false) === [];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: IPv4-only tunnel => one line; clamp off => none\n", $ok ? 'PASS' : 'FAIL');

    /* a disabled WAN gateway (but its interface still up) is not "unresolvable": wan_interface stays set */
    $c = $base();
    $c['gateways']['WAN_A']['disabled'] = true;
    $ok = wgct_derive($c, ['i-a'])['tunnels'][0]['wan_interface'] === 'opt1';
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: WAN gateway disabled but its interface is up => wan_interface still resolvable\n", $ok ? 'PASS' : 'FAIL');

    /* fail closed: unknown gateway on the bound route => interface-less WAN pin */
    $c = $base();
    $c['routes']['r-a']['gateway'] = 'NOPE';
    $dUnknown = wgct_derive($c, ['i-a']);
    $ok = $dUnknown['tunnels'][0]['wan_interface'] === null;
    $psUnknown = wgct_pin_set($dUnknown, true, true);
    $ok = $ok && $psUnknown === ['wan' => [['wan_if' => '', 'family' => 'inet', 'endpoints' => ['198.51.100.10']]], 'inner' => ['opt11']];
    $rulesUnknown = wgct_pin_rules($psUnknown);
    $wanRuleUnknown = $rulesUnknown[0];
    $ok = $ok && count($rulesUnknown) === 2
        && !array_key_exists('interface', $wanRuleUnknown) && !array_key_exists('interfacenot', $wanRuleUnknown)
        && $wanRuleUnknown['type'] === 'block' && $wanRuleUnknown['direction'] === 'out' && $wanRuleUnknown['quick'] === true
        && $wanRuleUnknown['log'] === true && $wanRuleUnknown['ipprotocol'] === 'inet' && $wanRuleUnknown['protocol'] === 'udp'
        && $wanRuleUnknown['to'] === '198.51.100.10' && $wanRuleUnknown['label'] === md5('wgct-pin-wan-anywhere-inet');
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: unknown gateway on the bound route => interface-less WAN pin, fail closed\n", $ok ? 'PASS' : 'FAIL');

    /* fail closed: bound WAN interface disabled => interface-less WAN pin */
    $c = $base();
    $c['interfaces']['opt1']['enable'] = false;
    $dDisabled = wgct_derive($c, ['i-a']);
    $ok = $dDisabled['tunnels'][0]['wan_interface'] === null && $dDisabled['tunnels'][0]['enforceable'] === true;
    $psDisabled = wgct_pin_set($dDisabled, true, true);
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
    $ps2 = wgct_pin_set(wgct_derive($c, ['i-a', 'i-b']), true, true);
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
    $ps3 = wgct_pin_set(wgct_derive($c, ['i-a', 'i-b']), true, true);
    $ok = $ps3 === ['wan' => [['wan_if' => 'opt1', 'family' => 'inet', 'endpoints' => ['198.51.100.10']]],
                    'inner' => ['opt11', 'opt12']];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: two tunnels sharing an endpoint => the endpoint is de-duplicated\n", $ok ? 'PASS' : 'FAIL');

    /* an interface MTU override feeds the MSS lines too */
    $c = $base();
    $c['interfaces']['opt11']['mtu'] = '1300';
    $ok = wgct_mss_lines(wgct_derive($c, ['i-a']), true) === [
        'match on wg1 inet proto tcp all scrub (max-mss 1260)',
        'match on wg1 inet6 proto tcp all scrub (max-mss 1240)',
    ];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: mtu-override MTU feeds the MSS lines\n", $ok ? 'PASS' : 'FAIL');

    /* MTU below the IPv4 minimum => no MSS lines at all, mtu-too-small raised */
    $c = $base();
    $c['instances']['i-a']['mtu'] = '500';
    $d5 = wgct_derive($c, ['i-a']);
    $t5 = $d5['tunnels'][0];
    $codes5 = array_map(function ($f) { return $f['code']; }, $t5['findings']);
    $ok = in_array('mtu-too-small', $codes5, true) && $t5['enforceable'] === true
        && wgct_mss_lines($d5, true) === [];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: MTU below the IPv4 minimum => no MSS lines, mtu-too-small raised\n", $ok ? 'PASS' : 'FAIL');

    /* MTU below the IPv6 minimum but above the IPv4 one, with an IPv6 address => only the IPv4 line, mtu-too-small raised */
    $c = $base();
    $c['instances']['i-a']['mtu'] = '1000';
    $d6 = wgct_derive($c, ['i-a']);
    $t6 = $d6['tunnels'][0];
    $codes6 = array_map(function ($f) { return $f['code']; }, $t6['findings']);
    $ok = in_array('mtu-too-small', $codes6, true)
        && wgct_mss_lines($d6, true) === ['match on wg1 inet proto tcp all scrub (max-mss 960)'];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] render: MTU below the IPv6 minimum, IPv6 address present => only the IPv4 MSS line, mtu-too-small raised\n", $ok ? 'PASS' : 'FAIL');

    /* wgct_clamp_for: the per-tunnel clamp shown in the GUI/CLI, mirroring wgct_mss_lines() */
    $ok = wgct_clamp_for($d['tunnels'][0], true) === ['v4' => 1336, 'v6' => 1316];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] clamp_for: healthy tunnel, clamp on => v4 and v6 clamps\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgct_clamp_for($d['tunnels'][0], false) === null;
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] clamp_for: healthy tunnel, clamp off => null\n", $ok ? 'PASS' : 'FAIL');

    $cDisabled = $base();
    $cDisabled['instances']['i-a']['enabled'] = false;
    $tDisabled = wgct_derive($cDisabled, ['i-a'])['tunnels'][0];
    $ok = wgct_clamp_for($tDisabled, true) === null;
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] clamp_for: not enforceable, clamp on => null\n", $ok ? 'PASS' : 'FAIL');

    $cV4Only = $base();
    $cV4Only['instances']['i-a']['tunneladdress'] = ['10.2.0.2/32'];
    unset($cV4Only['gateways']['tun_a-ipv6']);
    $tV4Only = wgct_derive($cV4Only, ['i-a'])['tunnels'][0];
    $ok = wgct_clamp_for($tV4Only, true) === ['v4' => 1336, 'v6' => null];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] clamp_for: IPv4-only tunnel, clamp on => v4 clamp, v6 omitted\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgct_clamp_for($t5, true) === ['v4' => null, 'v6' => null];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] clamp_for: MTU below the IPv4 minimum => clamp present but both families null\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgct_clamp_for($t6, true) === ['v4' => 960, 'v6' => null];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] clamp_for: MTU below the IPv6 minimum, IPv6 address present => v4 clamp only\n", $ok ? 'PASS' : 'FAIL');

    /* (o) the derived IPv6 monitor and its mode */
    $c = $base();
    $mon = wgct_derive($c, ['i-a'])['tunnels'][0];
    $c['gateways']['tun_a-ipv6']['monitor_disable'] = true;
    $off = wgct_derive($c, ['i-a'])['tunnels'][0];
    $c = $base();
    $c['gateways']['tun_a-ipv6']['monitor'] = '';
    $empty = wgct_derive($c, ['i-a'])['tunnels'][0];
    $ok = $mon['monitor6'] === '2001:db8:ffff::9' && $mon['monitor6_mode'] === 'monitored'
        && $off['monitor6'] === '' && $off['monitor6_mode'] === 'off' && $empty['monitor6'] === '' && $empty['monitor6_mode'] === 'empty';
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] derive: (o) monitor6 is the canonical monitor only when monitored; mode monitored/off/empty\n", $ok ? 'PASS' : 'FAIL');

    /* (p) the unmonitored detail says what each mode does */
    $detail6 = fn (array $t, string $code): string => implode(' ', array_column(array_filter($t['findings'], fn ($f) => $f['code'] === $code), 'detail'));
    $ok = str_contains($detail6($off, 'ipv6-unmonitored'), 'follows the IPv4 tunnel only')
        && str_contains($detail6($empty, 'ipv6-unmonitored'), 'never answers');
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] derive: (p) ipv6-unmonitored detail: off follows IPv4, empty reads down\n", $ok ? 'PASS' : 'FAIL');

    /* (q) routes switched off is fixed in the settings, not by Edit, and is not a repair reason */
    $c = $base();
    $c['ipv6_routes'] = false;
    $t = wgct_derive($c, ['i-a'])['tunnels'][0];
    $f = array_values(array_filter($t['findings'], fn ($x) => $x['code'] === 'ipv6-monitor-config'))[0] ?? ['fix' => ''];
    $ok = str_contains($f['fix'], 'IPv6 addresses and routes') && wgct_monitor6_repair_reasons($c, $t) === [];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] derive: (q) ipv6_routes off => fix names the setting; not an Edit repair reason\n", $ok ? 'PASS' : 'FAIL');

    /* (r) an IPv4-only tunnel has no IPv6 monitor state and no IPv6 findings */
    $c = $base();
    $c['instances']['i-a']['tunneladdress'] = ['10.2.0.2/32'];
    unset($c['gateways']['tun_a-ipv6']);
    $t = wgct_derive($c, ['i-a'])['tunnels'][0];
    $ok = $t['monitor6_mode'] === null && $t['monitor6'] === '' && $codes($t) === [];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] derive: (r) IPv4-only tunnel => monitor6_mode null, no IPv6 findings\n", $ok ? 'PASS' : 'FAIL');

    /* (s) without core's defaults, empty thresholds are not compared */
    $c = $base();
    unset($c['dpinger_defaults']);
    $c['gateways']['tun_a']['latencyhigh'] = '1600';
    $t = wgct_derive($c, ['i-a'])['tunnels'][0];
    $ok = $codes($t) === [] && wgct_threshold('', null) === null && wgct_threshold('', 500) === 500 && wgct_threshold('900', 500) === 900
        && wgct_threshold('x', 500) === null;
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] derive: (s) empty thresholds with no defaults are not compared; wgct_threshold\n", $ok ? 'PASS' : 'FAIL');

    /* gateway_config.php's protocol (spec 3.4.1) */
    $c = $base();
    $d = wgct_derive($c, ['i-a']);
    $ok = wgct_route_lines($d, false, true) === ['state|off'] && wgct_route_lines($d, true, false) === ['state|off'];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] routes: (a) plugin or IPv6 routes off => state|off and nothing else\n", $ok ? 'PASS' : 'FAIL');
    $ok = wgct_route_lines($d, true, true) === ['state|on', 'route|wg1|fd00::1:1/128|fd00::1:2|tun_a|tun_a-ipv6|2001:db8:ffff::9'];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] routes: (b) a monitored tunnel => its route line with the monitor\n", $ok ? 'PASS' : 'FAIL');
    $c['gateways']['tun_a-ipv6']['monitor_disable'] = true;
    $ok = wgct_route_lines(wgct_derive($c, ['i-a']), true, true) === ['state|on', 'route|wg1|fd00::1:1/128|fd00::1:2|tun_a|tun_a-ipv6|'];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] routes: (c) an unmonitored tunnel => an empty monitor field\n", $ok ? 'PASS' : 'FAIL');
    $c = $base();
    $c['interfaces']['opt11']['enable'] = false;
    $c2 = $base();
    unset($c2['interfaces']['opt11']);
    $ok = wgct_route_lines(wgct_derive($c, ['i-a']), true, true) === ['state|on', 'keep|wg1']
        && wgct_route_lines(wgct_derive($c2, ['i-a']), true, true) === ['state|on', 'keep|wg1'];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] routes: (d) a blocked tunnel (disabled or unassigned interface) => keep|wg1\n", $ok ? 'PASS' : 'FAIL');
    $c = $base();
    $c['instances']['i-a']['tunneladdress'] = ['10.2.0.2/32'];
    unset($c['gateways']['tun_a-ipv6']);
    $c2 = $base();
    $c2['instances']['i-a']['enabled'] = false;
    $ok = wgct_route_lines(wgct_derive($c, ['i-a']), true, true) === ['state|on']
        && wgct_route_lines(wgct_derive($c2, ['i-a']), true, true) === ['state|on'];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] routes: (e) an IPv4-only or disabled tunnel => no line\n", $ok ? 'PASS' : 'FAIL');

    printf("%d/%d passed\n", $total - $fail, $total);
    return $fail === 0 ? 0 : 1;
}
