<?php

/*
 * Copyright (C) 2026 cayossarian
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

/* checked first, as every require in the filter hook's chain is (render.php) */
if (!is_readable(__DIR__ . '/addr.php')) {
    throw new \RuntimeException('plugin library file addr.php missing');
}
require_once __DIR__ . '/addr.php';

/* WireGuard's MTU when neither the instance nor the interface sets one. */
const WGCT_DEFAULT_MTU = 1420;

/* where the plugin logs: core's WireGuard log, which takes the program name "wireguard" (wgct_log) */
const WGCT_LOG_PAGE = 'VPN > WireGuard > Log File';

/**
 * The logger(1) command that logs one plugin line to core's WireGuard log. Core's filter matches the
 * program name "wireguard" and cannot be extended by a plugin; logger sets that name without touching the
 * calling process's ident, which openlog() would do to core processes this runs in (the filter hook, the
 * controllers). Newlines fold into "; " so a message stays one line.
 */
function wgct_log_command(int $priority, string $message): string {
    $levels = [
        LOG_EMERG => 'emerg', LOG_ALERT => 'alert', LOG_CRIT => 'crit', LOG_ERR => 'err',
        LOG_WARNING => 'warning', LOG_NOTICE => 'notice', LOG_INFO => 'info', LOG_DEBUG => 'debug',
    ];
    $line = trim((string)preg_replace('/\s*\R\s*/', '; ', $message));
    return '/usr/bin/logger -t wireguard -p user.' . ($levels[$priority] ?? 'notice') . ' -- ' . escapeshellarg($line);
}

function wgct_log(int $priority, string $message): void {
    exec(wgct_log_command($priority, $message) . ' > /dev/null 2>&1');
}

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
    'render-failed' => [false, WGCT_LOG_PAGE . ': the plugin could not build its firewall rules at the last reload; they are missing until the next reload succeeds'],
    'render-fallback' => [false, WGCT_LOG_PAGE . ': the plugin could not build its firewall rules at the last reload, so pf keeps the pins it last put in place; the next reload that succeeds replaces them'],
    'apply-pending' => [false, 'Apply in the tunnel list (tunnel.php apply UUID) runs the apply the saved change still needs: Create or Edit saved this tunnel but its apply did not complete'],
    'core-value-invalid' => [false, 'The named settings hold a value core would not accept (a restored or hand-edited configuration): correct or delete the entry under System > Gateways, Interfaces > Assignments, Firewall > Aliases or VPN > WireGuard > Instances; the plugin ignores the value until then'],
    'core-contract' => [false, WGCT_LOG_PAGE . ': a core update changed the gateway lock or the routing alarm command the plugin copies, so its alarm replay may not match core; install a plugin update that matches this core'],
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

/* appended to a blocking finding's hint where the tunnel still renders a pin (wgct_pinned()); plain text */
const WGCT_PINS_KEPT_HINT = '; its firewall pins stay in place while this stands';

/**
 * A tunnel with a blocking finding is shown but skipped by the health mirror, the route set and the monitor
 * repair. Its WAN pins, inner-source block and MSS clamp stay (spec 2026-10-20 section 3.1 part C).
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
 * Whether the render emits at least one pin rule for the tunnel under the pin switches, so an unbound tunnel or
 * switched-off pins never claim a pin. Pure.
 *
 * @param array $t           derived record
 * @param bool  $wanPins     the wan_pins switch, false while the plugin is disabled
 * @param bool  $innerSource the inner_source switch, false while the plugin is disabled
 * @return bool
 */
function wgct_pinned(array $t, bool $wanPins, bool $innerSource): bool {
    return wgct_pin_rules(wgct_pin_set(['tunnels' => [$t]], $wanPins, $innerSource)) !== [];
}

/**
 * Whether the footprint pf enforces holds a pin for the tunnel: a WAN rule blocking one of its endpoints (on any
 * interface form), or the inner-source block on its interface. Pure.
 *
 * @param array $t     derived record
 * @param array $rules the footprint's rules
 * @return bool
 */
function wgct_footprint_pinned(array $t, array $rules): bool {
    $endpoints = array_column($t['pins']['wan'], 0);
    foreach ($rules as $rule) {
        if (isset($rule['from'])) {
            if ($t['interface'] !== null && ($rule['interface'] ?? null) === $t['interface']
                && $rule['from'] === $t['interface'] . 'ip') {
                return true;
            }
        } elseif (isset($rule['to']) && array_intersect(explode(',', $rule['to']), $endpoints) !== []) {
            return true;
        }
    }
    return false;
}

/**
 * Whether pf holds a plugin pin for the tunnel, by the render state (wgct_render_state()): the render's pins
 * under the switches, the footprint's, or none while render-failed shows. Pure; the views' `pinned`.
 *
 * @param array $t           derived record
 * @param array $state       wgct_render_state()
 * @param bool  $wanPins     the wan_pins switch, false while the plugin is disabled
 * @param bool  $innerSource the inner_source switch, false while the plugin is disabled
 * @return bool
 */
function wgct_pins_in_pf(array $t, array $state, bool $wanPins, bool $innerSource): bool {
    return match ($state['pins_from']) {
        'footprint' => wgct_footprint_pinned($t, $state['rules']),
        'none' => false,
        default => wgct_pinned($t, $wanPins, $innerSource),
    };
}

/**
 * The tunnel with WGCT_PINS_KEPT_HINT appended to each blocking finding's hint when it is pinned; unchanged
 * otherwise. Pure.
 *
 * @param array $t      derived record
 * @param bool  $pinned wgct_pinned()
 * @return array the record
 */
function wgct_pin_hint(array $t, bool $pinned): array {
    if (!$pinned) {
        return $t;
    }
    foreach ($t['findings'] as $i => $f) {
        if ($f['blocking']) {
            $t['findings'][$i]['fix'] = $f['fix'] . WGCT_PINS_KEPT_HINT;
        }
    }
    return $t;
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

/*
 * The shapes core's own models enforce (Gateways.xml and GatewayGroups.xml name Mask, AliasNameField, interface
 * assignment keys), applied again to everything a restored config.xml can carry into a pf line, a route or a
 * device name (spec 3.7, convention C7). The model masks do not run on a restored file. "D" keeps a trailing
 * newline from passing "$".
 */
const WGCT_GATEWAY_NAME_MASK = '/^[a-zA-Z0-9_-]{1,32}$/D';
const WGCT_INTERFACE_KEY_MASK = '/^[a-z0-9]+$/D';
/* an interface group's key is its name: core's GroupNameField (Firewall/FieldTypes/GroupNameField.php, lines 57-64)
 * allows letters, digits and underscores, at most 15 characters, and no leading or trailing digit */
const WGCT_INTERFACE_GROUP_MASK = '/^[a-zA-Z_]([a-zA-Z0-9_]{0,13}[a-zA-Z_])?$/D';
const WGCT_INTERFACE_DEVICE_MASK = '/^[a-zA-Z0-9_.-]*$/D';
/* AliasNameField's own shape: a letter, or an underscore before a letter, then up to 29 more word characters */
const WGCT_ALIAS_NAME_MASK = '/^([a-zA-Z]|(([_a-zA-Z][a-zA-Z0-9]|[a-zA-Z][_a-zA-Z0-9])[_a-zA-Z0-9]{0,29}))$/D';
/* the per-interface network aliases core itself adds to the model (__lan_network, __GroupA_network, ...), which the
 * field's user-facing mask would refuse: "__", a valid interface key, "_network" */
const WGCT_ALIAS_INTERNAL_MASK = '/^__(.+)_network$/D';

/**
 * @param mixed $v a value read from config
 * @return bool a gateway or gateway group name core accepts
 */
function wgct_valid_gateway_name(mixed $v): bool {
    return is_string($v) && preg_match(WGCT_GATEWAY_NAME_MASK, $v) === 1;
}

/**
 * @param mixed $v a value read from config
 * @return bool an interface assignment key (wan, lan, opt1, ...) or an interface group name
 */
function wgct_valid_interface_key(mixed $v): bool {
    return is_string($v) && (preg_match(WGCT_INTERFACE_KEY_MASK, $v) === 1 || preg_match(WGCT_INTERFACE_GROUP_MASK, $v) === 1);
}

/**
 * @param mixed $v a value read from config
 * @return bool an alias name core accepts
 */
function wgct_valid_alias_name(mixed $v): bool {
    if (!is_string($v)) {
        return false;
    }
    return preg_match(WGCT_ALIAS_NAME_MASK, $v) === 1
        || (preg_match(WGCT_ALIAS_INTERNAL_MASK, $v, $m) === 1 && wgct_valid_interface_key($m[1]));
}

/**
 * @param mixed $v a value read from config
 * @return bool a wgN device name
 */
function wgct_valid_wg_device(mixed $v): bool {
    return is_string($v) && preg_match('/^wg[0-9]+$/D', $v) === 1;
}

/**
 * @param string $instance a WireGuard instance number from the snapshot
 * @return string wgN, or '' for an instance without a valid number (the derivation's "no device")
 */
function wgct_device_name(string $instance): string {
    return $instance !== '' ? 'wg' . $instance : '';
}

/**
 * @param mixed $v a value read from config or derived from it
 * @param bool  $allowEmpty whether '' passes
 * @return bool a bare IPv4 or IPv6 address, or an IPv6 address with a link-scope zone
 */
function wgct_valid_ip_field(mixed $v, bool $allowEmpty = false): bool {
    if (!is_string($v)) {
        return false;
    }
    if ($v === '') {
        return $allowEmpty;
    }
    $bare = preg_replace('/%[A-Za-z0-9_.]+$/D', '', $v);
    return $bare !== null && filter_var($bare, FILTER_VALIDATE_IP) !== false;
}

/**
 * The snapshot with every value core would reject removed (spec 3.7). Pure, so the self-tests reach it with
 * hand-built input; wgct_core_snapshot() hands it the raw values. What fails is dropped or blanked, and 'invalid'
 * names each affected field once, never the value, because findings reach the GUI.
 *
 *  - instance numbers that are not all digits become '' (the derivation's "no device")
 *  - gateways and gateway groups whose name fails core's mask, and gateways whose interface key does, are dropped;
 *    a failing group member is dropped from its group
 *  - interfaces whose key or device name fails are dropped
 *  - alias names that fail core's mask are dropped
 *
 * @param array $raw the snapshot as read from config; 'aliases' is optional
 * @return array the same shape, plus 'aliases' (list) and 'invalid' (list of field names)
 */
function wgct_snapshot_validate(array $raw): array {
    $invalid = [];
    $flag = function (string $field) use (&$invalid): void {
        if (!in_array($field, $invalid, true)) {
            $invalid[] = $field;
        }
    };
    $core = $raw;
    foreach ($raw['instances'] as $uuid => $inst) {
        if (!ctype_digit((string)$inst['instance'])) {
            $core['instances'][$uuid]['instance'] = '';
            $flag('instance number');
        }
    }
    $core['interfaces'] = [];
    foreach ($raw['interfaces'] as $key => $if) {
        if (!wgct_valid_interface_key((string)$key)) {
            $flag('interface key');
        } elseif (preg_match(WGCT_INTERFACE_DEVICE_MASK, $if['if']) !== 1) {
            $flag('interface device');
        } else {
            $core['interfaces'][$key] = $if;
        }
    }
    $core['gateways'] = [];
    foreach ($raw['gateways'] as $name => $g) {
        if (!wgct_valid_gateway_name((string)$name)) {
            $flag('gateway name');
        } elseif (!wgct_valid_interface_key($g['interface'])) {
            $flag('interface key');
        } else {
            $core['gateways'][$name] = $g;
        }
    }
    $core['groups'] = [];
    foreach ($raw['groups'] as $name => $members) {
        if (!wgct_valid_gateway_name((string)$name)) {
            $flag('gateway name');
            continue;
        }
        $kept = array_values(array_filter($members, 'wgct_valid_gateway_name'));
        if (count($kept) !== count($members)) {
            $flag('gateway name');
        }
        $core['groups'][$name] = $kept;
    }
    $core['aliases'] = [];
    foreach ($raw['aliases'] ?? [] as $alias) {
        if (wgct_valid_alias_name($alias)) {
            $core['aliases'][] = $alias;
        } else {
            $flag('alias name');
        }
    }
    $core['invalid'] = $invalid;
    return $core;
}

/**
 * Everything the derivation reads from core config, through models, with the values core would reject removed
 * (wgct_snapshot_validate()).
 *
 * @return array see wgct_derive()
 */
function wgct_core_snapshot() {
    return wgct_snapshot_validate(wgct_core_read(true));
}

/**
 * The tunnels' part of the snapshot alone: instances, peers, interfaces and gateways, with the routes, outbound NAT,
 * gateway groups, aliases, DNS servers and forwarders left empty. The models of those ask configd while they load
 * (on 26.7.7 the routes and aliases 10 s each, outbound NAT 120 s and the gateway groups 100 s when configd does not
 * answer), so the package removal, which needs only each tunnel's gateways, reads this (ruling R29). Derived from
 * it, a tunnel's devices and gateways are as from the whole snapshot; its binding and findings are not.
 *
 * @return array see wgct_derive()
 */
function wgct_core_tunnel_snapshot(): array {
    return wgct_snapshot_validate(wgct_core_read(false));
}

/**
 * @param bool $context also the models that ask configd while they load (see wgct_core_tunnel_snapshot())
 * @return array the snapshot as read, before wgct_snapshot_validate()
 */
function wgct_core_read(bool $context): array {
    $root = Config::getInstance()->object();
    $core = [
        'instances' => [], 'peers' => [], 'interfaces' => [], 'routes' => [], 'gateways' => [],
        'snat' => [], 'groups' => [], 'dns_servers' => [], 'forwarders' => [], 'aliases' => [],
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
    if ($context) {
        wgct_core_read_context($core, $root);
    }
    /* the plugin's route switch (the monitor routes, spec 3.5) and core's dpinger defaults, read once here so
     * the derivation stays pure */
    $core['ipv6_routes'] = (string)(new \OPNsense\WGClientTunnels\WGClientTunnels())->ipv6_routes === '1';
    $core['dpinger_defaults'] = [];
    try {
        if (is_callable([\OPNsense\Routing\FieldTypes\GatewayField::class, 'getDpingerDefaults'])) {
            $core['dpinger_defaults'] = wgct_dpinger_defaults(\OPNsense\Routing\FieldTypes\GatewayField::getDpingerDefaults());
        }
    } catch (\Throwable $e) {
        /* advisory only: a core that no longer offers the defaults must not break the filter and mirror paths */
    }
    return $core;
}

/**
 * The routes, outbound NAT, gateway groups, DNS servers, aliases and forwarders, into $core.
 *
 * @param array             $core the snapshot being read, updated in place
 * @param \SimpleXMLElement $root config.xml
 */
function wgct_core_read_context(array &$core, \SimpleXMLElement $root): void {
    foreach ((new \OPNsense\Routes\Route())->route->iterateItems() as $uuid => $r) {
        $core['routes'][$uuid] = [
            'network' => (string)$r->network,
            'gateway' => (string)$r->gateway,
            'enabled' => (string)$r->enabled === '1',
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
    foreach ((new \OPNsense\Firewall\Alias())->aliases->alias->iterateItems() as $alias) {
        $core['aliases'][] = (string)$alias->name;
    }
    foreach ((new \OPNsense\Unbound\Unbound())->dots->dot->iterateItems() as $dot) {
        if ((string)$dot->enabled === '1' && (string)$dot->server !== '') {
            $core['forwarders'][] = (string)$dot->server;
        }
    }
}

/* the settings model version whose migration (M3_1_0) moves the managed list and the holds into the engine model */
const WGCT_SETTINGS_MIGRATED_VERSION = '3.1.0';

/* what a state-changing run says while that migration is pending (ruling R37) */
const WGCT_MIGRATION_PENDING = 'the plugin settings are not migrated to 3.1.0 yet (the package install runs run_migrations.php);'
    . ' nothing is held, released or written until they are';

/**
 * Whether the settings node in $root still waits for its 3.1.0 migration: between pkg installing 3.8's files and
 * the package's run_migrations.php, or for good when that migration failed. The node's stored version decides: one
 * below 3.1.0, or none (core reads that as 0.0.0), is pending. A box with no settings node (a new install) has
 * nothing to carry over and is not. Pure.
 *
 * @param \SimpleXMLElement $root config.xml's root
 * @return bool
 */
function wgct_settings_pending(\SimpleXMLElement $root): bool {
    if (!isset($root->OPNsense->WGClientTunnels)) {
        return false;
    }
    $stored = (string)($root->OPNsense->WGClientTunnels['version'] ?? '');
    return version_compare($stored !== '' ? $stored : '0.0.0', WGCT_SETTINGS_MIGRATED_VERSION, '<');
}

/**
 * The managed list as 3.7_1 stored it in the 3.0.0 settings node: M3_1_0's own source, split as 3.7_1 split it, so
 * a render while the migration is pending pins what 3.7_1 pinned. No list stored is none. Pure.
 *
 * @param \SimpleXMLElement $root config.xml's root
 * @return list<string> instance uuids, in order, as stored
 * @throws \RuntimeException when the node holds more than one list, or a list that is not one text value
 */
function wgct_legacy_managed(\SimpleXMLElement $root): array {
    $node = $root->OPNsense->WGClientTunnels;
    if (!isset($node->managed)) {
        return [];
    }
    if (count($node->managed) !== 1 || $node->managed->children()->count() !== 0) {
        throw new \RuntimeException('the 3.0.0 settings\' managed list cannot be read as one list');
    }
    return wgct_split_csv((string)$node->managed);
}

/**
 * The managed list wgct_managed() returns, from $root: the legacy one while the migration is pending (the engine
 * model is not read: it does not hold the list yet), else $engine's. Pure but for $engine.
 *
 * @param \SimpleXMLElement        $root   config.xml's root
 * @param callable(): list<string> $engine the engine model's list
 * @return list<string> instance uuids
 * @throws \RuntimeException when the migration is pending and the legacy list cannot be read
 */
function wgct_managed_in(\SimpleXMLElement $root, callable $engine): array {
    return wgct_settings_pending($root) ? wgct_legacy_managed($root) : $engine();
}

/**
 * @return bool whether config.xml's settings node waits for its 3.1.0 migration (wgct_settings_pending()): every
 *              state-changing run refuses then (ruling R37)
 */
function wgct_migration_pending(): bool {
    return wgct_settings_pending(Config::getInstance()->object());
}

/**
 * The WireGuard instances the plugin manages, in order, from the engine model (spec 3.5): the API cannot edit it.
 * While the 3.1.0 migration is pending, the list 3.7_1 stored in the settings node, which the migration carries
 * over (wgct_managed_in(), ruling R37): a render in that window pins what 3.7_1 pinned, and one that cannot read it
 * fails into the footprint.
 *
 * @return list<string> instance uuids
 * @throws \RuntimeException when the migration is pending and the legacy list cannot be read
 */
function wgct_managed(): array {
    return wgct_managed_in(Config::getInstance()->object(),
        fn (): array => wgct_split_csv((new \OPNsense\WGClientTunnels\Engine())->managed->getValue()));
}

/**
 * Core's dpinger defaults as the derivation uses them: the threshold entries that are whole numbers. Pure.
 *
 * @param mixed $raw whatever GatewayField::getDpingerDefaults() returned
 * @return array<string, int> threshold name => default; [] when $raw is unusable
 */
function wgct_dpinger_defaults(mixed $raw): array {
    if (!is_array($raw)) {
        return [];
    }
    $defaults = [];
    foreach (['latencylow', 'latencyhigh', 'losslow', 'losshigh'] as $name) {
        $v = $raw[$name] ?? null;
        if (is_int($v) || (is_string($v) && ctype_digit($v))) {
            $defaults[$name] = (int)$v;
        }
    }
    return $defaults;
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
    if (!empty($core['invalid'])) {
        $global[] = wgct_finding('core-value-invalid', 'ignored: ' . implode(', ', $core['invalid']));
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
        if ($inst['instance'] !== '') {
            $out[wgct_device_name($inst['instance'])] = true;
        }
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
 * Where a binding route's WAN pins its endpoint. Fail closed: the interface only when the gateway is saved, its
 * interface resolves and is up, and it can carry the endpoint's family (an IPv6 endpoint needs an IPv6 gateway
 * that is not on a 6rd/6to4 WAN; IPv4 keeps core's rule, RFC 5549); otherwise null, the block-everywhere form.
 * A disabled gateway on an enabled interface keeps that interface. Pure.
 *
 * @param array  $core   wgct_core_snapshot()
 * @param string $wan    the binding route's gateway name
 * @param string $family the endpoint's family, inet or inet6
 * @return array{interface: ?string, problem: ?string} the WAN interface key, and the wan-unavailable detail or null
 */
function wgct_binding_target(array $core, string $wan, string $family): array {
    $wanGw = $core['gateways'][$wan] ?? null;
    if ($wanGw === null) {
        return ['interface' => null, 'problem' => "{$wan} is not a saved gateway; save it once on System > Gateways"];
    }
    $wanIf = $core['interfaces'][$wanGw['interface']] ?? null;
    if ($family === 'inet6' && $wanGw['ipprotocol'] !== 'inet6') {
        return ['interface' => null, 'problem' => "{$wan} is IPv4; an IPv6 endpoint needs an IPv6 gateway"];
    }
    if ($family === 'inet6' && in_array($wanIf['ipaddrv6'] ?? '', ['6rd', '6to4'], true)) {
        return ['interface' => null, 'problem' => "{$wan} is on a 6rd/6to4 WAN; IPv6 over 6rd/6to4 is not supported as a binding"];
    }
    $up = $wanIf !== null && $wanIf['enable'];
    return [
        'interface' => $up ? $wanGw['interface'] : null,
        'problem' => $wanGw['disabled'] || !$up ? "{$wan} or its interface is disabled" : null,
    ];
}

/**
 * The WAN pins of an instance's peers (spec 2026-10-20 section 3.1 part C): every peer, in order, whose server
 * address is IPv4 or global IPv6 (wgct_endpoint_ip()) and has a binding route. A hostname, a ULA or a link-local
 * endpoint, or one with no binding route, gets no pin and stops no other peer's. Pure.
 *
 * @param array        $core  wgct_core_snapshot()
 * @param list<string> $peers the instance's peer uuids
 * @param array        $ctx   indexes built by wgct_derive()
 * @return list<array{0: string, 1: string}> [canonical endpoint, WAN interface key or '' (block everywhere)]
 */
function wgct_peer_pins(array $core, array $peers, array $ctx): array {
    $pins = [];
    foreach ($peers as $peerUuid) {
        $peer = $core['peers'][$peerUuid] ?? null;
        $ip = $peer !== null ? wgct_endpoint_ip($peer['serveraddress']) : null;
        $family = $ip !== null ? wgct_ip_family($ip) : null;
        $wan = $family !== null ? ($ctx['binding_routes'][$family][$ip] ?? null) : null;
        if ($wan !== null) {
            $pins[] = [$ip, wgct_binding_target($core, $wan, $family)['interface'] ?? ''];
        }
    }
    return $pins;
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
        'pins' => ['wan' => [], 'inner' => false],
    ];
    $inst = $core['instances'][$uuid] ?? null;
    if ($inst === null) {
        $t['findings'][] = wgct_finding('instance-missing', "no WireGuard instance {$uuid}");
        return $t;
    }
    $t['name'] = $inst['name'];
    $t['enabled'] = $inst['enabled'];
    $t['device'] = wgct_device_name($inst['instance']);

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
            $t['bound_wan'] = $ctx['binding_routes'][$family][$ip];
            $target = wgct_binding_target($core, $t['bound_wan'], $family);
            $t['wan_interface'] = $target['interface'];
            if ($target['problem'] !== null) {
                $t['findings'][] = wgct_finding('wan-unavailable', $target['problem']);
            }
        }
    }
    /* the WAN pins of every bound peer, whatever the findings; an instance with no device runs nothing to pin */
    if ($t['enabled'] && wgct_valid_wg_device($t['device'])) {
        $t['pins']['wan'] = wgct_peer_pins($core, $inst['peers'], $ctx);
    }

    /* everything else hangs off the interface assignment */
    $opt = $ctx['opt_by_device'][$t['device']] ?? null;
    if ($opt === null) {
        $t['findings'][] = wgct_finding('not-assigned', $t['device'] === ''
            ? 'the instance has no valid number, so no wgN device' : "{$t['device']} has no interface assignment");
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
    /* the inner-source block of a bound tunnel, whatever the findings; an unbound one stays unpinned (spec 2) */
    $t['pins']['inner'] = $t['pins']['wan'] !== [] && $if['enable'];

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
        if (!wgct_valid_wg_device($t['device'])) {
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
        /* the same shapes the snapshot enforced, again at the point the line is written (spec 3.7) */
        $address = explode('/', (string)$t['ipv6_address'], 2);
        if (!wgct_valid_ip_field($address[0]) || (isset($address[1]) && preg_match('/^[0-9]{1,3}$/D', $address[1]) !== 1)
            || !wgct_valid_ip_field($t['ipv6_next_hop']) || !wgct_valid_ip_field($t['monitor6'], true)
            || !wgct_valid_gateway_name($t['gw4']) || !wgct_valid_gateway_name($t['gw6'])) {
            continue;
        }
        $lines[] = implode('|', array_map($clean,
            ['route', $t['device'], $t['ipv6_address'], $t['ipv6_next_hop'], $t['gw4'], $t['gw6'], $t['monitor6']]));
    }
    return $lines;
}

/**
 * gateway_config.php's output while the 3.1.0 migration is pending (ruling R37): `state|pending` in place of the
 * state line, so wgct.sh's route set changes nothing, and the route lines kept for its status listing. Pure.
 *
 * @param list<string> $lines wgct_route_lines()
 * @return list<string>
 */
function wgct_route_lines_pending(array $lines): array {
    return array_merge(['state|pending'], array_slice($lines, 1));
}

/**
 * What the WAN pins (R1) and inner-source blocks (R7) cover, from each record's
 * pins (spec 2026-10-20 section 3.1 part C): a bound tunnel is pinned whatever
 * its findings, for every bound peer. Pure; canonical order so two sets compare
 * with ===. A pin whose WAN cannot be resolved to an enabled interface keeps
 * its entry with wan_if '' -- fail closed, so the handshake is blocked on every
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
        if ($innerSource && $t['pins']['inner'] && wgct_valid_interface_key($t['interface'])) {
            $inner[] = $t['interface'];
        }
        if (!$wanPins) {
            continue;
        }
        foreach ($t['pins']['wan'] as [$ip, $wanIf]) {
            if (!wgct_valid_ip_field($ip)) {
                continue;
            }
            $family = filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? 'inet6' : 'inet';
            /* a WAN interface key that fails the mask is treated as unresolved: the handshake is blocked everywhere */
            $wan[(wgct_valid_interface_key($wanIf) ? $wanIf : '') . '|' . $family][] = $ip;
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
        $w['endpoints'] = array_values(array_filter($w['endpoints'], 'wgct_valid_ip_field'));
        if ($w['endpoints'] === []) {
            continue;
        }
        if ($w['wan_if'] === '' || !wgct_valid_interface_key($w['wan_if'])) {
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
        if (!wgct_valid_interface_key($opt)) {
            continue;
        }
        /* only the tunnel's own addresses, not (self): every tunnel's address is the firewall's, so (self) let one
         * tunnel's NATed source out of another, and a provider that learns the client address from traffic then
         * sends that tunnel's replies to the wrong address.
         * The label names the source too, so pf still holding an older form reads as missing to freshness. */
        $from = $opt . 'ip';
        $rules[] = [
            'type' => 'block', 'direction' => 'out', 'quick' => true, 'log' => true,
            'interface' => $opt, 'ipprotocol' => 'inet46', 'from' => $from, 'from_not' => true,
            'label' => md5('wgct-pin-inner-' . $opt . '-' . $from),
            'descr' => "WireGuard Upstream Tunnels: only traffic NATed to this tunnel's own address may enter it",
        ];
    }
    return $rules;
}

/**
 * Whether a tunnel's device gets the MSS clamp (spec 2026-10-20 section 3.1 part C): an enabled instance whose
 * valid wgN device has an interface assignment, which gives its MTU, whatever its findings. The clamp is not a
 * pin, so a tunnel with no binding route gets it too. Pure.
 *
 * @param array $t derived record
 * @return bool
 */
function wgct_mss_applies(array $t): bool {
    return $t['enabled'] && $t['interface'] !== null && wgct_valid_wg_device($t['device']);
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
        if (!wgct_mss_applies($t)) {
            continue;
        }
        $n = (int)substr($t['device'], 2);
        $mtu = (int)$t['mtu'];
        if ($mtu >= 576) {
            $lines[] = sprintf('match on wg%d inet proto tcp all scrub (max-mss %d)', $n, $mtu - 40);
        }
        if ($t['ipv6_address'] !== null && $mtu >= 1280) {
            $lines[] = sprintf('match on wg%d inet6 proto tcp all scrub (max-mss %d)', $n, $mtu - 60);
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
 * off or wgct_mss_applies() is false, since nothing would be rendered for
 * it either way.
 *
 * @param array $t        derived tunnel record
 * @param bool  $mssClamp the mss_clamp switch
 * @return array|null ['v4' => int|null, 'v6' => int|null], or null
 */
function wgct_clamp_for(array $t, bool $mssClamp): ?array {
    if (!$mssClamp || !wgct_mss_applies($t)) {
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
        && $innerRule['from'] === 'opt11ip' && $innerRule['from_not'] === true
        && preg_match($labelRe, $innerRule['label']) === 1 && $innerRule['label'] === md5('wgct-pin-inner-opt11-opt11ip');
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
    printf("[%s] clamp_for: disabled instance, clamp on => null\n", $ok ? 'PASS' : 'FAIL');

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

    /* (t) core's dpinger defaults are read fail-soft: only the int thresholds survive */
    $ok = wgct_dpinger_defaults(null) === [] && wgct_dpinger_defaults('x') === []
        && wgct_dpinger_defaults(['latencyhigh' => 'x', 'losshigh' => '', 'losslow' => null, 'latencylow' => 2.5]) === []
        && wgct_dpinger_defaults(['latencyhigh' => 500, 'losshigh' => '20', 'interval' => 1, 'other' => 7])
            === ['latencyhigh' => 500, 'losshigh' => 20];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] derive: (t) wgct_dpinger_defaults keeps int thresholds, drops the rest\n", $ok ? 'PASS' : 'FAIL');

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

    /* values from a restored config (spec 3.7): validated again where the snapshot is built and where they are used */
    $invalidOf = fn (array $core): array => wgct_snapshot_validate($core);
    $findingFor = fn (array $core, string $field): bool => in_array($field, $core['invalid'] ?? [], true)
        && count(array_filter(wgct_derive($core, ['i-a'])['global'], fn (array $f): bool => $f['code'] === 'core-value-invalid'
            && !$f['blocking'] && str_contains($f['detail'], $field))) === 1;
    $raw = $base();
    $raw['aliases'] = ['hosts_alias'];
    $c = $invalidOf($raw);
    $ok = $c['invalid'] === [] && $c['gateways'] === $raw['gateways'] && $c['interfaces'] === $raw['interfaces']
        && $c['aliases'] === ['hosts_alias'] && $c['groups'] === $raw['groups']
        && wgct_derive($c, ['i-a'])['global'] === [] && $codes(wgct_derive($c, ['i-a'])['tunnels'][0]) === [];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] values: a valid snapshot passes unchanged, no core-value-invalid\n", $ok ? 'PASS' : 'FAIL');
    $raw = $base();
    $raw['instances']['i-a']['instance'] = "1\nblock all";
    $c = $invalidOf($raw);
    $d = wgct_derive($c, ['i-a']);
    $ok = $c['instances']['i-a']['instance'] === '' && $d['tunnels'][0]['device'] === '' && $findingFor($c, 'instance number')
        && !wgct_derive($c, ['i-a'])['tunnels'][0]['enforceable']
        && wgct_mss_lines($d, true) === [] && wgct_pin_set($d, true, true) === ['wan' => [], 'inner' => []]
        && wgct_route_lines($d, true, true) === ['state|on'];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] values: instance \"1\\nblock all\" => device '', finding, no MSS line, no pin, no route line\n", $ok ? 'PASS' : 'FAIL');
    $raw = $base();
    $raw['instances']['i-a']['instance'] = '';
    $c = $invalidOf($raw);
    $ok = $c['instances']['i-a']['instance'] === '' && wgct_derive($c, ['i-a'])['tunnels'][0]['device'] === ''
        && !isset(wgct_wg_devices($c)['wg']);
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] values: an empty instance number is no device either\n", $ok ? 'PASS' : 'FAIL');
    $raw = $base();
    $raw['gateways']['x;y'] = $gw(['interface' => 'opt1', 'gateway' => '192.0.2.77']);
    $raw['groups']['grp_a'][] = 'x;y';
    $c = $invalidOf($raw);
    $ok = !isset($c['gateways']['x;y']) && isset($c['gateways']['tun_a']) && !in_array('x;y', $c['groups']['grp_a'], true)
        && $findingFor($c, 'gateway name');
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] values: gateway name x;y => dropped, finding\n", $ok ? 'PASS' : 'FAIL');
    $raw = $base();
    $raw['gateways']['too_long'] = $gw(['interface' => 'opt1']);
    $raw['gateways'][str_repeat('g', 33)] = $gw(['interface' => 'opt1']);
    $raw['gateways']['ok-32_' . str_repeat('g', 26)] = $gw(['interface' => 'opt1']);
    $c = $invalidOf($raw);
    $ok = isset($c['gateways']['too_long']) && !isset($c['gateways'][str_repeat('g', 33)])
        && isset($c['gateways']['ok-32_' . str_repeat('g', 26)]) && $findingFor($c, 'gateway name');
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] values: gateway names follow core's mask (hyphen, 32 characters at most)\n", $ok ? 'PASS' : 'FAIL');
    $raw = $base();
    $raw['interfaces']['opt1;'] = ['if' => 'igc9', 'enable' => true, 'mtu' => '', 'mss' => '', 'descr' => ''];
    $raw['gateways']['stray'] = $gw(['interface' => 'opt1;']);
    $c = $invalidOf($raw);
    $ok = !isset($c['interfaces']['opt1;']) && !isset($c['gateways']['stray']) && isset($c['interfaces']['opt1'])
        && $findingFor($c, 'interface key');
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] values: interface key opt1; => dropped (and a gateway on it), finding\n", $ok ? 'PASS' : 'FAIL');
    $raw = $base();
    $raw['interfaces']['opt11']['if'] = "wg1\nblock all";
    $c = $invalidOf($raw);
    $ok = !isset($c['interfaces']['opt11']) && $findingFor($c, 'interface device');
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] values: an interface whose device name carries a newline => dropped, finding\n", $ok ? 'PASS' : 'FAIL');
    $raw = $base();
    $raw['aliases'] = ['hosts_alias', 'bad alias', 'LocalNetworks', "x\ny", '1abc', '__lan_network', '__opt1_network', '__x y_network'];
    $c = $invalidOf($raw);
    $ok = $c['aliases'] === ['hosts_alias', 'LocalNetworks', '__lan_network', '__opt1_network'] && $findingFor($c, 'alias name');
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] values: an alias name with a space => dropped, finding\n", $ok ? 'PASS' : 'FAIL');
    $raw = $base();
    $raw['gateways']['bad;'] = $gw(['interface' => 'opt1']);
    $raw['aliases'] = ['bad alias'];
    $raw['interfaces']['opt1;'] = ['if' => 'igc9', 'enable' => true, 'mtu' => '', 'mss' => '', 'descr' => ''];
    $c = $invalidOf($raw);
    $g = wgct_derive($c, ['i-a'])['global'];
    $ok = count($g) === 1 && $g[0]['code'] === 'core-value-invalid' && !$g[0]['blocking']
        && str_contains($g[0]['detail'], 'gateway name') && str_contains($g[0]['detail'], 'alias name')
        && str_contains($g[0]['detail'], 'interface key') && !str_contains($g[0]['detail'], 'bad;')
        && !str_contains($g[0]['detail'], 'bad alias') && !str_contains($g[0]['detail'], 'opt1;');
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] values: one global finding names the fields, never the values\n", $ok ? 'PASS' : 'FAIL');
    /* interface groups (core: Firewall/Group.xml ifname is a GroupNameField): mixed case, underscores, 15 characters at
     * most, no leading or trailing digit; the key and the device name are the group name */
    $group = fn (string $n): array => ['if' => $n, 'enable' => true, 'mtu' => '', 'mss' => '', 'descr' => ''];
    $raw = $base();
    $raw['interfaces']['GroupA'] = $group('GroupA');
    $raw['interfaces']['Group_B'] = $group('Group_B');
    $raw['aliases'] = ['__GroupA_network', '__Group_B_network', '__lan_network'];
    $c = $invalidOf($raw);
    $ok = $c['invalid'] === [] && $c['interfaces'] === $raw['interfaces'] && $c['aliases'] === $raw['aliases']
        && wgct_derive($c, ['i-a'])['global'] === [];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] values: interface groups GroupA and Group_B and their __<group>_network aliases pass, no finding\n", $ok ? 'PASS' : 'FAIL');
    $raw = $base();
    foreach (['Group A', 'Group;B', 'Grp9', '9Grp', 'GroupNameTooLong', 'Group-B', "GroupA\n"] as $bad) {
        $raw['interfaces'][$bad] = $group($bad);
    }
    $raw['interfaces']['Fifteen_Chars_ab'] = $group('Fifteen_Chars_ab');
    $raw['interfaces']['Fifteen_Chars_a'] = $group('Fifteen_Chars_a');
    $raw['aliases'] = ['__Group A_network', '__Group;B_network', '__Grp9_network', '__GroupNameTooLong_network', '__GroupA_net'];
    $c = $invalidOf($raw);
    $ok = array_keys($c['interfaces']) === array_merge(array_keys($base()['interfaces']), ['Fifteen_Chars_a'])
        && $c['aliases'] === [] && $findingFor($c, 'interface key') && $findingFor($c, 'alias name');
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] values: a group key or alias with a space, semicolon, edge digit or more than 15 characters => dropped, finding\n", $ok ? 'PASS' : 'FAIL');
    $raw = $base();
    $raw['groups']['bad grp'] = ['tun_a'];
    $raw['groups']['grp_ok'] = ['tun_a', 'x;y'];
    $c = $invalidOf($raw);
    $ok = !isset($c['groups']['bad grp']) && $c['groups']['grp_ok'] === ['tun_a'] && $findingFor($c, 'gateway name');
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] values: a gateway group name with a space => dropped, finding\n", $ok ? 'PASS' : 'FAIL');
    /* use-time checks on hand-built records: nothing a hostile field carries reaches a line */
    $d = wgct_derive($invalidOf($base()), ['i-a']);
    $d['tunnels'][0]['device'] = "wg1\nblock all";
    $d['tunnels'][0]['interface'] = 'opt11;';
    $ok = wgct_mss_lines($d, true) === [] && wgct_route_lines($d, true, true) === ['state|on']
        && wgct_pin_set($d, true, true)['inner'] === [];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] values: a hostile device or interface key on a derived record => no MSS line, route line or inner pin\n", $ok ? 'PASS' : 'FAIL');
    $d = wgct_derive($invalidOf($base()), ['i-a']);
    $d['tunnels'][0]['gw4'] = 'tun a';
    $e = wgct_derive($invalidOf($base()), ['i-a']);
    $e['tunnels'][0]['ipv6_next_hop'] = "fd00::1:2\nblock";
    $f = wgct_derive($invalidOf($base()), ['i-a']);
    $f['tunnels'][0]['monitor6'] = '2001:db8::9; reboot';
    $h = wgct_derive($invalidOf($base()), ['i-a']);
    $h['tunnels'][0]['ipv6_address'] = 'fd00::1:1/12x';
    $ok = wgct_route_lines($d, true, true) === ['state|on'] && wgct_route_lines($e, true, true) === ['state|on']
        && wgct_route_lines($f, true, true) === ['state|on'] && wgct_route_lines($h, true, true) === ['state|on'];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] values: a route line with a failing field is not emitted\n", $ok ? 'PASS' : 'FAIL');
    $d = wgct_derive($invalidOf($base()), ['i-a']);
    $d['tunnels'][0]['mtu'] = '1376 -x';
    $d['tunnels'][0]['pins']['wan'][0][1] = 'opt1;';
    $ok = wgct_mss_lines($d, true) === ['match on wg1 inet proto tcp all scrub (max-mss 1336)',
                                        'match on wg1 inet6 proto tcp all scrub (max-mss 1316)']
        && wgct_pin_set($d, true, false)['wan'] === [['wan_if' => '', 'family' => 'inet', 'endpoints' => ['198.51.100.10']]];
    $fail += $ok ? 0 : 1; $total++;
    printf("[%s] values: a non-numeric MTU is cast, and a hostile WAN interface key pins fail-closed\n", $ok ? 'PASS' : 'FAIL');

    /* pin by binding, not by enforceability (spec 2026-10-20 3.1 part C): a bound tunnel keeps its pins while a
     * blocking finding stands, for every peer */
    $p = ['fail' => 0, 'total' => 0];
    $safely = function (callable $case): bool {
        try {
            return $case();
        } catch (\Throwable $e) {
            printf("       threw %s: %s\n", get_class($e), $e->getMessage());
            return false;
        }
    };
    $both = ['match on wg1 inet proto tcp all scrub (max-mss 1336)', 'match on wg1 inet6 proto tcp all scrub (max-mss 1316)'];
    $pinA = ['wan_if' => 'opt1', 'family' => 'inet', 'endpoints' => ['198.51.100.10']];
    /* a second peer, 198.51.100.11, bound by its own /32 to WAN_B on the wan interface */
    $twoPeers = function (array $c) use ($gw): array {
        $c['instances']['i-a']['peers'][] = 'p-b';
        $c['peers']['p-b'] = ['name' => 'tun_a_b', 'serveraddress' => '198.51.100.11', 'serverport' => '51821'];
        $c['gateways']['WAN_B'] = $gw(['interface' => 'wan', 'gateway' => '192.0.2.129']);
        $c['routes']['r-b'] = ['network' => '198.51.100.11/32', 'gateway' => 'WAN_B', 'enabled' => true];
        return $c;
    };
    wgct_check($p, 'pins: (a) not-single-peer with two peers, both bound => a WAN pin for each, the inner block and the MSS clamp',
        $safely(function () use ($base, $twoPeers, $codes, $pinA, $both): bool {
            $d = wgct_derive($twoPeers($base()), ['i-a']);
            $t = $d['tunnels'][0];
            return $codes($t) === ['not-single-peer'] && $t['enforceable'] === false
                && $t['pins'] === ['wan' => [['198.51.100.10', 'opt1'], ['198.51.100.11', 'wan']], 'inner' => true]
                && wgct_pin_set($d, true, true) === ['wan' => [$pinA, ['wan_if' => 'wan', 'family' => 'inet', 'endpoints' => ['198.51.100.11']]],
                                                     'inner' => ['opt11']]
                && count(wgct_pin_rules(wgct_pin_set($d, true, true))) === 3 && wgct_mss_lines($d, true) === $both;
        }));
    wgct_check($p, 'pins: (b) interface-disabled => the WAN pin stays, no inner block (core comments it out), the MSS clamp stays',
        $safely(function () use ($base, $codes, $pinA, $both): bool {
            $c = $base();
            $c['interfaces']['opt11']['enable'] = false;
            $d = wgct_derive($c, ['i-a']);
            return $codes($d['tunnels'][0]) === ['interface-disabled']
                && $d['tunnels'][0]['pins'] === ['wan' => [['198.51.100.10', 'opt1']], 'inner' => false]
                && wgct_pin_set($d, true, true) === ['wan' => [$pinA], 'inner' => []] && wgct_mss_lines($d, true) === $both;
        }));
    wgct_check($p, 'pins: (c) ambiguous-gateway => the WAN pin, the inner block and the MSS clamp stay',
        $safely(function () use ($base, $gw, $codes, $pinA, $both): bool {
            $c = $base();
            $c['gateways']['tun_a_2'] = $gw(['interface' => 'opt11']);
            $d = wgct_derive($c, ['i-a']);
            return $codes($d['tunnels'][0]) === ['ambiguous-gateway'] && $d['tunnels'][0]['enforceable'] === false
                && wgct_pin_set($d, true, true) === ['wan' => [$pinA], 'inner' => ['opt11']] && wgct_mss_lines($d, true) === $both;
        }));
    wgct_check($p, 'pins: (d) unbound => no pin, with or without a blocking finding; the MSS clamp is not a pin and stays',
        $safely(function () use ($base, $twoPeers, $codes, $both): bool {
            $c = $base();
            $c['routes']['r-a']['enabled'] = false;
            $d = wgct_derive($c, ['i-a']);
            $c2 = $twoPeers($c);
            $c2['routes']['r-b']['enabled'] = false;
            $d2 = wgct_derive($c2, ['i-a']);
            return $codes($d['tunnels'][0]) === ['unbound'] && $d['tunnels'][0]['pins'] === ['wan' => [], 'inner' => false]
                && wgct_pin_set($d, true, true) === ['wan' => [], 'inner' => []] && wgct_mss_lines($d, true) === $both
                && $codes($d2['tunnels'][0]) === ['not-single-peer'] && wgct_pin_set($d2, true, true) === ['wan' => [], 'inner' => []];
        }));
    wgct_check($p, 'pins: (e) disabled instance => no pin, no MSS line, even with a blocking finding',
        $safely(function () use ($base, $twoPeers): bool {
            $c = $twoPeers($base());
            $c['instances']['i-a']['enabled'] = false;
            $d = wgct_derive($c, ['i-a']);
            return $d['tunnels'][0]['pins'] === ['wan' => [], 'inner' => false]
                && wgct_pin_set($d, true, true) === ['wan' => [], 'inner' => []] && wgct_mss_lines($d, true) === [];
        }));
    wgct_check($p, 'pins: (f) a binding via a disabled WAN interface or an unsaved gateway => the interface-less block, per peer',
        $safely(function () use ($base, $twoPeers): bool {
            $c = $base();
            $c['interfaces']['opt1']['enable'] = false;
            $d = wgct_derive($c, ['i-a']);
            $c2 = $twoPeers($base());
            $c2['routes']['r-b']['gateway'] = 'NOPE';
            $d2 = wgct_derive($c2, ['i-a']);
            return $d['tunnels'][0]['pins']['wan'] === [['198.51.100.10', '']]
                && wgct_pin_set($d, true, false)['wan'] === [['wan_if' => '', 'family' => 'inet', 'endpoints' => ['198.51.100.10']]]
                && $d2['tunnels'][0]['pins']['wan'] === [['198.51.100.10', 'opt1'], ['198.51.100.11', '']]
                && wgct_pin_set($d2, true, false)['wan'] === [['wan_if' => 'opt1', 'family' => 'inet', 'endpoints' => ['198.51.100.10']],
                                                              ['wan_if' => '', 'family' => 'inet', 'endpoints' => ['198.51.100.11']]];
        }));
    wgct_check($p, 'pins: (k) a hostname, fd00::1, fe80::1 and 198.51.100.10, all bound => only 198.51.100.10 is pinned, nothing throws',
        $safely(function () use ($base, $codes, $pinA): bool {
            $c = $base();
            $c['instances']['i-a']['peers'] = ['p-h', 'p-u', 'p-l', 'p-a'];
            $c['peers']['p-h'] = ['name' => 'host', 'serveraddress' => 'vpn.example.net', 'serverport' => '51820'];
            $c['peers']['p-u'] = ['name' => 'ula', 'serveraddress' => 'fd00::1', 'serverport' => '51820'];
            $c['peers']['p-l'] = ['name' => 'link', 'serveraddress' => 'fe80::1', 'serverport' => '51820'];
            $c['routes']['r-u'] = ['network' => 'fd00::1/128', 'gateway' => 'WAN_A6', 'enabled' => true];
            $c['routes']['r-l'] = ['network' => 'fe80::1/128', 'gateway' => 'WAN_A6', 'enabled' => true];
            $d = wgct_derive($c, ['i-a']);
            return $codes($d['tunnels'][0]) === ['not-single-peer']
                && $d['tunnels'][0]['pins'] === ['wan' => [['198.51.100.10', 'opt1']], 'inner' => true]
                && wgct_pin_set($d, true, true) === ['wan' => [$pinA], 'inner' => ['opt11']];
        }));
    /* the hint names the kept pins only where the tunnel renders one, and only on blocking findings */
    $fixOf = fn (array $t, string $code): string => (string)(array_values(array_filter($t['findings'], fn (array $f): bool => $f['code'] === $code))[0]['fix'] ?? '');
    wgct_check($p, 'pins: a blocking finding on a pinned tunnel ends its hint with the plain-text suffix; a non-blocking one is unchanged',
        $safely(function () use ($base, $twoPeers, $fixOf): bool {
            $c = $twoPeers($base());
            $c['interfaces']['opt11']['mss'] = '1376';
            $t = wgct_derive($c, ['i-a'])['tunnels'][0];
            $t = wgct_pin_hint($t, wgct_pinned($t, true, true));
            return $fixOf($t, 'not-single-peer') === WGCT_FINDINGS['not-single-peer'][1] . WGCT_PINS_KEPT_HINT
                && $fixOf($t, 'legacy-mss') === WGCT_FINDINGS['legacy-mss'][1]
                && strip_tags(WGCT_PINS_KEPT_HINT) === WGCT_PINS_KEPT_HINT && !str_contains(WGCT_PINS_KEPT_HINT, '&');
        }));
    wgct_check($p, 'pins: no suffix on an unbound tunnel, with the pin switches off, or where only a commented-out inner block would apply',
        $safely(function () use ($base, $twoPeers, $fixOf): bool {
            $c = $twoPeers($base());
            $c['routes']['r-a']['enabled'] = false;
            $c['routes']['r-b']['enabled'] = false;
            $hinted = fn (array $t, bool $wanPins, bool $innerSource): array => wgct_pin_hint($t, wgct_pinned($t, $wanPins, $innerSource));
            $unbound = $hinted(wgct_derive($c, ['i-a'])['tunnels'][0], true, true);
            $off = $hinted(wgct_derive($twoPeers($base()), ['i-a'])['tunnels'][0], false, false);
            $c3 = $base();
            $c3['interfaces']['opt11']['enable'] = false;
            $t3 = wgct_derive($c3, ['i-a'])['tunnels'][0];
            $innerOnly = $hinted($t3, false, true);
            return $fixOf($unbound, 'not-single-peer') === WGCT_FINDINGS['not-single-peer'][1]
                && $fixOf($off, 'not-single-peer') === WGCT_FINDINGS['not-single-peer'][1]
                && $fixOf($innerOnly, 'interface-disabled') === WGCT_FINDINGS['interface-disabled'][1]
                && !wgct_pinned($t3, false, true) && wgct_pinned($t3, true, false);
        }));
    wgct_check($p, 'pins: the view clamp follows the MSS lines: kept for a blocked bound tunnel, none for a disabled instance',
        $safely(function () use ($base): bool {
            $c = $base();
            $c['interfaces']['opt11']['enable'] = false;
            $c2 = $base();
            $c2['instances']['i-a']['enabled'] = false;
            return wgct_clamp_for(wgct_derive($c, ['i-a'])['tunnels'][0], true) === ['v4' => 1336, 'v6' => 1316]
                && wgct_clamp_for(wgct_derive($c2, ['i-a'])['tunnels'][0], true) === null;
        }));

    /* (M1, ruling R37) the window between pkg installing 3.8's files and the 3.1.0 migration */
    $cfg = fn (string $settings, string $engine = ''): \SimpleXMLElement
        => simplexml_load_string("<opnsense><OPNsense>{$settings}{$engine}</OPNsense></opnsense>");
    $uA = '0000000a-0000-4000-8000-00000000000a';
    $uUpper = 'ABCDEF00-0000-4000-8000-0000000000AB';
    $old = $cfg("<WGClientTunnels version=\"3.0.0\"><enabled>1</enabled><managed>{$uA},{$uUpper}</managed><held/></WGClientTunnels>");
    $new = $cfg('<WGClientTunnels version="3.1.0"><enabled>1</enabled></WGClientTunnels>',
        "<WGClientTunnelsEngine version=\"1.0.0\"><managed>{$uA}</managed></WGClientTunnelsEngine>");
    wgct_check($p, 'migration: (M1) a settings node stored below 3.1.0 is pending; 3.1.0 or later is not',
        wgct_settings_pending($old) && !wgct_settings_pending($new)
        && !wgct_settings_pending($cfg('<WGClientTunnels version="3.2.0"/>')));
    wgct_check($p, 'migration: (M1) a settings node without a version reads as 0.0.0, as core reads it: pending',
        wgct_settings_pending($cfg('<WGClientTunnels><enabled>1</enabled></WGClientTunnels>')));
    wgct_check($p, 'migration: (M1) no settings node at all (a new install) has nothing to carry over: not pending',
        !wgct_settings_pending($cfg('')));
    wgct_check($p, 'migration: (M1) the legacy list is 3.7_1\'s as stored, in order, upper case kept; none stored => none',
        wgct_legacy_managed($old) === [$uA, $uUpper]
        && wgct_legacy_managed($cfg('<WGClientTunnels version="3.0.0"><enabled>1</enabled></WGClientTunnels>')) === []);
    $unreadable = function (\SimpleXMLElement $root): bool {
        try {
            wgct_legacy_managed($root);
        } catch (\RuntimeException $e) {
            return $e->getMessage() === 'the 3.0.0 settings\' managed list cannot be read as one list';
        }
        return false;
    };
    wgct_check($p, 'migration: (M1) a legacy list that is not one text value (two managed nodes, or elements inside) => it throws',
        $unreadable($cfg("<WGClientTunnels version=\"3.0.0\"><managed>{$uA}</managed><managed>{$uUpper}</managed></WGClientTunnels>"))
        && $unreadable($cfg("<WGClientTunnels version=\"3.0.0\"><managed><item>{$uA}</item></managed></WGClientTunnels>")));
    $engineReads = 0;
    $engine = function () use (&$engineReads, $uA): array {
        $engineReads++;
        return [$uA];
    };
    wgct_check($p, 'migration: (M1) pending => the managed list is the legacy one, and the engine model is not read',
        wgct_managed_in($old, $engine) === [$uA, $uUpper] && $engineReads === 0);
    wgct_check($p, 'migration: (M1) migrated => the managed list is the engine model\'s',
        wgct_managed_in($new, $engine) === [$uA] && $engineReads === 1);
    wgct_check($p, 'migration: (M1) pending with an unreadable legacy list => the managed list throws (a render falls back to the footprint)',
        (function () use ($cfg, $engine): bool {
            try {
                wgct_managed_in($cfg('<WGClientTunnels version="3.0.0"><managed>a</managed><managed>b</managed></WGClientTunnels>'), $engine);
            } catch (\RuntimeException $e) {
                return true;
            }
            return false;
        })());
    wgct_check($p, 'migration: (M1) a pending route set says so on its state line and keeps its route lines for the status listing',
        wgct_route_lines_pending(['state|on', 'route|wg1|fd00::1:1/128|fd00::1:2|tun_a|tun_a-ipv6|']) === ['state|pending', 'route|wg1|fd00::1:1/128|fd00::1:2|tun_a|tun_a-ipv6|']
        && wgct_route_lines_pending(['state|off']) === ['state|pending']);
    $fail += $p['fail'];
    $total += $p['total'];

    printf("%d/%d passed\n", $total - $fail, $total);
    return $fail === 0 ? 0 : 1;
}
