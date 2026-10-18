<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Live collectors (spec 2026-10-17 section 3.2). Read-only: the plugin model, gateway groups and records and
 * status, the dpinger processes' ages, Unbound's state, forwarders and generated configuration, the resolver's
 * route, one sysctl, and the core hook files the contract checks. Builds the Snapshot uu_plan() consumes
 * (planner.php). The parsers are pure; the collectors are not and run only where core is installed.
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/zone.php';

/** Core's PHP library, loaded when a collector needs it so the parsers load anywhere. */
function uu_load_core(): void
{
    require_once 'config.inc';
    require_once 'util.inc';
    require_once 'interfaces.inc';
    require_once 'plugins.inc';
    require_once 'legacy_bindings.inc';
    require_once 'plugins.inc.d/dpinger.inc';
}

/**
 * `route -n get <resolver>`. Only a host route for the resolver itself counts: the answer's destination is the
 * address asked for and carries HOST. A default or other covering route (an answer for another destination) and
 * "not in table" are absent. A REJECT host route prints no gateway.
 *
 * @return array{present: bool, gateway: string, interface: string, reject: bool}
 */
function uu_parse_route_get(string $out): array
{
    $absent = ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false];
    if (preg_match('/^\s*route to:\s*(\S+)/m', $out, $to) !== 1
        || preg_match('/^\s*destination:\s*(\S+)/m', $out, $d) !== 1 || $d[1] !== $to[1]) {
        return $absent;
    }
    $flags = preg_match('/^\s*flags:\s*<([^>]*)>/m', $out, $f) === 1 ? explode(',', $f[1]) : [];
    if (!in_array('HOST', $flags, true)) {
        return $absent;
    }
    return [
        'present' => true,
        'gateway' => preg_match('/^\s*gateway:\s*(\S+)/m', $out, $g) === 1 ? $g[1] : '',
        'interface' => preg_match('/^\s*interface:\s*(\S+)/m', $out, $i) === 1 ? $i[1] : '',
        'reject' => in_array('REJECT', $flags, true),
    ];
}

/**
 * `unbound-control forward`: a space-separated address list, "off (using root hints)" when nothing is forwarded
 * (the empty list; Unbound 1.26.1 prints it after `forward_remove .`), or an error or anything else (null: the
 * channel did not answer).
 *
 * @return ?list<string>
 */
function uu_parse_forward(string $out): ?array
{
    $text = trim($out);
    if ($text === '') {
        return null;
    }
    if (preg_match('/^off(\s+\(using root hints\))?$/', $text) === 1) {
        return [];
    }
    $addrs = preg_split('/\s+/', $text) ?: [];
    foreach ($addrs as $addr) {
        if (preg_match('/^[0-9a-f:.]+(@\d+)?(#\S+)?$/i', $addr) !== 1 || preg_match('/\d|:/', $addr) !== 1) {
            return null;
        }
    }
    return array_values($addrs);
}

/** `sysctl -n` of an integer; null for empty output or anything that is not a non-negative integer. */
function uu_parse_sysctl_int(string $out): ?int
{
    $text = trim($out);
    return preg_match('/^\d+$/', $text) === 1 ? (int)$text : null;
}

/**
 * `ps -o pid= -o etimes=`: seconds since each process started. Monotonic, so a clock step cannot make a young
 * dpinger window look settled.
 *
 * @return array<int, int> pid => elapsed seconds
 */
function uu_parse_ps_etimes(string $out): array
{
    $ages = [];
    foreach (preg_split('/\R/', trim($out)) ?: [] as $line) {
        if (preg_match('/^\s*(\d+)\s+(\d+)\s*$/', $line, $m) === 1) {
            $ages[(int)$m[1]] = (int)$m[2];
        }
    }
    return $ages;
}

/**
 * The group's tiers, best first: names per tier, unused tiers (core fills 1 to 5, an unused one as [""]) and empty
 * names dropped.
 *
 * @param array{tiers?: array<array-key, list<string>>} $group one entry of getGroupsConfig()
 * @return list<list<string>>
 */
function uu_group_tiers(array $group): array
{
    $byKey = $group['tiers'] ?? [];
    ksort($byKey, SORT_NUMERIC);
    $tiers = [];
    foreach ($byKey as $names) {
        $tier = array_values(array_filter($names, fn (string $name): bool => $name !== ''));
        if ($tier !== []) {
            $tiers[] = $tier;
        }
    }
    return $tiers;
}

/** Whether an IPv4 address lies in an IPv4 network ("a.b.c.d/n", or a bare address as a /32); never for others. */
function uu_ipv4_in_network(string $addr, string $network): bool
{
    $parts = explode('/', $network);
    $bits = isset($parts[1]) ? $parts[1] : '32';
    $long = ip2long($addr);
    $net = ip2long($parts[0]);
    if ($long === false || $net === false || count($parts) > 2 || preg_match('/^\d{1,2}$/', $bits) !== 1 || (int)$bits > 32) {
        return false;
    }
    $mask = (int)$bits === 0 ? 0 : (-1 << (32 - (int)$bits)) & 0xFFFFFFFF;
    return ($long & $mask) === ($net & $mask);
}

/**
 * Whether plugins_scan() visits unbound.inc before unboundupstream.inc. Either missing is a fault: on an
 * installed box unboundupstream.inc is always scanned.
 *
 * @param list<string> $scanned the plugin names plugins_scan() returns, in its order
 */
function uu_unbound_sorts_first(array $scanned): bool
{
    if (!in_array('unbound', $scanned, true)) {
        return false;
    }
    if (!in_array('unboundupstream', $scanned, true)) {
        return false;
    }
    return array_search('unbound', $scanned, true) < array_search('unboundupstream', $scanned, true);
}

/**
 * Whether the plugin made the resolver's route: the REJECT host route (route(8) prints it on lo0 with no gateway),
 * or a route through a member's next hop on that member's device.
 *
 * @param array{present: bool, gateway: string, interface: string, reject: bool} $route
 * @param array<string, array{next_hop: string, if: string}> $members
 */
function uu_route_ours(array $route, array $members): bool
{
    if (!$route['present']) {
        return false;
    }
    if ($route['reject']) {
        return $route['interface'] === 'lo0';
    }
    if ($route['gateway'] === '') {
        return false;
    }
    foreach ($members as $m) {
        if ($m['next_hop'] === $route['gateway'] && $m['if'] === $route['interface']) {
            return true;
        }
    }
    return false;
}

/**
 * Ruling R22: a live route equal to the one the plugin last installed (the state's route_installed) is the
 * plugin's own even when no current member explains it, so a group renamed or deleted in tunnel mode lets
 * fallback and stop replace or delete the plugin's stale route instead of reading it as foreign. evaluate.php
 * applies it to every snapshot before planning; a route matching neither stays foreign.
 *
 * @param array{now: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, failback_delay: int,
 *         probe_name: string},
 *     trigger: string, tiers: list<list<string>>,
 *     members: array<string, array{name: string, interface: string, if: string, next_hop: string, disabled: bool,
 *         force_down: bool, monitor_disable: bool, monitor: string, time_period: int, interval: int,
 *         loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool},
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, resolver_is_monitor: list<string>, resolver_in_static: list<string>,
 *         unmonitored_members: list<string>, foreign_route: bool,
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int}} $s
 * @param ?array{kind: string, next_hop: string, if: string} $installed
 * @return array{now: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, failback_delay: int,
 *         probe_name: string},
 *     trigger: string, tiers: list<list<string>>,
 *     members: array<string, array{name: string, interface: string, if: string, next_hop: string, disabled: bool,
 *         force_down: bool, monitor_disable: bool, monitor: string, time_period: int, interval: int,
 *         loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool},
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, resolver_is_monitor: list<string>, resolver_in_static: list<string>,
 *         unmonitored_members: list<string>, foreign_route: bool,
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int}}
 */
function uu_route_adopt(array $s, ?array $installed): array
{
    $route = $s['route'];
    if ($installed === null || !$route['present'] || $route['ours']) {
        return $s;
    }
    $matches = $installed['kind'] === 'reject'
        ? $route['reject'] && $route['interface'] === $installed['if']
        : $installed['kind'] === 'member' && !$route['reject'] && $route['gateway'] !== ''
            && $route['gateway'] === $installed['next_hop'] && $route['interface'] === $installed['if'];
    if (!$matches) {
        return $s;
    }
    $s['route']['ours'] = true;
    $s['contract_input']['foreign_route'] = false;
    return $s;
}

/**
 * The plugin's settings. The group is the NAME of the gateway group the stored UUID points at, '' when the
 * group is gone or none is chosen.
 *
 * @return array{enabled: bool, dry_run: bool, group: string, resolver: string, failback_delay: int,
 *     probe_name: string}
 */
function uu_settings(): array
{
    uu_load_core();
    $mdl = new \OPNsense\UnboundUpstream\UnboundUpstream();
    $uuid = $mdl->gateway_group->getValue();
    $group = '';
    foreach ((new \OPNsense\Routing\GatewayGroups())->gateway_group->iterateItems() as $key => $item) {
        if ($uuid !== '' && (string)$key === $uuid) {
            $group = $item->name->getValue();
        }
    }
    return [
        'enabled' => $mdl->enabled->isEqual('1'),
        'dry_run' => $mdl->dry_run->isEqual('1'),
        'group' => $group,
        'resolver' => $mdl->resolver->getValue(),
        'failback_delay' => (int)$mdl->failback_delay->getValue(),
        'probe_name' => $mdl->probe_name->getValue(),
    ];
}

/**
 * Unbound's live root forwarders through the control channel; null when it does not answer in time.
 *
 * @return ?list<string>
 */
function uu_live_root(): ?array
{
    $out = [];
    $rc = 0;
    exec('/usr/bin/timeout ' . UU_CONTROL_CALL_TIMEOUT_SECONDS
        . ' /usr/local/sbin/unbound-control -c /var/unbound/unbound.conf forward 2>&1', $out, $rc);
    return $rc === 0 ? uu_parse_forward(implode("\n", $out)) : null;
}

/**
 * Unbound's generated configuration files, in file-name order.
 *
 * @return list<string>
 */
function uu_zone_texts(): array
{
    $texts = [];
    $files = glob('/var/unbound/etc/*.conf') ?: [];
    sort($files);
    foreach ($files as $file) {
        $text = is_readable($file) ? file_get_contents($file) : false;
        if ($text !== false) {
            $texts[] = $text;
        }
    }
    return $texts;
}

/**
 * The Snapshot (planner.php) for the given settings. now is monotonic seconds (every timer runs on it).
 *
 * @param array{enabled: bool, dry_run: bool, group: string, resolver: string, failback_delay: int,
 *     probe_name: string} $settings uu_settings()
 * @param list<string> $named the gateways the monitor hook passed
 * @return array{now: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, failback_delay: int,
 *         probe_name: string},
 *     trigger: string, tiers: list<list<string>>,
 *     members: array<string, array{name: string, interface: string, if: string, next_hop: string, disabled: bool,
 *         force_down: bool, monitor_disable: bool, monitor: string, time_period: int, interval: int,
 *         loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool},
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, resolver_is_monitor: list<string>, resolver_in_static: list<string>,
 *         unmonitored_members: list<string>, foreign_route: bool,
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int}}
 */
function uu_snapshot(array $settings, array $named): array
{
    uu_load_core();
    $now = intdiv(hrtime(true), 1000000000);
    $resolver = $settings['resolver'];

    /* the group: tiers and trigger */
    $groups = (new \OPNsense\Routing\GatewayGroups())->getGroupsConfig();
    $group = $settings['group'] !== '' ? ($groups[$settings['group']] ?? null) : null;
    $tiers = $group === null ? [] : uu_group_tiers($group);
    $trigger = $group === null ? '' : (string)($group['trigger'] ?? '');
    $groupsHaveTiers = true;
    foreach ($groups as $g) {
        if (!isset($g['tiers']) || !is_array($g['tiers'])) {
            $groupsHaveTiers = false;
        }
    }

    /* gateway records: members of the group, and the monitor addresses of every gateway */
    $all = (new \OPNsense\Routing\Gateways())->gatewaysIndexedByName(true);
    $resolverIsMonitor = [];
    foreach ($all as $name => $gw) {
        if ($resolver !== '' && ($gw['monitor'] ?? '') === $resolver) {
            $resolverIsMonitor[] = (string)$name;
        }
    }
    $members = [];
    $unmonitored = [];
    foreach ($tiers as $tier) {
        foreach ($tier as $name) {
            $gw = $all[$name] ?? null;
            if ($gw === null || isset($members[$name])) {
                continue;
            }
            $members[$name] = [
                'name' => $name,
                'interface' => (string)($gw['interface'] ?? ''),
                'if' => (string)($gw['if'] ?? ''),
                'next_hop' => (string)($gw['gateway'] ?? ''),
                'disabled' => !empty($gw['disabled']),
                'force_down' => !empty($gw['force_down']),
                'monitor_disable' => !empty($gw['monitor_disable']),
                'monitor' => (string)($gw['monitor'] ?? ''),
                'time_period' => (int)($gw['current_time_period'] ?? 60),
                'interval' => (int)($gw['current_interval'] ?? 1),
                'loss_interval' => (int)($gw['current_loss_interval'] ?? 4),
                'losshigh' => (int)($gw['current_losshigh'] ?? 20),
            ];
            if ($members[$name]['monitor_disable']) {
                $unmonitored[] = $name;
            }
        }
    }

    /* dpinger: status and loss with the watcher cache substituted for a window with no data, the raw cache, and
     * the age of each member's dpinger process (null without a process or its socket) */
    $status = return_gateways_status();
    $watcher = dpinger_watcher();
    $statusFields = true;
    foreach ($status as $st) {
        if (!isset($st['status'], $st['loss'])) {
            $statusFields = false;
        }
    }
    $pids = [];
    foreach (array_keys($members) as $name) {
        $pidFile = "/var/run/dpinger_{$name}.pid";
        $pid = is_readable($pidFile) ? (int)trim((string)file_get_contents($pidFile)) : 0;
        if ($pid > 0) {
            $pids[$name] = $pid;
        }
    }
    $ages = $pids === [] ? [] : uu_parse_ps_etimes((string)shell_exec('/bin/ps -o pid= -o etimes= -p '
        . escapeshellarg(implode(',', $pids)) . ' 2>/dev/null'));
    $probes = [];
    foreach (array_keys($members) as $name) {
        $st = $status[$name] ?? null;
        if ($st === null) {
            continue;
        }
        $age = isset($pids[$name]) && file_exists("/var/run/dpinger_{$name}.sock") ? ($ages[$pids[$name]] ?? null) : null;
        $probes[$name] = [
            'status' => (string)$st['status'],
            'loss' => (string)$st['loss'],
            'sock_age' => $age,
            'cached' => isset($watcher[$name]) ? (string)$watcher[$name] : null,
        ];
    }

    /* Unbound */
    $unboundMdl = new \OPNsense\Unbound\Unbound();
    $pidAlive = isvalidpid('/var/run/unbound.pid');
    $liveRoot = $pidAlive ? uu_live_root() : null;
    $zone = uu_root_zone(uu_zone_texts());

    /* the resolver's route */
    $route = ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false];
    if (filter_var($resolver, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
        $route = uu_parse_route_get((string)shell_exec('/sbin/route -n get -inet ' . escapeshellarg($resolver)
            . ' 2>/dev/null'));
    }
    $ours = uu_route_ours($route, $members);
    $fibSyncMs = uu_parse_sysctl_int((string)shell_exec('/sbin/sysctl -n net.route.algo.fib_max_sync_delay_ms 2>/dev/null'));

    /* static routes that cover the resolver */
    $inStatic = [];
    if ($resolver !== '') {
        foreach ((new \OPNsense\Routes\Route())->route->iterateItems() as $r) {
            $network = $r->network->getValue();
            if ($r->enabled->isEqual('1') && uu_ipv4_in_network($resolver, $network)) {
                $inStatic[] = $network;
            }
        }
    }

    /* the hook-order contract: unbound_start is registered by unbound.inc and unbound.inc is scanned first */
    $hooks = false;
    if (stream_resolve_include_path('plugins.inc.d/unbound.inc') !== false) {
        require_once 'plugins.inc.d/unbound.inc';
        $hooks = function_exists('unbound_configure') && array_key_exists('unbound_start', unbound_configure());
    }

    return [
        'now' => $now,
        'settings' => $settings,
        'trigger' => $trigger,
        'tiers' => $tiers,
        'members' => $members,
        'probes' => $probes,
        'named' => $named,
        'unbound' => [
            'enabled' => $unboundMdl->general->enabled->isEqual('1'),
            'pid_alive' => $pidAlive,
            'control_ok' => $liveRoot !== null,
            'live_root' => $liveRoot,
        ],
        'zone' => $zone,
        'route' => $route + ['ours' => $ours],
        'fib_sync_ms' => $fibSyncMs,
        'contract_input' => [
            'unbound_hooks_registered' => $hooks,
            'unbound_sorts_first' => uu_unbound_sorts_first(array_map('strval', array_keys(plugins_scan()))),
            'groups_have_tiers' => $groupsHaveTiers,
            'status_fields' => $statusFields,
            'resolver_is_monitor' => $resolverIsMonitor,
            'resolver_in_static' => $inStatic,
            'unmonitored_members' => $unmonitored,
            'foreign_route' => $route['present'] && !$ours,
            'zone' => $zone,
            'fib_sync_ms' => $fibSyncMs,
            'cacheflush' => $unboundMdl->general->cacheflush->isEqual('1'),
            'group_found' => $group !== null,
            'members' => count($members),
        ],
    ];
}
