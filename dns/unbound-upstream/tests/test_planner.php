<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The planner.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/planner.php';
require_once __DIR__ . '/test_verdict.php';
require_once __DIR__ . '/test_zone.php';
require_once __DIR__ . '/test_choose.php';
require_once __DIR__ . '/test_contract.php';
require_once __DIR__ . '/scratch.php';

/**
 * Two IPv4 members, wg-a tier 1 and wg-b tier 2, both settled with no loss and both on the Default resolver 10.2.0.1
 * (no per-member row); Unbound running on the configured DoT root; no resolver route; the rules verified loaded and
 * the counting table holding the resolver. Cases override fields directly; a route goes through uu_test_route() and
 * a member's resolver through uu_test_resolver(), so the snapshot's copies agree.
 *
 * @return array{now: int, wall: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, default: string,
 *         rows: array<string, string>, failback_delay: int, probe_name: string},
 *     trigger: string, tiers: list<list<string>>, family: string,
 *     members: array<string, array{name: string, interface: string, if: string, ipprotocol: string,
 *         resolver: string, next_hop: string, disabled: bool, force_down: bool, monitor_disable: bool,
 *         monitor: string, time_period: int, interval: int, loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>, stop: ?string,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool},
 *     routes: array<string, array{present: bool, gateway: string, interface: string, reject: bool,
 *         ours: bool}>,
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, monitors: array<string, list<string>>, statics: array<string, list<string>>,
 *         unmonitored_members: list<string>, foreign: list<string>, member_resolvers: array<string, string>,
 *         resolver_notes: list<string>, no_next_hop: list<string>,
 *         rules: array{state: string, problems: list<string>},
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int, core_commands: list<string>},
 *     rules: array{state: string, problems: list<string>, verified_at: ?int,
 *         record: ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>}},
 *     block_table: array{table: ?array{addresses: int, references: int, out_block: int}, addresses: list<string>}}
 */
function uu_test_snapshot(): array
{
    $a = uu_test_member();
    $a['monitor'] = '192.0.2.1';
    $a['ipprotocol'] = 'inet';
    $a['resolver'] = '10.2.0.1';
    $b = uu_test_member();
    $b['ipprotocol'] = 'inet';
    $b['resolver'] = '10.2.0.1';
    $b['name'] = 'wg-b';
    $b['interface'] = 'opt2';
    $b['if'] = 'wg2';
    $b['next_hop'] = '10.2.0.6';
    $b['monitor'] = '192.0.2.2';
    $zone = uu_root_zone([uu_test_fixture('dot_dot.conf')]);
    $contract = uu_test_contract_input();
    $contract['zone'] = $zone;
    $contract['fib_sync_ms'] = 1000;
    return [
        'now' => 10000,
        'wall' => 1792400000,
        'settings' => ['enabled' => true, 'dry_run' => false, 'group' => 'grp_test', 'resolver' => '10.2.0.1',
                       'default' => '10.2.0.1', 'rows' => [], 'failback_delay' => 120, 'probe_name' => '.'],
        'trigger' => 'downloss',
        'tiers' => [['wg-a'], ['wg-b']],
        'family' => 'inet',
        'members' => ['wg-a' => $a, 'wg-b' => $b],
        'probes' => ['wg-a' => uu_test_probe('none', '0.0 %', 300), 'wg-b' => uu_test_probe('none', '0.0 %', 300)],
        'named' => [],
        'stop' => null,
        'unbound' => ['enabled' => true, 'pid_alive' => true, 'control_ok' => true, 'live_root' => $zone['addrs']],
        'zone' => $zone,
        'route' => ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false, 'ours' => false],
        'routes' => ['10.2.0.1' => ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false,
                                    'ours' => false]],
        'fib_sync_ms' => 1000,
        'contract_input' => $contract,
        'rules' => ['state' => 'loaded', 'problems' => [], 'verified_at' => 1792399000, 'record' => null],
        'block_table' => ['table' => ['addresses' => 1, 'references' => 1, 'out_block' => 37],
                          'addresses' => ['10.2.0.1']],
    ];
}

/**
 * The snapshot as tunnel mode through a member leaves it: the member's resolver is the live root and our route to
 * it points at the member.
 *
 * @param array{now: int, wall: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, default: string,
 *         rows: array<string, string>, failback_delay: int, probe_name: string},
 *     trigger: string, tiers: list<list<string>>, family: string,
 *     members: array<string, array{name: string, interface: string, if: string, ipprotocol: string,
 *         resolver: string, next_hop: string, disabled: bool, force_down: bool, monitor_disable: bool,
 *         monitor: string, time_period: int, interval: int, loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>, stop: ?string,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool},
 *     routes: array<string, array{present: bool, gateway: string, interface: string, reject: bool,
 *         ours: bool}>,
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, monitors: array<string, list<string>>, statics: array<string, list<string>>,
 *         unmonitored_members: list<string>, foreign: list<string>, member_resolvers: array<string, string>,
 *         resolver_notes: list<string>, no_next_hop: list<string>,
 *         rules: array{state: string, problems: list<string>},
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int, core_commands: list<string>},
 *     rules: array{state: string, problems: list<string>, verified_at: ?int,
 *         record: ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>}},
 *     block_table: array{table: ?array{addresses: int, references: int, out_block: int}, addresses: list<string>}} $s
 * @return array{now: int, wall: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, default: string,
 *         rows: array<string, string>, failback_delay: int, probe_name: string},
 *     trigger: string, tiers: list<list<string>>, family: string,
 *     members: array<string, array{name: string, interface: string, if: string, ipprotocol: string,
 *         resolver: string, next_hop: string, disabled: bool, force_down: bool, monitor_disable: bool,
 *         monitor: string, time_period: int, interval: int, loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>, stop: ?string,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool},
 *     routes: array<string, array{present: bool, gateway: string, interface: string, reject: bool,
 *         ours: bool}>,
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, monitors: array<string, list<string>>, statics: array<string, list<string>>,
 *         unmonitored_members: list<string>, foreign: list<string>, member_resolvers: array<string, string>,
 *         resolver_notes: list<string>, no_next_hop: list<string>,
 *         rules: array{state: string, problems: list<string>},
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int, core_commands: list<string>},
 *     rules: array{state: string, problems: list<string>, verified_at: ?int,
 *         record: ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>}},
 *     block_table: array{table: ?array{addresses: int, references: int, out_block: int}, addresses: list<string>}}
 */
function uu_test_in_tunnel(array $s, string $member): array
{
    $resolver = $s['members'][$member]['resolver'] ?? $s['settings']['resolver'];
    $s['unbound']['live_root'] = [$resolver];
    return uu_test_route($s, ['present' => true, 'gateway' => $s['members'][$member]['next_hop'],
                              'interface' => $s['members'][$member]['if'], 'reject' => false, 'ours' => true],
        $resolver);
}

/**
 * The snapshot with the route of an address (the Default's unless named) as given, in routes and, for the Default,
 * in route too, as the snapshot reads them.
 *
 * @param array{now: int, wall: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, default: string,
 *         rows: array<string, string>, failback_delay: int, probe_name: string},
 *     trigger: string, tiers: list<list<string>>, family: string,
 *     members: array<string, array{name: string, interface: string, if: string, ipprotocol: string,
 *         resolver: string, next_hop: string, disabled: bool, force_down: bool, monitor_disable: bool,
 *         monitor: string, time_period: int, interval: int, loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>, stop: ?string,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool},
 *     routes: array<string, array{present: bool, gateway: string, interface: string, reject: bool,
 *         ours: bool}>,
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, monitors: array<string, list<string>>, statics: array<string, list<string>>,
 *         unmonitored_members: list<string>, foreign: list<string>, member_resolvers: array<string, string>,
 *         resolver_notes: list<string>, no_next_hop: list<string>,
 *         rules: array{state: string, problems: list<string>},
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int, core_commands: list<string>},
 *     rules: array{state: string, problems: list<string>, verified_at: ?int,
 *         record: ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>}},
 *     block_table: array{table: ?array{addresses: int, references: int, out_block: int}, addresses: list<string>}} $s
 * @param array{present: bool, gateway: string, interface: string, reject: bool, ours: bool} $route
 * @return array{now: int, wall: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, default: string,
 *         rows: array<string, string>, failback_delay: int, probe_name: string},
 *     trigger: string, tiers: list<list<string>>, family: string,
 *     members: array<string, array{name: string, interface: string, if: string, ipprotocol: string,
 *         resolver: string, next_hop: string, disabled: bool, force_down: bool, monitor_disable: bool,
 *         monitor: string, time_period: int, interval: int, loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>, stop: ?string,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool},
 *     routes: array<string, array{present: bool, gateway: string, interface: string, reject: bool,
 *         ours: bool}>,
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, monitors: array<string, list<string>>, statics: array<string, list<string>>,
 *         unmonitored_members: list<string>, foreign: list<string>, member_resolvers: array<string, string>,
 *         resolver_notes: list<string>, no_next_hop: list<string>,
 *         rules: array{state: string, problems: list<string>},
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int, core_commands: list<string>},
 *     rules: array{state: string, problems: list<string>, verified_at: ?int,
 *         record: ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>}},
 *     block_table: array{table: ?array{addresses: int, references: int, out_block: int}, addresses: list<string>}}
 */
function uu_test_route(array $s, array $route, ?string $address = null): array
{
    $key = uu_ip_canonical($address ?? $s['settings']['resolver']) ?? '';
    $s['routes'][$key] = $route;
    if ($key === uu_ip_canonical($s['settings']['resolver'])) {
        $s['route'] = $route;
    }
    return $s;
}

/**
 * The snapshot with a member's effective resolver set where the snapshot carries it (the member and the contract's
 * input), and the address's route read (absent) when the snapshot had none.
 *
 * @param array{now: int, wall: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, default: string,
 *         rows: array<string, string>, failback_delay: int, probe_name: string},
 *     trigger: string, tiers: list<list<string>>, family: string,
 *     members: array<string, array{name: string, interface: string, if: string, ipprotocol: string,
 *         resolver: string, next_hop: string, disabled: bool, force_down: bool, monitor_disable: bool,
 *         monitor: string, time_period: int, interval: int, loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>, stop: ?string,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool},
 *     routes: array<string, array{present: bool, gateway: string, interface: string, reject: bool,
 *         ours: bool}>,
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, monitors: array<string, list<string>>, statics: array<string, list<string>>,
 *         unmonitored_members: list<string>, foreign: list<string>, member_resolvers: array<string, string>,
 *         resolver_notes: list<string>, no_next_hop: list<string>,
 *         rules: array{state: string, problems: list<string>},
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int, core_commands: list<string>},
 *     rules: array{state: string, problems: list<string>, verified_at: ?int,
 *         record: ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>}},
 *     block_table: array{table: ?array{addresses: int, references: int, out_block: int}, addresses: list<string>}} $s
 * @return array{now: int, wall: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, default: string,
 *         rows: array<string, string>, failback_delay: int, probe_name: string},
 *     trigger: string, tiers: list<list<string>>, family: string,
 *     members: array<string, array{name: string, interface: string, if: string, ipprotocol: string,
 *         resolver: string, next_hop: string, disabled: bool, force_down: bool, monitor_disable: bool,
 *         monitor: string, time_period: int, interval: int, loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>, stop: ?string,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool},
 *     routes: array<string, array{present: bool, gateway: string, interface: string, reject: bool,
 *         ours: bool}>,
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, monitors: array<string, list<string>>, statics: array<string, list<string>>,
 *         unmonitored_members: list<string>, foreign: list<string>, member_resolvers: array<string, string>,
 *         resolver_notes: list<string>, no_next_hop: list<string>,
 *         rules: array{state: string, problems: list<string>},
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int, core_commands: list<string>},
 *     rules: array{state: string, problems: list<string>, verified_at: ?int,
 *         record: ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>}},
 *     block_table: array{table: ?array{addresses: int, references: int, out_block: int}, addresses: list<string>}}
 */
function uu_test_resolver(array $s, string $member, string $address): array
{
    $s['members'][$member]['resolver'] = $address;
    $s['contract_input']['member_resolvers'][$member] = $address;
    $key = uu_ip_canonical($address);
    if ($key !== null && !isset($s['routes'][$key])) {
        $s['routes'][$key] = ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false,
                              'ours' => false];
    }
    return $s;
}

/**
 * The snapshot with another Default resolver and no per-member row: the setting, every member's resolver and family
 * and the contract's input name it, and routes holds the route (the Default's) under it alone, as the snapshot reads a
 * fresh state's addresses.
 *
 * @param array{now: int, wall: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, default: string,
 *         rows: array<string, string>, failback_delay: int, probe_name: string},
 *     trigger: string, tiers: list<list<string>>, family: string,
 *     members: array<string, array{name: string, interface: string, if: string, ipprotocol: string,
 *         resolver: string, next_hop: string, disabled: bool, force_down: bool, monitor_disable: bool,
 *         monitor: string, time_period: int, interval: int, loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>, stop: ?string,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool},
 *     routes: array<string, array{present: bool, gateway: string, interface: string, reject: bool,
 *         ours: bool}>,
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, monitors: array<string, list<string>>, statics: array<string, list<string>>,
 *         unmonitored_members: list<string>, foreign: list<string>, member_resolvers: array<string, string>,
 *         resolver_notes: list<string>, no_next_hop: list<string>,
 *         rules: array{state: string, problems: list<string>},
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int, core_commands: list<string>},
 *     rules: array{state: string, problems: list<string>, verified_at: ?int,
 *         record: ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>}},
 *     block_table: array{table: ?array{addresses: int, references: int, out_block: int}, addresses: list<string>}} $s
 * @return array{now: int, wall: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, default: string,
 *         rows: array<string, string>, failback_delay: int, probe_name: string},
 *     trigger: string, tiers: list<list<string>>, family: string,
 *     members: array<string, array{name: string, interface: string, if: string, ipprotocol: string,
 *         resolver: string, next_hop: string, disabled: bool, force_down: bool, monitor_disable: bool,
 *         monitor: string, time_period: int, interval: int, loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>, stop: ?string,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool},
 *     routes: array<string, array{present: bool, gateway: string, interface: string, reject: bool,
 *         ours: bool}>,
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, monitors: array<string, list<string>>, statics: array<string, list<string>>,
 *         unmonitored_members: list<string>, foreign: list<string>, member_resolvers: array<string, string>,
 *         resolver_notes: list<string>, no_next_hop: list<string>,
 *         rules: array{state: string, problems: list<string>},
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int, core_commands: list<string>},
 *     rules: array{state: string, problems: list<string>, verified_at: ?int,
 *         record: ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>}},
 *     block_table: array{table: ?array{addresses: int, references: int, out_block: int}, addresses: list<string>}}
 */
function uu_test_default(array $s, string $address): array
{
    $family = uu_ip_family($address) ?? '';
    $s['settings']['resolver'] = $address;
    $s['settings']['default'] = $address;
    $s['family'] = $family;
    $s['contract_input']['member_resolvers'] = [];
    foreach (array_keys($s['members']) as $name) {
        $s['members'][$name]['resolver'] = $address;
        $s['members'][$name]['ipprotocol'] = $family;
        $s['contract_input']['member_resolvers'][$name] = $address;
    }
    $s['routes'] = [uu_ip_canonical($address) ?? $address => $s['route']];
    return $s;
}

/**
 * A state in tunnel mode on the member, or in fallback when it is null. In tunnel mode on a member of $snapshot (the
 * planner's base snapshot unless given) it records the resolver (10.2.0.1 unless $resolver names another, null for
 * none) with that member's route, as the plugin does.
 *
 * @param array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int,
 *         last_down: ?array{at: int, reason: string}, resolver: string}> $timers
 * @param ?array{members: array<string, array{next_hop: string, if: string}>} $snapshot
 * @return array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int,
 *         last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
 *     control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *         forwarded: bool, released_at: ?int}>}
 */
function uu_test_plan_state(
    ?string $member,
    array $timers = [],
    int $controlFailures = 0,
    ?int $silentSince = null,
    ?string $resolver = '10.2.0.1',
    ?array $snapshot = null
): array {
    $st = uu_state_new();
    $st['mode'] = $member === null ? 'fallback' : 'tunnel';
    $st['member'] = $member;
    $st['timers'] = $timers;
    $st['control_failures'] = $controlFailures;
    $st['control_silent_since'] = $silentSince;
    /* the entry the plugin writes for tunnel mode on a member: its route, forwarded */
    $m = ($snapshot ?? uu_test_snapshot())['members'][$member ?? ''] ?? null;
    if ($resolver !== null && $m !== null) {
        $key = uu_ip_canonical($resolver) ?? $resolver;
        $st['addresses'] = [$key => ['route' => ['kind' => 'member', 'next_hop' => $m['next_hop'], 'if' => $m['if']],
                                     'forwarded' => true, 'released_at' => null]];
    }
    return $st;
}

/**
 * @param list<string> $reasons
 */
function uu_test_reason_has(array $reasons, string ...$needles): bool
{
    foreach ($reasons as $reason) {
        $all = true;
        foreach ($needles as $needle) {
            $all = $all && str_contains($reason, $needle);
        }
        if ($all) {
            return true;
        }
    }
    return false;
}

uu_register_suite('planner', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $now = 10000;
    $settledDown = uu_test_probe('down', '100.0 %', 300);
    $usable = ['wg-a' => uu_test_timer(500, null, $now - 60), 'wg-b' => uu_test_timer(500, null, $now - 60)];

    // Entering from fallback needs failback_delay seconds of settled usable readings.
    $s = uu_test_snapshot();
    $p = uu_plan($s, uu_test_plan_state(null, ['wg-a' => uu_test_timer(60, null, $now - 60)]));
    uu_check($t, 'fallback, wg-a settled 120 s → tunnel [wg-a]',
        $p['action'] === 'tunnel' && $p['candidates'] === ['wg-a'] && !$p['reassert'] && !$p['route_repair']
        && !$p['escalate_restart'] && $p['state']['timers']['wg-a']['counted'] === 120
        && $p['state']['timers']['wg-b']['counted'] === 0
        && uu_test_reason_has($p['reasons'], 'wg-a', '120 s', 'downloss'));
    $p = uu_plan($s, uu_test_plan_state(null, ['wg-a' => uu_test_timer(59, null, $now - 60)]));
    uu_check($t, 'fallback, wg-a settled 119 s → none, no candidates; reject route planned (route absent)',
        $p['action'] === 'none' && $p['candidates'] === [] && $p['route_repair'] && !$p['reassert']);
    $s2 = $s;
    $s2 = uu_test_route($s2, ['present' => true, 'gateway' => '127.0.0.1', 'interface' => 'lo0', 'reject' => true,
                              'ours' => true]);
    $p = uu_plan($s2, uu_test_plan_state(null));
    uu_check($t, 'fallback with our reject route → none, no route repair',
        $p['action'] === 'none' && !$p['route_repair'] && $p['state']['mode'] === 'fallback');

    // Leaving.
    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['probes']['wg-a'] = $settledDown;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'tunnel on wg-a, wg-a settled down → tunnel [wg-b]',
        $p['action'] === 'tunnel' && $p['candidates'] === ['wg-b'] && !$p['route_repair'] && !$p['reassert']
        && $p['state']['timers']['wg-a']['counted'] === 0
        && uu_test_reason_has($p['reasons'], 'wg-a', 'settled down', 'downloss')
        && uu_test_reason_has($p['reasons'], 'wg-b'));

    $s['probes']['wg-b'] = $settledDown;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'tunnel on wg-a, both down → fallback',
        $p['action'] === 'fallback' && $p['candidates'] === []
        && uu_test_reason_has($p['reasons'], 'wg-a', 'settled down', 'downloss')
        && uu_test_reason_has($p['reasons'], 'wg-b', 'settled down'));

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['probes']['wg-a'] = uu_test_probe('down', '25.0 %', 8);
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'tunnel on wg-a, wg-a young 25 % → none (no false leave)',
        $p['action'] === 'none' && $p['candidates'] === ['wg-a', 'wg-b'] && !$p['route_repair'] && !$p['reassert']
        && $p['state']['timers']['wg-a']['counted'] === 500);

    $s['probes']['wg-a'] = uu_test_probe('down', '~', null);
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'tunnel on wg-a, wg-a ~ with no watcher cache → none, no verdict',
        $p['action'] === 'none' && $p['candidates'] === ['wg-a', 'wg-b']);

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['members']['wg-a']['force_down'] = true;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'tunnel on wg-a, wg-a force_down → tunnel [wg-b] at once',
        $p['action'] === 'tunnel' && $p['candidates'] === ['wg-b']
        && uu_test_reason_has($p['reasons'], 'wg-a', 'force_down'));

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['probes']['wg-a'] = uu_test_probe('none', '0.0 %', 6, 'down');
    $s['named'] = ['wg-a'];
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'named wg-a with watcher down, dpinger has data → tunnel [wg-b]',
        $p['action'] === 'tunnel' && $p['candidates'] === ['wg-b']
        && uu_test_reason_has($p['reasons'], 'wg-a', 'watcher down'));
    $s['named'] = [];
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'the same watcher down without the monitor hook naming wg-a → none',
        $p['action'] === 'none' && $p['candidates'][0] === 'wg-a');

    // Reconcile.
    $s = uu_test_snapshot();
    $s['unbound']['live_root'] = ['10.2.0.1'];
    $s['probes']['wg-a'] = uu_test_probe('none', '0.0 %', 6, 'none');
    $s['probes']['wg-b'] = uu_test_probe('none', '0.0 %', 6, 'none');
    $s['named'] = ['wg-a', 'wg-b'];
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'named healthy wg-a (device recreation), route absent → none + route_repair',
        $p['action'] === 'none' && $p['candidates'] === ['wg-a'] && $p['route_repair'] && !$p['reassert']
        && $p['state']['member'] === 'wg-a');

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s = uu_test_route($s, ['reject' => true] + $s['route']);
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'tunnel on wg-a, our route carries reject → none + route_repair',
        $p['action'] === 'none' && $p['route_repair']);
    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-b');
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'tunnel on wg-a, our route points at wg-b → none + route_repair',
        $p['action'] === 'none' && $p['route_repair']);
    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s = uu_test_route($s, ['interface' => 'wg2'] + $s['route']);
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'tunnel on wg-a, our route has wg-a\'s next hop on another device → route_repair',
        $p['action'] === 'none' && $p['route_repair']);

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['unbound']['live_root'] = $s['zone']['addrs'];
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'tunnel mode, live root = configured DoT (Unbound restarted) → reassert',
        $p['action'] === 'none' && $p['reassert'] && !$p['route_repair'] && $p['candidates'][0] === 'wg-a'
        && $p['state']['mode'] === 'tunnel' && $p['state']['member'] === 'wg-a');

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'tunnel on wg-a, everything in place → none, candidates in full for apply',
        $p['action'] === 'none' && $p['candidates'] === ['wg-a', 'wg-b'] && !$p['reassert'] && !$p['route_repair']
        && !$p['escalate_restart']);

    // Returning to a better tier.
    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-b');
    $p = uu_plan($s, uu_test_plan_state('wg-b', ['wg-a' => uu_test_timer(59, null, $now - 60)]));
    uu_check($t, 'on wg-b, wg-a usable 119 s → stays on wg-b',
        $p['action'] === 'none' && $p['candidates'] === ['wg-b']);
    $p = uu_plan($s, uu_test_plan_state('wg-b', ['wg-a' => uu_test_timer(60, null, $now - 60)]));
    uu_check($t, 'on wg-b, wg-a usable 120 s → tunnel [wg-a, wg-b] (return, wg-b next)',
        $p['action'] === 'tunnel' && $p['candidates'] === ['wg-a', 'wg-b']
        && uu_test_reason_has($p['reasons'], 'wg-a', '120 s'));
    $p = uu_plan($s, uu_test_plan_state('wg-b', ['wg-a' => uu_test_timer(500, $now + 30, $now - 60)]));
    uu_check($t, 'on wg-b, wg-a past the delay but resolver-failed → stays on wg-b',
        $p['action'] === 'none' && $p['candidates'] === ['wg-b']);

    // Contract.
    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['contract_input']['fib_sync_ms'] = null;
    $s['fib_sync_ms'] = null;
    $inTunnel = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $s = uu_test_snapshot();
    $s['contract_input']['fib_sync_ms'] = null;
    $s['fib_sync_ms'] = null;
    $inFallback = uu_plan($s, uu_test_plan_state(null, $usable));
    uu_check($t, 'contract failure in tunnel → fallback; in fallback → none',
        $inTunnel['action'] === 'fallback' && $inFallback['action'] === 'none'
        && uu_test_reason_has($inTunnel['reasons'], 'fib sync delay unreadable')
        && uu_test_reason_has($inFallback['reasons'], 'fib sync delay unreadable'));

    /* a zone read that failed never lets the plan enter tunnel mode, and in tunnel it falls back */
    $plans = null;
    try {
        $s = uu_test_snapshot();
        $s['zone'] = uu_root_zone(null);
        $s['contract_input']['zone'] = $s['zone'];
        $plans = [uu_plan($s, uu_test_plan_state(null, $usable)),
                  uu_plan(uu_test_in_tunnel($s, 'wg-a'), uu_test_plan_state('wg-a', $usable))];
    } catch (\Throwable $e) {
        printf("  threw %s: %s\n", get_class($e), $e->getMessage());
    }
    uu_check($t, 'zone configuration unreadable: in fallback → none, in tunnel → fallback, the reason named',
        $plans !== null && $plans[0]['action'] === 'none' && $plans[1]['action'] === 'fallback'
        && uu_test_reason_has($plans[0]['reasons'], 'configuration unreadable')
        && uu_test_reason_has($plans[1]['reasons'], 'configuration unreadable'));

    $s = uu_test_snapshot();
    $s = uu_test_route($s, ['present' => true, 'gateway' => '192.168.1.254', 'interface' => 'igc0', 'reject' => false,
                            'ours' => false]);
    $s['contract_input']['foreign'] = ['10.2.0.1'];
    $p = uu_plan($s, uu_test_plan_state(null, $usable));
    uu_check($t, 'a route the plugin did not make → none, never repaired',
        $p['action'] === 'none' && !$p['route_repair'] && uu_test_reason_has($p['reasons'], 'resolver route not ours'));

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['contract_input']['cacheflush'] = true;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'cacheflush on is a note, not a failure: tunnel stays',
        $p['action'] === 'none' && $p['candidates'][0] === 'wg-a');

    // Control channel.
    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['unbound']['control_ok'] = false;
    $s['unbound']['live_root'] = null;
    $p1 = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $s['now'] = $now + 60;
    $p2 = uu_plan($s, $p1['state']);
    $s['now'] = $now + UU_ESCALATE_MIN_SECONDS;
    $p3 = uu_plan($s, $p2['state']);
    $s4 = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s4['now'] = $now + 60;
    $p4 = uu_plan($s4, $p2['state']);
    uu_check($t, 'control silent once → skip; three evaluations in tunnel with live pid → escalate_restart',
        $p1['action'] === 'skip' && !$p1['escalate_restart'] && $p1['state']['control_failures'] === 1
        && $p1['state']['control_silent_since'] === $now
        && $p2['action'] === 'skip' && !$p2['escalate_restart'] && $p2['state']['control_failures'] === 2
        && $p2['state']['control_silent_since'] === $now
        && $p3['action'] === 'skip' && $p3['escalate_restart'] && $p3['state']['control_failures'] === 0
        && $p3['state']['control_silent_since'] === null
        && $p3['state']['mode'] === 'tunnel' && $p3['state']['member'] === 'wg-a'
        && uu_test_reason_has($p3['reasons'], 'restart')
        && $p4['action'] === 'none' && $p4['state']['control_failures'] === 0
        && $p4['state']['control_silent_since'] === null);

    $s['now'] = $now;
    $q1 = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $s['now'] = $now + 20;
    $q2 = uu_plan($s, $q1['state']);
    $s['now'] = $now + 40;
    $q3 = uu_plan($s, $q2['state']);
    $s['now'] = $now + UU_ESCALATE_MIN_SECONDS;
    $q4 = uu_plan($s, $q3['state']);
    uu_check($t, 'three silent evaluations 20 s apart → no escalation; the fourth at 120 s → escalation',
        $q3['action'] === 'skip' && !$q3['escalate_restart'] && $q3['state']['control_failures'] === 3
        && $q3['state']['control_silent_since'] === $now
        && $q4['action'] === 'skip' && $q4['escalate_restart']);

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['unbound']['control_ok'] = false;
    $s['unbound']['live_root'] = null;
    $r1 = uu_plan($s, uu_state_new());
    $s['now'] = $now + 60;
    $r2 = uu_plan($s, $r1['state']);
    $s['now'] = $now + UU_ESCALATE_MIN_SECONDS;
    $r3 = uu_plan($s, $r2['state']);
    uu_check($t, 'state lost, control silent, our route via wg-a → tunnel on wg-a; escalates after 120 s',
        $r1['action'] === 'skip' && $r1['state']['mode'] === 'tunnel' && $r1['state']['member'] === 'wg-a'
        && !$r1['escalate_restart'] && !$r2['escalate_restart'] && $r3['escalate_restart']
        && uu_test_reason_has($r1['reasons'], 'wg-a', 'route'));
    $s = uu_test_snapshot();
    $s['unbound']['control_ok'] = false;
    $s['unbound']['live_root'] = null;
    $s = uu_test_route($s, ['present' => true, 'gateway' => '127.0.0.1', 'interface' => 'lo0', 'reject' => true,
                            'ours' => true]);
    $p = uu_plan($s, uu_test_plan_state(null, $usable, UU_ESCALATE_EVALUATIONS, $now - UU_ESCALATE_MIN_SECONDS));
    uu_check($t, 'fallback, control silent, our reject route → stays fallback, never escalates',
        $p['action'] === 'skip' && $p['state']['mode'] === 'fallback' && $p['state']['member'] === null
        && !$p['escalate_restart']);

    $s = uu_test_snapshot();
    $s['unbound']['control_ok'] = false;
    $s['unbound']['live_root'] = null;
    $p = uu_plan($s, uu_test_plan_state(null, $usable, UU_ESCALATE_EVALUATIONS + 2,
        $now - UU_ESCALATE_MIN_SECONDS));
    uu_check($t, 'control silent in fallback → skip, never escalate',
        $p['action'] === 'skip' && !$p['escalate_restart']
        && $p['state']['control_failures'] === UU_ESCALATE_EVALUATIONS + 3);

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['unbound']['control_ok'] = false;
    $s['unbound']['live_root'] = null;
    $s['contract_input']['cacheflush'] = true;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable, UU_ESCALATE_EVALUATIONS - 1,
        $now - UU_ESCALATE_MIN_SECONDS));
    uu_check($t, 'cacheflush on → never escalate',
        $p['action'] === 'skip' && !$p['escalate_restart'] && uu_test_reason_has($p['reasons'], 'cacheflush'));

    // Stop.
    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['unbound']['enabled'] = false;
    $off = uu_plan($s, uu_test_plan_state('wg-a', $usable, UU_ESCALATE_EVALUATIONS,
        $now - UU_ESCALATE_MIN_SECONDS));
    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['unbound']['pid_alive'] = false;
    $s['unbound']['control_ok'] = false;
    $s['unbound']['live_root'] = null;
    $dead = uu_plan($s, uu_test_plan_state('wg-a', $usable, UU_ESCALATE_EVALUATIONS,
        $now - UU_ESCALATE_MIN_SECONDS));
    uu_check($t, 'Unbound disabled or pid dead → stop (route removed), never escalate',
        $off['action'] === 'stop' && !$off['escalate_restart'] && !$off['route_repair']
        && $dead['action'] === 'stop' && !$dead['escalate_restart'] && !$dead['route_repair']
        && $dead['state']['control_failures'] === 0 && $dead['state']['control_silent_since'] === null
        && $off['state']['control_silent_since'] === null
        && uu_test_reason_has($off['reasons'], 'Unbound not running')
        && uu_test_reason_has($dead['reasons'], 'Unbound not running'));

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['tiers'] = [];
    $s['members'] = [];
    $s['probes'] = [];
    $s['contract_input']['group_found'] = false;
    $s['contract_input']['members'] = 0;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'group deleted while in tunnel → fallback, reason names the group',
        $p['action'] === 'fallback' && $p['candidates'] === [] && $p['state']['timers'] === []
        && uu_test_reason_has($p['reasons'], 'group not found', 'grp_test'));

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['tiers'] = [['wg-b']];
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'current member removed from the group → tunnel [wg-b], reason names the group',
        $p['action'] === 'tunnel' && $p['candidates'] === ['wg-b']
        && uu_test_reason_has($p['reasons'], 'wg-a', 'grp_test'));

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    unset($s['members']['wg-a'], $s['probes']['wg-a']);
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'tier member without a gateway record is down → tunnel [wg-b]',
        $p['action'] === 'tunnel' && $p['candidates'] === ['wg-b']
        && uu_test_reason_has($p['reasons'], 'wg-a', 'no gateway record'));

    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['settings']['enabled'] = false;
    $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'disabled setting → stop', $p['action'] === 'stop' && !$p['escalate_restart']
        && uu_test_reason_has($p['reasons'], 'disabled in settings'));

    /* the minute job stays while a footprint remains, so a disabled plugin's tick on a silent channel
     * restarts Unbound only within the bound, never once a minute */
    $tick = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $tick['settings']['enabled'] = false;
    $tick['unbound']['control_ok'] = false;
    $tick['unbound']['live_root'] = null;
    $footprint = uu_test_plan_state('wg-a', $usable);
    $footprint['addresses'] = [$tick['settings']['resolver'] => ['route' => null, 'forwarded' => true,
                                                                 'released_at' => null]];
    $d1 = uu_plan($tick, $footprint);
    $tick['now'] = $now + 60;
    $d2 = uu_plan($tick, $d1['state']);
    $tick['now'] = $now + UU_ESCALATE_MIN_SECONDS;
    $d3 = uu_plan($tick, $d2['state']);
    uu_check($t, 'disabled tick, footprint, silent channel → a stop with no restart on the first and second evaluations, with one on the third at 120 s',
        $d1['action'] === 'stop' && !$d1['escalate_restart'] && $d1['state']['control_failures'] === 1
        && $d1['state']['control_silent_since'] === $now
        && $d2['action'] === 'stop' && !$d2['escalate_restart'] && $d2['state']['control_failures'] === 2
        && $d3['action'] === 'stop' && $d3['escalate_restart'] && $d3['state']['control_failures'] === 0
        && $d3['state']['control_silent_since'] === null
        && uu_test_reason_has($d1['reasons'], 'disabled in settings')
        && uu_test_reason_has($d1['reasons'], 'silent (1 evaluations, 0 s)')
        && uu_test_reason_has($d3['reasons'], 'while stopping', 'restart Unbound when the stop cannot restore'));
    /* With cacheflush on, the due tick's line says no restart follows, as tunnel mode's does */
    $flushTick = $tick;
    $flushTick['contract_input']['cacheflush'] = true;
    $flushDue = uu_plan($flushTick, $d2['state']);
    uu_check($t, 'the due tick with cacheflush on → its line says the restart escalation is disabled, and promises no restart',
        uu_test_reason_has($flushDue['reasons'], 'while stopping', 'restart escalation disabled: cacheflush on')
        && !uu_test_reason_has($flushDue['reasons'], 'restart Unbound'));
    $tick['now'] = $now;
    $e1 = uu_plan($tick, $footprint);
    $tick['now'] = $now + 20;
    $e2 = uu_plan($tick, $e1['state']);
    $tick['now'] = $now + 40;
    $e3 = uu_plan($tick, $e2['state']);
    $tick['now'] = $now + UU_ESCALATE_MIN_SECONDS;
    $e4 = uu_plan($tick, $e3['state']);
    uu_check($t, 'disabled tick: three silent evaluations within 120 s → no restart; the fourth at 120 s → one',
        !$e3['escalate_restart'] && $e3['state']['control_failures'] === 3 && $e4['escalate_restart']);
    $answering = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $answering['settings']['enabled'] = false;
    $counted = uu_test_plan_state('wg-a', $usable, UU_ESCALATE_EVALUATIONS + 2, $now - UU_ESCALATE_MIN_SECONDS);
    $counted['addresses'] = [$answering['settings']['resolver'] => ['route' => null, 'forwarded' => true,
                                                                    'released_at' => null]];
    $never = true;
    $st = $counted;
    foreach ([0, 60, 120, 180] as $offset) {
        $answering['now'] = $now + $offset;
        $a = uu_plan($answering, $st);
        $never = $never && $a['action'] === 'stop' && !$a['escalate_restart'] && $a['state']['control_failures'] === 0
            && $a['state']['control_silent_since'] === null;
        $st = $a['state'];
    }
    uu_check($t, 'disabled tick with an answering channel → never a restart, the count cleared', $never);
    $tickDead = $tick;
    $tickDead['unbound']['pid_alive'] = false;
    $tickDeadPlan = uu_plan($tickDead, $counted);
    $tickRequested = $tick;
    $tickRequested['stop'] = UU_STOP_REQUEST;
    $tickRequestedPlan = uu_plan($tickRequested, $counted);
    $tickRemove = $tick;
    $tickRemove['stop'] = UU_STOP_REMOVE;
    $tickRemovePlan = uu_plan($tickRemove, $counted);
    uu_check($t, 'a stopped Unbound, a requested stop or the removal (whose restarts are apply\'s own, at once) → no count and no escalation',
        !$tickDeadPlan['escalate_restart'] && $tickDeadPlan['state']['control_failures'] === 0
        && !$tickRequestedPlan['escalate_restart'] && $tickRequestedPlan['state']['control_failures'] === 0
        && !$tickRemovePlan['escalate_restart'] && $tickRemovePlan['state']['control_failures'] === 0);

    /* every other silent-channel stop waits for the same bound, so the undo of a replaced address, which a
     * disabled plugin's tick runs first while the setting names another, restarts at most once per bound */
    foreach (['disabled' => false, 'enabled' => true] as $what => $on) {
        $undo = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
        $undo['settings']['enabled'] = $on;
        $undo['stop'] = UU_STOP_RESOLVER;
        $undo['unbound']['control_ok'] = false;
        $undo['unbound']['live_root'] = null;
        $u1 = uu_plan($undo, $footprint);
        $undo['now'] = $now + 60;
        $u2 = uu_plan($undo, $u1['state']);
        $undo['now'] = $now + UU_ESCALATE_MIN_SECONDS;
        $u3 = uu_plan($undo, $u2['state']);
        uu_check($t, "the undo of a replaced address, plugin $what, silent channel → no restart on the first and second evaluations, one on the third at 120 s",
            $u1['action'] === 'stop' && !$u1['escalate_restart'] && $u1['state']['control_failures'] === 1
            && !$u2['escalate_restart'] && $u2['state']['control_failures'] === 2
            && $u3['escalate_restart'] && $u3['state']['control_failures'] === 0
            && uu_test_reason_has($u1['reasons'], 'resolver setting changed'));
    }
    /* a tick while the removal marker exists is such a stop too */
    foreach (['disabled' => false, 'enabled' => true] as $what => $on) {
        $m = null;
        $ok = uu_try_case(function () use ($on, $footprint, $now, &$m): bool {
            $marker = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
            $marker['settings']['enabled'] = $on;
            $marker['stop'] = UU_STOP_REMOVING;
            $marker['unbound']['control_ok'] = false;
            $marker['unbound']['live_root'] = null;
            $m1 = uu_plan($marker, $footprint);
            $marker['now'] = $now + 60;
            $m2 = uu_plan($marker, $m1['state']);
            $marker['now'] = $now + UU_ESCALATE_MIN_SECONDS;
            $m3 = uu_plan($marker, $m2['state']);
            $m = $m1;
            return $m1['action'] === 'stop' && !$m1['escalate_restart'] && $m1['state']['control_failures'] === 1
                && !$m2['escalate_restart'] && $m2['state']['control_failures'] === 2
                && $m3['escalate_restart'] && $m3['state']['control_failures'] === 0;
        });
        uu_check($t, "a tick while the removal marker exists, plugin $what, silent channel → a stop with no restart on the first and second evaluations, one on the third at 120 s",
            $ok && $m !== null && uu_test_reason_has($m['reasons'], 'package is being removed', 'removal marker')
            && !uu_test_reason_has($m['reasons'], 'disabled in settings'));
    }

    /* an evaluation's causes, for its run and for the undo of a replaced address before it */
    $causes = [
        'an evaluation: none, and the undo as the replaced address\'s' => [null, false,
            fn (): array => ['run' => null, 'undo' => UU_STOP_RESOLVER]],
        'an evaluation while the removal marker exists: both a tick of the removal' => [null, true,
            fn (): array => ['run' => UU_STOP_REMOVING, 'undo' => UU_STOP_REMOVING]],
        'a requested stop: both the requested stop' => [UU_STOP_REQUEST, false,
            fn (): array => ['run' => UU_STOP_REQUEST, 'undo' => UU_STOP_REQUEST]],
        'a requested stop while the removal marker exists: both still the requested stop' => [UU_STOP_REQUEST, true,
            fn (): array => ['run' => UU_STOP_REQUEST, 'undo' => UU_STOP_REQUEST]],
        'the removal, whose marker exists: both the removal' => [UU_STOP_REMOVE, true,
            fn (): array => ['run' => UU_STOP_REMOVE, 'undo' => UU_STOP_REMOVE]],
    ];
    foreach ($causes as $what => [$stop, $removing, $want]) {
        uu_check($t, "the causes of $what",
            uu_try_case(fn (): bool => uu_plan_causes($stop, $removing) === $want()));
    }

    /* each stop says why: a requested stop, a removal and a replaced resolver while enabled are not the setting */
    $stops = [];
    foreach ([UU_STOP_REQUEST, UU_STOP_REMOVE, UU_STOP_RESOLVER] as $cause) {
        $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
        $s['stop'] = $cause;
        $stops[$cause] = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    }
    uu_check($t, 'stop causes while enabled → stop, each with its own reason and none "disabled in settings"',
        array_map(fn (array $p): string => $p['action'], $stops) === [UU_STOP_REQUEST => 'stop',
            UU_STOP_REMOVE => 'stop', UU_STOP_RESOLVER => 'stop']
        && uu_test_reason_has($stops[UU_STOP_REQUEST]['reasons'], 'stopped on request')
        && uu_test_reason_has($stops[UU_STOP_REMOVE]['reasons'], 'package is being removed')
        && uu_test_reason_has($stops[UU_STOP_RESOLVER]['reasons'], 'resolver setting changed', '10.2.0.1')
        && !in_array(true, array_map(fn (array $p): bool => uu_test_reason_has($p['reasons'], 'disabled in settings'),
            $stops), true));
    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['settings']['enabled'] = false;
    $s['stop'] = UU_STOP_REQUEST;
    $save = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    $s['stop'] = UU_STOP_REMOVE;
    $remove = uu_plan($s, uu_test_plan_state('wg-a', $usable));
    uu_check($t, 'requested stop while disabled (Save, enabled off) reads as the setting; removal says removal',
        uu_test_reason_has($save['reasons'], 'disabled in settings')
        && uu_test_reason_has($remove['reasons'], 'package is being removed'));
    uu_check($t, 'no stop cause and enabled → no stop reason',
        uu_plan_stop_reason(uu_test_snapshot()) === null);

    /* A recording made before 1.3 has no contract_input.core_commands; replay reads it as nothing
     * drifted, and plans without a PHP warning */
    $old = uu_test_snapshot();
    unset($old['contract_input']['core_commands']);
    $warnings = [];
    set_error_handler(function (int $no, string $msg) use (&$warnings): bool {
        $warnings[] = $msg;
        return true;
    });
    try {
        $bare = uu_try_case(fn (): bool => is_array(uu_plan($old, uu_state_new())));
        $bareWarned = $warnings !== [];
        $warnings = [];
        $upgraded = null;
        $replayed = uu_try_case(function () use ($old, &$upgraded): bool {
            $upgraded = uu_snapshot_recorded($old, 'recording.json');
            return uu_plan($upgraded, uu_state_new()) === uu_plan(uu_test_snapshot(), uu_state_new());
        });
    } finally {
        restore_error_handler();
    }
    if ($warnings !== []) {
        printf("  %s\n", implode("\n  ", $warnings));
    }
    uu_check($t, 'a pre-1.3 recording (no core_commands): planned bare it warns; as replay reads it, it plans as with no drift and without a warning',
        $bare && $bareWarned && $replayed && $warnings === [] && $upgraded !== null
        && $upgraded['contract_input']['core_commands'] === []);
    uu_check($t, 'a recording that has core_commands keeps them',
        uu_try_case(function (): bool {
            $s = uu_test_snapshot();
            $s['contract_input']['core_commands'] = ['cron restart'];
            return uu_snapshot_recorded($s, 'recording.json') === $s;
        }));

    // Mode recovery.
    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-b');
    $p = uu_plan($s, uu_state_new());
    uu_check($t, 'state file lost but live root is the resolver → treated as tunnel on the route\'s member',
        $p['action'] === 'none' && $p['candidates'] === ['wg-b'] && $p['state']['mode'] === 'tunnel'
        && $p['state']['member'] === 'wg-b' && !$p['route_repair'] && !$p['reassert']
        && uu_test_reason_has($p['reasons'], 'wg-b', 'route'));
    $s = uu_test_snapshot();
    $s['unbound']['live_root'] = ['10.2.0.1'];
    $p = uu_plan($s, uu_state_new());
    uu_check($t, 'state lost, live root is the resolver, no route of ours to a member → fallback',
        $p['action'] === 'fallback' && $p['candidates'] === [] && $p['state']['mode'] === 'tunnel'
        && $p['state']['member'] === null);

    // One resolver per member. (p3) pins the shared address's reasons as 1.3_2 prints them; the rest use wg-a on
    // 2001:db8:a::53 (the Default) and wg-b on 2001:db8:b::53 (its own row), an IPv6 group.
    $reasonsOf = function (array $s, array $st): ?array {
        $p = null;
        uu_try_case(function () use ($s, $st, &$p): bool {
            $p = uu_plan($s, $st);
            return true;
        });
        return $p === null ? null : $p['reasons'];
    };
    $shared = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $leaving = $shared;
    $leaving['probes']['wg-a'] = $settledDown;
    $bothDown = $leaving;
    $bothDown['probes']['wg-b'] = $settledDown;
    $restarted = $shared;
    $restarted['unbound']['live_root'] = $restarted['zone']['addrs'];
    $routeLost = uu_test_route($shared, ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false,
                                         'ours' => false]);
    $silentWgA = $shared;
    $silentWgA['unbound']['control_ok'] = false;
    $silentWgA['unbound']['live_root'] = null;
    $noRoute = uu_test_snapshot();
    $noRoute['unbound']['live_root'] = ['10.2.0.1'];
    $groupGone = $shared;
    $groupGone['contract_input']['group_found'] = false;
    $pins = [
        'leave' => [$leaving, uu_test_plan_state('wg-a', $usable),
            ['leave wg-a for wg-b: wg-a down: settled down; wg-b usable and settled 560 s (trigger downloss)']],
        'no candidate' => [$bothDown, uu_test_plan_state('wg-a', $usable),
            ['no candidate, fallback: wg-a down: settled down; wg-b down: settled down (trigger downloss)']],
        'enter' => [uu_test_snapshot(), uu_test_plan_state(null, ['wg-a' => uu_test_timer(60, null, $now - 60)]),
            ['enter tunnel via wg-a: wg-a usable and settled 120 s (trigger downloss)']],
        'reassert' => [$restarted, uu_test_plan_state('wg-a', $usable),
            ['live root is not the resolver: reassert 10.2.0.1 via wg-a']],
        'route repair' => [$routeLost, uu_test_plan_state('wg-a', $usable),
            ['resolver route missing, elsewhere or reject: route via wg-a']],
        'inferred member' => [uu_test_in_tunnel(uu_test_snapshot(), 'wg-b'), uu_state_new(),
            ['live root is the resolver and our route is via wg-b: tunnel mode on wg-b']],
        'inferred, no member' => [$noRoute, uu_state_new(),
            ['live root is the resolver but our route is via no member: tunnel mode with no member',
             'no candidate, fallback: wg-a usable and settled 0 s; wg-b usable and settled 0 s (trigger downloss)']],
        'inferred, root unknown' => [$silentWgA, uu_state_new(),
            ['live root unknown and our route is via wg-a: tunnel mode on wg-a',
             'Unbound control channel silent (1 evaluations, 0 s)']],
        'contract' => [$groupGone, uu_test_plan_state('wg-a', $usable), ['contract: group not found (grp_test)']],
    ];
    foreach ($pins as $what => [$s, $st, $want]) {
        $got = $reasonsOf($s, $st);
        if ($got !== $want) {
            printf("  %s: %s\n", $what, json_encode($got));
        }
        uu_check($t, "(p3) shared address, $what: the reasons exactly as 1.3_2 prints them", $got === $want);
    }
    uu_check($t, '(p3) shared address, wg-a down in tunnel mode → tunnel [wg-b]',
        uu_try_case(function () use ($leaving, $usable): bool {
            $p = uu_plan($leaving, uu_test_plan_state('wg-a', $usable));
            return $p['action'] === 'tunnel' && $p['candidates'] === ['wg-b'] && $p['drain'] === [];
        }));

    $a6 = '2001:db8:a::53';
    $b6 = '2001:db8:b::53';
    $perMember = function () use ($a6, $b6): array {
        $s = uu_test_default(uu_test_snapshot(), $a6);
        $s['members']['wg-a']['next_hop'] = 'fd00::3:2';
        $s['members']['wg-a']['if'] = 'wg3';
        $s['members']['wg-b']['next_hop'] = 'fd00::4:2';
        $s['members']['wg-b']['if'] = 'wg4';
        $s['settings']['rows'] = ['0b6a7f9e-5c1d-4e0a-9d2b-3f8a1c4e5d6b' => $b6];
        return uu_test_resolver($s, 'wg-b', $b6);
    };
    $onA = fn (array $s, array $timers = []): array
        => uu_test_plan_state('wg-a', $timers === [] ? $usable : $timers, 0, null, $a6, $s);
    $routeVia = fn (array $s, string $member): array => ['present' => true,
        'gateway' => $s['members'][$member]['next_hop'], 'interface' => $s['members'][$member]['if'],
        'reject' => false, 'ours' => true];
    $rejectRoute = ['present' => true, 'gateway' => '', 'interface' => 'lo0', 'reject' => true, 'ours' => true];
    $mapEntry = fn (?array $route, bool $forwarded, ?int $released = null): array
        => ['route' => $route, 'forwarded' => $forwarded, 'released_at' => $released];

    uu_check($t, '(p4) per member: tunnel on wg-a (live root its own resolver), wg-a down → tunnel [wg-b]',
        uu_try_case(function () use ($perMember, $onA, $settledDown): bool {
            $s = uu_test_in_tunnel($perMember(), 'wg-a');
            $s['probes']['wg-a'] = $settledDown;
            $p = uu_plan($s, $onA($s));
            return $p['action'] === 'tunnel' && $p['candidates'] === ['wg-b'] && $p['state']['member'] === 'wg-a'
                && uu_test_reason_has($p['reasons'], 'leave wg-a for wg-b');
        }));

    uu_check($t, '(p5) inference, fresh state: the live root is wg-b\'s resolver and our route to it is via wg-b → '
        . 'tunnel on wg-b, with 1.3\'s reason',
        uu_try_case(function () use ($perMember): bool {
            $s = uu_test_in_tunnel($perMember(), 'wg-b');
            $p = uu_plan($s, uu_state_new());
            return $p['state']['mode'] === 'tunnel' && $p['state']['member'] === 'wg-b' && $p['action'] === 'none'
                && !$p['reassert'] && !$p['route_repair']
                && $p['reasons'] === ['live root is the resolver and our route is via wg-b: tunnel mode on wg-b'];
        }));
    uu_check($t, '(p5) inference, fresh state: the live root is wg-b\'s resolver with no member route to it (a route '
        . 'via wg-a to it is not wg-a\'s own) → tunnel with no member',
        uu_try_case(function () use ($perMember, $routeVia, $b6): bool {
            $s = $perMember();
            $s['unbound']['live_root'] = [$b6];
            $none = uu_plan($s, uu_state_new());
            $s = uu_test_route($s, $routeVia($s, 'wg-a'), $b6);
            $other = uu_plan($s, uu_state_new());
            $want = 'live root is the resolver but our route is via no member: tunnel mode with no member';
            return $none['state']['mode'] === 'tunnel' && $none['state']['member'] === null
                && ($none['reasons'][0] ?? '') === $want
                && $other['state']['mode'] === 'tunnel' && $other['state']['member'] === null
                && ($other['reasons'][0] ?? '') === $want;
        }));
    uu_check($t, '(p5) inference, fresh state: with both members routed to their own resolvers, the live root naming '
        . 'wg-b\'s → tunnel on wg-b, not the first member in tier order',
        uu_try_case(function () use ($perMember, $routeVia, $a6): bool {
            $s = uu_test_in_tunnel($perMember(), 'wg-b');
            $s = uu_test_route($s, $routeVia($s, 'wg-a'), $a6);
            $p = uu_plan($s, uu_state_new());
            return $p['state']['member'] === 'wg-b' && $p['action'] === 'none' && !$p['reassert']
                && !$p['route_repair'];
        }));
    uu_check($t, '(p5) inference, live root unknown: the first member in tier order whose own resolver\'s route is via '
        . 'it',
        uu_try_case(function () use ($perMember, $routeVia, $a6, $b6): bool {
            $s = $perMember();
            $s['unbound']['control_ok'] = false;
            $s['unbound']['live_root'] = null;
            $s = uu_test_route($s, $routeVia($s, 'wg-b'), $a6);
            $notOwn = uu_plan($s, uu_state_new());
            $s = uu_test_route($s, $routeVia($s, 'wg-b'), $b6);
            $onB = uu_plan($s, uu_state_new());
            $s = uu_test_route($s, $routeVia($s, 'wg-a'), $a6);
            $onA = uu_plan($s, uu_state_new());
            return $notOwn['state']['member'] === null && $notOwn['state']['mode'] === 'fallback'
                && $onB['state']['member'] === 'wg-b' && $onB['state']['mode'] === 'tunnel'
                && ($onB['reasons'][0] ?? '') === 'live root unknown and our route is via wg-b: tunnel mode on wg-b'
                && $onA['state']['member'] === 'wg-a';
        }));

    uu_check($t, '(p6) the current member\'s resolver changed (a Save): a switch in place to the same member, not a '
        . 'stop',
        uu_try_case(function () use ($perMember, $onA, $a6): bool {
            $s = uu_test_in_tunnel($perMember(), 'wg-a');
            /* the evaluation before the Save: wg-a's timer follows its resolver then */
            $before = uu_plan($s, $onA($s))['state'];
            $s = uu_test_resolver($s, 'wg-a', '2001:db8:c::53');
            $p = uu_plan($s, $before);
            return $p['action'] === 'tunnel' && ($p['candidates'][0] ?? '') === 'wg-a'
                && $p['candidates'] === ['wg-a', 'wg-b'] && $p['state']['mode'] === 'tunnel'
                && $p['state']['member'] === 'wg-a' && !$p['reassert'] && !$p['route_repair']
                && $p['reasons'] === ["resolver of wg-a changed from $a6 to 2001:db8:c::53: switching in place"];
        }));
    uu_check($t, '(p7) tunnel on wg-a, live root the configured DoT list (Unbound restarted) → none, reassert its own '
        . 'resolver, 1.3\'s reason',
        uu_try_case(function () use ($perMember, $onA, $a6): bool {
            $s = uu_test_in_tunnel($perMember(), 'wg-a');
            $s['unbound']['live_root'] = $s['zone']['addrs'];
            $p = uu_plan($s, $onA($s));
            return $p['action'] === 'none' && $p['reassert'] && !$p['route_repair']
                && $p['reasons'] === ["live root is not the resolver: reassert $a6 via wg-a"];
        }));

    uu_check($t, '(p8) a member with no resolver is never a candidate, even in tier 1 and settled past the delay',
        uu_try_case(function () use ($perMember, $usable): bool {
            $s = uu_test_resolver($perMember(), 'wg-a', '');
            $p = uu_plan($s, uu_test_plan_state(null, $usable));
            return $p['action'] === 'tunnel' && $p['candidates'] === ['wg-b']
                && uu_test_reason_has($p['reasons'], 'enter tunnel via wg-b');
        }));
    uu_check($t, '(p8) in tunnel on wg-a when it is left with no resolver → leave it for wg-b at once (its tier kept), '
        . 'saying it is no candidate',
        uu_try_case(function () use ($perMember, $onA): bool {
            $s = uu_test_in_tunnel($perMember(), 'wg-a');
            $st = $onA($s, ['wg-a' => uu_test_timer(500, null, 9940), 'wg-b' => uu_test_timer(0, null, 9940)]);
            $s = uu_test_resolver($s, 'wg-a', '');
            $p = uu_plan($s, $st);
            return $p['action'] === 'tunnel' && $p['candidates'] === ['wg-b']
                && uu_test_reason_has($p['reasons'], 'leave wg-a for wg-b: wg-a not a candidate');
        }));
    uu_check($t, '(p8) no member with a resolver → none in fallback, every note in the no-candidate line from tunnel',
        uu_try_case(function () use ($perMember, $onA, $usable): bool {
            $s = uu_test_resolver(uu_test_resolver($perMember(), 'wg-a', ''), 'wg-b', '');
            $fb = uu_plan($s, uu_test_plan_state(null, $usable));
            $tun = uu_plan(uu_test_in_tunnel($s, 'wg-a'), $onA($s));
            return $fb['action'] === 'none' && $fb['candidates'] === []
                && $tun['action'] === 'fallback'
                && uu_test_reason_has($tun['reasons'], 'no candidate, fallback: wg-a not a candidate',
                    'wg-b not a candidate');
        }));

    uu_check($t, '(p9) per address: wg-a\'s resolver is wg-b\'s monitor → wg-a excluded with its note, wg-b (another '
        . 'address) the candidate',
        uu_try_case(function () use ($perMember, $usable, $a6): bool {
            $s = $perMember();
            $s['contract_input']['monitors'] = [$a6 => ['wg-b']];
            $p = uu_plan($s, uu_test_plan_state(null, $usable));
            $c = uu_contract($s['contract_input']);
            return $p['action'] === 'tunnel' && $p['candidates'] === ['wg-b'] && $c['ok']
                && $c['excluded'] === ['wg-a'] && $c['notes'] === ['wg-a excluded: resolver is the monitor of wg-b'];
        }));
    uu_check($t, '(p9) one shared address that is a monitor → 1.3\'s failure exactly, as the reason, and no note',
        uu_try_case(function () use ($usable): bool {
            $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
            $s['contract_input']['monitors'] = ['10.2.0.1' => ['wg-b']];
            $p = uu_plan($s, uu_test_plan_state('wg-a', $usable));
            return $p['action'] === 'fallback' && $p['reasons'] === ['contract: resolver is the monitor of wg-b']
                && uu_contract($s['contract_input'])['notes'] === [];
        }));

    uu_check($t, '(p10) the planner follows each member\'s resolver: a mark about wg-a\'s old address no longer keeps '
        . 'it out; one about its current address does',
        uu_try_case(function () use ($perMember, $now, $a6): bool {
            $marked = ['resolver' => '2001:db8:c::53'] + uu_test_timer(500, $now + 30, $now - 60);
            $s = $perMember();
            $moved = uu_plan($s, uu_test_plan_state(null, ['wg-a' => $marked]));
            $same = uu_plan($s, uu_test_plan_state(null, ['wg-a' => ['resolver' => $a6] + $marked]));
            return $moved['candidates'] === ['wg-a'] && $moved['state']['timers']['wg-a']['resolver'] === $a6
                && $moved['state']['timers']['wg-a']['resolver_failed_until'] === null
                && $same['candidates'] === []
                && $same['state']['timers']['wg-a']['resolver_failed_until'] === $now + 30;
        }));

    uu_check($t, '(p11) drain: an orphan released UU_OLD_ADDRESS_HOLD (60) s ago is due; one released 59 s ago is not',
        uu_try_case(function () use ($perMember, $onA, $mapEntry, $rejectRoute, $now): bool {
            $s = uu_test_in_tunnel($perMember(), 'wg-a');
            $s = uu_test_route($s, $rejectRoute, '2001:db8:c::53');
            $s = uu_test_route($s, $rejectRoute, '2001:db8:d::53');
            $st = $onA($s);
            $st['addresses']['2001:db8:c::53'] = $mapEntry(['kind' => 'reject', 'next_hop' => '', 'if' => 'lo0'],
                false, $now - 60);
            $st['addresses']['2001:db8:d::53'] = $mapEntry(['kind' => 'reject', 'next_hop' => '', 'if' => 'lo0'],
                false, $now - 59);
            $p = uu_plan($s, $st);
            return UU_OLD_ADDRESS_HOLD === 60 && $p['action'] === 'none' && $p['drain'] === ['2001:db8:c::53']
                && !$p['route_repair'];
        }));
    uu_check($t, '(p11) drain: an entry that is some member\'s effective resolver again is never due, whatever its '
        . 'released_at; nor one the live root still names',
        uu_try_case(function () use ($perMember, $onA, $mapEntry, $rejectRoute, $now, $a6, $b6): bool {
            $s = uu_test_in_tunnel($perMember(), 'wg-a');
            $s = uu_test_route($s, $rejectRoute, $b6);
            $s['unbound']['live_root'] = [$a6, '2001:db8:c::53'];
            $st = $onA($s);
            $st['addresses'][$b6] = $mapEntry(['kind' => 'reject', 'next_hop' => '', 'if' => 'lo0'], false, $now - 900);
            $st['addresses']['2001:db8:c::53'] = $mapEntry(null, true, $now - 900);
            $p = uu_plan($s, $st);
            return $p['drain'] === [];
        }));
    uu_check($t, '(p11) drain: a stop and a skip list none; fallback and none do',
        uu_try_case(function () use ($perMember, $mapEntry, $rejectRoute, $now, $usable): bool {
            $s = $perMember();
            $s = uu_test_route($s, $rejectRoute, '2001:db8:c::53');
            $st = uu_test_plan_state(null, $usable);
            $st['addresses']['2001:db8:c::53'] = $mapEntry(['kind' => 'reject', 'next_hop' => '', 'if' => 'lo0'],
                false, $now - 600);
            $stop = $s;
            $stop['settings']['enabled'] = false;
            $skip = $s;
            $skip['unbound']['control_ok'] = false;
            $skip['unbound']['live_root'] = null;
            $s['probes']['wg-a'] = uu_test_probe('down', '100.0 %', 300);
            $s['probes']['wg-b'] = uu_test_probe('down', '100.0 %', 300);
            return uu_plan($stop, $st)['drain'] === [] && uu_plan($skip, $st)['drain'] === []
                && uu_plan($s, $st)['drain'] === ['2001:db8:c::53'];
        }));

    uu_check($t, '(p12) route repair: tunnel on wg-a, wg-b\'s address still on its member route while the live root '
        . 'names only wg-a\'s → route_repair (reject it), whether its entry says forwarded false, or still true from '
        . 'an earlier run (this run\'s read settles it)',
        uu_try_case(function () use ($perMember, $onA, $mapEntry, $routeVia, $b6): bool {
            $s = uu_test_in_tunnel($perMember(), 'wg-a');
            $s = uu_test_route($s, $routeVia($s, 'wg-b'), $b6);
            $record = ['kind' => 'member', 'next_hop' => 'fd00::4:2', 'if' => 'wg4'];
            $off = $onA($s);
            $off['addresses'][$b6] = $mapEntry($record, false);
            $stale = $onA($s);
            $stale['addresses'][$b6] = $mapEntry($record, true);
            $p = uu_plan($s, $off);
            $q = uu_plan($s, $stale);
            $line = "route of $b6 is missing or not its reject route: reject $b6 locally";
            return $p['action'] === 'none' && $p['route_repair'] && !$p['reassert'] && $p['reasons'] === [$line]
                && $q['route_repair'] && $q['reasons'] === [$line];
        }));
    uu_check($t, '(p12) route repair: the same while the live root still names wg-b\'s address (forwarded) → no reject '
        . 'route over it; with its reject route in place → nothing to repair',
        uu_try_case(function () use ($perMember, $onA, $mapEntry, $routeVia, $rejectRoute, $a6, $b6): bool {
            $s = uu_test_in_tunnel($perMember(), 'wg-a');
            $s = uu_test_route($s, $routeVia($s, 'wg-b'), $b6);
            $s['unbound']['live_root'] = [$a6, $b6];
            $st = $onA($s);
            $st['addresses'][$b6] = $mapEntry(['kind' => 'member', 'next_hop' => 'fd00::4:2', 'if' => 'wg4'], true);
            $p = uu_plan($s, $st);
            $r = uu_test_in_tunnel($perMember(), 'wg-a');
            $r = uu_test_route($r, $rejectRoute, $b6);
            $rst = $onA($r);
            $rst['addresses'][$b6] = $mapEntry(['kind' => 'reject', 'next_hop' => '', 'if' => 'lo0'], false);
            $q = uu_plan($r, $rst);
            return $p['action'] === 'none' && $p['reassert'] && !$p['route_repair']
                && $q['action'] === 'none' && !$q['route_repair'] && !$q['reassert'];
        }));
    uu_check($t, '(p12) route repair outside tunnel mode: every address the setting names or the map holds needs its '
        . 'reject route, not one Unbound still forwards to nor one whose route is not the plugin\'s',
        uu_try_case(function () use ($perMember, $mapEntry, $rejectRoute, $usable, $a6, $b6): bool {
            $s = $perMember();
            $s = uu_test_route($s, $rejectRoute, $a6);
            $st = uu_test_plan_state(null, ['wg-a' => uu_test_timer(0), 'wg-b' => uu_test_timer(0)]);
            $st['addresses'][$a6] = $mapEntry(['kind' => 'reject', 'next_hop' => '', 'if' => 'lo0'], false);
            $missing = uu_plan($s, $st);
            $s = uu_test_route($s, $rejectRoute, $b6);
            $s = uu_test_route($s, $rejectRoute, '2001:db8:c::53');
            $orphan = $st;
            $orphan['addresses']['2001:db8:c::53'] = $mapEntry(null, false, 9000);
            $placed = uu_plan($s, $orphan);
            $gone = uu_test_route($s, ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false,
                                       'ours' => false], '2001:db8:c::53');
            $orphanGone = uu_plan($gone, $orphan);
            $foreign = uu_test_route($gone, ['present' => true, 'gateway' => '192.0.2.99', 'interface' => 'igc0',
                                             'reject' => false, 'ours' => false], '2001:db8:c::53');
            $notOurs = uu_plan($foreign, $orphan);
            $live = $gone;
            $live['unbound']['live_root'] = ['2001:db8:c::53', '2001:db8:d::53'];
            $stillForwarded = $orphan;
            $stillForwarded['addresses']['2001:db8:c::53']['forwarded'] = true;
            $forwarded = uu_plan($live, $stillForwarded);
            return $missing['action'] === 'none' && $missing['route_repair']
                && $placed['action'] === 'none' && !$placed['route_repair']
                && $orphanGone['route_repair'] && !$notOurs['route_repair']
                && $forwarded['state']['mode'] === 'fallback' && !$forwarded['route_repair'];
        }));

    uu_check($t, '(p14) a Default stored as 2001:DB8:A:0::53 while Unbound prints 2001:db8:a::53: the settings, the '
        . 'member\'s resolver and the plan agree, no reassert and no route repair',
        uu_try_case(function () use ($perMember, $onA, $a6): bool {
            $clean = uu_settings_clean(['resolver' => '2001:DB8:A:0::53', 'rows' => [], 'probe_name' => '.',
                'failback_delay' => '120', 'group_uuid' => '0b6a7f9e-5c1d-4e0a-9d2b-3f8a1c4e5d60']);
            $default = $clean['settings']['default'];
            $members = uu_member_resolvers(['wg-a', 'wg-b'], [], [], $default)['resolvers'];
            $s = $perMember();
            $s['settings']['resolver'] = $default;
            $s['settings']['default'] = $default;
            $s = uu_test_resolver(uu_test_resolver($s, 'wg-a', $members['wg-a']), 'wg-b', $members['wg-b']);
            $s = uu_test_in_tunnel($s, 'wg-a');
            $s['unbound']['live_root'] = ['2001:db8:a::53'];
            $p = uu_plan($s, $onA($s));
            /* the planner compares in canonical form even when handed the stored spelling */
            $raw = uu_test_in_tunnel(uu_test_resolver($perMember(), 'wg-a', '2001:DB8:A:0::53'), 'wg-a');
            $raw['unbound']['live_root'] = ['2001:db8:a::53'];
            $q = uu_plan($raw, $onA($raw));
            /* and a live root in another spelling is the same address */
            $spelled = $s;
            $spelled['unbound']['live_root'] = ['2001:0DB8:A:0::0053'];
            $r = uu_plan($spelled, $onA($spelled));
            return $default === $a6 && $members['wg-a'] === $a6 && $p['action'] === 'none' && !$p['reassert']
                && !$p['route_repair'] && $p['reasons'] === []
                && $q['action'] === 'none' && !$q['reassert'] && !$q['route_repair']
                && $r['action'] === 'none' && !$r['reassert'] && $r['reasons'] === [];
        }));

    uu_check($t, '(p15) a member whose gateway record has no next hop (\'\' or dynamic) is never a candidate, with its '
        . 'note; the other member still runs',
        uu_try_case(function () use ($perMember, $usable): bool {
            $ok = true;
            foreach (['', 'dynamic'] as $hop) {
                $s = $perMember();
                $s['members']['wg-b']['next_hop'] = $hop;
                $s['contract_input']['no_next_hop'] = ['wg-b'];
                $p = uu_plan($s, uu_test_plan_state(null, $usable));
                $c = uu_contract($s['contract_input']);
                $ok = $ok && $p['action'] === 'tunnel' && $p['candidates'] === ['wg-a'] && $c['ok']
                    && $c['notes'] === ['wg-b has no next hop: not a candidate'] && $c['excluded'] === ['wg-b'];
            }
            return $ok;
        }));

    uu_check($t, '(p16) the setting\'s addresses: enabled with the group found, every effective resolver once, sorted',
        uu_try_case(function () use ($perMember, $a6, $b6): bool {
            $s = $perMember();
            $three = uu_test_resolver($s, 'wg-a', $b6);
            $three['members']['wg-c'] = ['name' => 'wg-c', 'resolver' => '2001:DB8:0::53'] + $s['members']['wg-a'];
            return uu_setting_addresses($s) === [$a6, $b6] && uu_setting_addresses($three) === ['2001:db8::53', $b6]
                && uu_setting_addresses(uu_test_snapshot()) === ['10.2.0.1'];
        }));
    uu_check($t, '(p16) the setting\'s addresses: none while disabled or with the group not found, while each '
        . 'member\'s own resolver is still filled; none from members with no resolver',
        uu_try_case(function () use ($perMember, $a6, $b6): bool {
            $off = $perMember();
            $off['settings']['enabled'] = false;
            $lost = $perMember();
            $lost['contract_input']['group_found'] = false;
            $empty = uu_test_resolver(uu_test_resolver($perMember(), 'wg-a', ''), 'wg-b', '');
            return uu_setting_addresses($off) === [] && uu_setting_addresses($lost) === []
                && uu_setting_addresses($empty) === []
                && $off['members']['wg-a']['resolver'] === $a6 && $lost['members']['wg-b']['resolver'] === $b6;
        }));

    // The planner's addresses: the effective resolvers, or the Default when the group has no member.
    $gone = uu_test_snapshot();
    $gone['tiers'] = [];
    $gone['members'] = [];
    $gone['probes'] = [];
    $gone['contract_input']['group_found'] = false;
    $gone['contract_input']['members'] = 0;
    $gone['contract_input']['member_resolvers'] = [];
    $memberRoute = ['present' => true, 'gateway' => '10.2.0.2', 'interface' => 'wg1', 'reject' => false,
                    'ours' => false];
    $rejectRecord = ['kind' => 'reject', 'next_hop' => '', 'if' => 'lo0'];
    uu_check($t, '(g0) planner addresses: the members\' effective resolvers (canonical, once, sorted, never the '
        . 'Default no member uses); with no member, the Default; none for no address at all',
        uu_try_case(function () use ($perMember, $gone, $b6): bool {
            $rows = uu_test_resolver(uu_test_resolver($perMember(), 'wg-a', '2001:DB8:E::53'), 'wg-b', $b6);
            $none = uu_test_resolver(uu_test_resolver($perMember(), 'wg-a', ''), 'wg-b', '');
            $noDefault = $gone;
            $noDefault['settings']['default'] = '';
            $spelled = $gone;
            $spelled['settings']['default'] = '2001:DB8:A:0::53';
            return uu_plan_addresses($rows) === [$b6, '2001:db8:e::53'] && uu_plan_addresses($none) === []
                && uu_plan_addresses($gone) === ['10.2.0.1'] && uu_plan_addresses($noDefault) === []
                && uu_plan_addresses($spelled) === ['2001:db8:a::53']
                && uu_plan_addresses(uu_test_snapshot()) === ['10.2.0.1'];
        }));
    uu_check($t, '(g1) group deleted, state file lost, Unbound still forwarding to the Default over a route no member '
        . 'explains → fallback, with 1.3_2\'s three reasons exactly',
        uu_try_case(function () use ($gone, $memberRoute): bool {
            $s = uu_test_route($gone, $memberRoute);
            $s['unbound']['live_root'] = ['10.2.0.1'];
            $s['contract_input']['foreign'] = ['10.2.0.1'];
            $p = uu_plan($s, uu_state_new());
            return $p['action'] === 'fallback' && $p['state']['mode'] === 'tunnel' && $p['state']['member'] === null
                && $p['reasons'] === [
                    'live root is the resolver but our route is via no member: tunnel mode with no member',
                    'contract: resolver route not ours', 'contract: group not found (grp_test)'];
        }));
    uu_check($t, '(g2) group deleted, fallback, an empty map and no route for the Default → its reject route is '
        . 'planned, as in 1.3_2',
        uu_try_case(function () use ($gone): bool {
            $p = uu_plan($gone, uu_test_plan_state(null));
            return $p['action'] === 'none' && $p['route_repair'] && !$p['reassert']
                && $p['reasons'] === ['contract: group not found (grp_test)'];
        }));
    uu_check($t, '(g3) group deleted, the Default on its reject route in the map: never drained, released or not',
        uu_try_case(function () use ($gone, $mapEntry, $rejectRoute, $rejectRecord, $now): bool {
            $s = uu_test_route($gone, $rejectRoute);
            $ok = true;
            foreach ([$now - 60, null] as $released) {
                $st = uu_test_plan_state(null);
                $st['addresses'] = ['10.2.0.1' => $mapEntry($rejectRecord, false, $released)];
                $p = uu_plan($s, $st);
                $ok = $ok && $p['action'] === 'none' && $p['drain'] === [] && !$p['route_repair'];
            }
            return $ok;
        }));
    uu_check($t, '(g3) an orphan with no release time is never drained',
        uu_try_case(function () use ($perMember, $onA, $mapEntry, $rejectRoute, $rejectRecord): bool {
            $s = uu_test_route(uu_test_in_tunnel($perMember(), 'wg-a'), $rejectRoute, '2001:db8:c::53');
            $st = $onA($s);
            $st['addresses']['2001:db8:c::53'] = $mapEntry($rejectRecord, false);
            return uu_plan($s, $st)['drain'] === [];
        }));
    uu_check($t, '(g0) with members, a Default that every member\'s row replaces is neither a planner address nor '
        . 'repaired',
        uu_try_case(function () use ($perMember, $mapEntry, $rejectRoute, $rejectRecord, $a6, $b6): bool {
            $s = uu_test_resolver($perMember(), 'wg-a', '2001:db8:e::53');
            $s = uu_test_route($s, $rejectRoute, '2001:db8:e::53');
            $s = uu_test_route($s, $rejectRoute, $b6);
            $s = uu_test_route($s, ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false,
                                    'ours' => false], $a6);
            $st = uu_test_plan_state(null, ['wg-a' => uu_test_timer(0), 'wg-b' => uu_test_timer(0)]);
            $st['addresses'] = ['2001:db8:e::53' => $mapEntry($rejectRecord, false), $b6 => $mapEntry($rejectRecord,
                false)];
            $p = uu_plan($s, $st);
            return $s['settings']['default'] === $a6 && !in_array($a6, uu_plan_addresses($s), true)
                && $p['action'] === 'none' && !$p['route_repair'];
        }));

    uu_check($t, '(g6) drain: an orphan whose live route the plugin did not make is never drained',
        uu_try_case(function () use ($perMember, $onA, $mapEntry, $rejectRecord, $now): bool {
            $s = uu_test_in_tunnel($perMember(), 'wg-a');
            $s = uu_test_route($s, ['present' => true, 'gateway' => '192.0.2.99', 'interface' => 'igc0',
                                    'reject' => false, 'ours' => false], '2001:db8:c::53');
            $st = $onA($s);
            $st['addresses']['2001:db8:c::53'] = $mapEntry($rejectRecord, false, $now - 600);
            $p = uu_plan($s, $st);
            return $p['drain'] === [] && !$p['route_repair'];
        }));
    uu_check($t, '(g7) drain: a stale recorded forwarded true is settled by this run\'s read, as the reject repair '
        . 'settles it: an orphan the live root no longer names is due',
        uu_try_case(function () use ($perMember, $onA, $mapEntry, $rejectRoute, $rejectRecord, $now): bool {
            $s = uu_test_route(uu_test_in_tunnel($perMember(), 'wg-a'), $rejectRoute, '2001:db8:c::53');
            $st = $onA($s);
            $st['addresses']['2001:db8:c::53'] = $mapEntry($rejectRecord, true, $now - 600);
            $named = $s;
            $named['unbound']['live_root'] = ['2001:db8:a::53', '2001:db8:c::53'];
            return uu_plan($s, $st)['drain'] === ['2001:db8:c::53'] && uu_plan($named, $st)['drain'] === [];
        }));

    uu_check($t, '(g8) tunnel on wg-a with the live root another member\'s address: a switch back in place, the reason '
        . 'saying the live root is not wg-a\'s resolver (it did not change)',
        uu_try_case(function () use ($perMember, $onA, $a6, $b6): bool {
            $s = uu_test_in_tunnel($perMember(), 'wg-a');
            $before = uu_plan($s, $onA($s))['state'];
            $s['unbound']['live_root'] = [$b6];
            $p = uu_plan($s, $before);
            return $p['action'] === 'tunnel' && $p['state']['member'] === 'wg-a'
                && $p['reasons'] === ["live root is $b6, not wg-a's resolver $a6: switching in place"];
        }));
    uu_check($t, '(g8) a resolver change whose timer has no address yet (converted from 1.3) cannot say what it '
        . 'changed from: the live-root wording',
        uu_try_case(function () use ($perMember, $onA, $a6): bool {
            $s = uu_test_resolver(uu_test_in_tunnel($perMember(), 'wg-a'), 'wg-a', '2001:db8:c::53');
            $p = uu_plan($s, $onA($s));
            return $p['action'] === 'tunnel'
                && $p['reasons'] === ["live root is $a6, not wg-a's resolver 2001:db8:c::53: switching in place"];
        }));
    uu_check($t, '(g9) tunnel on wg-a after an Unbound restart (live root the configured list), wg-b\'s address still '
        . 'on its member route with forwarded true recorded → reassert and reject it, both reasons in order',
        uu_try_case(function () use ($perMember, $onA, $mapEntry, $routeVia, $a6, $b6): bool {
            $s = uu_test_in_tunnel($perMember(), 'wg-a');
            $s = uu_test_route($s, $routeVia($s, 'wg-b'), $b6);
            $s['unbound']['live_root'] = $s['zone']['addrs'];
            $st = $onA($s);
            $st['addresses'][$b6] = $mapEntry(['kind' => 'member', 'next_hop' => 'fd00::4:2', 'if' => 'wg4'], true);
            $p = uu_plan($s, $st);
            return $p['action'] === 'none' && $p['reassert'] && $p['route_repair']
                && $p['reasons'] === ["live root is not the resolver: reassert $a6 via wg-a",
                    "route of $b6 is missing or not its reject route: reject $b6 locally"];
        }));
    uu_check($t, '(g10) a member with no timer yet has its resolver recorded after one plan',
        uu_try_case(function () use ($perMember, $a6, $b6): bool {
            $timers = uu_plan($perMember(), uu_test_plan_state(null))['state']['timers'];
            return ($timers['wg-a']['resolver'] ?? null) === $a6 && ($timers['wg-b']['resolver'] ?? null) === $b6;
        }));

    return uu_tally_report('planner', $t);
});
