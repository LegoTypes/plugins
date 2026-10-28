<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Live collectors. Read-only: the plugin model, gateway groups and records and
 * status, the dpinger processes' ages, Unbound's state, forwarders and generated configuration, the resolver's
 * route, one sysctl, the core hook files and configd actions files the contract checks, and pf (the
 * ruleset checksum, the counting table, and the ruleset listing only when an evaluation finds no verdict for the
 * live checksum). Builds the Snapshot uu_plan() consumes (planner.php). The parsers are pure; the collectors are not
 * and run only where core is installed.
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/address.php';
require_once __DIR__ . '/zone.php';
require_once __DIR__ . '/log.php';
require_once __DIR__ . '/pfobserve.php';
require_once __DIR__ . '/state.php';

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
 * `route -n get <family> <resolver>`. Only a host route for the resolver itself counts: the answer's destination is the
 * address asked for and carries HOST. A default or other covering route (an answer for another destination) is
 * absent, and so is any output without a destination. route(8) prints nothing on stdout for no route, a bad address
 * or a wrong family argument (IPv4: "not in table", IPv6: "route has not been found", both on stderr, which the
 * collectors drop), so those reach this parser as ''. Absent is the safe reading of a failure: apply only adds over an
 * absent route, route(8) refuses an add over a route that is there, and apply never deletes a route it cannot see.
 * A REJECT host route prints no gateway.
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
        if (!uu_forward_addr_ok($addr)) {
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
 * The command: value of one section of a configd actions file (actions_<service>.conf), as configd's parser reads
 * it: the section's command option (":" or "="), trimmed. Null when the section or its command is missing.
 */
function uu_configd_action_command(string $conf, string $section): ?string
{
    $in = false;
    foreach (preg_split('/\r?\n/', $conf) ?: [] as $line) {
        if (preg_match('/^\[(.+)\]\s*$/', $line, $m) === 1) {
            if ($in) {
                return null;
            }
            $in = $m[1] === $section;
        } elseif ($in && preg_match('/^command\s*[:=](.*)$/i', $line, $m) === 1) {
            return trim($m[1]);
        }
    }
    return null;
}

/**
 * The names of core's commands the plugin falls back to when configd does not answer that core's actions files no
 * longer run as the plugin's constants say, so a core change is noted as drift; an unreadable file counts as
 * changed.
 *
 * @return list<string>
 */
function uu_core_commands_changed(string $dir = '/usr/local/opnsense/service/conf/actions.d'): array
{
    $changed = [];
    foreach ([
        'filter reload' => ['actions_filter.conf', 'reload', UU_CORE_FILTER_RELOAD],
        'cron restart' => ['actions_cron.conf', 'restart', UU_CORE_CRON_RESTART],
        'unbound restart' => ['actions_unbound.conf', 'restart', UU_CORE_UNBOUND_RESTART],
    ] as $name => [$file, $section, $command]) {
        $conf = @file_get_contents("$dir/$file");
        if (!is_string($conf) || uu_configd_action_command($conf, $section) !== $command) {
            $changed[] = $name;
        }
    }
    return $changed;
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

/**
 * The names of the gateways whose monitor address is the resolver, compared in canonical form; none for an empty or
 * unusable resolver.
 *
 * @param array<array-key, array<string, mixed>> $records gatewaysIndexedByName()'s shape
 * @return list<string>
 */
function uu_resolver_monitors(array $records, string $resolver): array
{
    $names = [];
    foreach ($records as $name => $gw) {
        if ($resolver !== '' && uu_ip_same((string)($gw['monitor'] ?? ''), $resolver)) {
            $names[] = (string)$name;
        }
    }
    return $names;
}

/**
 * Whether an address lies in a static route's network ("addr/n", or a bare address as a host), in the address's own
 * family; never for another family or a malformed network. Core's own containment test, on the canonical address.
 */
function uu_in_static(string $addr, string $network): bool
{
    $canonical = uu_ip_canonical($addr);
    if ($canonical === null) {
        return false;
    }
    /* a bare network is a host route; the model's resolverProblems() completes it the same way (it cannot load
     * this library) */
    $cidr = str_contains($network, '/') ? $network : $network . (str_contains($network, ':') ? '/128' : '/32');
    return \OPNsense\Firewall\Util::isIPInCIDR($canonical, $cidr);
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
        if (uu_next_hop($m['next_hop']) === uu_next_hop($route['gateway']) && $m['if'] === $route['interface']) {
            return true;
        }
    }
    return false;
}

/**
 * The members the renderer gives pass rules: those whose gateway record names an interface and that have a
 * resolver, each with it in canonical form. Members sharing an interface and a resolver share its rules, so the
 * verdict asks each for them.
 *
 * @param array<string, array{name: string, interface: string, if: string, resolver: string, next_hop: string,
 *     disabled: bool, force_down: bool, monitor_disable: bool, monitor: string, time_period: int, interval: int,
 *     loss_interval: int, losshigh: int}> $members
 * @return list<array{name: string, interface: string, if: string, resolver: string}>
 */
function uu_ruled_members(array $members): array
{
    $ruled = [];
    foreach ($members as $m) {
        $resolver = uu_ip_canonical($m['resolver']);
        if ($m['interface'] !== '' && $resolver !== null) {
            $ruled[] = ['name' => $m['name'], 'interface' => $m['interface'], 'if' => $m['if'],
                        'resolver' => $resolver];
        }
    }
    return $ruled;
}

/**
 * What pf says about the plugin's rules and its counting table, through pfctl. The rules come from the record while
 * its checksum is live and it was made for these inputs (uu_rules_inputs(): the members' interfaces, devices and
 * resolvers, and the Default), except that an evaluation (listRules) never reuses a recorded fault: it lists again
 * while the fault stands, and a status call shows it. Otherwise an evaluation lists the ruleset (again when
 * a reload straddled the first listing or pfctl cut it short) and returns a record to save, and a status call
 * answers verifying. The table's addresses are read only while the table exists.
 *
 * @param list<array{name: string, interface: string, if: string, resolver: string}> $members uu_ruled_members()
 * @param list<string> $settingAddresses uu_setting_addresses(), the addresses the backstops and the table go to
 * @param string $default the Default resolver, canonical, or ''
 * @param ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>} $record the saved
 *     verification
 * @param callable(list<string>): array{out: string, err: string} $pfctl runs /sbin/pfctl with these arguments and
 *     returns its stdout and stderr apart (uu_pfctl_run()); stderr only decides whether a listing is whole
 * @return array{rules: array{state: string, problems: list<string>, verified_at: ?int,
 *         record: ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>}},
 *     block_table: array{table: ?array{addresses: int, references: int, out_block: int}, addresses: list<string>}}
 */
function uu_pf_observe(array $members, array $settingAddresses, string $default, ?array $record, int $wall,
    bool $listRules, callable $pfctl): array
{
    $rules = uu_rules_check(
        $record,
        uu_rules_inputs($members, $default),
        fn (): ?string => uu_pf_checksum($pfctl(['-si', '-v'])['out']),
        function () use ($pfctl): ?string {
            $run = $pfctl(['-vsr']);
            return uu_pf_listing_usable($run['err']) ? $run['out'] : null;
        },
        fn (string $listing): array => uu_rules_verdict($listing, $members, $settingAddresses),
        $wall,
        $listRules
    );
    $table = uu_pf_table($pfctl(['-vvsTables'])['out'], UU_BLOCK_TABLE);
    $addresses = $table === null ? [] : uu_pf_show_addresses($pfctl(['-t', UU_BLOCK_TABLE, '-T', 'show'])['out']);
    return ['rules' => $rules, 'block_table' => ['table' => $table, 'addresses' => $addresses]];
}

/**
 * /sbin/pfctl with these arguments, no shell, its stdout and stderr apart: stderr goes to a temporary file, so a
 * long listing cannot block on a full pipe and no stderr line (pfctl's ALTQ notices on every call, or
 * `pfctl: DIOCGETRULE: Device busy` when a load cut a listing short) ever reaches a parser. A pfctl that cannot
 * be started, or that exits non-zero (a signal mid-listing too), gets a `pfctl:` line on stderr, so its listing
 * is unusable (uu_pf_listing_usable()); its stdout is kept, and nothing else reads stderr. The temporary file
 * lives in the root-only run directory, never in world-writable /tmp: tempnam() silently falls back to the
 * system temporary directory when runDir is unusable, so a file anywhere else is removed and pfctl is not run.
 * The temporary file goes in every case. $binary and $runDir are for the tests.
 *
 * @param list<string> $args
 * @return array{out: string, err: string}
 */
function uu_pfctl_run(array $args, string $binary = '/sbin/pfctl', string $runDir = UU_RUN_DIR): array
{
    /* @: the fallback's notice would reach PHP_errors.log; the dirname check below refuses that file */
    $errFile = @tempnam($runDir, 'uu_pfctl');
    if ($errFile !== false && dirname($errFile) !== $runDir) {
        unlink($errFile);
        $errFile = false;
    }
    if ($errFile === false) {
        return ['out' => '', 'err' => 'pfctl: no temporary file for its stderr'];
    }
    try {
        $pipes = [];
        $proc = proc_open(array_merge([$binary], $args),
            [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['file', $errFile, 'w']], $pipes);
        if (!is_resource($proc)) {
            return ['out' => '', 'err' => 'pfctl: could not be started'];
        }
        $out = (string)stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $rc = proc_close($proc);
        $err = (string)file_get_contents($errFile);
        if ($rc !== 0) {
            $err .= ($err === '' || str_ends_with($err, "\n") ? '' : "\n") . 'pfctl: exit ' . $rc . "\n";
        }
        return ['out' => $out, 'err' => $err];
    } finally {
        if (is_file($errFile)) {
            unlink($errFile);
        }
    }
}

/**
 * A live route equal to the one the plugin last installed for that address (the route record of its entry in the
 * state's addresses, uu_state_route_record()) is the plugin's own even when no current member explains it, so a group
 * renamed or deleted in tunnel mode lets fallback and stop replace or delete the plugin's stale route instead of
 * reading it as foreign. Per address: each adopted address leaves contract_input.foreign. evaluate.php applies it to
 * every snapshot before planning; a route matching neither stays foreign.
 *
 * @param array{now: int, wall: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, default: string,
 *         rows: array<string, string>, failback_delay: int, probe_name: string},
 *     trigger: string, tiers: list<list<string>>, family: string,
 *     members: array<string, array{name: string, interface: string, if: string, ipprotocol: string,
 *         resolver: string, next_hop: string, disabled: bool, force_down: bool, monitor_disable: bool,
 *         monitor: string, time_period: int, interval: int, loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>, stop: ?string,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     routes: array<string, array{present: bool, gateway: string, interface: string, reject: bool,
 *         ours: bool}>,
 *     route_flags: array<string, list<string>>,
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, monitors: array<string, list<string>>, statics: array<string, list<string>>,
 *         unmonitored_members: list<string>, foreign: list<string>, member_resolvers: array<string, string>,
 *         resolver_notes: list<string>, no_next_hop: list<string>,
 *         rules: array{state: string, problems: list<string>},
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int, core_commands: list<string>,
 *         unbound_conf: ?array{do_ip4: bool, do_ip6: bool, outgoing_interface: bool}, group_family: string,
 *         mixed_family: bool, family_mismatch: list<string>},
 *     rules: array{state: string, problems: list<string>, verified_at: ?int,
 *         record: ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>}},
 *     block_table: array{table: ?array{addresses: int, references: int, out_block: int}, addresses: list<string>}} $s
 * @param array<string, array{route: ?array{kind: string, next_hop: string, if: string}, forwarded: bool,
 *     released_at: ?int}> $addresses the saved state's map
 * @return array{now: int, wall: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, default: string,
 *         rows: array<string, string>, failback_delay: int, probe_name: string},
 *     trigger: string, tiers: list<list<string>>, family: string,
 *     members: array<string, array{name: string, interface: string, if: string, ipprotocol: string,
 *         resolver: string, next_hop: string, disabled: bool, force_down: bool, monitor_disable: bool,
 *         monitor: string, time_period: int, interval: int, loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>, stop: ?string,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     routes: array<string, array{present: bool, gateway: string, interface: string, reject: bool,
 *         ours: bool}>,
 *     route_flags: array<string, list<string>>,
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, monitors: array<string, list<string>>, statics: array<string, list<string>>,
 *         unmonitored_members: list<string>, foreign: list<string>, member_resolvers: array<string, string>,
 *         resolver_notes: list<string>, no_next_hop: list<string>,
 *         rules: array{state: string, problems: list<string>},
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int, core_commands: list<string>,
 *         unbound_conf: ?array{do_ip4: bool, do_ip6: bool, outgoing_interface: bool}, group_family: string,
 *         mixed_family: bool, family_mismatch: list<string>},
 *     rules: array{state: string, problems: list<string>, verified_at: ?int,
 *         record: ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>}},
 *     block_table: array{table: ?array{addresses: int, references: int, out_block: int}, addresses: list<string>}}
 */
function uu_route_adopt(array $s, array $addresses): array
{
    $adopted = [];
    foreach ($s['routes'] as $address => $route) {
        $address = (string)$address;
        $installed = uu_state_route_record(['addresses' => $addresses], $address);
        if ($installed === null || !$route['present'] || $route['ours']) {
            continue;
        }
        $matches = $installed['kind'] === 'reject'
            ? $route['reject'] && $route['interface'] === $installed['if']
            : $installed['kind'] === 'member' && !$route['reject'] && $route['gateway'] !== ''
                && uu_next_hop($route['gateway']) === uu_next_hop($installed['next_hop'])
                && $route['interface'] === $installed['if'];
        if ($matches) {
            $s['routes'][$address]['ours'] = true;
            $adopted[] = $address;
        }
    }
    if ($adopted === []) {
        return $s;
    }
    $s['contract_input']['foreign'] = array_values(array_diff($s['contract_input']['foreign'], $adopted));
    return $s;
}

/**
 * The settings as the scripts use them, checked again where they are used: a restored configuration bypasses the
 * model's masks. A Default resolver (the model's resolver field) that is not an IPv4 or IPv6 address, or is one the
 * model refuses (link-local, multicast, loopback, unspecified), is '' (unset) and any other is its canonical form, the
 * per-member rows are uu_rows_clean()'s, a probe name outside UU_PROBE_NAME_MASK is '.', a failback_delay is clamped to
 * 60..UU_FAILBACK_DELAY_MAX, a group id that is not a UUID is ''. One problem per substitution; none quotes the
 * value.
 *
 * fallback is false only for "0"; fail_closed and fail_closed_networks are the model's comma lists, sorted with
 * duplicates removed, the networks in canonical form and a value that is no network dropped with its own problem.
 *
 * @param array{resolver: string, rows: list<array{gateway: string, address: string}>, probe_name: string,
 *     failback_delay: string, group_uuid: string, fallback: string, fail_closed: string,
 *     fail_closed_networks: string} $raw
 * @return array{settings: array{default: string, rows: array<string, string>, probe_name: string,
 *     failback_delay: int, group_uuid: string, fallback: bool, fail_closed: list<string>,
 *     fail_closed_networks: list<string>}, problems: list<string>}
 *   rows: gateway UUID => canonical address
 */
function uu_settings_clean(array $raw): array
{
    $problems = [];
    $resolver = $raw['resolver'];
    if ($resolver !== '') {
        $refused = uu_resolver_refusal($resolver);
        if ($refused !== null) {
            $problems[] = 'settings: the resolver is ' . $refused . '; evaluating as unset';
            $resolver = '';
        } else {
            $resolver = uu_ip_canonical($resolver) ?? '';
        }
    }
    $rows = uu_rows_clean($raw['rows']);
    array_push($problems, ...$rows['problems']);
    $probe = $raw['probe_name'];
    if (preg_match(UU_PROBE_NAME_MASK . 'D', $probe) !== 1) {
        $problems[] = 'settings: probe name is not a host name or "."; probing the root';
        $probe = '.';
    }
    if (preg_match('/^\d+$/D', $raw['failback_delay']) !== 1) {
        $problems[] = 'settings: failback delay is not a number of seconds; using ' . UU_FAILBACK_DEFAULT;
        $delay = UU_FAILBACK_DEFAULT;
    } else {
        $delay = (int)$raw['failback_delay'];
        if ($delay < 60 || $delay > UU_FAILBACK_DELAY_MAX) {
            $problems[] = 'settings: failback delay is outside 60 to ' . UU_FAILBACK_DELAY_MAX . ' seconds; clamped';
            $delay = max(60, min(UU_FAILBACK_DELAY_MAX, $delay));
        }
    }
    $uuid = $raw['group_uuid'];
    if ($uuid !== '' && preg_match('/^[0-9a-f-]{36}$/D', $uuid) !== 1) {
        $problems[] = 'settings: gateway group is not an id; evaluating as none chosen';
        $uuid = '';
    }
    $interfaces = array_values(array_unique(array_filter(explode(',', $raw['fail_closed']), 'strlen')));
    sort($interfaces);
    $networks = [];
    foreach (array_filter(explode(',', $raw['fail_closed_networks']), 'strlen') as $entry) {
        $parts = explode('/', $entry);
        $addr = count($parts) === 2 ? uu_ip_canonical($parts[0]) : null;
        if ($addr === null || preg_match('/^\d{1,3}$/D', $parts[1]) !== 1
            || (int)$parts[1] > (str_contains($addr, ':') ? 128 : 32)) {
            $problems[] = 'settings: fail-closed network ' . $entry . ' is not a network; ignored';
            continue;
        }
        $networks[$addr . '/' . (int)$parts[1]] = true;
    }
    $networks = array_keys($networks);
    sort($networks);
    return ['settings' => ['default' => $resolver, 'rows' => $rows['rows'], 'probe_name' => $probe,
                           'failback_delay' => $delay, 'group_uuid' => $uuid, 'fallback' => $raw['fallback'] !== '0',
                           'fail_closed' => $interfaces, 'fail_closed_networks' => $networks],
            'problems' => $problems];
}

/**
 * The plugin's settings, cleaned by uu_settings_clean(). The group is the NAME of the gateway group the stored
 * UUID points at, '' when the group is gone or none is chosen. default is the Default resolver, rows the per-member
 * rows by gateway UUID. $warn logs each
 * substitution at LOG_WARNING: the evaluations pass it, status (polled every 30 s, so it would repeat the line) and
 * record do not.
 *
 * @return array{enabled: bool, dry_run: bool, group: string, default: string,
 *     rows: array<string, string>, failback_delay: int, probe_name: string, fallback: bool,
 *     fail_closed: list<string>, fail_closed_networks: list<string>}
 */
function uu_settings(bool $warn = false): array
{
    uu_load_core();
    $mdl = new \OPNsense\UnboundUpstream\UnboundUpstream();
    $rows = [];
    foreach ($mdl->resolvers->resolver->iterateItems() as $row) {
        $rows[] = ['gateway' => $row->gateway->getValue(), 'address' => $row->address->getValue()];
    }
    $clean = uu_settings_clean([
        'resolver' => $mdl->resolver->getValue(),
        'rows' => $rows,
        'probe_name' => $mdl->probe_name->getValue(),
        'failback_delay' => $mdl->failback_delay->getValue(),
        'group_uuid' => $mdl->gateway_group->getValue(),
        'fallback' => $mdl->fallback->getValue(),
        'fail_closed' => $mdl->fail_closed->getValue(),
        'fail_closed_networks' => $mdl->fail_closed_networks->getValue(),
    ]);
    if ($warn) {
        foreach ($clean['problems'] as $problem) {
            uu_log($problem, LOG_WARNING);
        }
    }
    $uuid = $clean['settings']['group_uuid'];
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
        'default' => $clean['settings']['default'],
        'rows' => $clean['settings']['rows'],
        'failback_delay' => $clean['settings']['failback_delay'],
        'probe_name' => $clean['settings']['probe_name'],
        'fallback' => $clean['settings']['fallback'],
        'fail_closed' => $clean['settings']['fail_closed'],
        'fail_closed_networks' => $clean['settings']['fail_closed_networks'],
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
 * Unbound's generated configuration files, in file-name order, as zone_read.py reads them: no path in the
 * directory is resolved through a link, so no device behind one is ever looked up (devfs clones tun and tap
 * interfaces on a lookup), and a file over UU_FILE_MAX_BYTES gives its first UU_FILE_MAX_BYTES up to the last line
 * end in them, so a large blocklist file still counts and a line the cut falls in (a forward-addr) is dropped whole.
 * The files are core's, written as root, but the directory belongs to Unbound's chroot, which uid unbound can write.
 * The helper runs from its argv (no shell) for at most $seconds. Null when the read failed, so the root zone reads
 * as unreadable and never as "no . zone", which would restore recursion over the WAN: a helper that cannot start,
 * runs past that (it is killed), exits non-zero (a DIR it cannot reach) or prints anything uu_zone_decode() refuses,
 * and a *.conf entry it skipped (a link, anything but a regular file, a file it cannot open or read), which may be
 * the one holding the root zone; never the empty list, which means no files. It logs nothing: status runs it every
 * 30 s, and the stop or contract that reads the zone names the problem. $dir, $helper and $seconds are for the
 * tests.
 *
 * @return ?list<string>
 */
function uu_zone_texts(string $dir = '/var/unbound/etc', string $helper = __DIR__ . '/../zone_read.py',
    int $seconds = UU_ZONE_READ_SECONDS): ?array
{
    $doc = uu_zone_read_run([$dir], $helper, $seconds);
    return $doc === null || $doc['skipped'] > 0 ? null : $doc['texts'];
}

/**
 * Unbound's generated unbound.conf (a single file, not a directory's *.conf), read as uu_zone_texts() reads a
 * directory's: zone_read.py --file opens its directory without following a link and the file as a regular file only.
 * Null when the read failed in any way uu_zone_texts() names (the helper cannot start, runs past $seconds, exits
 * non-zero, prints what uu_zone_decode() refuses) and when the file is a link, anything but a regular file, missing
 * or unreadable; the contract then refuses tunnel mode, since "could not look" is never "do-ip6 is on". It logs
 * nothing. $path, $helper and $seconds are for the tests.
 */
function uu_conf_file_text(string $path = '/var/unbound/unbound.conf', string $helper = __DIR__ . '/../zone_read.py',
    int $seconds = UU_ZONE_READ_SECONDS): ?string
{
    $doc = uu_zone_read_run(['--file', $path], $helper, $seconds);
    return $doc === null || $doc['skipped'] > 0 || count($doc['texts']) !== 1 ? null : $doc['texts'][0];
}

/**
 * Unbound's configuration as Unbound reads it: $path's text with every "include:" line replaced, in place, by the
 * included files' text (zone_read.py --conf, which does it all in one process, so the directory core empties and
 * refills at every Unbound start is looked at once: a file a glob listed that is gone by the time it is opened is no
 * file). The last "do-ip6:" line over the whole text is the one Unbound keeps. The rules are the helper's: globs, a
 * relative include taken from the last "directory:" line, a link or a non-regular file refused. A file over
 * UU_FILE_MAX_BYTES is cut after its last line end, so an option past the cut is not seen. An "include:" whose path is
 * on the next line is not followed (core never writes it). Null when anything is unreadable or the files exceed
 * UU_CONF_MAX_FILES or UU_CONF_MAX_BYTES (which also ends a loop): "could not look" is never "no override".
 * $helper and $seconds are for the tests.
 */
function uu_conf_expanded_text(string $path = '/var/unbound/unbound.conf',
    string $helper = __DIR__ . '/../zone_read.py', int $seconds = UU_ZONE_READ_SECONDS): ?string
{
    $doc = uu_zone_read_run(['--conf', $path], $helper, $seconds,
        [(string)UU_CONF_MAX_FILES, (string)UU_CONF_MAX_BYTES]);
    return $doc === null || $doc['skipped'] > 0 || count($doc['texts']) !== 1 ? null : $doc['texts'][0];
}

/**
 * zone_read.py run with $args (a DIR, or --file or --conf and a PATH), UU_FILE_MAX_BYTES and $tail, from its argv (no
 * shell), for at most $seconds, its stdout decoded (uu_zone_decode()); null for a helper that cannot start, runs
 * past that (it is killed), exits non-zero or prints what the decoder refuses.
 *
 * @param list<string> $args
 * @param list<string> $tail
 * @return ?array{texts: list<string>, skipped: int}
 */
function uu_zone_read_run(array $args, string $helper, int $seconds, array $tail = []): ?array
{
    $pipes = [];
    $proc = @proc_open([UU_PYTHON, '-I', $helper, ...$args, (string)UU_FILE_MAX_BYTES, ...$tail],
        [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
    if (!is_resource($proc)) {
        return null;
    }
    $deadline = hrtime(true) + $seconds * 1000000000;
    $out = '';
    $exit = null;
    try {
        stream_set_blocking($pipes[1], false);
        while (!feof($pipes[1])) {
            $left = $deadline - hrtime(true);
            $ready = [$pipes[1]];
            $none = null;
            if ($left <= 0
                || @stream_select($ready, $none, $none, intdiv($left, 1000000000), intdiv($left % 1000000000, 1000))
                === false) {
                return null;
            }
            $out .= (string)fread($pipes[1], 65536);
        }
        $status = proc_get_status($proc);
        while ($status['running'] && hrtime(true) < $deadline) {
            usleep(10000);
            $status = proc_get_status($proc);
        }
        if ($status['running']) {
            return null;
        }
        $exit = $status['exitcode'];
    } finally {
        fclose($pipes[1]);
        if ($exit === null) {
            proc_terminate($proc, 9);
        }
        proc_close($proc);
    }
    return $exit === 0 ? uu_zone_decode($out) : null;
}

/**
 * zone_read.py's stdout, strictly: a JSON object with exactly texts, a list of base64 strings, each a file's bytes,
 * and skipped, the number of *.conf entries it skipped, a whole number. Null for anything else (bad JSON, a list, a
 * missing or extra key, texts that is not a list or holds a non-string or an entry that is not base64, skipped that
 * is not a whole number). Pure.
 *
 * @return ?array{texts: list<string>, skipped: int}
 */
function uu_zone_decode(string $stdout): ?array
{
    try {
        $doc = json_decode($stdout, false, 3, JSON_THROW_ON_ERROR);
    } catch (\JsonException) {
        return null;
    }
    if (!$doc instanceof \stdClass) {
        return null;
    }
    $keys = array_keys(get_object_vars($doc));
    sort($keys);
    if ($keys !== ['skipped', 'texts'] || !is_array($doc->texts) || !is_int($doc->skipped) || $doc->skipped < 0) {
        return null;
    }
    $texts = [];
    foreach ($doc->texts as $entry) {
        $text = is_string($entry) ? base64_decode($entry, true) : false;
        if ($text === false) {
            return null;
        }
        $texts[] = $text;
    }
    return ['texts' => $texts, 'skipped' => $doc->skipped];
}

/**
 * A snapshot evaluate.php record wrote, in this version's shape for replay: a recording made before 1.3 has no
 * contract_input.core_commands, which reads as nothing drifted, since that version did not check; an earlier 1.4
 * recording has no route_flags, which reads as no flags read (only the status shows them), placed right after routes
 * so the top-level order is this version's. A recording made before 1.4 (a route and no routes) is refused: it has
 * one resolver's route and none of the per-member fields, and a recording is a diagnostic of one box at one time, so
 * it is recorded again rather than converted. Anything else is as recorded; replay checks the top-level shape.
 *
 * @param array<string, mixed> $snapshot
 * @param string $path the recording's file, which the refusal names
 * @return array<string, mixed>
 */
function uu_snapshot_recorded(array $snapshot, string $path): array
{
    if (!array_key_exists('routes', $snapshot)) {
        throw new RuntimeException("$path was recorded before 1.4: record it again");
    }
    if (is_array($snapshot['contract_input'] ?? null)
        && !array_key_exists('core_commands', $snapshot['contract_input'])) {
        $snapshot['contract_input']['core_commands'] = [];
    }
    if (!array_key_exists('route_flags', $snapshot)) {
        $after = (int)array_search('routes', array_keys($snapshot), true) + 1;
        $snapshot = array_slice($snapshot, 0, $after, true) + ['route_flags' => []]
            + array_slice($snapshot, $after, null, true);
    }
    return $snapshot;
}

/**
 * The Snapshot (planner.php) for the given settings. now is monotonic seconds (every timer runs on it); wall is the wall clock, for display only.
 *
 * @param array{enabled: bool, dry_run: bool, group: string, default: string,
 *     rows: array<string, string>, failback_delay: int, probe_name: string} $settings uu_settings()
 * @param list<string> $named the gateways the monitor hook passed
 * @param ?string $stop why this run stops whatever the settings say (a UU_STOP_* cause), or null
 * @param bool $listRules whether the ruleset may be listed when no verification of the live checksum is saved, or
 *     the saved one is a fault (it is verified again), or a listing was cut short: an evaluation's snapshot, never
 *     a status call's
 * @param list<string> $stateAddresses the saved state's map keys (uu_state_footprint()): routes covers them beside
 *     the planner's addresses (uu_plan_addresses()), so an address the plugin may still be routed to is read too
 * @return array{now: int, wall: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, default: string,
 *         rows: array<string, string>, failback_delay: int, probe_name: string},
 *     trigger: string, tiers: list<list<string>>, family: string,
 *     members: array<string, array{name: string, interface: string, if: string, ipprotocol: string,
 *         resolver: string, next_hop: string, disabled: bool, force_down: bool, monitor_disable: bool,
 *         monitor: string, time_period: int, interval: int, loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>, stop: ?string,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     routes: array<string, array{present: bool, gateway: string, interface: string, reject: bool,
 *         ours: bool}>,
 *     route_flags: array<string, list<string>>,
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, monitors: array<string, list<string>>, statics: array<string, list<string>>,
 *         unmonitored_members: list<string>, foreign: list<string>, member_resolvers: array<string, string>,
 *         resolver_notes: list<string>, no_next_hop: list<string>,
 *         rules: array{state: string, problems: list<string>},
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int, core_commands: list<string>,
 *         unbound_conf: ?array{do_ip4: bool, do_ip6: bool, outgoing_interface: bool}, group_family: string,
 *         mixed_family: bool, family_mismatch: list<string>},
 *     rules: array{state: string, problems: list<string>, verified_at: ?int,
 *         record: ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>}},
 *     block_table: array{table: ?array{addresses: int, references: int, out_block: int}, addresses: list<string>}}
 */
function uu_snapshot(array $settings, array $named, ?string $stop, bool $listRules, array $stateAddresses): array
{
    /* pfctl's stderr file goes in the run directory, and a status after a boot runs before any evaluation made it */
    uu_run_dir();
    uu_load_core();
    $now = intdiv(hrtime(true), 1000000000);
    $wall = time();

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
                'ipprotocol' => (string)($gw['ipprotocol'] ?? ''),
                'resolver' => '',
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

    /* each member's effective resolver: its row (by the gateway's UUID; a dynamic gateway has none) else the
     * Default */
    $effective = uu_member_resolvers(array_map('strval', array_keys($members)), $settings['rows'],
        uu_gateway_names($all), $settings['default']);
    $noNextHop = [];
    foreach ($members as $name => $m) {
        $members[$name]['resolver'] = $effective['resolvers'][$name] ?? '';
        if (!uu_next_hop_routable($m['next_hop'])) {
            $noNextHop[] = (string)$name;
        }
    }
    /* the planner's addresses: the effective resolvers, or the Default when the group has no member */
    $addresses = uu_plan_addresses(['settings' => $settings, 'members' => $members]);
    /* the group's family, and the effective resolvers of the other one (the family of an address is its own) */
    $groupFamily = uu_group_family($members, $tiers);
    $mismatch = uu_family_mismatch($groupFamily, $addresses);
    $monitors = [];
    foreach ($addresses as $address) {
        $monitoring = uu_resolver_monitors($all, $address);
        if ($monitoring !== []) {
            $monitors[$address] = $monitoring;
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
    $confText = uu_conf_expanded_text();
    $unboundConf = $confText === null ? null : uu_unbound_conf_facts($confText);

    /* the route of every planner address and every address the state's map holds; a foreign route is the contract's
     * only for a planner address (one the state alone holds excludes nobody) */
    $routed = [];
    foreach ($addresses as $address) {
        $routed[$address] = true;
    }
    foreach ($stateAddresses as $address) {
        $canonical = uu_ip_canonical($address);
        if ($canonical !== null) {
            $routed[$canonical] = true;
        }
    }
    /* each read's flags are kept as route(8) printed them, whatever route they describe: the status shows them for a
     * present route */
    $routeFlags = [];
    $read = function (string $address) use ($members, &$routeFlags): array {
        $route = ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false];
        $routeArgs = uu_route_get_args($address);
        if ($routeArgs !== null) {
            $out = (string)shell_exec('/sbin/route -n get ' . $routeArgs . ' 2>/dev/null');
            $route = uu_parse_route_get($out);
            $routeFlags[$address] = uu_status_route_flags($out);
        }
        return $route + ['ours' => uu_route_ours($route, $members)];
    };
    $routes = [];
    $foreign = [];
    $keys = array_map('strval', array_keys($routed));
    sort($keys, SORT_STRING);
    foreach ($keys as $address) {
        $routes[$address] = $read($address);
        if ($routes[$address]['present'] && !$routes[$address]['ours'] && in_array($address, $addresses, true)) {
            $foreign[] = $address;
        }
    }
    $fibSyncMs = uu_parse_sysctl_int((string)shell_exec('/sbin/sysctl -n net.route.algo.fib_max_sync_delay_ms 2>/dev/null'));

    /* static routes that cover a planner address */
    $statics = [];
    if ($addresses !== []) {
        foreach ((new \OPNsense\Routes\Route())->route->iterateItems() as $r) {
            $network = $r->network->getValue();
            foreach ($addresses as $address) {
                if ($r->enabled->isEqual('1') && uu_in_static($address, $network)) {
                    $statics[$address][] = $network;
                }
            }
        }
    }

    /* the hook-order contract: unbound_start is registered by unbound.inc and unbound.inc is scanned first */
    $hooks = false;
    if (stream_resolve_include_path('plugins.inc.d/unbound.inc') !== false) {
        require_once 'plugins.inc.d/unbound.inc';
        $hooks = function_exists('unbound_configure') && array_key_exists('unbound_start', unbound_configure());
    }

    /* pf: the rules' verdict for the live checksum and the counting table */
    $setting = uu_setting_addresses(['settings' => $settings, 'contract_input' => ['group_found' => $group !== null],
        'members' => $members]);
    $pf = uu_pf_observe(uu_ruled_members($members), $setting, $settings['default'], uu_rules_record_load(UU_RULES_PATH),
        $wall, $listRules, 'uu_pfctl_run');

    return [
        'now' => $now,
        'wall' => $wall,
        'settings' => $settings,
        'trigger' => $trigger,
        'tiers' => $tiers,
        'family' => $groupFamily['family'],
        'members' => $members,
        'probes' => $probes,
        'named' => $named,
        'stop' => $stop,
        'unbound' => [
            'enabled' => $unboundMdl->general->enabled->isEqual('1'),
            'pid_alive' => $pidAlive,
            'control_ok' => $liveRoot !== null,
            'live_root' => $liveRoot,
        ],
        'zone' => $zone,
        'routes' => $routes,
        'route_flags' => $routeFlags,
        'fib_sync_ms' => $fibSyncMs,
        'contract_input' => [
            'unbound_hooks_registered' => $hooks,
            'unbound_sorts_first' => uu_unbound_sorts_first(array_map('strval', array_keys(plugins_scan()))),
            'groups_have_tiers' => $groupsHaveTiers,
            'status_fields' => $statusFields,
            'monitors' => $monitors,
            'statics' => $statics,
            'unmonitored_members' => $unmonitored,
            'foreign' => $foreign,
            'member_resolvers' => $effective['resolvers'],
            'resolver_notes' => $effective['notes'],
            'no_next_hop' => $noNextHop,
            'rules' => ['state' => $pf['rules']['state'], 'problems' => $pf['rules']['problems']],
            'zone' => $zone,
            'fib_sync_ms' => $fibSyncMs,
            'cacheflush' => $unboundMdl->general->cacheflush->isEqual('1'),
            'group_found' => $group !== null,
            'members' => count($members),
            'core_commands' => uu_core_commands_changed(),
            'unbound_conf' => $unboundConf,
            'group_family' => $groupFamily['family'],
            'mixed_family' => $groupFamily['mixed'],
            'family_mismatch' => $mismatch,
        ],
        'rules' => $pf['rules'],
        'block_table' => $pf['block_table'],
    ];
}
