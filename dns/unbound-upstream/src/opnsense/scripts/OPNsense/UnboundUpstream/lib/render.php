<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Rendered allow-list (spec 2026-10-17 section 3.6b): queries to the resolver may leave only through a member
 * of the configured group. One pass per member, then two blocks to the resolver on every other interface,
 * registered as filter rules at every filter reload and never stored in the configuration. Core calls the
 * plugin's firewall hook both for a real reload and to list rules for display, so the hook only registers.
 *
 * Why there are two blocks and a table: the counting block targets the table __unboundupstream_block, so the
 * status can read which addresses the table holds and how many packets it stopped; the backstop targets the
 * resolver as a literal address and does not depend on the table. The table counts, the literal guarantees:
 * should the table be empty or missing, the backstop still keeps the resolver off every other interface. The
 * table is registered without persist or file, so core's ruleset load never depends on a plugin file, and pf
 * keeps the addresses a table declared without any holds across reloads. Its name is in core's __ namespace,
 * which core's alias-name validator refuses, so no alias can share it.
 *
 * The footprint (spec -04 section 3.2, convention C2): while the state records an address the plugin's route or
 * Unbound's live root may still refer to, that address keeps a block of its own, and a pass on the device of the
 * plugin's route, whatever the settings say, until a stop clears it. Core also calls the hook in the web server's
 * process to list the automatic rules; that process cannot search the root-only run directory, so the listing
 * shows the setting's rules only, while the loaded ruleset has both.
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/logline.php';
require_once __DIR__ . '/state.php';

/** The pf label of a member interface's pass rule; the status reads its counters by it. */
function uu_label_pass(string $opt): string
{
    return md5('uu-pass-' . $opt);
}

/** The pf label of the counting block; the rules verdict looks for it by this label. */
function uu_label_block(): string
{
    return md5('uu-block');
}

/** The pf label of the backstop block; the rules verdict looks for it by this label. */
function uu_label_backstop(): string
{
    return md5('uu-backstop');
}

/** The pf label of the footprint block; the rules verdict ignores it (spec -04 decision D3). */
function uu_label_footprint(): string
{
    return md5('uu-footprint');
}

/**
 * The pf label of the footprint pass on a member interface. Not uu_label_pass(): the verdict requires every line under
 * a member's pass label to go to the setting's resolver, and the footprint pass goes to another address (ruling R2).
 */
function uu_label_footprint_pass(string $opt): string
{
    return md5('uu-footprint-pass-' . $opt);
}

/**
 * The setting's rules, when it names a resolver: one pass per distinct member interface, then the counting block
 * when asked, then the backstop. The pass is on the member's friendly interface name, which core maps to the
 * device, with the interface's own address as source so a query that Unbound sent from another address cannot ride
 * a member out. disablereplyto keeps the pass from also stamping reply-to. The counting block targets the plugin
 * table; the backstop targets the resolver itself and is always rendered with the setting's rules. Then the
 * footprint's: its pass on the same terms when it has an interface, and its block.
 *
 * @param list<array{interface: string}> $members
 * @param ?array{resolver: string, interface: string} $footprint
 * @return list<array<string, string|bool>>
 */
function uu_rule_confs(string $resolver, array $members, bool $counting, ?array $footprint): array
{
    $confs = [];
    if ($resolver !== '') {
        array_push($confs, ...uu_setting_confs($resolver, $members, $counting));
    }
    if ($footprint !== null) {
        $opt = $footprint['interface'];
        if ($opt !== '') {
            $confs[] = [
                'type' => 'pass', 'direction' => 'out', 'quick' => true, 'interface' => $opt,
                'ipprotocol' => 'inet', 'protocol' => 'tcp/udp', 'from' => $opt . 'ip',
                'to' => $footprint['resolver'], 'to_port' => '53', 'disablereplyto' => true,
                'label' => uu_label_footprint_pass($opt),
                'descr' => 'Unbound upstream: the address the plugin last used, through the device of its route',
            ];
        }
        $confs[] = [
            'type' => 'block', 'direction' => 'out', 'quick' => true, 'log' => true, 'ipprotocol' => 'inet',
            'to' => $footprint['resolver'], 'label' => uu_label_footprint(),
            'descr' => 'Unbound upstream: the address the plugin last used never leaves by another interface',
        ];
    }
    return $confs;
}

/**
 * The setting's part of uu_rule_confs().
 *
 * @param list<array{interface: string}> $members
 * @return list<array<string, string|bool>>
 */
function uu_setting_confs(string $resolver, array $members, bool $counting): array
{
    $confs = [];
    $seen = [];
    foreach ($members as $member) {
        $opt = $member['interface'];
        if ($opt === '' || isset($seen[$opt])) {
            continue;
        }
        $seen[$opt] = true;
        $confs[] = [
            'type' => 'pass', 'direction' => 'out', 'quick' => true, 'interface' => $opt, 'ipprotocol' => 'inet',
            'protocol' => 'tcp/udp', 'from' => $opt . 'ip', 'to' => $resolver, 'to_port' => '53',
            'disablereplyto' => true, 'label' => uu_label_pass($opt),
            'descr' => 'Unbound upstream: the resolver through this member',
        ];
    }
    if ($counting) {
        $confs[] = [
            'type' => 'block', 'direction' => 'out', 'quick' => true, 'log' => true, 'ipprotocol' => 'inet',
            'to' => '<' . UU_BLOCK_TABLE . '>', 'label' => uu_label_block(),
            'descr' => 'Unbound upstream: the resolver never leaves by another interface (counted)',
        ];
    }
    $confs[] = [
        'type' => 'block', 'direction' => 'out', 'quick' => true, 'log' => true, 'ipprotocol' => 'inet',
        'to' => $resolver, 'label' => uu_label_backstop(),
        'descr' => 'Unbound upstream: the resolver never leaves by another interface (backstop)',
    ];
    return $confs;
}

/**
 * The footprint (ruling R1): the address the state records, when it is IPv4 and not the address the setting's rules
 * already go to ($settingResolver, '' when they render none), with the friendly interface of the plugin's route. That
 * interface is the one of the gateway record on the route's device with the route's next hop, the first such record
 * by name that has one; it is '' when the route is no member route or no record names it, and the footprint then
 * has its block only, since core renders an interface it does not know as a placeholder that breaks the ruleset.
 * A recorded address that is not IPv4 is no footprint but a problem, which never quotes the address.
 *
 * @param array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int,
 *         last_down: ?array{at: int, reason: string}}>, control_failures: int, control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     route_installed: ?array{kind: string, next_hop: string, if: string}, resolver: ?string} $state
 * @param array<array-key, array<string, mixed>> $records gatewaysIndexedByName()'s shape
 * @return array{footprint: ?array{resolver: string, interface: string}, problem: ?string}
 */
function uu_footprint_from_state(array $state, array $records, string $settingResolver): array
{
    $address = $state['resolver'];
    if ($address === null) {
        return ['footprint' => null, 'problem' => null];
    }
    if (filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
        return ['footprint' => null, 'problem' => 'the address the plugin last used is not an IPv4 address'];
    }
    if ($address === $settingResolver) {
        return ['footprint' => null, 'problem' => null];
    }
    $interface = '';
    $route = $state['route_installed'];
    if ($route !== null && $route['kind'] === 'member') {
        $names = array_map('strval', array_keys($records));
        sort($names, SORT_STRING);
        foreach ($names as $name) {
            $record = $records[$name];
            $opt = (string)($record['interface'] ?? '');
            if ($opt !== '' && (string)($record['if'] ?? '') === $route['if']
                && (string)($record['gateway'] ?? '') === $route['next_hop']) {
                $interface = $opt;
                break;
            }
        }
    }
    return ['footprint' => ['resolver' => $address, 'interface' => $interface], 'problem' => null];
}

/**
 * What to render, from the setting, the gateway records and the state file at $statePath. $enabled is whether the
 * setting renders (on, with its group found and a resolver set) and $members are the group's; the setting's rules
 * go to the resolver only when it is IPv4, so a setting naming anything else leaves the footprint its own rules. A
 * state file that cannot be read is no footprint, and its problem is the footprint's.
 *
 * @param list<array{name: string, interface: string, if: string}> $members
 * @param array<array-key, array<string, mixed>> $records gatewaysIndexedByName()'s shape
 * @return array{enabled: bool, resolver: string, members: list<array{name: string, interface: string, if: string}>,
 *     footprint: ?array{resolver: string, interface: string}, footprint_problem: ?string}
 */
function uu_wanted_from(bool $enabled, string $resolver, array $members, array $records, string $statePath): array
{
    $setting = $enabled && filter_var($resolver, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false ? $resolver : '';
    $read = uu_state_read($statePath);
    $found = uu_footprint_from_state($read['state'], $records, $setting);
    return ['enabled' => $enabled, 'resolver' => $resolver, 'members' => $members, 'footprint' => $found['footprint'],
        'footprint_problem' => $read['problem'] !== null ? 'the state file is ' . $read['problem'] : $found['problem']];
}

/**
 * What to render, from the saved model, the live gateway records and the plugin's state file. Disabled, or a group
 * or resolver that cannot be resolved, is enabled false: no setting rules. The records are read in every case, for
 * the footprint.
 *
 * @return array{enabled: bool, resolver: string, members: list<array{name: string, interface: string, if: string}>,
 *     footprint: ?array{resolver: string, interface: string}, footprint_problem: ?string}
 */
function uu_wanted_render(): array
{
    $mdl = new \OPNsense\UnboundUpstream\UnboundUpstream();
    $records = (new \OPNsense\Routing\Gateways())->gatewaysIndexedByName(true);
    $members = null;
    if ($mdl->enabled->isEqual('1') && !$mdl->gateway_group->isEmpty() && !$mdl->resolver->isEmpty()) {
        $members = uu_group_members($mdl->gateway_group->getValue(), $records);
    }
    return uu_wanted_from($members !== null, $members !== null ? $mdl->resolver->getValue() : '', $members ?? [],
        $records, UU_STATE_PATH);
}

/**
 * The members of the gateway group with this id that have a gateway record, or null when no group has the id.
 *
 * @param array<array-key, array<string, mixed>> $records gatewaysIndexedByName()'s shape
 * @return ?list<array{name: string, interface: string, if: string}>
 */
function uu_group_members(string $uuid, array $records): ?array
{
    $groups = new \OPNsense\Routing\GatewayGroups();
    foreach ($groups->gateway_group->iterateItems() as $key => $item) {
        if ($key !== $uuid) {
            continue;
        }
        $members = [];
        foreach ($groups->gatewaysInGroup($item) as $name) {
            if (!isset($records[$name])) {
                continue;
            }
            $members[] = ['name' => (string)$name, 'interface' => (string)($records[$name]['interface'] ?? ''),
                'if' => (string)($records[$name]['if'] ?? '')];
        }
        return $members;
    }
    return null;
}

/**
 * The plugins_firewall hook body. Never throws: any failure renders nothing and is logged.
 *
 * The setting's rules render when it is enabled and its resolver is IPv4; a resolver that is not is one error, and
 * the setting renders nothing (ruling R11). The footprint's rules follow, whatever the setting, and the table is
 * registered for the setting's counting block only. A footprint that cannot be read is one warning for the render
 * (spec -04 section 3.2): each filter reload is a process of its own, so the hook keeps nothing between renders.
 *
 * Lines go through logger(1), not openlog(): the hook runs inside core's filter reload and must not replace core's
 * syslog ident or drop its connection.
 *
 * @param ?callable(): array{enabled: bool, resolver: string, members: list<array{interface: string}>,
 *     footprint: ?array{resolver: string, interface: string}, footprint_problem: ?string} $wanted
 * @param ?callable(string, string): void $log receives the message and its syslog level name (err, warning); default
 *     logs it as UU_SYSLOG_IDENT at local4
 */
function uu_render_firewall(\OPNsense\Firewall\Plugin $fw, ?callable $wanted = null, ?callable $log = null): void
{
    $emit = static function (string $msg, string $level) use ($log): void {
        if ($log !== null) {
            $log($msg, $level);
        } else {
            uu_logger($msg, $level);
        }
    };
    try {
        $w = $wanted !== null ? $wanted() : uu_wanted_render();
        $resolver = '';
        if ($w['enabled']) {
            if (filter_var($w['resolver'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
                $emit('rules for the resolver setting not rendered: resolver is not an IPv4 address', 'err');
            } else {
                $resolver = $w['resolver'];
            }
        }
        if ($w['footprint_problem'] !== null) {
            $emit('footprint rules not rendered: ' . uu_log_text($w['footprint_problem']), 'warning');
        }
        // The counting block needs its table; a failure here must never cost the passes or the backstop.
        $counting = false;
        if ($resolver !== '') {
            try {
                $fw->registerTable(UU_BLOCK_TABLE);
                $counting = true;
            } catch (\Throwable $e) {
                $counting = false;
                $emit('rules: counting block not rendered: ' . uu_log_text($e->getMessage()), 'err');
            }
        }
        foreach (uu_rule_confs($resolver, $w['members'], $counting, $w['footprint']) as $conf) {
            $fw->registerFilterRule(UU_RULE_PRIORITY, $conf);
        }
    } catch (\Throwable $e) {
        $emit('rules not rendered: ' . uu_log_text($e->getMessage()), 'err');
    }
}
