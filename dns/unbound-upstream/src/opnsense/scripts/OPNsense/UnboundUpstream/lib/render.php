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
 * The rules, every pass before every block (ruling R47), so that no block, the counting block's table included, can
 * shadow a pass: the setting's passes, the footprint's pass when it has an interface, the setting's blocks, the
 * footprint's block.
 *
 * @param list<array{interface: string}> $members
 * @param ?array{resolver: string, interface: string} $footprint
 * @return list<array<string, string|bool>>
 */
function uu_rule_confs(string $resolver, array $members, bool $counting, ?array $footprint): array
{
    $confs = uu_setting_passes($resolver, $members);
    if ($footprint !== null && $footprint['interface'] !== '') {
        $confs[] = uu_pass_conf($footprint['interface'], $footprint['resolver'],
            uu_label_footprint_pass($footprint['interface']),
            'Unbound upstream: the address the plugin last used, through the device of its route');
    }
    array_push($confs, ...uu_setting_blocks($resolver, $counting));
    if ($footprint !== null) {
        $confs[] = uu_block_conf($footprint['resolver'], uu_label_footprint(),
            'Unbound upstream: the address the plugin last used never leaves by another interface');
    }
    return $confs;
}

/**
 * The setting's passes when it names a resolver: one per distinct member interface, on the member's friendly
 * interface name, which core maps to the device, with the interface's own address as source so a query that Unbound
 * sent from another address cannot ride a member out. disablereplyto keeps the pass from also stamping reply-to.
 *
 * @param list<array{interface: string}> $members
 * @return list<array<string, string|bool>>
 */
function uu_setting_passes(string $resolver, array $members): array
{
    $confs = [];
    $seen = [];
    foreach ($resolver === '' ? [] : $members as $member) {
        $opt = $member['interface'];
        if ($opt === '' || isset($seen[$opt])) {
            continue;
        }
        $seen[$opt] = true;
        $confs[] = uu_pass_conf($opt, $resolver, uu_label_pass($opt),
            'Unbound upstream: the resolver through this member');
    }
    return $confs;
}

/**
 * The setting's blocks when it names a resolver: the counting block when asked, which targets the plugin table, then
 * the backstop, which targets the resolver itself and is always rendered with the setting's rules.
 *
 * @return list<array<string, string|bool>>
 */
function uu_setting_blocks(string $resolver, bool $counting): array
{
    if ($resolver === '') {
        return [];
    }
    $confs = [];
    if ($counting) {
        $confs[] = uu_block_conf('<' . UU_BLOCK_TABLE . '>', uu_label_block(),
            'Unbound upstream: the resolver never leaves by another interface (counted)');
    }
    $confs[] = uu_block_conf($resolver, uu_label_backstop(),
        'Unbound upstream: the resolver never leaves by another interface (backstop)');
    return $confs;
}

/**
 * @return array<string, string|bool>
 */
function uu_pass_conf(string $opt, string $to, string $label, string $descr): array
{
    return [
        'type' => 'pass', 'direction' => 'out', 'quick' => true, 'interface' => $opt, 'ipprotocol' => 'inet',
        'protocol' => 'tcp/udp', 'from' => $opt . 'ip', 'to' => $to, 'to_port' => '53',
        'disablereplyto' => true, 'label' => $label, 'descr' => $descr,
    ];
}

/**
 * @return array<string, string|bool>
 */
function uu_block_conf(string $to, string $label, string $descr): array
{
    return [
        'type' => 'block', 'direction' => 'out', 'quick' => true, 'log' => true, 'ipprotocol' => 'inet',
        'to' => $to, 'label' => $label, 'descr' => $descr,
    ];
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
    $address = uu_state_footprint($state);
    if ($address === null) {
        return ['footprint' => null, 'problem' => $state['resolver'] === null ? null
            : 'the address the plugin last used is not an IPv4 address'];
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
 * What to render (ruling R48). The state file at $statePath is read first, on its own; core's settings ($model) are
 * read next, and the gateway records ($records) only when the setting may render or the state records an address,
 * so a disabled plugin with no footprint reads no records. The setting renders when the settings and the records were
 * both read and name it; its rules go to the resolver only when that is IPv4, so a setting naming anything else
 * leaves the footprint its own rules. A failed settings read renders the footprint as if the setting rendered nothing
 * (its pass and its block); a failed records read leaves the footprint its block alone, which error then names: DNS
 * to that address is blocked until a reload can read the records (ruling R48). Each failed read is part of error,
 * which is null when every read needed succeeded; a state file that cannot be read is no footprint, and its problem
 * is footprint_problem.
 *
 * @param callable(): array{resolver: string, gateways: ?list<string>} $model the settings: the resolver, and the
 *     group's gateway names when the plugin is on with a group found and a resolver set, else null
 * @param callable(): array<array-key, array<string, mixed>> $records gatewaysIndexedByName()'s shape
 * @return array{enabled: bool, resolver: string, members: list<array{name: string, interface: string, if: string}>,
 *     footprint: ?array{resolver: string, interface: string}, footprint_problem: ?string, error: ?string}
 */
function uu_wanted_from(callable $model, callable $records, string $statePath): array
{
    $read = uu_state_read($statePath);
    $errors = [];
    $settings = null;
    try {
        $settings = $model();
    } catch (\Throwable $e) {
        $errors[] = 'cannot read the settings: ' . $e->getMessage();
    }
    $gateways = $settings['gateways'] ?? null;
    $recs = null;
    $recsFailed = false;
    if ($gateways !== null || $read['state']['resolver'] !== null) {
        try {
            $recs = $records();
        } catch (\Throwable $e) {
            $recsFailed = true;
            $errors[] = 'cannot read the gateway records: ' . $e->getMessage();
        }
    }
    $enabled = $gateways !== null && $recs !== null;
    $resolver = $enabled ? (string)($settings['resolver'] ?? '') : '';
    $members = [];
    foreach ($enabled ? $gateways : [] as $name) {
        if (!isset($recs[$name])) {
            continue;
        }
        $members[] = ['name' => (string)$name, 'interface' => (string)($recs[$name]['interface'] ?? ''),
            'if' => (string)($recs[$name]['if'] ?? '')];
    }
    $setting = $enabled && filter_var($resolver, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false ? $resolver : '';
    $found = uu_footprint_from_state($read['state'], $recs ?? [], $setting);
    if ($recsFailed && $found['footprint'] !== null) {
        /* the address passed uu_footprint_from_state()'s IPv4 check */
        $errors[] = 'DNS to ' . $found['footprint']['resolver']
            . ' is blocked until a filter reload can read the gateway records';
    }
    return ['enabled' => $enabled, 'resolver' => $resolver, 'members' => $members, 'footprint' => $found['footprint'],
        'footprint_problem' => $read['problem'] !== null ? 'the state file is ' . $read['problem'] : $found['problem'],
        'error' => $errors === [] ? null : implode('; ', $errors)];
}

/**
 * The plugin's settings as uu_wanted_from() takes them, from the saved model and core's gateway groups: the group's
 * gateway names only when the plugin is on, a group is chosen and found, and a resolver is set.
 *
 * @return array{resolver: string, gateways: ?list<string>}
 */
function uu_render_model(): array
{
    $mdl = new \OPNsense\UnboundUpstream\UnboundUpstream();
    if (!$mdl->enabled->isEqual('1') || $mdl->gateway_group->isEmpty() || $mdl->resolver->isEmpty()) {
        return ['resolver' => '', 'gateways' => null];
    }
    $groups = new \OPNsense\Routing\GatewayGroups();
    foreach ($groups->gateway_group->iterateItems() as $uuid => $item) {
        if ($uuid === $mdl->gateway_group->getValue()) {
            return ['resolver' => $mdl->resolver->getValue(),
                    'gateways' => array_map('strval', array_values($groups->gatewaysInGroup($item)))];
        }
    }
    return ['resolver' => '', 'gateways' => null];
}

/**
 * What to render, from the plugin's state file, the saved model and the live gateway records (uu_wanted_from()).
 *
 * @return array{enabled: bool, resolver: string, members: list<array{name: string, interface: string, if: string}>,
 *     footprint: ?array{resolver: string, interface: string}, footprint_problem: ?string, error: ?string}
 */
function uu_wanted_render(): array
{
    return uu_wanted_from('uu_render_model',
        fn (): array => (new \OPNsense\Routing\Gateways())->gatewaysIndexedByName(true), UU_STATE_PATH);
}

/**
 * The plugins_firewall hook body. Never throws. What each failure keeps:
 * - a settings or gateway records read that fails is one error, and the footprint still renders (uu_wanted_from());
 * - a setting resolver that is not IPv4 is one error, the setting renders nothing and the footprint still renders;
 * - a state file that cannot be read, or a recorded address that is not IPv4, is one warning for the render, and the
 *   setting's rules still render: each filter reload is a process of its own, so the hook keeps nothing between
 *   renders;
 * - a table that cannot be registered costs only the counting block;
 * - a rule that cannot be registered costs only itself, and is one error naming its description;
 * - anything else that throws renders nothing, and is one error.
 * The table is registered for the setting's counting block only.
 *
 * Lines go through logger(1), not openlog(): the hook runs inside core's filter reload and must not replace core's
 * syslog ident or drop its connection.
 *
 * @param ?callable(): array{enabled: bool, resolver: string, members: list<array{interface: string}>,
 *     footprint: ?array{resolver: string, interface: string}, footprint_problem: ?string, error: ?string} $wanted
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
        if ($w['error'] !== null) {
            $emit('rules for the setting not rendered: ' . uu_log_text($w['error']), 'err');
        }
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
        // Each rule registers on its own: a rule core refuses must never cost the blocks after it.
        foreach (uu_rule_confs($resolver, $w['members'], $counting, $w['footprint']) as $conf) {
            try {
                $fw->registerFilterRule(UU_RULE_PRIORITY, $conf);
            } catch (\Throwable $e) {
                $emit('rules: "' . $conf['descr'] . '" not rendered: ' . uu_log_text($e->getMessage()), 'err');
            }
        }
    } catch (\Throwable $e) {
        $emit('rules not rendered: ' . uu_log_text($e->getMessage()), 'err');
    }
}
