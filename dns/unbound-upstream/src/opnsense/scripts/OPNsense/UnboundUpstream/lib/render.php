<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Rendered allow-list: queries to a member's resolver may leave only through that member of the configured group.
 * One pass per member interface and resolver, then blocks to every setting address on every other interface, each
 * rule in its address's family, registered as filter rules at every filter reload and never stored in the
 * configuration. Core calls the plugin's firewall hook both for a real reload and to list rules for display, so the
 * hook only registers.
 *
 * Why there are two kinds of block and a table: the counting blocks (one per family) target the table
 * __unboundupstream_block, which holds exactly the setting's addresses, so the status can read which addresses the
 * table holds and how many packets it stopped; a backstop per setting address targets that address literally and
 * does not depend on the table. The table counts, the literals guarantee: should the table be empty or missing, the
 * backstops still keep every resolver off every other interface. The table is registered without persist or file,
 * so core's ruleset load never depends on a plugin file, and pf keeps the addresses a table declared without any
 * holds across reloads. Its name is in core's __ namespace, which core's alias-name validator refuses, so no alias
 * can share it.
 *
 * The footprints: while the state records an address the plugin's route or Unbound's live root may still refer to
 * and that is no setting address, that address keeps a block of its own, and a pass on the device of the plugin's
 * route while that is a member route, whatever the settings say, until a stop or its drain clears it, so a stop that
 * could not undo the plugin's changes never leaves them unenforced. The counting table never holds a footprint: its
 * literal block covers it. Core also calls the hook in the web GUI's PHP to list the automatic rules; it runs as
 * root, so the listing reads the same state and shows the footprints' rules too. A process that cannot search the
 * root-only run directory reads no footprint and renders the setting's rules only.
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/address.php';
require_once __DIR__ . '/logline.php';
require_once __DIR__ . '/state.php';

/**
 * The pf label of a member's pass, per interface and address ($address canonical); the status reads its counters by
 * it, and the verdict finds the pass by it whatever else the interface carries.
 */
function uu_label_pass(string $opt, string $address): string
{
    return md5('uu-pass-' . $opt . '-' . $address);
}

/** The pf label of the counting blocks, one per family; the rules verdict looks for them by this label. */
function uu_label_block(): string
{
    return md5('uu-block');
}

/** The pf label of the backstop blocks, one per setting address; the rules verdict looks for them by this label. */
function uu_label_backstop(): string
{
    return md5('uu-backstop');
}

/** The pf label of the footprint blocks; the rules verdict ignores them, so it is not the backstop's label. */
function uu_label_footprint(): string
{
    return md5('uu-footprint');
}

/**
 * The pf label of a footprint pass on a member interface, per interface and address ($address canonical). Not
 * uu_label_pass(): the verdict requires every line under a member's pass label to go to that member's resolver, and
 * the footprint pass goes to another address.
 */
function uu_label_footprint_pass(string $opt, string $address): string
{
    return md5('uu-footprint-pass-' . $opt . '-' . $address);
}

/**
 * The rules, every pass before every block, so that no block, the counting blocks' table included, can shadow a pass:
 * the members' passes, the footprints' passes (each that has an interface), the counting blocks, the backstops, the
 * footprints' blocks. Each rule is in its own address's family.
 *
 * @param list<array{interface: string, resolver: string}> $members
 * @param list<string> $settingAddresses the setting's addresses (uu_setting_addresses()), canonical
 * @param list<array{resolver: string, interface: string}> $footprints uu_footprints_from_state()'s
 * @return list<array<string, string|bool>>
 */
function uu_rule_confs(array $members, bool $counting, array $settingAddresses, array $footprints): array
{
    $confs = uu_setting_passes($members);
    foreach ($footprints as $footprint) {
        if ($footprint['interface'] !== '') {
            $confs[] = uu_pass_conf($footprint['interface'], $footprint['resolver'],
                uu_label_footprint_pass($footprint['interface'], $footprint['resolver']),
                'Unbound upstream: the address the plugin last used, through the device of its route');
        }
    }
    array_push($confs, ...uu_setting_blocks($settingAddresses, $counting));
    foreach ($footprints as $footprint) {
        $confs[] = uu_block_conf($footprint['resolver'], uu_label_footprint(),
            'Unbound upstream: the address the plugin last used never leaves by another interface',
            uu_ip_family($footprint['resolver']) ?? 'inet');
    }
    return $confs;
}

/**
 * The setting's passes: one per distinct member interface and resolver (members on one interface with one resolver
 * share it; with two resolvers each has its own), on the member's friendly interface name, which core maps to the
 * device, with the interface's own address as source so a query that Unbound sent from another address cannot ride a
 * member out. None for a member with no interface or no resolver.
 *
 * @param list<array{interface: string, resolver: string}> $members
 * @return list<array<string, string|bool>>
 */
function uu_setting_passes(array $members): array
{
    $confs = [];
    $seen = [];
    foreach ($members as $member) {
        $opt = $member['interface'];
        $resolver = uu_ip_canonical($member['resolver']);
        if ($opt === '' || $resolver === null || isset($seen[$opt][$resolver])) {
            continue;
        }
        $seen[$opt][$resolver] = true;
        $confs[] = uu_pass_conf($opt, $resolver, uu_label_pass($opt, $resolver),
            'Unbound upstream: the resolver through this member');
    }
    return $confs;
}

/**
 * The setting's blocks: when asked, one counting block per family of the setting's addresses, which targets the
 * plugin table (a table holds both families, a rule one); then one backstop per setting address, which targets the
 * address itself and is always rendered with the setting's rules.
 *
 * @param list<string> $settingAddresses
 * @return list<array<string, string|bool>>
 */
function uu_setting_blocks(array $settingAddresses, bool $counting): array
{
    $families = [];
    $backstops = [];
    foreach ($settingAddresses as $address) {
        $family = uu_ip_family($address);
        $canonical = uu_ip_canonical($address);
        if ($family !== null && $canonical !== null) {
            $families[$family] = true;
            $backstops[] = uu_block_conf($canonical, uu_label_backstop(),
                'Unbound upstream: the resolver never leaves by another interface (backstop)', $family);
        }
    }
    $confs = [];
    foreach ($counting ? ['inet', 'inet6'] : [] as $family) {
        if (isset($families[$family])) {
            $confs[] = uu_block_conf('<' . UU_BLOCK_TABLE . '>', uu_label_block(),
                'Unbound upstream: the resolver never leaves by another interface (counted)', $family);
        }
    }
    return array_merge($confs, $backstops);
}

/**
 * A pass to an address, with the address's own protocol. disablereplyto keeps the pass from also stamping reply-to.
 * Its states are bound to the interface (keep state (if-bound); core renders a state-policy only beside a statetype):
 * a floating state would let a packet of an established connection (a TCP ACK or FIN) leave by whatever route the
 * address has once the member's route is gone, past every block.
 *
 * @return array<string, string|bool>
 */
function uu_pass_conf(string $opt, string $to, string $label, string $descr): array
{
    return [
        'type' => 'pass', 'direction' => 'out', 'quick' => true, 'interface' => $opt,
        'ipprotocol' => uu_ip_family($to) ?? 'inet',
        'protocol' => 'tcp/udp', 'from' => $opt . 'ip', 'to' => $to, 'to_port' => '53',
        'disablereplyto' => true, 'statetype' => 'keep', 'state-policy' => 'if-bound', 'label' => $label,
        'descr' => $descr,
    ];
}

/**
 * A block to an address or to the counting table, whose protocol is the resolver's, so $family is given.
 *
 * @param string $family 'inet' or 'inet6'
 * @return array<string, string|bool>
 */
function uu_block_conf(string $to, string $label, string $descr, string $family): array
{
    return [
        'type' => 'block', 'direction' => 'out', 'quick' => true, 'log' => true, 'ipprotocol' => $family,
        'to' => $to, 'label' => $label, 'descr' => $descr,
    ];
}

/**
 * The footprints: every address the state records that is not one of the setting's addresses ($settingAddresses, the
 * addresses the setting's rules already go to; none when they render none), compared in canonical form, in the
 * state's sorted order, each with the friendly interface of the plugin's route to it. That interface is the one of the
 * gateway record on the route's device with the route's next hop (compared in canonical form), the first such record
 * by name that has one; it is '' when the route is no member route, no record names it or the records could not be
 * read ($records null), and the footprint then has its block only, since core renders an interface it does not know
 * as a placeholder that breaks the ruleset. problem is set only when the records could not be read and there is a
 * footprint: DNS to its addresses is blocked until a filter reload can read them.
 *
 * @param array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int,
 *         last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
 *     control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *         forwarded: bool, released_at: ?int}>} $state
 * @param ?array<array-key, array<string, mixed>> $records gatewaysIndexedByName()'s shape, or null when it could not
 *     be read
 * @param list<string> $settingAddresses
 * @return array{footprints: list<array{resolver: string, interface: string}>, problem: ?string}
 */
function uu_footprints_from_state(array $state, ?array $records, array $settingAddresses): array
{
    $setting = [];
    foreach ($settingAddresses as $address) {
        $setting[uu_ip_canonical($address) ?? $address] = true;
    }
    $recs = $records ?? [];
    $names = array_map('strval', array_keys($recs));
    sort($names, SORT_STRING);
    $footprints = [];
    foreach (uu_state_footprint($state) as $address) {
        if (isset($setting[$address])) {
            continue;
        }
        $interface = '';
        $route = uu_state_route_record($state, $address);
        if ($route !== null && $route['kind'] === 'member') {
            foreach ($names as $name) {
                $record = $recs[$name];
                $opt = (string)($record['interface'] ?? '');
                if ($opt !== '' && (string)($record['if'] ?? '') === $route['if']
                    && uu_next_hop((string)($record['gateway'] ?? '')) === uu_next_hop($route['next_hop'])) {
                    $interface = $opt;
                    break;
                }
            }
        }
        $footprints[] = ['resolver' => $address, 'interface' => $interface];
    }
    $problem = $records === null && $footprints !== []
        ? 'DNS to ' . implode(', ', array_column($footprints, 'resolver'))
            . ' is blocked until a filter reload can read the gateway records'
        : null;
    return ['footprints' => $footprints, 'problem' => $problem];
}

/**
 * What to render. The state file at $statePath is read first, on its own; core's settings ($model) are read next, and
 * the gateway records ($records) only when the setting may render or the state records an address, so a disabled plugin
 * with no footprint reads no records. The setting renders when the settings and the records were both read and name a
 * group (enabled): each member found in the records gets its effective resolver (uu_member_resolvers(): its row, by
 * the UUID of its record, else the Default when that is an address the model accepts, the same refusal as
 * uu_settings_clean(), in its canonical form; '' for none), and the setting's addresses are uu_setting_addresses()'s.
 * default is the Default as the setting has it, so the hook can name a refused one. A failed settings read renders the
 * footprints as if the setting rendered nothing (their passes and blocks); a failed records read leaves the footprints
 * their blocks alone, which error then names (uu_footprints_from_state()). Each failed read is part of error, which is
 * null when every read needed succeeded; a state file that cannot be read is no footprint, and its problem is
 * footprint_problem.
 *
 * @param callable(): array{default: string, rows: array<string, string>, gateways: ?list<string>} $model the
 *     settings: the Default, the per-member rows (gateway UUID => canonical address), and the group's gateway names
 *     when the plugin is on with a group found, else null
 * @param callable(): array<array-key, array<string, mixed>> $records gatewaysIndexedByName(true)'s shape
 * @return array{enabled: bool, default: string,
 *     members: list<array{name: string, interface: string, if: string, resolver: string}>, addresses: list<string>,
 *     footprints: list<array{resolver: string, interface: string}>, footprint_problem: ?string, error: ?string}
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
    if ($gateways !== null || uu_state_footprint($read['state']) !== []) {
        try {
            $recs = $records();
        } catch (\Throwable $e) {
            $recsFailed = true;
            $errors[] = 'cannot read the gateway records: ' . $e->getMessage();
        }
    }
    $enabled = $gateways !== null && $recs !== null;
    $default = $enabled ? (string)($settings['default'] ?? '') : '';
    $names = [];
    foreach ($enabled ? $gateways : [] as $name) {
        if (isset($recs[$name])) {
            $names[] = (string)$name;
        }
    }
    $resolvers = uu_member_resolvers($names, $settings['rows'] ?? [], uu_gateway_names($recs ?? []),
        uu_resolver_refusal($default) === null ? (uu_ip_canonical($default) ?? '') : '')['resolvers'];
    $members = [];
    $byName = [];
    foreach ($names as $name) {
        $members[] = ['name' => $name, 'interface' => (string)($recs[$name]['interface'] ?? ''),
            'if' => (string)($recs[$name]['if'] ?? ''), 'resolver' => $resolvers[$name] ?? ''];
        $byName[$name] = ['resolver' => $resolvers[$name] ?? ''];
    }
    $addresses = uu_setting_addresses(['settings' => ['enabled' => $enabled],
        'contract_input' => ['group_found' => $gateways !== null], 'members' => $byName]);
    $found = uu_footprints_from_state($read['state'], $recsFailed ? null : ($recs ?? []), $addresses);
    if ($found['problem'] !== null) {
        $errors[] = $found['problem'];
    }
    return ['enabled' => $enabled, 'default' => $default, 'members' => $members, 'addresses' => $addresses,
        'footprints' => $found['footprints'],
        'footprint_problem' => $read['problem'] !== null ? 'the state file is ' . $read['problem'] : null,
        'error' => $errors === [] ? null : implode('; ', $errors)];
}

/**
 * The plugin's settings as uu_wanted_from() takes them, from the saved model and core's gateway groups: the Default
 * as saved, the per-member rows (uu_rows_clean(): a row the model would refuse is dropped, as the evaluation drops it),
 * and the group's gateway names only when the plugin is on and a group is chosen and found.
 *
 * @return array{default: string, rows: array<string, string>, gateways: ?list<string>}
 */
function uu_render_model(): array
{
    $mdl = new \OPNsense\UnboundUpstream\UnboundUpstream();
    if (!$mdl->enabled->isEqual('1') || $mdl->gateway_group->isEmpty()) {
        return ['default' => '', 'rows' => [], 'gateways' => null];
    }
    $rows = [];
    foreach ($mdl->resolvers->resolver->iterateItems() as $row) {
        $rows[] = ['gateway' => $row->gateway->getValue(), 'address' => $row->address->getValue()];
    }
    $groups = new \OPNsense\Routing\GatewayGroups();
    foreach ($groups->gateway_group->iterateItems() as $uuid => $item) {
        if ($uuid === $mdl->gateway_group->getValue()) {
            return ['default' => $mdl->resolver->getValue(), 'rows' => uu_rows_clean($rows)['rows'],
                    'gateways' => array_map('strval', array_values($groups->gatewaysInGroup($item)))];
        }
    }
    return ['default' => '', 'rows' => [], 'gateways' => null];
}

/**
 * What to render, from the plugin's state file, the saved model and the live gateway records (uu_wanted_from()).
 *
 * @return array{enabled: bool, default: string,
 *     members: list<array{name: string, interface: string, if: string, resolver: string}>, addresses: list<string>,
 *     footprints: list<array{resolver: string, interface: string}>, footprint_problem: ?string, error: ?string}
 */
function uu_wanted_render(): array
{
    return uu_wanted_from('uu_render_model',
        fn (): array => (new \OPNsense\Routing\Gateways())->gatewaysIndexedByName(true), UU_STATE_PATH);
}

/**
 * The plugins_firewall hook body. Never throws. What each failure keeps:
 * - a settings or gateway records read that fails is one error, and the footprints still render (uu_wanted_from());
 * - a Default that is not an IPv4 or IPv6 address is one error, the members it would cover render nothing and the
 *   footprints still render;
 * - a state file that cannot be read, or a recorded address that is no address, is one warning for the render, and the
 *   setting's rules still render: each filter reload is a process of its own, so the hook keeps nothing between
 *   renders;
 * - a table that cannot be registered costs only the counting blocks;
 * - a rule that cannot be registered costs only itself, and is one error naming its description;
 * - anything else that throws renders nothing, and is one error.
 * The table is registered for the setting's counting blocks only.
 *
 * Lines go through logger(1), not openlog(): the hook runs inside core's filter reload and must not replace core's
 * syslog ident or drop its connection.
 *
 * @param ?callable(): array{enabled: bool, default: string, members: list<array{interface: string, resolver: string}>,
 *     addresses: list<string>, footprints: list<array{resolver: string, interface: string}>,
 *     footprint_problem: ?string, error: ?string} $wanted
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
        $refused = $w['enabled'] && $w['default'] !== '' ? uu_resolver_refusal($w['default']) : null;
        if ($refused !== null) {
            $emit('rules for the resolver setting not rendered: resolver is ' . $refused, 'err');
        }
        if ($w['footprint_problem'] !== null) {
            $emit('footprint rules not rendered: ' . uu_log_text($w['footprint_problem']), 'warning');
        }
        $members = $w['enabled'] ? $w['members'] : [];
        $addresses = $w['enabled'] ? $w['addresses'] : [];
        // The counting blocks need their table; a failure here must never cost the passes or the backstops.
        $counting = false;
        if ($addresses !== []) {
            try {
                $fw->registerTable(UU_BLOCK_TABLE);
                $counting = true;
            } catch (\Throwable $e) {
                $counting = false;
                $emit('rules: counting block not rendered: ' . uu_log_text($e->getMessage()), 'err');
            }
        }
        // Each rule registers on its own: a rule core refuses must never cost the blocks after it.
        foreach (uu_rule_confs($members, $counting, $addresses, $w['footprints']) as $conf) {
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
