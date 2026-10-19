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
 */

require_once __DIR__ . '/constants.php';

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

/**
 * One pass per distinct member interface, then the counting block when asked, then the backstop. The pass is on
 * the member's friendly interface name, which core maps to the device, with the interface's own address as
 * source so a query that Unbound sent from another address cannot ride a member out. disablereplyto keeps the
 * pass from also stamping reply-to. The counting block targets the plugin table; the backstop targets the
 * resolver itself and is always rendered.
 *
 * @param list<array{interface: string}> $members
 * @return list<array<string, string|bool>>
 */
function uu_rule_confs(string $resolver, array $members, bool $counting): array
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
 * What to render, from the saved model and the live gateway records. Disabled, or a group or resolver that
 * cannot be resolved, is enabled false: no rules.
 *
 * @return array{enabled: bool, resolver: string, members: list<array{name: string, interface: string, if: string}>}
 */
function uu_wanted_render(): array
{
    $none = ['enabled' => false, 'resolver' => '', 'members' => []];
    $mdl = new \OPNsense\UnboundUpstream\UnboundUpstream();
    if (!$mdl->enabled->isEqual('1') || $mdl->gateway_group->isEmpty() || $mdl->resolver->isEmpty()) {
        return $none;
    }
    $groups = new \OPNsense\Routing\GatewayGroups();
    $group = null;
    foreach ($groups->gateway_group->iterateItems() as $uuid => $item) {
        if ($uuid === $mdl->gateway_group->getValue()) {
            $group = $item;
            break;
        }
    }
    if ($group === null) {
        return $none;
    }
    $records = (new \OPNsense\Routing\Gateways())->gatewaysIndexedByName(true);
    $members = [];
    foreach ($groups->gatewaysInGroup($group) as $name) {
        if (!isset($records[$name])) {
            continue;
        }
        $members[] = ['name' => (string)$name, 'interface' => (string)($records[$name]['interface'] ?? ''),
            'if' => (string)($records[$name]['if'] ?? '')];
    }
    return ['enabled' => true, 'resolver' => $mdl->resolver->getValue(), 'members' => $members];
}

/**
 * The plugins_firewall hook body. Never throws: any failure renders nothing and is logged.
 *
 * The failure is logged through logger(1), not openlog(): the hook runs inside core's filter reload and must
 * not replace core's syslog ident or drop its connection.
 *
 * @param ?callable(): array{enabled: bool, resolver: string, members: list<array{interface: string}>} $wanted
 * @param ?callable(string): void $log receives the message; default logs it as UU_SYSLOG_IDENT at local4.err
 */
function uu_render_firewall(\OPNsense\Firewall\Plugin $fw, ?callable $wanted = null, ?callable $log = null): void
{
    $emit = static function (string $msg) use ($log): void {
        if ($log !== null) {
            $log($msg);
        } else {
            exec('/usr/bin/logger -t ' . UU_SYSLOG_IDENT . ' -p local4.err -- ' . escapeshellarg($msg) . ' > /dev/null 2>&1');
        }
    };
    try {
        $w = $wanted !== null ? $wanted() : uu_wanted_render();
        if (!$w['enabled']) {
            return;
        }
        if (filter_var($w['resolver'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            throw new \RuntimeException('resolver is not an IPv4 address');
        }
        // The counting block needs its table; a failure here must never cost the passes or the backstop.
        $counting = false;
        try {
            $fw->registerTable(UU_BLOCK_TABLE);
            $counting = true;
        } catch (\Throwable $e) {
            $counting = false;
            $emit('rules: counting block not rendered: ' . str_replace(["\r", "\n"], '; ', $e->getMessage()));
        }
        foreach (uu_rule_confs($w['resolver'], $w['members'], $counting) as $conf) {
            $fw->registerFilterRule(UU_RULE_PRIORITY, $conf);
        }
    } catch (\Throwable $e) {
        $msg = 'rules not rendered: ' . str_replace(["\r", "\n"], '; ', $e->getMessage());
        $emit($msg);
    }
}
