<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Rendered allow-list (spec 2026-10-17 section 3.6b): queries to the resolver may leave only through a member
 * of the configured group. One pass per member, then one block to the resolver on every other interface,
 * registered as filter rules at every filter reload and never stored in the configuration. Core calls the
 * plugin's firewall hook both for a real reload and to list rules for display, so the hook only registers.
 */

require_once __DIR__ . '/constants.php';

/**
 * One pass per distinct member interface, then the block. The pass is on the member's friendly interface name,
 * which core maps to the device, with the interface's own address as source so a query that Unbound sent from
 * another address cannot ride a member out. disablereplyto keeps the pass from also stamping reply-to.
 *
 * @param list<array{interface: string}> $members
 * @return list<array<string, string|bool>>
 */
function uu_rule_confs(string $resolver, array $members): array
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
            'disablereplyto' => true, 'label' => md5('uu-pass-' . $opt),
            'descr' => 'Unbound upstream: the resolver through this member',
        ];
    }
    $confs[] = [
        'type' => 'block', 'direction' => 'out', 'quick' => true, 'log' => true, 'ipprotocol' => 'inet',
        'to' => $resolver, 'label' => md5('uu-block'),
        'descr' => 'Unbound upstream: the resolver never leaves by another interface',
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
 * @param ?callable(): array{enabled: bool, resolver: string, members: list<array{interface: string}>} $wanted
 */
function uu_render_firewall(\OPNsense\Firewall\Plugin $fw, ?callable $wanted = null): void
{
    try {
        $w = $wanted !== null ? $wanted() : uu_wanted_render();
        if (!$w['enabled']) {
            return;
        }
        if (filter_var($w['resolver'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            throw new \RuntimeException('resolver is not an IPv4 address');
        }
        foreach (uu_rule_confs($w['resolver'], $w['members']) as $conf) {
            $fw->registerFilterRule(UU_RULE_PRIORITY, $conf);
        }
    } catch (\Throwable $e) {
        openlog('unboundupstream', LOG_PID, LOG_LOCAL4);
        syslog(LOG_ERR, 'rules not rendered: ' . $e->getMessage());
        closelog();
    }
}
