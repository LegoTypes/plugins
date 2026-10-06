<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Core contract (spec 2026-10-05 section 3.12). Judging dependencies: without them no WAN can be read,
 * so a drift releases every hold and stops planning. Command dependencies: copied or invoked core
 * internals; a drift blocks new holds only. Pure: callers pass the file contents.
 */

const WF_GATEWAY_LOCK = '/tmp/filter_reload_gateway.lock';
const WF_INSTANCE_KEYS = ['current_losslow', 'current_losshigh', 'current_time_period', 'current_interval', 'current_loss_interval'];

function wf_ini_section(string $text, string $name): ?string
{
    return preg_match('/^\[' . preg_quote($name, '/') . '\]\s*$(.*?)(?=^\[|\z)/ms', $text, $m) === 1 ? $m[1] : null;
}

/**
 * @return list<string>
 */
function wf_contract_commands(?string $interfaceActions, ?string $filterActions, ?string $tailscaleActions, ?string $rc): array
{
    $p = [];
    $alarm = $interfaceActions === null ? null : wf_ini_section($interfaceActions, 'routes.alarm');
    if ($alarm === null) {
        $p[] = 'actions_interface.conf [routes.alarm] missing or unreadable';
    } elseif (!str_contains($alarm, WF_GATEWAY_LOCK) || !str_contains($alarm, 'rc.routing_configure alarm')) {
        $p[] = '[routes.alarm] no longer takes ' . WF_GATEWAY_LOCK . ' and runs rc.routing_configure alarm';
    }
    if ($filterActions === null) {
        $p[] = 'actions_filter.conf unreadable';
    } else {
        $state = wf_ini_section($filterActions, 'kill.state');
        $gw = wf_ini_section($filterActions, 'kill.gateway_states');
        if ($state === null || !str_contains($state, '-k id -k %s/%s') || $gw === null || !str_contains($gw, '-k gateway -k %s')) {
            $p[] = '[kill.state] or [kill.gateway_states] changed';
        }
    }
    if ($tailscaleActions === null || wf_ini_section($tailscaleActions, 'restart') === null) {
        $p[] = 'actions_tailscale.conf [restart] missing or unreadable';
    }
    $early = $rc === null ? false : strpos($rc, 'rc.syshook early');
    $bootup = $rc === null ? false : strpos($rc, 'rc.bootup');
    if ($early === false || $bootup === false || $early > $bootup) {
        $p[] = '/usr/local/etc/rc no longer runs rc.syshook early before rc.bootup';
    }
    return $p;
}

/**
 * @param array<string, string|int|float>|null $instanceRow one dpinger_instances() row
 * @param array<string, string>|null $statusRow the same gateway's dpinger_status() row
 * @return list<string>
 */
function wf_contract_judging(?array $instanceRow, ?array $statusRow, ?string $routeOut, bool $socketFound): array
{
    $p = [];
    $missing = $instanceRow === null ? WF_INSTANCE_KEYS : array_values(array_diff(WF_INSTANCE_KEYS, array_keys($instanceRow)));
    if ($missing !== []) {
        $p[] = 'dpinger_instances() rows lack ' . implode(', ', $missing);
    }
    if ($statusRow === null || !array_key_exists('status', $statusRow) || !array_key_exists('loss', $statusRow)) {
        $p[] = 'dpinger_status() rows lack status or loss';
    }
    if ($routeOut === null || preg_match('/^\s*(gateway|destination):\s*\S+/m', $routeOut) !== 1) {
        $p[] = 'route -n get output no longer parses';
    }
    if (!$socketFound) {
        $p[] = 'no dpinger socket at /var/run/dpinger_<name>.sock for a monitored WAN';
    }
    return $p;
}

/**
 * Log a drift once when it appears or changes, and once when it clears.
 *
 * @param array{judging: list<string>, command: list<string>} $contract
 * @return array{line: ?string, prio: int, last: string}
 */
function wf_contract_log(array $contract, string $last): array
{
    $all = array_merge($contract['judging'], $contract['command']);
    $now = implode("\n", $all);
    if ($now === $last) {
        return ['line' => null, 'prio' => LOG_NOTICE, 'last' => $last];
    }
    if ($all === []) {
        return ['line' => 'core-contract: core matches again', 'prio' => LOG_NOTICE, 'last' => $now];
    }
    $effect = $contract['judging'] !== [] ? 'releasing every hold and stopping' : 'no new holds';
    return ['line' => "core-contract: core changed what the plugin relies on ({$effect}): " . implode('; ', $all),
            'prio' => LOG_WARNING, 'last' => $now];
}
