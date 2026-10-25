<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Core contract (spec 2026-10-05 section 3.12). Judging dependencies: without them no WAN can be read,
 * so a drift releases every hold and stops planning. Command dependencies: copied or invoked core
 * internals; a drift blocks new holds only. Removal dependencies: what only the package removal copies, its
 * fallback for core's routing reconfigure; a drift there blocks nothing, and the removal no longer runs the copy.
 * Pure: callers pass the file contents.
 */

require_once __DIR__ . '/constants.php';

const WF_GATEWAY_LOCK = '/tmp/filter_reload_gateway.lock';
const WF_INSTANCE_KEYS = ['current_losslow', 'current_losshigh', 'current_time_period', 'current_interval', 'current_loss_interval'];

function wf_ini_section(string $text, string $name): ?string
{
    return preg_match('/^\[' . preg_quote($name, '/') . '\]\s*$(.*?)(?=^\[|\z)/ms', $text, $m) === 1 ? $m[1] : null;
}

/** A configd action section's command: line, trimmed; null when it has none. */
function wf_ini_command(string $section): ?string
{
    return preg_match('/^command:(.*)$/m', $section, $m) === 1 ? trim($m[1]) : null;
}

/**
 * @return list<string>
 */
function wf_contract_commands(?string $interfaceActions, ?string $filterActions, ?string $rc): array
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
        /* failback kills through kill.state; a hold's kill runs the same pfctl form itself */
        $state = wf_ini_section($filterActions, 'kill.state');
        if ($state === null || !str_contains($state, '-k id -k %s/%s')) {
            $p[] = '[kill.state] changed';
        }
    }
    $early = $rc === null ? false : strpos($rc, 'rc.syshook early');
    $bootup = $rc === null ? false : strpos($rc, 'rc.bootup');
    if ($early === false || $bootup === false || $early > $bootup) {
        $p[] = '/usr/local/etc/rc no longer runs rc.syshook early before rc.bootup';
    }
    return $p;
}

/**
 * The package removal runs core's [routes.configure] command itself when configd does not answer
 * (WF_CORE_ROUTES_CONFIGURE): a drift of that command is reported here, and the removal then leaves it unrun. Every
 * evaluation reconfigures routing through core's action by name, so the drift blocks no hold.
 *
 * @return list<string>
 */
function wf_contract_removal(?string $interfaceActions): array
{
    if ($interfaceActions === null) {
        return [];
    }
    $configure = wf_ini_section($interfaceActions, 'routes.configure');
    return $configure === null || wf_ini_command($configure) !== WF_CORE_ROUTES_CONFIGURE ? ['[routes.configure] changed'] : [];
}

/**
 * Tailscale is optional: no actions file means it is not installed, and a missing [restart] only turns
 * Tailscale restarts off; neither touches holds.
 *
 * @return list<string>
 */
function wf_contract_tailscale(?string $tailscaleActions): array
{
    if ($tailscaleActions === null || wf_ini_section($tailscaleActions, 'restart') !== null) {
        return [];
    }
    return ['actions_tailscale.conf has no [restart]'];
}

/**
 * Does core run a dpinger for this WAN right now? Only for a monitored, enabled gateway whose interface
 * has carrier and an IPv4 address: dpinger binds the interface's address, and core stops it when the
 * link or the address goes (2026-10-07: a flapping WAN lost both, and its missing socket was taken for
 * core drift). The judge reads such a WAN as unavailable; the contract must not read it as drift.
 *
 * @param array{carrier: bool, has_ipv4: bool} $link wf_parse_ifconfig()
 */
function wf_dpinger_expected(bool $monitored, array $link): bool
{
    return $monitored && $link['carrier'] && $link['has_ipv4'];
}

/**
 * @param array<string, string|int|float>|null $instanceRow one dpinger_instances() row
 * @param array<string, string>|null $statusRow the same gateway's dpinger_status() row
 * @param bool $dpingerExpected wf_dpinger_expected(): core runs a dpinger for this WAN
 * @return list<string>
 */
function wf_contract_judging(?array $instanceRow, ?array $statusRow, ?string $routeOut, bool $socketFound, bool $dpingerExpected): array
{
    $p = [];
    if ($routeOut === null || preg_match('/^\s*(gateway|destination):\s*\S+/m', $routeOut) !== 1) {
        $p[] = 'route -n get output no longer parses';
    }
    /* without a dpinger (an unmonitored or disabled gateway, or a WAN without carrier or an address) there is
     * no instance, status row or socket to check, by design */
    if (!$dpingerExpected) {
        return $p;
    }
    $missing = $instanceRow === null ? WF_INSTANCE_KEYS : array_values(array_diff(WF_INSTANCE_KEYS, array_keys($instanceRow)));
    if ($missing !== []) {
        $p[] = 'dpinger_instances() rows lack ' . implode(', ', $missing);
    }
    if ($statusRow === null || !array_key_exists('status', $statusRow) || !array_key_exists('loss', $statusRow)) {
        $p[] = 'dpinger_status() rows lack status or loss';
    }
    if (!$socketFound) {
        $p[] = 'no dpinger socket at /var/run/dpinger_<name>.sock for a monitored WAN';
    }
    return $p;
}

/**
 * Log a drift once when it appears or changes, and once when it clears.
 *
 * @param array{judging: list<string>, command: list<string>, tailscale?: list<string>, removal?: list<string>} $contract
 * @return array{line: ?string, prio: int, last: string}
 */
function wf_contract_log(array $contract, string $last): array
{
    $all = array_merge($contract['judging'], $contract['command'], $contract['tailscale'] ?? [], $contract['removal'] ?? []);
    $now = implode("\n", $all);
    if ($now === $last) {
        return ['line' => null, 'prio' => LOG_NOTICE, 'last' => $last];
    }
    if ($all === []) {
        return ['line' => 'core-contract: core matches again', 'prio' => LOG_NOTICE, 'last' => $now];
    }
    $effect = $contract['judging'] !== [] ? 'releasing every hold if it persists for ' . WF_UNKNOWN_MAX_SECONDS . ' s'
        : ($contract['command'] !== [] ? 'no new holds'
        : (($contract['tailscale'] ?? []) !== [] ? 'Tailscale restarts off' : 'a package removal re-syncs routing through configd only'));
    return ['line' => "core-contract: core changed what the plugin relies on ({$effect}): " . implode('; ', $all),
            'prio' => LOG_WARNING, 'last' => $now];
}
