<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Core contract, by class. Judging (without it no WAN can be read): a drift blocks new holds, and one that persists
 * releases every hold and stops planning. Command (copied or invoked core internals): blocks new holds only. Failback
 * (the pf rule listing failback reads, the gateway groups' tiers): suspends failback, blocks nothing else. Tailscale
 * (its [restart] action): turns Tailscale restarts off. Removal (the package removal's fallbacks when configd does not
 * answer): blocks nothing; after a [routes.configure] drift the removal leaves core's routing command unrun. Names
 * (core's gateway-name mask, copied as WF_GATEWAY_NAME_MASK): blocks nothing, as a name the copy refuses only reads as
 * unresolved. Pure, except wf_contract_groups_read(), the one guarded call into core.
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/pfstate.php';

const WF_GATEWAY_LOCK = '/tmp/filter_reload_gateway.lock';
const WF_DRIFT_ROUTES_CONFIGURE = '[routes.configure] changed';
const WF_DRIFT_CRON_RESTART = 'actions_cron.conf [restart] changed';
const WF_INSTANCE_KEYS = ['current_losslow', 'current_losshigh', 'current_time_period', 'current_interval', 'current_loss_interval'];
const WF_DRIFT_RULES_FORMAT = 'pfctl -vvsr no longer prints rule labels or route-to targets as the failback parser reads them';
/* a pf listing pfctl did not give whole on two tries (wf_pf_listing()): it tells no drift */
const WF_UNREAD_RULES = 'pfctl -vvsr could not be read';
const WF_UNREAD_STATES = 'pfctl -vvss could not be read';

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
 * The two core commands the package removal runs itself when configd does not answer: [routes.configure]'s
 * (WF_CORE_ROUTES_CONFIGURE), and actions_cron.conf's [restart] (WF_CORE_CRON_RESTART), which +POST_DEINSTALL.post
 * runs. After a routing drift the removal leaves that command unrun (wf_contract_routes_fallback()). Evaluations run
 * neither, so no drift here blocks a hold. An unreadable actions_cron.conf is reported here, an unreadable
 * actions_interface.conf by the command contract.
 *
 * @return list<string>
 */
function wf_contract_removal(?string $interfaceActions, ?string $cronActions): array
{
    $p = [];
    $configure = $interfaceActions === null ? null : wf_ini_section($interfaceActions, 'routes.configure');
    if ($interfaceActions !== null && ($configure === null || wf_ini_command($configure) !== WF_CORE_ROUTES_CONFIGURE)) {
        $p[] = WF_DRIFT_ROUTES_CONFIGURE;
    }
    $restart = $cronActions === null ? null : wf_ini_section($cronActions, 'restart');
    if ($restart === null || wf_ini_command($restart) !== WF_CORE_CRON_RESTART) {
        $p[] = WF_DRIFT_CRON_RESTART;
    }
    return $p;
}

/**
 * Whether the package removal may run core's routing command itself, from the removal drifts wf_contract_removal()
 * reported: not once that command drifted; a drift of the cron command does not stop it.
 *
 * @param list<string> $removal
 */
function wf_contract_routes_fallback(array $removal): bool
{
    return !in_array(WF_DRIFT_ROUTES_CONFIGURE, $removal, true);
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
 * link or the address goes. The judge reads such a WAN as unavailable; the contract must not read it as drift.
 *
 * @param array{carrier: bool, has_ipv4: bool} $link wf_parse_ifconfig()
 */
function wf_dpinger_expected(bool $monitored, array $link): bool
{
    return $monitored && $link['carrier'] && $link['has_ipv4'];
}

/**
 * The reads the judge rests on: `route -n get`'s format, which the live default and every route lookup parse; and,
 * for a WAN core runs a dpinger for, its dpinger_instances() row (WF_INSTANCE_KEYS), its dpinger_status() row (status
 * and loss), its socket (WF_DPINGER_SOCK), and its pid file (WF_DPINGER_PID) and that pid's `ps -o etimes=`, which
 * the window age is read from. Without the socket the pid and age go unchecked: the socket's line already says it.
 *
 * @param array<string, string|int|float>|null $instanceRow one dpinger_instances() row
 * @param array<string, string>|null $statusRow the same gateway's dpinger_status() row
 * @param bool $socketFound the WAN's WF_DPINGER_SOCK exists
 * @param bool $dpingerExpected wf_dpinger_expected(): core runs a dpinger for this WAN
 * @param bool $pidFound the WAN's WF_DPINGER_PID names a pid
 * @param bool $ageFound ps gives that pid an age
 * @return list<string>
 */
function wf_contract_judging(?array $instanceRow, ?array $statusRow, ?string $routeOut, bool $socketFound,
                             bool $dpingerExpected, bool $pidFound, bool $ageFound): array
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
        $p[] = 'no dpinger socket at ' . sprintf(WF_DPINGER_SOCK, '<name>') . ' for a monitored WAN';
    } elseif (!$pidFound) {
        $p[] = 'no dpinger pid at ' . sprintf(WF_DPINGER_PID, '<name>') . ' for a monitored WAN';
    } elseif (!$ageFound) {
        $p[] = "ps -o etimes= gives no age for a monitored WAN's dpinger";
    }
    return $p;
}

/**
 * Core's mask for a gateway name, the Mask of the name field in Gateways.xml, against WF_GATEWAY_NAME_MASK without
 * its D flag. Compared as text, so a respelled but equal regex reads as changed.
 *
 * @return list<string>
 */
function wf_contract_name_mask(?string $gatewaysXml): array
{
    if ($gatewaysXml === null) {
        return ['Gateways.xml unreadable'];
    }
    $internal = libxml_use_internal_errors(true);
    $xml = simplexml_load_string($gatewaysXml, 'SimpleXMLElement', LIBXML_NONET);
    libxml_clear_errors();
    libxml_use_internal_errors($internal);
    if ($xml === false) {
        return ['Gateways.xml unreadable'];
    }
    $mask = $xml->items->gateway_item->name->Mask ?? null;
    return $mask !== null && (string)$mask === substr(WF_GATEWAY_NAME_MASK, 0, -1) ? [] : ['Gateways.xml gateway name Mask changed'];
}

/**
 * The shape the failback gate reads from GatewayGroups::getGroupsConfig() (wf_first_tier()): every row an array whose
 * tiers is an array of lists of gateway names.
 *
 * @param array<array-key, mixed> $groups getGroupsConfig()'s raw return, whose shape is what this tests
 * @return list<string>
 */
function wf_contract_groups(array $groups): array
{
    foreach ($groups as $row) {
        $tiers = is_array($row) ? ($row['tiers'] ?? null) : null;
        $ok = is_array($tiers);
        foreach ($ok ? $tiers : [] as $tier) {
            $ok = $ok && is_array($tier) && array_is_list($tier) && count(array_filter($tier, 'is_string')) === count($tier);
        }
        if (!$ok) {
            return ['GatewayGroups::getGroupsConfig() rows no longer carry tiers as lists of gateway names'];
        }
    }
    return [];
}

/**
 * Core's gateway groups, read so that no change of core's API can throw past this: the class or the method gone, the
 * call throwing, or a return that is not an array leaves groups null (unreadable) and is a drift naming it. A return
 * that is an array is checked for its shape (wf_contract_groups()). Every snapshot reads the groups through this, so
 * a groups drift reaches failback only.
 *
 * @param string $class WF_CORE_GROUPS_CLASS
 * @param string $method WF_CORE_GROUPS_METHOD
 * @return array{groups: ?array<array-key, mixed>, drift: list<string>} groups: the method's raw return
 */
function wf_contract_groups_read(string $class, string $method): array
{
    $short = substr((string)strrchr('\\' . $class, '\\'), 1);
    $unread = fn (string $why): array => ['groups' => null, 'drift' => [$why]];
    try {
        if (!class_exists($class)) {
            return $unread("{$short} no longer exists");
        }
        if (!method_exists($class, $method)) {
            return $unread("{$short}::{$method}() no longer exists");
        }
        $groups = (new $class())->$method();
    } catch (\Throwable $e) {
        return $unread("{$short}::{$method}() threw " . get_class($e));
    }
    if (!is_array($groups)) {
        return $unread("{$short}::{$method}() no longer returns an array");
    }
    return ['groups' => $groups, 'drift' => wf_contract_groups($groups)];
}

/**
 * The reads failback rests on: `pfctl -vvsr`'s format (wf_rules_selfcheck()), whose labels and route-to targets tell
 * whether a rule renders its preferred WAN yet, and the groups (wf_contract_groups_read()), whose tiers give that
 * preference. Null, or a blank listing, is one that could not be read (wf_pf_listing()): it says so (WF_UNREAD_RULES),
 * not that the format moved, and wf_contract_kept() keeps the last reading in its place.
 *
 * @param array{groups: ?array<array-key, mixed>, drift: list<string>} $groups wf_contract_groups_read()
 * @return list<string>
 */
function wf_contract_failback(?string $rawRules, array $groups): array
{
    $p = [];
    if ($rawRules === null || trim($rawRules) === '') {
        $p[] = WF_UNREAD_RULES;
    } elseif (!wf_rules_selfcheck($rawRules)) {
        $p[] = WF_DRIFT_RULES_FORMAT;
    }
    return array_merge($p, $groups['drift']);
}

/**
 * The contract as an evaluation acts on it and the page shows it. A rule listing that could not be read
 * (WF_UNREAD_RULES in the failback class) tells no drift, so the class keeps the rule-format drift as the last
 * evaluation read it ($last, wf_contract_log()'s), present or not, and wf_contract_log() logs nothing new for it. The
 * groups' drift is read every time and stands as read.
 *
 * @param array{judging: list<string>, command: list<string>, failback: list<string>, tailscale: list<string>,
 *               removal: list<string>, names: list<string>} $contract wf_snapshot()'s
 * @return array{contract: array{judging: list<string>, command: list<string>, failback: list<string>,
 *                                tailscale: list<string>, removal: list<string>, names: list<string>}, line: ?string}
 *     line: the notice for an unread listing, for the caller to log once (wf_once()); null when it was read
 */
function wf_contract_kept(array $contract, string $last): array
{
    if (!in_array(WF_UNREAD_RULES, $contract['failback'], true)) {
        return ['contract' => $contract, 'line' => null];
    }
    $kept = in_array(WF_DRIFT_RULES_FORMAT, explode("\n", $last), true) ? [WF_DRIFT_RULES_FORMAT] : [];
    $contract['failback'] = array_merge($kept, array_values(array_diff($contract['failback'], [WF_UNREAD_RULES])));
    return ['contract' => $contract,
            'line' => 'core-contract: ' . WF_UNREAD_RULES . ' on two tries; the failback check keeps its last result'];
}

/**
 * Log a drift once when it appears or changes, and once when it clears.
 *
 * @param array{judging: list<string>, command: list<string>, failback?: list<string>, tailscale?: list<string>,
 *               removal?: list<string>, names?: list<string>} $contract
 * @return array{line: ?string, prio: int, last: string}
 */
function wf_contract_log(array $contract, string $last): array
{
    $all = array_merge($contract['judging'], $contract['command'], $contract['failback'] ?? [], $contract['tailscale'] ?? [],
        $contract['removal'] ?? [], $contract['names'] ?? []);
    $now = implode("\n", $all);
    if ($now === $last) {
        return ['line' => null, 'prio' => LOG_NOTICE, 'last' => $last];
    }
    if ($all === []) {
        return ['line' => 'core-contract: core matches again', 'prio' => LOG_NOTICE, 'last' => $now];
    }
    $effect = $contract['judging'] !== [] ? 'releasing every hold if it persists for ' . WF_UNKNOWN_MAX_SECONDS . ' s'
        : ($contract['command'] !== [] ? 'no new holds'
        : (($contract['failback'] ?? []) !== [] ? 'failback suspended'
        : (($contract['tailscale'] ?? []) !== [] ? 'Tailscale restarts off'
        : (($contract['removal'] ?? []) !== [] ? 'only a package removal, when configd does not answer'
        : 'a gateway name core now accepts may read as unresolved'))));
    return ['line' => "core-contract: core changed what the plugin relies on ({$effect}): " . implode('; ', $all),
            'prio' => LOG_WARNING, 'last' => $now];
}
