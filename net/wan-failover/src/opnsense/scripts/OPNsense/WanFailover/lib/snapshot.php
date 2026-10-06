<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Live collectors. Read-only: the plugin model, gateway config and status, dpinger socket ages, link
 * state, routes, pf, and the core files the contract checks. Only short-lived readers are exec'd.
 */

require_once 'config.inc';
require_once 'util.inc';
require_once 'interfaces.inc';
require_once 'plugins.inc.d/dpinger.inc';
require_once __DIR__ . '/parsers.php';
require_once __DIR__ . '/pfstate.php';
require_once __DIR__ . '/contract.php';

function wf_boot_id(): string
{
    return wf_parse_boot_id((string)shell_exec('/sbin/sysctl -x -n kern.boot_id 2>/dev/null'));
}

/* product::__call() returns the value only when it is non-empty, so booting() is true or null */
function wf_booting(): bool
{
    return product::getInstance()->booting() === true;
}

function wf_route_get(string $dst): array
{
    return wf_parse_route_get((string)shell_exec('/sbin/route -n get -inet ' . escapeshellarg($dst) . ' 2>/dev/null'));
}

/** The live IPv4 default route as a route target (gateway@interface), or null without one. */
function wf_live_default(): ?string
{
    return wf_route_get_target(wf_route_get('default'));
}

/**
 * @return list<string>
 */
function wf_model_list(\OPNsense\Base\FieldTypes\BaseField $field): array
{
    $v = $field->getValue();
    return $v === '' ? [] : explode(',', $v);
}

/**
 * @return array{now: int, boot_id: string, release: ?string, failback_now: bool, enabled: bool, dry: bool, failback: bool,
 *               failback_delay: int, tailscale_restart: bool,
 *               default_gw: ?string, wans: array<string, array>, unresolved: list<string>, held: list<string>,
 *               held_stale: list<string>, force_down: array<string, bool>, uuid_by_name: array<string, string>,
 *               contract: array{judging: list<string>, command: list<string>, tailscale: list<string>}}
 */
function wf_snapshot(): array
{
    $now = time();
    $mdl = new \OPNsense\WanFailover\WanFailover();
    $all = (new \OPNsense\Routing\Gateways())->gatewaysIndexedByName(true);
    $nameByUuid = [];
    $forceDown = [];
    foreach ($all as $name => $g) {
        if (!empty($g['uuid'])) {
            $nameByUuid[(string)$g['uuid']] = (string)$name;
        }
        $forceDown[(string)$name] = !empty($g['force_down']);
    }
    $wansRes = wf_resolve_uuids(wf_model_list($mdl->wans), $nameByUuid);
    $heldRes = wf_resolve_uuids(wf_model_list($mdl->held), $nameByUuid);
    $status = dpinger_status();
    $instances = dpinger_instances(true);
    $defaultOut = (string)shell_exec('/sbin/route -n get -inet default 2>/dev/null');
    /* the route-format check probes the loopback route, which always exists; the default route can be
     * missing for a moment while routing is reconfigured, which is not a format drift */
    $loopbackOut = (string)shell_exec('/sbin/route -n get -inet 127.0.0.1 2>/dev/null');
    /* a window's age is its dpinger's process age: monotonic, so a clock step cannot make it look settled */
    $pids = [];
    foreach ($wansRes['names'] as $name) {
        $pidFile = "/var/run/dpinger_{$name}.pid";
        $pid = is_readable($pidFile) ? (int)trim((string)file_get_contents($pidFile)) : 0;
        if ($pid > 0) {
            $pids[$name] = $pid;
        }
    }
    $ages = $pids === [] ? [] : wf_parse_ps_etimes((string)shell_exec('/bin/ps -o pid= -o etimes= -p '
        . escapeshellarg(implode(',', $pids)) . ' 2>/dev/null'));
    $wans = [];
    $judging = [];
    foreach ($wansRes['names'] as $name) {
        $g = $all[$name];
        if (($g['ipprotocol'] ?? '') !== 'inet') {
            $wansRes['unresolved'][] = (string)($g['uuid'] ?? $name);
            continue;
        }
        $st = $status[$name] ?? null;
        $lossStr = (string)($st['loss'] ?? '~');
        $sock = "/var/run/dpinger_{$name}.sock";
        $sockFound = file_exists($sock);
        $link = wf_parse_ifconfig((string)shell_exec('/sbin/ifconfig ' . escapeshellarg((string)($g['if'] ?? '')) . ' 2>/dev/null'));
        $monitored = empty($g['monitor_disable']) && empty($g['disabled']);
        $judging = array_merge($judging, wf_contract_judging($instances[$name] ?? null, $st, $loopbackOut, $sockFound, $monitored));
        $age = isset($pids[$name]) ? ($ages[$pids[$name]] ?? null) : null;
        $wans[$name] = [
            'uuid' => (string)($g['uuid'] ?? ''),
            'gateway_ip' => (string)($g['gateway'] ?? ''),
            'route_target' => wf_route_target((string)($g['gateway'] ?? ''), (string)($g['if'] ?? '')),
            'rank' => 0,
            'disabled' => !empty($g['disabled']),
            'force_down' => !empty($g['force_down']),
            'status' => (string)($st['status'] ?? 'none'),
            'present' => $st !== null,
            'tilde' => $st !== null && $lossStr === '~',
            'carrier' => $link['carrier'],
            'has_ipv4' => $link['has_ipv4'],
            'loss' => $lossStr === '~' ? null : (float)$lossStr,
            'sock_age' => $sockFound ? $age : null,
            'losslow' => (float)($g['current_losslow'] ?? 10),
            'losshigh' => (float)($g['current_losshigh'] ?? 20),
            'time_period' => (int)($g['current_time_period'] ?? 60),
            'interval' => (int)($g['current_interval'] ?? 1),
            'loss_interval' => (int)($g['current_loss_interval'] ?? 4),
        ];
    }
    foreach (wf_core_rank(array_map('strval', array_keys($all)), array_keys($wans)) as $name => $rank) {
        $wans[$name]['rank'] = $rank;
    }
    $read = fn (string $f): ?string => is_readable($f) ? (string)file_get_contents($f) : null;
    $a = '/usr/local/opnsense/service/conf/actions.d/';
    $command = wf_contract_commands($read($a . 'actions_interface.conf'), $read($a . 'actions_filter.conf'),
        $read('/usr/local/etc/rc'));
    $bootId = wf_boot_id();
    if ($bootId === '') {
        $command[] = 'kern.boot_id unreadable (a reboot the early hook missed would go unnoticed)';
    }
    $tsActions = $read($a . 'actions_tailscale.conf');
    $tailscale = wf_contract_tailscale($tsActions);
    return [
        'now' => $now, 'boot_id' => $bootId, 'release' => null,
        'enabled' => $mdl->enabled->isEqual('1'), 'dry' => $mdl->dry->isEqual('1'),
        'failback' => $mdl->failback->isEqual('1'), 'failback_delay' => (int)$mdl->failback_delay->getValue() * 60,
        'failback_now' => false,
        'tailscale_restart' => $mdl->tailscale_restart->isEqual('1') && $tsActions !== null && $tailscale === [],
        'default_gw' => wf_route_get_target(wf_parse_route_get($defaultOut)),
        'wans' => $wans, 'unresolved' => $wansRes['unresolved'],
        'held' => $heldRes['names'], 'held_stale' => $heldRes['unresolved'],
        'force_down' => $forceDown, 'uuid_by_name' => array_flip($nameByUuid),
        'contract' => ['judging' => array_values(array_unique($judging)), 'command' => $command, 'tailscale' => $tailscale],
    ];
}

/**
 * @param array<string, string> $wanTargets WAN name => route target
 * @return array{flows: list<array>, renderings: array<string, list<array>>, pinned: array<string, true>,
 *               rule_pref: array<string, list<string>>, default: ?string, selfcheck: bool, raw_states: string, raw_rules: string}
 */
function wf_snapshot_pf(array $wanTargets): array
{
    $rawStates = (string)shell_exec('/sbin/pfctl -vvss 2>/dev/null');
    $rawRules = (string)shell_exec('/sbin/pfctl -vvsr 2>/dev/null');
    $states = wf_parse_states($rawStates);
    $flows = wf_flows($states, array_flip($wanTargets));
    $pinned = wf_pinned_hosts($flows, function (string $host, array $f): bool {
        $r = wf_route_get($host);
        return $r['destination'] !== null && $r['destination'] !== 'default'
            && wf_route_get_target($r) === wf_route_target((string)$f['anchor']['route_to_gw'], (string)$f['anchor']['route_to_if']);
    }, 200);
    $groups = (new \OPNsense\Routing\GatewayGroups())->getGroupsConfig();
    $pref = [];
    foreach ((new \OPNsense\Firewall\Filter())->rules->rule->iterateItems() as $uuid => $rule) {
        $gw = $rule->gateway->getValue();
        if ($gw === '') {
            $pref[(string)$uuid] = [];
        } elseif (isset($groups[$gw])) {
            $pref[(string)$uuid] = wf_first_tier($groups[$gw]['tiers']);
        } else {
            $pref[(string)$uuid] = [$gw];
        }
    }
    $default = array_search(wf_live_default(), $wanTargets, true);
    return ['flows' => $flows, 'renderings' => wf_parse_rules($rawRules), 'pinned' => $pinned, 'rule_pref' => $pref,
            'default' => $default === false ? null : $default, 'selfcheck' => wf_pf_selfcheck($rawStates, $states),
            'raw_states' => $rawStates, 'raw_rules' => $rawRules];
}
