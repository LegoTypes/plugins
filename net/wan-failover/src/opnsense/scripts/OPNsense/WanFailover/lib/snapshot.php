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

function wf_boot_time(): int
{
    return wf_parse_boottime((string)shell_exec('/sbin/sysctl -n kern.boottime'));
}

function wf_booting(): bool
{
    return product::getInstance()->booting();
}

function wf_route_get(string $dst): array
{
    return wf_parse_route_get((string)shell_exec('/sbin/route -n get -inet ' . escapeshellarg($dst) . ' 2>/dev/null'));
}

function wf_live_default(): ?string
{
    return wf_route_get('default')['gateway'];
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
 * @return array{now: int, boot_time: int, enabled: bool, dry: bool, failback: bool, tailscale_restart: bool,
 *               default_gw: ?string, wans: array<string, array>, unresolved: list<string>, held: list<string>,
 *               held_stale: list<string>, force_down: array<string, bool>, uuid_by_name: array<string, string>,
 *               contract: array{judging: list<string>, command: list<string>}}
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
        $judging = array_merge($judging, wf_contract_judging($instances[$name] ?? null, $st, $defaultOut, $sockFound || !$monitored));
        $wans[$name] = [
            'uuid' => (string)($g['uuid'] ?? ''),
            'gateway_ip' => (string)($g['gateway'] ?? ''),
            'priority' => (int)($g['priority'] ?? 255),
            'disabled' => !empty($g['disabled']),
            'force_down' => !empty($g['force_down']),
            'status' => (string)($st['status'] ?? 'none'),
            'present' => $st !== null,
            'tilde' => $st !== null && $lossStr === '~',
            'carrier' => $link['carrier'],
            'has_ipv4' => $link['has_ipv4'],
            'loss' => $lossStr === '~' ? null : (float)$lossStr,
            'sock_age' => $sockFound ? max(0, $now - (int)filemtime($sock)) : null,
            'losslow' => (float)($g['current_losslow'] ?? 10),
            'losshigh' => (float)($g['current_losshigh'] ?? 20),
            'time_period' => (int)($g['current_time_period'] ?? 60),
            'interval' => (int)($g['current_interval'] ?? 1),
            'loss_interval' => (int)($g['current_loss_interval'] ?? 4),
        ];
    }
    $read = fn (string $f): ?string => is_readable($f) ? (string)file_get_contents($f) : null;
    $a = '/usr/local/opnsense/service/conf/actions.d/';
    $command = wf_contract_commands($read($a . 'actions_interface.conf'), $read($a . 'actions_filter.conf'),
        $read($a . 'actions_tailscale.conf'), $read('/usr/local/etc/rc'));
    return [
        'now' => $now, 'boot_time' => wf_boot_time(),
        'enabled' => $mdl->enabled->isEqual('1'), 'dry' => $mdl->dry->isEqual('1'),
        'failback' => $mdl->failback->isEqual('1'), 'tailscale_restart' => $mdl->tailscale_restart->isEqual('1'),
        'default_gw' => wf_parse_route_get($defaultOut)['gateway'],
        'wans' => $wans, 'unresolved' => $wansRes['unresolved'],
        'held' => $heldRes['names'], 'held_stale' => $heldRes['unresolved'],
        'force_down' => $forceDown, 'uuid_by_name' => array_flip($nameByUuid),
        'contract' => ['judging' => array_values(array_unique($judging)), 'command' => $command],
    ];
}

/**
 * @param array<string, string> $wanGwIp WAN name => gateway ip
 * @return array{flows: list<array>, renderings: array<string, list<array>>, pinned: array<string, true>,
 *               rule_pref: array<string, list<string>>, default: ?string, selfcheck: bool, raw_states: string, raw_rules: string}
 */
function wf_snapshot_pf(array $wanGwIp): array
{
    $rawStates = (string)shell_exec('/sbin/pfctl -vvss 2>/dev/null');
    $rawRules = (string)shell_exec('/sbin/pfctl -vvsr 2>/dev/null');
    $states = wf_parse_states($rawStates);
    $flows = wf_flows($states, array_flip($wanGwIp));
    $pinned = [];
    $looked = [];
    foreach ($flows as $f) {
        $host = wf_addr_host($f['anchor']['dst']);
        if ($f['kind'] !== 'local' || isset($looked[$host]) || count($looked) >= 200) {
            continue;
        }
        $looked[$host] = true;
        $r = wf_route_get($host);
        if ($r['destination'] !== null && $r['destination'] !== 'default' && $r['gateway'] === $f['anchor']['route_to_gw']) {
            $pinned[$host] = true;
        }
    }
    $groups = (new \OPNsense\Routing\GatewayGroups())->getGroupsConfig();
    $pref = [];
    foreach ((new \OPNsense\Firewall\Filter())->rules->rule->iterateItems() as $uuid => $rule) {
        $gw = $rule->gateway->getValue();
        if ($gw === '') {
            $pref[(string)$uuid] = [];
        } elseif (isset($groups[$gw])) {
            $tiers = $groups[$gw]['tiers'];
            ksort($tiers);
            $first = reset($tiers);
            $pref[(string)$uuid] = is_array($first) ? array_values($first) : [];
        } else {
            $pref[(string)$uuid] = [$gw];
        }
    }
    $default = array_search(wf_live_default(), $wanGwIp, true);
    return ['flows' => $flows, 'renderings' => wf_parse_rules($rawRules), 'pinned' => $pinned, 'rule_pref' => $pref,
            'default' => $default === false ? null : $default, 'selfcheck' => wf_pf_selfcheck($rawStates, $states),
            'raw_states' => $rawStates, 'raw_rules' => $rawRules];
}
