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
 * Live collectors. Read-only: the plugin's settings and hold records, gateway config and status, dpinger socket
 * ages, link state, routes, pf, and the core files the contract checks. Only short-lived readers are exec'd.
 */

require_once 'config.inc';
require_once 'util.inc';
require_once 'interfaces.inc';
require_once 'plugins.inc.d/dpinger.inc';
require_once __DIR__ . '/judge.php';
require_once __DIR__ . '/parsers.php';
require_once __DIR__ . '/pfstate.php';
require_once __DIR__ . '/contract.php';
require_once __DIR__ . '/failback.php';
require_once __DIR__ . '/state.php';

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

/**
 * /sbin/pfctl with $args and no shell: its stdout, its stderr kept apart (in a temporary file, so a long listing cannot
 * block on a full pipe), and its exit status. A pfctl that cannot be started, or no temporary file for its stderr, is a
 * failed run (rc -1). Every pf listing the snapshot and the failback gate read comes through here (wf_pf_listing()).
 *
 * @param list<string> $args
 * @return array{out: string, err: string, rc: int}
 */
function wf_pfctl_run(array $args): array
{
    $errFile = tempnam(sys_get_temp_dir(), 'wf_pfctl');
    if ($errFile === false) {
        return ['out' => '', 'err' => 'pfctl: no temporary file for its stderr', 'rc' => -1];
    }
    try {
        $pipes = [];
        $proc = proc_open(array_merge(['/sbin/pfctl'], $args),
            [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['file', $errFile, 'w']], $pipes);
        if (!is_resource($proc)) {
            return ['out' => '', 'err' => 'pfctl: could not be started', 'rc' => -1];
        }
        $out = (string)stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $rc = proc_close($proc);
        $err = (string)file_get_contents($errFile);
    } finally {
        unlink($errFile);
    }
    return ['out' => $out, 'err' => $err, 'rc' => $rc];
}

/** The live IPv4 default route as a route target (gateway@interface), or null without one. */
function wf_live_default(): ?string
{
    return wf_route_get_target(wf_route_get('default'));
}

/**
 * 1.3_1's held list, read from the raw config (the settings model no longer has it): the node's text, or null when
 * the config has no such node. An upgrade's migration, or an evaluation's import, removes it.
 */
function wf_holds_legacy_csv(): ?string
{
    $root = \OPNsense\Core\Config::getInstance()->object();
    return isset($root->OPNsense->WanFailover->held) ? (string)$root->OPNsense->WanFailover->held : null;
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
 *               default_gw: ?string,
 *               wans: array<string, array{uuid: string, gateway_ip: string, if: string, route_target: string, rank: int,
 *                                         disabled: bool, monitor_disable: bool, force_down: bool, status: string,
 *                                         present: bool, tilde: bool, carrier: bool, has_ipv4: bool, loss: ?float,
 *                                         sock_age: ?int, losslow: float, losshigh: float, time_period: int,
 *                                         interval: int, loss_interval: int}>,
 *               unresolved: list<string>,
 *               holds: array<string, array{boot: string, since: int}>, holds_stale: list<string>, holds_dupes: list<string>,
 *               legacy_held: list<string>, force_down: array<string, bool>,
 *               contract: array{judging: list<string>, command: list<string>, failback: list<string>, tailscale: list<string>,
 *                               removal: list<string>, names: list<string>}}
 *     wans: by gateway name; disabled and monitor_disable are the gateway's own settings, either of which means the
 *     engine can never judge it (wf_unjudgeable());
 *     holds: the hold records by gateway name, as found; whose they are is the planner's to prove (wf_reconcile());
 *     legacy_held: the gateways 1.3_1's held list names while it is still in the config;
 *     contract.failback: read only while failback is on, since its drift suspends failback alone; WF_UNREAD_RULES in it
 *     is a rule listing that could not be read, which wf_contract_kept() resolves before anything acts on it
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
    /* a name or interface that is not a plain token never reaches a path or a command: the WAN is unresolved */
    $usable = [];
    foreach ($wansRes['names'] as $name) {
        $g = $all[$name];
        if (wf_name_ok($name) && wf_if_ok((string)($g['if'] ?? ''))) {
            $usable[] = $name;
        } else {
            $wansRes['unresolved'][] = (string)($g['uuid'] ?? $name);
        }
    }
    $wansRes['names'] = $usable;
    $holds = wf_resolve_records((new \OPNsense\WanFailover\Holds())->records(), $nameByUuid);
    $legacyCsv = wf_holds_legacy_csv();
    $legacy = $legacyCsv === null ? [] : array_values(wf_legacy_entries($legacyCsv, $nameByUuid)['named']);
    $status = dpinger_status();
    $instances = dpinger_instances(true);
    $defaultOut = (string)shell_exec('/sbin/route -n get -inet default 2>/dev/null');
    /* the route-format check probes the loopback route, which always exists; the default route can be
     * missing for a moment while routing is reconfigured, which is not a format drift */
    $loopbackOut = (string)shell_exec('/sbin/route -n get -inet 127.0.0.1 2>/dev/null');
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
        /* a window's age is its dpinger's process age: monotonic, so a clock step cannot make it look settled. The
         * socket, the pid file and the age are read together, so a dpinger restart can fall between them only for
         * this WAN */
        $sockFound = file_exists(sprintf(WF_DPINGER_SOCK, $name));
        $pidFile = sprintf(WF_DPINGER_PID, $name);
        $pid = is_readable($pidFile) ? (int)trim((string)file_get_contents($pidFile)) : 0;
        $age = $pid > 0 ? (wf_parse_ps_etimes((string)shell_exec('/bin/ps -o pid= -o etimes= -p '
            . escapeshellarg((string)$pid) . ' 2>/dev/null'))[$pid] ?? null) : null;
        $link = wf_parse_ifconfig((string)shell_exec('/sbin/ifconfig ' . escapeshellarg((string)($g['if'] ?? '')) . ' 2>/dev/null'));
        /* core runs a dpinger only for a gateway the engine can judge */
        $flags = ['disabled' => !empty($g['disabled']), 'monitor_disable' => !empty($g['monitor_disable'])];
        $judging = array_merge($judging, wf_contract_judging($instances[$name] ?? null, $st, $loopbackOut, $sockFound,
            wf_dpinger_expected(wf_unjudgeable($flags) === null, $link), $pid > 0, $age !== null));
        $wans[$name] = [
            'uuid' => (string)($g['uuid'] ?? ''),
            'gateway_ip' => (string)($g['gateway'] ?? ''),
            'if' => (string)($g['if'] ?? ''),
            'route_target' => wf_route_target((string)($g['gateway'] ?? ''), (string)($g['if'] ?? '')),
            'rank' => 0,
            'disabled' => $flags['disabled'],
            'monitor_disable' => $flags['monitor_disable'],
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
    $interfaceActions = $read($a . 'actions_interface.conf');
    $command = wf_contract_commands($interfaceActions, $read($a . 'actions_filter.conf'), $read('/usr/local/etc/rc'));
    $bootId = wf_boot_id();
    if ($bootId === '') {
        $command[] = 'kern.boot_id unreadable (a reboot the early hook missed would go unnoticed)';
    }
    $tsActions = $read($a . 'actions_tailscale.conf');
    $tailscale = wf_contract_tailscale($tsActions);
    $names = wf_contract_name_mask($read(WF_CORE_GATEWAYS_XML));
    $failbackOn = $mdl->failback->isEqual('1');
    $failback = $failbackOn ? wf_contract_failback(wf_pf_listing('wf_pfctl_run', ['-vvsr']),
        wf_contract_groups_read(WF_CORE_GROUPS_CLASS, WF_CORE_GROUPS_METHOD)) : [];
    return [
        'now' => $now, 'boot_id' => $bootId, 'release' => null,
        'enabled' => $mdl->enabled->isEqual('1'), 'dry' => $mdl->dry->isEqual('1'),
        'failback' => $failbackOn, 'failback_delay' => (int)$mdl->failback_delay->getValue() * 60,
        'failback_now' => false,
        'tailscale_restart' => $mdl->tailscale_restart->isEqual('1') && $tsActions !== null && $tailscale === [],
        'default_gw' => wf_route_get_target(wf_parse_route_get($defaultOut)),
        'wans' => $wans, 'unresolved' => $wansRes['unresolved'],
        'holds' => $holds['holds'], 'holds_stale' => $holds['stale'], 'holds_dupes' => $holds['dupes'],
        'legacy_held' => $legacy, 'force_down' => $forceDown,
        'contract' => ['judging' => array_values(array_unique($judging)), 'command' => $command, 'failback' => $failback,
                       'tailscale' => $tailscale, 'removal' => wf_contract_removal($interfaceActions, $read($a . 'actions_cron.conf')),
                       'names' => $names],
    ];
}

/**
 * Both listings are read through wf_pf_listing(), once more when cut short. drift is the failback contract on this
 * read's own rule listing and groups (wf_contract_failback()), after WF_UNREAD_STATES when the state listing could not
 * be read; such a read never parses (selfcheck false). Groups that cannot be read, or a group whose shape drifted, give
 * no preference (wf_rule_pref()), so the read never throws on them.
 *
 * @param array<string, string> $wanTargets WAN name => route target
 * @return array{flows: list<array>, renderings: array<string, list<array>>, pinned: array<string, true>,
 *               rule_pref: array<string, list<string>>, default: ?string, selfcheck: bool, drift: list<string>,
 *               raw_states: string, raw_rules: string} raw_states, raw_rules: empty when unread
 */
function wf_snapshot_pf(array $wanTargets): array
{
    $readStates = wf_pf_listing('wf_pfctl_run', ['-vvss']);
    $readRules = wf_pf_listing('wf_pfctl_run', ['-vvsr']);
    $rawStates = $readStates ?? '';
    $rawRules = $readRules ?? '';
    $states = wf_parse_states($rawStates);
    $flows = wf_flows($states, array_flip($wanTargets));
    $pinned = wf_pinned_hosts($flows, function (string $host, array $f): bool {
        $r = wf_route_get($host);
        return $r['destination'] !== null && $r['destination'] !== 'default'
            && wf_route_get_target($r) === wf_route_target((string)$f['anchor']['route_to_gw'], (string)$f['anchor']['route_to_if']);
    }, 200);
    $groups = wf_contract_groups_read(WF_CORE_GROUPS_CLASS, WF_CORE_GROUPS_METHOD);
    $ruleGateways = [];
    foreach ((new \OPNsense\Firewall\Filter())->rules->rule->iterateItems() as $uuid => $rule) {
        $ruleGateways[(string)$uuid] = (string)$rule->gateway->getValue();
    }
    $pref = wf_rule_pref($ruleGateways, $groups['groups']);
    $default = array_search(wf_live_default(), $wanTargets, true);
    return ['flows' => $flows, 'renderings' => wf_parse_rules($rawRules), 'pinned' => $pinned, 'rule_pref' => $pref,
            'default' => $default === false ? null : $default,
            'selfcheck' => $readStates !== null && wf_pf_selfcheck($rawStates, $states),
            'drift' => array_merge($readStates === null ? [WF_UNREAD_STATES] : [], wf_contract_failback($readRules, $groups)),
            'raw_states' => $rawStates, 'raw_rules' => $rawRules];
}
