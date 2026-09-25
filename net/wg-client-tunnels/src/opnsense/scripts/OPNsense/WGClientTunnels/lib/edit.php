<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Edit (spec 2026-09-24 section 6.5): the request check, the outbound NAT
 * as Edit sees it, the dialog's prefill and the planner. All pure. The
 * planner compares the requested values with the derived record and returns
 * only the differences, the apply mode they need (none < filter < routes <
 * tunnel), or why it cannot proceed. A replacement config's private and
 * preshared keys never reach this file: the planner sees the config's public
 * parts, our public key, and whether its preshared key equals the stored one.
 */

require_once __DIR__ . '/tunnels.php';
require_once __DIR__ . '/refs.php';
require_once __DIR__ . '/wgconf.php';
require_once __DIR__ . '/actions.php';
require_once __DIR__ . '/selftest.php';

/* the Edit request's keys: the API form's edit.<key> and the CLI's JSON (which adds uuid) */
const WGCT_EDIT_FIELDS = ['config', 'wan', 'monitor', 'mtu', 'ipv6', 'unique', 'nat4', 'nat6'];

/**
 * The typed Edit request. $raw is a form/JSON boundary, so every value is
 * type-checked here. An absent or null key keeps the tunnel's current value
 * (the CLI sends only what changes; the API form sends every field); an empty
 * wan keeps it too (an unbound tunnel's dialog offers none). A present
 * nat4/nat6 is the full wanted list, as a list of strings or a comma list;
 * empty means no sources. Pure.
 *
 * @param array  $raw  keys of WGCT_EDIT_FIELDS
 * @param string $uuid the managed instance
 * @return array{errors: array<string, string>, req: array{uuid: string, wan: ?string, monitor: ?string, mtu: ?int, ipv6: ?bool, unique: ?bool, nat: array{inet: ?list<string>, inet6: ?list<string>}}, text: string}
 */
function wgct_edit_request(#[\SensitiveParameter] array $raw, string $uuid): array {
    $errors = [];
    $given = fn (string $key): bool => ($raw[$key] ?? null) !== null;
    $str = function (string $key) use ($raw): string {
        $v = $raw[$key] ?? '';
        return is_string($v) ? trim($v) : '';
    };
    $list = function (string $key) use ($raw, &$errors): array {
        $v = $raw[$key];
        if (is_string($v)) {
            return array_values(array_unique(wgct_split_csv($v)));
        }
        if (!is_array($v)) {
            $errors[$key] = 'a list of interfaces and aliases';
            return [];
        }
        $out = [];
        foreach ($v as $item) {
            if (!is_string($item)) {
                $errors[$key] = 'a list of interfaces and aliases';
                return [];
            }
            if (trim($item) !== '') {
                $out[] = trim($item);
            }
        }
        return array_values(array_unique($out));
    };

    $wan = null;
    if ($given('wan')) {
        if (!is_string($raw['wan'])) {
            $errors['wan'] = 'a gateway name';
        } elseif ($str('wan') !== '') {
            $wan = $str('wan');
        }
    }
    $monitor = null;
    if ($given('monitor')) {
        $monitor = $str('monitor');
        if (filter_var($monitor, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            $errors['monitor'] = 'an IPv4 address';
        }
    }
    $mtu = null;
    if ($given('mtu')) {
        $m = $raw['mtu'];
        if (is_int($m)) {
            $mtu = $m;
        } elseif (is_string($m) && ctype_digit(trim($m))) {
            $mtu = (int)trim($m);
        } else {
            $errors['mtu'] = is_string($m) && trim($m) === '' ? 'measure or enter the MTU' : 'a whole number';
        }
        if ($mtu !== null && ($mtu < WGCT_TUNNEL_MTU_MIN || $mtu > WGCT_TUNNEL_MTU_MAX)) {
            $errors['mtu'] = sprintf('%d to %d', WGCT_TUNNEL_MTU_MIN, WGCT_TUNNEL_MTU_MAX);
        }
    }
    $flags = [];
    foreach (['ipv6', 'unique'] as $key) {
        [$valid, $value] = wgct_request_flag($raw[$key] ?? null);
        if (!$valid) {
            $errors[$key] = 'true or false (1 or 0), or leave it out to keep it';
        }
        $flags[$key] = $value;
    }
    if ($given('config') && !is_string($raw['config'])) {
        $errors['config'] = 'the wg-quick text';
    }
    $nat = ['inet' => $given('nat4') ? $list('nat4') : null, 'inet6' => $given('nat6') ? $list('nat6') : null];
    if (preg_match('/^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$/', $uuid) !== 1) {
        $errors['general'] = 'not a tunnel uuid';
    }
    return [
        'errors' => $errors,
        'req' => [
            'uuid' => $uuid, 'wan' => $wan, 'monitor' => $monitor, 'mtu' => $mtu,
            'ipv6' => $flags['ipv6'], 'unique' => $flags['unique'], 'nat' => $nat,
        ],
        'text' => is_string($raw['config'] ?? null) ? $raw['config'] : '',
    ];
}

/**
 * @param array $snap the action snapshot
 * @return list<string> the NAT sources Edit offers: real interface keys and every alias. Pure.
 */
function wgct_edit_nat_known(array $snap): array {
    return array_values(array_unique(array_merge(
        array_values(array_filter(array_map('strval', array_keys($snap['core']['interfaces'])), 'wgct_is_nat_interface_key')),
        $snap['aliases']
    )));
}

/**
 * @param array $r an action-snapshot snat rule
 * @return string the rule as the preview and the dialog list it. Pure.
 */
function wgct_edit_rule_text(array $r): string {
    $f = $r['fields'];
    $family = ['inet' => 'IPv4', 'inet6' => 'IPv6', 'inet46' => 'IPv4+IPv6'][$r['ipprotocol']] ?? $r['ipprotocol'];
    return sprintf(
        '%s on %s from %s%s to %s%s%s%s',
        $family, $r['interface'],
        ($f['source_not'] ?? '0') === '1' ? '!' : '', $f['source_net'] ?? 'any',
        ($f['destination_not'] ?? '0') === '1' ? '!' : '', $f['destination_net'] ?? 'any',
        $r['enabled'] === '1' ? '' : ' (disabled)',
        ($f['description'] ?? '') !== '' ? " \"{$f['description']}\"" : ''
    );
}

/**
 * The tunnel interface's outbound NAT as Edit sees it (ruling 6). A rule is
 * plain when it names only this interface, one family, a source Edit offers
 * and no negation: its source is ticked and unticked. Every other rule on
 * the interface is kept exactly as it is, and listed. Pure.
 *
 * @param array  $snap the action snapshot
 * @param string $opt  the tunnel interface key
 * @return array{sources: array{inet: list<string>, inet6: list<string>}, rules: array{inet: array<string, list<string>>, inet6: array<string, list<string>>}, kept: list<string>}
 *         sources: those with an enabled plain rule, in config order;
 *         rules: source => every plain rule with it, enabled or not (an untick deletes them all)
 */
function wgct_edit_nat_state(array $snap, string $opt): array {
    $known = wgct_edit_nat_known($snap);
    $state = ['sources' => ['inet' => [], 'inet6' => []], 'rules' => ['inet' => [], 'inet6' => []], 'kept' => []];
    foreach ($snap['snat_rules'] as $ruleUuid => $r) {
        $ifs = wgct_split_csv($r['interface']);
        if (!in_array($opt, $ifs, true)) {
            continue;
        }
        $family = $r['ipprotocol'];
        $source = trim($r['fields']['source_net'] ?? '');
        if ($ifs === [$opt] && ($family === 'inet' || $family === 'inet6')
            && ($r['fields']['source_not'] ?? '0') !== '1' && in_array($source, $known, true)) {
            $state['rules'][$family][$source][] = (string)$ruleUuid;
            if ($r['enabled'] === '1' && !in_array($source, $state['sources'][$family], true)) {
                $state['sources'][$family][] = $source;
            }
        } else {
            $state['kept'][] = wgct_edit_rule_text($r);
        }
    }
    return $state;
}

/**
 * @param array  $derived wgct_derive()
 * @param string $uuid    a managed instance (the caller checked)
 * @return array its derived record
 */
function wgct_edit_find(array $derived, string $uuid): array {
    foreach ($derived['tunnels'] as $t) {
        if ($t['uuid'] === $uuid) {
            return $t;
        }
    }
    throw new \LogicException("{$uuid} is not among the derived tunnels");
}

/**
 * @param array $inst a wgct_core_snapshot() instance
 * @return int its MTU, WireGuard's default when unset
 */
function wgct_edit_instance_mtu(array $inst): int {
    return $inst['mtu'] !== '' ? (int)$inst['mtu'] : WGCT_DEFAULT_MTU;
}

/**
 * @param array  $core wgct_core_snapshot()
 * @param string $uuid the instance to leave out
 * @return array<string, string> canonical IPv6 tunnel address => name, of every other instance. Pure.
 */
function wgct_edit_other_ipv6(array $core, string $uuid): array {
    $out = [];
    foreach ($core['instances'] as $otherUuid => $inst) {
        if ((string)$otherUuid === $uuid) {
            continue;
        }
        foreach ($inst['tunneladdress'] as $address) {
            $ip = explode('/', $address)[0];
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
                $out[wgct_canonical_ip($ip)] = $inst['name'];
            }
        }
    }
    return $out;
}

/**
 * @param list<string> $addresses tunnel addresses (CIDR)
 * @return list<string> canonical and sorted, so two spellings or orders compare equal. Pure.
 */
function wgct_edit_address_set(array $addresses): array {
    $out = [];
    foreach ($addresses as $a) {
        $parts = explode('/', $a, 2);
        $out[] = wgct_canonical_ip($parts[0]) . (isset($parts[1]) ? '/' . $parts[1] : '');
    }
    sort($out);
    return $out;
}

/**
 * The IPv6 tunnel address a swap config gives a tunnel: Create's
 * unique-addressing rule (spec 6.1), with the tunnel's own instance left out
 * of "already on an instance" (ruling 10). Pure.
 *
 * @param list<string> $configV6 the config's IPv6 Address entries (not empty)
 * @return array{address: string, why: string, error: ?string}
 */
function wgct_edit_ipv6_address(array $core, array $derived, string $uuid, string $n, array $configV6, ?bool $unique): array {
    $others = wgct_edit_other_ipv6($core, $uuid);
    $shared = null;
    foreach ($configV6 as $address) {
        $canonical = wgct_canonical_ip(explode('/', $address)[0]);
        if ($shared === null && isset($others[$canonical])) {
            $shared = [$address, $others[$canonical]];
        }
    }
    $convention = wgct_unique_convention($derived);
    if ($unique ?? ($shared !== null || $convention)) {
        $own = "fd00::{$n}:1";
        $holder = $others[wgct_canonical_ip($own)] ?? null;
        if ($holder !== null) {
            return ['address' => '', 'why' => '', 'error' => "{$own} is already on instance {$holder}"];
        }
        $why = $unique !== null ? 'as requested'
            : ($shared !== null ? "default: {$shared[0]} is already on instance {$shared[1]}" : 'default: the managed tunnels use the fd00::N:1 convention');
        return ['address' => "{$own}/128", 'why' => "unique addressing, {$why}; the provider must accept and translate it", 'error' => null];
    }
    if (count($configV6) !== 1) {
        return ['address' => '', 'why' => '', 'error' => 'the config has several IPv6 addresses; turn on unique addressing'];
    }
    if ($shared !== null) {
        return ['address' => '', 'why' => '', 'error' => "{$shared[0]} is already on instance {$shared[1]} (FreeBSD refuses one IPv6 address on two interfaces); turn on unique addressing"];
    }
    return ['address' => $configV6[0], 'why' => 'the config\'s IPv6 address, unique addressing ' . ($unique !== null ? 'off as requested' : 'off by default'), 'error' => null];
}

/**
 * The Edit dialog's starting values: the tunnel's current configuration.
 * ipv6 is ticked when any IPv6 piece exists (ruling 9). Pure.
 *
 * @param array  $snap the action snapshot
 * @param string $uuid the managed instance
 * @return array{errors: list<string>, form: array<string, string|int|bool|list<string>>}
 */
function wgct_edit_prefill(array $snap, string $uuid): array {
    if (!in_array($uuid, $snap['managed'], true)) {
        return ['errors' => ['not a managed tunnel'], 'form' => []];
    }
    $core = $snap['core'];
    $derived = wgct_derive($core, $snap['managed']);
    $t = wgct_edit_find($derived, $uuid);
    $inst = $core['instances'][$uuid] ?? null;
    if ($inst === null || $t['interface'] === null) {
        return ['errors' => [($t['name'] !== '' ? $t['name'] : $uuid) . ' has no WireGuard instance or interface assignment to edit ('
            . implode(', ', array_column($t['findings'], 'code')) . ')'], 'form' => []];
    }
    $nat = wgct_edit_nat_state($snap, $t['interface']);
    return ['errors' => [], 'form' => [
        'uuid' => $uuid, 'name' => $t['name'], 'device' => $t['device'], 'interface' => $t['interface'],
        'wan' => $t['bound_wan'] ?? '', 'monitor' => $t['monitor'],
        'mtu' => wgct_edit_instance_mtu($inst), 'mtu_effective' => $t['mtu'],
        'ipv6' => $t['gw6'] !== null || $t['ipv6_address'] !== null,
        'unique' => $t['ipv6_address'] !== null && wgct_ip_equal(explode('/', $t['ipv6_address'])[0], "fd00::{$inst['instance']}:1"),
        'endpoint_ip' => $t['endpoint_ip'] ?? '',
        'nat4' => $nat['sources']['inet'], 'nat6' => $nat['sources']['inet6'], 'nat_kept' => $nat['kept'],
        'ipv6_others' => array_map('strval', array_keys(wgct_edit_other_ipv6($core, $uuid))),
        'unique_convention' => wgct_unique_convention($derived),
        'findings' => array_values(array_column($t['findings'], 'code')),
    ]];
}

/**
 * Everything Edit will write, or why it cannot (spec 6.5). Pure.
 *
 * @param array      $snap the action snapshot (with peer_fields and instance_pubkeys)
 * @param array      $refs wgct_refs_snapshot(): what may reference the IPv6 gateway that IPv6 off deletes
 * @param array      $req  wgct_edit_request()['req']
 * @param array|null $swap null without a replacement config, else
 *                         ['public' => wgct_parse_wgquick()['public'], 'own_pubkey' => string, 'psk_same' => bool]
 * @return array{errors: array<string, string>, changes: list<string>, mode: string, uuid: string, name: string, opt: string,
 *               instance: array<string, string>, peer_uuid: string, peer: array<string, string>, swap_keys: bool,
 *               gateways: array{update: array<string, array<string, string>>, add: list<array<string, string>>, delete: list<string>},
 *               routes: array{add: list<array<string, string>>, update: array<string, array<string, string>>, delete: array<string, string>},
 *               nat: array{add: list<array<string, string>>, delete: list<string>}, replay: list<string>}
 */
function wgct_plan_edit(array $snap, array $refs, array $req, ?array $swap): array {
    $uuid = $req['uuid'];
    $plan = [
        'errors' => [], 'changes' => [], 'mode' => 'none', 'uuid' => $uuid, 'name' => '', 'opt' => '',
        'instance' => [], 'peer_uuid' => '', 'peer' => [], 'swap_keys' => false,
        'gateways' => ['update' => [], 'add' => [], 'delete' => []],
        'routes' => ['add' => [], 'update' => [], 'delete' => []],
        'nat' => ['add' => [], 'delete' => []], 'replay' => [], 'kernel_routes' => [],
    ];
    if (!in_array($uuid, $snap['managed'], true)) {
        $plan['errors']['general'] = 'not a managed tunnel';
        return $plan;
    }
    $core = $snap['core'];
    $derived = wgct_derive($core, $snap['managed']);
    $t = wgct_edit_find($derived, $uuid);
    $label = $t['name'] !== '' ? $t['name'] : $uuid;
    $plan['name'] = $t['name'];

    /* a blocking finding stops the edit, unless the edit resolves it: a swap gives an IPv4 endpoint (ruling 13) */
    $resolvable = $swap !== null ? ['endpoint-unsupported'] : [];
    $blocking = [];
    foreach ($t['findings'] as $f) {
        if ($f['blocking'] && !in_array($f['code'], $resolvable, true)) {
            $blocking[] = $f['code'];
        }
    }
    if ($blocking !== []) {
        $plan['errors']['general'] = "{$label} has the blocking finding(s) " . implode(', ', array_unique($blocking))
            . '; fix them on their core pages first (hover each finding)';
        return $plan;
    }
    $inst = $core['instances'][$uuid];
    $peerUuid = $inst['peers'][0];
    $peerCore = $core['peers'][$peerUuid] ?? null;
    if ($peerCore === null) {
        $plan['errors']['general'] = "{$label}'s peer {$peerUuid} is missing; fix it on VPN > WireGuard > Peers";
        return $plan;
    }
    $opt = (string)$t['interface'];
    $n = $inst['instance'];
    $peerNow = $snap['peer_fields'][$peerUuid] ?? ['tunneladdress' => '', 'pubkey' => ''];
    $pub = $swap['public'] ?? null;
    $plan['opt'] = $opt;
    $plan['peer_uuid'] = $peerUuid;
    $e = [];
    $c = [];
    $need = ['tunnel' => false, 'routes' => false, 'filter' => false];

    /* MTU */
    $mtuNow = wgct_edit_instance_mtu($inst);
    if ($req['mtu'] !== null && $req['mtu'] !== $mtuNow) {
        $plan['instance']['mtu'] = (string)$req['mtu'];
        $need['tunnel'] = true;
        $c[] = "instance {$label}: mtu {$mtuNow} -> {$req['mtu']}";
        $ifMtu = $core['interfaces'][$opt]['mtu'];
        if ($ifMtu !== '' && (int)$ifMtu !== $req['mtu']) {
            $c[] = "NOTE mtu-override: interface {$opt} sets its own MTU {$ifMtu}, which wins over the instance MTU; the finding stays until Interfaces > {$opt} clears it";
        }
    }

    /* the other instances' peer endpoints, managed or not: endpoint => instance name */
    $theirs = [];
    foreach ($core['instances'] as $otherUuid => $other) {
        if ((string)$otherUuid === $uuid) {
            continue;
        }
        foreach ($other['peers'] as $otherPeer) {
            $address = $core['peers'][$otherPeer]['serveraddress'] ?? '';
            if ($address !== '' && !isset($theirs[$address])) {
                $theirs[$address] = $other['name'] !== '' ? $other['name'] : (string)$otherUuid;
            }
        }
    }

    /* a server swap: keys and endpoint (the addresses follow below) */
    $endpointNow = $t['endpoint_ip'];
    $endpointAfter = $pub !== null ? $pub['endpoint_ip'] : $endpointNow;
    if ($pub !== null) {
        $keys = [];
        if ($swap['own_pubkey'] !== ($snap['instance_pubkeys'][$uuid] ?? '')) {
            $plan['instance']['pubkey'] = $swap['own_pubkey'];
            $keys[] = 'the instance key pair';
        }
        if ($pub['peer_pubkey'] !== $peerNow['pubkey']) {
            $plan['peer']['pubkey'] = $pub['peer_pubkey'];
            $keys[] = 'the peer public key';
        }
        if (!$swap['psk_same']) {
            $keys[] = $pub['has_psk'] ? 'the preshared key' : 'the preshared key (removed)';
        }
        if ($keys !== []) {
            $plan['swap_keys'] = true;
            $need['tunnel'] = true;
            $c[] = "keys of {$label}: " . implode(', ', $keys) . ' replaced';
        }
        if ($pub['endpoint_ip'] !== $peerCore['serveraddress'] || $pub['endpoint_port'] !== $peerCore['serverport']) {
            $plan['peer']['serveraddress'] = $pub['endpoint_ip'];
            $plan['peer']['serverport'] = $pub['endpoint_port'];
            $need['tunnel'] = true;
            $c[] = "peer {$label}: endpoint " . ($t['endpoint'] !== '' ? $t['endpoint'] : '(none)') . " -> {$pub['endpoint_ip']}:{$pub['endpoint_port']}";
        }
        if (isset($theirs[$pub['endpoint_ip']])) {
            $e['config'] = "{$pub['endpoint_ip']} is already the endpoint of {$theirs[$pub['endpoint_ip']]}";
        }
    }

    /* IPv6: on, off, or as it is (rulings 7-9) */
    $v6State = ($t['gw6'] !== null && $t['ipv6_address'] !== null) ? 'on'
        : (($t['gw6'] !== null || $t['ipv6_address'] !== null) ? 'partial' : 'off');
    $v6Change = 'none';
    if ($req['ipv6'] === false && $v6State !== 'off') {
        $v6Change = 'off';
    } elseif ($req['ipv6'] === true && $v6State === 'off') {
        $v6Change = 'on';
    }
    $ipv6After = $v6Change === 'on' || ($v6Change === 'none' && $v6State !== 'off');
    $name6 = $t['gw4'] !== null ? $t['gw4'] . '-ipv6' : '';
    $next6 = "fd00::{$n}:2";
    if ($v6Change === 'on') {
        if ($pub === null) {
            $e['ipv6'] = 'turning IPv6 on needs a replacement config whose Address has an IPv6 address (the provider assigns it with the key)';
        } elseif ($t['gw4'] === null) {
            $e['ipv6'] = "{$label} has no IPv4 gateway for an IPv6 gateway to follow";
        } elseif (preg_match('/^[a-zA-Z0-9_-]{1,32}$/', $name6) !== 1 || isset($core['gateways'][$name6])) {
            $e['ipv6'] = "the IPv6 gateway would be named {$name6}, which is too long or already taken";
        } else {
            foreach ($core['gateways'] as $gwName => $g) {
                if ($g['gateway'] !== '' && wgct_ip_equal($g['gateway'], $next6)) {
                    $e['ipv6'] = "the IPv6 next hop {$next6} is already the address of {$gwName}";
                }
            }
        }
    }
    if ($pub !== null && $ipv6After && !isset($e['ipv6'])) {
        if ($v6State === 'partial' && $v6Change === 'none') {
            $e['ipv6'] = "{$label}'s IPv6 is incomplete (finding ipv6-incomplete): turn IPv6 off with the swap, or complete it on the core pages first";
        } elseif ($pub['addresses']['inet6'] === []) {
            $e['ipv6'] = 'the replacement config has no IPv6 Address, so the provider assigned this key none: turn IPv6 off with it';
        }
    }

    /* the tunnel addresses: rewritten only by a swap or an IPv6 change (ruling 10) */
    if (($pub !== null || $v6Change !== 'none') && !isset($e['ipv6'])) {
        $v4 = $pub !== null
            ? [$pub['addresses']['inet'][0]]
            : array_values(array_filter($inst['tunneladdress'], fn (string $a): bool => !str_contains($a, ':')));
        $v6 = [];
        $why6 = '';
        if ($ipv6After && $pub === null) {
            $v6 = array_values(array_filter($inst['tunneladdress'], fn (string $a): bool => str_contains($a, ':')));
        } elseif ($ipv6After) {
            $a6 = wgct_edit_ipv6_address($core, $derived, $uuid, $n, $pub['addresses']['inet6'], $req['unique']);
            if ($a6['error'] !== null) {
                $e['unique'] = $a6['error'];
            } else {
                $v6 = [$a6['address']];
                $why6 = $a6['why'];
            }
        }
        $after = array_merge($v4, $v6);
        if (!isset($e['unique']) && wgct_edit_address_set($after) !== wgct_edit_address_set($inst['tunneladdress'])) {
            $plan['instance']['tunneladdress'] = implode(',', $after);
            $need['tunnel'] = true;
            $c[] = "instance {$label}: tunnel addresses " . implode(',', $inst['tunneladdress']) . ' -> ' . implode(',', $after)
                . ($why6 !== '' ? " ({$why6})" : '');
        }
    }

    /* IPv6 objects: the gateway, the IPv6 NAT, the peer's allowed IPs */
    if ($v6Change === 'off') {
        if ($t['gw6'] !== null) {
            $refusals = wgct_remove_refusals($refs, [$t['gw6']], '', []);
            if ($refusals !== []) {
                $e['ipv6'] = implode('; ', $refusals) . "; take {$t['gw6']} out of those first";
            } else {
                $plan['gateways']['delete'][] = $core['gateways'][$t['gw6']]['uuid'];
                $c[] = "gateway {$t['gw6']}: deleted (IPv6 off); the tunnel restart removes its next-hop route";
            }
        }
        foreach ($snap['snat_rules'] as $ruleUuid => $r) {
            if ($r['interface'] === $opt && $r['ipprotocol'] === 'inet6') {
                $plan['nat']['delete'][] = (string)$ruleUuid;
                $c[] = 'outbound NAT ' . wgct_edit_rule_text($r) . ': deleted (IPv6 off)';
            } elseif (in_array($opt, wgct_split_csv($r['interface']), true) && $r['ipprotocol'] === 'inet46') {
                $c[] = 'NOTE outbound NAT ' . wgct_edit_rule_text($r) . ' covers both families and is kept';
            }
        }
        $need['tunnel'] = true;
    } elseif ($v6Change === 'on' && !isset($e['ipv6'])) {
        $plan['gateways']['add'][] = [
            'disabled' => '0', 'name' => $name6, 'descr' => "{$name6} (follows {$t['gw4']})", 'interface' => $opt, 'ipprotocol' => 'inet6',
            'gateway' => $next6, 'monitor' => '', 'defaultgw' => '0', 'fargw' => '1', 'monitor_disable' => '1', 'force_down' => '1',
        ];
        $c[] = "gateway {$name6} {$next6} on {$opt}, starts forced down (the health mirror releases it)";
        $need['tunnel'] = true;
    }
    if ($v6Change !== 'none' && !isset($e['ipv6'])) {
        $allowed = wgct_split_csv($peerNow['tunneladdress']);
        $allowed6 = array_values(array_filter($allowed, fn (string $a): bool => str_contains($a, ':')));
        $allowedAfter = $v6Change === 'off'
            ? array_values(array_diff($allowed, $allowed6))
            : ($allowed6 === [] ? array_merge($allowed, ['::/0']) : $allowed);
        if ($allowedAfter !== $allowed) {
            $plan['peer']['tunneladdress'] = implode(',', $allowedAfter);
            $c[] = "peer {$label}: allowed IPs " . implode(',', $allowed) . ' -> ' . implode(',', $allowedAfter);
        }
    }

    /* monitor (R2, as Create checks it; the tunnel's own monitor is no conflict) */
    if ($req['monitor'] !== null && !wgct_ip_equal($req['monitor'], $t['monitor'])) {
        $monitor = $req['monitor'];
        if ($t['gw4'] === null) {
            $e['monitor'] = "{$label} has no IPv4 gateway to monitor";
        } else {
            $uses = [];
            foreach ($core['gateways'] as $gwName => $g) {
                if ((string)$gwName !== $t['gw4'] && $g['monitor'] !== '' && wgct_ip_equal($g['monitor'], $monitor)) {
                    $uses[] = "the monitor of {$gwName}";
                }
                if ($g['gateway'] !== '' && wgct_ip_equal($g['gateway'], $monitor)) {
                    $uses[] = "the address of {$gwName}";
                }
            }
            if (wgct_ip_in($monitor, array_merge($core['dns_servers'], $core['forwarders']))) {
                $uses[] = 'a system DNS server or Unbound forwarder';
            }
            $endpoints = array_column($core['peers'], 'serveraddress');
            if ($endpointAfter !== null) {
                $endpoints[] = $endpointAfter;
            }
            if (wgct_ip_in($monitor, $endpoints)) {
                $uses[] = 'a WireGuard endpoint';
            }
            if ($uses !== []) {
                $e['monitor'] = "{$monitor} is already " . implode(', ', array_unique($uses)) . '; a tunnel needs a monitor IP nothing else uses';
            } else {
                $plan['gateways']['update'][$t['gw4']] = ['monitor' => $monitor];
                $need['routes'] = true;
                $c[] = "gateway {$t['gw4']}: monitor " . ($t['monitor'] !== '' ? $t['monitor'] : '(none)') . " -> {$monitor}";
                if ($t['monitor'] !== '') {
                    /* dpinger adds the new monitor's host route but never deletes the old one */
                    $plan['kernel_routes'][$core['gateways'][$t['gw4']]['uuid']] = $t['monitor'] . '/32';
                    $c[] = "kernel host route {$t['monitor']}/32 (the old monitor): deleted";
                }
            }
        }
    }

    /* the endpoint route: a WAN move, or a swap to a new endpoint (rulings 12, 13) */
    $wanNow = $t['bound_wan'];
    $wanAfter = $req['wan'] ?? $wanNow;
    /* a refused new endpoint plans no route work, and its refusal is the one reported on config */
    if (($wanAfter !== $wanNow || $endpointAfter !== $endpointNow) && !($endpointAfter !== $endpointNow && isset($e['config']))) {
        $wanError = $wanAfter === null ? "{$label} is unbound: choose the WAN the new endpoint is routed to" : wgct_wan_error($core, $wanAfter);
        if ($wanError !== null) {
            $e['wan'] = $wanError;
        } elseif ($endpointAfter === $endpointNow) {
            if ($wanNow === null) {
                $e['wan'] = "{$label} is unbound: Rebind (the row's link button, or tunnel.php rebind) binds it to a WAN";
            } else {
                $binding = array_filter(wgct_binding_routes($core), fn (array $b): bool => $b['ip'] === $endpointNow);
                if (count($binding) !== 1) {
                    $e['wan'] = "several routes bind {$endpointNow}/32; keep one on System > Routes first";
                } elseif (isset($theirs[$endpointNow])) {
                    $e['wan'] = "{$endpointNow} is also the endpoint of {$theirs[$endpointNow]}, so its route would move that tunnel too; "
                        . "give one of them another server first";
                } else {
                    $plan['routes']['update'][(string)array_key_first($binding)] = ['gateway' => $wanAfter];
                    $need['tunnel'] = true;
                    $c[] = "static route {$endpointNow}/32: via {$wanNow} -> {$wanAfter}";
                }
            }
        } elseif ($endpointAfter !== null) {
            if ($endpointNow !== null) {
                foreach ($core['routes'] as $routeUuid => $r) {
                    if ($r['network'] !== $endpointNow . '/32') {
                        continue;
                    }
                    if (isset($theirs[$endpointNow])) {
                        $c[] = "KEEP static route {$r['network']}: {$theirs[$endpointNow]}'s peer uses {$endpointNow}";
                    } else {
                        $plan['routes']['delete'][(string)$routeUuid] = $r['network'];
                        $c[] = "static route {$r['network']} via {$r['gateway']}: deleted, and its kernel route";
                    }
                }
            }
            $network = $endpointAfter . '/32';
            $same = array_filter($core['routes'], fn (array $r): bool => $r['network'] === $network);
            if (count($same) > 1) {
                $e['wan'] = "several routes to {$network} exist; keep one on System > Routes first";
            } elseif (count($same) === 1) {
                $routeUuid = (string)array_key_first($same);
                $existing = $same[$routeUuid];
                if ($existing['enabled'] && $existing['gateway'] !== $wanAfter) {
                    $e['config'] = "{$network} is already routed via {$existing['gateway']}";
                } elseif ($existing['enabled']) {
                    $c[] = "static route {$network} via {$wanAfter} exists already; kept";
                } else {
                    $plan['routes']['update'][$routeUuid] = ['gateway' => $wanAfter, 'enabled' => '1'];
                    $c[] = "static route {$network}: enabled, via {$wanAfter}";
                }
            } else {
                $plan['routes']['add'][] = ['network' => $network, 'gateway' => $wanAfter, 'descr' => 'wireguard - ' . $t['name'], 'enabled' => '1'];
                $c[] = "static route {$network} via {$wanAfter}";
            }
            $need['tunnel'] = true;
        }
    }

    /* NAT sources (ruling 6): a ticked source adds one plain rule, an unticked one deletes its plain rules */
    $state = wgct_edit_nat_state($snap, $opt);
    $known = wgct_edit_nat_known($snap);
    $touched = ['inet' => false, 'inet6' => $v6Change !== 'none'];
    foreach (['inet' => 'nat4', 'inet6' => 'nat6'] as $family => $field) {
        $want = $req['nat'][$family];
        if ($want === null || ($family === 'inet6' && !$ipv6After)) {
            continue;
        }
        $unknown = array_values(array_diff($want, $known));
        if ($unknown !== []) {
            $e[$field] = 'not an interface or alias: ' . implode(', ', $unknown);
            continue;
        }
        $familyLabel = $family === 'inet' ? 'IPv4' : 'IPv6';
        foreach (array_values(array_diff($want, $state['sources'][$family])) as $source) {
            $plan['nat']['add'][] = [
                'enabled' => '1', 'ipprotocol' => $family, 'source_net' => $source, 'destination_net' => 'any',
                'target' => '', 'description' => "{$t['name']}: outbound NAT from {$source}",
            ];
            $c[] = "outbound NAT on {$opt} {$familyLabel} from {$source}: added";
            $touched[$family] = true;
        }
        foreach (array_values(array_diff($state['sources'][$family], $want)) as $source) {
            foreach ($state['rules'][$family][$source] as $ruleUuid) {
                $plan['nat']['delete'][] = $ruleUuid;
            }
            $c[] = "outbound NAT on {$opt} {$familyLabel} from {$source}: " . count($state['rules'][$family][$source]) . ' rule(s) deleted';
            $touched[$family] = true;
        }
    }
    if ($touched['inet'] || ($touched['inet6'] && $v6Change === 'none')) {
        $need['filter'] = true;
    }
    foreach (['inet' => 'IPv4', 'inet6' => 'IPv6'] as $family => $familyLabel) {
        $wanted = $family === 'inet' ? $t['gw4'] !== null : $ipv6After;
        if (!$wanted || !$touched[$family]) {
            continue;
        }
        $left = count(array_filter($plan['nat']['add'], fn (array $r): bool => $r['ipprotocol'] === $family));
        foreach ($snap['snat_rules'] as $ruleUuid => $r) {
            if ($r['enabled'] === '1' && in_array($opt, wgct_split_csv($r['interface']), true)
                && ($r['ipprotocol'] === $family || $r['ipprotocol'] === 'inet46')
                && !in_array((string)$ruleUuid, $plan['nat']['delete'], true)) {
                $left++;
            }
        }
        if ($left === 0) {
            $c[] = "WARNING nat-missing: no {$familyLabel} outbound NAT is left on {$opt}; the inner-source block drops everything a LAN sends into this tunnel";
        }
    }

    $plan['changes'] = $c;
    if ($e !== []) {
        $plan['errors'] = $e;
        return $plan;
    }
    $plan['mode'] = $need['tunnel'] ? 'tunnel' : ($need['routes'] ? 'routes' : ($need['filter'] ? 'filter' : 'none'));
    if ($plan['mode'] === 'none') {
        $plan['changes'] = [];
        return $plan;
    }
    if ($plan['mode'] === 'tunnel' && !$snap['wireguard_enabled']) {
        $c[] = 'WARNING WireGuard is disabled (VPN > WireGuard > Settings); the tunnel starts once it is enabled';
    }
    $c[] = match ($plan['mode']) {
        'filter' => 'apply: filter reload',
        'routes' => 'apply: interface routes configure (gateways and monitors; it ends with a filter reload)',
        default => "apply: the tunnel apply (as Create's), then wireguard restart, so {$label} handshakes again on its new path",
    };
    $plan['changes'] = $c;
    $plan['replay'] = array_values(array_filter(
        [$t['gw4'], $v6Change === 'on' ? $name6 : ($v6Change === 'off' ? null : $t['gw6'])],
        fn (?string $g): bool => $g !== null
    ));
    return $plan;
}

/**
 * The actions fixture plus the public key material Edit compares.
 * Documentation addresses and letter keys only.
 *
 * @return array the wgct_action_snapshot() shape
 */
function wgct_edit_fixture(): array {
    $snap = wgct_actions_fixture();
    $key = fn (string $c): string => base64_encode(str_repeat($c, 32));
    $snap['peer_fields'] = [
        'p-a' => ['tunneladdress' => '0.0.0.0/0,::/0', 'pubkey' => $key('P')],
        'p-b' => ['tunneladdress' => '0.0.0.0/0', 'pubkey' => $key('Q')],
        'p-d' => ['tunneladdress' => '0.0.0.0/0', 'pubkey' => $key('R')],
        'p-x' => ['tunneladdress' => '192.0.2.0/24', 'pubkey' => $key('S')],
    ];
    $snap['instance_pubkeys'] = ['i-a' => $key('E'), 'i-b' => $key('F'), 'i-d' => $key('G'), 'i-x' => $key('H')];
    return $snap;
}

/**
 * Self-tests for Edit. Pure.
 *
 * @return int exit code, 0 when every case passes
 */
function wgct_edit_selftest(): int {
    $t = ['fail' => 0, 'total' => 0];
    $snap = wgct_edit_fixture();
    $key = fn (string $c): string => base64_encode(str_repeat($c, 32));
    $has = fn (array $lines, string $needle): bool => array_filter($lines, fn (string $l): bool => str_contains($l, $needle)) !== [];
    $u = '00000000-0000-4000-8000-000000000001';
    $none = ['uuid' => 'i-a', 'wan' => null, 'monitor' => null, 'mtu' => null, 'ipv6' => null, 'unique' => null, 'nat' => ['inet' => null, 'inet6' => null]];
    $keepA = ['uuid' => 'i-a', 'wan' => 'WAN_A', 'monitor' => '203.0.113.9', 'mtu' => 1420, 'ipv6' => true, 'unique' => true,
              'nat' => ['inet' => ['opt3', 'TailscaleNetworks'], 'inet6' => ['opt3']]];
    $plan = fn (array $req, ?array $swap = null, ?array $s = null, array $refs = []): array => wgct_plan_edit($s ?? $snap, $refs, $req, $swap);
    /* tun_b's current config, with public overrides */
    $swapB = fn (array $over = [], ?string $own = null, bool $pskSame = true): array => [
        'public' => array_merge(['addresses' => ['inet' => ['10.2.0.2/32'], 'inet6' => []], 'peer_pubkey' => $key('Q'),
                                 'endpoint_ip' => '198.51.100.11', 'endpoint_port' => '51820', 'has_psk' => false], $over),
        'own_pubkey' => $own ?? $key('F'), 'psk_same' => $pskSame,
    ];
    $rule = fn (string $iface, string $family, string $source, string $not = '0'): array => [
        'interface' => $iface, 'ipprotocol' => $family, 'enabled' => '1', 'sequence' => '90',
        'fields' => ['enabled' => '1', 'ipprotocol' => $family, 'source_net' => $source, 'source_not' => $not,
                     'destination_net' => 'any', 'destination_not' => '0', 'target' => '', 'description' => ''],
    ];
    $emptyWrites = fn (array $p): bool => $p['instance'] === [] && $p['peer'] === [] && !$p['swap_keys']
        && $p['gateways'] === ['update' => [], 'add' => [], 'delete' => []]
        && $p['routes'] === ['add' => [], 'update' => [], 'delete' => []] && $p['nat'] === ['add' => [], 'delete' => []];

    /* ---- the request ---- */
    $r = wgct_edit_request(['config' => '', 'name' => 'ignored', 'wan' => 'WAN_A', 'monitor' => '203.0.113.9', 'mtu' => '1420',
                            'ipv6' => '1', 'unique' => '0', 'nat4' => 'opt3,TailscaleNetworks', 'nat6' => ''], $u);
    wgct_check($t, 'edit request: the API form (every field, strings) => typed; an empty NAT list is an empty list, not "keep"',
        $r['errors'] === [] && $r['text'] === ''
        && $r['req'] === ['uuid' => $u, 'wan' => 'WAN_A', 'monitor' => '203.0.113.9', 'mtu' => 1420, 'ipv6' => true, 'unique' => false,
                          'nat' => ['inet' => ['opt3', 'TailscaleNetworks'], 'inet6' => []]]);
    $r = wgct_edit_request(['monitor' => '203.0.113.20', 'wan' => ''], $u);
    wgct_check($t, 'edit request: absent keys, and an empty WAN, keep the current value (null)',
        $r['errors'] === [] && $r['req']['monitor'] === '203.0.113.20' && $r['req']['wan'] === null && $r['req']['mtu'] === null
        && $r['req']['ipv6'] === null && $r['req']['nat'] === ['inet' => null, 'inet6' => null]);
    $r = wgct_edit_request(['monitor' => '2001:db8::1', 'mtu' => '1500', 'ipv6' => 'yes', 'nat4' => 7, 'nat6' => ['opt3', 5]], $u);
    $keys = array_keys($r['errors']);
    sort($keys);
    wgct_check($t, 'edit request: an IPv6 monitor, an MTU out of range, a malformed flag and non-list NAT sources are field errors, never defaults',
        $keys === ['ipv6', 'monitor', 'mtu', 'nat4', 'nat6']);
    wgct_check($t, 'edit request: a uuid that is not one is refused',
        wgct_edit_request([], 'i-a')['errors'] === ['general' => 'not a tunnel uuid']);

    /* ---- NAT as Edit sees it ---- */
    $n = wgct_edit_nat_state($snap, 'opt11');
    wgct_check($t, 'edit NAT: plain rules by family; a source whose only rule is disabled is not ticked, but its rule is known',
        $n['sources'] === ['inet' => ['opt3', 'TailscaleNetworks'], 'inet6' => ['opt3']]
        && $n['rules']['inet'] === ['opt3' => ['s-a1'], 'TailscaleNetworks' => ['s-a2'], 'lan' => ['s-a4']] && $n['kept'] === []);
    $s = $snap;
    $s['snat_rules']['s-a5'] = $rule('opt11', 'inet46', 'opt3');
    $s['snat_rules']['s-a6'] = $rule('opt11,opt12', 'inet', 'lan');
    $s['snat_rules']['s-a7'] = $rule('opt11', 'inet', '192.0.2.0/24');
    $s['snat_rules']['s-a8'] = $rule('opt11', 'inet', 'opt3', '1');
    $n = wgct_edit_nat_state($s, 'opt11');
    wgct_check($t, 'edit NAT: both-family, multi-interface, network and negated rules are kept and listed, never ticked',
        count($n['kept']) === 4 && $n['sources']['inet'] === ['opt3', 'TailscaleNetworks'] && $n['rules']['inet']['opt3'] === ['s-a1']);

    /* ---- only differences ---- */
    $p = $plan($keepA);
    wgct_check($t, 'edit: every current value, or nothing given => nothing to change, nothing to write',
        $p['errors'] === [] && $p['mode'] === 'none' && $p['changes'] === [] && $emptyWrites($p) && $plan($none)['mode'] === 'none');

    /* ---- NAT ---- */
    $p = $plan(['nat' => ['inet' => ['opt3', 'TailscaleNetworks', 'lan'], 'inet6' => ['opt3']]] + $keepA);
    wgct_check($t, 'edit: ticking a source adds one plain rule (destination any, the interface address); the disabled lan rule stays; filter reload only',
        $p['errors'] === [] && $p['mode'] === 'filter' && $p['nat'] === ['add' => [[
            'enabled' => '1', 'ipprotocol' => 'inet', 'source_net' => 'lan', 'destination_net' => 'any', 'target' => '',
            'description' => 'tun_a: outbound NAT from lan',
        ]], 'delete' => []] && $has($p['changes'], 'apply: filter reload') && $p['gateways']['update'] === []);
    $p = $plan(['nat' => ['inet' => ['opt3'], 'inet6' => ['opt3']]] + $keepA);
    wgct_check($t, 'edit: unticking a source deletes every rule with it and that family (its !LocalNetworks destination too), and nothing else',
        $p['mode'] === 'filter' && $p['nat'] === ['add' => [], 'delete' => ['s-a2']]);
    $s = $snap;
    $s['snat_rules']['s-a5'] = $rule('opt11', 'inet46', 'opt3');
    $p = $plan(['nat' => ['inet' => ['TailscaleNetworks'], 'inet6' => ['opt3']]] + $keepA, null, $s);
    wgct_check($t, 'edit: unticking IPv4 opt3 leaves the IPv6 opt3 rule and the both-family rule alone',
        $p['errors'] === [] && $p['nat']['delete'] === ['s-a1']);
    $p = $plan(['nat' => ['inet' => [], 'inet6' => ['opt3']]] + $keepA);
    wgct_check($t, 'edit: the last IPv4 source unticked => both rules deleted, with a nat-missing warning',
        $p['nat']['delete'] === ['s-a1', 's-a2'] && $has($p['changes'], 'WARNING nat-missing: no IPv4'));
    $p = $plan(['nat' => ['inet' => ['opt3', 'bogus', 'wireguard'], 'inet6' => ['opt3']]] + $keepA);
    wgct_check($t, 'edit: an unknown source, or a virtual interface key, is refused on nat4',
        $p['errors'] === ['nat4' => 'not an interface or alias: bogus, wireguard']);

    /* ---- monitor ---- */
    $p = $plan(['monitor' => '203.0.113.20'] + $keepA);
    wgct_check($t, 'edit: a new monitor updates the IPv4 gateway alone; interface routes configure; both gateways replayed',
        $p['errors'] === [] && $p['mode'] === 'routes'
        && $p['gateways'] === ['update' => ['tun_a' => ['monitor' => '203.0.113.20']], 'add' => [], 'delete' => []]
        && $p['replay'] === ['tun_a', 'tun_a-ipv6'] && $has($p['changes'], 'gateway tun_a: monitor 203.0.113.9 -> 203.0.113.20')
        && $p['kernel_routes'] === ['g-a4' => '203.0.113.9/32'] && $p['routes']['delete'] === []);
    foreach ([
        ['another gateway\'s monitor', '203.0.113.10'],
        ['a DNS server', '203.0.113.53'],
        ['a WireGuard endpoint', '198.51.100.11'],
        ['another gateway\'s address', '10.2.0.5'],
    ] as [$desc, $ip]) {
        wgct_check($t, "edit: a monitor that is {$desc} => refused on monitor", isset($plan(['monitor' => $ip] + $keepA)['errors']['monitor']));
    }
    $p = $plan(['monitor' => '203.0.113.20', 'nat' => ['inet' => ['opt3'], 'inet6' => ['opt3']]] + $keepA);
    wgct_check($t, 'edit: monitor and NAT together => interface routes configure alone (it ends with a filter reload)',
        $p['mode'] === 'routes' && $p['nat']['delete'] === ['s-a2']);

    /* ---- MTU ---- */
    $p = $plan(['mtu' => 1400] + $keepA);
    wgct_check($t, 'edit: a new MTU writes the instance MTU; the tunnel apply with its restart',
        $p['instance'] === ['mtu' => '1400'] && $p['mode'] === 'tunnel' && $has($p['changes'], 'apply: the tunnel apply'));
    $s = $snap;
    $s['core']['interfaces']['opt11']['mtu'] = '1300';
    $p = $plan(['mtu' => 1400] + $keepA, null, $s);
    wgct_check($t, 'edit: an MTU the interface overrides => written, and the preview says the mtu-override finding stays',
        $p['instance'] === ['mtu' => '1400'] && $has($p['changes'], 'NOTE mtu-override: interface opt11 sets its own MTU 1300'));

    /* ---- bound WAN ---- */
    $p = $plan(['wan' => 'WAN_B'] + $keepA);
    wgct_check($t, 'edit: a new WAN re-points the endpoint route, deletes nothing, and restarts the tunnel',
        $p['routes'] === ['add' => [], 'update' => ['r-a' => ['gateway' => 'WAN_B']], 'delete' => []] && $p['mode'] === 'tunnel'
        && $has($p['changes'], 'static route 198.51.100.10/32: via WAN_A -> WAN_B'));
    foreach ([['a WireGuard gateway', 'tun_b'], ['a sentinel', 'NO_DEFAULT4'], ['no gateway', 'NOPE']] as [$desc, $wan]) {
        wgct_check($t, "edit: a WAN that is {$desc} => refused on wan", isset($plan(['wan' => $wan] + $keepA)['errors']['wan']));
    }
    $s = $snap;
    $s['core']['peers']['p-a']['serveraddress'] = '198.51.100.20';
    $p1 = $plan(['wan' => 'WAN_B'] + $none, null, $s);
    $p2 = $plan(['monitor' => '203.0.113.20'] + $none, null, $s);
    wgct_check($t, 'edit: an unbound tunnel keeps Rebind for its WAN, and is otherwise editable',
        str_contains($p1['errors']['wan'] ?? '', 'Rebind') && $p2['errors'] === [] && $p2['mode'] === 'routes');
    $s = $snap;
    $s['core']['peers']['p-x']['serveraddress'] = '198.51.100.10';
    $p = $plan(['wan' => 'WAN_B'] + $keepA, null, $s);
    wgct_check($t, 'edit: a WAN move of an endpoint another instance\'s peer also uses => refused on wan, naming it; nothing written',
        str_contains($p['errors']['wan'] ?? '', 'site_x') && $emptyWrites($p));

    /* ---- IPv6 ---- */
    $p = $plan(['ipv6' => false] + $keepA);
    wgct_check($t, 'edit: IPv6 off deletes the IPv6 gateway, the IPv6 tunnel address, ::/0 from the peer and the IPv6 NAT rules',
        $p['errors'] === [] && $p['mode'] === 'tunnel' && $p['gateways']['delete'] === ['g-a6']
        && $p['instance'] === ['tunneladdress' => '10.2.0.2/32'] && $p['peer'] === ['tunneladdress' => '0.0.0.0/0']
        && $p['nat'] === ['add' => [], 'delete' => ['s-a3']] && $p['replay'] === ['tun_a']);
    $refs = [['id' => 'group:g6', 'what' => 'gateway group g6', 'gateways' => ['tun_a-ipv6'], 'interfaces' => []]];
    $p = $plan(['ipv6' => false] + $keepA, null, null, $refs);
    wgct_check($t, 'edit: IPv6 off while a group lists the IPv6 gateway => refused, naming it',
        str_contains($p['errors']['ipv6'] ?? '', 'gateway group g6 uses gateway tun_a-ipv6'));
    wgct_check($t, 'edit: IPv6 on without a replacement config => refused on ipv6',
        isset($plan(['uuid' => 'i-b', 'ipv6' => true] + $none)['errors']['ipv6']));
    $p = $plan(['uuid' => 'i-b', 'ipv6' => true, 'nat' => ['inet' => null, 'inet6' => ['opt3']]] + $none,
        $swapB(['addresses' => ['inet' => ['10.2.0.2/32'], 'inet6' => ['2001:db8::2:2/128']]]));
    $g6 = $p['gateways']['add'][0] ?? [];
    wgct_check($t, 'edit: IPv6 on with a config that has an IPv6 address => fd00::2:1 (the site convention), a forced-down tun_b-ipv6 at fd00::2:2, ::/0, the IPv6 NAT; keys and route untouched',
        $p['errors'] === [] && $p['mode'] === 'tunnel' && $p['instance'] === ['tunneladdress' => '10.2.0.2/32,fd00::2:1/128']
        && $p['peer'] === ['tunneladdress' => '0.0.0.0/0,::/0'] && ($g6['name'] ?? '') === 'tun_b-ipv6' && ($g6['gateway'] ?? '') === 'fd00::2:2'
        && ($g6['force_down'] ?? '') === '1' && ($g6['interface'] ?? '') === 'opt12' && count($p['nat']['add']) === 1
        && $p['nat']['add'][0]['ipprotocol'] === 'inet6' && $p['swap_keys'] === false
        && $p['routes'] === ['add' => [], 'update' => [], 'delete' => []] && $p['replay'] === ['tun_b', 'tun_b-ipv6']);

    /* ---- server swap ---- */
    $p = $plan(['uuid' => 'i-b'] + $none, $swapB(['peer_pubkey' => $key('L'), 'has_psk' => true], $key('K'), false));
    wgct_check($t, 'edit: a new config for the same server replaces the keys only; no route change; no private key in the plan',
        $p['errors'] === [] && $p['swap_keys'] === true && $p['instance'] === ['pubkey' => $key('K')] && $p['peer'] === ['pubkey' => $key('L')]
        && $p['routes'] === ['add' => [], 'update' => [], 'delete' => []] && $p['mode'] === 'tunnel'
        && !isset($p['instance']['privkey']) && !isset($p['peer']['psk']));
    $p = $plan(['uuid' => 'i-b', 'wan' => 'WAN_A'] + $none, $swapB(['endpoint_ip' => '198.51.100.40']));
    wgct_check($t, 'edit: a new endpoint deletes the old endpoint route (with its kernel route) and routes the new one via the chosen WAN',
        $p['errors'] === [] && $p['routes'] === [
            'add' => [['network' => '198.51.100.40/32', 'gateway' => 'WAN_A', 'descr' => 'wireguard - tun_b', 'enabled' => '1']],
            'update' => [], 'delete' => ['r-b' => '198.51.100.11/32'],
        ] && $p['peer'] === ['serveraddress' => '198.51.100.40', 'serverport' => '51820'] && $p['mode'] === 'tunnel' && $p['swap_keys'] === false);
    $s = $snap;
    $s['core']['peers']['p-x']['serveraddress'] = '198.51.100.11';
    $p = $plan(['uuid' => 'i-b'] + $none, $swapB(['endpoint_ip' => '198.51.100.40']), $s);
    wgct_check($t, 'edit: another instance\'s peer still uses the old endpoint => its route is kept',
        $p['errors'] === [] && $p['routes']['delete'] === [] && $has($p['changes'], 'KEEP static route 198.51.100.11/32'));
    $p = $plan(['uuid' => 'i-b', 'wan' => 'WAN_B'] + $none, $swapB(['endpoint_ip' => '198.51.100.10']));
    wgct_check($t, 'edit: a new endpoint another managed tunnel uses (routed via another WAN) => refused on config, naming that tunnel; no route planned',
        str_contains($p['errors']['config'] ?? '', 'already the endpoint of tun_a')
        && $p['routes'] === ['add' => [], 'update' => [], 'delete' => []]);
    $s = $snap;
    $s['core']['peers']['p-x']['serveraddress'] = '198.51.100.50';
    $p = $plan(['uuid' => 'i-b', 'wan' => 'WAN_A'] + $none, $swapB(['endpoint_ip' => '198.51.100.50']), $s);
    wgct_check($t, 'edit: a new endpoint an unmanaged instance\'s peer uses => refused on config, naming it',
        str_contains($p['errors']['config'] ?? '', 'site_x'));
    $p = $plan(['uuid' => 'i-b'] + $none, $swapB());
    wgct_check($t, 'edit: an identical config (same keys, preshared key, endpoint, addresses) => nothing to change',
        $p['errors'] === [] && $p['mode'] === 'none' && $p['changes'] === [] && $emptyWrites($p));
    $swapA = ['public' => ['addresses' => ['inet' => ['10.2.0.2/32'], 'inet6' => []], 'peer_pubkey' => $key('P'),
                           'endpoint_ip' => '198.51.100.10', 'endpoint_port' => '51820', 'has_psk' => false],
              'own_pubkey' => $key('E'), 'psk_same' => true];
    $p1 = $plan($none, $swapA);
    $p2 = $plan(['ipv6' => false] + $none, $swapA);
    wgct_check($t, 'edit: a config without IPv6 on a tunnel with IPv6 => refused, unless the same edit turns IPv6 off',
        str_contains($p1['errors']['ipv6'] ?? '', 'no IPv6 Address') && $p2['errors'] === [] && $p2['gateways']['delete'] === ['g-a6']);

    /* ---- blocking findings, managed list ---- */
    $s = $snap;
    $s['core']['gateways']['tun_a2'] = ['uuid' => 'g-a9', 'interface' => 'opt11', 'ipprotocol' => 'inet', 'gateway' => '10.2.0.250',
                                       'monitor' => '', 'disabled' => true, 'force_down' => false, 'losshigh' => '', 'losslow' => '', 'time_period' => ''];
    wgct_check($t, 'edit: a blocking finding (ambiguous-gateway) refuses any change',
        str_contains($plan(['mtu' => 1400] + $keepA, null, $s)['errors']['general'] ?? '', 'ambiguous-gateway'));
    $s = $snap;
    $s['core']['peers']['p-b']['serveraddress'] = 'vpn.example.net';
    $p1 = $plan(['uuid' => 'i-b', 'mtu' => 1400] + $none, null, $s);
    $p2 = $plan(['uuid' => 'i-b', 'wan' => 'WAN_B'] + $none, $swapB(['endpoint_ip' => '198.51.100.40']), $s);
    $p3 = $plan(['uuid' => 'i-b'] + $none, $swapB(['endpoint_ip' => '198.51.100.40']), $s);
    wgct_check($t, 'edit: endpoint-unsupported refuses an MTU edit, but a swap to an IPv4 endpoint with a WAN resolves it (without a WAN: refused)',
        isset($p1['errors']['general']) && $p2['errors'] === [] && ($p2['routes']['add'][0]['network'] ?? '') === '198.51.100.40/32'
        && $p2['routes']['delete'] === [] && isset($p3['errors']['wan']));
    wgct_check($t, 'edit: an unmanaged instance => refused',
        $plan(['uuid' => 'i-x'] + $none)['errors'] === ['general' => 'not a managed tunnel']);

    /* ---- prefill ---- */
    $f = wgct_edit_prefill($snap, 'i-a');
    wgct_check($t, 'edit prefill: the current WAN, monitor, instance MTU, IPv6 with fd00::N:1, the ticked NAT sources and the convention',
        $f['errors'] === [] && $f['form']['wan'] === 'WAN_A' && $f['form']['monitor'] === '203.0.113.9' && $f['form']['mtu'] === 1420
        && $f['form']['ipv6'] === true && $f['form']['unique'] === true && $f['form']['nat4'] === ['opt3', 'TailscaleNetworks']
        && $f['form']['nat6'] === ['opt3'] && $f['form']['nat_kept'] === [] && $f['form']['endpoint_ip'] === '198.51.100.10'
        && $f['form']['ipv6_others'] === [] && $f['form']['unique_convention'] === true);
    $f = wgct_edit_prefill($snap, 'i-b');
    wgct_check($t, 'edit prefill: an IPv4-only tunnel lists the other instances\' IPv6 addresses; an unmanaged one is refused',
        $f['form']['ipv6'] === false && $f['form']['unique'] === false && $f['form']['ipv6_others'] === ['fd00::1:1']
        && wgct_edit_prefill($snap, 'i-x')['errors'] === ['not a managed tunnel']);

    return wgct_tally_report('edit', $t);
}
