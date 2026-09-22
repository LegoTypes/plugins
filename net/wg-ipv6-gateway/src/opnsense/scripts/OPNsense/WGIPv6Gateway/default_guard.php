#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Default-route guard: a gateway that is not flagged "default gateway" (a
 * WireGuard tunnel, the unifi VPN, anything priority-ordered but not a native
 * WAN) must never carry the firewall's default route, for either family.
 *
 * OPNsense has no per-gateway "never default" setting: getDefaultGW() returns
 * the first eligible gateway in priority order, and defaultgw=0 only sorts. The
 * sentinel gateways (NO_DEFAULT4 / NO_DEFAULT6, address-less, priority 254)
 * stop such a gateway being *installed* -- system_routing_configure() installs
 * nothing when the winner has no address. This guard is the second layer: it
 * removes one that is present anyway (installed before the sentinel existed,
 * or by any path that bypasses the election), because system_routing_configure()
 * never deletes a stale default on its own.
 *
 * Positive match only: the default route is removed only when its gateway is
 * identified as a configured non-default gateway on that interface. A default
 * through anything unrecognised is left alone, so this can never remove a
 * native WAN default it merely failed to recognise.
 *
 * Runs from wgipv6gw.sh reconcile: the plugin's "monitor" hook (end of every
 * routing reconfigure) and the once-a-minute cron.
 *
 * Usage: default_guard.php [--dry] [--selftest]
 */

require "/usr/local/opnsense/mvc/script/load_phalcon.php";

const GUARD_TAG = 'wgipv6gw-guard';

/**
 * Canonical form of an address for comparison: scope id dropped, IPv6
 * compressed. Returns '' for anything that is not an address.
 */
function guard_norm_addr($addr) {
    $addr = explode('%', trim((string)$addr))[0];
    $bin = @inet_pton($addr);
    return $bin === false ? '' : inet_ntop($bin);
}

/**
 * The configured gateway a default route points at, if it is one that must
 * never be the default.
 *
 * @param array  $gateways getGateways() rows
 * @param string $family   inet|inet6
 * @param string $routeGw  route's gateway address
 * @param string $routeIf  route's interface
 * @return string|null gateway name, or null when it is not a forbidden gateway
 */
function guard_forbidden_match(array $gateways, $family, $routeGw, $routeIf) {
    $want = guard_norm_addr($routeGw);
    if ($want === '') {
        return null;
    }
    foreach ($gateways as $gw) {
        if (($gw['ipprotocol'] ?? '') !== $family || !empty($gw['is_loopback']) || !empty($gw['defaultgw'])) {
            continue;
        }
        if (($gw['if'] ?? '') === $routeIf && guard_norm_addr($gw['gateway'] ?? '') === $want) {
            return (string)$gw['name'];
        }
    }
    return null;
}

/**
 * Current default route for a family.
 *
 * @return array|null ['gateway' => string, 'interface' => string], null if none
 */
function guard_default_route($family) {
    $out = shell_exec(sprintf('/sbin/route -n get -%s default 2>/dev/null', $family === 'inet6' ? 'inet6' : 'inet'));
    if (!is_string($out) || !preg_match('/^\s*gateway:\s*(\S+)/m', $out, $g) || !preg_match('/^\s*interface:\s*(\S+)/m', $out, $i)) {
        return null;
    }
    return ['gateway' => $g[1], 'interface' => $i[1]];
}

if (in_array('--selftest', $argv ?? [], true)) {
    $gws = [
        ['name' => 'PRIMARY_WAN_DHCP6', 'ipprotocol' => 'inet6', 'gateway' => 'fe80::1', 'if' => 'igc1', 'defaultgw' => true],
        ['name' => 'wg-A-ipv6', 'ipprotocol' => 'inet6', 'gateway' => 'fd00::5:2', 'if' => 'wg5', 'defaultgw' => false],
        ['name' => 'wg-A', 'ipprotocol' => 'inet', 'gateway' => '10.2.0.8', 'if' => 'wg5', 'defaultgw' => false],
        ['name' => 'WAN2', 'ipprotocol' => 'inet', 'gateway' => '192.168.12.1', 'if' => 'igc2', 'defaultgw' => true],
        ['name' => 'NO_DEFAULT6', 'ipprotocol' => 'inet6', 'if' => 'lo1', 'defaultgw' => false],
        ['name' => 'loopback', 'ipprotocol' => 'inet6', 'gateway' => '::1', 'if' => 'lo0', 'is_loopback' => true],
    ];
    $cases = [
        // description, family, route gw, route if, expected match
        ['tunnel IPv6 default => match',        'inet6', 'fd00::5:2',        'wg5',  'wg-A-ipv6'],
        ['tunnel IPv6, expanded form => match', 'inet6', 'fd00:0:0:0:0:0:5:2', 'wg5', 'wg-A-ipv6'],
        ['tunnel IPv4 default => match',        'inet',  '10.2.0.8',         'wg5',  'wg-A'],
        ['native IPv6 link-local => keep',      'inet6', 'fe80::1%igc1',     'igc1', null],
        ['native IPv4 => keep',                 'inet',  '192.168.12.1',     'igc2', null],
        ['tunnel address, other if => keep',    'inet6', 'fd00::5:2',        'wg4',  null],
        ['unknown gateway => keep',             'inet',  '203.0.113.1',      'igc1', null],
        ['not an address => keep',              'inet',  'link#5',           'lo0',  null],
        ['loopback reject route => keep',       'inet6', '::1',              'lo0',  null],
    ];
    $fail = 0;
    foreach ($cases as [$desc, $fam, $rgw, $rif, $exp]) {
        $got = guard_forbidden_match($gws, $fam, $rgw, $rif);
        $fail += $got === $exp ? 0 : 1;
        printf("[%s] %s\n", $got === $exp ? 'PASS' : 'FAIL', $desc);
    }
    printf("%d/%d passed\n", count($cases) - $fail, count($cases));
    exit($fail === 0 ? 0 : 1);
}

$dry = in_array('--dry', $argv ?? [], true);
$gateways = array_values((new OPNsense\Routing\Gateways())->getGateways());

foreach (['inet', 'inet6'] as $family) {
    $route = guard_default_route($family);
    if ($route === null) {
        if ($dry) {
            printf("%-5s no default route\n", $family);
        }
        continue;
    }
    $name = guard_forbidden_match($gateways, $family, $route['gateway'], $route['interface']);
    if ($dry) {
        printf(
            "%-5s default via %s on %s: %s\n",
            $family,
            $route['gateway'],
            $route['interface'],
            $name === null ? 'allowed' : "FORBIDDEN ({$name}), would remove"
        );
        continue;
    }
    if ($name !== null) {
        exec(sprintf('/sbin/route -q -n delete -%s default', $family === 'inet6' ? 'inet6' : 'inet'));
        syslog(LOG_WARNING, sprintf(
            '[%s] removed %s default route via %s on %s: %s is not a default gateway',
            GUARD_TAG,
            $family,
            $route['gateway'],
            $route['interface'],
            $name
        ));
    }
}
