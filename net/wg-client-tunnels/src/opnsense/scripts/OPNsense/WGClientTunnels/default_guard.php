#!/usr/local/bin/php
<?php

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
 *
 * Default-route guard: a gateway that is not flagged "default gateway" (a
 * WireGuard tunnel, a VPN gateway on another device, anything
 * priority-ordered but not a native WAN) must never carry the firewall's
 * default route, for either family.
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
 * Positive match only: the default route is removed only when its next hop
 * (address and interface) belongs to configured non-default gateways alone. A
 * default through anything unrecognised, or through a next hop a default
 * gateway shares, is left alone, so this can never remove a native WAN default
 * it merely failed to recognise.
 *
 * Runs from wgct.sh reconcile: queued by the plugin's monitor, newwanip and
 * bootup hooks (wgct.sh hook) and by the config-save syshook
 * (rc.syshook.d/config/50-wgclienttunnels), and run by the once-a-minute
 * cron. So it runs beside core's routing work, never inside it: the delete
 * names the gateway it judged (guard_delete_command()), so a default route
 * core replaced in between is left in place.
 *
 * The plugin/enable and default_guard switches gate only the route delete:
 * both families are classified either way, so wg_ipv6_default_check.sh (which
 * greps FORBIDDEN out of `--dry`) keeps alarming on a forbidden default even
 * while the guard is switched off. With the guard off, --dry says so up
 * front, and a forbidden default that would otherwise be removed is instead
 * left in place and logged.
 *
 * Usage: default_guard.php [--dry] [--selftest]
 */

require "/usr/local/opnsense/mvc/script/load_phalcon.php";
if (!is_readable(__DIR__ . '/entry.php')) {
    exit(0);
}
require_once __DIR__ . '/entry.php';
wgct_entry_load('default_guard.php', 'wgct-guard', ['tunnels.php']);

const GUARD_TAG = 'wgct-guard';

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
 * never be the default. A route names a next hop (address and interface), not
 * a gateway, and several gateways may share one -- a second gateway on a WAN's
 * own address, say. The route is forbidden only when every gateway on that next
 * hop is a non-default one: a default gateway among them owns it.
 *
 * @param array  $gateways getGateways() rows
 * @param string $family   inet|inet6
 * @param string $routeGw  route's gateway address
 * @param string $routeIf  route's interface
 * @return string|null name of the first non-default gateway on that next hop,
 *                     or null when the route is allowed
 */
function guard_forbidden_match(array $gateways, $family, $routeGw, $routeIf) {
    $want = guard_norm_addr($routeGw);
    if ($want === '') {
        return null;
    }
    $forbidden = null;
    foreach ($gateways as $gw) {
        if (($gw['ipprotocol'] ?? '') !== $family || !empty($gw['is_loopback'])) {
            continue;
        }
        if (($gw['if'] ?? '') !== $routeIf || guard_norm_addr($gw['gateway'] ?? '') !== $want) {
            continue;
        }
        if (!empty($gw['defaultgw'])) {
            return null;
        }
        $forbidden = $forbidden ?? (string)$gw['name'];
    }
    return $forbidden;
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

/**
 * The delete of a family's default route, naming the gateway the guard judged: the kernel refuses to delete a
 * default route whose gateway is another, so one that core replaced after guard_default_route() read it stays.
 *
 * @param string $family  inet|inet6
 * @param string $gateway the route's gateway as guard_default_route() read it
 * @return string the route(8) command
 */
function guard_delete_command(string $family, string $gateway): string {
    return sprintf('/sbin/route -q -n delete -%s default %s', $family, escapeshellarg($gateway));
}

/**
 * What a failed named delete logs, from the default route read again: gone (another guard run removed it), leaving
 * by another next hop (core replaced it, so it stays), or unchanged (route(8) refused it all the same). Pure.
 *
 * @param string     $family inet|inet6
 * @param array      $judged the route the delete named: ['gateway' => string, 'interface' => string]
 * @param array|null $now    guard_default_route() read again, null when there is none
 * @return string the log line
 */
function guard_delete_failed_message(string $family, array $judged, ?array $now): string {
    if ($now === null) {
        return sprintf('[%s] %s default route via %s on %s was already removed', GUARD_TAG, $family,
            $judged['gateway'], $judged['interface']);
    }
    if ($now['gateway'] !== $judged['gateway'] || $now['interface'] !== $judged['interface']) {
        return sprintf('[%s] %s default route changed before it could be removed: it was via %s on %s,'
            . ' now via %s on %s; left in place', GUARD_TAG, $family, $judged['gateway'], $judged['interface'],
            $now['gateway'], $now['interface']);
    }
    return sprintf('[%s] %s default route via %s on %s could not be removed; left in place', GUARD_TAG, $family,
        $judged['gateway'], $judged['interface']);
}

if (in_array('--selftest', $argv ?? [], true)) {
    $gws = [
        ['name' => 'WAN_A6', 'ipprotocol' => 'inet6', 'gateway' => 'fe80::1', 'if' => 'igc1', 'defaultgw' => true],
        ['name' => 'wg-A-ipv6', 'ipprotocol' => 'inet6', 'gateway' => 'fd00::5:2', 'if' => 'wg5', 'defaultgw' => false],
        ['name' => 'wg-A', 'ipprotocol' => 'inet', 'gateway' => '10.2.0.8', 'if' => 'wg5', 'defaultgw' => false],
        ['name' => 'WAN_B', 'ipprotocol' => 'inet', 'gateway' => '198.51.100.1', 'if' => 'igc2', 'defaultgw' => true],
        ['name' => 'NO_DEFAULT6', 'ipprotocol' => 'inet6', 'if' => 'lo1', 'defaultgw' => false],
        ['name' => 'loopback', 'ipprotocol' => 'inet6', 'gateway' => '::1', 'if' => 'lo0', 'is_loopback' => true],
    ];
    $cases = [
        // description, family, route gw, route if, expected match
        ['tunnel IPv6 default => match',        'inet6', 'fd00::5:2',        'wg5',  'wg-A-ipv6'],
        ['tunnel IPv6, expanded form => match', 'inet6', 'fd00:0:0:0:0:0:5:2', 'wg5', 'wg-A-ipv6'],
        ['tunnel IPv4 default => match',        'inet',  '10.2.0.8',         'wg5',  'wg-A'],
        ['native IPv6 link-local => keep',      'inet6', 'fe80::1%igc1',     'igc1', null],
        ['native IPv4 => keep',                 'inet',  '198.51.100.1',     'igc2', null],
        ['tunnel address, other if => keep',    'inet6', 'fd00::5:2',        'wg4',  null],
        ['unknown gateway => keep',             'inet',  '203.0.113.1',      'igc1', null],
        ['not an address => keep',              'inet',  'link#5',           'lo0',  null],
        ['loopback reject route => keep',       'inet6', '::1',              'lo0',  null],
    ];
    /* two gateways on one next hop (a second gateway on the WAN's own address and interface): a default gateway
     * among them makes the route allowed, whatever the order */
    $nonDefault = ['name' => 'WAN_B', 'ipprotocol' => 'inet', 'gateway' => '192.0.2.1', 'if' => 'hn1', 'defaultgw' => false];
    $default = ['name' => 'WAN_DHCP', 'ipprotocol' => 'inet', 'gateway' => '192.0.2.1', 'if' => 'hn1', 'defaultgw' => true];
    $other = ['name' => 'WAN_C', 'ipprotocol' => 'inet', 'gateway' => '192.0.2.1', 'if' => 'hn1', 'defaultgw' => false];
    $shared = [
        // description, gateways, expected match
        ['shared next hop, non-default listed first => keep', [$nonDefault, $default], null],
        ['shared next hop, default listed first => keep',     [$default, $nonDefault], null],
        ['shared next hop, only non-default gateways => match the first', [$nonDefault, $other], 'WAN_B'],
        ['same address, default on another interface => match', [$nonDefault, ['if' => 'hn2'] + $default], 'WAN_B'],
        ['same address, default in the other family => match',
            [$nonDefault, ['ipprotocol' => 'inet6'] + $default], 'WAN_B'],
    ];
    $fail = 0;
    foreach ($cases as [$desc, $fam, $rgw, $rif, $exp]) {
        $got = guard_forbidden_match($gws, $fam, $rgw, $rif);
        $fail += $got === $exp ? 0 : 1;
        printf("[%s] %s\n", $got === $exp ? 'PASS' : 'FAIL', $desc);
    }
    foreach ($shared as [$desc, $sgws, $exp]) {
        $got = guard_forbidden_match($sgws, 'inet', '192.0.2.1', 'hn1');
        $fail += $got === $exp ? 0 : 1;
        printf("[%s] %s\n", $got === $exp ? 'PASS' : 'FAIL', $desc);
    }
    $ok = guard_delete_command('inet6', 'fe80::1%igc1') === "/sbin/route -q -n delete -inet6 default 'fe80::1%igc1'";
    $fail += $ok ? 0 : 1;
    printf("[%s] guard: the delete names the judged gateway\n", $ok ? 'PASS' : 'FAIL');
    $judged = ['gateway' => 'fd00::5:2', 'interface' => 'wg5'];
    $failed = [
        // description, the route read again, expected message
        ['guard: a failed delete whose route is gone says it was already removed', null,
            '[wgct-guard] inet6 default route via fd00::5:2 on wg5 was already removed'],
        ['guard: a failed delete whose route now leaves by another gateway names both and leaves it',
            ['gateway' => 'fe80::1%igc1', 'interface' => 'igc1'],
            '[wgct-guard] inet6 default route changed before it could be removed: it was via fd00::5:2 on wg5,'
            . ' now via fe80::1%igc1 on igc1; left in place'],
        ['guard: a failed delete whose route is unchanged says it could not be removed', $judged,
            '[wgct-guard] inet6 default route via fd00::5:2 on wg5 could not be removed; left in place'],
    ];
    foreach ($failed as [$desc, $now, $exp]) {
        $got = guard_delete_failed_message('inet6', $judged, $now);
        $fail += $got === $exp ? 0 : 1;
        printf("[%s] %s\n", $got === $exp ? 'PASS' : 'FAIL', $desc);
        if ($got !== $exp) {
            printf("       got %s\n", $got);
        }
    }
    $total = count($cases) + count($shared) + 1 + count($failed);
    printf("%d/%d passed\n", $total - $fail, $total);
    exit($fail === 0 ? 0 : 1);
}

$dry = in_array('--dry', $argv ?? [], true);
$mdl = new OPNsense\WGClientTunnels\WGClientTunnels();
$guardOn = $mdl->enabled->isEqual('1') && $mdl->default_guard->isEqual('1');

/*
 * The switch never skips classification: it only decides whether a forbidden
 * default gets removed. That way --dry (and the Monit check that greps
 * FORBIDDEN out of it) keeps reporting the truth even while the guard itself
 * is off.
 */
if ($dry && !$guardOn) {
    echo "default-route guard is off in the plugin settings: forbidden defaults are reported, not removed\n";
}

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
    if ($name === null) {
        continue;
    }
    if (!$guardOn) {
        wgct_log(LOG_WARNING, sprintf(
            '[%s] %s default route via %s on %s: %s is not a default gateway, left in place because the guard is off',
            GUARD_TAG,
            $family,
            $route['gateway'],
            $route['interface'],
            $name
        ));
        continue;
    }
    $output = [];
    exec(guard_delete_command($family, $route['gateway']), $output, $rc);
    if ($rc !== 0) {
        $now = guard_default_route($family);
        /* unchanged and still there: a forbidden default stays, which is worth more than a notice */
        $unchanged = $now !== null && $now['gateway'] === $route['gateway']
            && $now['interface'] === $route['interface'];
        wgct_log($unchanged ? LOG_WARNING : LOG_NOTICE, guard_delete_failed_message($family, $route, $now));
        continue;
    }
    wgct_log(LOG_WARNING, sprintf(
        '[%s] removed %s default route via %s on %s: %s is not a default gateway',
        GUARD_TAG,
        $family,
        $route['gateway'],
        $route['interface'],
        $name
    ));
}
