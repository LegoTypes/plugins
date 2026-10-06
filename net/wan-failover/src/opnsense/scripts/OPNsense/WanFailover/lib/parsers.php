<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Pure parsers for the live snapshot: ifconfig, route get, kern.boot_id, UUID resolution.
 */

require_once __DIR__ . '/pfstate.php';

/**
 * Only an explicit "status: no carrier" is carrier loss: wg, pppoe and similar interfaces print no
 * status line at all.
 *
 * @return array{carrier: bool, has_ipv4: bool}
 */
function wf_parse_ifconfig(string $out): array
{
    return ['carrier' => $out !== '' && preg_match('/^\s+status: no carrier/m', $out) !== 1,
            'has_ipv4' => preg_match('/^\s+inet \d+\.\d+\.\d+\.\d+/m', $out) === 1];
}

/**
 * @return array{destination: ?string, gateway: ?string, interface: ?string}
 */
function wf_parse_route_get(string $out): array
{
    return ['destination' => preg_match('/^\s*destination:\s*(\S+)/m', $out, $d) === 1 ? $d[1] : null,
            'gateway' => preg_match('/^\s*gateway:\s*(\S+)/m', $out, $g) === 1 ? $g[1] : null,
            'interface' => preg_match('/^\s*interface:\s*(\S+)/m', $out, $i) === 1 ? $i[1] : null];
}

/**
 * @param array{destination: ?string, gateway: ?string, interface: ?string} $route wf_parse_route_get()
 */
function wf_route_get_target(array $route): ?string
{
    return $route['gateway'] === null || $route['interface'] === null ? null : wf_route_target($route['gateway'], $route['interface']);
}

/**
 * kern.boot_id is a random value drawn at each boot. Unlike kern.boottime (wall clock minus uptime), it
 * does not move when the clock is stepped, so it tells a reboot from a clock adjustment.
 */
function wf_parse_boot_id(string $out): string
{
    return preg_match('/Dump:0x([0-9a-f]+)/', $out, $m) === 1 ? $m[1] : '';
}

/**
 * `ps -o pid= -o etimes=`: seconds since each process started. Monotonic, unlike a file's mtime against
 * time(), so a clock step does not make a young dpinger window look settled.
 *
 * @return array<int, int> pid => elapsed seconds
 */
function wf_parse_ps_etimes(string $out): array
{
    $ages = [];
    foreach (preg_split('/\R/', trim($out)) ?: [] as $line) {
        if (preg_match('/^\s*(\d+)\s+(\d+)\s*$/', $line, $m) === 1) {
            $ages[(int)$m[1]] = (int)$m[2];
        }
    }
    return $ages;
}

/**
 * Each managed WAN's place in core's gateway order (Gateways::getGateways(): upstream flag, then
 * priority, then sequence), which is the order core picks the default gateway in.
 *
 * @param list<string> $coreOrder every gateway name, in core's order
 * @param list<string> $wans the managed WANs
 * @return array<string, int>
 */
function wf_core_rank(array $coreOrder, array $wans): array
{
    $managed = array_values(array_filter($coreOrder, fn (string $n): bool => in_array($n, $wans, true)));
    $rank = [];
    foreach ($wans as $n) {
        $i = array_search($n, $managed, true);
        $rank[$n] = $i === false ? count($managed) : $i;
    }
    return $rank;
}

/**
 * @param list<string> $uuids
 * @param array<string, string> $nameByUuid
 * @return array{names: list<string>, unresolved: list<string>}
 */
function wf_resolve_uuids(array $uuids, array $nameByUuid): array
{
    $names = [];
    $unresolved = [];
    foreach ($uuids as $u) {
        if ($u === '') {
            continue;
        }
        if (isset($nameByUuid[$u])) {
            $names[] = $nameByUuid[$u];
        } else {
            $unresolved[] = $u;
        }
    }
    return ['names' => $names, 'unresolved' => $unresolved];
}
