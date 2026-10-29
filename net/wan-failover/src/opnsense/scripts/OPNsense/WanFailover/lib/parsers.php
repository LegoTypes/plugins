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
 * Pure parsers for the live snapshot: ifconfig, route get, kern.boot_id, UUID and hold record resolution.
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/pfstate.php';

/** A gateway name as core's model accepts it: safe in a pid or socket path and in a command argument. */
function wf_name_ok(string $name): bool
{
    return preg_match(WF_GATEWAY_NAME_MASK, $name) === 1;
}

function wf_if_ok(string $if): bool
{
    return preg_match(WF_IF_MASK, $if) === 1;
}

/** A state-kill target, gateway-address@interface, with an IPv4 address and an interface name. */
function wf_kill_target_ok(string $target): bool
{
    if (preg_match('/^(\d{1,3}\.){3}\d{1,3}@[a-z][a-z0-9_.]*\z/', $target) !== 1) {
        return false;
    }
    return filter_var(explode('@', $target)[0], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false;
}

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

/**
 * The hold records by gateway name. A row whose gateway UUID names no gateway, or a gateway whose name is not a plain
 * token, is stale; of two rows for one gateway the newer by since is kept (then the greater item UUID) and the other
 * is a duplicate. The next write prunes both kinds.
 *
 * @param array<string, array{gateway: string, boot: string, since: int}> $rows Holds::records(), by item UUID
 * @param array<string, string> $nameByUuid every configured gateway's UUID => its name
 * @return array{holds: array<string, array{boot: string, since: int}>, stale: list<string>, dupes: list<string>}
 *     stale: the rows' item UUIDs; dupes: a gateway name for each row dropped as a duplicate
 */
function wf_resolve_records(array $rows, array $nameByUuid): array
{
    $best = [];
    $stale = [];
    $dupes = [];
    foreach ($rows as $item => $row) {
        $item = (string)$item;
        $name = $nameByUuid[$row['gateway']] ?? null;
        if ($name === null || !wf_name_ok($name)) {
            $stale[] = $item;
            continue;
        }
        if (isset($best[$name])) {
            $dupes[] = $name;
            [$since, $kept] = $best[$name];
            if ($row['since'] < $since || ($row['since'] === $since && strcmp($item, $kept) < 0)) {
                continue;
            }
        }
        $best[$name] = [$row['since'], $item, ['boot' => $row['boot'], 'since' => $row['since']]];
    }
    return ['holds' => array_map(fn (array $b): array => $b[2], $best), 'stale' => $stale, 'dupes' => $dupes];
}
