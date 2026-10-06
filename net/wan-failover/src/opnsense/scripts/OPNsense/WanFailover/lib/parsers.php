<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Pure parsers for the live snapshot: ifconfig, route get, kern.boottime, UUID resolution.
 */

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
 * @return array{destination: ?string, gateway: ?string}
 */
function wf_parse_route_get(string $out): array
{
    return ['destination' => preg_match('/^\s*destination:\s*(\S+)/m', $out, $d) === 1 ? $d[1] : null,
            'gateway' => preg_match('/^\s*gateway:\s*(\S+)/m', $out, $g) === 1 ? $g[1] : null];
}

function wf_parse_boottime(string $out): int
{
    return preg_match('/sec = (\d+)/', $out, $m) === 1 ? (int)$m[1] : 0;
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
