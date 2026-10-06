<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Parsers for `pfctl -vvss` and `pfctl -vvsr`, and flow pairing for
 * failback (spec 2026-10-05 section 3.5). Pure.
 *
 * States are floating ("all"). An outgoing state ("->") whose route-to is a
 * WAN gateway is a flow's anchor; its partner is the incoming state ("<-")
 * with the same protocol and src/dst as the anchor's pre-NAT source. Incoming
 * states are never anchors, even when they carry route-to (route-to LAN rules
 * put it on the incoming state too). ICMP is skipped until its pairing has
 * been verified against a live capture (review N10).
 */

const WF_ICMP_PROTOS = ['icmp', 'icmp6', 'ipv6-icmp'];

/**
 * @return list<array{proto: string, dir: string, src: string, orig_src: string, dst: string, rule: ?int,
 *                    rlabel: ?string, id: ?string, creatorid: ?string, route_to_gw: ?string,
 *                    route_to_if: ?string, origif: ?string}>
 */
function wf_parse_states(string $text): array
{
    $states = [];
    $cur = null;
    foreach (preg_split('/\R/', $text) ?: [] as $line) {
        if (preg_match('/^all (\S+) (\S+)(?: \((\S+)\))? (<-|->) (\S+)(?: \((\S+)\))?\s+\S+$/', $line, $m) === 1) {
            if ($cur !== null) {
                $states[] = $cur;
            }
            $a = $m[2];
            $aParen = $m[3] ?? '';
            $b = $m[5];
            if ($m[4] === '->') {
                $cur = ['proto' => $m[1], 'dir' => 'out', 'src' => $a, 'orig_src' => $aParen !== '' ? $aParen : $a, 'dst' => $b];
            } else {
                $cur = ['proto' => $m[1], 'dir' => 'in', 'src' => $b, 'orig_src' => $b, 'dst' => $a];
            }
            $cur += ['rule' => null, 'rlabel' => null, 'id' => null, 'creatorid' => null,
                     'route_to_gw' => null, 'route_to_if' => null, 'origif' => null];
            continue;
        }
        if ($cur === null) {
            continue;
        }
        if (preg_match('/\brule (\d+)/', $line, $m) === 1) {
            $cur['rule'] = (int)$m[1];
        }
        if (preg_match('/\brlabel ([^,\s]+)/', $line, $m) === 1) {
            $cur['rlabel'] = $m[1];
        }
        if (preg_match('/\bid: ([0-9a-f]+) creatorid: ([0-9a-f]+)/', $line, $m) === 1) {
            $cur['id'] = $m[1];
            $cur['creatorid'] = $m[2];
        }
        if (preg_match('/\broute-to: (\S+)@(\S+)/', $line, $m) === 1) {
            $cur['route_to_gw'] = $m[1];
            $cur['route_to_if'] = $m[2];
        }
        if (preg_match('/^\s+origif: (\S+)/', $line, $m) === 1) {
            $cur['origif'] = $m[1];
        }
    }
    if ($cur !== null) {
        $states[] = $cur;
    }
    return $states;
}

/**
 * @return array<string, list<array{gw: ?string, if: ?string, balanced: bool}>> label => renderings
 */
function wf_parse_rules(string $text): array
{
    $out = [];
    foreach (preg_split('/\R/', $text) ?: [] as $line) {
        if (preg_match('/^@\d+ /', $line) !== 1 || preg_match('/label "([^"]+)"/', $line, $lm) !== 1) {
            continue;
        }
        $r = ['gw' => null, 'if' => null, 'balanced' => str_contains($line, 'route-to {')];
        if (!$r['balanced'] && preg_match('/route-to \((\S+) (\S+)\)/', $line, $m) === 1) {
            $r['if'] = $m[1];
            $r['gw'] = $m[2];
        }
        $out[$lm[1]][] = $r;
    }
    return $out;
}

function wf_addr_host(string $addr): string
{
    $bracket = strpos($addr, '[');
    if ($bracket !== false) {
        return substr($addr, 0, $bracket);
    }
    $colon = strrpos($addr, ':');
    return $colon === false ? $addr : substr($addr, 0, $colon);
}

/**
 * @param list<array{proto: string, dir: string, src: string, orig_src: string, dst: string, route_to_gw: ?string}> $states
 * @param array<string, string> $wanGws gateway ip => WAN name
 * @return list<array{anchor: array, partner: ?array, kind: string, current: string}>
 */
function wf_flows(array $states, array $wanGws): array
{
    $incoming = [];
    foreach ($states as $s) {
        if ($s['dir'] === 'in') {
            $incoming[$s['proto'] . '|' . $s['src'] . '|' . $s['dst']][] = $s;
        }
    }
    $flows = [];
    foreach ($states as $s) {
        if ($s['dir'] !== 'out' || $s['route_to_gw'] === null || !isset($wanGws[$s['route_to_gw']])
            || in_array($s['proto'], WF_ICMP_PROTOS, true)) {
            continue;
        }
        $matches = $incoming[$s['proto'] . '|' . $s['orig_src'] . '|' . $s['dst']] ?? [];
        $kind = match (count($matches)) {
            0 => 'local',
            1 => 'forwarded',
            default => 'ambiguous',
        };
        $flows[] = ['anchor' => $s, 'partner' => $kind === 'forwarded' ? $matches[0] : null,
                    'kind' => $kind, 'current' => $wanGws[$s['route_to_gw']]];
    }
    return $flows;
}

/**
 * pf output format drift check (spec 3.12): the raw text holds states, or route-to tokens, that the
 * parser did not recover.
 *
 * @param list<array{route_to_gw: ?string}> $states wf_parse_states($raw)
 */
function wf_pf_selfcheck(string $raw, array $states): bool
{
    $headers = preg_match_all('/^\S+ \S+ \S+.* (<-|->) \S+/m', $raw);
    if ($headers > 0 && $states === []) {
        return false;
    }
    /* a route target prints as "<gateway>@<interface>" at the end of a state's detail line, whatever
     * the token before it is called */
    $gwTokens = preg_match_all('/\s\S+@[a-z][a-z0-9_.]*\s*$/m', $raw);
    $parsed = count(array_filter($states, fn (array $s): bool => $s['route_to_gw'] !== null));
    return !($gwTokens > 0 && $parsed === 0);
}
