<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Parsers for `pfctl -vvss` and `pfctl -vvsr`, and flow pairing for
 * failback (spec 2026-10-05 section 3.5). Pure.
 *
 * Failback pairs floating states ("all") only. An outgoing state ("->") whose route-to is a
 * WAN gateway is a flow's anchor; its partner is the incoming state ("<-")
 * with the same protocol and src/dst as the anchor's pre-NAT source. Incoming
 * states are never anchors, even when they carry route-to (route-to LAN rules
 * put it on the incoming state too). ICMP is skipped until its pairing has
 * been verified against a live capture (review N10).
 *
 * A hold kills the states whose route target is the WAN's gateway@interface, floating or interface-bound,
 * by state id. pf prints a
 * state's target at the end of its id line as "<token>: <gateway>@<interface>", the token being route-to,
 * reply-to or dup-to.
 */

require_once __DIR__ . '/parsers.php';

const WF_ICMP_PROTOS = ['icmp', 'icmp6', 'ipv6-icmp'];

/**
 * A state is floating ("all") or bound to the interface pf prints in its place ("bind states to interface"):
 * bound holds that interface, or null. rt and rt_target are any target token and its gateway@interface;
 * route_to_gw and route_to_if are filled for route-to only, which is what failback pairs flows by. Any other
 * unindented line ends the state before it, so that state's id is never paired with another state's target.
 *
 * @return list<array{proto: string, dir: string, src: string, orig_src: string, dst: string, rule: ?int,
 *                    bound: ?string, rlabel: ?string, id: ?string, creatorid: ?string, rt: ?string, rt_target: ?string,
 *                    route_to_gw: ?string, route_to_if: ?string, origif: ?string}>
 */
function wf_parse_states(string $text): array
{
    $states = [];
    $cur = null;
    foreach (preg_split('/\R/', $text) ?: [] as $line) {
        if (preg_match('/^([a-z][a-z0-9_.]*) (\S+) (\S+)(?: \((\S+)\))? (<-|->) (\S+)(?: \((\S+)\))?\s+\S+$/', $line, $m) === 1) {
            if ($cur !== null) {
                $states[] = $cur;
            }
            $a = $m[3];
            $aParen = $m[4] ?? '';
            $b = $m[6];
            if ($m[5] === '->') {
                $cur = ['proto' => $m[2], 'dir' => 'out', 'src' => $a, 'orig_src' => $aParen !== '' ? $aParen : $a, 'dst' => $b];
            } else {
                $cur = ['proto' => $m[2], 'dir' => 'in', 'src' => $b, 'orig_src' => $b, 'dst' => $a];
            }
            $cur += ['bound' => $m[1] === 'all' ? null : $m[1], 'rule' => null, 'rlabel' => null, 'id' => null, 'creatorid' => null, 'rt' => null, 'rt_target' => null,
                     'route_to_gw' => null, 'route_to_if' => null, 'origif' => null];
            continue;
        }
        if ($cur !== null && preg_match('/^\S/', $line) === 1) {
            $states[] = $cur;
            $cur = null;
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
        if (preg_match('/\s([a-z-]+-to): (\S+)@(\S+)/', $line, $m) === 1) {
            $cur['rt'] = $m[1];
            $cur['rt_target'] = wf_route_target($m[2], $m[3]);
            if ($m[1] === 'route-to') {
                $cur['route_to_gw'] = $m[2];
                $cur['route_to_if'] = $m[3];
            }
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
 * A rule's route-to is one target, "route-to (<if> <gw>)", or a pool, "route-to { (<if> <gw>), ... }".
 * Core lists a gateway group member once per unit of its weight, so a pool can name a single target
 * several times: that routes to the target as surely as the plain form. Only a pool of different
 * targets is balanced.
 *
 * @return array<string, list<array{gw: ?string, if: ?string, balanced: bool}>> label => renderings
 */
function wf_parse_rules(string $text): array
{
    $out = [];
    foreach (preg_split('/\R/', $text) ?: [] as $line) {
        if (preg_match('/^@\d+ /', $line) !== 1 || preg_match('/label "([^"]+)"/', $line, $lm) !== 1) {
            continue;
        }
        $targets = [];
        if (preg_match('/route-to \{([^}]*)\}/', $line, $pool) === 1) {
            preg_match_all('/\((\S+) (\S+)\)/', $pool[1], $members, PREG_SET_ORDER);
            foreach ($members as $m) {
                $targets[$m[1] . ' ' . $m[2]] = [$m[1], $m[2]];
            }
        } elseif (preg_match('/route-to \((\S+) (\S+)\)/', $line, $m) === 1) {
            $targets[$m[1] . ' ' . $m[2]] = [$m[1], $m[2]];
        }
        $single = count($targets) === 1 ? reset($targets) : null;
        $out[$lm[1]][] = ['gw' => $single === null ? null : $single[1], 'if' => $single === null ? null : $single[0],
                          'balanced' => count($targets) > 1];
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
 * A WAN's identity in pf and the routing table: "<gateway>@<interface>", as pf prints a route target.
 * The gateway address alone is ambiguous when two WANs share one (two modems both at 192.168.1.1).
 */
function wf_route_target(string $gateway, string $interface): string
{
    return $gateway . '@' . $interface;
}

/**
 * Floating states only, as anchors and as partners: the pairing is defined on floating states. An
 * interface-bound state is killed by a hold's target like any other, but failback never moves it back.
 *
 * @param list<array{proto: string, dir: string, src: string, orig_src: string, dst: string, bound: ?string, route_to_gw: ?string, route_to_if: ?string}> $states
 * @param array<string, string> $wanTargets route target => WAN name
 * @return list<array{anchor: array, partner: ?array, kind: string, current: string}>
 */
function wf_flows(array $states, array $wanTargets): array
{
    $states = array_values(array_filter($states, fn (array $s): bool => $s['bound'] === null));
    $incoming = [];
    foreach ($states as $s) {
        if ($s['dir'] === 'in') {
            $incoming[$s['proto'] . '|' . $s['src'] . '|' . $s['dst']][] = $s;
        }
    }
    $flows = [];
    foreach ($states as $s) {
        $target = $s['route_to_gw'] === null || $s['route_to_if'] === null ? null : wf_route_target($s['route_to_gw'], $s['route_to_if']);
        if ($s['dir'] !== 'out' || $target === null || !isset($wanTargets[$target]) || in_array($s['proto'], WF_ICMP_PROTOS, true)) {
            continue;
        }
        $matches = $incoming[$s['proto'] . '|' . $s['orig_src'] . '|' . $s['dst']] ?? [];
        $kind = match (count($matches)) {
            0 => 'local',
            1 => 'forwarded',
            default => 'ambiguous',
        };
        $flows[] = ['anchor' => $s, 'partner' => $kind === 'forwarded' ? $matches[0] : null,
                    'kind' => $kind, 'current' => $wanTargets[$target]];
    }
    return $flows;
}

/**
 * pf output format drift check (spec 3.12). A live firewall always has states (dpinger's own probes at
 * least), every rule-created state carries an rlabel and every state an id, so any of these coming back
 * empty means pfctl failed or its format moved, not that there is nothing to do. Every route target pf
 * printed must parse: one token form that moved while another still parses would leave a hold's kill, or
 * failback, silently missing states.
 *
 * @param list<array{rlabel: ?string, id: ?string, rt_target: ?string}> $states wf_parse_states($raw)
 */
function wf_pf_selfcheck(string $raw, array $states): bool
{
    if ($states === []) {
        return false;
    }
    /* a route target prints as "<gateway>@<interface>" at the end of a state's detail line, whatever
     * the token before it is called */
    $gwTokens = preg_match_all('/\s\S+@[a-z][a-z0-9_.]*\s*$/m', $raw);
    $parsed = count(array_filter($states, fn (array $s): bool => $s['rt_target'] !== null));
    if ($parsed < $gwTokens) {
        return false;
    }
    return array_filter($states, fn (array $s): bool => $s['rlabel'] !== null) !== []
        && array_filter($states, fn (array $s): bool => $s['id'] !== null) !== [];
}

/**
 * The states pf routes via $target (gateway@interface), whatever the target's token, that carry an id.
 *
 * @param list<array{id: ?string, creatorid: ?string, rt_target: ?string}> $states wf_parse_states()
 * @return list<array{id: string, creatorid: string}>
 */
function wf_states_via(array $states, string $target): array
{
    $out = [];
    foreach ($states as $s) {
        if ($s['rt_target'] === $target && $s['id'] !== null && $s['creatorid'] !== null) {
            $out[] = ['id' => $s['id'], 'creatorid' => $s['creatorid']];
        }
    }
    return $out;
}

/**
 * Kill every state routed via $target, one state id at a time, as core's kill.state does. Unlike core's
 * kill by gateway address, it leaves the states of another WAN that shares the address alone. A kill counts
 * as done when pfctl exits 0. A listing that fails or does not parse kills nothing and says so, rather than
 * reading as no states to kill. The parser reads ids and creator ids as hex only, so the kill's command line
 * needs no quoting.
 *
 * @param callable(string): array{out: string, rc: int} $run runs one command line
 * @return array{line: string, rc: int}
 */
function wf_kill_states_run(string $target, callable $run): array
{
    if (!wf_kill_target_ok($target)) {
        return ['line' => 'rejected target', 'rc' => 1];
    }
    $listing = $run('/sbin/pfctl -vvss');
    if ($listing['rc'] !== 0) {
        return ['line' => "listing failed: pfctl exited {$listing['rc']}", 'rc' => 1];
    }
    $states = wf_parse_states($listing['out']);
    if (!wf_pf_selfcheck($listing['out'], $states)) {
        return ['line' => 'listing failed: the state listing did not parse', 'rc' => 1];
    }
    $killed = 0;
    $failed = 0;
    foreach (wf_states_via($states, $target) as $s) {
        if ($run("/sbin/pfctl -k id -k {$s['id']}/{$s['creatorid']}")['rc'] === 0) {
            $killed++;
        } else {
            $failed++;
        }
    }
    return ['line' => "killed {$killed} states ({$failed} failed)", 'rc' => 0];
}

/**
 * Whether a kill's answer (wf_kill_states_run()'s line, as configd hands it back) says that every state it found was
 * killed: the format lives here, beside the code that prints it.
 */
function wf_kill_answer_clean(string $answer): bool
{
    return preg_match('/^killed \d+ states \(0 failed\)\z/', $answer) === 1;
}

/**
 * The gateways of a group's first tier that has any: core numbers tiers 1-5 and keeps an empty tier
 * as [''].
 *
 * @param array<int, list<string>> $tiers
 * @return list<string>
 */
function wf_first_tier(array $tiers): array
{
    ksort($tiers);
    foreach ($tiers as $members) {
        $named = array_values(array_filter($members, fn (string $m): bool => $m !== ''));
        if ($named !== []) {
            return $named;
        }
    }
    return [];
}

/**
 * Destinations of local flows that a host route pins to their WAN. Each host is looked up once; past
 * the cap a host is not looked up and is treated as pinned, so it is spared rather than killed.
 *
 * @param list<array{anchor: array{dst: string}, kind: string}> $flows
 * @param callable(string, array): bool $isPinned host, its flow => a host route pins it
 * @return array<string, true>
 */
function wf_pinned_hosts(array $flows, callable $isPinned, int $cap): array
{
    $pinned = [];
    $seen = [];
    $looked = 0;
    foreach ($flows as $f) {
        $host = wf_addr_host($f['anchor']['dst']);
        if ($f['kind'] !== 'local' || isset($seen[$host])) {
            continue;
        }
        $seen[$host] = true;
        if ($looked >= $cap) {
            $pinned[$host] = true;
            continue;
        }
        $looked++;
        if ($isPinned($host, $f)) {
            $pinned[$host] = true;
        }
    }
    return $pinned;
}
