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
 * Failback. Pure. A flow's preferred WAN is
 * its rule's gateway (tier 1 of a group), else the live default route. A
 * pending failback for WAN R kills flows that prefer R but sit elsewhere --
 * only once every rendering of their rule routes to R, and, when R is the
 * usable WAN core ranks first, only once the live default is R.
 */

require_once __DIR__ . '/pfstate.php';
require_once __DIR__ . '/contract.php';

/**
 * Each rule's preferred gateways: none without a gateway, a group's first tier that has members (wf_first_tier()),
 * else the gateway itself. A group whose row drifted (wf_contract_groups()) gives none, and so does every rule while
 * the groups are unreadable (null), since a group cannot be told from a gateway then: a drift never throws here, and
 * the failback contract reports it.
 *
 * @param array<string, string> $ruleGateways rule UUID => its gateway field
 * @param array<array-key, mixed>|null $groups wf_contract_groups_read()'s groups
 * @return array<string, list<string>>
 */
function wf_rule_pref(array $ruleGateways, ?array $groups): array
{
    $pref = [];
    foreach ($ruleGateways as $uuid => $gw) {
        if ($gw === '' || $groups === null) {
            $pref[$uuid] = [];
        } elseif (isset($groups[$gw])) {
            $pref[$uuid] = wf_contract_groups([$gw => $groups[$gw]]) === [] ? wf_first_tier($groups[$gw]['tiers']) : [];
        } else {
            $pref[$uuid] = [$gw];
        }
    }
    return $pref;
}

/**
 * @param array{anchor: array{dst: string}, partner: ?array{rlabel: ?string}, kind: string, current: string} $flow
 * @param array<string, list<string>> $rulePref
 * @param array<string, true> $pinned
 */
function wf_preferred(array $flow, array $rulePref, ?string $liveDefault, array $pinned): ?string
{
    if ($flow['kind'] === 'forwarded') {
        $label = $flow['partner']['rlabel'] ?? null;
        $tier1 = $label !== null ? ($rulePref[$label] ?? []) : [];
        if ($tier1 !== []) {
            return in_array($flow['current'], $tier1, true) ? $flow['current'] : $tier1[0];
        }
        return $liveDefault;
    }
    if ($flow['kind'] === 'local') {
        return isset($pinned[wf_addr_host($flow['anchor']['dst'])]) ? null : $liveDefault;
    }
    return null;
}

/**
 * @param list<array{anchor: array{dst: string, id: ?string, creatorid: ?string}, partner: ?array{rlabel: ?string, id: ?string, creatorid: ?string}, kind: string, current: string}> $flows
 * @param array<string, list<string>> $rulePref
 * @param array<string, list<array{gw: ?string, if: ?string, balanced: bool}>> $renderings
 * @param array<string, string> $wanTargets WAN name => route target
 * @param array<string, true> $pinned
 * @return array{ready: bool, kills: list<array{id: string, creatorid: string}>, stale_labels: list<string>, default_ok: bool, spared: int}
 */
function wf_failback_gate(string $recovering, array $flows, array $rulePref, array $renderings, array $wanTargets,
                          ?string $liveDefault, bool $recoveringIsTop, array $pinned): array
{
    $defaultOk = !$recoveringIsTop || $liveDefault === $recovering;
    $kills = [];
    $stale = [];
    $spared = 0;
    foreach ($flows as $f) {
        if (wf_preferred($f, $rulePref, $liveDefault, $pinned) !== $recovering || $f['current'] === $recovering) {
            $spared++;
            continue;
        }
        $label = $f['kind'] === 'forwarded' ? ($f['partner']['rlabel'] ?? null) : null;
        if ($label !== null && ($rulePref[$label] ?? []) !== []) {
            $r = $renderings[$label] ?? [];
            $onRecovering = array_filter($r, fn (array $x): bool => $x['gw'] !== null && $x['if'] !== null
                && wf_route_target($x['gw'], $x['if']) === $wanTargets[$recovering]);
            if ($r === [] || count($onRecovering) !== count($r)) {
                $stale[$label] = true;
                continue;
            }
        }
        foreach ([$f['anchor'], $f['partner']] as $s) {
            if ($s !== null && $s['id'] !== null && $s['creatorid'] !== null) {
                $kills[] = ['id' => $s['id'], 'creatorid' => $s['creatorid']];
            }
        }
    }
    return ['ready' => $defaultOk && $stale === [], 'kills' => $kills, 'stale_labels' => array_keys($stale),
            'default_ok' => $defaultOk, 'spared' => $spared];
}

/**
 * Whether failback may act on a pf read: only when its state listing parsed (wf_pf_selfcheck()) and its rule listing
 * and groups show no drift (wf_contract_failback()). Otherwise the line saying why failback is suspended, the drift
 * first, which the apply gate logs and a dry run says too.
 *
 * @param array{selfcheck: bool, drift: list<string>} $pf wf_snapshot_pf()
 */
function wf_failback_suspended(string $n, array $pf): ?string
{
    if ($pf['selfcheck'] && $pf['drift'] === []) {
        return null;
    }
    $why = array_merge($pf['drift'], $pf['selfcheck'] ? [] : ['pf state format did not parse']);
    return "failback {$n}: " . implode('; ', $why) . ' (core contract); failback suspended';
}

/**
 * What a dry run says for a due failback: what the apply gate would do on this pf read, suspend it or kill.
 *
 * @param array{flows: list<array>, renderings: array<string, list<array>>, pinned: array<string, true>,
 *              rule_pref: array<string, list<string>>, default: ?string, selfcheck: bool, drift: list<string>} $pf wf_snapshot_pf()
 * @param array<string, string> $wanTargets WAN name => route target
 */
function wf_failback_dry(string $n, array $pf, array $wanTargets, bool $top): string
{
    $suspended = wf_failback_suspended($n, $pf);
    if ($suspended !== null) {
        return "[dry] {$suspended}";
    }
    $g = wf_failback_gate($n, $pf['flows'], $pf['rule_pref'], $pf['renderings'], $wanTargets, $pf['default'], $top, $pf['pinned']);
    return sprintf('[dry] failback %s would kill %d states, spare %d flows%s', $n, count($g['kills']), $g['spared'],
        $g['ready'] ? '' : ' (not ready)');
}
