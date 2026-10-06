<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Failback (spec 2026-10-05 section 3.5). Pure. A flow's preferred WAN is
 * its rule's gateway (tier 1 of a group), else the live default route. A
 * pending failback for WAN R kills flows that prefer R but sit elsewhere --
 * only once every rendering of their rule routes to R, and, when R is the
 * usable WAN core ranks first, only once the live default is R.
 */

require_once __DIR__ . '/pfstate.php';

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
