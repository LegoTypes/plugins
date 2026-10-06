<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Hold planning (spec 2026-10-05 section 3.3). Pure. Releases are decided
 * before starts, starts use the post-release held set, and a hold needs a
 * fresh usable alternative -- so no tick can ever leave two holds.
 */

require_once __DIR__ . '/judge.php';

/**
 * @param array{judgement: array{value: ?string}, manual_down: bool, disabled: bool, core_down: bool} $w
 */
function wf_usable(array $w, bool $heldNow): bool
{
    return !$heldNow && !$w['manual_down'] && !$w['disabled'] && !$w['core_down'] && wf_up($w['judgement']);
}

/**
 * Positive evidence that a WAN cannot carry traffic (release-on-invariant).
 *
 * @param array{reading: string, judgement: array{value: ?string}, manual_down: bool, disabled: bool, core_down: bool} $w
 */
function wf_positively_failed(array $w): bool
{
    return $w['disabled'] || $w['manual_down'] || $w['core_down']
        || $w['reading'] === WF_UNAVAILABLE || $w['judgement']['value'] === WF_BAD;
}

/**
 * @param array{reading: string, judgement: array{value: ?string, last_settled_at: ?int}, manual_down: bool,
 *              disabled: bool, core_down: bool, raw_loss: ?float, losslow: float} $a
 */
function wf_fresh_alternative(array $a, bool $heldNow, int $now, int $freshSeconds): bool
{
    $at = $a['judgement']['last_settled_at'];
    return wf_usable($a, $heldNow)
        && $at !== null && max(0, $now - $at) <= $freshSeconds
        && $a['raw_loss'] !== null && $a['raw_loss'] <= $a['losslow']
        && $a['reading'] !== WF_BAD && $a['reading'] !== WF_UNAVAILABLE;
}

/**
 * @param array<string, array{reading: string, judgement: array, held: bool, manual_down: bool, disabled: bool,
 *                            core_down: bool, raw_loss: ?float, losslow: float, priority: int, no_rehold: bool}> $wans
 * @return array{release: list<string>, hold: list<string>, log: list<string>}
 */
function wf_plan_holds(array $wans, int $now, int $freshSeconds): array
{
    $held = [];
    foreach ($wans as $name => $w) {
        if ($w['held']) {
            $held[$name] = true;
        }
    }
    $release = [];
    $log = [];
    foreach (array_keys($held) as $name) {
        $w = $wans[$name];
        if ($w['reading'] === WF_CLEAN) {
            $release[] = $name;
            $log[] = "release {$name}: loss-free";
            continue;
        }
        $others = array_diff_key($wans, [$name => true]);
        $failed = array_filter($others, 'wf_positively_failed');
        if (count($failed) === count($others)) {
            $release[] = $name;
            $log[] = "release {$name}: no other WAN usable";
        }
    }
    foreach ($release as $name) {
        unset($held[$name]);
    }

    $order = array_keys($wans);
    usort($order, fn (string $a, string $b): int => [$wans[$a]['priority'], $a] <=> [$wans[$b]['priority'], $b]);
    $hold = [];
    foreach ($order as $name) {
        $w = $wans[$name];
        if (isset($held[$name]) || in_array($name, $release, true) || $w['no_rehold']
            || $w['manual_down'] || $w['disabled']) {
            continue;
        }
        if ($w['reading'] !== WF_BAD && $w['reading'] !== WF_UNAVAILABLE) {
            continue;
        }
        $alternative = null;
        foreach ($wans as $other => $ow) {
            if ($other !== $name && wf_fresh_alternative($ow, isset($held[$other]), $now, $freshSeconds)) {
                $alternative = $other;
                break;
            }
        }
        if ($alternative === null) {
            continue;
        }
        $held[$name] = true;
        $hold[] = $name;
        $log[] = "hold {$name}: {$w['reading']}, alternative {$alternative}";
    }
    return ['release' => $release, 'hold' => $hold, 'log' => $log];
}
