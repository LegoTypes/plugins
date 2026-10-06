<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Runtime state (spec 2026-10-05 section 3.8): what does not belong in config. Ownership itself -- the
 * held list -- is in the plugin model, saved with force_down; this file only resumes an apply a crash
 * interrupted and notices held changes the engine did not make. Load/save touch one file; the rest is pure.
 */

require_once __DIR__ . '/tailscale.php';

const WF_STATE_VERSION = 3;

/**
 * @return array{version: int, boot_id: string, installed_at: ?int, last_now: ?int, judgements: array<string, array>,
 *               no_rehold: array<string, true>, pending_failbacks: array<string, array{since: int, clean_since: ?int, due: ?int}>, ts: array,
 *               unowned_alerted_at: array<string, int>, apply_pending: array<string, string>, last_held: list<string>,
 *               contract_last: string, contract_judging_since: ?int, boot_note: ?string, dry_held: list<string>,
 *               said: array<string, string>}
 */
function wf_state_new(string $bootId): array
{
    return ['version' => WF_STATE_VERSION, 'boot_id' => $bootId, 'installed_at' => null, 'last_now' => null,
            'judgements' => [], 'no_rehold' => [], 'pending_failbacks' => [], 'ts' => wf_ts_new(),
            'unowned_alerted_at' => [], 'apply_pending' => [], 'last_held' => [], 'contract_last' => '',
            'contract_judging_since' => null, 'boot_note' => null, 'dry_held' => [], 'said' => []];
}

/**
 * A recurring condition is logged once when it appears or changes, and forgotten when it clears.
 *
 * @param array<string, string> $said the state's said map
 * @return ?string the line to log now, if any
 */
function wf_once(array &$said, string $key, ?string $line): ?string
{
    if ($line === null) {
        unset($said[$key]);
        return null;
    }
    if (($said[$key] ?? null) === $line) {
        return null;
    }
    $said[$key] = $line;
    return $line;
}

/**
 * @return array{state: array, corrupt: bool}
 */
function wf_state_load(string $path, string $bootId): array
{
    if (!is_file($path)) {
        return ['state' => wf_state_new($bootId), 'corrupt' => false];
    }
    try {
        $data = json_decode((string)file_get_contents($path), true, 64, JSON_THROW_ON_ERROR);
    } catch (JsonException) {
        return ['state' => wf_state_new($bootId), 'corrupt' => true];
    }
    if (!is_array($data) || !is_int($data['version'] ?? null)) {
        return ['state' => wf_state_new($bootId), 'corrupt' => true];
    }
    /* another version (an upgrade): start fresh in this boot; ownership lives in config, so nothing is
     * released and held gateways stay held until they read loss-free */
    if ($data['version'] !== WF_STATE_VERSION) {
        return ['state' => wf_state_new($bootId), 'corrupt' => false];
    }
    return ['state' => array_merge(wf_state_new($bootId), $data), 'corrupt' => false];
}

/**
 * @param array $state the shape returned by wf_state_new()
 */
function wf_state_save(string $path, array $state): void
{
    $dir = dirname($path);
    if (!is_dir($dir)) {
        mkdir($dir, 0750, true);
    }
    $tmp = $path . '.tmp';
    file_put_contents($tmp, json_encode($state, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR) . "\n", LOCK_EX);
    rename($tmp, $path);
}

/**
 * @param list<string> $held names in the plugin's held list that resolve to a gateway
 * @param array<string, bool> $forceDown every configured gateway name => force_down
 * @param array<string, string> $applyPending name => hold|release, written before an engine save
 * @param list<string> $lastHeld the held list the engine last wrote (or last saw after a foreign change)
 * @return array{owned: list<string>, manual_released: list<string>, redo_apply: list<string>, redo_replay: list<string>,
 *               foreign: list<string>, apply_pending: array<string, string>, log: list<string>}
 */
function wf_reconcile(array $held, array $forceDown, array $applyPending, array $lastHeld): array
{
    $out = ['owned' => [], 'manual_released' => [], 'redo_apply' => [], 'redo_replay' => [], 'foreign' => [],
            'apply_pending' => [], 'log' => []];
    foreach ($held as $name) {
        if (!array_key_exists($name, $forceDown)) {
            continue;
        }
        if ($forceDown[$name]) {
            $out['owned'][] = $name;
        } else {
            $out['manual_released'][] = $name;
            $out['log'][] = "{$name} released by hand; it leaves held and is not re-held until it reads up and then over threshold";
        }
    }
    foreach ($applyPending as $name => $what) {
        $inHeld = in_array($name, $held, true);
        if ($what === 'hold' && $inHeld) {
            $out['redo_apply'][] = $name;
            $out['apply_pending'][$name] = 'hold';
            $out['log'][] = "apply-resumed {$name}: hold was saved, finishing replay and state kill";
        } elseif ($what === 'release' && !$inHeld) {
            $out['redo_replay'][] = $name;
            $out['apply_pending'][$name] = 'release';
            $out['log'][] = "apply-resumed {$name}: release was saved, finishing replay";
        } else {
            $out['log'][] = "apply-resumed {$name}: the {$what} was never saved; dropped";
        }
    }
    $changed = array_merge(array_diff($held, $lastHeld), array_diff($lastHeld, $held));
    $out['foreign'] = array_values(array_diff(array_unique($changed), array_keys($applyPending)));
    foreach ($out['foreign'] as $name) {
        $out['log'][] = "held changed outside the engine for {$name} (a config revert or restore); re-syncing routing";
    }
    return $out;
}

/**
 * Discard everything measured before a reboot (spec 3.11). Ownership in config is released by the
 * caller (boot.php, or evaluate's own boot detector); this resets the runtime side only.
 *
 * @param array $state the shape returned by wf_state_new()
 * @return array the shape returned by wf_state_new()
 */
function wf_boot_reset(array $state, string $bootId): array
{
    $new = wf_state_new($bootId);
    $new['installed_at'] = $state['installed_at'] ?? null;
    $new['unowned_alerted_at'] = $state['unowned_alerted_at'] ?? [];
    $new['contract_last'] = $state['contract_last'] ?? '';
    return $new;
}
