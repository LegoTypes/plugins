#!/usr/local/bin/php
<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Early-boot release (spec 2026-10-05 section 3.11). Nobody knows how long the firewall was down or
 * whether the modems rebooted too, so every hold the plugin took is released before routing starts, in one
 * config save without a backup. A record proves the plugin took it only by carrying the boot before's id, the one
 * the state file names; every other record is pruned in the same save, its gateway's force_down left as it is. 1.3_1's
 * held list, still in the config when an upgrade's migration did not run before the reboot, goes in the same save:
 * the entries the state's last_held proves are released, the others left as they are. With the state file missing
 * or unreadable nothing is proven and nothing is written: the first evaluation prunes the records as foreign. The
 * runtime state is reset only after the save landed: if it did not, the state keeps the old boot id, so evaluate's
 * own boot detector releases the holds instead, and the reason is left in the state's boot note. syslog is not
 * running yet, so every outcome is a boot note, which the first evaluation logs. While the package removal's marker
 * exists it does nothing and writes nothing.
 */

require_once 'script/load_phalcon.php';
require_once __DIR__ . '/lib/snapshot.php';
require_once __DIR__ . '/lib/state.php';
require_once __DIR__ . '/lib/log.php';
require_once __DIR__ . '/lib/apply.php';

try {
    if (wf_removing()) {
        exit(0);
    }
    $bootId = wf_boot_id();
    /* read without the live boot id, so that a missing file names no boot before and proves no record */
    $loaded = wf_state_load(WF_STATE, '');
    $proof = wf_state_proof($loaded);
    $rows = (new \OPNsense\WanFailover\Holds())->records();
    $nameByUuid = [];
    $forceDown = [];
    foreach ((new \OPNsense\Routing\Gateways())->gatewaysIndexedByName(true) as $name => $g) {
        if (!empty($g['uuid'])) {
            $nameByUuid[(string)$g['uuid']] = (string)$name;
        }
        $forceDown[(string)$name] = !empty($g['force_down']);
    }
    $records = wf_resolve_records($rows, $nameByUuid);
    $legacy = wf_boot_legacy(wf_holds_legacy_csv(), $nameByUuid, $proof);
    $outcome = wf_boot_outcome($records['holds'], count($records['stale']) + count($records['dupes']), $proof['boot'], $legacy);
    $reset = wf_boot_reset($loaded['state'], $bootId);
    if ($rows === [] && !$legacy['present']) {
        wf_state_save(WF_STATE, $reset);
    } elseif (wf_boot_unread($proof['boot'])) {
        $reset['boot_note'] = $outcome['note'];
        wf_state_save(WF_STATE, $reset);
    } else {
        /* every record goes, and the held list with them: the boot before's released, the others pruned */
        $release = array_fill_keys($outcome['release'], false);
        $written = wf_write_holds($release, array_intersect_key($forceDown, $release), [], false, $outcome['drop_legacy']);
        if ($written['ok']) {
            $reset['boot_note'] = $outcome['note'];
            foreach ($outcome['pruned'] as $n) {
                $reset['foreign_pruned'][$n] = time();
            }
            wf_state_save(WF_STATE, $reset);
        } else {
            /* the state keeps the boot before's id, so the first evaluation's boot detector releases the holds */
            $state = $loaded['state'];
            $state['boot_note'] = $written['skipped'] !== []
                ? 'boot: force_down on ' . implode(',', $written['skipped'])
                    . ' changed since it was read; write skipped; the first evaluation releases the holds'
                : 'boot: config write failed; the first evaluation releases the holds';
            wf_state_save(WF_STATE, $state);
        }
    }
} catch (Throwable $e) {
    $line = 'boot: the early hook failed: ' . $e->getMessage();
    wf_log($line, LOG_ERR);
    /* the line above is lost while syslog is not running: the state's boot note carries it to the first evaluation */
    try {
        $kept = wf_state_load(WF_STATE, '');
        if (!$kept['corrupt']) {
            $kept['state']['boot_note'] = $line;
            wf_state_save(WF_STATE, $kept['state']);
        }
    } catch (Throwable) {
        /* nothing more can be told: the first evaluation's boot detector still finds the boot before's id */
    }
}
exit(0);
