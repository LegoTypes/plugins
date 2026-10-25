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
 * the state file names; every other record is pruned in the same save, its gateway's force_down left as it is. With
 * the state file missing or unreadable nothing is proven and nothing is written: the first evaluation prunes the
 * records as foreign. The runtime state is reset only after the save landed: if it did not, the state keeps the old
 * boot id and evaluate's own boot detector releases the holds instead.
 */

require_once 'script/load_phalcon.php';
require_once __DIR__ . '/lib/snapshot.php';
require_once __DIR__ . '/lib/state.php';
require_once __DIR__ . '/lib/log.php';
require_once __DIR__ . '/lib/apply.php';

try {
    $bootId = wf_boot_id();
    /* read without the live boot id, so that a missing file names no boot before and proves no record */
    $loaded = wf_state_load(WF_STATE, '');
    $stateBoot = $loaded['corrupt'] ? 'corrupt' : $loaded['state']['boot_id'];
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
    $outcome = wf_boot_outcome($records['holds'], count($records['stale']) + count($records['dupes']), $stateBoot);
    $reset = wf_boot_reset($loaded['state'], $bootId);
    /* syslog is not running yet: the first evaluation logs the note */
    if ($rows === []) {
        wf_state_save(WF_STATE, $reset);
    } elseif ($stateBoot === '' || $stateBoot === 'corrupt') {
        $reset['boot_note'] = $outcome['note'];
        wf_state_save(WF_STATE, $reset);
    } else {
        /* every record goes: the boot before's released, the others pruned */
        $release = array_fill_keys($outcome['release'], false);
        $written = wf_write_holds($release, array_intersect_key($forceDown, $release), []);
        if ($written['ok']) {
            $reset['boot_note'] = $outcome['note'];
            foreach ($outcome['pruned'] as $n) {
                $reset['foreign_pruned'][$n] = time();
            }
            wf_state_save(WF_STATE, $reset);
        } elseif ($written['skipped'] !== []) {
            wf_log('boot: force_down on ' . implode(',', $written['skipped'])
                . ' changed since it was read; write skipped; the first evaluation releases the holds', LOG_WARNING);
        } else {
            wf_log('boot: config write failed; the first evaluation releases the holds', LOG_WARNING);
        }
    }
} catch (Throwable $e) {
    wf_log('boot hook failed: ' . $e->getMessage(), LOG_ERR);
}
exit(0);
