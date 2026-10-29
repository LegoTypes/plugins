#!/usr/local/bin/php
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
 * Early-boot release: every hold the plugin took is released before routing starts, in one config save without a
 * backup, since nobody knows how long the firewall was down or whether the modems rebooted too. A record proves a hold
 * only by the boot before's id, the one the state file names; every other record is pruned in the same save, its
 * gateway's force_down left as it is. 1.3_1's held list goes in the same save, the entries the state proves released
 * (wf_boot_legacy()). With the state file missing or unreadable nothing is written. The state is reset only once the
 * save landed; otherwise it keeps the boot before's id, so evaluate's boot detector releases the holds. Every outcome
 * goes in the state's boot note, which the first evaluation logs. While the removal's marker exists it writes nothing.
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
            $state['boot_note'] = "boot: {$written['problem']}; nothing written, and the first evaluation releases the holds";
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
