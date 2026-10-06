#!/usr/local/bin/php
<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Early-boot release (spec 2026-10-05 section 3.11). Nobody knows how long the firewall was down or
 * whether the modems rebooted too, so every held gateway is released before routing starts, in one
 * config save without a backup. The runtime state is reset only after that save landed: if it did not,
 * the state keeps the old boot time and evaluate's own boot detector releases the holds instead.
 */

const WF_STATE = '/var/db/wanfailover/state.json';

require_once 'script/load_phalcon.php';
require_once __DIR__ . '/lib/snapshot.php';
require_once __DIR__ . '/lib/state.php';
require_once __DIR__ . '/lib/log.php';
require_once __DIR__ . '/lib/apply.php';

try {
    $bootTime = wf_boot_time();
    $state = wf_state_load(WF_STATE, $bootTime)['state'];
    $heldUuids = wf_model_list((new \OPNsense\WanFailover\WanFailover())->held);
    $nameByUuid = [];
    foreach ((new \OPNsense\Routing\Gateways())->gatewaysIndexedByName(true) as $name => $g) {
        if (!empty($g['uuid'])) {
            $nameByUuid[(string)$g['uuid']] = (string)$name;
        }
    }
    $names = wf_resolve_uuids($heldUuids, $nameByUuid)['names'];
    if ($heldUuids === []) {
        wf_state_save(WF_STATE, wf_boot_reset($state, $bootTime));
    } elseif (wf_write_holds(array_fill_keys($names, false), [])) {
        /* syslog is not running yet: the first evaluation logs this note */
        $reset = wf_boot_reset($state, $bootTime);
        $reset['boot_note'] = 'boot: released ' . (implode(',', $names) ?: 'stale held entries');
        wf_state_save(WF_STATE, $reset);
    } else {
        wf_log('boot: config write failed; the first evaluation releases the holds', LOG_WARNING);
    }
} catch (Throwable $e) {
    wf_log('boot hook failed: ' . $e->getMessage(), LOG_ERR);
}
exit(0);
