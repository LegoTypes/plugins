<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Runtime state, held reconciliation and boot reset, spec 3.8 and 3.11.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/state.php';

wf_register_suite('state', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $fd = ['PRIMARY_WAN' => false, 'WAN2' => true];

    $r = wf_reconcile(['WAN2'], $fd, [], ['WAN2']);
    wf_check($t, 'held with force_down=1 is owned', $r['owned'] === ['WAN2'] && $r['foreign'] === []);
    $r = wf_reconcile(['WAN2'], ['WAN2' => false], [], ['WAN2']);
    wf_check($t, 'held with force_down=0 was released by hand', $r['owned'] === [] && $r['manual_released'] === ['WAN2']);
    $r = wf_reconcile(['WAN2'], $fd, ['WAN2' => 'hold'], []);
    wf_check($t, 'pending hold that landed: redo replay and kill (N5a), not foreign', $r['redo_apply'] === ['WAN2']
        && $r['apply_pending'] === ['WAN2' => 'hold'] && $r['foreign'] === []);
    $r = wf_reconcile([], $fd, ['WAN2' => 'hold'], []);
    wf_check($t, 'pending hold that never saved: dropped', $r['redo_apply'] === [] && $r['apply_pending'] === []);
    $r = wf_reconcile([], ['WAN2' => false], ['WAN2' => 'release'], ['WAN2']);
    wf_check($t, 'pending release that landed: redo replay, not foreign', $r['redo_replay'] === ['WAN2'] && $r['foreign'] === []);
    $r = wf_reconcile(['WAN2'], $fd, ['WAN2' => 'release'], ['WAN2']);
    wf_check($t, 'pending release that never saved: dropped', $r['redo_replay'] === [] && $r['apply_pending'] === []);
    $r = wf_reconcile(['WAN2'], $fd, [], []);
    wf_check($t, 'held gained outside the engine (a revert): foreign (R3-8)', $r['foreign'] === ['WAN2']);
    $r = wf_reconcile([], $fd, [], ['WAN2']);
    wf_check($t, 'held lost outside the engine: foreign', $r['foreign'] === ['WAN2']);
    $r = wf_reconcile(['GONE'], $fd, [], ['GONE']);
    wf_check($t, 'a held name with no gateway in config is neither owned nor manual', $r['owned'] === [] && $r['manual_released'] === []);

    $s = wf_state_new(500);
    $s['installed_at'] = 400;
    $s['judgements']['WAN2'] = ['value' => 'bad'];
    $s['apply_pending'] = ['WAN2' => 'hold'];
    $s['last_held'] = ['WAN2'];
    $b = wf_boot_reset($s, 900);
    wf_check($t, 'boot reset clears judgements, apply_pending, last_held; keeps installed_at', $b['judgements'] === []
        && $b['apply_pending'] === [] && $b['last_held'] === [] && $b['installed_at'] === 400 && $b['boot_time'] === 900);

    $dir = sys_get_temp_dir() . '/wf-test-' . getmypid();
    $path = "{$dir}/state.json";
    wf_state_save($path, $s);
    $l = wf_state_load($path, 500);
    wf_check($t, 'save creates the directory and round-trips', !$l['corrupt'] && $l['state']['apply_pending'] === ['WAN2' => 'hold']);
    file_put_contents($path, '{"version":2,"judgements":');
    $l = wf_state_load($path, 500);
    wf_check($t, 'RF2: truncated file loads fresh, flagged corrupt', $l['corrupt'] && $l['state']['judgements'] === []);
    file_put_contents($path, '{"version":1,"holds":{}}');
    $l = wf_state_load($path, 500);
    wf_check($t, 'an older state version loads fresh, flagged corrupt', $l['corrupt'] && $l['state']['version'] === 2);
    unlink($path);
    $l = wf_state_load($path, 500);
    wf_check($t, 'missing file loads fresh, not corrupt', !$l['corrupt'] && $l['state']['boot_time'] === 500);
    @rmdir($dir);
    return wf_tally_report('state', $t);
});
