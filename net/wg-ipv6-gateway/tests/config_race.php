#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Race test for wgipv6_locked_commit(). Run on the firewall as root, with the
 * plugin deployed. It changes the `descr` field of the two core sentinel
 * gateways NO_DEFAULT4 and NO_DEFAULT6 (OPNsense\Routing\Gateways model,
 * gateway_item entries found by name) and restores them. `descr` is cosmetic
 * and read by no logic, so this is safe to run against the live config.
 *
 *   php config_race.php                 run the test
 *   php config_race.php --set=IDX:TEXT  (child) locked write of one row
 *                                        (IDX 0 = NO_DEFAULT4, 1 = NO_DEFAULT6)
 *   php config_race.php --read          (child) print the descriptions as JSON
 *
 * Exit 0: all checks passed. Exit 1: a check failed. Exit 2: the test itself
 * could not run (a child process failed, or either sentinel gateway is
 * missing) -- originals are restored in every case the restore itself can run.
 */

require '/usr/local/opnsense/mvc/script/load_phalcon.php';
require_once '/usr/local/opnsense/scripts/OPNsense/WGIPv6Gateway/lib/mirror.php';

use OPNsense\Core\Config;
use OPNsense\Routing\Gateways;

const RACE_NAMES = ['NO_DEFAULT4', 'NO_DEFAULT6'];

function race_find(Gateways $mdl, $name) {
    foreach ($mdl->gateway_item->iterateItems() as $item) {
        if ((string)$item->name === $name) {
            return $item;
        }
    }
    return null;
}

function race_set_locked($idx, $text) {
    wgipv6_locked_commit(function () use ($idx, $text) {
        $mdl = new Gateways();
        $node = race_find($mdl, RACE_NAMES[$idx]);
        $node->descr = $text;
        $mdl->serializeToConfig();
        return ['save' => true];
    });
}

/* A separate process, so its write is a genuinely concurrent one. */
function race_child(array $args) {
    $cmd = implode(' ', array_map('escapeshellarg', array_merge(['/usr/local/bin/php', __FILE__], $args)));
    exec($cmd, $out, $rc);
    if ($rc !== 0) {
        throw new RuntimeException('child failed: ' . implode(' ', $args));
    }
    return implode("\n", $out);
}

function race_read() {
    return json_decode(race_child(['--read']), true);
}

$opt = getopt('', ['set:', 'read']);
if (isset($opt['read'])) {
    $mdl = new Gateways();
    $out = [];
    foreach (RACE_NAMES as $name) {
        $node = race_find($mdl, $name);
        $out[] = $node !== null ? (string)$node->descr : null;
    }
    echo json_encode($out);
    exit(0);
}
if (isset($opt['set'])) {
    [$idx, $text] = explode(':', $opt['set'], 2);
    race_set_locked((int)$idx, $text);
    exit(0);
}

$orig = race_read();
if (!is_array($orig) || count($orig) < 2 || $orig[0] === null || $orig[1] === null) {
    fwrite(STDERR, "needs both core gateways NO_DEFAULT4 and NO_DEFAULT6\n");
    exit(2);
}
$fail = 0;
$crashed = false;
try {
    /* Control: the old pattern -- load, a concurrent write lands, save the
     * snapshot -- loses the concurrent write. If it does not, this test
     * cannot tell the fix from no fix. */
    $stale = new Gateways();
    race_child(['--set=0:race-A']);
    race_find($stale, 'NO_DEFAULT6')->descr = 'race-B';
    $stale->serializeToConfig();
    Config::getInstance()->save();
    $now = race_read();
    $lost = $now[0] !== 'race-A' && $now[1] === 'race-B';
    printf("[%s] control: a stale save loses a concurrent write (row0=%s row1=%s)\n",
        $lost ? 'PASS' : 'FAIL', $now[0], $now[1]);
    $fail += $lost ? 0 : 1;

    /* Fix: the same interleaving through wgipv6_locked_commit keeps both.
     * This process's in-memory config is stale again once the child writes. */
    race_child(['--set=0:race-C']);
    race_set_locked(1, 'race-D');
    $now = race_read();
    $kept = $now[0] === 'race-C' && $now[1] === 'race-D';
    printf("[%s] locked commit keeps the concurrent write (row0=%s row1=%s)\n",
        $kept ? 'PASS' : 'FAIL', $now[0], $now[1]);
    $fail += $kept ? 0 : 1;
} catch (Throwable $e) {
    fwrite(STDERR, 'ERROR: ' . $e->getMessage() . "\n");
    $fail++;
    $crashed = true;
} finally {
    race_set_locked(0, $orig[0]);
    race_set_locked(1, $orig[1]);
    $back = race_read();
    printf("[%s] original descriptions restored\n", $back === $orig ? 'PASS' : 'FAIL');
    $fail += $back === $orig ? 0 : 1;
}
exit($crashed ? 2 : ($fail === 0 ? 0 : 1));
