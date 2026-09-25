#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Run this plugin's model migration under Config::lock(), so it reads and
 * saves in one locked window (core's run_migrations.php saves without the
 * lock). Model 3.0.0 copies the os-wg-ipv6-gateway 2.x settings and removes
 * that section (Migrations/M3_0_0.php, lib/migration.php).
 *
 * Usage: migrate.php [--dry]
 *   --dry  print what the migration takes from the old section -- switches as
 *          0/1 and list sizes, never a uuid -- and write nothing; exit 1 when
 *          it would refuse. Needs only lib/migration.php beside it, so the
 *          deploy runs the staged copy before installing anything.
 */

require "/usr/local/opnsense/mvc/script/load_phalcon.php";
require_once __DIR__ . '/lib/migration.php';

use OPNsense\Core\Config;

if (in_array('--dry', $argv ?? [], true)) {
    $plan = wgct_legacy_settings(wgct_read_legacy_node(Config::getInstance()->object()));
    echo wgct_migration_summary($plan), "\n";
    exit($plan['error'] === null ? 0 : 1);
}

$cfg = Config::getInstance();
$cfg->lock();
try {
    $mdl = new OPNsense\WGClientTunnels\WGClientTunnels(true);
    $before = $mdl->getVersion();
    $ok = $mdl->runMigrations();
    $after = $mdl->getVersion();
    if ($before !== $after && $ok) {
        $cfg->save(['description' => "wg client tunnels: model {$after} migration"]);
    }
} finally {
    $cfg->unlock();
}
/* exit() skips finally blocks, so report and exit only after unlocking */
if ($before === $after) {
    echo "WGClientTunnels already at {$after}\n";
    exit(0);
}
if (!$ok) {
    fwrite(STDERR, "WGClientTunnels migration {$before} -> {$after} FAILED (see syslog [wgct-migrate])\n");
    exit(1);
}
echo "WGClientTunnels migrated {$before} -> {$after}\n";
