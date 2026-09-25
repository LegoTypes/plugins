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
 * that section (Migrations/M3_0_0.php, lib/migration.php). The deploy runs
 * it, and so does `wgct.sh reconcile` when config holds the old section and
 * no section of this model (a Config History revert to a pre-3.0 revision).
 *
 * Usage: migrate.php [--dry]
 *   --dry  print what the migration takes from the old section -- switches as
 *          0/1 and list sizes, never a uuid -- and write nothing; exit 1 when
 *          it would refuse. Once this model is already at 3.0.0 it prints
 *          "nothing to migrate", or, when the old section is still there, a
 *          line starting "WARNING:" that names it stale, and exits 0. It loads
 *          core's load_phalcon.php and, from beside this script,
 *          lib/migration.php and lib/selftest.php, so the deploy runs the
 *          staged copy against live config before installing anything.
 *
 * Without --dry the migration loads the installed lib/migration.php
 * (Migrations/M3_0_0.php), never the copy beside this script: a staged copy
 * loaded as well would redeclare its functions. Exit 0 when migrated or
 * already at 3.0.0, 1 when the migration failed. Already at 3.0.0 with the
 * old section still there, it also writes a "WARNING:" line to stderr: no
 * migration applies that section, and it stays until removed by hand.
 */

require "/usr/local/opnsense/mvc/script/load_phalcon.php";

use OPNsense\Core\Config;

/* the library M3_0_0 loads; the non-dry path reads the stale check from the same file */
const WGCT_INSTALLED_MIGRATION_LIB = '/usr/local/opnsense/scripts/OPNsense/WGClientTunnels/lib/migration.php';

if (in_array('--dry', $argv ?? [], true)) {
    require_once __DIR__ . '/lib/migration.php';
    $root = Config::getInstance()->object();
    $report = wgct_dry_report(wgct_read_model_version($root), wgct_read_legacy_node($root));
    echo $report['text'], "\n";
    exit($report['rc']);
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
    if (!is_readable(WGCT_INSTALLED_MIGRATION_LIB)) {
        fwrite(STDERR, 'WARNING: cannot check for a stale old section: missing ' . WGCT_INSTALLED_MIGRATION_LIB . "\n");
        exit(0);
    }
    require_once WGCT_INSTALLED_MIGRATION_LIB;
    $warning = wgct_stale_legacy_warning($after, wgct_read_legacy_node($cfg->object()));
    if ($warning !== null) {
        fwrite(STDERR, $warning . "\n");
    }
    exit(0);
}
if (!$ok) {
    fwrite(STDERR, "WGClientTunnels migration {$before} -> {$after} FAILED (see syslog [wgct-migrate])\n");
    exit(1);
}
echo "WGClientTunnels migrated {$before} -> {$after}\n";
