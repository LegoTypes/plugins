#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Run this plugin's model migrations under Config::lock(), so the migration
 * reads the rows and saves in one locked window (core's run_migrations.php
 * saves without the lock). The deploy runs it before anything can serialize
 * the new model, because serializing drops the old rows unread.
 *
 * Usage: migrate.php
 */

require "/usr/local/opnsense/mvc/script/load_phalcon.php";

use OPNsense\Core\Config;

$cfg = Config::getInstance();
$cfg->lock();
try {
    $mdl = new OPNsense\WGIPv6Gateway\WGIPv6Gateway(true);
    $before = $mdl->getVersion();
    $ok = $mdl->runMigrations();
    $after = $mdl->getVersion();
    if ($before !== $after && $ok) {
        $cfg->save();
    }
} finally {
    $cfg->unlock();
}
/* exit() skips finally blocks, so report and exit only after unlocking */
if ($before === $after) {
    echo "WGIPv6Gateway already at {$after}\n";
    exit(0);
}
if (!$ok) {
    fwrite(STDERR, "WGIPv6Gateway migration {$before} -> {$after} FAILED (see syslog)\n");
    exit(1);
}
echo "WGIPv6Gateway migrated {$before} -> {$after}\n";
