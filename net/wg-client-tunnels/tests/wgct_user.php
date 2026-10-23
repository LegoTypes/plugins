<?php

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Test VM only, never a firewall: a GUI user with an API key, through core's User model, for the VM tests that call
 * the plugin's API (wgct_api.sh, wgct_migrate.sh). The caller syncs it (configctl auth sync user NAME).
 *
 * Usage: wgct_user.php create NAME PRIVS   prints "key:secret"
 *        wgct_user.php delete NAME
 */

require_once 'config.inc';
require_once '/usr/local/opnsense/mvc/script/load_phalcon.php';

use OPNsense\Auth\User;
use OPNsense\Core\Config;

[, $mode, $name] = $argv;
Config::getInstance()->lock();
$model = new User();
if ($mode === 'create') {
    $user = $model->user->Add();
    $user->name = $name;
    $user->scope = 'user';
    $user->password = $model->generatePasswordHash(bin2hex(random_bytes(24)));
    $user->priv = $argv[3];
    $key = $user->apikeys->add();
    foreach ($model->performValidation() as $msg) {
        fwrite(STDERR, $msg->getMessage() . "\n");
        Config::getInstance()->unlock();
        exit(1);
    }
    $model->serializeToConfig(false, true);
    Config::getInstance()->save();
    echo $key['key'], ':', $key['secret'], "\n";
    exit(0);
}
foreach ($model->user->iterateItems() as $uuid => $node) {
    if ((string)$node->name === $name) {
        $model->user->del($uuid);
    }
}
$model->serializeToConfig(false, true);
Config::getInstance()->save();
