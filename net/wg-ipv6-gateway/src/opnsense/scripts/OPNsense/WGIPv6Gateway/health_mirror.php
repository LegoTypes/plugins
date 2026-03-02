#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Health mirror daemon: watches IPv4 WireGuard gateway dpinger status
 * and toggles the corresponding IPv6 gateway's disabled state.
 * Runs as a cron job every 10 seconds.
 */

require "/usr/local/opnsense/mvc/script/load_phalcon.php";

use OPNsense\Core\Config;

$logTag = 'wgipv6gw-health';

function logMsg($tag, $msg) {
    syslog(LOG_NOTICE, "[$tag] $msg");
}

// Read our plugin config to get mappings
$mdl = new OPNsense\WGIPv6Gateway\WGIPv6Gateway();
if ((string)$mdl->enabled !== '1') {
    exit(0);
}

$routingMdl = new OPNsense\Routing\Gateways();
$configChanged = false;

foreach ($mdl->gateways->gateway->iterateItems() as $uuid => $item) {
    if ((string)$item->enabled !== '1') {
        continue;
    }

    $ipv4Ref = (string)$item->ipv4_gateway;

    // Resolve IPv4 gateway name
    $ipv4Gw = $routingMdl->getNodeByReference('gateway_item.' . $ipv4Ref);
    if ($ipv4Gw == null) {
        continue;
    }
    $ipv4Name = (string)$ipv4Gw->name;
    $ipv6GwName = $ipv4Name . '-ipv6';

    // Check IPv4 dpinger status
    $sock = "/var/run/dpinger_{$ipv4Name}.sock";
    $ipv4Up = false;
    if (file_exists($sock)) {
        $fp = @stream_socket_client("unix://{$sock}", $errno, $errstr, 1);
        if ($fp) {
            fwrite($fp, "\n");
            $line = fgets($fp, 1024);
            fclose($fp);
            if ($line) {
                $parts = preg_split('/\s+/', trim($line));
                $loss = end($parts);
                if (is_numeric($loss) && (int)$loss < 100) {
                    $ipv4Up = true;
                }
            }
        }
    }

    // Find the corresponding IPv6 gateway and toggle force_down state
    foreach ($routingMdl->gateway_item->iterateItems() as $gwUuid => $gw6) {
        if ((string)$gw6->name === $ipv6GwName) {
            $currentForceDown = (string)$gw6->force_down;
            $shouldForceDown = $ipv4Up ? '0' : '1';

            if ($currentForceDown !== $shouldForceDown) {
                $gw6->force_down = $shouldForceDown;
                $configChanged = true;
                $state = $ipv4Up ? 'online' : 'force_down';
                logMsg($logTag, "{$ipv6GwName}: {$state} (IPv4 {$ipv4Name} " . ($ipv4Up ? 'up' : 'down') . ")");
            }
            break;
        }
    }
}

if ($configChanged) {
    $routingMdl->serializeToConfig();
    Config::getInstance()->save();
    // Trigger gateway reconfiguration so dpinger/groups pick up the change
    (new OPNsense\Core\Backend())->configdRun('interface routes configure');
}
