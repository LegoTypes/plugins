#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Emits enabled WireGuard IPv6 gateway mappings for wgipv6gw.sh.
 */

require "/usr/local/opnsense/mvc/script/load_phalcon.php";

function sanitizeField($value): string
{
    return str_replace(["|", "\r", "\n"], ' ', trim((string)$value));
}

$mdl = new OPNsense\WGIPv6Gateway\WGIPv6Gateway();
if ((string)$mdl->enabled !== '1') {
    exit(0);
}

$routingMdl = new OPNsense\Routing\Gateways();
$gatewaysByName = $routingMdl->gatewaysIndexedByName();

foreach ($mdl->gateways->gateway->iterateItems() as $uuid => $item) {
    if ((string)$item->enabled !== '1') {
        continue;
    }

    $ipv4Ref = (string)$item->ipv4_gateway;
    $ipv4Gw = $routingMdl->getNodeByReference('gateway_item.' . $ipv4Ref);
    if ($ipv4Gw == null) {
        continue;
    }

    $ipv4Name = (string)$ipv4Gw->name;
    $devName = $gatewaysByName[$ipv4Name]['if'] ?? '';
    $ipv6Address = (string)$item->ipv6_address;
    $ipv6Gateway = (string)$item->ipv6_gw_address;
    $description = (string)$item->description;
    if ($description === '') {
        $description = $ipv4Name . '-ipv6';
    }

    if ($devName === '' || $ipv6Address === '' || $ipv6Gateway === '') {
        continue;
    }

    echo implode('|', [
        '1',
        sanitizeField($devName),
        sanitizeField($ipv6Address),
        sanitizeField($ipv6Gateway),
        sanitizeField($ipv4Name),
        sanitizeField($description),
    ]) . PHP_EOL;
}
