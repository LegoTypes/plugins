<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
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

namespace OPNsense\WGIPv6Gateway\Api;

use OPNsense\Base\ApiMutableModelControllerBase;
use OPNsense\Core\Config;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelName = 'wgipv6gateway';
    protected static $internalModelClass = '\OPNsense\WGIPv6Gateway\WGIPv6Gateway';

    public function searchGatewayAction()
    {
        $result = $this->searchBase('gateways.gateway', [
            'enabled', 'description', 'ipv4_gateway', 'ipv6_gw_address', 'ipv6_address'
        ]);
        // Resolve IPv4 gateway UUID to display name
        if (!empty($result['rows'])) {
            $routingMdl = new \OPNsense\Routing\Gateways();
            foreach ($result['rows'] as &$row) {
                if (!empty($row['ipv4_gateway'])) {
                    $node = $routingMdl->getNodeByReference('gateway_item.' . $row['ipv4_gateway']);
                    if ($node != null) {
                        $row['ipv4_gateway'] = (string)$node->name;
                    }
                }
            }
        }
        return $result;
    }

    public function getGatewayAction($uuid = null)
    {
        return $this->getBase('gateway', 'gateways.gateway', $uuid);
    }

    public function addGatewayAction()
    {
        return $this->addBase('gateway', 'gateways.gateway');
    }

    public function setGatewayAction($uuid)
    {
        return $this->setBase('gateway', 'gateways.gateway', $uuid);
    }

    public function delGatewayAction($uuid)
    {
        return $this->delBase('gateways.gateway', $uuid);
    }

    /**
     * Given an IPv4 gateway UUID, resolve the WireGuard tunnel info:
     * - interface device name (wg0, wg1, ...)
     * - IPv6 tunnel address from the WG instance
     * - derived IPv6 gateway hop address
     * - whether an existing IPv6 gateway already exists for this interface
     */
    public function resolveWgInfoAction($uuid)
    {
        $result = [
            'ipv4_name' => '',
            'interface' => '',
            'ipv6_address' => '',
            'ipv6_gw_address' => '',
            'existing_gw_name' => '',
            'description' => ''
        ];

        // Resolve IPv4 gateway to get interface
        $routingMdl = new \OPNsense\Routing\Gateways();
        $gw = $routingMdl->getNodeByReference('gateway_item.' . $uuid);
        if ($gw == null) {
            return $result;
        }

        $ipv4Name = (string)$gw->name;
        $ifaceId = (string)$gw->interface;
        $result['ipv4_name'] = $ipv4Name;
        $result['description'] = $ipv4Name . '-ipv6';

        // Get device name from interface config
        $config = Config::getInstance()->object();
        $ifNode = $config->interfaces->$ifaceId ?? null;
        if ($ifNode == null) {
            return $result;
        }
        $devName = (string)$ifNode->if;
        $result['interface'] = $devName;

        // Find WireGuard instance matching this device
        if (strpos($devName, 'wg') === 0) {
            $wgInstance = substr($devName, 2); // wg1 -> 1
            $wgMdl = new \OPNsense\Wireguard\Server();
            foreach ($wgMdl->servers->server->iterateItems() as $srvUuid => $srv) {
                if ((string)$srv->instance === $wgInstance) {
                    $tunnelAddr = (string)$srv->tunneladdress;
                    // Extract IPv6 address from comma-separated tunnel addresses
                    foreach (explode(',', $tunnelAddr) as $addr) {
                        $addr = trim($addr);
                        if (strpos($addr, ':') !== false) {
                            $result['ipv6_address'] = $addr;
                            // Derive gateway hop: last hex group + 1
                            $addrOnly = explode('/', $addr)[0];
                            $bin = @inet_pton($addrOnly);
                            if ($bin !== false) {
                                $expanded = inet_ntop($bin);
                                $groups = explode(':', $expanded);
                                $last = hexdec($groups[count($groups) - 1]);
                                $groups[count($groups) - 1] = dechex($last + 1);
                                $derived = inet_ntop(inet_pton(implode(':', $groups)));
                                $result['ipv6_gw_address'] = $derived;
                            }
                        }
                    }
                    break;
                }
            }
        }

        // Check if an existing IPv6 gateway already exists for this interface
        foreach ($routingMdl->gateway_item->iterateItems() as $gwUuid => $existGw) {
            if ((string)$existGw->ipprotocol === 'inet6' && (string)$existGw->interface === $ifaceId) {
                $result['existing_gw_name'] = (string)$existGw->name;
                // Use the existing gateway's address instead of derived
                $existAddr = (string)$existGw->gateway;
                if (!empty($existAddr)) {
                    $result['ipv6_gw_address'] = $existAddr;
                }
                break;
            }
        }

        return $result;
    }

    /**
     * Ensure IPv6 gateway objects exist in System -> Gateways for all enabled mappings.
     * Called during reconfigure.
     */
    public function ensureGatewayObjectsAction()
    {
        $mdl = $this->getModel();
        $routingMdl = new \OPNsense\Routing\Gateways();
        $created = [];

        foreach ($mdl->gateways->gateway->iterateItems() as $uuid => $item) {
            if ((string)$item->enabled !== '1') {
                continue;
            }

            $ipv4Ref = (string)$item->ipv4_gateway;
            $ipv6GwAddr = (string)$item->ipv6_gw_address;

            // Resolve IPv4 gateway
            $ipv4Gw = $routingMdl->getNodeByReference('gateway_item.' . $ipv4Ref);
            if ($ipv4Gw == null || empty($ipv6GwAddr)) {
                continue;
            }

            $ipv4Name = (string)$ipv4Gw->name;
            $ifaceId = (string)$ipv4Gw->interface;
            $gwName = $ipv4Name . '-ipv6';

            // Check if IPv6 gateway already exists
            $exists = false;
            foreach ($routingMdl->gateway_item->iterateItems() as $gwUuid => $existGw) {
                if ((string)$existGw->name === $gwName) {
                    $exists = true;
                    break;
                }
            }

            if (!$exists) {
                // Find a unique loopback monitor address
                $usedMonitors = [];
                foreach ($routingMdl->gateway_item->iterateItems() as $gwUuid2 => $existGw2) {
                    $m = (string)$existGw2->monitor;
                    if (!empty($m)) {
                        $usedMonitors[$m] = true;
                    }
                }
                $monIdx = 1;
                while (isset($usedMonitors["::$monIdx"])) {
                    $monIdx++;
                }

                $newGw = $routingMdl->gateway_item->Add();
                $newGw->name = $gwName;
                $newGw->interface = $ifaceId;
                $newGw->ipprotocol = 'inet6';
                $newGw->gateway = $ipv6GwAddr;
                $newGw->monitor_disable = '0';
                $newGw->monitor = "::$monIdx";
                $newGw->force_down = '0';
                $newGw->priority = '255';
                $newGw->disabled = '0';
                $routingMdl->serializeToConfig();
                Config::getInstance()->save();
                $created[] = $gwName;
            }
        }

        return ['status' => 'ok', 'created' => $created];
    }
}
