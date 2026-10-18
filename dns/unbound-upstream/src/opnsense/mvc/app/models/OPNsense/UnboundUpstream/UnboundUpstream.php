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

namespace OPNsense\UnboundUpstream;

use OPNsense\Base\BaseModel;
use OPNsense\Base\Messages\Message;
use OPNsense\Routing\GatewayGroups;
use OPNsense\Routing\Gateways;
use OPNsense\Routes\Route;

class UnboundUpstream extends BaseModel
{
    /**
     * Cross-field checks that need the gateway and route models run only while the plugin is enabled.
     *
     * @param bool $validateFullModel
     * @return \OPNsense\Base\Messages\MessageCollection|\Phalcon\Messages\Messages
     */
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);

        if (!$this->enabled->isEqual('1')) {
            return $messages;
        }
        if ($this->gateway_group->isEmpty()) {
            $messages->appendMessage(new Message(gettext('Select a gateway group.'), $this->gateway_group->__reference));
        } else {
            $this->checkGroup($messages);
        }
        if ($this->resolver->isEmpty()) {
            $messages->appendMessage(new Message(gettext('Enter the resolver address.'), $this->resolver->__reference));
        } else {
            $this->checkResolver($messages);
        }
        return $messages;
    }

    /**
     * Group members by gateway name, from the group the UUID names.
     *
     * @return array<string, string>|null member names keyed by themselves, null when the group is gone
     */
    private function groupMembers(): ?array
    {
        $uuid = $this->gateway_group->getValue();
        foreach ((new GatewayGroups())->gateway_group->iterateItems() as $key => $group) {
            if ($key !== $uuid) {
                continue;
            }
            $members = [];
            foreach (['item', 'item2', 'item3', 'item4', 'item5'] as $tier) {
                foreach (explode(',', $group->$tier->getValue()) as $entry) {
                    $name = explode('|', $entry)[0];
                    if ($name !== '') {
                        $members[$name] = $name;
                    }
                }
            }
            return $members;
        }
        return null;
    }

    private function checkGroup(object $messages): void
    {
        $field = $this->gateway_group->__reference;
        $members = $this->groupMembers();
        if ($members === null || $members === []) {
            $messages->appendMessage(new Message(gettext('The selected gateway group has no members.'), $field));
            return;
        }
        $gateways = (new Gateways())->gatewaysIndexedByName(true);
        $longest = 0;
        foreach ($members as $name) {
            $gw = $gateways[$name] ?? null;
            if ($gw === null || !empty($gw['monitor_disable'])) {
                $messages->appendMessage(new Message(
                    sprintf(gettext('Gateway %s is not monitored; every member of the group must be.'), $name),
                    $field
                ));
                continue;
            }
            $longest = max($longest, (int)($gw['current_time_period'] ?? 0));
        }
        $delay = (int)$this->failback_delay->getValue();
        if ($delay < $longest) {
            $messages->appendMessage(new Message(
                sprintf(
                    gettext('Failback delay %d is shorter than the longest member time period, %d seconds.'),
                    $delay,
                    $longest
                ),
                $this->failback_delay->__reference
            ));
        }
    }

    private function checkResolver(object $messages): void
    {
        $field = $this->resolver->__reference;
        $addr = $this->resolver->getValue();
        $long = ip2long($addr);
        if ($long === false) {
            return; /* the field's own validation reports it */
        }
        foreach ((new Gateways())->gatewaysIndexedByName(true) as $name => $gw) {
            if (($gw['monitor'] ?? '') === $addr) {
                $messages->appendMessage(new Message(
                    sprintf(gettext('Resolver %s is the monitor address of gateway %s.'), $addr, $name),
                    $field
                ));
            }
        }
        foreach ((new Route())->route->iterateItems() as $route) {
            if (!$route->enabled->isEqual('1')) {
                continue;
            }
            $parts = explode('/', $route->network->getValue());
            $net = ip2long($parts[0]);
            $bits = (int)($parts[1] ?? 32);
            if ($net === false || $bits < 0 || $bits > 32) {
                continue; /* an IPv6 route, or one the Route model refuses */
            }
            /* the same arithmetic as uu_ipv4_in_network() in the scripts' lib/snapshot.php, which the model does not
             * load (it would pull the scripts tree into every page that saves this model) */
            $mask = $bits === 0 ? 0 : (-1 << (32 - $bits)) & 0xFFFFFFFF;
            if (($long & $mask) === ($net & $mask)) {
                $messages->appendMessage(new Message(
                    sprintf(gettext('Resolver %s lies inside the static route %s.'), $addr, $route->network->getValue()),
                    $field
                ));
            }
        }
    }
}
