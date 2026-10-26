<?php

/*
 * Copyright (C) 2026 cayossarian
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
use OPNsense\Core\Config;
use OPNsense\Firewall\Util;
use OPNsense\Routing\GatewayGroups;
use OPNsense\Routing\Gateways;
use OPNsense\Routes\Route;

class UnboundUpstream extends BaseModel
{
    /**
     * Cross-field checks that need the gateway and route models run only while the plugin is enabled; the notify
     * URL is required whenever notify is on.
     *
     * @param bool $validateFullModel
     * @return \OPNsense\Base\Messages\MessageCollection|\Phalcon\Messages\Messages
     */
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);

        if ($this->notify->isEqual('1') && $this->notify_url->isEmpty()) {
            $messages->appendMessage(new Message(gettext('Enter the URL to notify.'), $this->notify_url->__reference));
        }
        if (!$this->enabled->isEqual('1')) {
            return $messages;
        }
        if ($this->gateway_group->isEmpty()) {
            $messages->appendMessage(new Message(gettext('Select a gateway group.'), $this->gateway_group->__reference));
        } else {
            $this->checkGroup($messages);
        }
        $this->checkResolvers($messages);
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

    /**
     * The Default resolver and the per-member rows, against the selected group.
     */
    private function checkResolvers(object $messages): void
    {
        $members = $this->gateway_group->isEmpty() ? null : $this->groupMembers();
        $gateways = (new Gateways())->gatewaysIndexedByName(true);
        $family = null;
        $mixed = false;
        $names = [];
        foreach (array_keys($members ?? []) as $name) {
            $proto = (string)($gateways[$name]['ipprotocol'] ?? '');
            if ($proto !== 'inet' && $proto !== 'inet6') {
                continue;
            }
            $family ??= $proto;
            $mixed = $mixed || $proto !== $family;
        }
        if ($mixed) {
            $messages->appendMessage(new Message(
                sprintf(
                    gettext('The gateway group %s has IPv4 and IPv6 members; use a group of one address family.'),
                    $this->groupName()
                ),
                $this->gateway_group->__reference
            ));
        }

        $uuidNames = [];
        foreach ((new Gateways())->gateway_item->iterateItems() as $key => $item) {
            $uuidNames[(string)$key] = $item->name->getValue();
        }
        $monitors = [];
        foreach ($gateways as $name => $gw) {
            if (($gw['monitor'] ?? '') !== '') {
                $monitors[(string)$name] = (string)$gw['monitor'];
            }
        }
        $networks = [];
        foreach ((new Route())->route->iterateItems() as $route) {
            if ($route->enabled->isEqual('1')) {
                $networks[] = $route->network->getValue();
            }
        }
        $v6 = self::ipv6Allowed();
        $group = $this->groupName();
        $family = $mixed ? null : $family;

        $covered = [];
        $seen = [];
        foreach ($this->resolvers->resolver->iterateItems() as $row) {
            $name = $uuidNames[$row->gateway->getValue()] ?? '';
            if ($name === '') {
                continue; /* the relation field reports an unknown gateway */
            }
            if ($members !== null && !isset($members[$name])) {
                $messages->appendMessage(new Message(
                    sprintf(gettext('Gateway %s is not a member of the selected group.'), $name),
                    $row->gateway->__reference
                ));
            } else {
                $covered[$name] = true;
            }
            if (isset($seen[$name])) {
                $messages->appendMessage(new Message(
                    sprintf(gettext('Gateway %s has more than one resolver row.'), $name),
                    $row->gateway->__reference
                ));
            }
            $seen[$name] = true;
            $this->appendProblems(
                $messages,
                $row->address->getValue(),
                $row->address->__reference,
                $group,
                $family,
                $v6,
                $monitors,
                $networks
            );
        }

        if ($this->resolver->isEmpty()) {
            $all = $members !== null && $members !== [];
            foreach (array_keys($members ?? []) as $name) {
                $all = $all && isset($covered[$name]);
            }
            if (!$all) {
                $messages->appendMessage(new Message(
                    gettext('Enter the default resolver address, or one for every member of the group.'),
                    $this->resolver->__reference
                ));
            }
        } else {
            $this->appendProblems(
                $messages,
                $this->resolver->getValue(),
                $this->resolver->__reference,
                $group,
                $family,
                $v6,
                $monitors,
                $networks
            );
        }
    }

    /**
     * @param array<string, string> $monitors
     * @param list<string> $networks
     */
    private function appendProblems(
        object $messages,
        string $addr,
        string $field,
        string $group,
        ?string $family,
        bool $v6,
        array $monitors,
        array $networks
    ): void {
        foreach (self::resolverProblems($addr, $group, $family ?? '', $v6, $monitors, $networks) as $problem) {
            $messages->appendMessage(new Message($problem, $field));
        }
    }

    private function groupName(): string
    {
        $uuid = $this->gateway_group->getValue();
        foreach ((new GatewayGroups())->gateway_group->iterateItems() as $key => $group) {
            if ($key === $uuid) {
                return $group->name->getValue();
            }
        }
        return '';
    }

    /**
     * Whether core lets Unbound use IPv6: the same setting is_ipv6_allowed() reads, which is stored negated and
     * counts "0" as unset.
     */
    public static function ipv6Allowed(): bool
    {
        return empty((string)Config::getInstance()->object()->OPNsense->Interfaces->settings->disableipv6);
    }

    /**
     * What is wrong with a resolver address for a group of the given family, in the order the settings page shows it.
     * Pure: the callers pass in what the box says. A string that is no address is the field's own validation.
     *
     * @param string $addr the address as entered
     * @param string $groupName the group's name, for the message
     * @param string $groupFamily 'inet' or 'inet6'; anything else skips the family check
     * @param bool $ipv6Allowed whether core lets Unbound use IPv6
     * @param array<string, string> $monitors gateway name => monitor address
     * @param list<string> $networks the enabled static routes' networks
     * @return list<string>
     */
    public static function resolverProblems(
        string $addr,
        string $groupName,
        string $groupFamily,
        bool $ipv6Allowed,
        array $monitors,
        array $networks
    ): array {
        $packed = inet_pton($addr);
        if ($packed === false) {
            return [];
        }
        $v6 = strlen($packed) === 16;
        if (self::unusable($packed)) {
            return [gettext('Enter a resolver address that is not link-local, multicast, loopback or unspecified.')];
        }
        $canonical = (string)inet_ntop($packed);
        $problems = [];
        if ($groupFamily === 'inet6' && !$v6) {
            $problems[] = sprintf(gettext('The group %s is IPv6; its resolvers must be IPv6 addresses.'), $groupName);
        } elseif ($groupFamily === 'inet' && $v6) {
            $problems[] = sprintf(gettext('The group %s is IPv4; its resolvers must be IPv4 addresses.'), $groupName);
        }
        if ($v6 && !$ipv6Allowed) {
            $problems[] = gettext('Unbound does not use IPv6 while IPv6 is not allowed.');
        }
        foreach ($monitors as $name => $monitor) {
            $theirs = inet_pton($monitor);
            if ($theirs !== false && inet_ntop($theirs) === $canonical) {
                $problems[] = sprintf(gettext('Resolver %s is the monitor address of gateway %s.'), $canonical, $name);
            }
        }
        foreach ($networks as $network) {
            $cidr = str_contains($network, '/') ? $network : $network . (str_contains($network, ':') ? '/128' : '/32');
            if (Util::isIPInCIDR($canonical, $cidr)) {
                $problems[] = sprintf(gettext('Resolver %s lies inside the static route %s.'), $canonical, $network);
            }
        }
        return $problems;
    }

    /**
     * Link-local, multicast, loopback, unspecified and IPv4-mapped addresses, from an address in packed form.
     */
    private static function unusable(string $packed): bool
    {
        if (strlen($packed) === 4) {
            $first = ord($packed[0]);
            return $first === 127 || $first >= 224 || $packed === "\0\0\0\0"
                || ($first === 169 && ord($packed[1]) === 254);
        }
        return $packed === str_repeat("\0", 16) || $packed === str_repeat("\0", 15) . "\x01"
            || str_starts_with($packed, str_repeat("\0", 10) . "\xff\xff")
            || (ord($packed[0]) === 0xfe && (ord($packed[1]) & 0xc0) === 0x80) || ord($packed[0]) === 0xff;
    }
}
