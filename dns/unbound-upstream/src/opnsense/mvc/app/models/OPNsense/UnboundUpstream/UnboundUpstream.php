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
use OPNsense\Interfaces\Settings;
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
        $gateways = new Gateways();
        if ($this->gateway_group->isEmpty()) {
            $messages->appendMessage(new Message(gettext('Select a gateway group.'), $this->gateway_group->__reference));
        } else {
            $this->checkGroup($messages, $gateways);
        }
        $this->checkResolvers($messages, $gateways);
        return $messages;
    }

    /**
     * The group the UUID names: its name and its members by gateway name, in tier order.
     *
     * @return array{name: string, members: array<string, string>}|null members keyed by themselves, null when the
     *         group is gone
     */
    private function findGroup(): ?array
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
            return ['name' => $group->name->getValue(), 'members' => $members];
        }
        return null;
    }

    private function checkGroup(object $messages, Gateways $model): void
    {
        $field = $this->gateway_group->__reference;
        $members = $this->findGroup()['members'] ?? null;
        if ($members === null || $members === []) {
            $messages->appendMessage(new Message(gettext('The selected gateway group has no members.'), $field));
            return;
        }
        $gateways = $model->gatewaysIndexedByName(true);
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
    private function checkResolvers(object $messages, Gateways $model): void
    {
        $found = $this->gateway_group->isEmpty() ? null : $this->findGroup();
        $members = $found['members'] ?? null;
        $group = $found['name'] ?? '';
        $gateways = $model->gatewaysIndexedByName(true);
        $protos = [];
        foreach (array_keys($members ?? []) as $name) {
            $protos[] = (string)($gateways[$name]['ipprotocol'] ?? '');
        }
        $family = self::groupFamily($protos);
        foreach (self::groupProblems($group, (string)$family) as $problem) {
            $messages->appendMessage(new Message($problem, $this->gateway_group->__reference));
        }
        $family = $family === 'inet' || $family === 'inet6' ? $family : '';

        $uuidNames = [];
        foreach ($model->gateway_item->iterateItems() as $key => $item) {
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

        $covered = [];
        $seen = [];
        foreach ($this->resolvers->resolver->iterateItems() as $row) {
            /* a gateway deleted since the row was saved is no member either: the UUID stands in for its name */
            $name = $uuidNames[$row->gateway->getValue()] ?? $row->gateway->getValue();
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
        string $family,
        bool $v6,
        array $monitors,
        array $networks
    ): void {
        foreach (self::resolverProblems($addr, $group, $family, $v6, $monitors, $networks) as $problem) {
            $messages->appendMessage(new Message($problem, $field));
        }
    }

    /**
     * The address family of a group, from its members' protocols in tier order.
     *
     * @param list<string> $protocols each member's ipprotocol; anything but 'inet' and 'inet6' is skipped
     * @return string|null 'inet', 'inet6' or 'mixed' (both families), null for a group with no usable member
     */
    public static function groupFamily(array $protocols): ?string
    {
        $family = null;
        foreach ($protocols as $proto) {
            if ($proto !== 'inet' && $proto !== 'inet6') {
                continue;
            }
            $family ??= $proto;
            if ($proto !== $family) {
                return 'mixed';
            }
        }
        return $family;
    }

    /**
     * What is wrong with the group itself for this plugin: a group of both address families. Pure.
     *
     * @param string $family what groupFamily() returned, with null as ''
     * @return list<string>
     */
    public static function groupProblems(string $groupName, string $family): array
    {
        if ($family !== 'mixed') {
            return [];
        }
        return [sprintf(
            gettext('The gateway group %s has IPv4 and IPv6 members; use a group of one address family.'),
            $groupName
        )];
    }

    /**
     * Whether core lets Unbound use IPv6, from the stored System: Settings: General value, which says "disabled".
     * Core's is_ipv6_allowed() reads the same field and counts any value but "1" as allowed.
     */
    public static function ipv6AllowedFrom(string $disableIpv6): bool
    {
        return $disableIpv6 !== '1';
    }

    public static function ipv6Allowed(): bool
    {
        return self::ipv6AllowedFrom((new Settings())->disableipv6->getValue());
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
            return $first === 127 || ($first >= 224 && $first <= 239) || $packed === "\0\0\0\0"
                || ($first === 169 && ord($packed[1]) === 254);
        }
        return $packed === str_repeat("\0", 16) || $packed === str_repeat("\0", 15) . "\x01"
            || str_starts_with($packed, str_repeat("\0", 10) . "\xff\xff")
            || (ord($packed[0]) === 0xfe && (ord($packed[1]) & 0xc0) === 0x80) || ord($packed[0]) === 0xff;
    }
}
