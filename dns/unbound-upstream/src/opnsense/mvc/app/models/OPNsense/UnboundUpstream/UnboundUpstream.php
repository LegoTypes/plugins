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
use OPNsense\Interfaces\Settings;
use OPNsense\Routing\GatewayGroups;
use OPNsense\Routing\Gateways;
use OPNsense\Routes\Route;
use OPNsense\Unbound\Unbound;

require_once 'interfaces.lib.inc';

$lib = dirname(__DIR__, 5) . '/scripts/OPNsense/UnboundUpstream/lib/views.php';
if (!function_exists('uu_view_iface_nets')) {
    if (!is_readable($lib)) {
        throw new \RuntimeException('plugin library missing: ' . $lib);
    }
    require_once $lib;
}

class UnboundUpstream extends BaseModel
{
    /**
     * The notify URL is required whenever notify is on, and one that is set must be a URL the run posts to
     * (uu_notify_url_ok()); the fail-closed lists are checked while the fallback is on; cross-field checks that need
     * the gateway, route and Unbound models run only while the plugin is enabled.
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
        /* UrlField passes URLs the run refuses (https://host?x); the field's own refusal already says this */
        if (!$this->notify_url->isEmpty() && !uu_notify_url_ok($this->notify_url->getValue())) {
            $named = false;
            foreach ($messages as $message) {
                $named = $named || $message->getField() === $this->notify_url->__reference;
            }
            if (!$named) {
                $messages->appendMessage(new Message(
                    gettext('Enter an http or https URL.'),
                    $this->notify_url->__reference
                ));
            }
        }
        if ($this->fallback->isEqual('1')) {
            $this->checkFailClosed($messages);
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
        $this->checkUnbound($messages, $gateways);
        return $messages;
    }

    /**
     * The interfaces and networks that fail closed, against the gateway group's member interfaces and the live
     * addresses; run only while the fallback is on, since off refuses every client anyway. Nothing is read from the
     * box while both lists are empty.
     */
    private function checkFailClosed(object $messages): void
    {
        $ids = array_filter(explode(',', $this->fail_closed->getValue()));
        $listed = array_filter(explode(',', $this->fail_closed_networks->getValue()));
        if ($ids === [] && $listed === []) {
            return;
        }
        $details = legacy_interfaces_details();
        $devices = self::interfaceDevices();
        $gateways = (new Gateways())->gatewaysIndexedByName(true);
        $memberNets = [];
        foreach (array_keys($this->findGroup()['members'] ?? []) as $name) {
            $id = (string)($gateways[$name]['interface'] ?? '');
            if ($id !== '') {
                $memberNets[$id] = uu_view_iface_nets($details, [$id], $devices)['nets'];
            }
        }

        $field = $this->fail_closed->__reference;
        foreach ($ids as $id) {
            if ($id === 'lo0') {
                $messages->appendMessage(new Message(gettext('the loopback interface cannot fail closed'), $field));
            } elseif (isset($memberNets[$id])) {
                $messages->appendMessage(new Message(
                    sprintf(gettext('%s is a member of the gateway group'), $id),
                    $field
                ));
            } elseif (uu_view_iface_nets($details, [$id], $devices)['nets'] === []) {
                $messages->appendMessage(new Message(sprintf(gettext('%s has no address'), $id), $field));
            }
        }

        /* host bits are the field's own Strict refusal; a repeat is named against the first entry of its network, as
         * the run reads both (it keeps the network once) */
        $first = [];
        foreach ($listed as $net) {
            $entry = uu_net_entry($net, UU_NET_LENGTH_DIGITS);
            $canonical = $entry === null ? null : uu_net_canonical($entry['addr'] . '/' . $entry['len']);
            if ($canonical !== null && isset($first[$canonical])) {
                $messages->appendMessage(new Message(
                    sprintf(gettext('%s is the same network as %s'), $net, $first[$canonical]),
                    $this->fail_closed_networks->__reference
                ));
            } elseif ($canonical !== null) {
                $first[$canonical] = $net;
            }
            foreach (self::networkProblems($net, $memberNets) as $problem) {
                $messages->appendMessage(new Message($problem, $this->fail_closed_networks->__reference));
            }
        }
    }

    /**
     * Each interface id's device, from the MVC configuration object: the same map in the web GUI's process, in a
     * configd script and in the plugin's evaluation, whichever of them loaded config.inc and where (the legacy global
     * it fills is empty when it was loaded inside a function).
     *
     * @return array<string, string> interface id => device
     */
    public static function interfaceDevices(): array
    {
        $devices = [];
        $interfaces = Config::getInstance()->object()->interfaces;
        if ($interfaces === null) {
            return $devices;
        }
        foreach ($interfaces->children() as $id => $node) {
            $devices[(string)$id] = (string)$node->if;
        }
        return $devices;
    }

    /**
     * What is wrong with one listed network besides host bits: a default route, the loopback network
     * (UU_LOOPBACK_NETS), a member interface's network. Pure, on the scripts' network tests (lib/address.php). A
     * string that is no "address/length" network is the field's own validation. The entry is read as the run reads
     * it (uu_net_entry() with UU_NET_LENGTH_DIGITS, as uu_settings_clean()), so 127.0.0.0/08 is tested as
     * 127.0.0.0/8 and named as entered.
     *
     * @param array<string, list<string>> $memberNets interface id => its live networks
     * @return list<string>
     */
    private static function networkProblems(string $net, array $memberNets): array
    {
        $entry = uu_net_entry($net, UU_NET_LENGTH_DIGITS);
        $cidr = $entry === null ? '' : $entry['addr'] . '/' . $entry['len'];
        $parsed = $entry === null ? null : uu_net_parse($cidr);
        if ($parsed === null) {
            return [];
        }
        if ($parsed['prefix'] === 0) {
            return [$net . ': cannot be listed; turn off "Fall back to Unbound\'s own forwarders" instead'];
        }
        if (uu_net_touches_loopback($cidr)) {
            return [$net . ' overlaps the loopback network: the firewall\'s own lookups would be refused'];
        }
        foreach ($memberNets as $id => $theirs) {
            foreach ($theirs as $their) {
                if (uu_net_overlaps($cidr, $their)) {
                    return [sprintf('%s overlaps the network of %s, a member of the gateway group', $net, $id)];
                }
            }
        }
        return [];
    }

    /**
     * What in Unbound's own settings the run would refuse, named at Save as an early warning (the run's contract
     * stays the authority, for a later change on Unbound's pages): its Outgoing Network Interfaces, a forward of the
     * root zone to a member's effective resolver while a group is selected, and, while the set is not empty, a view
     * line in another of Unbound's configuration files. Run only while the plugin is enabled.
     */
    private function checkUnbound(object $messages, Gateways $model): void
    {
        $unbound = new Unbound();
        if (!$unbound->general->outgoing_interface->isEmpty()) {
            $messages->appendMessage(new Message(
                gettext("Unbound's Outgoing Network Interfaces is set: the resolver's queries would not leave from the tunnel's own address."),
                $this->enabled->__reference
            ));
        }
        if (!$this->gateway_group->isEmpty()) {
            $this->checkRootForwards($messages, $unbound, $model);
        }

        $field = $this->foreignViewField();
        if ($field === null) {
            return;
        }
        foreach (self::foreignViewProblems(self::foreignViewTexts(dirname(UU_VIEW_FILE))) as $problem) {
            $messages->appendMessage(new Message($problem, $field));
        }
    }

    /**
     * The reference of the setting a foreign-view message goes on: the one that makes the set not empty (fallback off
     * refuses every client; with it on, the interfaces, else the networks). Null while the set is empty with the
     * fallback on and nothing selected or listed.
     */
    private function foreignViewField(): ?string
    {
        if ($this->fallback->isEqual('0')) {
            return $this->fallback->__reference;
        }
        if (!$this->fail_closed->isEmpty()) {
            return $this->fail_closed->__reference;
        }
        if (!$this->fail_closed_networks->isEmpty()) {
            return $this->fail_closed_networks->__reference;
        }
        return null;
    }

    /**
     * Unbound's own forwarding of the root zone (a Query Forwarding or DNS over TLS item, enabled, for "" or ".") to
     * a member's effective resolver, as the run reads both (uu_root_forward_conflicts()). The resolvers are the run's:
     * each member's row, else the Default, each kept as the scripts keep it (uu_rows_clean(), a refused Default is
     * none). The message goes on the field each member's resolver came from: the Default for a member with no row of
     * its own, else that member's row.
     */
    private function checkRootForwards(object $messages, Unbound $unbound, Gateways $model): void
    {
        $roots = [];
        foreach ($unbound->dots->dot->iterateItems() as $dot) {
            if ($dot->enabled->isEqual('1') && in_array($dot->domain->getValue(), ['', '.'], true)) {
                $roots[] = $dot->server->getValue();
            }
        }
        if ($roots === []) {
            return;
        }
        $raw = [];
        foreach ($this->resolvers->resolver->iterateItems() as $row) {
            $raw[] = ['gateway' => $row->gateway->getValue(), 'address' => $row->address->getValue()];
        }
        $rows = uu_rows_clean($raw)['rows'];
        $names = uu_gateway_names($model->gatewaysIndexedByName(true));
        $members = array_map('strval', array_keys($this->findGroup()['members'] ?? []));
        $own = [];
        foreach (array_keys($rows) as $uuid) {
            $own[$names[$uuid] ?? ''] = true;
        }
        $default = $this->resolver->getValue();
        $default = uu_resolver_refusal($default) === null ? (uu_ip_canonical($default) ?? '') : '';
        $resolvers = uu_member_resolvers($members, $rows, $names, $default)['resolvers'];

        foreach (uu_root_forward_conflicts($roots, $resolvers) as $address => $users) {
            $address = (string)$address;
            $text = sprintf(
                gettext("Unbound's own forwarding of the root zone goes to %s, the resolver of %s: the plugin cannot tell that forwarding from its own."),
                $address,
                implode(', ', $users)
            );
            if (array_filter($users, fn (string $name): bool => !isset($own[$name])) !== []) {
                $messages->appendMessage(new Message($text, $this->resolver->__reference));
            }
            foreach ($this->resolvers->resolver->iterateItems() as $row) {
                $name = $names[$row->gateway->getValue()] ?? '';
                if (in_array($name, $users, true) && uu_ip_canonical($row->address->getValue()) === $address) {
                    $messages->appendMessage(new Message($text, $row->address->__reference));
                }
            }
        }
    }

    /**
     * The view lines of other configuration texts, one message each: what uu_view_foreign() finds in each. Pure.
     *
     * @param array<string, string> $texts file basename => its text
     * @return list<string>
     */
    public static function foreignViewProblems(array $texts): array
    {
        $problems = [];
        foreach ($texts as $file => $text) {
            foreach (uu_view_foreign($text) as $line) {
                $problems[] = sprintf(
                    gettext('%s holds "%s", a view the plugin does not own: fail closed cannot share Unbound with it.'),
                    $file,
                    $line
                );
            }
        }
        return $problems;
    }

    /**
     * The *.conf files of a directory, as Unbound's include of it lists them, but the plugin's own
     * (basename(UU_VIEW_FILE)): regular files only, never through a link, each read to at most UU_FILE_MAX_BYTES. A
     * file that cannot be read is left out; the run's contract still reads Unbound's whole configuration.
     *
     * @return array<string, string> file basename => its text
     */
    public static function foreignViewTexts(string $dir): array
    {
        $texts = [];
        foreach (glob($dir . '/*.conf') ?: [] as $path) {
            $file = basename($path);
            if ($file === basename(UU_VIEW_FILE) || is_link($path) || !is_file($path)) {
                continue;
            }
            $text = @file_get_contents($path, false, null, 0, UU_FILE_MAX_BYTES);
            if ($text !== false) {
                $texts[$file] = $text;
            }
        }
        return $texts;
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
            /* an empty gateway is the field's own Required message; a gateway deleted since the row was saved is no
             * member either, and its UUID stands in for its name */
            if (!$row->gateway->isEmpty()) {
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
            }
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
     * Core's is_ipv6_allowed() reads the same field and uses empty(), which allows "" and "0" and refuses
     * any other value; the two agree for every value a boolean field holds.
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
     * Pure, on the scripts' address tests (lib/address.php): the callers pass in what the box says. A string that is
     * no address (a name, a scoped address, white space around it) is the field's own validation.
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
        if (filter_var($addr, FILTER_VALIDATE_IP) === false) {
            return [];
        }
        /* an IPv4-mapped address has no family in the library ('not an address'), and is refused with the rest */
        $canonical = uu_ip_problem($addr) === null ? uu_ip_canonical($addr) : null;
        if ($canonical === null) {
            return [gettext('Enter a resolver address that is not link-local, multicast, loopback or unspecified.')];
        }
        $v6 = uu_ip_family($canonical) === 'inet6';
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
            if (uu_ip_same($monitor, $canonical)) {
                $problems[] = sprintf(gettext('Resolver %s is the monitor address of gateway %s.'), $canonical, $name);
            }
        }
        foreach ($networks as $network) {
            if (uu_in_static($canonical, $network)) {
                $problems[] = sprintf(gettext('Resolver %s lies inside the static route %s.'), $canonical, $network);
            }
        }
        return $problems;
    }
}
