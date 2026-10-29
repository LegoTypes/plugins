<?php

declare(strict_types=1);

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
 *
 * The settings model: defaults and Save-time validation. Needs the OPNsense model
 * classes, so it runs only on the test VM (vm_selftest.sh) and reports a skip anywhere else.
 *
 * The suite does not write config.xml. Some cases change Unbound's settings in the configuration object in memory
 * and put them back (uu_test_model_with_unbound()), with the file's md5 as the guard.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/constants.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/address.php';
require_once __DIR__ . '/scratch.php';

/**
 * Field names with a validation message, after applying $values to a fresh model.
 *
 * @param array<string, string> $values
 * @return list<string>
 */
function uu_test_model_refused(array $values): array
{
    $m = new \OPNsense\UnboundUpstream\UnboundUpstream();
    $m->setNodes($values);
    $fields = [];
    foreach ($m->performValidation() as $msg) {
        $fields[] = substr((string)strrchr('.' . $msg->getField(), '.'), 1);
    }
    return $fields;
}

/**
 * Every validation message after applying $values to a fresh model, with $rows added to the resolvers grid.
 *
 * @param array<string, string> $values
 * @param list<array{gateway: string, address: string}> $rows gateway UUID and address of each row
 * @return list<array{field: string, message: string}> field is the last part of the node's reference
 */
function uu_test_model_messages(array $values, array $rows = []): array
{
    $m = new \OPNsense\UnboundUpstream\UnboundUpstream();
    $m->setNodes($values);
    foreach ($rows as $row) {
        $m->resolvers->resolver->add()->setNodes($row);
    }
    $out = [];
    foreach ($m->performValidation() as $msg) {
        $out[] = [
            'field' => substr((string)strrchr('.' . $msg->getField(), '.'), 1),
            'message' => (string)$msg->getMessage(),
        ];
    }
    return $out;
}

/**
 * Every validation message with its field's full reference, after applying $values to a fresh model and adding $rows
 * as uu_test_model_messages() does, and each added row's address reference, in the order given.
 *
 * @param array<string, string> $values
 * @param list<array{gateway: string, address: string}> $rows gateway UUID and address of each row
 * @return array{messages: list<array{field: string, message: string}>, rows: list<string>}
 */
function uu_test_model_refs(array $values, array $rows = []): array
{
    $m = new \OPNsense\UnboundUpstream\UnboundUpstream();
    $m->setNodes($values);
    $refs = [];
    foreach ($rows as $row) {
        $node = $m->resolvers->resolver->add();
        $node->setNodes($row);
        $refs[] = $node->address->__reference;
    }
    $out = [];
    foreach ($m->performValidation() as $msg) {
        $out[] = ['field' => (string)$msg->getField(), 'message' => (string)$msg->getMessage()];
    }
    return ['messages' => $out, 'rows' => $refs];
}

/**
 * $body's verdict with core's Unbound settings changed by $change, in the configuration object only (serialized,
 * never saved), and put back by the undo $change returns, on a fresh model, whatever happens. config.xml's md5 across
 * the whole is the guard: should anything have written the file, the case fails with a line saying so.
 *
 * @param callable(\OPNsense\Unbound\Unbound): (callable(\OPNsense\Unbound\Unbound): void) $change
 * @param callable(): bool $body
 */
function uu_test_model_with_unbound(callable $change, callable $body): bool
{
    $config = '/conf/config.xml';
    $before = md5_file($config);
    $undo = null;
    $ok = false;
    try {
        $unbound = new \OPNsense\Unbound\Unbound();
        $undo = $change($unbound);
        $unbound->serializeToConfig(false, true);
        $ok = (bool)$body();
    } finally {
        if ($undo !== null) {
            $unbound = new \OPNsense\Unbound\Unbound();
            $undo($unbound);
            $unbound->serializeToConfig(false, true);
        }
        $written = md5_file($config) !== $before;
        if ($written) {
            printf("  config.xml was written while Unbound's settings were changed in memory: restore the VM to the "
                . "'unbound-upstream base' checkpoint before anything else runs\n");
        }
    }
    return $ok && !$written;
}

/**
 * The messages of one field.
 *
 * @param list<array{field: string, message: string}> $messages
 * @return list<string>
 */
function uu_test_model_field(array $messages, string $field): array
{
    return array_values(array_map(
        fn (array $m): string => $m['message'],
        array_filter($messages, fn (array $m): bool => $m['field'] === $field)
    ));
}

/**
 * A gateway group's UUID by name.
 */
function uu_test_model_group_uuid(string $name): string
{
    foreach ((new \OPNsense\Routing\GatewayGroups())->gateway_group->iterateItems() as $key => $group) {
        if ($group->name->getValue() === $name) {
            return (string)$key;
        }
    }
    return '';
}

/**
 * A gateway's UUID by name, from core's Gateways model.
 */
function uu_test_model_gateway_uuid(string $name): string
{
    foreach ((new \OPNsense\Routing\Gateways())->gateway_item->iterateItems() as $key => $gw) {
        if ($gw->name->getValue() === $name) {
            return (string)$key;
        }
    }
    return '';
}

uu_register_suite('model', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $loader = '/usr/local/opnsense/mvc/script/load_phalcon.php';
    $class = __DIR__ . '/../src/opnsense/mvc/app/models/OPNsense/UnboundUpstream/UnboundUpstream.php';
    if (!is_file($loader)) {
        uu_check($t, 'model: skipped, the OPNsense framework is not installed here', true);
        return uu_tally_report('model', $t);
    }
    require_once $loader;
    require_once $class;

    $m = new \OPNsense\UnboundUpstream\UnboundUpstream();
    uu_check($t, 'model: fallback defaults to 1', $m->fallback->isEqual('1'));
    uu_check($t, 'model: fail_closed and fail_closed_networks default empty',
        $m->fail_closed->isEmpty() && $m->fail_closed_networks->isEmpty());
    $loopback = ' overlaps the loopback network: the firewall\'s own lookups would be refused';
    $listed = ': cannot be listed; turn off "Fall back to Unbound\'s own forwarders" instead';
    /* the field's own messages on a listed network, after a Save with the fallback on */
    $netField = fn (array $values): array => uu_test_model_field(uu_test_model_messages(['fallback' => '1'] + $values),
        'fail_closed_networks');
    uu_check($t, 'model: Save names a listed network overlapping loopback or a default route, through performValidation',
        uu_try_case(function () use ($netField, $loopback, $listed): bool {
            $ok = true;
            foreach (['127.0.0.0/16' => $loopback, '::1/128' => $loopback, '::ffff:127.0.0.0/104' => $loopback,
                      '0.0.0.0/1' => $loopback, '0.0.0.0/0' => $listed, '::/0' => $listed] as $net => $message) {
                $got = $netField(['fail_closed_networks' => $net]);
                if (!in_array($net . $message, $got, true)) {
                    printf("  %s: %s\n", $net, implode('; ', $got));
                    $ok = false;
                }
            }
            return $ok;
        }));
    uu_check($t, 'model: Save reads a listed network\'s prefix length as the run does, leading zeros included',
        uu_try_case(function () use ($netField, $loopback, $listed): bool {
            $loop = $netField(['fail_closed_networks' => '127.0.0.0/08']);
            $all = $netField(['fail_closed_networks' => '0.0.0.0/00']);
            /* four digits are more than the run reads: it ignores the entry, so Save names nothing of the plugin's */
            $long = $netField(['fail_closed_networks' => '127.0.0.0/0008']);
            $ok = in_array('127.0.0.0/08' . $loopback, $loop, true) && in_array('0.0.0.0/00' . $listed, $all, true)
                && !in_array('127.0.0.0/0008' . $loopback, $long, true);
            if (!$ok) {
                printf("  127.0.0.0/08: %s; 0.0.0.0/00: %s; 127.0.0.0/0008: %s\n", implode('; ', $loop),
                    implode('; ', $all), implode('; ', $long));
            }
            return $ok;
        }));
    uu_check($t, 'model: Save names a listed network overlapping a member\'s live net',
        uu_try_case(function () use ($netField): bool {
            $group = uu_test_model_group_uuid('proton_test_grp');
            $gateways = (new \OPNsense\Routing\Gateways())->gatewaysIndexedByName(true);
            $id = (string)($gateways['wg-test-429']['interface'] ?? '');
            $device = \OPNsense\UnboundUpstream\UnboundUpstream::interfaceDevices()[$id] ?? '';
            $addr = (string)(legacy_interfaces_details()[$device]['ipv4'][0]['ipaddr'] ?? '');
            $net = uu_net_canonical($addr . '/16');
            if ($group === '' || $net === null) {
                printf("  no live IPv4 net for wg-test-429 (group %s, interface %s, device %s, address %s)\n",
                    $group, $id, $device, $addr);
                return false;
            }
            $set = ['gateway_group' => $group];
            $member = $netField($set + ['fail_closed_networks' => $net]);
            $tailnet = array_merge($netField($set + ['fail_closed_networks' => '100.64.0.0/10']),
                $netField($set + ['fail_closed_networks' => 'fd7a:115c:a1e0::/48']));
            $want = [sprintf('%s overlaps the network of %s, a member of the gateway group', $net, $id)];
            if ($member !== $want || $tailnet !== []) {
                printf("  %s: %s; the tailnet ranges: %s\n", $net, implode('; ', $member), implode('; ', $tailnet));
            }
            return $member === $want && $tailnet === [];
        }));
    uu_check($t, 'model: the static-route refusal completes a bare IPv6 route written two ways',
        uu_try_case(fn (): bool => \OPNsense\UnboundUpstream\UnboundUpstream::resolverProblems('2001:db8::50',
            'uu_far6_grp', 'inet6', true, [], ['2001:DB8::0050'])
            === ['Resolver 2001:db8::50 lies inside the static route 2001:DB8::0050.']));
    uu_check($t, 'model: the static-route refusal reads a route\'s length as core does, leading zeros included',
        uu_try_case(fn (): bool => \OPNsense\UnboundUpstream\UnboundUpstream::resolverProblems('192.0.2.5',
            'proton_test_grp', 'inet', true, [], ['192.0.2.0/024'])
            === ['Resolver 192.0.2.5 lies inside the static route 192.0.2.0/024.']
            && \OPNsense\UnboundUpstream\UnboundUpstream::resolverProblems('2001:db8::5', 'uu_far6_grp', 'inet6',
                true, [], ['2001:db8::/0064'])
            === ['Resolver 2001:db8::5 lies inside the static route 2001:db8::/0064.']));
    uu_check($t, 'model: the networks field refuses host bits and a default route while fallback is on',
        in_array('fail_closed_networks', uu_test_model_refused(['fail_closed_networks' => '192.0.2.1/24']), true)
        && in_array('fail_closed_networks', uu_test_model_refused(['fail_closed_networks' => '0.0.0.0/0']), true)
        && uu_test_model_field(uu_test_model_messages(['fail_closed_networks' => '192.0.2.1/24']), 'fail_closed_networks')
            === ['Enter each network with its prefix length and no host bits, for example 100.64.0.0/10.']
        && !in_array('fail_closed_networks', uu_test_model_refused(['fail_closed_networks' => '100.64.0.0/10']), true)
        && !in_array('fail_closed_networks', uu_test_model_refused(
            ['fallback' => '0', 'fail_closed_networks' => '0.0.0.0/0']
        ), true));
    uu_check($t, "model: a selected interface's address is found through the configuration object, with the legacy "
        . 'global empty (as config.inc leaves it when a function loaded it)',
        uu_try_case(function (): bool {
            $had = array_key_exists('config', $GLOBALS);
            $saved = $GLOBALS['config'] ?? null;
            $GLOBALS['config'] = [];
            try {
                $refused = uu_test_model_field(uu_test_model_messages(['fallback' => '1', 'fail_closed' => 'lan']),
                    'fail_closed');
            } finally {
                if ($had) {
                    $GLOBALS['config'] = $saved;
                } else {
                    unset($GLOBALS['config']);
                }
            }
            if ($refused !== []) {
                printf("  fail_closed refused: %s\n", implode('; ', $refused));
            }
            return $refused === []
                && (\OPNsense\UnboundUpstream\UnboundUpstream::interfaceDevices()['lan'] ?? '') !== '';
        }));
    uu_check($t, 'model: a repeated network is refused after normalising, naming both entries',
        uu_try_case(function () use ($netField): bool {
            $same = fn (string $nets): array => array_values(array_filter($netField(['fail_closed_networks' => $nets]),
                fn (string $m): bool => str_contains($m, ' is the same network as ')));
            $got = [$same('fd7a::/48,FD7A:0::/48'), $same('2001:DB8::/48,2001:db8:0::/48'),
                $same('192.0.2.0/24,198.51.100.0/24')];
            /* named as the field holds each entry: core's network field stores it in lower case */
            $ok = $got === [['fd7a:0::/48 is the same network as fd7a::/48'],
                ['2001:db8:0::/48 is the same network as 2001:db8::/48'], []];
            if (!$ok) {
                printf("  %s\n", json_encode($got));
            }
            return $ok;
        }));
    $outgoing = "Unbound's Outgoing Network Interfaces is set: the resolver's queries would not leave from the tunnel's "
        . 'own address.';
    uu_check($t, 'model: Save refuses Unbound\'s Outgoing Network Interfaces while enabled, not while disabled',
        uu_try_case(function () use ($outgoing): bool {
            $set = ['gateway_group' => uu_test_model_group_uuid('proton_test_grp'), 'resolver' => '10.2.0.1'];
            $on = [];
            $off = [];
            $ok = uu_test_model_with_unbound(function (\OPNsense\Unbound\Unbound $u): callable {
                $stored = $u->general->outgoing_interface->getValue();
                $u->general->outgoing_interface->setValue('lan');
                return function (\OPNsense\Unbound\Unbound $u) use ($stored): void {
                    $u->general->outgoing_interface->setValue($stored);
                };
            }, function () use ($set, &$on, &$off): bool {
                $on = uu_test_model_messages(['enabled' => '1'] + $set);
                $off = uu_test_model_messages(['enabled' => '0'] + $set);
                return true;
            });
            $refused = uu_test_model_field($on, 'enabled') === [$outgoing]
                && !in_array($outgoing, array_column($off, 'message'), true);
            if (!$refused) {
                printf("  enabled: %s; disabled: %s\n", json_encode($on), json_encode($off));
            }
            return $ok && $set['gateway_group'] !== '' && $refused;
        }));
    uu_check($t, 'model: the foreign-view check runs only while enabled',
        uu_try_case(function () use ($class): bool {
            $src = (string)file_get_contents($class);
            $body = fn (string $name): string => preg_match('/ function ' . $name . '\(.*?\n    \}\n/s', $src, $m) === 1
                ? $m[0] : '';
            $validate = $body('performValidation');
            $gate = strpos($validate, "if (!\$this->enabled->isEqual('1')) {\n            return \$messages;\n        }");
            $call = strpos($validate, '$this->checkUnbound(');
            $unbound = $body('checkUnbound');
            /* and nothing else calls either */
            return $gate !== false && $call !== false && $call > $gate
                && str_contains($unbound, 'self::foreignViewProblems(self::foreignViewTexts(dirname(UU_VIEW_FILE)))')
                && preg_match_all('/(?:self::|\$this->)foreignViewProblems\(/', $src) === 1
                && preg_match_all('/(?:self::|\$this->)checkUnbound\(/', $src) === 1;
        }));
    uu_check($t, 'model: Save refuses a root forward to a member\'s resolver on the field the address came from, both '
        . 'families',
        uu_try_case(function (): bool {
            $v4 = uu_test_model_group_uuid('proton_test_grp');
            $v6 = uu_test_model_group_uuid('uu_far6_grp');
            $gwA = uu_test_model_gateway_uuid('wg-far-a-ipv6');
            $gwB = uu_test_model_gateway_uuid('wg-far-b-ipv6');
            $text = fn (string $address, string $members): string => sprintf("Unbound's own forwarding of the root "
                . 'zone goes to %s, the resolver of %s: the plugin cannot tell that forwarding from its own.',
                $address, $members);
            /* a Query Forwarding item for the whole zone, added in memory; its undo deletes it */
            $forward = fn (string $server, string $enabled): callable => function (\OPNsense\Unbound\Unbound $u)
                use ($server, $enabled): callable {
                $node = $u->dots->dot->add();
                $node->setNodes(['enabled' => $enabled, 'type' => 'forward', 'domain' => '', 'server' => $server]);
                $uuid = (string)($node->getAttributes()['uuid'] ?? '');
                return function (\OPNsense\Unbound\Unbound $u) use ($uuid): void {
                    $u->dots->dot->del($uuid);
                };
            };
            $fields = fn (array $refs, string $message): array => array_column(array_values(array_filter(
                $refs['messages'], fn (array $m): bool => $m['message'] === $message)), 'field');
            $got = ['v4' => null, 'v6' => null, 'off' => null];
            $onV4 = ['enabled' => '1', 'gateway_group' => $v4, 'resolver' => '10.2.0.1'];
            $rows = [['gateway' => $gwA, 'address' => '2001:DB8:A:0::53'],
                ['gateway' => $gwB, 'address' => '2001:db8:b::53']];
            $ok = uu_test_model_with_unbound($forward('10.2.0.1', '1'), function () use ($onV4, &$got): bool {
                $got['v4'] = uu_test_model_refs($onV4);
                return true;
            }) && uu_test_model_with_unbound($forward('2001:db8:a::53', '1'), function () use ($v6, $rows, &$got): bool {
                $got['v6'] = uu_test_model_refs(['enabled' => '1', 'gateway_group' => $v6], $rows);
                return true;
            }) && uu_test_model_with_unbound($forward('10.2.0.1', '0'), function () use ($onV4, &$got): bool {
                $got['off'] = uu_test_model_refs($onV4);
                return true;
            });
            $resolver = (new \OPNsense\UnboundUpstream\UnboundUpstream())->resolver->__reference;
            $named = $ok && $v4 !== '' && $v6 !== '' && $gwA !== '' && $gwB !== ''
                && $fields($got['v4'], $text('10.2.0.1', 'wg-test-429, wg-test-529')) === [$resolver]
                && $fields($got['v6'], $text('2001:db8:a::53', 'wg-far-a-ipv6')) === [$got['v6']['rows'][0]]
                && array_filter(array_column($got['off']['messages'], 'message'),
                    fn (string $m): bool => str_contains($m, 'forwarding of the root zone')) === [];
            if (!$named) {
                printf("  %s\n", json_encode($got));
            }
            return $named;
        }));
    uu_check(
        $t,
        'defaults: disabled, dry run on, failback 120, notify off with no URL',
        $m->enabled->isEqual('0') && $m->dry_run->isEqual('1') && $m->failback_delay->isEqual('120')
            && $m->notify->isEqual('0') && $m->notify_url->isEmpty()
    );

    $hook = 'https://ha.example.test/api/webhook/example-id';
    uu_check(
        $t,
        'notify on needs a URL, whether or not the plugin is enabled; notify off does not',
        in_array('notify_url', uu_test_model_refused(['notify' => '1']), true)
            && in_array('notify_url', uu_test_model_refused(['enabled' => '1', 'notify' => '1']), true)
            && !in_array('notify_url', uu_test_model_refused(['notify' => '0']), true)
    );
    $url = fn (string $v): bool => !in_array('notify_url', uu_test_model_refused(['notify' => '1', 'notify_url' => $v]), true);
    uu_check(
        $t,
        'notify_url: http and https URLs accepted; ftp, a bare host and a URL with a space refused',
        $url($hook) && $url('http://127.0.0.1:18080/hook') && $url('https://ha.example.test')
            && !$url('ftp://ha.example.test/x') && !$url('ha.example.test/x') && !$url('https://ha.example.test/a b')
    );
    $m = new \OPNsense\UnboundUpstream\UnboundUpstream();
    $m->setNodes(['notify' => '1', 'notify_url' => $hook]);
    $shown = $m->getNodes()['notify_url'] ?? null;
    $m->setNodes(['notify_url' => '']);
    uu_check(
        $t,
        'notify_url is a plain setting: the page shows the saved URL, and Saving it empty clears it',
        $shown === $hook && $m->notify_url->getValue() === ''
    );

    $xml = simplexml_load_file(__DIR__ . '/../src/opnsense/mvc/app/models/OPNsense/UnboundUpstream/UnboundUpstream.xml');
    $urlMessage = 'Enter an http or https URL.';
    uu_check(
        $t,
        'model: notify_url is a UrlField that Save also holds to the run\'s URL shape',
        uu_try_case(function () use ($xml, $url, $urlMessage): bool {
            $shape = uu_test_model_field(uu_test_model_messages(['notify' => '1',
                'notify_url' => 'https://ha.example.test?x']), 'notify_url');
            $ftp = uu_test_model_field(uu_test_model_messages(['notify' => '1',
                'notify_url' => 'ftp://ha.example.test/x']), 'notify_url');
            return $xml !== false && (string)$xml->items->notify_url['type'] === 'UrlField'
                && !isset($xml->items->notify_url->Mask)
                && !$url('https://ha.example.test?x') && $shape === [$urlMessage] && $ftp === [$urlMessage];
        })
    );
    uu_check(
        $t,
        'model: a URL both the field and the run\'s shape refuse gets exactly one message, on notify_url',
        uu_try_case(function () use ($urlMessage): bool {
            $got = uu_test_model_messages(['notify' => '1', 'notify_url' => 'ha.example.test/x']);
            $all = array_column($got, 'message');
            if (uu_test_model_field($got, 'notify_url') !== [$urlMessage] || count($got) !== 1) {
                printf("  messages: %s\n", json_encode($got));
            }
            return uu_test_model_field($got, 'notify_url') === [$urlMessage] && $all === [$urlMessage];
        })
    );
    uu_check(
        $t,
        'model: a stored URL UrlField refuses still loads and is still used',
        uu_try_case(function () use ($urlMessage): bool {
            $stored = 'http://ha_box.example:8123/x';
            $m = new \OPNsense\UnboundUpstream\UnboundUpstream();
            $m->setNodes(['notify' => '1', 'notify_url' => $stored]);
            $named = uu_test_model_field(uu_test_model_messages(['notify' => '1', 'notify_url' => $stored]),
                'notify_url');
            if ($named !== [$urlMessage]) {
                printf("  notify_url messages for %s: %s\n", $stored, implode('; ', $named));
            }
            return $m->notify_url->getValue() === $stored && uu_notify_url_ok($m->notify_url->getValue())
                && $named !== [];
        })
    );
    uu_check(
        $t,
        'model: no probe_name field, and a config holding one loads',
        uu_try_case(function (): bool {
            $root = \OPNsense\Core\Config::getInstance()->object();
            $added = [];
            foreach (['OPNsense', 'UnboundUpstream'] as $name) {
                if (!isset($root->$name)) {
                    $root->addChild($name);
                    $added[] = $name;
                }
                $root = $root->$name;
            }
            $root->addChild('probe_name', 'probe.example.test');
            try {
                $m = new \OPNsense\UnboundUpstream\UnboundUpstream();
                $messages = uu_test_model_messages([]);
                $mentions = array_filter($messages, fn (array $x): bool => $x['field'] === 'probe_name'
                    || str_contains($x['message'], 'probe'));
                return $m->getNodeByReference('probe_name') === null && $mentions === [];
            } finally {
                unset($root->probe_name);
                if ($added !== []) {
                    $top = \OPNsense\Core\Config::getInstance()->object();
                    unset($top->OPNsense->UnboundUpstream);
                }
            }
        })
    );

    $bad = ['59', '3601'];
    $refused = array_map(fn (string $v): bool => in_array('failback_delay', uu_test_model_refused(['failback_delay' => $v]), true), $bad);
    uu_check(
        $t,
        'failback_delay 59 refused, 3601 refused, 60 accepted',
        $refused === [true, true] && !in_array('failback_delay', uu_test_model_refused(['failback_delay' => '60']), true)
    );

    uu_check(
        $t,
        'resolver takes either family: 2001:db8::1 and 10.2.0.1 accepted, a name refused',
        !in_array('resolver', uu_test_model_refused(['resolver' => '2001:db8::1']), true)
            && !in_array('resolver', uu_test_model_refused(['resolver' => '10.2.0.1']), true)
            && in_array('resolver', uu_test_model_refused(['resolver' => 'resolver.example.test']), true)
    );
    uu_check(
        $t,
        'resolver with a prefix length refused',
        in_array('resolver', uu_test_model_refused(['resolver' => '10.2.0.0/24']), true)
    );

    uu_check(
        $t,
        'gateway_group required when enabled, not when disabled',
        in_array('gateway_group', uu_test_model_refused(['enabled' => '1', 'resolver' => '10.2.0.1']), true)
            && !in_array('gateway_group', uu_test_model_refused(['enabled' => '0']), true)
    );
    uu_check(
        $t,
        'resolver required when enabled',
        in_array('resolver', uu_test_model_refused(['enabled' => '1']), true)
    );
    $uuid = '00000000-0000-0000-0000-000000000000';
    uu_check(
        $t,
        'an unknown gateway group is refused when enabled',
        in_array('gateway_group', uu_test_model_refused(['enabled' => '1', 'gateway_group' => $uuid, 'resolver' => '10.2.0.1']), true)
    );

    $v4 = uu_test_model_group_uuid('proton_test_grp');
    $v6 = uu_test_model_group_uuid('uu_far6_grp');
    $gw429 = uu_test_model_gateway_uuid('wg-test-429');
    $gwA = uu_test_model_gateway_uuid('wg-far-a-ipv6');
    $gwB = uu_test_model_gateway_uuid('wg-far-b-ipv6');
    if ($v4 === '' || $v6 === '' || $gw429 === '' || $gwA === '' || $gwB === '') {
        uu_check($t, 'model: the Proton and far-end groups and gateways are not on this box (base missing)', false);
        return uu_tally_report('model', $t);
    }
    uu_check(
        $t,
        'enabled on the IPv4 group with Default 10.2.0.1 and no rows: nothing about the resolver (1.3 settings mean the same)',
        uu_test_model_messages(['enabled' => '1', 'gateway_group' => $v4, 'resolver' => '10.2.0.1']) === []
    );

    $gf = fn (array $protos): ?string => \OPNsense\UnboundUpstream\UnboundUpstream::groupFamily($protos);
    uu_check(
        $t,
        'groupFamily: all IPv4 is inet, all IPv6 is inet6, both families is mixed in either order, no usable member is null',
        $gf(['inet', 'inet']) === 'inet' && $gf(['inet6']) === 'inet6' && $gf(['inet', 'inet6']) === 'mixed'
            && $gf(['inet6', 'inet']) === 'mixed' && $gf([]) === null && $gf(['', 'inet6', 'x', 'inet6']) === 'inet6'
            && $gf(['', 'inet6', 'inet']) === 'mixed' && $gf(['', 'x']) === null
    );
    $gp = fn (string $family): array => \OPNsense\UnboundUpstream\UnboundUpstream::groupProblems('g1', $family);
    uu_check(
        $t,
        'groupProblems: a mixed group gets the exact one-family message; inet, inet6 and no usable member get none',
        $gp('mixed') === ['The gateway group g1 has IPv4 and IPv6 members; use a group of one address family.']
            && $gp('inet') === [] && $gp('inet6') === [] && $gp('') === []
    );

    $problems = fn (string $addr, string $group, string $family, bool $v6, array $mon, array $nets): array =>
        \OPNsense\UnboundUpstream\UnboundUpstream::resolverProblems($addr, $group, $family, $v6, $mon, $nets);
    $linkLocal = 'Enter a resolver address that is not link-local, multicast, loopback or unspecified.';
    $v6Group = 'The group uu_far6_grp is IPv6; its resolvers must be IPv6 addresses.';
    $v4Group = 'The group proton_test_grp is IPv4; its resolvers must be IPv4 addresses.';

    uu_check(
        $t,
        'resolverProblems: an IPv6 address in an IPv6 group has none; an IPv4 one gets exactly the IPv6-group message, and the reverse',
        $problems('2001:db8:a::53', 'uu_far6_grp', 'inet6', true, [], []) === []
            && $problems('192.0.2.53', 'uu_far6_grp', 'inet6', true, [], []) === [$v6Group]
            && $problems('192.0.2.53', 'proton_test_grp', 'inet', true, [], []) === []
            && $problems('2001:db8:a::53', 'proton_test_grp', 'inet', true, [], []) === [$v4Group]
    );
    $bad = ['fe80::1' => 'inet6', '169.254.0.1' => 'inet', 'ff02::1' => 'inet6', '224.0.0.251' => 'inet', '::' => 'inet6',
        '0.0.0.0' => 'inet', '::1' => 'inet6', '127.0.0.53' => 'inet', '::ffff:192.0.2.1' => 'inet6',
        '239.255.255.255' => 'inet'];
    $bad_ok = true;
    foreach ($bad as $addr => $family) {
        $bad_ok = $bad_ok && $problems($addr, 'g', $family, true, [], []) === [$linkLocal];
    }
    uu_check(
        $t,
        'resolverProblems: link-local, multicast, unspecified, loopback and IPv4-mapped addresses give the not-link-local message alone',
        $bad_ok
    );
    uu_check(
        $t,
        'resolverProblems: multicast is exactly 224.0.0.0/4; 240.0.0.1 is left to the other checks',
        $problems('240.0.0.1', 'proton_test_grp', 'inet', true, [], []) === []
            && $problems('223.255.255.255', 'proton_test_grp', 'inet', true, [], []) === []
    );
    uu_check(
        $t,
        'resolverProblems: an IPv6 address while IPv6 is not allowed gets the IPv6-allowed message; IPv4 does not',
        $problems('2001:db8:a::53', 'uu_far6_grp', 'inet6', false, [], [])
            === ['Unbound does not use IPv6 while IPv6 is not allowed.']
            && $problems('192.0.2.53', 'proton_test_grp', 'inet', false, [], []) === []
    );
    uu_check(
        $t,
        'resolverProblems: a gateway monitor equal to the resolver is refused in canonical form, both families',
        $problems('2001:db8:a::53', 'uu_far6_grp', 'inet6', true, ['g' => '2001:DB8:A:0::53'], [])
            === ['Resolver 2001:db8:a::53 is the monitor address of gateway g.']
            && $problems('10.2.0.1', 'proton_test_grp', 'inet', true, ['g' => '10.2.0.1'], [])
            === ['Resolver 10.2.0.1 is the monitor address of gateway g.']
            && $problems('2001:DB8:A:0::53', 'uu_far6_grp', 'inet6', true, ['g' => '2001:db8:a::53'], [])
            === ['Resolver 2001:db8:a::53 is the monitor address of gateway g.']
            && $problems('2001:0db8:a::0053', 'uu_far6_grp', 'inet6', true, ['g' => '2001:DB8:A:0::53'], [])
            === ['Resolver 2001:db8:a::53 is the monitor address of gateway g.']
            && $problems('2001:db8:a::53', 'uu_far6_grp', 'inet6', true, ['g' => '2001:db8:a::54'], []) === []
    );
    uu_check(
        $t,
        'resolverProblems: a static route holding the resolver is refused, both families, and not the other family',
        $problems('2001:db8:a::53', 'uu_far6_grp', 'inet6', true, [], ['2001:db8:a::/48'])
            === ['Resolver 2001:db8:a::53 lies inside the static route 2001:db8:a::/48.']
            && $problems('10.2.0.1', 'proton_test_grp', 'inet', true, [], ['10.2.0.0/24'])
            === ['Resolver 10.2.0.1 lies inside the static route 10.2.0.0/24.']
            && $problems('2001:0db8:a::0053', 'uu_far6_grp', 'inet6', true, [], ['2001:db8:a::/48'])
            === ['Resolver 2001:db8:a::53 lies inside the static route 2001:db8:a::/48.']
            && $problems('2001:db8:a::53', 'uu_far6_grp', 'inet6', true, [], ['10.2.0.0/24']) === []
            && $problems('10.2.0.1', 'proton_test_grp', 'inet', true, [], ['2001:db8:a::/48']) === []
    );

    $far = ['enabled' => '1', 'gateway_group' => $v6];
    $rowA = ['gateway' => $gwA, 'address' => '2001:db8:a::53'];
    $rowB = ['gateway' => $gwB, 'address' => '2001:db8:b::53'];
    $notMember = 'Gateway wg-test-429 is not a member of the selected group.';
    $twice = 'Gateway wg-far-b-ipv6 has more than one resolver row.';
    $needAll = 'Enter the default resolver address, or one for every member of the group.';
    $all = fn (array $v, array $rows): array => array_column(uu_test_model_messages($v, $rows), 'message');
    uu_check(
        $t,
        'a row for a gateway outside the group is refused',
        in_array($notMember, $all($far + ['resolver' => '2001:db8:a::53'], [['gateway' => $gw429, 'address' => '2001:db8:a::54']]), true)
            && uu_test_model_messages($far + ['resolver' => '2001:db8:a::53'], [$rowA]) === []
    );
    $gone = '00000000-0000-0000-0000-00000000dead';
    uu_check(
        $t,
        'a row whose gateway no longer exists is refused as a non-member, naming the UUID',
        in_array(
            'Gateway ' . $gone . ' is not a member of the selected group.',
            $all($far + ['resolver' => '2001:db8:a::53'], [['gateway' => $gone, 'address' => '2001:db8:a::54']]),
            true
        )
    );
    uu_check(
        $t,
        'two rows for one gateway are refused',
        in_array($twice, $all($far + ['resolver' => '2001:db8:a::53'], [$rowB, $rowB]), true)
            && !in_array($twice, $all($far + ['resolver' => '2001:db8:a::53'], [$rowB]), true)
    );
    uu_check(
        $t,
        'an empty Default needs a row for every member: one row refused, rows for both accepted, no rows refused',
        in_array($needAll, $all($far, [$rowA]), true)
            && uu_test_model_messages($far, [$rowA, $rowB]) === []
            && in_array($needAll, $all($far, []), true)
            && !in_array($needAll, $all($far + ['resolver' => '2001:db8:a::53'], []), true)
            && !in_array('Enter the resolver address.', $all($far, []), true)
    );
    uu_check(
        $t,
        'the refusals of resolverProblems land on the Default and on a row\'s address',
        in_array($v6Group, uu_test_model_field(uu_test_model_messages($far + ['resolver' => '192.0.2.53']), 'resolver'), true)
            && in_array(
                $v6Group,
                uu_test_model_field(uu_test_model_messages($far + ['resolver' => '2001:db8:a::53'], [['gateway' => $gwA, 'address' => '192.0.2.54']]), 'address'),
                true
            )
    );

    $emptyRow = ['gateway' => '', 'address' => '2001:db8:a::54'];
    uu_check(
        $t,
        'two rows with an empty gateway get only the field\'s own Required message each',
        array_column(
            uu_test_model_messages($far + ['resolver' => '2001:db8:a::53'], [$emptyRow, $emptyRow]),
            'message'
        ) === ['A value is required.', 'A value is required.']
    );

    $snapshot = fn (): string => (string)preg_replace(
        '/ persisted_at="[^"]*"/',
        '',
        (string)\OPNsense\Core\Config::getInstance()->object()->asXML()
    );
    $before = $snapshot();
    $mixedRefused = [];
    $mixedUuid = '';
    try {
        $groups = new \OPNsense\Routing\GatewayGroups();
        $node = $groups->gateway_group->add();
        $node->setNodes(['name' => 'uu_mixed_grp', 'item' => 'wg-test-429|0', 'item2' => 'wg-far-a-ipv6|0']);
        $mixedUuid = (string)($node->getAttributes()['uuid'] ?? '');
        $groups->serializeToConfig(false, true);
        $mixedRefused = uu_test_model_field(
            uu_test_model_messages(['enabled' => '1', 'gateway_group' => $mixedUuid, 'resolver' => '10.2.0.1']),
            'gateway_group'
        );
    } finally {
        $groups = new \OPNsense\Routing\GatewayGroups();
        if ($mixedUuid !== '') {
            $groups->gateway_group->del($mixedUuid);
        }
        $groups->serializeToConfig(false, true);
    }
    uu_check(
        $t,
        'Save refuses a group of both families on the group field (built in memory, removed in the case)',
        in_array('The gateway group uu_mixed_grp has IPv4 and IPv6 members; use a group of one address family.', $mixedRefused, true)
    );
    uu_check($t, 'the in-memory group left the configuration as it was', $snapshot() === $before);

    $core = new \OPNsense\Interfaces\Settings();
    $storedV6 = $core->disableipv6->getValue();
    $refusedV6 = [];
    try {
        $core->disableipv6 = '1';
        $core->serializeToConfig(false, true);
        $refusedV6 = uu_test_model_field(uu_test_model_messages($far + ['resolver' => '2001:db8:a::53']), 'resolver');
    } finally {
        $core->disableipv6 = $storedV6;
        $core->serializeToConfig(false, true);
    }
    uu_check(
        $t,
        'Save refuses an IPv6 resolver while core has IPv6 disabled (set in memory, restored in the case)',
        in_array('Unbound does not use IPv6 while IPv6 is not allowed.', $refusedV6, true)
            && \OPNsense\UnboundUpstream\UnboundUpstream::ipv6Allowed() === ($storedV6 !== '1')
    );

    $m = new \OPNsense\UnboundUpstream\UnboundUpstream();
    $row = $m->resolvers->resolver->add();
    $row->setNodes(['gateway' => $gwA, 'address' => '2001:db8:a::53']);
    $rows = $m->getNodes()['resolvers']['resolver'] ?? [];
    $stored = '';
    foreach ($rows as $entry) {
        foreach ((array)($entry['gateway'] ?? []) as $key => $opt) {
            if (!empty($opt['selected'])) {
                $stored = (string)$key;
            }
        }
    }
    uu_check(
        $t,
        'a row\'s gateway stores the gateway\'s UUID, not its name',
        $row->gateway->getValue() === $gwA && $row->gateway->getValue() !== 'wg-far-a-ipv6' && $stored === $gwA
    );

    require_once 'util.inc';
    $kept = $GLOBALS['config'] ?? null;
    $agrees = true;
    foreach (['0', '1', ''] as $stored) {
        $GLOBALS['config'] = ['OPNsense' => ['Interfaces' => ['settings' => ['disableipv6' => $stored]]]];
        $agrees = $agrees && \OPNsense\UnboundUpstream\UnboundUpstream::ipv6AllowedFrom($stored) === is_ipv6_allowed();
    }
    $GLOBALS['config'] = $kept;
    uu_check(
        $t,
        'ipv6AllowedFrom agrees with is_ipv6_allowed() for "0", "1" and unset, and reads false for "1"',
        $agrees && !\OPNsense\UnboundUpstream\UnboundUpstream::ipv6AllowedFrom('1')
            && \OPNsense\UnboundUpstream\UnboundUpstream::ipv6AllowedFrom('0')
    );

    $monitor = '';
    foreach ((new \OPNsense\Routing\Gateways())->gatewaysIndexedByName(true) as $gw) {
        if (!empty($gw['monitor']) && $monitor === '' && empty($gw['monitor_disable'])) {
            $monitor = (string)$gw['monitor'];
        }
    }
    if ($monitor === '') {
        uu_check($t, 'resolver equal to a gateway monitor: skipped, no monitored gateway here', true);
    } else {
        uu_check(
            $t,
            'resolver equal to a gateway monitor address is refused',
            in_array('resolver', uu_test_model_refused(['enabled' => '1', 'resolver' => $monitor]), true)
        );
    }

    uu_check($t, 'model: the foreign-view message goes on the setting that makes the set not empty, a list of '
        . 'networks alone included',
        uu_try_case(function (): bool {
            $field = function (array $values): ?string {
                $m = new \OPNsense\UnboundUpstream\UnboundUpstream();
                $m->setNodes($values);
                return (new \ReflectionMethod($m, 'foreignViewField'))->invoke($m);
            };
            $m = new \OPNsense\UnboundUpstream\UnboundUpstream();
            $got = [
                'off' => $field(['fallback' => '0', 'fail_closed_networks' => '192.0.2.0/24']),
                'interfaces' => $field(['fallback' => '1', 'fail_closed' => 'lan', 'fail_closed_networks' => '192.0.2.0/24']),
                'networks' => $field(['fallback' => '1', 'fail_closed_networks' => '192.0.2.0/24']),
                'none' => $field(['fallback' => '1']),
            ];
            $ok = $got === [
                'off' => $m->fallback->__reference,
                'interfaces' => $m->fail_closed->__reference,
                'networks' => $m->fail_closed_networks->__reference,
                'none' => null,
            ];
            if (!$ok) {
                printf("  %s\n", json_encode($got));
            }
            return $ok;
        }));
    /* the other configuration files' view lines: the VM cannot stage one in Unbound's own directory, so the reader
     * runs over a scratch directory and the line test over texts */
    uu_check($t, 'model: foreignViewProblems names each file and line',
        uu_try_case(fn (): bool => \OPNsense\UnboundUpstream\UnboundUpstream::foreignViewProblems([
                'custom.conf' => "server:\nview: # x\n  name: v\n",
                'other.conf' => "access-control: 192.0.2.0/24 allow\n"])
            === ['custom.conf holds "view:", a view the plugin does not own: fail closed cannot share Unbound with '
                . 'it.']));
    uu_check($t, 'model: foreignViewTexts reads the regular *.conf files but the plugin\'s own, each to the size limit',
        uu_scratch_case(function (string $dir): bool {
            $big = str_pad("view: x\n", UU_SCRATCH_MIB + 1, ' ');
            $own = basename(UU_VIEW_FILE);
            $placed = file_put_contents($dir . '/a.conf', "server:\nview:\n") !== false
                && file_put_contents($dir . '/big.conf', $big) !== false
                && file_put_contents($dir . '/x.txt', "view:\n") !== false
                && file_put_contents($dir . '/' . $own, "view:\n") !== false;
            uu_scratch_place('link', $dir . '/l.conf', "view:\n");
            uu_scratch_place('dir', $dir . '/d.conf', '');
            uu_scratch_place('fifo', $dir . '/f.conf', '');
            $texts = \OPNsense\UnboundUpstream\UnboundUpstream::foreignViewTexts($dir);
            $ok = $placed && $own === 'unboundupstream.conf'
                && $texts === ['a.conf' => "server:\nview:\n", 'big.conf' => substr($big, 0, UU_FILE_MAX_BYTES)];
            if (!$ok) {
                printf("  read %s\n", json_encode(array_map('strlen', $texts)));
            }
            return $ok;
        }));
    return uu_tally_report('model', $t);
});
