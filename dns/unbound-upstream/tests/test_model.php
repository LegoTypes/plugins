<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The settings model: defaults and Save-time validation. Needs the OPNsense model
 * classes, so it runs only on the test VM (vm_selftest.sh) and reports a skip anywhere else.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/constants.php';

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
    uu_check(
        $t,
        'defaults: disabled, dry run on, failback 120, probe ".", notify off with no URL',
        $m->enabled->isEqual('0') && $m->dry_run->isEqual('1') && $m->failback_delay->isEqual('120')
            && $m->probe_name->isEqual('.') && $m->notify->isEqual('0') && $m->notify_url->isEmpty()
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
    uu_check(
        $t,
        'the XML masks of notify_url and probe_name are UU_NOTIFY_URL_MASK and UU_PROBE_NAME_MASK, byte for byte',
        $xml !== false && (string)$xml->items->notify_url->Mask === UU_NOTIFY_URL_MASK
            && (string)$xml->items->probe_name->Mask === UU_PROBE_NAME_MASK
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
    $probe = fn (string $v): bool => !in_array('probe_name', uu_test_model_refused(['probe_name' => $v]), true);
    uu_check(
        $t,
        'probe_name: "." and "example.com" accepted, "bad name!" refused',
        $probe('.') && $probe('example.com') && !$probe('bad name!')
    );

    $uuid = '00000000-0000-0000-0000-000000000000';
    uu_check(
        $t,
        'an unknown gateway group is refused when enabled',
        in_array('gateway_group', uu_test_model_refused(['enabled' => '1', 'gateway_group' => $uuid, 'resolver' => '10.2.0.1']), true)
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
    uu_check(
        $t,
        'the model reads core\'s own IPv6 setting: ipv6Allowed() is true unless the stored value is 1',
        \OPNsense\UnboundUpstream\UnboundUpstream::ipv6Allowed()
            === ((new \OPNsense\Interfaces\Settings())->disableipv6->getValue() !== '1')
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
    return uu_tally_report('model', $t);
});
