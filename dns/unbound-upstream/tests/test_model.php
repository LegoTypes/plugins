<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The settings model: defaults and Save-time validation (spec section 3.9). Needs the OPNsense model
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
        'resolver must be IPv4: 2001:db8::1 refused, 10.2.0.1 accepted',
        in_array('resolver', uu_test_model_refused(['resolver' => '2001:db8::1']), true)
            && !in_array('resolver', uu_test_model_refused(['resolver' => '10.2.0.1']), true)
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
