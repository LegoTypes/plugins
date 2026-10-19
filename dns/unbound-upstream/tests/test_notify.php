<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The switch notification (spec section 3.11): when one is due, its body, and what a log may show of the URL.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/notify.php';

uu_register_suite('notify', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $a = ['at' => 1000, 'from' => 'fallback', 'to' => 'wg-a', 'reason' => 'wg-a usable for 120 s'];
    $b = ['at' => 1060, 'from' => 'wg-a', 'to' => 'fallback', 'reason' => 'wg-a: settled down'];

    uu_check($t, 'due: a first switch, and a switch that replaced another',
        uu_notify_due(null, $a) && uu_notify_due($a, $b));
    uu_check($t, 'due: not when the run kept the saved switch, nor with none at all',
        !uu_notify_due($a, $a) && !uu_notify_due(null, null));
    uu_check($t, 'due: a switch back to the same place at a later time is a new switch',
        uu_notify_due($a, ['at' => 1200] + $a));

    $body = json_decode(uu_notify_body(['mode' => 'fallback', 'member' => null, 'last_switch' => $b]), true);
    uu_check($t, 'body: the last switch, then the saved mode and member, as JSON',
        $body === ['at' => 1060, 'from' => 'wg-a', 'to' => 'fallback', 'reason' => 'wg-a: settled down',
            'mode' => 'fallback', 'member' => null]);
    uu_check($t, 'body: a tunnel switch carries its member',
        json_decode(uu_notify_body(['mode' => 'tunnel', 'member' => 'wg-a', 'last_switch' => $a]), true)['member']
            === 'wg-a');

    uu_check($t, 'where: scheme and host of a webhook URL, never its path',
        uu_notify_where('https://ha.example.test/api/webhook/secret-id') === 'https://ha.example.test');
    uu_check($t, 'where: the port is kept, the query dropped',
        uu_notify_where('http://127.0.0.1:18080/hook?token=x') === 'http://127.0.0.1:18080');
    uu_check($t, 'where: credentials in the URL are dropped',
        uu_notify_where('https://user:pass@ha.example.test/x') === 'https://ha.example.test');
    uu_check($t, 'where: a URL without a host is named, not echoed',
        uu_notify_where('not a url') === 'the notify URL');
    return uu_tally_report('notify', $t);
});
