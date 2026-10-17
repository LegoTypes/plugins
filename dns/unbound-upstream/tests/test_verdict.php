<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Readings and verdicts (spec section 3.2): settled, young, cached and no readings.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/constants.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/verdict.php';

/**
 * @return array{name: string, interface: string, if: string, next_hop: string, disabled: bool, force_down: bool,
 *               monitor_disable: bool, monitor: string, time_period: int, interval: int, loss_interval: int, losshigh: int}
 */
function uu_test_member(): array
{
    return ['name' => 'wg-a', 'interface' => 'opt1', 'if' => 'wg1', 'next_hop' => '10.2.0.2', 'disabled' => false,
            'force_down' => false, 'monitor_disable' => false, 'monitor' => '10.2.0.1', 'time_period' => 80,
            'interval' => 1, 'loss_interval' => 4, 'losshigh' => 20];
}

/**
 * @return array{status: string, loss: string, sock_age: ?int, cached: ?string}
 */
function uu_test_probe(string $status, string $loss, ?int $age, ?string $cached = null): array
{
    return ['status' => $status, 'loss' => $loss, 'sock_age' => $age, 'cached' => $cached];
}

uu_register_suite('verdict', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $a = uu_test_member();

    uu_check($t, 'unusable: down, force_down, loss under downloss; delay only under downlatency',
        uu_status_unusable('down', 'downloss') && uu_status_unusable('force_down', 'downloss')
        && uu_status_unusable('loss', 'downloss') && !uu_status_unusable('delay', 'downloss')
        && !uu_status_unusable('none', 'downloss') && uu_status_unusable('delay', 'downlatency')
        && !uu_status_unusable('loss', 'downlatency') && uu_status_unusable('down', 'downlatency')
        && uu_status_unusable('loss', 'downlosslatency') && uu_status_unusable('delay', 'downlosslatency')
        && uu_status_unusable('delay+loss', 'downlosslatency') && !uu_status_unusable('none', 'downlosslatency')
        && uu_status_unusable('down', 'down') && !uu_status_unusable('loss', 'down'));

    uu_check($t, 'young 8 s, 25 % → down string but no verdict',
        uu_member_down($a, uu_test_probe('down', '25.0 %', 8), 'downloss', false) === null);
    uu_check($t, 'young 12 s, 12.5 % loss → no verdict',
        uu_member_down($a, uu_test_probe('loss', '12.5 %', 12), 'downloss', false) === null);
    uu_check($t, 'young 100 % for 10 s → all lost',
        uu_member_down($a, uu_test_probe('down', '100.0 %', 14), 'downloss', false) === 'all lost 10 s');
    uu_check($t, 'young 100 % for 9 s → none',
        uu_member_down($a, uu_test_probe('down', '100.0 %', 13), 'downloss', false) === null);
    uu_check($t, 'young 16 lost → lost 16 of losshigh; 15 lost → none',
        uu_member_down($a, uu_test_probe('loss', '44.4 %', 40), 'downloss', false) === 'lost 16 of losshigh'
        && uu_member_down($a, uu_test_probe('loss', '41.6 %', 40), 'downloss', false) === null);
    uu_check($t, 'lost probes: counted = (age - loss_interval) / interval',
        abs(uu_lost_probes($a, uu_test_probe('loss', '50.0 %', 24)) - 10.0) < 1e-9
        && uu_lost_probes($a, uu_test_probe('loss', '50.0 %', 2)) === 0.0
        && uu_lost_probes($a, uu_test_probe('loss', '44.4 %', 40)) === 16.0
        && uu_lost_probes($a, uu_test_probe('loss', '41.6 %', 40)) === 15.0
        && uu_lost_probes($a, uu_test_probe('down', '~', 40)) === 0.0);
    uu_check($t, 'cached down while loss ~ → cached down',
        uu_member_down($a, uu_test_probe('down', '~', null, 'down'), 'downloss', false) === 'cached down');
    uu_check($t, 'loss ~ without cache → none (watcher starting)',
        uu_member_down($a, uu_test_probe('down', '~', null, null), 'downloss', false) === null
        && uu_reading_kind($a, uu_test_probe('down', '~', null, null)) === 'none');
    uu_check($t, 'named + watcher down, dpinger already has data → watcher down',
        uu_member_down($a, uu_test_probe('none', '0.0 %', 6, 'down'), 'downloss', true) === 'watcher down'
        && uu_member_down($a, uu_test_probe('none', '0.0 %', 6, 'down'), 'downloss', false) === null);
    uu_check($t, 'named + watcher none (device recreation) → no verdict',
        uu_member_down($a, uu_test_probe('none', '0.0 %', 6, 'none'), 'downloss', true) === null
        && uu_member_down($a, uu_test_probe('down', '~', null, 'none'), 'downloss', true) === null);
    uu_check($t, 'reading kinds: settled, young, cached, none',
        uu_reading_kind($a, uu_test_probe('none', '0.0 %', 90)) === 'settled'
        && uu_reading_kind($a, uu_test_probe('none', '0.0 %', 79)) === 'young'
        && uu_reading_kind($a, uu_test_probe('down', '~', null, 'down')) === 'cached'
        && uu_reading_kind($a, uu_test_probe('none', '0.0 %', null)) === 'none');
    uu_check($t, 'settled down → settled down; settled loss under downloss → settled loss',
        uu_member_down($a, uu_test_probe('down', '100.0 %', 90), 'downloss', false) === 'settled down'
        && uu_member_down($a, uu_test_probe('loss', '30.0 %', 90), 'downloss', false) === 'settled loss'
        && uu_member_down($a, uu_test_probe('delay', '0.0 %', 90), 'downloss', false) === null);

    $forced = $a;
    $forced['force_down'] = true;
    $off = $a;
    $off['disabled'] = true;
    uu_check($t, 'force_down → force_down regardless of reading; disabled first',
        uu_member_down($forced, uu_test_probe('none', '0.0 %', 90), 'downloss', false) === 'force_down'
        && uu_member_down($forced, uu_test_probe('none', '~', null), 'downloss', false) === 'force_down'
        && uu_member_down($off, uu_test_probe('none', '0.0 %', 90), 'downloss', false) === 'disabled'
        && uu_member_down($off, uu_test_probe('none', '0.0 %', 90), 'downloss', true) === 'disabled');

    uu_check($t, 'usable_settled: only settled + usable; cached/young/none never',
        uu_usable_settled($a, uu_test_probe('none', '0.0 %', 90), 'downloss')
        && !uu_usable_settled($a, uu_test_probe('loss', '30.0 %', 90), 'downloss')
        && !uu_usable_settled($a, uu_test_probe('none', '0.0 %', 30), 'downloss')
        && !uu_usable_settled($a, uu_test_probe('none', '~', null, 'none'), 'downloss')
        && !uu_usable_settled($a, uu_test_probe('none', '~', null), 'downloss')
        && !uu_usable_settled($forced, uu_test_probe('none', '0.0 %', 90), 'downloss')
        && !uu_usable_settled($off, uu_test_probe('none', '0.0 %', 90), 'downloss'));

    return uu_tally_report('verdict', $t);
});
