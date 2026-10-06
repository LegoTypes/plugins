<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Readings and judgements, spec section 3.2.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/judge.php';

/** @return array{disabled: bool, manual_down: bool, present: bool, tilde: bool, carrier: bool, has_ipv4: bool, loss: ?float, sock_age: ?int, losslow: float, losshigh: float, time_period: int, interval: int, loss_interval: int} */
function wf_t_w(array $over = []): array
{
    return array_merge([
        'disabled' => false, 'manual_down' => false, 'present' => true, 'tilde' => false, 'carrier' => true, 'has_ipv4' => true,
        'loss' => 0.0, 'sock_age' => 300, 'losslow' => 10.0, 'losshigh' => 20.0,
        'time_period' => 60, 'interval' => 1, 'loss_interval' => 4,
    ], $over);
}

wf_register_suite('judge', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $d = 10;
    wf_check($t, 'settled 0% is clean', wf_reading(wf_t_w(), $d) === WF_CLEAN);
    wf_check($t, 'settled 3% is marginal', wf_reading(wf_t_w(['loss' => 3.0]), $d) === WF_MARGINAL);
    wf_check($t, 'settled exactly losslow (10%) is marginal: core compares strictly', wf_reading(wf_t_w(['loss' => 10.0]), $d) === WF_MARGINAL);
    wf_check($t, 'settled 11% is bad', wf_reading(wf_t_w(['loss' => 11.0]), $d) === WF_BAD);
    wf_check($t, 'disabled is unavailable', wf_reading(wf_t_w(['disabled' => true]), $d) === WF_UNAVAILABLE);
    wf_check($t, 'manual force_down is unavailable', wf_reading(wf_t_w(['manual_down' => true]), $d) === WF_UNAVAILABLE);
    wf_check($t, 'no carrier is unavailable even with numbers', wf_reading(wf_t_w(['carrier' => false]), $d) === WF_UNAVAILABLE);
    wf_check($t, 'no IPv4 address is unavailable', wf_reading(wf_t_w(['has_ipv4' => false, 'present' => false, 'loss' => null]), $d) === WF_UNAVAILABLE);
    wf_check($t, 'absent from status with link up is unknown', wf_reading(wf_t_w(['present' => false, 'loss' => null, 'sock_age' => null]), $d) === WF_UNKNOWN);
    wf_check($t, '~ numbers right after restart are unknown', wf_reading(wf_t_w(['loss' => null, 'sock_age' => 1]), $d) === WF_UNKNOWN);
    wf_check($t, '100% for 10 s is unavailable', wf_reading(wf_t_w(['loss' => 100.0, 'sock_age' => 10]), $d) === WF_UNAVAILABLE);
    wf_check($t, '100% for 6 s is not yet unavailable', wf_reading(wf_t_w(['loss' => 100.0, 'sock_age' => 6]), $d) === WF_UNKNOWN);
    wf_check($t, 'young 6 s at 50% (1 of 2) is unknown', wf_reading(wf_t_w(['loss' => 50.0, 'sock_age' => 6]), $d) === WF_UNKNOWN);
    wf_check($t, 'young 20 s at 25% (4 lost) is unknown', wf_reading(wf_t_w(['loss' => 25.0, 'sock_age' => 20]), $d) === WF_UNKNOWN);
    wf_check($t, 'young 40 s at 35% (12.6 lost >= 12) is bad', wf_reading(wf_t_w(['loss' => 35.0, 'sock_age' => 40]), $d) === WF_BAD);
    wf_check($t, 'young 0% is unknown, never clean', wf_reading(wf_t_w(['loss' => 0.0, 'sock_age' => 30]), $d) === WF_UNKNOWN);
    wf_check($t, '~ on a settled dpinger (stddev and loss exactly 0) is clean (R3-10)', wf_reading(wf_t_w(['loss' => null, 'tilde' => true, 'sock_age' => 300]), $d) === WF_CLEAN);
    wf_check($t, '~ on a young dpinger is unknown', wf_reading(wf_t_w(['loss' => null, 'tilde' => true, 'sock_age' => 30]), $d) === WF_UNKNOWN);

    $j = wf_judgement_new(1000);
    wf_check($t, 'new judgement is unset', $j['value'] === null && $j['recovering'] === false);
    $j = wf_judge($j, WF_CLEAN, true, 0.0, 1000, 180);
    wf_check($t, 'clean sets value and last_settled_at', $j['value'] === WF_CLEAN && $j['last_settled_at'] === 1000);
    $j2 = wf_judge($j, WF_UNKNOWN, false, null, 1015, 180);
    wf_check($t, 'unknown keeps the judgement', $j2['value'] === WF_CLEAN && $j2['unknown_since'] === 1015);
    $j3 = wf_judge($j2, WF_UNKNOWN, false, null, 1195, 180);
    wf_check($t, 'unknown for 180 s keeps it (not more than)', $j3['value'] === WF_CLEAN);
    $j4 = wf_judge($j3, WF_UNKNOWN, false, null, 1196, 180);
    wf_check($t, 'unknown for over 180 s becomes bad and recovering', $j4['value'] === WF_BAD && $j4['recovering']);
    $j5 = wf_judge($j, WF_UNAVAILABLE, false, null, 1020, 180);
    wf_check($t, 'unavailable sets bad, recovering, loss 100', $j5['value'] === WF_BAD && $j5['recovering'] && $j5['last_settled_loss'] === 100.0);
    $j6 = wf_judge($j5, WF_MARGINAL, true, 2.0, 1100, 180);
    wf_check($t, 'marginal after bad keeps recovering set', $j6['value'] === WF_MARGINAL && $j6['recovering']);
    wf_check($t, 'wf_up: clean and marginal are up', wf_up($j) && wf_up($j6) && !wf_up($j5));
    return wf_tally_report('judge', $t);
});
