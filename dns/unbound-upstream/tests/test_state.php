<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Runtime state under /var/run (spec section 3.3): round trip and every way a file can be unusable.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/state.php';

function uu_test_state_dir(): string
{
    $dir = sys_get_temp_dir() . '/uu-state-' . getmypid() . '-' . bin2hex(random_bytes(4));
    return $dir;
}

function uu_test_state_cleanup(string $dir): void
{
    foreach (glob($dir . '/*') ?: [] as $file) {
        unlink($file);
    }
    if (is_dir($dir)) {
        rmdir($dir);
    }
}

uu_register_suite('state', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $dir = uu_test_state_dir();
    $path = $dir . '/run/state.json';

    $new = uu_state_new();
    uu_check($t, 'new state: version 3, fallback, no member, no timers, no failures, not silent, no switch',
        UU_STATE_VERSION === 3 && $new['version'] === UU_STATE_VERSION && $new['mode'] === 'fallback'
        && $new['member'] === null && $new['timers'] === [] && $new['control_failures'] === 0
        && $new['control_silent_since'] === null && $new['last_switch'] === null);
    uu_check($t, 'new state: no checks yet, no TLS flag applied, no blocked count',
        $new['checks'] === ['direct' => null, 'unbound' => null] && $new['tls_applied'] === null
        && $new['blocked'] === null);

    uu_check($t, 'missing file loads as a new state', uu_state_load($path) === $new);

    $s = $new;
    $s['mode'] = 'tunnel';
    $s['member'] = 'wg-a';
    $s['timers'] = ['wg-a' => ['usable_since' => 1200, 'counted' => 45, 'last_at' => 1245,
        'resolver_failed_until' => null, 'probe_failures' => 1]];
    $s['control_failures'] = 2;
    $s['control_silent_since'] = 1300;
    $s['last_switch'] = ['at' => 1760000000, 'from' => 'fallback', 'to' => 'wg-a', 'reason' => 'member usable'];
    $s['checks'] = ['direct' => ['ok' => true, 'at' => 1760000001, 'member' => 'wg-a'],
                    'unbound' => ['ok' => false, 'at' => 1760000002, 'member' => 'wg-a']];
    $s['tls_applied'] = false;
    $s['blocked'] = 12;
    uu_state_save($path, $s);
    uu_check($t, 'round trip returns the saved state', uu_state_load($path) === $s);
    uu_check($t, 'save creates the directory 0700',
        (fileperms(dirname($path)) & 0777) === 0700);
    uu_check($t, 'save leaves no .tmp file behind', !file_exists($path . '.tmp'));

    uu_state_save($path, $new);
    uu_check($t, 'a second save replaces the first', uu_state_load($path) === $new);

    $json = json_encode($s);
    file_put_contents($path, substr((string)$json, 0, intdiv(strlen((string)$json), 2)));
    uu_check($t, 'truncated JSON loads as a new state', uu_state_load($path) === $new);

    file_put_contents($path, '');
    uu_check($t, 'an empty file loads as a new state', uu_state_load($path) === $new);

    file_put_contents($path, '"text"');
    uu_check($t, 'JSON that is not an object loads as a new state', uu_state_load($path) === $new);

    $wrong = $s;
    $wrong['version'] = UU_STATE_VERSION + 1;
    file_put_contents($path, json_encode($wrong));
    uu_check($t, 'a wrong version loads as a new state', uu_state_load($path) === $new);

    $bad = $s;
    $bad['timers'] = 'wg-a';
    file_put_contents($path, json_encode($bad));
    uu_check($t, 'a non-array timers loads as a new state', uu_state_load($path) === $new);

    $bad = $s;
    $bad['mode'] = 'sideways';
    file_put_contents($path, json_encode($bad));
    uu_check($t, 'an unknown mode loads as a new state', uu_state_load($path) === $new);

    $bad = $s;
    unset($bad['control_failures']);
    file_put_contents($path, json_encode($bad));
    uu_check($t, 'a missing field loads as a new state', uu_state_load($path) === $new);

    $bad = $s;
    $bad['timers']['wg-a']['counted'] = 'many';
    file_put_contents($path, json_encode($bad));
    uu_check($t, 'a timer with a wrongly typed field loads as a new state', uu_state_load($path) === $new);

    $bad = $s;
    $bad['control_silent_since'] = 'soon';
    file_put_contents($path, json_encode($bad));
    uu_check($t, 'a wrongly typed control_silent_since loads as a new state', uu_state_load($path) === $new);

    $bad = $s;
    $bad['checks']['direct'] = ['ok' => 'yes', 'at' => 1, 'member' => 'wg-a'];
    file_put_contents($path, json_encode($bad));
    uu_check($t, 'a wrongly typed check loads as a new state', uu_state_load($path) === $new);

    $bad = $s;
    unset($bad['checks']['unbound']);
    file_put_contents($path, json_encode($bad));
    uu_check($t, 'checks without the through-Unbound entry load as a new state', uu_state_load($path) === $new);

    $bad = $s;
    $bad['tls_applied'] = 1;
    file_put_contents($path, json_encode($bad));
    uu_check($t, 'a non-boolean tls_applied loads as a new state', uu_state_load($path) === $new);

    $bad = $s;
    $bad['blocked'] = '12';
    file_put_contents($path, json_encode($bad));
    uu_check($t, 'a non-integer blocked count loads as a new state', uu_state_load($path) === $new);

    $old = $s;
    unset($old['control_silent_since']);
    $old['version'] = 1;
    file_put_contents($path, json_encode($old));
    uu_check($t, 'a version 1 file (no control_silent_since) loads as a new state', uu_state_load($path) === $new);

    $old['version'] = UU_STATE_VERSION;
    file_put_contents($path, json_encode($old));
    uu_check($t, 'a current-version file without control_silent_since loads as a new state',
        uu_state_load($path) === $new);

    $old = $s;
    unset($old['checks'], $old['tls_applied'], $old['blocked']);
    $old['version'] = 2;
    file_put_contents($path, json_encode($old));
    uu_check($t, 'a version 2 file (no checks, tls_applied, blocked) loads as a new state',
        uu_state_load($path) === $new);

    $doc = json_decode((string)json_encode($s), true);
    uu_check($t, 'a decoded document of the State shape converts; any other is null',
        is_array($doc) && uu_state_from_doc($doc) === $s
        && uu_state_from_doc(['version' => UU_STATE_VERSION]) === null);

    uu_test_state_cleanup($dir . '/run');
    uu_test_state_cleanup($dir);
    return uu_tally_report('state', $t);
});
