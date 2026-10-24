<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Runtime state under /var/run (spec section 3.3): round trip and every way a file can be unusable, the path read
 * as a regular file only, and the run directory's mode (convention C3).
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/state.php';
require_once __DIR__ . '/scratch.php';

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
    uu_check($t, 'new state: version 5, fallback, no member, no timers, no failures, not silent, no switch',
        UU_STATE_VERSION === 5 && $new['version'] === UU_STATE_VERSION && $new['mode'] === 'fallback'
        && $new['member'] === null && $new['timers'] === [] && $new['control_failures'] === 0
        && $new['control_silent_since'] === null && $new['last_switch'] === null);
    uu_check($t, 'new state: no checks yet, no TLS flag applied, no blocked count, no route installed, no resolver',
        $new['checks'] === ['direct' => null, 'unbound' => null] && $new['tls_applied'] === null
        && $new['blocked'] === null && $new['route_installed'] === null && $new['resolver'] === null);

    uu_check($t, 'missing file loads as a new state', uu_state_load($path) === $new);

    $s = $new;
    $s['mode'] = 'tunnel';
    $s['member'] = 'wg-a';
    $s['timers'] = ['wg-a' => ['usable_since' => 1200, 'counted' => 45, 'last_at' => 1245,
        'resolver_failed_until' => null, 'probe_failures' => 1,
        'last_down' => ['at' => 5, 'reason' => 'x']]];
    $s['control_failures'] = 2;
    $s['control_silent_since'] = 1300;
    $s['last_switch'] = ['at' => 1760000000, 'from' => 'fallback', 'to' => 'wg-a', 'reason' => 'member usable'];
    $s['checks'] = ['direct' => ['ok' => true, 'at' => 1760000001, 'member' => 'wg-a'],
                    'unbound' => ['ok' => false, 'at' => 1760000002, 'member' => 'wg-a']];
    $s['tls_applied'] = false;
    $s['blocked'] = 12;
    $s['route_installed'] = ['kind' => 'member', 'next_hop' => '10.2.0.2', 'if' => 'wg1'];
    $s['resolver'] = '10.2.0.1';
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

    $bad = $s;
    $bad['route_installed']['kind'] = 'other';
    file_put_contents($path, json_encode($bad));
    uu_check($t, 'a route record of an unknown kind loads as a new state', uu_state_load($path) === $new);

    $bad = $s;
    unset($bad['route_installed']['if']);
    file_put_contents($path, json_encode($bad));
    uu_check($t, 'a route record without its device loads as a new state', uu_state_load($path) === $new);

    $old = $s;
    unset($old['checks'], $old['tls_applied'], $old['blocked'], $old['route_installed']);
    $old['version'] = 2;
    file_put_contents($path, json_encode($old));
    uu_check($t, 'a version 2 file (no checks, tls_applied, blocked) loads as a new state',
        uu_state_load($path) === $new);

    $old = $s;
    unset($old['route_installed'], $old['resolver']);
    $old['version'] = 3;
    file_put_contents($path, json_encode($old));
    uu_check($t, 'a version 3 file (no route_installed) loads as a new state', uu_state_load($path) === $new);

    $old = $s;
    unset($old['resolver']);
    $old['version'] = 4;
    file_put_contents($path, json_encode($old));
    uu_check($t, 'a version 4 file (no resolver) loads as a new state', uu_state_load($path) === $new);

    $bad = $s;
    $bad['resolver'] = 10;
    file_put_contents($path, json_encode($bad));
    uu_check($t, 'a non-string resolver loads as a new state', uu_state_load($path) === $new);

    /* finding M4: json_decode turns an all-digit gateway name into an int key; the timers must survive it */
    $digits = $s;
    $digits['timers'] = ['123' => $s['timers']['wg-a']];
    uu_state_save($path, $digits);
    $loaded = uu_state_load($path);
    uu_check($t, 'a timer of an all-digit gateway name survives the round trip',
        $loaded['mode'] === 'tunnel' && array_keys($loaded['timers']) === [123]
        && $loaded['timers'][123] === $s['timers']['wg-a']);

    $marked = $s;
    $marked['timers']['wg-a']['resolver_failed_until'] = 1400;
    $forgot = uu_state_forget_resolver($marked);
    $want = $marked;
    $want['timers']['wg-a']['resolver_failed_until'] = null;
    $want['timers']['wg-a']['probe_failures'] = 0;
    uu_check($t, 'forgetting an undone resolver clears every resolver-failed mark and probe failure count, nothing else',
        $forgot === $want);

    $doc = json_decode((string)json_encode($s), true);
    uu_check($t, 'a decoded document of the State shape converts; any other is null',
        is_array($doc) && uu_state_from_doc($doc) === $s
        && uu_state_from_doc(['version' => UU_STATE_VERSION]) === null);

    $v11 = json_decode((string)json_encode($s), true);
    unset($v11['timers']['wg-a']['last_down']);
    $from11 = is_array($v11) ? uu_state_from_doc($v11) : null;
    uu_check($t, 'state: a 1.1 timer without last_down loads, last_down null',
        $from11 !== null && $from11['timers']['wg-a']['last_down'] === null
        && $from11['timers']['wg-a']['counted'] === 45);
    $rt = json_decode((string)json_encode($s), true);
    $badAt = $rt;
    unset($badAt['timers']['wg-a']['last_down']['at']);
    $badType = $rt;
    $badType['timers']['wg-a']['last_down']['at'] = 'soon';
    uu_check($t, 'state: last_down round-trips; a missing or non-int at makes the document invalid',
        is_array($rt) && uu_state_from_doc($rt) === $s
        && is_array($badAt) && uu_state_from_doc($badAt) === null
        && is_array($badType) && uu_state_from_doc($badType) === null);

    /* convention C3: only a regular file of at most UU_FILE_MAX_BYTES is read; anything else is a new state, and
     * the read names why */
    $valid = (string)json_encode($s);
    $reads = function (string $kind, string $problem) use ($valid, $new): bool {
        return uu_scratch_case(function (string $dir) use ($kind, $problem, $valid, $new): bool {
            uu_scratch_place($kind, $dir . '/state.json', $valid);
            return uu_state_read($dir . '/state.json') === ['state' => $new, 'problem' => $problem]
                && uu_state_load($dir . '/state.json') === $new;
        });
    };
    uu_check($t, '(s1) read: a symbolic link to a valid state file is a new state, "a symbolic link"',
        $reads('link', 'a symbolic link'));
    uu_check($t, 'read: a dangling symbolic link is a new state, "a symbolic link", not a missing file',
        uu_scratch_case(fn (string $dir): bool => symlink($dir . '/none', $dir . '/state.json')
            && uu_state_read($dir . '/state.json') === ['state' => $new, 'problem' => 'a symbolic link']));
    uu_check($t, '(s2) read: a directory at the path is a new state, "not a regular file"',
        $reads('dir', 'not a regular file'));
    uu_check($t, 'read: a named pipe at the path is a new state, "not a regular file", at once (never opened)',
        $reads('fifo', 'not a regular file'));
    uu_check($t, '(s3) read: a valid state padded to 1 MiB + 1 byte is a new state, "larger than 1 MiB"',
        $reads('large', 'larger than 1 MiB'));
    uu_check($t, '(s4) read: a missing path is a new state with no problem',
        uu_scratch_case(fn (string $dir): bool
            => uu_state_read($dir . '/state.json') === ['state' => $new, 'problem' => null]));
    uu_check($t, 'read: a path below a missing directory is a new state with no problem',
        uu_scratch_case(fn (string $dir): bool
            => uu_state_read($dir . '/run/state.json') === ['state' => $new, 'problem' => null]));
    uu_check($t, 'read: a valid state padded to exactly 1 MiB is read, with no problem',
        uu_scratch_case(function (string $dir) use ($valid, $s): bool {
            file_put_contents($dir . '/state.json', str_pad($valid, UU_SCRATCH_MIB, ' '));
            return uu_state_read($dir . '/state.json') === ['state' => $s, 'problem' => null];
        }));
    uu_check($t, 'read: a file that is not JSON is a new state, "not JSON"',
        uu_scratch_case(function (string $dir) use ($valid, $new): bool {
            file_put_contents($dir . '/state.json', substr($valid, 0, 20));
            return uu_state_read($dir . '/state.json') === ['state' => $new, 'problem' => 'not JSON'];
        }));
    uu_check($t, 'read: JSON of another shape is a new state, "not this version\'s shape"',
        uu_scratch_case(function (string $dir) use ($wrong, $new): bool {
            file_put_contents($dir . '/state.json', json_encode($wrong));
            return uu_state_read($dir . '/state.json') === ['state' => $new, 'problem' => 'not this version\'s shape'];
        }));

    /* the run directory: created 0700, an existing one put back to 0700, and anything but a directory refused */
    uu_check($t, '(s5) run dir: an existing 0755 directory is left 0700',
        uu_scratch_case(function (string $dir): bool {
            mkdir($dir . '/run');
            chmod($dir . '/run', 0755);
            uu_run_dir($dir . '/run');
            clearstatcache();
            return (fileperms($dir . '/run') & 07777) === 0700;
        }));
    uu_check($t, 'run dir: a missing directory is created 0700',
        uu_scratch_case(function (string $dir): bool {
            uu_run_dir($dir . '/run');
            return is_dir($dir . '/run') && !is_link($dir . '/run') && (fileperms($dir . '/run') & 07777) === 0700;
        }));
    $refuses = function (callable $place): bool {
        return uu_scratch_case(function (string $dir) use ($place): bool {
            $place($dir);
            try {
                uu_run_dir($dir . '/run');
            } catch (\RuntimeException) {
                return true;
            }
            return false;
        });
    };
    uu_check($t, 'run dir: a symbolic link to a directory throws',
        $refuses(fn (string $dir): bool => mkdir($dir . '/real', 0700) && symlink($dir . '/real', $dir . '/run')));
    uu_check($t, 'run dir: a regular file at the path throws',
        $refuses(fn (string $dir): bool => file_put_contents($dir . '/run', 'x') === 1));

    // The footprint (spec -04 section 3.2): one definition, and what an evaluation that changed it runs (ruling R4,
    // decision D4).
    $recorded = uu_state_new();
    $recorded['resolver'] = '192.0.2.1';
    $named = uu_state_new();
    $named['resolver'] = 'resolver.example';
    uu_check($t, 'footprint: the recorded address when it is IPv4; none when nothing is recorded or it is not IPv4',
        uu_try_case(fn (): bool => uu_state_footprint($recorded) === '192.0.2.1'
            && uu_state_footprint(uu_state_new()) === null && uu_state_footprint($named) === null));
    /* the minute job is there while the plugin is enabled or a footprint is recorded: disabled, it comes and goes
     * with the footprint */
    $cases = [
        'null → A, enabled: reload only' => [null, '192.0.2.1', true, true, false],
        'null → A, disabled: reload, and cron so the job stays for it' => [null, '192.0.2.1', false, true, true],
        'A → null, enabled: reload only' => ['192.0.2.1', null, true, true, false],
        'A → null, disabled: reload, and cron so the job goes' => ['192.0.2.1', null, false, true, true],
        'A → A, enabled: nothing' => ['192.0.2.1', '192.0.2.1', true, false, false],
        'A → A, disabled: nothing' => ['192.0.2.1', '192.0.2.1', false, false, false],
        'A → B, enabled: reload only' => ['192.0.2.1', '192.0.2.9', true, true, false],
        'A → B, disabled: reload only, the job stays' => ['192.0.2.1', '192.0.2.9', false, true, false],
        'null → null, enabled: nothing' => [null, null, true, false, false],
        'null → null, disabled: nothing' => [null, null, false, false, false],
    ];
    foreach ($cases as $what => [$before, $after, $enabled, $reload, $cron]) {
        uu_check($t, "(e1) footprint $what",
            uu_try_case(fn (): bool => uu_footprint_actions($before, $after, $enabled)
                === ['reload' => $reload, 'cron' => $cron]));
    }

    uu_test_state_cleanup($dir . '/run');
    uu_test_state_cleanup($dir);
    return uu_tally_report('state', $t);
});
