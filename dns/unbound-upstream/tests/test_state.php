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
 * Runtime state under /var/run: round trip and every way a file can be unusable, the path read
 * as a regular file only, and the run directory's mode.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/state.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/snapshot.php';
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
    uu_check($t, 'new state: version 7, fallback, no member, no timers, no failures, not silent, no switch',
        UU_STATE_VERSION === 7 && $new['version'] === UU_STATE_VERSION && $new['mode'] === 'fallback'
        && $new['member'] === null && $new['timers'] === [] && $new['control_failures'] === 0
        && $new['control_silent_since'] === null && $new['last_switch'] === null);
    uu_check($t, 'new state: no checks yet, no TLS flag applied, no blocked count, no address recorded',
        $new['checks'] === ['direct' => null, 'unbound' => null] && $new['tls_applied'] === null
        && $new['blocked'] === null && $new['addresses'] === [] && count($new) === 12);

    uu_check($t, 'missing file loads as a new state', uu_state_load($path) === $new);

    $s = $new;
    $s['mode'] = 'tunnel';
    $s['member'] = 'wg-a';
    $s['timers'] = ['wg-a' => ['usable_since' => 1200, 'counted' => 45, 'last_at' => 1245,
        'resolver_failed_until' => null, 'probe_failures' => 1,
        'last_down' => ['at' => 5, 'reason' => 'x'], 'resolver' => '10.2.0.1']];
    $s['control_failures'] = 2;
    $s['control_silent_since'] = 1300;
    $s['last_switch'] = ['at' => 1760000000, 'from' => 'fallback', 'to' => 'wg-a', 'reason' => 'member usable'];
    $s['checks'] = ['direct' => ['ok' => true, 'at' => 1760000001, 'member' => 'wg-a'],
                    'unbound' => ['ok' => false, 'at' => 1760000002, 'member' => 'wg-a']];
    $s['tls_applied'] = false;
    $s['blocked'] = 12;
    $s['addresses'] = ['10.2.0.1' => ['route' => ['kind' => 'member', 'next_hop' => '10.2.0.2', 'if' => 'wg1'],
                                      'forwarded' => true, 'released_at' => null]];
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
    $bad['addresses']['10.2.0.1']['route']['kind'] = 'other';
    file_put_contents($path, json_encode($bad));
    uu_check($t, 'a route record of an unknown kind loads as a new state', uu_state_load($path) === $new);

    $bad = $s;
    unset($bad['addresses']['10.2.0.1']['route']['if']);
    file_put_contents($path, json_encode($bad));
    uu_check($t, 'a route record without its device loads as a new state', uu_state_load($path) === $new);

    $old = $s;
    unset($old['checks'], $old['tls_applied'], $old['blocked'], $old['addresses']);
    $old['version'] = 2;
    file_put_contents($path, json_encode($old));
    uu_check($t, 'a version 2 file (no checks, tls_applied, blocked) loads as a new state',
        uu_state_load($path) === $new);

    $old = $s;
    unset($old['addresses']);
    $old['version'] = 3;
    file_put_contents($path, json_encode($old));
    uu_check($t, 'a version 3 file (no route_installed) loads as a new state', uu_state_load($path) === $new);

    $old = $s;
    unset($old['addresses']);
    $old['version'] = 4;
    file_put_contents($path, json_encode($old));
    uu_check($t, 'a version 4 file (no resolver) loads as a new state', uu_state_load($path) === $new);

    $bad = $s;
    $bad['addresses'] = 10;
    file_put_contents($path, json_encode($bad));
    uu_check($t, 'a non-array addresses loads as a new state', uu_state_load($path) === $new);

    /* json_decode turns an all-digit gateway name into an int key; the timers must survive it */
    $digits = $s;
    $digits['timers'] = ['123' => $s['timers']['wg-a']];
    uu_state_save($path, $digits);
    $loaded = uu_state_load($path);
    uu_check($t, 'a timer of an all-digit gateway name survives the round trip',
        $loaded['mode'] === 'tunnel' && array_keys($loaded['timers']) === [123]
        && $loaded['timers'][123] === $s['timers']['wg-a']);

    $doc = json_decode((string)json_encode($s), true);
    uu_check($t, 'a decoded document of the State shape converts; any other is null',
        is_array($doc) && uu_state_from_doc($doc) === $s
        && uu_state_from_doc(['version' => UU_STATE_VERSION]) === null);

    $v11 = json_decode((string)json_encode($s), true);
    unset($v11['addresses'], $v11['view'], $v11['timers']['wg-a']['last_down'], $v11['timers']['wg-a']['resolver']);
    $v11['version'] = 5;
    $v11['route_installed'] = null;
    $v11['resolver'] = null;
    $from11 = is_array($v11) ? uu_state_from_doc($v11) : null;
    uu_check($t, 'state: a 1.1 timer without last_down loads (in a version 5 file), last_down null',
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

    /* only a regular file of at most UU_FILE_MAX_BYTES is read; anything else is a new state, and
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

    // State version 6: a map of the addresses the plugin may still be routed to.
    $member = ['kind' => 'member', 'next_hop' => '2001:db8:a::2', 'if' => 'wg3'];
    $rejected = ['kind' => 'reject', 'next_hop' => '', 'if' => 'lo0'];
    $two = $new;
    $two['mode'] = 'tunnel';
    $two['member'] = 'wg-a6';
    $two['addresses'] = [
        '2001:db8:a::53' => ['route' => $member, 'forwarded' => true, 'released_at' => null],
        '2001:db8:b::53' => ['route' => $rejected, 'forwarded' => false, 'released_at' => 9000],
    ];
    uu_state_save($path, $two);
    uu_check($t, 'state v6 (s1): two entries, a member route forwarded and a reject route released, survive save and read',
        uu_try_case(fn (): bool => uu_state_load($path) === $two
            && uu_state_read($path) === ['state' => $two, 'problem' => null]));
    uu_state_save($path, $new);
    uu_check($t, 'state v6 (s2): an empty map is written as "addresses":[] and reads back empty (and {} reads too)',
        uu_try_case(function () use ($path, $new): bool {
            $text = (string)file_get_contents($path);
            file_put_contents($path, str_replace('"addresses":[]', '"addresses":{}', $text));
            return str_contains($text, '"addresses":[]') && uu_state_load($path) === $new;
        }));
    $malformed = [
        'an entry with a fourth key' => function (array $d): array {
            $d['addresses']['2001:db8:a::53']['extra'] = 1;
            return $d;
        },
        'forwarded a string' => function (array $d): array {
            $d['addresses']['2001:db8:a::53']['forwarded'] = 'yes';
            return $d;
        },
        'released_at a string' => function (array $d): array {
            $d['addresses']['2001:db8:b::53']['released_at'] = '9000';
            return $d;
        },
        'a key that is not an address' => function (array $d): array {
            $d['addresses']['resolver.example'] = $d['addresses']['2001:db8:a::53'];
            return $d;
        },
        'a key that is an address in another spelling' => function (array $d): array {
            $d['addresses']['2001:DB8:A::53'] = $d['addresses']['2001:db8:a::53'];
            unset($d['addresses']['2001:db8:a::53']);
            return $d;
        },
        'an IPv4-mapped key' => function (array $d): array {
            $d['addresses']['::ffff:192.0.2.1'] = $d['addresses']['2001:db8:a::53'];
            return $d;
        },
        'addresses as a JSON list' => function (array $d): array {
            $d['addresses'] = [$d['addresses']['2001:db8:a::53']];
            return $d;
        },
        'a route of an unknown kind' => function (array $d): array {
            $d['addresses']['2001:db8:a::53']['route']['kind'] = 'other';
            return $d;
        },
        'an entry without its route' => function (array $d): array {
            unset($d['addresses']['2001:db8:a::53']['route']);
            $d['addresses']['2001:db8:a::53']['extra'] = null;
            return $d;
        },
        'a timer without resolver' => function (array $d): array {
            $d['timers'] = ['wg-a6' => ['usable_since' => null, 'counted' => 0, 'last_at' => null,
                'resolver_failed_until' => null, 'probe_failures' => 0, 'last_down' => null]];
            return $d;
        },
        'a timer whose resolver is not a string' => function (array $d): array {
            $d['timers'] = ['wg-a6' => ['usable_since' => null, 'counted' => 0, 'last_at' => null,
                'resolver_failed_until' => null, 'probe_failures' => 0, 'last_down' => null, 'resolver' => 5]];
            return $d;
        },
        'eleven keys plus one' => function (array $d): array {
            $d['resolver'] = '2001:db8:a::53';
            return $d;
        },
        'the old route_installed in place of addresses' => function (array $d): array {
            unset($d['addresses']);
            $d['route_installed'] = null;
            return $d;
        },
    ];
    foreach ($malformed as $what => $break) {
        $doc = json_decode((string)json_encode($two), true);
        uu_check($t, "state v6 (s3): $what is not this version's shape",
            uu_try_case(function () use ($doc, $break, $path, $new): bool {
                file_put_contents($path, json_encode($break($doc)));
                return uu_state_from_doc($break($doc)) === null
                    && uu_state_read($path) === ['state' => $new, 'problem' => 'not this version\'s shape'];
            }));
    }

    // A version 5 file converts on read; nothing writes it back.
    $v5 = [
        'version' => 5, 'mode' => 'tunnel', 'member' => 'wg-a',
        'timers' => ['wg-a' => ['usable_since' => 1200, 'counted' => 45, 'last_at' => 1245,
            'resolver_failed_until' => 1400, 'probe_failures' => 1, 'last_down' => ['at' => 5, 'reason' => 'x']],
                     'wg-b' => ['usable_since' => null, 'counted' => 0, 'last_at' => null,
            'resolver_failed_until' => null, 'probe_failures' => 0]],
        'control_failures' => 2, 'control_silent_since' => 1300,
        'last_switch' => ['at' => 1760000000, 'from' => 'fallback', 'to' => 'wg-a', 'reason' => 'member usable'],
        'checks' => ['direct' => ['ok' => true, 'at' => 1760000001, 'member' => 'wg-a'], 'unbound' => null],
        'tls_applied' => false, 'blocked' => 12,
        'route_installed' => ['kind' => 'member', 'next_hop' => '10.2.0.4', 'if' => 'wg1'],
        'resolver' => '10.2.0.1',
    ];
    $converted = uu_state_from_doc($v5);
    uu_check($t, 'state v6 (s4): a version 5 tunnel-mode file converts to one forwarded entry with its route kept',
        $converted !== null && $converted['version'] === 7 && $converted['mode'] === 'tunnel'
        && $converted['member'] === 'wg-a' && $converted['control_failures'] === 2
        && $converted['addresses'] === ['10.2.0.1' => ['route' => $v5['route_installed'], 'forwarded' => true,
                                                        'released_at' => null]]
        && $converted['blocked'] === 12 && $converted['tls_applied'] === false
        && $converted['last_switch'] === $v5['last_switch'] && $converted['checks'] === $v5['checks']);
    uu_check($t, 'state v6 (s4): each timer of a version 5 file gains resolver "" and last_down null when it had none',
        $converted !== null && $converted['timers']['wg-a']['resolver'] === ''
        && $converted['timers']['wg-a']['last_down'] === ['at' => 5, 'reason' => 'x']
        && $converted['timers']['wg-a']['resolver_failed_until'] === 1400
        && $converted['timers']['wg-b'] === ['usable_since' => null, 'counted' => 0, 'last_at' => null,
            'resolver_failed_until' => null, 'probe_failures' => 0, 'last_down' => null, 'resolver' => '']);
    uu_check($t, 'state v6 (s4): the converted route is adopted from a live route that matches it',
        uu_try_case(function () use ($converted): bool {
            if ($converted === null) {
                return false;
            }
            $route = ['present' => true, 'gateway' => '10.2.0.4', 'interface' => 'wg1', 'reject' => false,
                      'ours' => false];
            $live = ['settings' => ['default' => '10.2.0.1'], 'routes' => ['10.2.0.1' => $route],
                     'contract_input' => ['foreign' => ['10.2.0.1']]];
            $adopted = uu_route_adopt($live, $converted['addresses']);
            $otherRoute = ['gateway' => '10.2.0.5'] + $route;
            $other = ['routes' => ['10.2.0.1' => $otherRoute]] + $live;
            return $adopted['routes']['10.2.0.1']['ours'] === true
                && uu_route_adopt($other, $converted['addresses']) === $other;
        }));
    $v5Fallback = $v5;
    $v5Fallback['mode'] = 'fallback';
    $v5Fallback['member'] = null;
    $v5Fallback['route_installed'] = null;
    $fromFallback = uu_state_from_doc($v5Fallback);
    uu_check($t, 'state v6 (s5): a version 5 file with a resolver and no route record converts to one entry, route null, '
        . 'not forwarded',
        $fromFallback !== null && $fromFallback['addresses'] === ['10.2.0.1' => ['route' => null,
            'forwarded' => false, 'released_at' => null]]);
    $v5NoResolver = $v5;
    $v5NoResolver['resolver'] = null;
    $v5Named = $v5;
    $v5Named['resolver'] = 'resolver.example';
    $v5Upper = $v5;
    $v5Upper['resolver'] = '2001:DB8:A:0::0053';
    uu_check($t, 'state v6 (s6): a version 5 file with no resolver, or one that is no address, converts to an empty map '
        . 'whatever route_installed says; an IPv6 one is keyed canonical',
        uu_try_case(fn (): bool => (uu_state_from_doc($v5NoResolver)['addresses'] ?? null) === []
            && (uu_state_from_doc($v5Named)['addresses'] ?? null) === []
            && array_keys(uu_state_from_doc($v5Upper)['addresses'] ?? []) === ['2001:db8:a::53']));
    uu_check($t, 'state v6: a version 5 file that is not exactly 1.3\'s shape is not converted',
        uu_try_case(function () use ($v5): bool {
            $extra = $v5 + ['addresses' => []];
            $noResolver = $v5;
            unset($noResolver['resolver']);
            $badRoute = $v5;
            $badRoute['route_installed']['kind'] = 'other';
            $badTimer = $v5;
            $badTimer['timers']['wg-a']['resolver'] = '';
            return uu_state_from_doc($extra) === null && uu_state_from_doc($noResolver) === null
                && uu_state_from_doc($badRoute) === null && uu_state_from_doc($badTimer) === null;
        }));
    uu_check($t, 'state v6 (s4): reading a version 5 file reports no problem and leaves the file as it was',
        uu_scratch_case(function (string $dir) use ($v5, $converted): bool {
            $text = (string)json_encode($v5);
            file_put_contents($dir . '/state.json', $text);
            $read = uu_state_read($dir . '/state.json');
            uu_state_load($dir . '/state.json');
            return $read === ['state' => $converted, 'problem' => null]
                && file_get_contents($dir . '/state.json') === $text;
        }));
    $v5Doc = json_decode((string)json_encode($v5), true);
    $v6Round = is_array($v5Doc) ? uu_state_from_doc($v5Doc) : null;
    uu_check($t, 'state v6: a converted state saves and reads back as itself',
        $v6Round !== null && uu_try_case(function () use ($v6Round, $path): bool {
            uu_state_save($path, $v6Round);
            return uu_state_load($path) === $v6Round;
        }));

    uu_check($t, 'state: a version 6 file converts with the view none',
        uu_try_case(function () use ($s, $new): bool {
            $v6 = json_decode((string)json_encode($s), true);
            if (!is_array($v6)) {
                return false;
            }
            unset($v6['view']);
            $v6['version'] = 6;
            $converted = uu_state_from_doc($v6);
            $extra = $v6;
            $extra['view'] = $new['view'];
            $short = $v6;
            unset($short['blocked']);
            return $converted === $s && $s['view'] === ['refuse' => 'none', 'scope' => 'none', 'nets' => [],
                'problem' => null, 'restarted' => null, 'unwritable' => 0] && uu_state_from_doc($extra) === null
                && uu_state_from_doc($short) === null;
        }));
    uu_check($t, 'state: a view record of another shape is refused',
        uu_try_case(function () use ($s): bool {
            $doc = json_decode((string)json_encode($s), true);
            if (!is_array($doc)) {
                return false;
            }
            $bad = [];
            foreach ([['refuse', 'maybe'], ['refuse', null], ['scope', 7], ['nets', 'x'], ['nets', [4]],
                      ['nets', ['a' => 'x']], ['problem', 3], ['restarted', 7], ['unwritable', -1],
                      ['unwritable', '1'], ['unwritable', null]] as [$key, $value]) {
                $variant = $doc;
                $variant['view'][$key] = $value;
                $bad[] = uu_state_from_doc($variant);
            }
            $missing = $doc;
            unset($missing['view']['problem']);
            $noRestarted = $doc;
            unset($noRestarted['view']['restarted']);
            $noUnwritable = $doc;
            unset($noUnwritable['view']['unwritable']);
            $extra = $doc;
            $extra['view']['more'] = 1;
            $notArray = $doc;
            $notArray['view'] = 'none';
            $absent = $doc;
            unset($absent['view']);
            $armed = $doc;
            $armed['view'] = ['refuse' => 'armed', 'scope' => 'set', 'nets' => ['192.0.2.0/24'], 'problem' => 'x',
                'restarted' => hash('sha256', ''), 'unwritable' => 2];
            return array_filter($bad, fn (?array $r): bool => $r !== null) === []
                && uu_state_from_doc($missing) === null && uu_state_from_doc($noRestarted) === null
                && uu_state_from_doc($noUnwritable) === null
                && uu_state_from_doc($extra) === null
                && uu_state_from_doc($notArray) === null && uu_state_from_doc($absent) === null
                && (uu_state_from_doc($armed)['view'] ?? null) === $armed['view'];
        }));
    uu_check($t, 'state: armed and lifted are a footprint, none is not',
        uu_try_case(function (): bool {
            $st = uu_state_new();
            $out = [uu_state_view_footprint($st, false)];
            foreach (['armed', 'lifted'] as $refuse) {
                $st['view']['refuse'] = $refuse;
                $out[] = uu_state_view_footprint($st, false);
            }
            return $out === [false, true, true];
        }));
    uu_check($t, 'state: a file on disk is a footprint',
        uu_try_case(fn (): bool => uu_state_view_footprint(uu_state_new(), true)
            && uu_state_footprint(uu_state_new()) === []));
    uu_check($t, 'state: a version 5 file converts through 6 to 7',
        uu_try_case(function () use ($v5): bool {
            $st = uu_state_from_doc($v5);
            return $st !== null && $st['version'] === 7
                && $st['view'] === ['refuse' => 'none', 'scope' => 'none', 'nets' => [], 'problem' => null,
                    'restarted' => null, 'unwritable' => 0];
        }));

    // The footprint: the map's keys, and what an evaluation that changed it runs.
    $recorded = uu_state_new();
    $recorded['addresses'] = ['192.0.2.1' => ['route' => null, 'forwarded' => false, 'released_at' => null]];
    uu_check($t, 'footprint: the recorded addresses, sorted; none when the map is empty',
        uu_try_case(fn (): bool => uu_state_footprint($recorded) === ['192.0.2.1']
            && uu_state_footprint(uu_state_new()) === []
            && uu_state_footprint($two) === ['2001:db8:a::53', '2001:db8:b::53']));
    $reordered = $two;
    $reordered['addresses'] = array_reverse($two['addresses'], true);
    uu_check($t, 'footprint: the order of the map does not matter',
        uu_try_case(fn (): bool => uu_state_footprint($reordered) === uu_state_footprint($two)));
    uu_check($t, 'route record: the entry\'s route by the address in any spelling; none for no entry or a null route',
        uu_try_case(fn (): bool => uu_state_route_record($two, '2001:db8:a::53') === $member
            && uu_state_route_record($two, '2001:DB8:A:0::0053') === $member
            && uu_state_route_record($two, '2001:db8:b::53') === $rejected
            && uu_state_route_record($two, '192.0.2.1') === null
            && uu_state_route_record($recorded, '192.0.2.1') === null
            && uu_state_route_record(uu_state_new(), 'not an address') === null));
    uu_check($t, '(s8) footprint text: none for the empty list, the address for one, a comma list for more',
        uu_try_case(fn (): bool => uu_footprint_text([]) === 'none' && uu_footprint_text(['10.2.0.1']) === '10.2.0.1'
            && uu_footprint_text(['192.0.2.1', '2001:db8:a::53']) === '192.0.2.1, 2001:db8:a::53'));
    /* the minute job is there while the plugin is enabled or a footprint is recorded: disabled, it comes and goes
     * with the footprint */
    $a = ['192.0.2.1'];
    $ab = ['192.0.2.1', '192.0.2.9'];
    $cases = [
        '[] → [A], enabled: reload only' => [[], $a, true, true, false],
        '[] → [A], disabled: reload, and cron so the job stays for it' => [[], $a, false, true, true],
        '[A] → [], enabled: reload only' => [$a, [], true, true, false],
        '[A] → [], disabled: reload, and cron so the job goes' => [$a, [], false, true, true],
        '[A] → [A], enabled: nothing' => [$a, $a, true, false, false],
        '[A] → [A], disabled: nothing' => [$a, $a, false, false, false],
        '[A] → [B], enabled: reload only' => [$a, ['192.0.2.9'], true, true, false],
        '[A] → [B], disabled: reload only, the job stays' => [$a, ['192.0.2.9'], false, true, false],
        '[A] → [A, B], enabled: reload only' => [$a, $ab, true, true, false],
        '[A] → [A, B], disabled: reload only, the job stays' => [$a, $ab, false, true, false],
        '[A, B] → [A], disabled: reload only, the job stays' => [$ab, $a, false, true, false],
        '[] → [], enabled: nothing' => [[], [], true, false, false],
        '[] → [], disabled: nothing' => [[], [], false, false, false],
    ];
    foreach ($cases as $what => [$before, $after, $enabled, $reload, $cron]) {
        uu_check($t, (str_contains($what, 'A, B') ? '(s7)' : '(e1)') . " footprint $what",
            uu_try_case(fn (): bool => uu_footprint_actions($before, $after, $enabled, null)
                === ['reload' => $reload, 'cron' => $cron]));
    }
    /* a tick while the removal marker exists is an evaluation and follows the footprint; only remove
     * itself waits, and runs core's reload and cron restart after its stop */
    $marker = [
        'a tick while the removal marker exists, A → none, enabled: reload' => [true, true, false],
        'a tick while the removal marker exists, A → none, disabled: reload and cron' => [false, true, true],
    ];
    foreach ($marker as $what => [$enabled, $reload, $cron]) {
        uu_check($t, "footprint $what",
            uu_try_case(fn (): bool => uu_footprint_actions($a, [], $enabled, UU_STOP_REMOVING)
                === ['reload' => $reload, 'cron' => $cron]));
    }
    foreach (['A → none' => [$a, []], 'none → A' => [[], $a], 'A → B' => [$a, ['192.0.2.9']]] as $what => [$before, $after]) {
        uu_check($t, "footprint $what in remove itself, enabled or disabled: nothing until its stop is over",
            uu_try_case(fn (): bool => uu_footprint_actions($before, $after, true, UU_STOP_REMOVE)
                === ['reload' => false, 'cron' => false]
                && uu_footprint_actions($before, $after, false, UU_STOP_REMOVE)
                === ['reload' => false, 'cron' => false]));
    }
    uu_check($t, 'footprint A → none in a requested stop: as an evaluation',
        uu_try_case(fn (): bool => uu_footprint_actions($a, [], false, UU_STOP_REQUEST)
            === ['reload' => true, 'cron' => true]));
    uu_check($t, 'footprint: a view footprint that comes or goes while disabled restarts cron, never the filter',
        uu_try_case(fn (): bool => uu_footprint_actions([], [], false, null, false, true)
            === ['reload' => false, 'cron' => true]
            && uu_footprint_actions([], [], false, null, true, false) === ['reload' => false, 'cron' => true]
            && uu_footprint_actions([], [], true, null, true, false) === ['reload' => false, 'cron' => false]
            && uu_footprint_actions([], [], false, null, true, true) === ['reload' => false, 'cron' => false]
            /* the minute job stays while either footprint remains */
            && uu_footprint_actions($a, [], false, null, true, true) === ['reload' => true, 'cron' => false]
            && uu_footprint_actions([], $a, false, null, true, false) === ['reload' => true, 'cron' => false]
            && uu_footprint_actions([], [], false, UU_STOP_REMOVE, true, false)
            === ['reload' => false, 'cron' => false]));

    uu_test_state_cleanup($dir . '/run');
    uu_test_state_cleanup($dir);
    // The forwarded rule, as the planner's reject routes and apply's entries take it from a live root read.
    uu_check($t, 'forwarded: a read naming the address (as Unbound prints a forwarder, with @port or #name, in any '
        . 'spelling) is true; one naming only others is false, whatever was recorded',
        uu_try_case(fn (): bool => uu_state_forwarded(['2001:db8:a::53@53#dns.example'], '2001:db8:a::53', false)
            && uu_state_forwarded(['192.0.2.53', '2001:DB8:A:0::53'], '2001:db8:a::53', false)
            && uu_state_forwarded(['10.2.0.1'], '10.2.0.1', false)
            && uu_state_forwarded(['192.0.2.53#dns.example'], '192.0.2.53', false)
            && !uu_state_forwarded(['192.0.2.53@853#dns.example'], '10.2.0.1', true)
            && !uu_state_forwarded([], '10.2.0.1', true)));
    uu_check($t, 'forwarded: a read that failed keeps what was recorded',
        uu_try_case(fn (): bool => uu_state_forwarded(null, '10.2.0.1', true)
            && !uu_state_forwarded(null, '10.2.0.1', false)));
    uu_check($t, 'snapshot read: the live root while Unbound runs (null when its channel did not answer), the empty '
        . 'root when it does not run',
        uu_try_case(fn (): bool => uu_state_snapshot_read(['pid_alive' => true, 'live_root' => ['10.2.0.1']])
                === ['10.2.0.1']
            && uu_state_snapshot_read(['pid_alive' => true, 'live_root' => null]) === null
            && uu_state_snapshot_read(['pid_alive' => false, 'live_root' => null]) === []
            && uu_state_snapshot_read(['pid_alive' => false, 'live_root' => ['10.2.0.1']]) === []));

    return uu_tally_report('state', $t);
});
