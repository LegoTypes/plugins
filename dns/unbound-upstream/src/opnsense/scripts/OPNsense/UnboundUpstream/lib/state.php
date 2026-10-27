<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Runtime state under /var/run. Lost at boot on purpose: a boot starts in fallback.
 *
 * State = array{version: int, mode: string, member: ?string, timers: Timers, control_failures: int,
 *               control_silent_since: ?int, last_switch: ?array{at: int, from: string, to: string, reason: string},
 *               checks: array{direct: ?Check, unbound: ?Check}, tls_applied: ?bool, blocked: ?int,
 *               addresses: array<string, Entry>}
 * Check = array{ok: bool, at: int, member: string}
 * Entry = array{route: ?RouteRecord, forwarded: bool, released_at: ?int}
 * RouteRecord = array{kind: string, next_hop: string, if: string}  (kind 'member' or 'reject'; a reject route is
 *               next_hop '' on lo0, as route(8) prints it)
 * mode is 'tunnel' or 'fallback'. Timers (choose.php) and control_silent_since (the first of the consecutive
 * evaluations with a silent control channel) are monotonic seconds; last_switch.at and the checks' at are
 * wall-clock time, for display only. checks are the last direct and through-Unbound results,
 * tls_applied the TLS flag the plugin last gave forward_add (Unbound cannot print it back; null before the plugin
 * set the forwarders) and blocked the counting table's blocked packets at the last evaluation, so a rise is logged.
 * addresses holds every resolver address the plugin may still be routed to, keyed by its canonical form: an address
 * is in the map while its route is present and the plugin's, or while forwarded is true (the plugin is in tunnel mode
 * on it, sent forward_add for it and has not seen Unbound forward elsewhere, or the live root names it). route is
 * the resolver route the plugin last added or changed for that address (null when none was installed in this file or
 * after its delete), so the route stays the plugin's own when the group that explained it is renamed or deleted;
 * released_at is the monotonic second an address left use, null while in use. A Save that changes the resolver
 * setting undoes every other recorded address's route and forwarders first. A version 5 file (one resolver and one
 * route_installed) converts on read. A file that cannot be read back exactly as written is discarded: the planner
 * derives the mode from the live forwarders and route, so a fresh state costs only the failback timers. The file lives in the root-only run directory and is read as a
 * regular file only.
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/address.php';

const UU_STATE_VERSION = 6;

/**
 * The plugin's runtime directory (UU_RUN_DIR by default), root's alone, since what it holds is trusted: created
 * 0700 when missing, put back to 0700 when its mode differs, refused when the path is a symbolic link or not a
 * directory.
 */
function uu_run_dir(string $dir = UU_RUN_DIR): void
{
    clearstatcache(true, $dir);
    if (@lstat($dir) === false) {
        /* a failure, or another process's mkdir in between, is judged by the checks below */
        @mkdir($dir, 0700, true);
        clearstatcache(true, $dir);
    }
    $st = @lstat($dir);
    if ($st === false) {
        throw new RuntimeException("cannot create $dir");
    }
    if (($st['mode'] & 0170000) === 0120000) {
        throw new RuntimeException("$dir is a symbolic link");
    }
    if (($st['mode'] & 0170000) !== 0040000) {
        throw new RuntimeException("$dir is not a directory");
    }
    if (($st['mode'] & 07777) !== 0700 && !@chmod($dir, 0700)) {
        throw new RuntimeException("cannot make $dir mode 0700");
    }
}

/**
 * A file the plugin trusts, read as a regular file only: the path is no symbolic link and a regular file (lstat), and
 * the file opened is the one checked (the same device and inode), so a swap between the check and the open is refused,
 * and the open never blocks. The open still follows a link swapped in after the lstat, so this reader is for files in a
 * directory only root can write (UU_RUN_DIR); Unbound's goes through zone_read.py, which opens no path through a link.
 * A missing path, or one below a directory this process cannot search, has no text and no problem; with a problem there
 * is no text either.
 *
 * @return array{text: ?string, problem: ?string} problem: 'a symbolic link', 'not a regular file', 'larger than
 *     1 MiB' (the default limit) or 'unreadable'
 */
function uu_read_regular_file(string $path, int $maxBytes = UU_FILE_MAX_BYTES): array
{
    clearstatcache(true, $path);
    $link = @lstat($path);
    if ($link === false) {
        return ['text' => null, 'problem' => null];
    }
    if (($link['mode'] & 0170000) === 0120000) {
        return ['text' => null, 'problem' => 'a symbolic link'];
    }
    if (($link['mode'] & 0170000) !== 0100000) {
        return ['text' => null, 'problem' => 'not a regular file'];
    }
    /* n is O_NONBLOCK (the plain-files wrapper): a FIFO or device swapped in after the lstat opens at once, and the
     * identity check below refuses it, instead of the open blocking until a writer appears; a regular file ignores
     * the flag */
    $fh = @fopen($path, 'rbn');
    if ($fh === false) {
        return ['text' => null, 'problem' => 'unreadable'];
    }
    try {
        $st = fstat($fh);
        if ($st === false || $st['dev'] !== $link['dev'] || $st['ino'] !== $link['ino']) {
            return ['text' => null, 'problem' => 'unreadable'];
        }
        $text = stream_get_contents($fh, $maxBytes + 1);
        if ($text === false) {
            return ['text' => null, 'problem' => 'unreadable'];
        }
        if (strlen($text) > $maxBytes) {
            $limit = $maxBytes > 0 && $maxBytes % 1048576 === 0
                ? intdiv($maxBytes, 1048576) . ' MiB' : "$maxBytes bytes";
            return ['text' => null, 'problem' => "larger than $limit"];
        }
        return ['text' => $text, 'problem' => null];
    } finally {
        fclose($fh);
    }
}

/**
 * @return array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int,
 *         last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
 *     control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *         forwarded: bool, released_at: ?int}>}
 */
function uu_state_new(): array
{
    return [
        'version' => UU_STATE_VERSION,
        'mode' => 'fallback',
        'member' => null,
        'timers' => [],
        'control_failures' => 0,
        'control_silent_since' => null,
        'last_switch' => null,
        'checks' => ['direct' => null, 'unbound' => null],
        'tls_applied' => null,
        'blocked' => null,
        'addresses' => [],
    ];
}

/**
 * A timer exactly as the version has it: seven keys in this version (1.3's six and the resolver the failed mark and
 * probe failures are about); in a version 5 file the five keys of 1.1, or the six of 1.2 (last_down added).
 *
 * @param array<array-key, mixed> $timer
 */
function uu_state_timer_ok(array $timer, bool $current): bool
{
    $nullableInt = fn (string $key): bool => array_key_exists($key, $timer)
        && ($timer[$key] === null || is_int($timer[$key]));
    $lastDown = $timer['last_down'] ?? null;
    $lastDownOk = $lastDown === null || (is_array($lastDown) && count($lastDown) === 2
        && isset($lastDown['at']) && is_int($lastDown['at'])
        && isset($lastDown['reason']) && is_string($lastDown['reason']));
    $keysOk = $current
        ? count($timer) === 7 && array_key_exists('last_down', $timer) && isset($timer['resolver'])
            && is_string($timer['resolver'])
        : count($timer) === 5 || (count($timer) === 6 && array_key_exists('last_down', $timer));
    return $keysOk
        && $lastDownOk
        && $nullableInt('usable_since') && $nullableInt('last_at') && $nullableInt('resolver_failed_until')
        && isset($timer['counted']) && is_int($timer['counted'])
        && isset($timer['probe_failures']) && is_int($timer['probe_failures']);
}

/**
 * A Check, or null, exactly.
 *
 * @param array<array-key, mixed> $checks
 */
function uu_state_check_ok(array $checks, string $key): bool
{
    if (!array_key_exists($key, $checks)) {
        return false;
    }
    $check = $checks[$key];
    return $check === null || (is_array($check) && count($check) === 3
        && isset($check['ok']) && is_bool($check['ok'])
        && isset($check['at']) && is_int($check['at'])
        && isset($check['member']) && is_string($check['member']));
}

/**
 * Whether a decoded value is a RouteRecord exactly, or null.
 */
function uu_state_route_ok(mixed $route): bool
{
    return $route === null || (is_array($route) && count($route) === 3
        && in_array($route['kind'] ?? null, ['member', 'reject'], true)
        && isset($route['next_hop']) && is_string($route['next_hop'])
        && isset($route['if']) && is_string($route['if']));
}

/**
 * The fields version 5 and version 6 share: mode, member, the counters, timers (as the version has them), checks, the
 * TLS flag, the blocked count and the last switch.
 *
 * @param array<array-key, mixed> $doc
 */
function uu_state_common_ok(array $doc, bool $current): bool
{
    if (!in_array($doc['mode'] ?? null, ['tunnel', 'fallback'], true)) {
        return false;
    }
    if (!array_key_exists('member', $doc) || ($doc['member'] !== null && !is_string($doc['member']))) {
        return false;
    }
    if (!isset($doc['control_failures']) || !is_int($doc['control_failures'])) {
        return false;
    }
    if (!array_key_exists('control_silent_since', $doc)
        || ($doc['control_silent_since'] !== null && !is_int($doc['control_silent_since']))) {
        return false;
    }
    if (!isset($doc['timers']) || !is_array($doc['timers'])) {
        return false;
    }
    foreach ($doc['timers'] as $name => $timer) {
        /* json_decode turns an all-digit gateway name into an int key */
        if (!(is_string($name) || is_int($name)) || !is_array($timer) || !uu_state_timer_ok($timer, $current)) {
            return false;
        }
    }
    if (!isset($doc['checks']) || !is_array($doc['checks']) || count($doc['checks']) !== 2
        || !uu_state_check_ok($doc['checks'], 'direct') || !uu_state_check_ok($doc['checks'], 'unbound')) {
        return false;
    }
    if (!array_key_exists('tls_applied', $doc) || ($doc['tls_applied'] !== null && !is_bool($doc['tls_applied']))) {
        return false;
    }
    if (!array_key_exists('blocked', $doc) || ($doc['blocked'] !== null && !is_int($doc['blocked']))) {
        return false;
    }
    if (!array_key_exists('last_switch', $doc)) {
        return false;
    }
    $switch = $doc['last_switch'];
    return $switch === null || (is_array($switch) && count($switch) === 4
        && isset($switch['at']) && is_int($switch['at'])
        && isset($switch['from']) && is_string($switch['from'])
        && isset($switch['to']) && is_string($switch['to'])
        && isset($switch['reason']) && is_string($switch['reason']));
}

/**
 * Whether a decoded document has exactly this version's State shape: 11 keys, and every key of addresses an address in
 * its canonical form with an entry of exactly route, forwarded and released_at.
 *
 * @param array<array-key, mixed> $doc
 */
function uu_state_valid(array $doc): bool
{
    if (count($doc) !== 11 || ($doc['version'] ?? null) !== UU_STATE_VERSION || !uu_state_common_ok($doc, true)) {
        return false;
    }
    if (!isset($doc['addresses']) || !is_array($doc['addresses'])) {
        return false;
    }
    foreach ($doc['addresses'] as $address => $entry) {
        if (!is_string($address) || uu_ip_canonical($address) !== $address || !is_array($entry)
            || count($entry) !== 3 || !array_key_exists('route', $entry) || !uu_state_route_ok($entry['route'])
            || !isset($entry['forwarded']) || !is_bool($entry['forwarded'])
            || !array_key_exists('released_at', $entry)
            || ($entry['released_at'] !== null && !is_int($entry['released_at']))) {
            return false;
        }
    }
    return true;
}

/**
 * Whether a decoded document has exactly 1.3's State shape (version 5): one resolver address, or null, and one route
 * record, or null.
 *
 * @param array<array-key, mixed> $doc
 */
function uu_state_valid_v5(array $doc): bool
{
    return count($doc) === 12 && ($doc['version'] ?? null) === 5 && uu_state_common_ok($doc, false)
        && array_key_exists('route_installed', $doc) && uu_state_route_ok($doc['route_installed'])
        && array_key_exists('resolver', $doc) && ($doc['resolver'] === null || is_string($doc['resolver']));
}

/**
 * The State's fields that versions 5 and 6 share, from a document that passed its version's check, with the addresses
 * given; a timer without a resolver or last_down gets them empty.
 *
 * @param array<array-key, mixed> $doc
 * @param array<string, array{route: ?array{kind: string, next_hop: string, if: string}, forwarded: bool,
 *     released_at: ?int}> $addresses
 * @return array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int,
 *         last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
 *     control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *         forwarded: bool, released_at: ?int}>}
 */
function uu_state_assemble(array $doc, array $addresses): array
{
    $state = uu_state_new();
    $state['mode'] = (string)$doc['mode'];
    $state['member'] = $doc['member'] === null ? null : (string)$doc['member'];
    $state['control_failures'] = (int)$doc['control_failures'];
    $state['control_silent_since'] = $doc['control_silent_since'] === null
        ? null : (int)$doc['control_silent_since'];
    foreach ($doc['timers'] as $name => $timer) {
        $state['timers'][(string)$name] = [
            'usable_since' => $timer['usable_since'] === null ? null : (int)$timer['usable_since'],
            'counted' => (int)$timer['counted'],
            'last_at' => $timer['last_at'] === null ? null : (int)$timer['last_at'],
            'resolver_failed_until' => $timer['resolver_failed_until'] === null
                ? null : (int)$timer['resolver_failed_until'],
            'probe_failures' => (int)$timer['probe_failures'],
            'last_down' => is_array($timer['last_down'] ?? null)
                ? ['at' => (int)$timer['last_down']['at'], 'reason' => (string)$timer['last_down']['reason']]
                : null,
            'resolver' => (string)($timer['resolver'] ?? ''),
        ];
    }
    if (is_array($doc['last_switch'])) {
        $state['last_switch'] = [
            'at' => (int)$doc['last_switch']['at'],
            'from' => (string)$doc['last_switch']['from'],
            'to' => (string)$doc['last_switch']['to'],
            'reason' => (string)$doc['last_switch']['reason'],
        ];
    }
    foreach (['direct', 'unbound'] as $key) {
        $check = $doc['checks'][$key];
        if (is_array($check)) {
            $state['checks'][$key] = ['ok' => (bool)$check['ok'], 'at' => (int)$check['at'],
                                      'member' => (string)$check['member']];
        }
    }
    $state['tls_applied'] = $doc['tls_applied'] === null ? null : (bool)$doc['tls_applied'];
    $state['blocked'] = $doc['blocked'] === null ? null : (int)$doc['blocked'];
    $state['addresses'] = $addresses;
    return $state;
}

/**
 * A route record as the State holds it, from a document that passed uu_state_route_ok().
 *
 * @param array<array-key, mixed>|null $route
 * @return ?array{kind: string, next_hop: string, if: string}
 */
function uu_state_route_from(?array $route): ?array
{
    return $route === null ? null : ['kind' => (string)$route['kind'], 'next_hop' => (string)$route['next_hop'],
                                     'if' => (string)$route['if']];
}

/**
 * A version 5 document as a State, or null when it is not exactly 1.3's shape. The one address the file records is
 * the map's entry: its route is route_installed, it is forwarded in tunnel mode and released never. A resolver that is
 * null, or no address, gives an empty map whatever route_installed says: nothing referred to an address.
 *
 * @param array<array-key, mixed> $doc
 * @return ?array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int,
 *         last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
 *     control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *         forwarded: bool, released_at: ?int}>}
 */
function uu_state_from_v5(array $doc): ?array
{
    if (!uu_state_valid_v5($doc)) {
        return null;
    }
    $addresses = [];
    $address = is_string($doc['resolver']) ? uu_ip_canonical($doc['resolver']) : null;
    if ($address !== null) {
        $addresses[$address] = ['route' => uu_state_route_from($doc['route_installed']),
                                'forwarded' => $doc['mode'] === 'tunnel', 'released_at' => null];
    }
    return uu_state_assemble($doc, $addresses);
}

/**
 * A decoded document as a State, or null when it is not exactly this version's shape or version 5's. Shared by the
 * state file and evaluate.php's replay.
 *
 * @param array<array-key, mixed> $doc
 * @return ?array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int,
 *         last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
 *     control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *         forwarded: bool, released_at: ?int}>}
 */
function uu_state_from_doc(array $doc): ?array
{
    if (($doc['version'] ?? null) === 5) {
        return uu_state_from_v5($doc);
    }
    if (!uu_state_valid($doc)) {
        return null;
    }
    $addresses = [];
    foreach ($doc['addresses'] as $address => $entry) {
        $addresses[(string)$address] = ['route' => uu_state_route_from($entry['route']),
                                        'forwarded' => (bool)$entry['forwarded'],
                                        'released_at' => $entry['released_at'] === null ? null
                                            : (int)$entry['released_at']];
    }
    return uu_state_assemble($doc, $addresses);
}

/**
 * The saved state and why it could not be used: a new state, with no problem when the file is missing, and with
 * uu_read_regular_file()'s problem, "not JSON" or "not this version's shape" otherwise.
 *
 * @return array{state: array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int,
 *         last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
 *     control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *         forwarded: bool, released_at: ?int}>},
 *     problem: ?string}
 */
function uu_state_read(string $path): array
{
    $read = uu_read_regular_file($path);
    if ($read['text'] === null) {
        return ['state' => uu_state_new(), 'problem' => $read['problem']];
    }
    $doc = json_decode($read['text'], true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        return ['state' => uu_state_new(), 'problem' => 'not JSON'];
    }
    $state = is_array($doc) ? uu_state_from_doc($doc) : null;
    return $state === null ? ['state' => uu_state_new(), 'problem' => 'not this version\'s shape']
        : ['state' => $state, 'problem' => null];
}

/**
 * The saved state, or a new one when the file is missing, not a regular file within the limit, truncated, not
 * this version or not this shape.
 *
 * @return array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int,
 *         last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
 *     control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *         forwarded: bool, released_at: ?int}>}
 */
function uu_state_load(string $path): array
{
    return uu_state_read($path)['state'];
}

/**
 * The route the plugin last installed for an address, from the state's map: null for an address with no entry or an
 * entry with none. The address is looked up in its canonical form, as the map is keyed.
 *
 * @param array{addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *     forwarded: bool, released_at: ?int}>} $state
 * @return ?array{kind: string, next_hop: string, if: string}
 */
function uu_state_route_record(array $state, string $address): ?array
{
    return $state['addresses'][uu_ip_canonical($address) ?? $address]['route'] ?? null;
}

/**
 * The plugin's footprint: every address the state records while the plugin's route or Unbound's live root may still
 * refer to it (so its block stays until a stop has really undone it), in its canonical form, sorted. The one
 * definition the rendered rules, an evaluation's filter reload and the minute job share.
 *
 * @param array{addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *     forwarded: bool, released_at: ?int}>} $state
 * @return list<string>
 */
function uu_state_footprint(array $state): array
{
    $addresses = array_map('strval', array_keys($state['addresses']));
    sort($addresses, SORT_STRING);
    return $addresses;
}

/**
 * The footprint as a log line prints it: the addresses, comma separated, or none.
 *
 * @param list<string> $addresses
 */
function uu_footprint_text(array $addresses): string
{
    return $addresses === [] ? 'none' : implode(', ', $addresses);
}

/**
 * What an evaluation runs once it has saved a changed footprint: a filter reload whenever the footprint changed,
 * since the rules follow it; and, with the plugin disabled, a cron restart when a footprint came or went, since the
 * minute job is installed exactly while the plugin is enabled or a footprint is recorded (a disabled plugin's stop
 * needs a tick to retry it). Nothing in remove itself (UU_STOP_REMOVE), which runs core's reload and cron restart
 * once its stop is over; a tick while the removal marker exists (UU_STOP_REMOVING) is an evaluation and follows.
 *
 * @param list<string> $before
 * @param list<string> $after
 * @param ?string $stop the run's UU_STOP_* cause, or null
 * @return array{reload: bool, cron: bool}
 */
function uu_footprint_actions(array $before, array $after, bool $enabled, ?string $stop): array
{
    if ($stop === UU_STOP_REMOVE) {
        return ['reload' => false, 'cron' => false];
    }
    return ['reload' => $before !== $after, 'cron' => !$enabled && ($before === []) !== ($after === [])];
}

/**
 * The state once the plugin's footprint on another resolver address has been undone: every member's resolver-failed
 * mark and probe failure count were about that address, so none holds for the new one.
 *
 * @param array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int,
 *         last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
 *     control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *         forwarded: bool, released_at: ?int}>} $state
 * @return array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int,
 *         last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
 *     control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *         forwarded: bool, released_at: ?int}>}
 */
function uu_state_forget_resolver(array $state): array
{
    foreach (array_keys($state['timers']) as $name) {
        $state['timers'][$name]['resolver_failed_until'] = null;
        $state['timers'][$name]['probe_failures'] = 0;
    }
    return $state;
}

/**
 * Write the state to path.tmp and rename it over path, so a crash leaves the old file or the new one. The
 * directory is created 0700.
 *
 * @param array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int,
 *         last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
 *     control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *         forwarded: bool, released_at: ?int}>} $state
 */
function uu_state_save(string $path, array $state): void
{
    $dir = dirname($path);
    if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
        throw new RuntimeException("cannot create $dir");
    }
    $tmp = $path . '.tmp';
    if (file_put_contents($tmp, json_encode($state, JSON_THROW_ON_ERROR)) === false || !rename($tmp, $path)) {
        throw new RuntimeException("cannot write $path");
    }
}
