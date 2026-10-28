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
 *               addresses: array<string, Entry>, view: ViewRecord}
 * Check = array{ok: bool, at: int, member: string}
 * Entry = array{route: ?RouteRecord, forwarded: bool, released_at: ?int}
 * RouteRecord = array{kind: string, next_hop: string, if: string}  (kind 'member' or 'reject'; a reject route is
 *               next_hop '' on lo0, as route(8) prints it)
 * ViewRecord = array{refuse: string, scope: string, nets: list<string>, problem: ?string}  (refuse is 'armed',
 *               'lifted' or 'none')
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
 * released_at is the monotonic second an address became an orphan (no member's resolver, not forwarded to), null
 * otherwise; a drain deletes an orphan's route and entry at least UU_OLD_ADDRESS_HOLD later (apply.php). A version 5
 * file (one resolver and one route_installed) and a version 6 file (no view) convert on read. view records the fail-closed
 * view: refuse is armed while Unbound refuses internet names to the scope's clients, lifted while the plugin has lifted
 * the refusal for a healthy tunnel, none when no view is rendered; scope the setting's scope; nets the netblocks last
 * rendered; problem the last reason the view is not armed, stuck or not rendered. A file that cannot be read back exactly as written is
 * discarded: the planner derives the mode from the live forwarders and route, so a fresh state costs only the
 * failback timers. The file lives in the root-only run directory and is read as a regular file only.
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/address.php';

const UU_STATE_VERSION = 7;

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
 *         forwarded: bool, released_at: ?int}>,
 *     view: array{refuse: string, scope: string, nets: list<string>, problem: ?string}}
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
        'view' => ['refuse' => 'none', 'scope' => 'none', 'nets' => [], 'problem' => null],
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
 * Whether a decoded value is a ViewRecord exactly: refuse armed, lifted or none, a scope, a list of netblock strings
 * and a problem text or null.
 */
function uu_state_view_ok(mixed $view): bool
{
    if (!is_array($view) || count($view) !== 4 || !in_array($view['refuse'] ?? null, ['armed', 'lifted', 'none'], true)
        || !isset($view['scope']) || !is_string($view['scope'])
        || !isset($view['nets']) || !is_array($view['nets']) || !array_is_list($view['nets'])
        || !array_key_exists('problem', $view) || ($view['problem'] !== null && !is_string($view['problem']))) {
        return false;
    }
    foreach ($view['nets'] as $net) {
        if (!is_string($net)) {
            return false;
        }
    }
    return true;
}

/**
 * Whether a decoded document's addresses is a map of canonical addresses, each with an entry of exactly route,
 * forwarded and released_at. Versions 6 and 7 share it.
 *
 * @param array<array-key, mixed> $doc
 */
function uu_state_addresses_ok(array $doc): bool
{
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
 * Whether a decoded document has exactly this version's State shape: 12 keys, every key of addresses an address in its
 * canonical form with an entry of exactly route, forwarded and released_at, and a ViewRecord.
 *
 * @param array<array-key, mixed> $doc
 */
function uu_state_valid(array $doc): bool
{
    return count($doc) === 12 && ($doc['version'] ?? null) === UU_STATE_VERSION && uu_state_common_ok($doc, true)
        && uu_state_addresses_ok($doc) && uu_state_view_ok($doc['view'] ?? null);
}

/**
 * Whether a decoded document has exactly 1.4's State shape (version 6): version 7's without the view.
 *
 * @param array<array-key, mixed> $doc
 */
function uu_state_valid_v6(array $doc): bool
{
    return count($doc) === 11 && ($doc['version'] ?? null) === 6 && uu_state_common_ok($doc, true)
        && uu_state_addresses_ok($doc);
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
 * The State's fields that versions 5, 6 and 7 share, from a document that passed its version's check, with the addresses
 * given and the view (none when null); a timer without a resolver or last_down gets them empty.
 *
 * @param array<array-key, mixed> $doc
 * @param array<string, array{route: ?array{kind: string, next_hop: string, if: string}, forwarded: bool,
 *     released_at: ?int}> $addresses
 * @param ?array<array-key, mixed> $view
 * @return array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int,
 *         last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
 *     control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *         forwarded: bool, released_at: ?int}>,
 *     view: array{refuse: string, scope: string, nets: list<string>, problem: ?string}}
 */
function uu_state_assemble(array $doc, array $addresses, ?array $view = null): array
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
    if ($view !== null) {
        $state['view'] = ['refuse' => (string)$view['refuse'], 'scope' => (string)$view['scope'],
                          'nets' => array_map('strval', $view['nets']),
                          'problem' => $view['problem'] === null ? null : (string)$view['problem']];
    }
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
 *         forwarded: bool, released_at: ?int}>,
 *     view: array{refuse: string, scope: string, nets: list<string>, problem: ?string}}
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
 * A decoded document as a State, or null when it is not exactly this version's shape, version 6's or version 5's. Shared by the
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
 *         forwarded: bool, released_at: ?int}>,
 *     view: array{refuse: string, scope: string, nets: list<string>, problem: ?string}}
 */
function uu_state_from_doc(array $doc): ?array
{
    if (($doc['version'] ?? null) === 5) {
        return uu_state_from_v5($doc);
    }
    $current = ($doc['version'] ?? null) !== 6;
    if ($current ? !uu_state_valid($doc) : !uu_state_valid_v6($doc)) {
        return null;
    }
    $addresses = [];
    foreach ($doc['addresses'] as $address => $entry) {
        $addresses[(string)$address] = ['route' => uu_state_route_from($entry['route']),
                                        'forwarded' => (bool)$entry['forwarded'],
                                        'released_at' => $entry['released_at'] === null ? null
                                            : (int)$entry['released_at']];
    }
    return uu_state_assemble($doc, $addresses, $current ? $doc['view'] : null);
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
 *         forwarded: bool, released_at: ?int}>,
 *     view: array{refuse: string, scope: string, nets: list<string>, problem: ?string}},
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
 *         forwarded: bool, released_at: ?int}>,
 *     view: array{refuse: string, scope: string, nets: list<string>, problem: ?string}}
 */
function uu_state_load(string $path): array
{
    return uu_state_read($path)['state'];
}

/**
 * The live root an evaluation's snapshot read: Unbound's root forwarders as unbound-control printed them, null when
 * the channel did not answer, and the empty root when Unbound is not running (it forwards to nothing, and restarts on
 * its configured root).
 *
 * @param array{pid_alive: bool, live_root: ?list<string>} $unbound the Snapshot's unbound
 * @return ?list<string>
 */
function uu_state_snapshot_read(array $unbound): ?array
{
    return $unbound['pid_alive'] ? $unbound['live_root'] : [];
}

/**
 * Whether Unbound forwards to an address once a live root read is taken: it does when the read names it (as
 * unbound-control prints a forwarder, @port and #name dropped, compared in canonical form) and does not when the read
 * names only others; a read that failed (null) leaves what was recorded. The one home of the forwarded rule: the
 * planner's reject routes and apply's map entries both take it.
 *
 * @param ?list<string> $read
 */
function uu_state_forwarded(?array $read, string $address, bool $recorded): bool
{
    if ($read === null) {
        return $recorded;
    }
    foreach ($read as $forwarder) {
        if (uu_ip_same(uu_forwarder_addr($forwarder), $address)) {
            return true;
        }
    }
    return false;
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
 * Whether the fail-closed view is a footprint: the state records it armed or lifted, or its file is on disk. The minute
 * job follows it beside the addresses (uu_state_footprint()), so a disabled plugin still lifts a view it left; the
 * filter reload does not, since the view has no rules.
 *
 * @param array{view: array{refuse: string, scope: string, nets: list<string>, problem: ?string}} $state
 */
function uu_state_view_footprint(array $state, bool $fileExists): bool
{
    return in_array($state['view']['refuse'], ['armed', 'lifted'], true) || $fileExists;
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
 * needs a tick to retry it). The view's footprint (uu_state_view_footprint()) counts for the minute job beside the
 * addresses, never for the filter reload: the view has no rules. Nothing in remove itself (UU_STOP_REMOVE), which runs
 * core's reload and cron restart once its stop is over; a tick while the removal marker exists (UU_STOP_REMOVING) is an
 * evaluation and follows.
 *
 * @param list<string> $before
 * @param list<string> $after
 * @param ?string $stop the run's UU_STOP_* cause, or null
 * @param bool $viewBefore the view's footprint before the run
 * @param bool $viewAfter the view's footprint after it
 * @return array{reload: bool, cron: bool}
 */
function uu_footprint_actions(array $before, array $after, bool $enabled, ?string $stop, bool $viewBefore = false,
    bool $viewAfter = false): array
{
    if ($stop === UU_STOP_REMOVE) {
        return ['reload' => false, 'cron' => false];
    }
    return ['reload' => $before !== $after,
            'cron' => !$enabled && ($before !== [] || $viewBefore) !== ($after !== [] || $viewAfter)];
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
 *         forwarded: bool, released_at: ?int}>,
 *     view: array{refuse: string, scope: string, nets: list<string>, problem: ?string}} $state
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
