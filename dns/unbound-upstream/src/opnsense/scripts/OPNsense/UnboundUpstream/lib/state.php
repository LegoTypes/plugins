<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Runtime state under /var/run (spec 2026-10-17 section 3.3). Lost at boot on purpose: a boot starts in fallback.
 *
 * State = array{version: int, mode: string, member: ?string, timers: Timers, control_failures: int,
 *               control_silent_since: ?int, last_switch: ?array{at: int, from: string, to: string, reason: string},
 *               checks: array{direct: ?Check, unbound: ?Check}, tls_applied: ?bool, blocked: ?int,
 *               route_installed: ?RouteRecord, resolver: ?string}
 * Check = array{ok: bool, at: int, member: string}
 * RouteRecord = array{kind: string, next_hop: string, if: string}  (kind 'member' or 'reject'; a reject route is
 *               next_hop '' on lo0, as route(8) prints it)
 * mode is 'tunnel' or 'fallback'. Timers (choose.php) and control_silent_since (the first of the consecutive
 * evaluations with a silent control channel) are monotonic seconds; last_switch.at and the checks' at are
 * wall-clock time, for display only. checks are the last direct and through-Unbound results (section 3.8),
 * tls_applied the TLS flag the plugin last gave forward_add (Unbound cannot print it back; null before the plugin
 * set the forwarders) and blocked the counting table's blocked packets at the last evaluation, so a rise is logged.
 * route_installed is the resolver route the plugin last added or changed (null after its delete), so the route
 * stays the plugin's own when the group that explained it is renamed or deleted (ruling R22). resolver is the
 * address that route and Unbound's live root referred to (null once nothing does), so a Save that changes the
 * resolver setting undoes the old address's route and forwarders first (ruling R31). A file that cannot
 * be read back exactly as written is discarded: the planner derives the mode from the live forwarders and route,
 * so a fresh state costs only the failback timers. The file lives in the root-only run directory and is read as a
 * regular file only (convention C3).
 */

require_once __DIR__ . '/constants.php';

const UU_STATE_VERSION = 5;

/**
 * The plugin's runtime directory (UU_RUN_DIR by default, convention C3): created 0700 when missing, put back to
 * 0700 when its mode differs, refused when the path is a symbolic link or not a directory.
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
 * A file the plugin trusts, read as a regular file only (convention C3): the path is no symbolic link and a regular
 * file (lstat), and the file opened is the one checked (the same device and inode), so a swap between the check and
 * the open is refused, and the open never blocks. A missing path, or one below a directory this process cannot
 * search, has no text and no problem. A file over maxBytes gives its first maxBytes as text, with the problem; a
 * reader that needs the whole file treats every problem as absent.
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
            return ['text' => substr($text, 0, $maxBytes), 'problem' => "larger than $limit"];
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
 *         last_down: ?array{at: int, reason: string}}>, control_failures: int, control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     route_installed: ?array{kind: string, next_hop: string, if: string}, resolver: ?string}
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
        'route_installed' => null,
        'resolver' => null,
    ];
}

/**
 * @param array<array-key, mixed> $timer
 */
function uu_state_timer_ok(array $timer): bool
{
    $nullableInt = fn (string $key): bool => array_key_exists($key, $timer)
        && ($timer[$key] === null || is_int($timer[$key]));
    $lastDown = $timer['last_down'] ?? null;
    $lastDownOk = $lastDown === null || (is_array($lastDown) && count($lastDown) === 2
        && isset($lastDown['at']) && is_int($lastDown['at'])
        && isset($lastDown['reason']) && is_string($lastDown['reason']));
    /* a 1.1 timer has the five keys; 1.2 adds last_down */
    return (count($timer) === 5 || (count($timer) === 6 && array_key_exists('last_down', $timer)))
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
 * Whether a decoded document has exactly the State shape.
 *
 * @param array<array-key, mixed> $doc
 */
function uu_state_valid(array $doc): bool
{
    if (count($doc) !== 12 || ($doc['version'] ?? null) !== UU_STATE_VERSION) {
        return false;
    }
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
        if (!(is_string($name) || is_int($name)) || !is_array($timer) || !uu_state_timer_ok($timer)) {
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
    if (!array_key_exists('route_installed', $doc)) {
        return false;
    }
    if (!array_key_exists('resolver', $doc) || ($doc['resolver'] !== null && !is_string($doc['resolver']))) {
        return false;
    }
    $installed = $doc['route_installed'];
    if ($installed !== null && !(is_array($installed) && count($installed) === 3
        && in_array($installed['kind'] ?? null, ['member', 'reject'], true)
        && isset($installed['next_hop']) && is_string($installed['next_hop'])
        && isset($installed['if']) && is_string($installed['if']))) {
        return false;
    }
    if (!array_key_exists('last_switch', $doc)) {
        return false;
    }
    $switch = $doc['last_switch'];
    if ($switch === null) {
        return true;
    }
    return is_array($switch) && count($switch) === 4
        && isset($switch['at']) && is_int($switch['at'])
        && isset($switch['from']) && is_string($switch['from'])
        && isset($switch['to']) && is_string($switch['to'])
        && isset($switch['reason']) && is_string($switch['reason']);
}

/**
 * A decoded document as a State, or null when it is not exactly this version's shape. Shared by the state file and
 * evaluate.php's replay.
 *
 * @param array<array-key, mixed> $doc
 * @return ?array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int,
 *         last_down: ?array{at: int, reason: string}}>, control_failures: int, control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     route_installed: ?array{kind: string, next_hop: string, if: string}, resolver: ?string}
 */
function uu_state_from_doc(array $doc): ?array
{
    if (!uu_state_valid($doc)) {
        return null;
    }
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
    if (is_array($doc['route_installed'])) {
        $state['route_installed'] = ['kind' => (string)$doc['route_installed']['kind'],
                                     'next_hop' => (string)$doc['route_installed']['next_hop'],
                                     'if' => (string)$doc['route_installed']['if']];
    }
    $state['resolver'] = $doc['resolver'] === null ? null : (string)$doc['resolver'];
    return $state;
}

/**
 * The saved state and why it could not be used: a new state, with no problem when the file is missing, and with
 * uu_read_regular_file()'s problem, "not JSON" or "not this version's shape" otherwise.
 *
 * @return array{state: array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int,
 *         last_down: ?array{at: int, reason: string}}>, control_failures: int, control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     route_installed: ?array{kind: string, next_hop: string, if: string}, resolver: ?string},
 *     problem: ?string}
 */
function uu_state_read(string $path): array
{
    $read = uu_read_regular_file($path);
    if ($read['problem'] !== null || $read['text'] === null) {
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
 *         last_down: ?array{at: int, reason: string}}>, control_failures: int, control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     route_installed: ?array{kind: string, next_hop: string, if: string}, resolver: ?string}
 */
function uu_state_load(string $path): array
{
    return uu_state_read($path)['state'];
}

/**
 * The state once the plugin's footprint on another resolver address has been undone (ruling R31): every member's
 * resolver-failed mark and probe failure count were about that address, so none holds for the new one.
 *
 * @param array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int,
 *         last_down: ?array{at: int, reason: string}}>, control_failures: int, control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     route_installed: ?array{kind: string, next_hop: string, if: string}, resolver: ?string} $state
 * @return array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int,
 *         last_down: ?array{at: int, reason: string}}>, control_failures: int, control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     route_installed: ?array{kind: string, next_hop: string, if: string}, resolver: ?string}
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
 *         last_down: ?array{at: int, reason: string}}>, control_failures: int, control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     route_installed: ?array{kind: string, next_hop: string, if: string}, resolver: ?string} $state
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
