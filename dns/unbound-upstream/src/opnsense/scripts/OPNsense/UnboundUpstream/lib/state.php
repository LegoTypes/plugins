<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Runtime state under /var/run (spec 2026-10-17 section 3.3). Lost at boot on purpose: a boot starts in fallback.
 *
 * State = array{version: int, mode: string, member: ?string, timers: Timers, control_failures: int,
 *               control_silent_since: ?int, last_switch: ?array{at: int, from: string, to: string, reason: string},
 *               checks: array{direct: ?Check, unbound: ?Check}, tls_applied: ?bool, blocked: ?int}
 * Check = array{ok: bool, at: int, member: string}
 * mode is 'tunnel' or 'fallback'. Timers (choose.php) and control_silent_since (the first of the consecutive
 * evaluations with a silent control channel) are monotonic seconds; last_switch.at and the checks' at are
 * wall-clock time, for display only. checks are the last direct and through-Unbound results (section 3.8),
 * tls_applied the TLS flag the plugin last gave forward_add (Unbound cannot print it back; null before the plugin
 * set the forwarders) and blocked the block rule's packet count at the last evaluation, so a rise is logged. A
 * file that cannot be read back exactly as written is discarded: the planner derives the mode from the live
 * forwarders and route, so a fresh state costs only the failback timers.
 */

const UU_STATE_VERSION = 3;

/**
 * @return array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int}>, control_failures: int, control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int}
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
    ];
}

/**
 * @param array<array-key, mixed> $timer
 */
function uu_state_timer_ok(array $timer): bool
{
    $nullableInt = fn (string $key): bool => array_key_exists($key, $timer)
        && ($timer[$key] === null || is_int($timer[$key]));
    return count($timer) === 5
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
    if (count($doc) !== 10 || ($doc['version'] ?? null) !== UU_STATE_VERSION) {
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
        if (!is_string($name) || !is_array($timer) || !uu_state_timer_ok($timer)) {
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
 *     probe_failures: int}>, control_failures: int, control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int}
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
    return $state;
}

/**
 * The saved state, or a new one when the file is missing, truncated, not this version or not this shape.
 *
 * @return array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int}>, control_failures: int, control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int}
 */
function uu_state_load(string $path): array
{
    $text = @file_get_contents($path);
    if ($text === false) {
        return uu_state_new();
    }
    $doc = json_decode($text, true);
    return (is_array($doc) ? uu_state_from_doc($doc) : null) ?? uu_state_new();
}

/**
 * Write the state to path.tmp and rename it over path, so a crash leaves the old file or the new one. The
 * directory is created 0700.
 *
 * @param array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int}>, control_failures: int, control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int} $state
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
