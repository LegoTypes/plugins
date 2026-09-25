<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The apply half of every action (spec 2026-09-24 sections 4.6 and 6.1):
 *
 *   gateway lock -> commit (Config::lock, build, save once, unlock)
 *   -> hand-offs that are not config (route todo files, interface_reset)
 *   -> the configd apply steps -> release the gateway lock
 *   -> replay any gateway alarm routes.alarm dropped meanwhile -> reconcile.
 *
 * The gateway lock is /tmp/filter_reload_gateway.lock, opened close-on-exec
 * so nothing the apply starts inherits it; every step goes through configd,
 * never exec(). core's routes.alarm runs `flock -n` on the same lock, so any
 * alarm raised while it is held is dropped -- for our own new gateways and
 * for any WAN that changed state meanwhile -- and is replayed after release.
 */

use OPNsense\Core\Backend;
use OPNsense\Core\Config;

require_once __DIR__ . '/tunnels.php';
require_once __DIR__ . '/actions.php';
require_once __DIR__ . '/mirror.php';
require_once __DIR__ . '/render.php';
require_once __DIR__ . '/selftest.php';

const WGIPV6_GATEWAY_LOCK_FILE = '/tmp/filter_reload_gateway.lock';
/* as long as the replay action's `flock -w 120` waits (ruling 22) */
const WGIPV6_GATEWAY_LOCK_WAIT_MS = 120000;
const WGIPV6_ACTION_LOG_TAG = 'wgipv6gw-action';
/* instances whose Create saved but whose apply has not completed (ruling 20); runtime state, lost at reboot */
const WGIPV6_APPLY_PENDING_FILE = '/var/run/wgipv6gateway/apply_pending.json';
/* spec 6.1: what core's WireGuard, assignment and routes applies do, in order */
const WGIPV6_TUNNEL_APPLY_STEPS = [
    ['template reload', ['OPNsense/Wireguard']],   // writes wgN.conf; `wireguard configure` alone never does
    ['wireguard configure', []],                   // creates (or destroys) wgN; a first start configures its interface
    ['interface invoke registration', []],         // the device appears on Interfaces > Assignments
    ['!interface list assign-opts', []],           // and the 60 s cached device list is refreshed
    ['interface routes configure', []],            // endpoint route, gateways, dpinger; consumes route todo files
    ['filter reload', []],                         // outbound NAT and the rendered pins
];

/**
 * Run a configd action and decode its JSON boundary once, for every API
 * caller (both controllers). A reply that does not decode to an array --
 * Backend::configdRun()/configdpRun() return '' on a timeout, a dropped
 * socket or a stripped 'Execute error' (ruling 14) -- used to be reported as
 * "ok: false, errors: ['backend: ']", which reads as nothing happened even
 * though the action may still be running on the box (controller review,
 * 2026-09-25); it is now a clear message naming the timeout used and telling
 * the caller to reload and check the log instead. `errors`, when the action
 * supplied one, is flattened to a plain list (array_values()): the GUI
 * (Task 8) reads one shape regardless of whether the underlying
 * wgipv6_result() keyed it by request field or apply step.
 *
 * @param string       $action
 * @param list<string> $params  uuids, gateway names and addresses only (configd shows argv in ps)
 * @param int          $timeout
 * @return array the action's decoded JSON result, or a failure of the same shape
 */
function wgipv6_configd_json(string $action, array $params, int $timeout): array {
    $backend = new Backend();
    $raw = (string)($params === []
        ? $backend->configdRun($action, false, $timeout)
        : $backend->configdpRun($action, $params, false, $timeout));
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        return ['ok' => false, 'errors' => [
            "no reply from the backend within {$timeout} s (timeout or configd error); "
            . 'the action may still be running — reload the list and check the system log',
        ]];
    }
    if (isset($data['errors']) && is_array($data['errors'])) {
        $data['errors'] = array_values($data['errors']);
    }
    return $data;
}

/**
 * The API's {dry: ...} flag. ajaxCall posts JSON, so a bool or int can arrive
 * where a form-encoded post only ever carried '0'/'1' strings: absent, '',
 * '0', 0 (int) and false all mean "run for real"; '1', 1 (int) and true all
 * mean "preview only"; anything else -- a stray float, a string like 'yes',
 * an array -- is refused rather than silently defaulting to either side, so a
 * malformed value can never fall through into a real Remove/Adopt/Sentinel
 * (controller review, 2026-09-25).
 *
 * @param mixed $value the raw {dry: ...} POST value -- a JSON boundary, hence mixed
 * @return bool|null true for dry, false for real, null when the caller must refuse
 */
function wgipv6_dry_flag(mixed $value): ?bool {
    if ($value === null || $value === '' || $value === '0' || $value === 0 || $value === false) {
        return false;
    }
    if ($value === '1' || $value === 1 || $value === true) {
        return true;
    }
    return null;
}

/**
 * @return \SplFileObject the gateway lock, held until LOCK_UN or the object is released
 * @throws \RuntimeException when it is still held elsewhere after WGIPV6_GATEWAY_LOCK_WAIT_MS
 */
function wgipv6_gateway_lock(): \SplFileObject {
    $file = wgipv6_poll_lock(WGIPV6_GATEWAY_LOCK_FILE, WGIPV6_GATEWAY_LOCK_WAIT_MS, 200);
    if ($file === null) {
        $seconds = intdiv(WGIPV6_GATEWAY_LOCK_WAIT_MS, 1000);
        throw new \RuntimeException(
            WGIPV6_GATEWAY_LOCK_FILE . " is still held after {$seconds} s (fstat -f " . WGIPV6_GATEWAY_LOCK_FILE . ' names the holder); nothing was changed'
        );
    }
    return $file;
}

/**
 * @param mixed $data json_decode() of the pending file -- a JSON boundary, hence mixed
 * @return array<string, int> instance uuid => unix time its apply was requested;
 *                            anything malformed reads as nothing pending
 */
function wgipv6_pending_from_json(mixed $data): array {
    $out = [];
    if (!is_array($data)) {
        return $out;
    }
    foreach ($data as $uuid => $at) {
        if (is_string($uuid) && preg_match('/^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$/', $uuid) === 1 && is_int($at)) {
            $out[$uuid] = $at;
        }
    }
    return $out;
}

/**
 * @return array<string, int> wgipv6_pending_from_json() of the file, [] when there is none
 */
function wgipv6_read_apply_pending(): array {
    $raw = is_file(WGIPV6_APPLY_PENDING_FILE) ? file_get_contents(WGIPV6_APPLY_PENDING_FILE) : false;
    return wgipv6_pending_from_json($raw === false ? null : json_decode($raw, true));
}

/**
 * Mark or clear "Create saved this instance but its apply has not completed".
 * Serialized on a close-on-exec lock beside the file; written atomically.
 */
function wgipv6_set_apply_pending(string $uuid, bool $pending): void {
    $dir = dirname(WGIPV6_APPLY_PENDING_FILE);
    if (!is_dir($dir) && !mkdir($dir, 0755, true) && !is_dir($dir)) {
        throw new \RuntimeException("could not create {$dir}");
    }
    $lock = new \SplFileObject(WGIPV6_APPLY_PENDING_FILE . '.lock', 'ce');
    $lock->flock(LOCK_EX);
    try {
        $all = wgipv6_read_apply_pending();
        if ($pending) {
            $all[$uuid] = time();
        } else {
            unset($all[$uuid]);
        }
        if (!wgipv6_write_file_atomic(WGIPV6_APPLY_PENDING_FILE, (string)json_encode($all))) {
            throw new \RuntimeException('could not write ' . WGIPV6_APPLY_PENDING_FILE);
        }
    } finally {
        $lock->flock(LOCK_UN);
    }
}

/**
 * @param string $out a configd reply
 * @return string one short line for the result list
 */
function wgipv6_step_summary(string $out): string {
    $out = trim($out);
    if ($out === '') {
        return '(no output)';
    }
    if ($out[0] === '{' || $out[0] === '[') {
        return 'OK';
    }
    $first = strtok($out, "\n");
    return substr($first === false ? $out : $first, 0, 120);
}

/**
 * @param list<array{action: string, result: string}> $apply wgipv6_run_steps()
 * @return list<string> the actions configd reported as failed
 */
function wgipv6_failed_steps(array $apply): array {
    $out = [];
    foreach ($apply as $step) {
        /*
         * Success-only: wgipv6_step_summary() already maps a JSON reply to
         * 'OK', and every step in WGIPV6_TUNNEL_APPLY_STEPS and every
         * writer's 'steps' list answers exactly 'OK' on success -- so a step
         * failed iff its summarized result is anything else. A fixed list of
         * failure prefixes missed cases: inline.py's template.reload (the
         * first apply step) can reply 'ERR', which the case-sensitive
         * 'Error' prefix never matched, and script.py can surface an
         * arbitrary str(e) that matches no prefix at all; Backend also
         * returns '' (summarized as '(no output)') on a timeout, a dropped
         * socket, or an 'Execute error' reply it strips before returning.
         */
        if ($step['result'] !== 'OK') {
            $out[] = $step['action'];
        }
    }
    return $out;
}

/**
 * @param list<array{0: string, 1: list<string>}> $steps configd actions and their parameters
 * @return list<array{action: string, result: string}>
 */
function wgipv6_run_steps(array $steps): array {
    $backend = new Backend();
    $results = [];
    foreach ($steps as [$action, $params]) {
        $out = $params === []
            ? $backend->configdRun($action, false, 300)
            : $backend->configdpRun($action, $params, false, 300);
        $results[] = ['action' => trim($action . ' ' . implode(' ', $params)), 'result' => wgipv6_step_summary((string)$out)];
    }
    return $results;
}

/**
 * Which gateways to replay the routes alarm for once the lock is released
 * (spec 4.6 step 6): the action's own, plus every gateway whose status
 * changed while the lock was held. Pure.
 *
 * @param list<string>               $ours      gateway names the action wrote
 * @param array<string, string>|null $before    gateway status taken before the lock
 * @param array<string, string>|null $after     gateway status taken after release
 * @param array<string, bool>        $forceDown name => force_down in config now
 * @return array<string, bool> name => expected force_down, sorted by name
 */
function wgipv6_replay_set(array $ours, ?array $before, ?array $after, array $forceDown): array {
    $set = [];
    foreach ($ours as $name) {
        if (isset($forceDown[$name])) {
            $set[$name] = $forceDown[$name];
        }
    }
    if ($before !== null && $after !== null) {
        foreach ($after as $name => $status) {
            if (isset($forceDown[$name]) && ($before[$name] ?? null) !== $status) {
                $set[(string)$name] = $forceDown[$name];
            }
        }
    }
    ksort($set);
    return $set;
}

/**
 * core's own "delete this kernel route" hand-off (RoutesController::delrouteAction):
 * rc.routing_configure consumes /tmp/delete_route_<uuid>.todo files at the
 * next `interface routes configure`.
 *
 * @param array<string, string> $todos route uuid => network
 */
function wgipv6_write_route_todos(array $todos): void {
    foreach ($todos as $uuid => $network) {
        if (preg_match('/^[0-9a-fA-F-]{36}$/', (string)$uuid) !== 1) {
            throw new \RuntimeException("not a route uuid: {$uuid}");
        }
        if (file_put_contents("/tmp/delete_route_{$uuid}.todo", $network) === false) {
            throw new \RuntimeException("could not write the route todo for {$network}");
        }
    }
}

/**
 * After the gateway lock is released: replay swallowed alarms, then reconcile.
 *
 * @param list<string>               $ours   gateway names the action wrote
 * @param array<string, string>|null $before gateway status taken before the lock
 * @return array{replayed: list<string>, reconcile: string}
 */
function wgipv6_after_apply(array $ours, ?array $before): array {
    Config::getInstance()->forceReload();
    $forceDown = [];
    foreach (wgipv6_core_snapshot()['gateways'] as $name => $g) {
        $forceDown[(string)$name] = $g['force_down'];
    }
    $set = wgipv6_replay_set($ours, $before, wgipv6_gateway_status(), $forceDown);
    if ($set !== []) {
        wgipv6_replay_alarm($set, WGIPV6_ACTION_LOG_TAG);
    }
    $out = (new Backend())->configdRun('wgipv6gateway reconcile', false, 300);
    return ['replayed' => array_keys($set), 'reconcile' => wgipv6_step_summary((string)$out)];
}

/**
 * Spec 4.6 for an action that changes routing. A dry run takes no gateway
 * lock and applies nothing.
 *
 * @param callable(): array $commit a writer from writer.php, returning wgipv6_result()
 * @param bool              $dry
 * @return array wgipv6_result() with 'apply' and 'after' filled once saved
 */
function wgipv6_routing_action(callable $commit, bool $dry): array {
    if ($dry) {
        return $commit();
    }
    $before = wgipv6_gateway_status();
    $lock = wgipv6_gateway_lock();
    $result = wgipv6_result();
    $ours = [];
    $pending = null;
    try {
        try {
            $result = $commit();
            if ($result['ok'] && $result['saved']) {
                $ours = $result['gateways'];
                wgipv6_write_route_todos($result['route_todos']);
                if ($result['reset_interface'] !== null) {
                    if (!function_exists('interface_reset')) {
                        throw new \RuntimeException('interface_reset() needs interfaces.inc; run Remove through tunnel.php');
                    }
                    /* reads the legacy $config loaded when this process started, which still holds the interface */
                    interface_reset($result['reset_interface']);
                }
                $result['apply'] = wgipv6_run_steps($result['steps']);
            }
        } finally {
            $lock->flock(LOCK_UN);
        }
    } catch (\Throwable $e) {
        $pending = $e;
    }
    /*
     * Always replay, once the lock is released, whether the commit refused
     * to save, something above threw, or everything succeeded: routes.alarm
     * (flock -n) silently drops any alarm raised while we held it, for our
     * own gateways (ruling 13, only once the commit actually saved) and for
     * any other gateway whose status changed meanwhile regardless.
     *
     * When $pending is set we are already unwinding a real failure, so a
     * second failure out of wgipv6_after_apply() here must not silently
     * replace it as the exception the caller sees: it is caught, logged
     * (never with key material -- nothing replayed here carries one), and
     * the original exception is what gets rethrown. With nothing pending,
     * an after_apply failure is the only error there is, so it propagates
     * exactly as it would from a direct call.
     */
    if ($pending !== null) {
        try {
            wgipv6_after_apply($ours, $before);
        } catch (\Throwable $afterError) {
            logMsg(WGIPV6_ACTION_LOG_TAG, 'after_apply failed while unwinding ' . get_class($pending) . ': ' . $afterError->getMessage());
        }
        throw $pending;
    }
    $result['after'] = wgipv6_after_apply($ours, $before);
    if (!$result['ok'] || !$result['saved']) {
        return $result;
    }
    $failed = wgipv6_failed_steps($result['apply']);
    if ($failed !== []) {
        $result['errors']['apply'] = 'saved, but these apply steps failed: ' . implode(', ', $failed)
            . '; the reconcile repairs what it can and the findings show the rest';
    } elseif ($result['uuid'] !== '') {
        wgipv6_set_apply_pending($result['uuid'], false);
    }
    return $result;
}

/**
 * An action that changes only the plugin's own config (Adopt): no gateway
 * lock; after the save, the reconcile renders whatever follows from it.
 *
 * @param callable(): array $commit returns wgipv6_result()
 * @return array wgipv6_result()
 */
function wgipv6_config_action(callable $commit, bool $dry): array {
    $result = $commit();
    if (!$dry && $result['ok'] && $result['saved']) {
        $out = (new Backend())->configdRun('wgipv6gateway reconcile', false, 300);
        $result['after'] = ['replayed' => [], 'reconcile' => wgipv6_step_summary((string)$out)];
    }
    return $result;
}

/**
 * The tunnel apply on its own: the API's Create saved in-process and runs this
 * as the keyless configd action `wgipv6gateway apply <uuid>` (spec 6.1); the
 * Apply button of an `apply-pending` tunnel runs it again. A complete apply
 * clears the pending marker.
 *
 * @param string $uuid the WireGuard instance; its gateways (for the replay) are derived here
 * @return array wgipv6_result()
 */
function wgipv6_apply_only(string $uuid): array {
    $t = wgipv6_derive(wgipv6_core_snapshot(), [$uuid])['tunnels'][0];
    if (in_array('instance-missing', array_column($t['findings'], 'code'), true)) {
        return wgipv6_result(['errors' => ['no WireGuard instance with this uuid'], 'uuid' => $uuid]);
    }
    $gatewayNames = array_values(array_filter([$t['gw4'], $t['gw6']], fn (?string $g): bool => $g !== null));
    $before = wgipv6_gateway_status();
    $lock = wgipv6_gateway_lock();
    $apply = [];
    $pending = null;
    try {
        try {
            $apply = wgipv6_run_steps(WGIPV6_TUNNEL_APPLY_STEPS);
        } finally {
            $lock->flock(LOCK_UN);
        }
    } catch (\Throwable $e) {
        $pending = $e;
    }
    /* Always replay, once the lock is released; see wgipv6_routing_action(). */
    if ($pending !== null) {
        try {
            wgipv6_after_apply($gatewayNames, $before);
        } catch (\Throwable $afterError) {
            logMsg(WGIPV6_ACTION_LOG_TAG, 'after_apply failed while unwinding ' . get_class($pending) . ': ' . $afterError->getMessage());
        }
        throw $pending;
    }
    $after = wgipv6_after_apply($gatewayNames, $before);
    $result = wgipv6_result([
        'ok' => true, 'saved' => true, 'uuid' => $uuid, 'gateways' => $gatewayNames, 'steps' => WGIPV6_TUNNEL_APPLY_STEPS,
        'apply' => $apply, 'after' => $after,
    ]);
    $failed = wgipv6_failed_steps($apply);
    if ($failed !== []) {
        $result['errors']['apply'] = 'these apply steps failed: ' . implode(', ', $failed)
            . '; the reconcile repairs what it can and the findings show the rest';
    } else {
        wgipv6_set_apply_pending($uuid, false);
    }
    return $result;
}

/**
 * Self-tests for the pure parts of the apply. No configd, no locks.
 *
 * @return int exit code, 0 when every case passes
 */
function wgipv6_apply_selftest(): int {
    $t = ['fail' => 0, 'total' => 0];
    wgipv6_check($t, 'apply: empty output => (no output)', wgipv6_step_summary("  \n") === '(no output)');
    wgipv6_check($t, 'apply: OK => OK', wgipv6_step_summary("OK\n") === 'OK');
    wgipv6_check($t, 'apply: JSON output (assign-opts) => OK', wgipv6_step_summary('{"igc0": "igc0"}') === 'OK');
    wgipv6_check($t, 'apply: first line only', wgipv6_step_summary("Error (1)\nmore") === 'Error (1)');
    wgipv6_check($t, 'apply: long output cut at 120', strlen(wgipv6_step_summary(str_repeat('a', 200))) === 120);
    wgipv6_check($t, 'apply: only an exact OK passes; (no output), ERR, an Error prefix and an arbitrary message all fail',
        wgipv6_failed_steps([
            ['action' => 'a', 'result' => 'OK'], ['action' => 'b', 'result' => '(no output)'],
            ['action' => 'c', 'result' => 'ERR'], ['action' => 'd', 'result' => 'Error (1)'],
            ['action' => 'e', 'result' => 'unexpected widget failure'],
        ]) === ['b', 'c', 'd', 'e']);
    wgipv6_check($t, "apply: step_summary()'d replies feed the same rule -- OK and JSON pass, an empty reply fails",
        wgipv6_failed_steps([['action' => 'x', 'result' => wgipv6_step_summary("OK\n")]]) === []
        && wgipv6_failed_steps([['action' => 'x', 'result' => wgipv6_step_summary('{"igc0": "igc0"}')]]) === []
        && wgipv6_failed_steps([['action' => 'x', 'result' => wgipv6_step_summary('')]]) === ['x']);
    $forceDown = ['WAN_A' => false, 'tun_c' => false, 'tun_c-ipv6' => true, 'tun_a' => false];
    wgipv6_check($t, 'apply: replay covers our gateways plus any whose status changed during the hold',
        wgipv6_replay_set(['tun_c', 'tun_c-ipv6'], ['WAN_A' => 'none', 'tun_a' => 'none'], ['WAN_A' => 'down', 'tun_a' => 'none'], $forceDown)
        === ['WAN_A' => false, 'tun_c' => false, 'tun_c-ipv6' => true]);
    wgipv6_check($t, 'apply: no status before the lock => our gateways only',
        wgipv6_replay_set(['tun_c'], null, ['WAN_A' => 'down'], $forceDown) === ['tun_c' => false]);
    wgipv6_check($t, 'apply: a removed gateway and one missing from config are skipped',
        wgipv6_replay_set(['tun_gone'], ['X' => 'none'], ['X' => 'down'], $forceDown) === []);
    wgipv6_check($t, 'apply: nothing ours, nothing changed => no replay',
        wgipv6_replay_set([], ['WAN_A' => 'none'], ['WAN_A' => 'none'], $forceDown) === []);
    wgipv6_check($t, 'apply: a refused/failed commit leaves ours empty, but a gateway that changed meanwhile is still replayed',
        wgipv6_replay_set([], ['WAN_A' => 'none'], ['WAN_A' => 'down'], $forceDown) === ['WAN_A' => false]);
    $u1 = '00000000-0000-4000-8000-000000000001';
    wgipv6_check($t, 'apply: the pending record keeps only uuid => integer time entries',
        wgipv6_pending_from_json([$u1 => 1700000000, 'not-a-uuid' => 1, '00000000-0000-4000-8000-000000000002' => 'soon']) === [$u1 => 1700000000]);
    wgipv6_check($t, 'apply: a malformed pending record reads as nothing pending',
        wgipv6_pending_from_json('garbage') === [] && wgipv6_pending_from_json(null) === []);
    wgipv6_check($t, 'apply: dry flag -- absent, empty, "0", 0 and false all mean real',
        wgipv6_dry_flag(null) === false && wgipv6_dry_flag('') === false && wgipv6_dry_flag('0') === false
        && wgipv6_dry_flag(0) === false && wgipv6_dry_flag(false) === false);
    wgipv6_check($t, 'apply: dry flag -- "1", 1 and true all mean dry',
        wgipv6_dry_flag('1') === true && wgipv6_dry_flag(1) === true && wgipv6_dry_flag(true) === true);
    wgipv6_check($t, 'apply: dry flag -- anything else (a stray float, string, array) is refused, not defaulted',
        wgipv6_dry_flag('yes') === null && wgipv6_dry_flag(2) === null && wgipv6_dry_flag(1.0) === null && wgipv6_dry_flag([]) === null);
    return wgipv6_tally_report('apply', $t);
}
