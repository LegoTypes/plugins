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

const WGCT_GATEWAY_LOCK_FILE = '/tmp/filter_reload_gateway.lock';
/* as long as the replay action's `flock -w 120` waits (ruling 22) */
const WGCT_GATEWAY_LOCK_WAIT_MS = 120000;
const WGCT_ACTION_LOG_TAG = 'wgct-action';
/*
 * Instances whose Create or Edit saved but whose apply has not completed
 * (ruling 20; S5 review I2), each with the apply mode it still needs. Kept in
 * /var/db, not /var/run, so it survives a reboot: boot runs only `wireguard
 * configure`, never `template reload`, so a tunnel whose apply never ran still
 * has no current wgN.conf after a reboot, and nothing else re-applies a saved
 * NAT or monitor change; either way it still needs Apply.
 */
const WGCT_APPLY_PENDING_FILE = '/var/db/wgclienttunnels/apply_pending.json';
/*
 * Create's apply (spec 6.1, amended): what core's WireGuard, assignment and
 * routes applies do, with the routes applied once BEFORE the device exists.
 * WireGuard keeps the source address of its first path, core's force-gateway
 * rules keep that state alive and keepalive 25 refreshes it forever: a first
 * handshake sent before the endpoint /32 is in place leaves by the default
 * route's WAN and stays there. The complete list is also what clears
 * apply-pending (wgct_pending_outcome()).
 */
const WGCT_CREATE_APPLY_STEPS = [
    ['template reload', ['OPNsense/Wireguard']],   // writes wgN.conf; `wireguard configure` alone never does
    ['interface routes configure', []],            // the endpoint /32 via the bound WAN, before the first handshake
    ['wireguard configure', []],                   // creates wgN; a first start configures its interface
    ['interface invoke registration', []],         // the device appears on Interfaces > Assignments
    ['!interface list assign-opts', []],           // and the 60 s cached device list is refreshed
    ['interface routes configure', []],            // gateways and dpinger on the new device; consumes route todo files
    ['filter reload', []],                         // outbound NAT and the rendered pins
];
/*
 * Remove's apply (ruling 21): registering after `wireguard configure` has
 * destroyed the device is the order that leaves Assignments right.
 */
const WGCT_REMOVE_APPLY_STEPS = [
    ['template reload', ['OPNsense/Wireguard']],   // renders the remaining instances' confs only
    ['wireguard configure', []],                   // destroys wgN and removes its orphaned wgN.conf
    ['interface invoke registration', []],         // the device leaves Interfaces > Assignments
    ['!interface list assign-opts', []],           // and the 60 s cached device list is refreshed
    ['interface routes configure', []],            // gateways, dpinger; consumes the endpoint route todo files
    ['filter reload', []],                         // outbound NAT and the rendered pins
];

/**
 * Rebind's apply. `interface routes configure` installs the new endpoint /32
 * (and consumes the stale route's todo file); `wireguard restart` then makes
 * the tunnel handshake again on that route -- without it WireGuard keeps its
 * old source address, which core's force-gateway state and keepalive hold on
 * the old WAN. The restart (wg-service-control) destroys and recreates wgN,
 * then reconfigures its interface and routing (interfaces_restart_by_device());
 * the ruleset itself was reloaded by the routes configure before it. Pure.
 *
 * @param string $uuid the WireGuard instance (configd `wireguard restart %s`)
 * @return list<array{0: string, 1: list<string>}>
 */
function wgct_rebind_apply_steps(string $uuid): array {
    return [
        ['interface routes configure', []],
        ['wireguard restart', [$uuid]],
    ];
}

/*
 * The apply modes of `tunnel.php apply UUID [MODE]` and the configd action
 * apply_mode (S5 ruling 1), weakest first: each mode's steps do what every
 * weaker mode's do (`interface routes configure` ends with a filter reload,
 * and the tunnel applies run both), which is what lets a stronger apply
 * settle a weaker pending record (wgct_pending_settle()).
 */
const WGCT_APPLY_MODES = ['filter', 'routes', 'first', 'tunnel'];

/**
 * The configd steps of an apply mode. Pure.
 * - filter: an Edit of the NAT sources alone;
 * - routes: an Edit of the monitor (with or without NAT: facts 1);
 * - first: Create's steps, the API's apply right after its Create;
 * - tunnel: Create's steps, then `wireguard restart`: the re-run of Create's
 *   apply and an Edit of the tunnel itself. A re-run may find a device that
 *   already handshook by the wrong WAN (the step list carries on past a
 *   failed step), and an Edit moves the path, so both end with the restart
 *   (S5 ruling 2).
 *
 * @param string $mode one of WGCT_APPLY_MODES
 * @param string $uuid the WireGuard instance
 * @return list<array{0: string, 1: list<string>}>
 * @throws \InvalidArgumentException for anything else, before anything runs
 */
function wgct_apply_mode_steps(string $mode, string $uuid): array {
    return match ($mode) {
        'first' => WGCT_CREATE_APPLY_STEPS,
        'tunnel' => array_merge(WGCT_CREATE_APPLY_STEPS, [['wireguard restart', [$uuid]]]),
        'routes' => [['interface routes configure', []]],
        'filter' => [['filter reload', []]],
        default => throw new \InvalidArgumentException(
            'not an apply mode: ' . substr($mode, 0, 20) . ' (' . implode(', ', WGCT_APPLY_MODES) . ')'
        ),
    };
}

/**
 * @return bool whether the mode's apply changes routing and so holds the
 *              gateway lock (spec 4.6 step 1); filter and none do not. Pure.
 */
function wgct_apply_mode_locks(string $mode): bool {
    return in_array($mode, ['first', 'tunnel', 'routes'], true);
}

/**
 * The mode the Apply button (`tunnel.php apply UUID` without a mode) runs for
 * a pending record: the recorded one, except that Create's first apply is
 * re-run as the tunnel apply, restart included (S5 ruling 2); with nothing
 * recorded, the tunnel apply. Pure.
 */
function wgct_rerun_mode(?string $recorded): string {
    return $recorded === null || $recorded === 'first' ? 'tunnel' : $recorded;
}

/*
 * core's wg-service-control.php takes its argument as an instance only when
 * it matches this -- a lower-case v4 uuid -- and reads anything else as a
 * CARP vhid, for which start, stop, restart and configure act on every
 * instance (wg-service-control.php:212).
 */
const WGCT_CORE_INSTANCE_UUID = '/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/';
const WGCT_WIREGUARD_INSTANCE_ACTIONS = ['wireguard start', 'wireguard stop', 'wireguard restart', 'wireguard configure'];

/**
 * Why a step must not be issued, or null when it may. Pure.
 *
 * @param string       $action a configd action
 * @param list<string> $params its parameters
 * @return string|null the failure result to record instead of running it
 */
function wgct_step_refusal(string $action, array $params): ?string {
    if ($params === [] || !in_array($action, WGCT_WIREGUARD_INSTANCE_ACTIONS, true)) {
        return null;
    }
    if (count($params) === 1 && preg_match(WGCT_CORE_INSTANCE_UUID, $params[0]) === 1) {
        return null;
    }
    return "refused: {$action} takes one lower-case v4 instance uuid; core reads anything else as a CARP vhid and acts on every instance";
}

/**
 * What an action's apply means for the apply-pending record of its instance
 * (ruling 20; S5 review I2). A complete apply mode -- its exact step list,
 * every step OK -- is that mode, which settles a record of the same or a
 * weaker mode (wgct_pending_settle()). A Rebind, a Sentinel repair or a
 * failed apply is null and settles nothing. A saved Remove is 'forget'
 * whatever its apply did: the instance is no longer in config, so the record
 * could never be shown or cleared again. Pure.
 *
 * @param list<array{0: string, 1: list<string>}> $steps  the action's configd steps
 * @param list<string>                            $failed wgct_failed_steps() of its apply
 * @return string|null 'forget', one of WGCT_APPLY_MODES, or null
 */
function wgct_pending_outcome(array $steps, array $failed): ?string {
    if ($steps === WGCT_REMOVE_APPLY_STEPS) {
        return 'forget';
    }
    if ($failed !== []) {
        return null;
    }
    if ($steps === WGCT_CREATE_APPLY_STEPS) {
        return 'first';
    }
    $n = count(WGCT_CREATE_APPLY_STEPS);
    if (count($steps) === $n + 1 && array_slice($steps, 0, $n) === WGCT_CREATE_APPLY_STEPS
        && $steps[$n][0] === 'wireguard restart') {
        return 'tunnel';
    }
    foreach (['routes', 'filter'] as $mode) {
        if ($steps === wgct_apply_mode_steps($mode, '')) {
            return $mode;
        }
    }
    return null;
}

/**
 * Record that an instance's saved change still needs a mode's apply: the
 * stronger of that mode and one already recorded is kept, with the new time.
 * Pure.
 *
 * @param array<string, array{at: int, mode: string}> $all wgct_read_apply_pending()
 * @return array<string, array{at: int, mode: string}>
 */
function wgct_pending_mark(array $all, string $uuid, string $mode, int $at): array {
    $recorded = $all[$uuid]['mode'] ?? null;
    if ($recorded !== null && array_search($recorded, WGCT_APPLY_MODES, true) > array_search($mode, WGCT_APPLY_MODES, true)) {
        $mode = $recorded;
    }
    $all[$uuid] = ['at' => $at, 'mode' => $mode];
    return $all;
}

/**
 * Apply an outcome (wgct_pending_outcome()) to the record: 'forget' drops it,
 * a completed mode drops it when that mode is at least as strong as the one
 * recorded. Pure.
 *
 * @param array<string, array{at: int, mode: string}> $all wgct_read_apply_pending()
 * @return array<string, array{at: int, mode: string}>
 */
function wgct_pending_settle(array $all, string $uuid, string $outcome): array {
    if (!isset($all[$uuid])) {
        return $all;
    }
    if ($outcome === 'forget'
        || array_search($outcome, WGCT_APPLY_MODES, true) >= array_search($all[$uuid]['mode'], WGCT_APPLY_MODES, true)) {
        unset($all[$uuid]);
    }
    return $all;
}

/**
 * The advice appended to a failure that may have happened after a save
 * (lib/cli.php and the API's Create). Only Create and Apply leave a tunnel
 * whose apply `tunnel.php apply` completes; for the other writers the list
 * and its findings show what the save changed and what is left. Commands that
 * never save get no advice. Pure.
 *
 * @param string $cmd  the command (the CLI's COMMAND word)
 * @param string $uuid the tunnel's instance uuid when known, else ''
 * @return string '' when there is nothing to advise
 */
function wgct_failure_footer(string $cmd, string $uuid): string {
    $apply = '`tunnel.php apply ' . ($uuid !== '' ? $uuid : 'UUID') . '`';
    $which = $uuid !== '' ? '' : ' (the new tunnel\'s uuid ends its line in `tunnel.php list`)';
    return match ($cmd) {
        'create' => 'If this happened after the save, the tunnel is in config and only its apply is incomplete: '
            . "run {$apply}{$which} and check `tunnel.php status`.",
        'apply' => "The tunnel's apply is incomplete: run {$apply} again and check `tunnel.php status`.",
        'edit' => 'If this happened after the save, the change is in config and its apply may be incomplete: '
            . "run {$apply}{$which} (it runs the apply the change still needs) and check `tunnel.php status`.",
        'remove', 'rebind', 'adopt', 'ensure-sentinel' => 'If this happened after the save, the change is in config '
            . 'and its apply may be incomplete: check `tunnel.php status` and `tunnel.php list` for what is left.',
        default => '',
    };
}

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
 * wgct_result() keyed it by request field or apply step.
 *
 * @param string       $action
 * @param list<string> $params  uuids, gateway names and addresses only (configd shows argv in ps)
 * @param int          $timeout
 * @return array the action's decoded JSON result, or a failure of the same shape
 */
function wgct_configd_json(string $action, array $params, int $timeout): array {
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
function wgct_dry_flag(mixed $value): ?bool {
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
 * @throws \RuntimeException when it is still held elsewhere after WGCT_GATEWAY_LOCK_WAIT_MS
 */
function wgct_gateway_lock(): \SplFileObject {
    $file = wgct_poll_lock(WGCT_GATEWAY_LOCK_FILE, WGCT_GATEWAY_LOCK_WAIT_MS, 200);
    if ($file === null) {
        $seconds = intdiv(WGCT_GATEWAY_LOCK_WAIT_MS, 1000);
        throw new \RuntimeException(
            WGCT_GATEWAY_LOCK_FILE . " is still held after {$seconds} s (fstat -f " . WGCT_GATEWAY_LOCK_FILE . ' names the holder); nothing was changed'
        );
    }
    return $file;
}

/**
 * @param mixed $data json_decode() of the pending file -- a JSON boundary, hence mixed
 * @return array<string, array{at: int, mode: string}> instance uuid => when its
 *         apply was requested and the mode it needs; a bare time (a 3.0 record,
 *         always Create's) reads as mode first; anything malformed reads as
 *         nothing pending
 */
function wgct_pending_from_json(mixed $data): array {
    $out = [];
    if (!is_array($data)) {
        return $out;
    }
    foreach ($data as $uuid => $record) {
        if (!is_string($uuid) || preg_match('/^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$/', $uuid) !== 1) {
            continue;
        }
        if (is_int($record)) {
            $out[$uuid] = ['at' => $record, 'mode' => 'first'];
        } elseif (is_array($record) && is_int($record['at'] ?? null) && in_array($record['mode'] ?? null, WGCT_APPLY_MODES, true)) {
            $out[$uuid] = ['at' => $record['at'], 'mode' => (string)$record['mode']];
        }
    }
    return $out;
}

/**
 * @return array<string, array{at: int, mode: string}> wgct_pending_from_json() of the file, [] when there is none
 */
function wgct_read_pending_file(string $path): array {
    $raw = is_file($path) ? file_get_contents($path) : false;
    return wgct_pending_from_json($raw === false ? null : json_decode($raw, true));
}

/**
 * @return array<string, array{at: int, mode: string}> instance uuid => when its apply was requested, and the mode it needs
 */
function wgct_read_apply_pending(): array {
    return wgct_read_pending_file(WGCT_APPLY_PENDING_FILE);
}

/**
 * Change the pending record read-modify-write, serialized on a close-on-exec
 * lock beside the file (so a mark and a settle never lose each other); written
 * atomically, and only when the change changed something.
 *
 * @param callable(array<string, array{at: int, mode: string}>): array<string, array{at: int, mode: string}> $change
 */
function wgct_update_apply_pending(callable $change): void {
    $dir = dirname(WGCT_APPLY_PENDING_FILE);
    if (!is_dir($dir) && !mkdir($dir, 0755, true) && !is_dir($dir)) {
        throw new \RuntimeException("could not create {$dir}");
    }
    $lock = new \SplFileObject(WGCT_APPLY_PENDING_FILE . '.lock', 'ce');
    $lock->flock(LOCK_EX);
    try {
        $all = wgct_read_apply_pending();
        $after = $change($all);
        if ($after === $all) {
            return;
        }
        if (!wgct_write_file_atomic(WGCT_APPLY_PENDING_FILE, (string)json_encode($after))) {
            throw new \RuntimeException('could not write ' . WGCT_APPLY_PENDING_FILE);
        }
    } finally {
        $lock->flock(LOCK_UN);
    }
}

/**
 * Record "saved, but its <mode> apply has not completed" (wgct_pending_mark()).
 */
function wgct_mark_apply_pending(string $uuid, string $mode): void {
    if (!in_array($mode, WGCT_APPLY_MODES, true)) {
        /* never InvalidArgumentException: this runs after a save, and the CLI reads that one as a pre-write input error */
        throw new \LogicException('not an apply mode: ' . substr($mode, 0, 20));
    }
    wgct_update_apply_pending(fn (array $all): array => wgct_pending_mark($all, $uuid, $mode, time()));
}

/**
 * Settle the record with an apply's outcome (wgct_pending_outcome(), wgct_pending_settle()).
 */
function wgct_settle_apply_pending(string $uuid, string $outcome): void {
    wgct_update_apply_pending(fn (array $all): array => wgct_pending_settle($all, $uuid, $outcome));
}

/**
 * @param string $out a configd reply
 * @return string one short line for the result list
 */
function wgct_step_summary(string $out): string {
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
 * @param list<array{action: string, result: string}> $apply wgct_run_steps()
 * @return list<string> the actions configd reported as failed
 */
function wgct_failed_steps(array $apply): array {
    $out = [];
    foreach ($apply as $step) {
        /*
         * Success-only: wgct_step_summary() already maps a JSON reply to
         * 'OK', and every step in the tunnel apply lists and every
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
 * @return list<array{action: string, result: string}> a refused step (wgct_step_refusal()) is never issued
 */
function wgct_run_steps(array $steps): array {
    $backend = new Backend();
    $results = [];
    foreach ($steps as [$action, $params]) {
        $name = trim($action . ' ' . implode(' ', $params));
        $refusal = wgct_step_refusal($action, $params);
        if ($refusal !== null) {
            $results[] = ['action' => $name, 'result' => $refusal];
            continue;
        }
        $out = $params === []
            ? $backend->configdRun($action, false, 300)
            : $backend->configdpRun($action, $params, false, 300);
        $results[] = ['action' => $name, 'result' => wgct_step_summary((string)$out)];
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
function wgct_replay_set(array $ours, ?array $before, ?array $after, array $forceDown): array {
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
function wgct_write_route_todos(array $todos): void {
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
 * After the gateway lock is released: replay the alarms routes.alarm dropped
 * while it was held (wgct_replay_set()).
 *
 * @param list<string>               $ours   gateway names the action wrote
 * @param array<string, string>|null $before gateway status taken before the lock
 * @return list<string> the gateways replayed
 */
function wgct_replay_after_hold(array $ours, ?array $before): array {
    Config::getInstance()->forceReload();
    $forceDown = [];
    foreach (wgct_core_snapshot()['gateways'] as $name => $g) {
        $forceDown[(string)$name] = $g['force_down'];
    }
    $set = wgct_replay_set($ours, $before, wgct_gateway_status(), $forceDown);
    if ($set !== []) {
        wgct_replay_alarm($set, WGCT_ACTION_LOG_TAG);
    }
    return array_map('strval', array_keys($set));
}

/**
 * After the gateway lock is released: replay swallowed alarms, then reconcile.
 *
 * @param list<string>               $ours   gateway names the action wrote
 * @param array<string, string>|null $before gateway status taken before the lock
 * @return array{replayed: list<string>, reconcile: string}
 */
function wgct_after_apply(array $ours, ?array $before): array {
    $replayed = wgct_replay_after_hold($ours, $before);
    $out = (new Backend())->configdRun('wgclienttunnels reconcile', false, 300);
    return ['replayed' => $replayed, 'reconcile' => wgct_step_summary((string)$out)];
}

/**
 * A config write that holds the gateway lock but applies nothing itself: the
 * API's in-process Create (spec 4.6 steps 1-5), whose apply then runs as the
 * configd action `wgclienttunnels apply`, which takes the lock on its own -- so
 * the lock is released before this returns, never held across that call.
 * Lock order stays gateway lock, then Config::lock() (inside $commit). Any
 * gateway alarm dropped during the hold is replayed after release, as every
 * gateway-locked action does (ruling 13); the tunnel's own gateways are not
 * running yet, and the apply replays them.
 *
 * @param callable(): array $commit a writer from writer.php, returning wgct_result()
 * @return array its result
 * @throws \RuntimeException when the gateway lock is still held elsewhere after WGCT_GATEWAY_LOCK_WAIT_MS
 */
function wgct_gateway_locked_commit(callable $commit): array {
    $before = wgct_gateway_status();
    $lock = wgct_gateway_lock();
    $pending = null;
    $result = wgct_result();
    try {
        try {
            $result = $commit();
        } finally {
            $lock->flock(LOCK_UN);
        }
    } catch (\Throwable $e) {
        $pending = $e;
    }
    /* Always replay once released; a replay failure never hides the commit's own (see wgct_routing_action()). */
    try {
        wgct_replay_after_hold([], $before);
    } catch (\Throwable $replayError) {
        if ($pending === null) {
            throw $replayError;
        }
        logMsg(WGCT_ACTION_LOG_TAG, 'alarm replay failed while unwinding ' . get_class($pending) . ': ' . $replayError->getMessage());
    }
    if ($pending !== null) {
        throw $pending;
    }
    return $result;
}

/**
 * Spec 4.6 for an action that changes routing. A dry run takes no gateway
 * lock and applies nothing.
 *
 * @param callable(): array $commit a writer from writer.php, returning wgct_result()
 * @param bool              $dry
 * @return array wgct_result() with 'apply' and 'after' filled once saved
 */
function wgct_routing_action(callable $commit, bool $dry): array {
    if ($dry) {
        return $commit();
    }
    $before = wgct_gateway_status();
    $lock = wgct_gateway_lock();
    $result = wgct_result();
    $ours = [];
    $pending = null;
    try {
        try {
            $result = $commit();
            if ($result['ok'] && $result['saved']) {
                $ours = $result['gateways'];
                wgct_write_route_todos($result['route_todos']);
                if ($result['reset_interface'] !== null) {
                    if (!function_exists('interface_reset')) {
                        throw new \RuntimeException('interface_reset() needs interfaces.inc; run Remove through tunnel.php');
                    }
                    /* reads the legacy $config loaded when this process started, which still holds the interface */
                    interface_reset($result['reset_interface']);
                }
                $result['apply'] = wgct_run_steps($result['steps']);
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
     * second failure out of wgct_after_apply() here must not silently
     * replace it as the exception the caller sees: it is caught, logged
     * (never with key material -- nothing replayed here carries one), and
     * the original exception is what gets rethrown. With nothing pending,
     * an after_apply failure is the only error there is, so it propagates
     * exactly as it would from a direct call.
     */
    if ($pending !== null) {
        try {
            wgct_after_apply($ours, $before);
        } catch (\Throwable $afterError) {
            logMsg(WGCT_ACTION_LOG_TAG, 'after_apply failed while unwinding ' . get_class($pending) . ': ' . $afterError->getMessage());
        }
        throw $pending;
    }
    $result['after'] = wgct_after_apply($ours, $before);
    if (!$result['ok'] || !$result['saved']) {
        return $result;
    }
    $failed = wgct_failed_steps($result['apply']);
    if ($failed !== []) {
        $result['errors']['apply'] = 'saved, but these apply steps failed: ' . implode(', ', $failed)
            . '; the reconcile repairs what it can and the findings show the rest';
    }
    $outcome = wgct_pending_outcome($result['steps'], $failed);
    if ($result['uuid'] !== '' && $outcome !== null) {
        wgct_settle_apply_pending($result['uuid'], $outcome);
    }
    return $result;
}

/**
 * An action that changes only the plugin's own config (Adopt): no gateway
 * lock; after the save, the reconcile renders whatever follows from it.
 *
 * @param callable(): array $commit returns wgct_result()
 * @return array wgct_result()
 */
function wgct_config_action(callable $commit, bool $dry): array {
    $result = $commit();
    if (!$dry && $result['ok'] && $result['saved']) {
        $out = (new Backend())->configdRun('wgclienttunnels reconcile', false, 300);
        $result['after'] = ['replayed' => [], 'reconcile' => wgct_step_summary((string)$out)];
    }
    return $result;
}

/**
 * A write whose apply is a filter reload alone (an Edit of the NAT sources):
 * no gateway lock (spec 4.6 step 1), then the reconcile. Anything but a filter
 * reload in its steps is a bug upstream: it is not run, and the change stays
 * apply-pending.
 *
 * @param callable(): array $commit a writer, returning wgct_result()
 * @return array wgct_result() with 'apply' and 'after' filled once saved
 */
function wgct_filter_action(callable $commit): array {
    $result = $commit();
    if (!$result['ok'] || !$result['saved']) {
        return $result;
    }
    foreach ($result['steps'] as [$action]) {
        if ($action !== 'filter reload') {
            throw new \LogicException("a filter-only action may not run {$action} without the gateway lock");
        }
    }
    $result['apply'] = wgct_run_steps($result['steps']);
    $result['after'] = wgct_after_apply([], null);
    $failed = wgct_failed_steps($result['apply']);
    if ($failed !== []) {
        $result['errors']['apply'] = 'saved, but these apply steps failed: ' . implode(', ', $failed)
            . '; the reconcile repairs what it can and the findings show the rest';
    }
    $outcome = wgct_pending_outcome($result['steps'], $failed);
    if ($result['uuid'] !== '' && $outcome !== null) {
        wgct_settle_apply_pending($result['uuid'], $outcome);
    }
    return $result;
}

/**
 * An apply on its own, as the keyless configd actions `wgclienttunnels apply
 * <uuid>` and `apply_mode <uuid> <mode>` run it: the API's in-process Create
 * (first) and Edit (its plan's mode) hand off here, and the Apply button of an
 * apply-pending tunnel runs it again -- without a mode, the mode its record
 * still needs (wgct_rerun_mode()). The modes are wgct_apply_mode_steps()'s;
 * filter takes no gateway lock. Only a complete run of at least the recorded
 * mode settles apply-pending.
 *
 * @param string      $uuid the WireGuard instance; its gateways (for the replay) are derived here
 * @param string|null $mode one of WGCT_APPLY_MODES, or null for the recorded one
 * @return array wgct_result()
 * @throws \InvalidArgumentException for an unknown mode, before anything runs
 */
function wgct_apply_only(string $uuid, ?string $mode = null): array {
    $mode ??= wgct_rerun_mode(wgct_read_apply_pending()[$uuid]['mode'] ?? null);
    $steps = wgct_apply_mode_steps($mode, $uuid);
    $t = wgct_derive(wgct_core_snapshot(), [$uuid])['tunnels'][0];
    if (in_array('instance-missing', array_column($t['findings'], 'code'), true)) {
        return wgct_result(['errors' => ['no WireGuard instance with this uuid'], 'uuid' => $uuid, 'apply_mode' => $mode]);
    }
    $locks = wgct_apply_mode_locks($mode);
    $gatewayNames = $locks ? array_values(array_filter([$t['gw4'], $t['gw6']], fn (?string $g): bool => $g !== null)) : [];
    $before = $locks ? wgct_gateway_status() : null;
    $lock = $locks ? wgct_gateway_lock() : null;
    $apply = [];
    $pending = null;
    try {
        try {
            $apply = wgct_run_steps($steps);
        } finally {
            $lock?->flock(LOCK_UN);
        }
    } catch (\Throwable $e) {
        $pending = $e;
    }
    /* Always replay, once the lock is released; see wgct_routing_action(). */
    if ($pending !== null) {
        try {
            wgct_after_apply($gatewayNames, $before);
        } catch (\Throwable $afterError) {
            logMsg(WGCT_ACTION_LOG_TAG, 'after_apply failed while unwinding ' . get_class($pending) . ': ' . $afterError->getMessage());
        }
        throw $pending;
    }
    $after = wgct_after_apply($gatewayNames, $before);
    $result = wgct_result([
        'ok' => true, 'saved' => true, 'uuid' => $uuid, 'gateways' => $gatewayNames, 'steps' => $steps,
        'apply' => $apply, 'after' => $after, 'apply_mode' => $mode,
    ]);
    $failed = wgct_failed_steps($apply);
    if ($failed !== []) {
        $result['errors']['apply'] = 'these apply steps failed: ' . implode(', ', $failed)
            . '; the reconcile repairs what it can and the findings show the rest';
    }
    $outcome = wgct_pending_outcome($steps, $failed);
    if ($outcome !== null) {
        wgct_settle_apply_pending($uuid, $outcome);
    }
    return $result;
}

/**
 * Self-tests for the pure parts of the apply. No configd, no locks.
 *
 * @return int exit code, 0 when every case passes
 */
function wgct_apply_selftest(): int {
    $t = ['fail' => 0, 'total' => 0];
    wgct_check($t, 'apply: empty output => (no output)', wgct_step_summary("  \n") === '(no output)');
    wgct_check($t, 'apply: OK => OK', wgct_step_summary("OK\n") === 'OK');
    wgct_check($t, 'apply: JSON output (assign-opts) => OK', wgct_step_summary('{"igc0": "igc0"}') === 'OK');
    wgct_check($t, 'apply: first line only', wgct_step_summary("Error (1)\nmore") === 'Error (1)');
    wgct_check($t, 'apply: long output cut at 120', strlen(wgct_step_summary(str_repeat('a', 200))) === 120);
    wgct_check($t, 'apply: only an exact OK passes; (no output), ERR, an Error prefix and an arbitrary message all fail',
        wgct_failed_steps([
            ['action' => 'a', 'result' => 'OK'], ['action' => 'b', 'result' => '(no output)'],
            ['action' => 'c', 'result' => 'ERR'], ['action' => 'd', 'result' => 'Error (1)'],
            ['action' => 'e', 'result' => 'unexpected widget failure'],
        ]) === ['b', 'c', 'd', 'e']);
    wgct_check($t, "apply: step_summary()'d replies feed the same rule -- OK and JSON pass, an empty reply fails",
        wgct_failed_steps([['action' => 'x', 'result' => wgct_step_summary("OK\n")]]) === []
        && wgct_failed_steps([['action' => 'x', 'result' => wgct_step_summary('{"igc0": "igc0"}')]]) === []
        && wgct_failed_steps([['action' => 'x', 'result' => wgct_step_summary('')]]) === ['x']);
    $forceDown = ['WAN_A' => false, 'tun_c' => false, 'tun_c-ipv6' => true, 'tun_a' => false];
    wgct_check($t, 'apply: replay covers our gateways plus any whose status changed during the hold',
        wgct_replay_set(['tun_c', 'tun_c-ipv6'], ['WAN_A' => 'none', 'tun_a' => 'none'], ['WAN_A' => 'down', 'tun_a' => 'none'], $forceDown)
        === ['WAN_A' => false, 'tun_c' => false, 'tun_c-ipv6' => true]);
    wgct_check($t, 'apply: no status before the lock => our gateways only',
        wgct_replay_set(['tun_c'], null, ['WAN_A' => 'down'], $forceDown) === ['tun_c' => false]);
    wgct_check($t, 'apply: a removed gateway and one missing from config are skipped',
        wgct_replay_set(['tun_gone'], ['X' => 'none'], ['X' => 'down'], $forceDown) === []);
    wgct_check($t, 'apply: nothing ours, nothing changed => no replay',
        wgct_replay_set([], ['WAN_A' => 'none'], ['WAN_A' => 'none'], $forceDown) === []);
    wgct_check($t, 'apply: a refused/failed commit leaves ours empty, but a gateway that changed meanwhile is still replayed',
        wgct_replay_set([], ['WAN_A' => 'none'], ['WAN_A' => 'down'], $forceDown) === ['WAN_A' => false]);
    $u1 = '00000000-0000-4000-8000-000000000001';
    wgct_check($t, 'apply: the pending record keeps only uuid entries with a time (and a mode, once written by 3.1)',
        wgct_pending_from_json([$u1 => 1700000000, 'not-a-uuid' => 1, '00000000-0000-4000-8000-000000000002' => 'soon'])
            === [$u1 => ['at' => 1700000000, 'mode' => 'first']]);
    wgct_check($t, 'apply: a malformed pending record reads as nothing pending',
        wgct_pending_from_json('garbage') === [] && wgct_pending_from_json(null) === []);
    wgct_check($t, 'apply: dry flag -- absent, empty, "0", 0 and false all mean real',
        wgct_dry_flag(null) === false && wgct_dry_flag('') === false && wgct_dry_flag('0') === false
        && wgct_dry_flag(0) === false && wgct_dry_flag(false) === false);
    wgct_check($t, 'apply: dry flag -- "1", 1 and true all mean dry',
        wgct_dry_flag('1') === true && wgct_dry_flag(1) === true && wgct_dry_flag(true) === true);
    wgct_check($t, 'apply: dry flag -- anything else (a stray float, string, array) is refused, not defaulted',
        wgct_dry_flag('yes') === null && wgct_dry_flag(2) === null && wgct_dry_flag(1.0) === null && wgct_dry_flag([]) === null);

    /* step lists: Create routes the endpoint before the device first sends; Remove registers after the destroy */
    $actions = fn (array $steps): array => array_map(fn (array $s): string => trim($s[0] . ' ' . implode(' ', $s[1])), $steps);
    wgct_check($t, 'apply: Create runs template reload, routes, wireguard configure, registration, assign-opts, routes, filter reload',
        $actions(WGCT_CREATE_APPLY_STEPS) === [
            'template reload OPNsense/Wireguard', 'interface routes configure', 'wireguard configure', 'interface invoke registration',
            '!interface list assign-opts', 'interface routes configure', 'filter reload',
        ]);
    $create = $actions(WGCT_CREATE_APPLY_STEPS);
    wgct_check($t, 'apply: Create installs the endpoint route before wireguard configure first starts the device',
        array_search('interface routes configure', $create, true) < array_search('wireguard configure', $create, true));
    wgct_check($t, 'apply: Remove keeps its order -- wireguard configure destroys the device before registration',
        $actions(WGCT_REMOVE_APPLY_STEPS) === [
            'template reload OPNsense/Wireguard', 'wireguard configure', 'interface invoke registration',
            '!interface list assign-opts', 'interface routes configure', 'filter reload',
        ]);
    wgct_check($t, 'apply: Rebind routes the new endpoint, then restarts the instance so it handshakes on that route',
        wgct_rebind_apply_steps($u1) === [['interface routes configure', []], ['wireguard restart', [$u1]]]);

    /* core reads anything but a lower-case v4 uuid as a CARP vhid and acts on every instance;
     * $v4 carries hex letters, so its upper-case form really differs */
    $v4 = 'a0000000-0000-4000-8000-00000000000b';
    wgct_check($t, 'apply: a WireGuard restart of a lower-case v4 instance uuid is issued',
        wgct_step_refusal('wireguard restart', [$u1]) === null && wgct_step_refusal('wireguard restart', [$v4]) === null);
    wgct_check($t, 'apply: an upper-case, v1, bad-variant or non-uuid id, or two parameters, is refused and counts as a failed step',
        wgct_step_refusal('wireguard restart', [strtoupper($v4)]) !== null
        && wgct_step_refusal('wireguard restart', ['00000000-0000-1000-8000-000000000001']) !== null
        && wgct_step_refusal('wireguard restart', ['00000000-0000-4000-7000-000000000001']) !== null
        && wgct_step_refusal('wireguard restart', ['1']) !== null
        && wgct_step_refusal('wireguard restart', [$u1, $u1]) !== null
        && wgct_step_refusal('wireguard stop', ['vhid1']) !== null
        && wgct_failed_steps([['action' => 'x', 'result' => (string)wgct_step_refusal('wireguard restart', ['1'])]]) === ['x']);
    wgct_check($t, 'apply: steps without parameters, and other actions, are never refused',
        wgct_step_refusal('wireguard configure', []) === null && wgct_step_refusal('interface routes configure', []) === null
        && wgct_step_refusal('wgclienttunnels replay_alarm', ['a,b']) === null);

    /* apply modes (S5, rulings 1 and 2): tunnel is the re-run and Edit's full apply */
    wgct_check($t, 'apply: modes -- first is Create\'s steps, tunnel adds wireguard restart <uuid>, routes and filter are one step each',
        wgct_apply_mode_steps('first', $u1) === WGCT_CREATE_APPLY_STEPS
        && wgct_apply_mode_steps('tunnel', $u1) === array_merge(WGCT_CREATE_APPLY_STEPS, [['wireguard restart', [$u1]]])
        && wgct_apply_mode_steps('routes', $u1) === [['interface routes configure', []]]
        && wgct_apply_mode_steps('filter', $u1) === [['filter reload', []]]);
    $refusedMode = false;
    try {
        wgct_apply_mode_steps('none', $u1);
    } catch (\InvalidArgumentException) {
        $refusedMode = true;
    }
    wgct_check($t, 'apply: only filter runs without the gateway lock; none and an unknown mode have no steps',
        wgct_apply_mode_locks('first') && wgct_apply_mode_locks('tunnel') && wgct_apply_mode_locks('routes')
        && !wgct_apply_mode_locks('filter') && !wgct_apply_mode_locks('none') && $refusedMode);

    /* apply-pending (S5 review I2): each complete mode is its outcome; a saved Remove forgets the record */
    $sentinelSteps = [['interface loopback configure', []], ['interface routes configure', []]];
    wgct_check($t, 'apply: pending outcome -- each mode\'s complete step list with every step OK is that mode',
        wgct_pending_outcome(WGCT_CREATE_APPLY_STEPS, []) === 'first'
        && wgct_pending_outcome(wgct_apply_mode_steps('tunnel', $u1), []) === 'tunnel'
        && wgct_pending_outcome(wgct_apply_mode_steps('routes', $u1), []) === 'routes'
        && wgct_pending_outcome(wgct_apply_mode_steps('filter', $u1), []) === 'filter');
    wgct_check($t, 'apply: pending outcome -- none for a failed step, a Rebind, a Sentinel apply or a partial list',
        wgct_pending_outcome(WGCT_CREATE_APPLY_STEPS, ['wireguard configure']) === null
        && wgct_pending_outcome(wgct_apply_mode_steps('tunnel', $u1), ['wireguard restart ' . $u1]) === null
        && wgct_pending_outcome(wgct_apply_mode_steps('filter', $u1), ['filter reload']) === null
        && wgct_pending_outcome(wgct_rebind_apply_steps($u1), []) === null
        && wgct_pending_outcome($sentinelSteps, []) === null
        && wgct_pending_outcome(array_slice(WGCT_CREATE_APPLY_STEPS, 1), []) === null);
    wgct_check($t, 'apply: a saved Remove forgets the record even when its apply failed (the instance is gone from config)',
        wgct_pending_outcome(WGCT_REMOVE_APPLY_STEPS, ['filter reload']) === 'forget');
    $rec = wgct_pending_mark([], $u1, 'filter', 100);
    wgct_check($t, 'apply: pending mark -- the stronger of the recorded and the new mode is kept, with the new time',
        $rec === [$u1 => ['at' => 100, 'mode' => 'filter']]
        && wgct_pending_mark($rec, $u1, 'tunnel', 200) === [$u1 => ['at' => 200, 'mode' => 'tunnel']]
        && wgct_pending_mark(wgct_pending_mark($rec, $u1, 'tunnel', 200), $u1, 'routes', 300) === [$u1 => ['at' => 300, 'mode' => 'tunnel']]);
    $routes = wgct_pending_mark([], $u1, 'routes', 100);
    wgct_check($t, 'apply: pending settle -- a complete mode at least as strong as the record clears it; a weaker one keeps it',
        wgct_pending_settle($routes, $u1, 'filter') === $routes
        && wgct_pending_settle($routes, $u1, 'routes') === []
        && wgct_pending_settle($routes, $u1, 'tunnel') === []
        && wgct_pending_settle(wgct_pending_mark([], $u1, 'tunnel', 1), $u1, 'first') !== []
        && wgct_pending_settle(wgct_pending_mark([], $u1, 'first', 1), $u1, 'first') === []
        && wgct_pending_settle(wgct_pending_mark([], $u1, 'tunnel', 1), $u1, 'forget') === []
        && wgct_pending_settle([], $u1, 'tunnel') === []);
    wgct_check($t, 'apply: the Apply button re-runs the recorded mode; Create\'s first apply and no record re-run as the tunnel apply',
        wgct_rerun_mode('filter') === 'filter' && wgct_rerun_mode('routes') === 'routes'
        && wgct_rerun_mode('first') === 'tunnel' && wgct_rerun_mode('tunnel') === 'tunnel' && wgct_rerun_mode(null) === 'tunnel');
    wgct_check($t, 'apply: pending file -- a 3.0 bare time reads as Create\'s (first); a malformed mode or uuid reads as nothing',
        wgct_pending_from_json([$u1 => 7]) === [$u1 => ['at' => 7, 'mode' => 'first']]
        && wgct_pending_from_json([$u1 => ['at' => 7, 'mode' => 'routes']]) === [$u1 => ['at' => 7, 'mode' => 'routes']]
        && wgct_pending_from_json([$u1 => ['at' => 7, 'mode' => 'none']]) === []
        && wgct_pending_from_json([$u1 => ['at' => '7', 'mode' => 'filter']]) === []
        && wgct_pending_from_json(['x' => 7]) === [] && wgct_pending_from_json('x') === []);
    wgct_check($t, 'apply: the pending record lives in /var/db/wgclienttunnels (survives a reboot)',
        WGCT_APPLY_PENDING_FILE === '/var/db/wgclienttunnels/apply_pending.json');

    /* the failure footer, per command */
    $createFooter = wgct_failure_footer('create', $u1);
    wgct_check($t, 'apply: create footer names `tunnel.php apply <uuid>` when the uuid is known',
        str_contains($createFooter, "`tunnel.php apply {$u1}`") && str_contains($createFooter, 'tunnel.php status'));
    wgct_check($t, 'apply: create footer without a uuid says where to find it',
        str_contains(wgct_failure_footer('create', ''), '`tunnel.php apply UUID`')
        && str_contains(wgct_failure_footer('create', ''), 'tunnel.php list'));
    wgct_check($t, 'apply: apply footer names `tunnel.php apply <uuid>` again',
        str_contains(wgct_failure_footer('apply', $u1), "`tunnel.php apply {$u1}` again"));
    wgct_check($t, 'apply: edit footer names `tunnel.php apply <uuid>` and status',
        str_contains(wgct_failure_footer('edit', $u1), "`tunnel.php apply {$u1}`")
        && str_contains(wgct_failure_footer('edit', $u1), '`tunnel.php status`'));
    $others = array_map(fn (string $c): string => wgct_failure_footer($c, $u1), ['remove', 'rebind', 'adopt', 'ensure-sentinel']);
    wgct_check($t, 'apply: remove, rebind, adopt and ensure-sentinel footers point to status and the list, never to apply',
        array_filter($others, fn (string $f): bool => str_contains($f, 'tunnel.php apply') || !str_contains($f, '`tunnel.php status`')
            || !str_contains($f, '`tunnel.php list`')) === []);
    wgct_check($t, 'apply: commands that never save get no footer',
        wgct_failure_footer('list', '') === '' && wgct_failure_footer('status', '') === ''
        && wgct_failure_footer('reconcile', '') === '' && wgct_failure_footer('measure-mtu', '') === '');
    return wgct_tally_report('apply', $t);
}
