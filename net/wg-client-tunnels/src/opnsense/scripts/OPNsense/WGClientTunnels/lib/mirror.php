<?php

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Health mirror library. The decisions are pure functions of a snapshot:
 *
 *   config.enabled    bool, plugin enabled AND the health_mirror switch
 *   config.gateways   name => [uuid, ipprotocol, interface, disabled, force_down,
 *                              losshigh, losslow, time_period]
 *   config.underlays  IPv4 tunnel gateway name => WAN gateway name
 *   config.pairs      IPv4 tunnel gateway name => its IPv6 gateway name
 *   config.held       gateway names held down by pass 1: the owned hold records
 *   config.foreign    name (uuid when the gateway is gone) => 'released' | 'foreign',
 *                     the hold records the next commit prunes (wgct_resolve_holds())
 *   config.duplicates names with a second hold record, which the next commit drops
 *   config.holds_rows the engine model's hold records as stored
 *   config.live_boot  kern.boot_id, '' when unreadable
 *   config.previous_boot boot.json's boot id when it names another boot, else null
 *   config.boot_unreadable no live boot id: the tick neither takes nor releases a hold
 *   live.status       name => gateway_status.php status, null when unavailable
 *   live.loss         name => dpinger loss percent, null without data
 *   live.sock_age     name => dpinger socket age in seconds, null when absent
 *
 * Collectors build the snapshot; wgct_locked_commit() is the only way the
 * mirror writes config (spec 2026-09-24 section 4.6). The hold records live in
 * the engine model, which has no API (spec 2026-10-20 section 3.5): a record
 * proves a hold only when its boot is one the mirror itself ran under.
 */

use OPNsense\Core\Config;

require_once __DIR__ . '/tunnels.php';
require_once __DIR__ . '/render.php';

/* Used only when a gateway has no time_period configured. */
const SETTLE_FALLBACK_SECONDS = 60;

function logMsg($tag, $msg) {
    wgct_log(LOG_NOTICE, "[$tag] $msg");
}

/* The tick lock and the markers that make a skipped tick log once per state. */
const WGCT_HEALTH_LOCK_FILE = WGCT_RUN_DIR . '/health.lock';
const WGCT_HEALTH_SKIPPED_FILE = WGCT_RUN_DIR . '/health.skipped';
const WGCT_HEALTH_UNOPENABLE_FILE = WGCT_RUN_DIR . '/health.unopenable';
const WGCT_GATEWAY_SKIPPED_FILE = WGCT_RUN_DIR . '/gateway.skipped';
const WGCT_BOOT_UNREADABLE_FILE = WGCT_RUN_DIR . '/boot.unreadable';

/* The boot the mirror last ran under, written at the end of every tick: after a reboot it still names the
 * previous boot until the first tick, which is how that tick knows the records of that boot are its own. */
const WGCT_BOOT_FILE = WGCT_DB_DIR . '/boot.json';
const WGCT_BOOT_FILE_MAX_BYTES = 256;

/**
 * What a tick does about a lock it could not take, once per state (the shape of wgct_failure_log_plan()).
 *
 * @param bool $skipped      whether this tick could not take the lock
 * @param bool $markerExists whether the marker of an earlier skip is present
 * @return array{log: ?string, marker: 'write'|'remove'|'keep'} log is 'skip' on the first skip,
 *         'resume' on the first success after one, null otherwise
 */
function wgct_skip_log_plan(bool $skipped, bool $markerExists): array {
    if ($skipped) {
        return $markerExists ? ['log' => null, 'marker' => 'keep'] : ['log' => 'skip', 'marker' => 'write'];
    }
    return $markerExists ? ['log' => 'resume', 'marker' => 'remove'] : ['log' => null, 'marker' => 'keep'];
}

/**
 * Apply wgct_skip_log_plan() for one lock: log the change of state, keep the marker in step.
 *
 * @param string $marker  the marker file of this lock
 * @param bool   $skipped whether this tick could not take the lock
 * @param string $skipMsg logged on the first skip
 * @param string $resumeMsg logged on the first success after a skip
 */
function wgct_note_lock(string $marker, bool $skipped, string $skipMsg, string $resumeMsg): void {
    $plan = wgct_skip_log_plan($skipped, wgct_read_state_file($marker, 16) !== null);
    if ($plan['log'] !== null) {
        logMsg('wgct-health', $plan['log'] === 'skip' ? $skipMsg : $resumeMsg);
    }
    if ($plan['marker'] === 'write') {
        wgct_write_file_atomic($marker, "skipped\n");
    } elseif ($plan['marker'] === 'remove') {
        @unlink($marker);
    }
}

/**
 * Seconds since a dpinger control socket was created, or null if it is absent.
 *
 * @param string $sock path to the dpinger control socket
 * @return int|null age in seconds, null when the socket does not exist
 */
function wgct_socket_age($sock) {
    clearstatcache(true, $sock);
    $mtime = @filemtime($sock);
    if ($mtime === false) {
        return null;
    }
    return max(0, time() - $mtime);
}

/**
 * Decide whether the IPv6 gateway should be forced down, given the paired IPv4
 * gateway's current loss and its own loss watermarks. Mirrors dpinger's
 * hysteresis: trip at losshigh, recover at losslow, hold in between.
 *
 * @param int|null $lossVal     current IPv4 loss percent, or null if no data
 * @param int      $lossHigh    high watermark (force down at/above)
 * @param int      $lossLow     low watermark (recover at/below)
 * @param bool     $currentDown current force_down state (hysteresis memory)
 * @param bool     $settled     false while dpinger has not filled its averaging
 *                              window, which makes any reading unreliable
 * @return bool    true => force_down
 */
function wgct_decide_down($lossVal, $lossHigh, $lossLow, $currentDown, $settled = true) {
    if (!$settled) {
        // A just-restarted dpinger has no samples yet: it reads 0% or 100% (or has
        // no socket at all) whatever the path is doing. Neither direction counts.
        return $currentDown;
    }
    if ($lossVal === null) {
        return true;                // no dpinger data => treat tunnel as down
    }
    if ($lossVal >= $lossHigh) {
        return true;                // at/above high watermark => down
    }
    if ($lossVal <= $lossLow) {
        return false;               // at/below low watermark => up
    }
    return $currentDown;            // between watermarks => hold (hysteresis)
}

/**
 * Is a WAN gateway status "down" for a downloss gateway group? Same semantics
 * as GatewayGroups::gatewayIsUp('downloss', ...): latency alone never counts.
 *
 * @param string|null $status gateway_status.php status, null when absent
 * @return bool true => down
 */
function wgct_wan_status_down($status) {
    return $status === null || in_array($status, ['down', 'force_down', 'loss', 'delay+loss'], true);
}

/**
 * Underlay decision for one tunnel.
 *
 * @param array $wan  ['disabled' => bool, 'force_down' => bool,
 *                     'status' => string|null, 'settled' => bool]
 * @param bool  $held this pass currently holds the tunnel down
 * @return bool true => the tunnel must be held down
 */
function wgct_decide_underlay(array $wan, $held) {
    // Configuration, not a reading: a disabled or forced-down WAN holds its tunnels at once.
    if ($wan['disabled'] || $wan['force_down'] || $wan['status'] === 'force_down') {
        return true;
    }
    // Every routing reconfigure restarts all dpingers, and a fresh one reads down or up
    // before it has samples. Until the WAN's reading has settled, the decision stands.
    if (!$wan['settled']) {
        return $held;
    }
    return wgct_wan_status_down($wan['status']);
}

/**
 * Current dpinger loss for a gateway, read from its control socket.
 *
 * @param string $name gateway name
 * @return int|null loss percent, null when the socket is absent or unreadable
 */
function wgct_read_loss($name) {
    $sock = "/var/run/dpinger_{$name}.sock";
    if (!file_exists($sock)) {
        return null;
    }
    $fp = @stream_socket_client("unix://{$sock}", $errno, $errstr, 1);
    if (!$fp) {
        return null;
    }
    fwrite($fp, "\n");
    $line = fgets($fp, 1024);
    fclose($fp);
    if (!$line) {
        return null;
    }
    $parts = preg_split('/\s+/', trim($line));
    $loss = end($parts);
    return is_numeric($loss) ? (int)$loss : null;
}

/**
 * Live status of every monitored gateway, as the GUI and the groups see it.
 *
 * @return array|null name => status string, null when status is unavailable
 */
function wgct_gateway_status() {
    $json = shell_exec('/usr/local/opnsense/scripts/routes/gateway_status.php');
    $data = is_string($json) ? json_decode($json, true) : null;
    if (!is_array($data)) {
        return null;
    }
    $status = [];
    foreach ($data as $name => $row) {
        $status[$name] = (string)($row['status'] ?? '');
    }
    return $status;
}

/**
 * Replay the gateway alarm OPNsense dropped for our own force_down changes.
 *
 * The reconfigure below restarts dpinger and SIGHUPs gateway_watcher, which
 * then raises "none -> force_down" (or back) for the gateways we changed and
 * calls the routes.alarm action. That action is
 * `flock -n -E 0 /tmp/filter_reload_gateway.lock rc.routing_configure alarm`:
 * non-blocking, so while we still hold the lock it silently does nothing. The
 * filter is then never rebuilt with the new status of dpinger-monitored
 * gateways -- their status comes from the watcher, which had not re-read
 * config when our reconfigure generated the ruleset -- and 20-recover never
 * kills their states. Observed 2026-09-22: a forced-down tunnel stayed the
 * group's route-to until an unrelated reconfigure.
 *
 * So, lock released: wait until gateway status shows what we wrote, then run
 * the alarm path ourselves, blocking on the lock. It reconfigures routing
 * without restarting monitors, runs the monitor syshooks (state kill) for the
 * named gateways, and rebuilds the filter.
 *
 * @param array $expected name => bool force_down for every gateway we changed
 */
function wgct_replay_alarm(array $expected, $logTag) {
    $deadline = time() + 20;
    do {
        $status = wgct_gateway_status() ?? [];
        $pending = [];
        foreach ($expected as $name => $down) {
            if (isset($status[$name]) && (($status[$name] === 'force_down') !== $down)) {
                $pending[] = $name;
            }
        }
        if (empty($pending)) {
            break;
        }
        sleep(1);
    } while (time() < $deadline);
    if (!empty($pending)) {
        logMsg($logTag, 'gateway status still stale for ' . implode(',', $pending) . ' after 20s; replaying alarm anyway');
    }
    /*
     * Run it through configd, never exec() from here: PHP opens files without
     * close-on-exec, so anything this process starts inherits its open lock
     * files -- including the single-instance lock -- and a daemon the
     * reconfigure (re)starts keeps them for as long as it lives. Both happened
     * on 2026-09-22: a restarted filterlog held first the gateway lock
     * (blocking every reconfigure, dropping every alarm) and then this
     * script's own lock (every later tick exited at the guard). configd starts
     * the action from its own process, which holds neither.
     */
    $result = trim((new OPNsense\Core\Backend())->configdpRun(
        'wgclienttunnels replay_alarm',
        [implode(',', array_keys($expected))]
    ));
    if ($result !== 'OK') {
        logMsg($logTag, 'alarm replay for ' . implode(',', array_keys($expected)) . " failed: {$result}");
    }
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
 * The mirror's replay set (spec 4.6 step 6, as for every gateway-locked action): the force_down
 * changes it applied, as written, plus every gateway whose status changed while it held the gateway
 * lock -- routes.alarm dropped those alarms, and gateway_watcher never raises them again. Pure.
 *
 * @param array<string, bool>        $changes  name => force_down the mirror wrote
 * @param array<string, string>|null $before   gateway status taken before the lock
 * @param array<string, string>|null $after    gateway status taken after release
 * @param array<string, array>       $gateways config rows by name, each with 'force_down'
 * @return array<string, bool> name => expected force_down, sorted by name
 */
function wgct_mirror_replay_set(array $changes, ?array $before, ?array $after, array $gateways): array {
    $forceDown = [];
    foreach ($gateways as $name => $row) {
        $forceDown[(string)$name] = !empty($row['force_down']);
    }
    $set = wgct_replay_set([], $before, $after, $forceDown);
    foreach ($changes as $name => $down) {
        $set[(string)$name] = (bool)$down;
    }
    ksort($set);
    return $set;
}

/**
 * After the mirror released the gateway lock: replay its own changes and any alarm dropped while it
 * held the lock (wgct_mirror_replay_set()).
 *
 * @param array<string, bool>        $changes name => force_down the mirror wrote
 * @param array<string, string>|null $before  gateway status taken before the lock
 */
function wgct_mirror_replay(array $changes, ?array $before, $logTag): void {
    OPNsense\Core\Config::getInstance()->forceReload();
    $set = wgct_mirror_replay_set($changes, $before, wgct_gateway_status(), wgct_collect_config()['gateways']);
    if ($set !== []) {
        wgct_replay_alarm($set, $logTag);
    }
}

/**
 * Loss watermarks for a gateway, normalised. Empty/zero losshigh means the
 * gateway has no loss alarm, so only a fully-dead path counts as down.
 *
 * @param array $row gateway row from wgct_collect_config()
 * @return array [int $lossLow, int $lossHigh]
 */
function wgct_watermarks(array $row) {
    $high = (int)$row['losshigh'];
    if ($high <= 0) {
        $high = 100;
    }
    $low = (int)$row['losslow'];
    if ($low < 0 || $low > $high) {
        $low = $high;
    }
    return [$low, $high];
}

/**
 * How long this gateway's dpinger needs before a healthy reading means
 * anything: its own loss averaging window, unless overridden.
 *
 * @param array    $row      gateway row
 * @param int|null $override --settle=N, or null to use the gateway's own
 * @return int seconds
 */
function wgct_settle_window(array $row, $override) {
    if ($override !== null) {
        return $override;
    }
    $window = (int)$row['time_period'];
    return $window > 0 ? $window : SETTLE_FALLBACK_SECONDS;
}

/**
 * Is this gateway's dpinger old enough for a healthy reading to count?
 *
 * @param array    $row      gateway row
 * @param int|null $age      dpinger socket age in seconds, null when absent
 * @param int|null $override --settle=N
 * @return array [bool $settled, int|null $ageSeconds, int $windowSeconds]
 */
function wgct_settled(array $row, $age, $override) {
    $window = wgct_settle_window($row, $override);
    return [($window === 0) || ($age !== null && $age >= $window), $age, $window];
}

/**
 * Everything the decisions read from config, derived from core (spec 4.1).
 * Builds fresh models, so called after Config::lock() it reflects config.xml
 * as it is now.
 *
 * @return array see the file header
 */
function wgct_collect_config() {
    $mdl = new OPNsense\WGClientTunnels\WGClientTunnels();
    $engine = new OPNsense\WGClientTunnels\Engine();
    $core = wgct_core_snapshot();
    $inputs = wgct_mirror_inputs(wgct_derive($core, wgct_split_csv($engine->managed->getValue())));
    $holds = wgct_engine_holds($engine, $core['gateways']);
    $nameByUuid = [];
    foreach ($core['gateways'] as $name => $g) {
        $nameByUuid[$g['uuid']] = (string)$name;
    }
    $held = [];
    foreach ($holds['owned'] as $uuid) {
        if (isset($nameByUuid[$uuid])) {
            $held[] = $nameByUuid[$uuid];
        }
    }
    $foreign = [];
    foreach ($holds['pruned'] as $uuid => $reason) {
        $foreign[$nameByUuid[$uuid] ?? $uuid] = $reason;
    }
    return [
        'enabled' => $mdl->enabled->isEqual('1') && $mdl->health_mirror->isEqual('1'),
        'gateways' => $core['gateways'],
        'underlays' => $inputs['underlays'],
        'pairs' => $inputs['pairs'],
        'held' => $held,
        'foreign' => $foreign,
        'duplicates' => array_map(fn (string $uuid): string => $nameByUuid[$uuid] ?? $uuid, $holds['duplicates']),
        'holds_rows' => $holds['rows'],
        'live_boot' => $holds['live_boot'],
        'previous_boot' => $holds['previous_boot'],
        'boot_unreadable' => $holds['live_boot'] === '',
    ];
}

/**
 * The engine model's hold records resolved against the live boot and boot.json's (spec 3.5), for the mirror and
 * the Tunnels view. With no live boot id nothing is decided (ruling R17): no row is owned or pruned, so a reader
 * shows nothing held and the mirror's tick neither takes nor releases a hold.
 *
 * @param \OPNsense\WGClientTunnels\Engine $engine
 * @param array $gateways core snapshot gateways: name => row with uuid and force_down
 * @return array{rows: list<array>, live_boot: string, previous_boot: ?string, owned: list<string>,
 *               pruned: array<string, string>, duplicates: list<string>} rows as stored; uuids otherwise
 */
function wgct_engine_holds(\OPNsense\WGClientTunnels\Engine $engine, array $gateways): array {
    $rows = array_values($engine->holdRows());
    $live = OPNsense\WGClientTunnels\Engine::liveBootId();
    $recorded = wgct_parse_boot_record(wgct_read_state_file(WGCT_BOOT_FILE, WGCT_BOOT_FILE_MAX_BYTES));
    $previous = $recorded !== null && $recorded !== $live ? $recorded : null;
    $out = ['rows' => $rows, 'live_boot' => $live, 'previous_boot' => $previous, 'owned' => [], 'pruned' => [], 'duplicates' => []];
    if ($live === '') {
        return $out;
    }
    $forceDown = [];
    foreach ($gateways as $g) {
        $forceDown[$g['uuid']] = $g['force_down'];
    }
    $deduped = wgct_dedupe_hold_rows($rows, $live, $previous);
    $resolved = wgct_resolve_holds($deduped['rows'], $live, $previous, $forceDown);
    return ['owned' => $resolved['owned'], 'pruned' => $resolved['pruned'], 'duplicates' => $deduped['duplicates']] + $out;
}

/**
 * boot.json's boot id. Pure.
 *
 * @param string|null $json the file's content, null when absent or untrustworthy
 * @return string|null the boot id; null unless the content is exactly {"boot_id": <1-64 lower-case hex>, "at": <int>}
 */
function wgct_parse_boot_record(?string $json): ?string {
    $r = $json !== null ? json_decode($json, true) : null;
    if (!is_array($r) || array_is_list($r) || !wgct_has_exact_keys($r, ['boot_id', 'at']) || !is_int($r['at'])
        || !is_string($r['boot_id']) || preg_match('/^[0-9a-f]{1,64}$/D', $r['boot_id']) !== 1) {
        return null;
    }
    return $r['boot_id'];
}

/**
 * @return string boot.json's content for $bootId at $at. Pure.
 */
function wgct_boot_record_json(string $bootId, int $at): string {
    return (string)json_encode(['boot_id' => $bootId, 'at' => $at]);
}

/**
 * Record the boot this tick ran under (the C3 writer: root, 0600, in the 0700 state directory).
 */
function wgct_write_boot_record(string $bootId): bool {
    return wgct_write_file_atomic(WGCT_BOOT_FILE, wgct_boot_record_json($bootId, time()));
}

/**
 * Decide which hold records are ours, by the boot each was taken in (spec 3.5, convention C1). Pure.
 *
 * A record proves a hold only when its boot is one the plugin itself observed:
 *
 *   boot                               gateway force_down   result
 *   the live boot                      1                    owned
 *   the live boot                      0                    pruned 'released' (taken off by hand)
 *   boot.json's previous boot          1                    owned (ours from before the reboot)
 *   boot.json's previous boot          0                    pruned 'released' (as the row above)
 *   any other boot, whatever force_down                     pruned 'foreign' (restored or edited config)
 *
 * A gateway missing from $forceDown reads as not forced down. With no live boot id nothing is owned and
 * every row is foreign. A previous boot equal to the live one is no previous boot. The caller re-stamps
 * every owned row with the live boot id and passes a previous boot only on the first tick after a reboot.
 * A force_down gateway with no row is manual and never reaches this function.
 *
 * @param array<int, array{gateway: string, boot: string, underlay: string, taken_at: int}> $rows
 * @param string $liveBoot     the live kern.boot_id as hex, '' when unreadable
 * @param ?string $previousBoot boot.json's boot id when it names another boot than the live one
 * @param array<string, bool> $forceDown gateway uuid => force_down
 * @return array{owned: list<string>, pruned: array<string, string>} sorted owned uuids; uuid => 'released'|'foreign'
 */
function wgct_resolve_holds(array $rows, string $liveBoot, ?string $previousBoot, array $forceDown): array {
    $owned = [];
    $pruned = [];
    foreach ($rows as $row) {
        $uuid = $row['gateway'];
        $boot = $row['boot'];
        $isLive = $liveBoot !== '' && $boot === $liveBoot;
        $isPrevious = $liveBoot !== '' && $previousBoot !== null && $previousBoot !== ''
            && $previousBoot !== $liveBoot && $boot === $previousBoot;
        if (!$isLive && !$isPrevious) {
            $pruned[$uuid] = 'foreign';
        } elseif (empty($forceDown[$uuid])) {
            $pruned[$uuid] = 'released';
        } else {
            $owned[] = $uuid;
        }
    }
    sort($owned);
    return ['owned' => $owned, 'pruned' => $pruned];
}

/**
 * One hold record per gateway (the engine model's ArrayField has no uniqueness), so no gateway is ever both owned
 * and pruned: of a gateway's rows the first with the live boot is kept, else the first with the previous boot, else
 * the first. Pure.
 *
 * @param list<array{gateway: string, boot: string, underlay: string, taken_at: int}> $rows
 * @return array{rows: list<array>, duplicates: list<string>} the kept rows in their first gateway order; the uuid
 *         of each row dropped
 */
function wgct_dedupe_hold_rows(array $rows, string $liveBoot, ?string $previousBoot): array {
    $rank = function (array $row) use ($liveBoot, $previousBoot): int {
        if ($liveBoot !== '' && $row['boot'] === $liveBoot) {
            return 2;
        }
        return $previousBoot !== null && $previousBoot !== '' && $row['boot'] === $previousBoot ? 1 : 0;
    };
    $kept = [];
    $duplicates = [];
    foreach ($rows as $row) {
        $uuid = $row['gateway'];
        if (!isset($kept[$uuid])) {
            $kept[$uuid] = $row;
        } else {
            $duplicates[] = $uuid;
            if ($rank($row) > $rank($kept[$uuid])) {
                $kept[$uuid] = $row;
            }
        }
    }
    return ['rows' => array_values($kept), 'duplicates' => $duplicates];
}

/**
 * The hold records a commit writes for the planner's held set, or null when config already holds exactly these
 * (in any order). Every gateway held keeps its owned row, re-stamped with the live boot (when it was taken and on
 * which WAN kept), or gets a new row taken now on its tunnel's WAN; every other row goes: released by the planner,
 * released by hand, foreign, or a second row for one gateway. With no live boot id nothing is written, not even
 * a prune (ruling R17). Pure.
 *
 * @param array               $config    wgct_collect_config() (gateways, underlays, holds_rows, previous_boot)
 * @param array<string, true> $heldNames the planner's held set
 * @param string              $liveBoot  the live kern.boot_id
 * @param int                 $now       the time a new hold is taken
 * @return list<array{gateway: string, boot: string, underlay: string, taken_at: int}>|null sorted by gateway
 */
function wgct_hold_rows_next(array $config, array $heldNames, string $liveBoot, int $now): ?array {
    if ($liveBoot === '') {
        return null;
    }
    $rows = wgct_dedupe_hold_rows($config['holds_rows'], $liveBoot, $config['previous_boot'])['rows'];
    $forceDown = [];
    foreach ($config['gateways'] as $g) {
        $forceDown[$g['uuid']] = $g['force_down'];
    }
    $owned = array_flip(wgct_resolve_holds($rows, $liveBoot, $config['previous_boot'], $forceDown)['owned']);
    /* only an owned row carries over; a hold taken on a gateway with a pruned row is a new hold */
    $prior = [];
    foreach ($rows as $row) {
        if (isset($owned[$row['gateway']])) {
            $prior[$row['gateway']] = $row;
        }
    }
    $next = [];
    foreach (array_keys($heldNames) as $name) {
        $uuid = $config['gateways'][$name]['uuid'] ?? null;
        if ($uuid === null) {
            continue;
        }
        $underlay = (string)($config['underlays'][$name] ?? '');
        $next[] = [
            'gateway' => $uuid,
            'boot' => $liveBoot,
            'underlay' => $prior[$uuid]['underlay'] ?? (wgct_valid_gateway_name($underlay) ? $underlay : ''),
            'taken_at' => $prior[$uuid]['taken_at'] ?? $now,
        ];
    }
    $byGateway = fn (array $a, array $b): int => [$a['gateway'], $a['boot']] <=> [$b['gateway'], $b['boot']];
    usort($next, $byGateway);
    $stored = $config['holds_rows'];
    usort($stored, $byGateway);
    return $next === $stored ? null : $next;
}

/**
 * The log line of each hold record a commit pruned, in the spec's wording (3.5). Pure.
 *
 * @param array $config wgct_collect_config() (foreign, duplicates) made under the commit's lock
 * @return list<string>
 */
function wgct_hold_prune_lines(array $config): array {
    $lines = [];
    foreach ($config['foreign'] as $name => $reason) {
        $lines[] = $reason === 'released'
            ? "{$name}: released elsewhere; forgotten"
            : "hold record for {$name} from another boot or box; not ours, left alone";
    }
    foreach ($config['duplicates'] as $name) {
        $lines[] = "{$name}: a second hold record for the same gateway; forgotten";
    }
    return $lines;
}

/**
 * Write the hold records for the planner's held set into the engine model when they differ from config. Call
 * only inside wgct_locked_commit(), with $config from a collection made under that lock. With no live boot id
 * nothing is written (ruling R17).
 *
 * @param array  $heldNames name => true
 * @param array  $config    wgct_collect_config() made under the lock
 * @param string $liveBoot  the live kern.boot_id
 * @return bool whether the model was serialized (the caller must save)
 */
function wgct_commit_held(array $heldNames, array $config, string $liveBoot): bool {
    $rows = wgct_hold_rows_next($config, $heldNames, $liveBoot, time());
    if ($rows === null) {
        return false;
    }
    $engine = new OPNsense\WGClientTunnels\Engine();
    $engine->setHolds($rows);
    $engine->serializeToConfig();
    return true;
}

/**
 * Everything the decisions read from the running system. Runs
 * gateway_status.php as a subprocess. Config::lock() only holds a shared lock
 * after its reload, so a plain reader would still succeed while this process
 * holds it -- the hazard is starting or waiting on anything that may itself
 * write config: it would wait for exclusive access while this process waits
 * for it to finish. So this must never be called while holding
 * Config::lock(); simplest is to call it only outside lock()/unlock().
 *
 * @return array see the file header
 */
function wgct_collect_live() {
    $loss = [];
    $age = [];
    foreach (glob('/var/run/dpinger_*.sock') ?: [] as $sock) {
        $name = substr(basename($sock, '.sock'), strlen('dpinger_'));
        $loss[$name] = wgct_read_loss($name);
        $age[$name] = wgct_socket_age($sock);
    }
    return ['status' => wgct_gateway_status(), 'loss' => $loss, 'sock_age' => $age];
}

/**
 * Decide every force_down change for one tick. Pure: reads only its arguments.
 *
 * @param array    $config         wgct_collect_config()
 * @param array    $live           wgct_collect_live()
 * @param array    $held           name => true, tunnels pass 1 holds down
 * @param int|null $settleOverride --settle=N
 * @return array ['changes' => name => bool force_down, 'held' => name => true,
 *                'held_changed' => bool, 'report' => string[], 'log' => string[]]
 */
function wgct_plan(array $config, array $live, array $held, $settleOverride) {
    $gws = $config['gateways'];
    $forced = [];               // force_down as it stands after the decisions so far
    foreach ($gws as $name => $row) {
        $forced[$name] = $row['force_down'];
    }
    $changes = [];
    $report = [];
    $log = [];
    $heldChanged = false;

    /* ---- pass 1: underlay ---- */
    if (!empty($config['boot_unreadable'])) {
        /* Without the live boot id a new hold could not be recorded and no record can be shown to be ours
         * (ruling R17): neither take nor release a hold this tick. The tick logs this once per state. */
        $report[] = 'underlay: kern.boot_id unreadable, pass skipped';
    } elseif ($live['status'] === null) {
        /* Without status every WAN would read absent and every tunnel would be
         * forced down on a transient read failure. Skip the pass this tick. */
        $log[] = 'gateway status unavailable; underlay pass skipped this tick';
        $report[] = 'underlay: gateway status unavailable, pass skipped';
    } else {
        foreach ($config['underlays'] as $tunnelName => $wanName) {
            $tunnel = $gws[$tunnelName] ?? null;
            if ($tunnel === null || $tunnel['disabled']) {
                continue;
            }
            $wanGw = $gws[$wanName] ?? null;
            /* a gateway with monitoring disabled has no dpinger socket and core reports it
             * 'none' or 'force_down', never down: its reading is settled as it stands
             * (spec 2026-09-27 section 3.4) */
            [$wanSettled, $wanAge, $wanWindow] = $wanGw === null || !empty($wanGw['monitor_disable'])
                ? [true, null, 0]
                : wgct_settled($wanGw, $live['sock_age'][$wanName] ?? null, $settleOverride);
            $wan = [
                'disabled' => $wanGw === null || $wanGw['disabled'],
                'force_down' => $wanGw !== null && $wanGw['force_down'],
                'status' => $live['status'][$wanName] ?? null,
                'settled' => $wanSettled,
            ];
            $isHeld = isset($held[$tunnelName]);
            $manual = $tunnel['force_down'] && !$isHeld;
            $down = wgct_decide_underlay($wan, $isHeld);

            $wanDesc = $wan['disabled'] ? 'disabled' : ($wan['force_down'] ? 'force_down'
                : ($wan['status'] ?? 'absent') . ($wanSettled ? '' : " settling {$wanAge}/{$wanWindow}s"));
            $report[] = sprintf(
                'underlay %-18s on %-12s WAN %-24s -> %s',
                $tunnelName,
                $wanName,
                $wanDesc,
                $manual ? 'manual force_down, left alone' : ($down ? 'held down' : 'up')
            );
            if ($manual) {
                continue;
            }
            if ($down && !$isHeld) {
                $held[$tunnelName] = true;
                $heldChanged = true;
                $forced[$tunnelName] = true;
                $changes[$tunnelName] = true;
                $log[] = "{$tunnelName}: force_down (underlay {$wanName} {$wanDesc})";
            } elseif (!$down && $isHeld) {
                unset($held[$tunnelName]);
                $heldChanged = true;
                $forced[$tunnelName] = false;
                $changes[$tunnelName] = false;
                $log[] = "{$tunnelName}: online (underlay {$wanName} {$wanDesc})";
            }
        }
        /* forget tunnels that no longer exist */
        foreach (array_keys($held) as $name) {
            if (!isset($gws[$name])) {
                unset($held[$name]);
                $heldChanged = true;
            }
        }
    }

    /* ---- pass 2: IPv6 follows its own IPv4 tunnel ---- */
    foreach ($config['pairs'] as $ipv4Name => $ipv6Name) {
        $ipv4 = $gws[$ipv4Name] ?? null;
        $gw6 = $gws[$ipv6Name] ?? null;
        /*
         * A disabled gateway is already out of the default-gateway election and out
         * of every gateway group, so force_down would not change its effect, and
         * writing it would reconfigure routing for nothing. Leave it alone.
         */
        if ($ipv4 === null || $gw6 === null || $gw6['disabled']) {
            continue;
        }
        [$lossLow, $lossHigh] = wgct_watermarks($ipv4);
        [$settled, $sockAge, $settleWindow] = wgct_settled(
            $ipv4,
            $live['sock_age'][$ipv4Name] ?? null,
            $settleOverride
        );
        $lossVal = $live['loss'][$ipv4Name] ?? null;
        $currentDown = $forced[$ipv6Name];
        $ipv4Forced = $forced[$ipv4Name];     // includes pass 1's decisions
        $down = $ipv4Forced || wgct_decide_down($lossVal, $lossHigh, $lossLow, $currentDown, $settled);
        $lossStr = $lossVal === null ? 'no-data' : "{$lossVal}% loss";
        $why = $ipv4Forced ? 'IPv4 force_down' : ($down ? 'IPv4 unhealthy' : 'IPv4 healthy');

        $report[] = sprintf(
            'ipv6     %-22s force_down %s -> %s  (%s; %s %s%s)',
            $ipv6Name,
            $currentDown ? '1' : '0',
            $down ? '1' : '0',
            $why,
            $ipv4Name,
            $lossStr,
            $settled ? '' : "; settling {$sockAge}/{$settleWindow}s"
        );
        if ($down !== $currentDown) {
            $forced[$ipv6Name] = $down;
            $changes[$ipv6Name] = $down;
            $log[] = sprintf(
                '%s: %s (%s; %s %s; watermarks %d/%d%s)',
                $ipv6Name,
                $down ? 'force_down' : 'online',
                $why,
                $ipv4Name,
                $lossStr,
                $lossLow,
                $lossHigh,
                $settled ? '' : "; dpinger settling {$sockAge}/{$settleWindow}s"
            );
        }
    }

    return [
        'changes' => $changes,
        'held' => $held,
        'held_changed' => $heldChanged,
        'report' => $report,
        'log' => $log,
    ];
}

/**
 * Write planned force_down values into a Gateways model.
 *
 * @param \OPNsense\Routing\Gateways $mdl     freshly built after Config::lock()
 * @param array                      $changes name => bool force_down
 */
function wgct_apply_changes($mdl, array $changes) {
    foreach ($mdl->gateway_item->iterateItems() as $gw) {
        $name = (string)$gw->name;
        if (array_key_exists($name, $changes)) {
            $gw->force_down = $changes[$name] ? '1' : '0';
        }
    }
}

/**
 * The only way the mirror writes config. Config::lock() re-reads config.xml, so
 * $mutate builds its models from what is on disk now, never from a snapshot
 * loaded before a concurrent GUI save. lock() only holds a shared lock after
 * that reload, so a plain reader would still succeed inside $mutate -- the
 * real hazard is a writer (a configd action, another script's lock()/save(),
 * plugins_configure): it would wait for exclusive access while this process
 * waits for it to finish. Never start or wait on anything that may write
 * config inside $mutate; simplest is to start or wait on nothing at all.
 *
 * @param callable $mutate builds models, changes and serializes them; returns an
 *                         array whose 'save' key says whether to save
 * @param string|null $description the config-history text of the save (null: core's default)
 * @return array whatever $mutate returned
 */
function wgct_locked_commit(callable $mutate, ?string $description = null) {
    $cfg = Config::getInstance();
    $cfg->lock();
    try {
        $result = $mutate();
        if (!empty($result['save'])) {
            $cfg->save($description !== null ? ['description' => $description] : null);
        }
        return $result;
    } finally {
        $cfg->unlock();
    }
}

/**
 * Run the decision self-tests. No config, no sockets, no processes.
 *
 * @return int exit code, 0 when every case passes
 */
function wgct_selftest() {
    $fail = 0;
    $total = 0;

    /* ---- wgct_decide_down / wgct_decide_underlay ---- */
    $cases = [
        // description, lossVal, high, low, currentDown, settled, expectedDown
        ['no data => down',              null, 20,  10,  false, true,  true],
        ['no data => down (was up)',     null, 20,  10,  true,  true,  true],
        ['0% => up',                     0,    20,  10,  false, true,  false],
        ['at low (10) => up',            10,   20,  10,  true,  true,  false],
        ['below low, was down => up',    5,    20,  10,  true,  true,  false],
        ['in band (15), was up => up',   15,   20,  10,  false, true,  false],
        ['in band (15), was down => dn', 15,   20,  10,  true,  true,  true],
        ['at high (20) => down',         20,   20,  10,  false, true,  true],
        ['above high (30) => down',      30,   20,  10,  false, true,  true],
        ['no threshold: 50% => up',      50,   100, 100, false, true,  false],
        ['no threshold: 100% => down',   100,  100, 100, false, true,  true],
        // Settle guard: a fresh dpinger's reading decides nothing, either way (it reads
        // 0% or 100% before it has samples); the previous decision stands.
        ['unsettled 0%, was down => dn',      0,    20,  10,  true,  false, true],
        ['unsettled 0%, was up => up',        0,    20,  10,  false, false, false],
        ['unsettled 100%, was up => up',      100,  20,  10,  false, false, false],
        ['unsettled 100%, was down => dn',    100,  20,  10,  true,  false, true],
        ['unsettled no data, was up => up',   null, 20,  10,  false, false, false],
        ['unsettled no data, was down => dn', null, 20,  10,  true,  false, true],
        ['unsettled in band => hold',         15,   20,  10,  true,  false, true],
    ];
    $up = ['disabled' => false, 'force_down' => false, 'status' => 'none', 'settled' => true];
    $underlayCases = [
        // description, wan, held, expectedDown
        ['WAN up, settled => up',              $up, false, false],
        ['WAN up, settled, was held => up',    $up, true,  false],
        ['WAN delay only => up',               ['status' => 'delay'] + $up, false, false],
        ['WAN disabled => down',               ['disabled' => true] + $up, false, true],
        ['WAN force_down => down',             ['force_down' => true] + $up, false, true],
        ['WAN absent from status => down',     ['status' => null] + $up, false, true],
        ['WAN down => down',                   ['status' => 'down'] + $up, false, true],
        ['WAN loss => down',                   ['status' => 'loss'] + $up, false, true],
        ['WAN delay+loss => down',             ['status' => 'delay+loss'] + $up, false, true],
        ['WAN up, unsettled, held => hold',    ['settled' => false] + $up, true,  true],
        ['WAN up, unsettled, not held => up',  ['settled' => false] + $up, false, false],
        // a fresh dpinger reads down before it has samples: the previous decision stands
        ['WAN down, unsettled, not held => up',        ['status' => 'down', 'settled' => false] + $up, false, false],
        ['WAN down, unsettled, held => hold',          ['status' => 'down', 'settled' => false] + $up, true,  true],
        ['WAN loss, unsettled, not held => up',        ['status' => 'loss', 'settled' => false] + $up, false, false],
        ['WAN absent, unsettled, not held => up',      ['status' => null, 'settled' => false] + $up, false, false],
        // configuration is not a reading: it acts at once, settled or not
        ['WAN disabled, unsettled => down',            ['disabled' => true, 'settled' => false] + $up, false, true],
        ['WAN force_down, unsettled => down',          ['force_down' => true, 'settled' => false] + $up, false, true],
        ['WAN status force_down, unsettled => down',   ['status' => 'force_down', 'settled' => false] + $up, false, true],
    ];
    foreach ($cases as $c) {
        [$desc, $lv, $hi, $lo, $cur, $settled, $exp] = $c;
        $got = wgct_decide_down($lv, $hi, $lo, $cur, $settled);
        $fail += $got === $exp ? 0 : 1;
        $total++;
        printf("[%s] ipv6: %s\n", $got === $exp ? 'PASS' : 'FAIL', $desc);
    }
    foreach ($underlayCases as $c) {
        [$desc, $wan, $held, $exp] = $c;
        $got = wgct_decide_underlay($wan, $held);
        $fail += $got === $exp ? 0 : 1;
        $total++;
        printf("[%s] underlay: %s\n", $got === $exp ? 'PASS' : 'FAIL', $desc);
    }

    /* ---- wgct_plan over synthetic snapshots ---- */
    $row = function (array $o = []) {
        return $o + [
            'uuid' => 'u', 'ipprotocol' => 'inet', 'interface' => 'optX',
            'disabled' => false, 'force_down' => false,
            'losshigh' => '20', 'losslow' => '10', 'time_period' => '60',
        ];
    };
    $config = function (array $gwOverrides = []) use ($row) {
        $gws = [
            'WAN_A' => $row(),
            'tun_a' => $row(),
            'tun_a-ipv6' => $row(['ipprotocol' => 'inet6']),
        ];
        foreach ($gwOverrides as $name => $o) {
            $gws[$name] = $row($o + $gws[$name]);
        }
        return [
            'enabled' => true,
            'gateways' => $gws,
            'underlays' => ['tun_a' => 'WAN_A'],
            'pairs' => ['tun_a' => 'tun_a-ipv6'],
        ];
    };
    $live = function (array $o = []) {
        return $o + [
            'status' => ['WAN_A' => 'none', 'tun_a' => 'none'],
            'loss' => ['WAN_A' => 0, 'tun_a' => 0],
            'sock_age' => ['WAN_A' => 600, 'tun_a' => 600],
        ];
    };
    $planCases = [
        // description, config, live, held (names), expected changes, expected held (names)
        ['healthy => no change',
            $config(), $live(), [], [], []],
        ['WAN down => tunnel held, IPv6 follows',
            $config(), $live(['status' => ['WAN_A' => 'down', 'tun_a' => 'none']]), [],
            ['tun_a' => true, 'tun_a-ipv6' => true], ['tun_a']],
        ['WAN back, settled => release tunnel and IPv6',
            $config(['tun_a' => ['force_down' => true], 'tun_a-ipv6' => ['force_down' => true]]),
            $live(), ['tun_a'],
            ['tun_a' => false, 'tun_a-ipv6' => false], []],
        ['WAN back, unsettled => keep holding',
            $config(['tun_a' => ['force_down' => true], 'tun_a-ipv6' => ['force_down' => true]]),
            $live(['sock_age' => ['WAN_A' => 5, 'tun_a' => 600]]), ['tun_a'],
            [], ['tun_a']],
        ['manual force_down on tunnel => left alone, IPv6 follows it',
            $config(['tun_a' => ['force_down' => true]]),
            $live(['status' => ['WAN_A' => 'down', 'tun_a' => 'none']]), [],
            ['tun_a-ipv6' => true], []],
        ['status unavailable => pass 1 skipped, pass 2 still runs',
            $config(), $live(['status' => null, 'loss' => ['tun_a' => 30]]), ['tun_a'],
            ['tun_a-ipv6' => true], ['tun_a']],
        ['held gateway that no longer exists => forgotten',
            $config(), $live(), ['gone'], [], []],
        ['disabled IPv6 gateway => untouched',
            $config(['tun_a-ipv6' => ['disabled' => true]]),
            $live(['loss' => ['tun_a' => 100]]), [], [], []],
        ['IPv4 loss in band, IPv6 down => hold',
            $config(['tun_a-ipv6' => ['force_down' => true]]),
            $live(['loss' => ['tun_a' => 15]]), [], [], []],
        ['no dpinger data for IPv4, settled socket => IPv6 down',
            $config(), $live(['loss' => []]), [],
            ['tun_a-ipv6' => true], []],
        ['no dpinger socket for IPv4 (restarting) => IPv6 unchanged',
            $config(), $live(['loss' => [], 'sock_age' => ['WAN_A' => 600]]), [],
            [], []],
        /* 2026-10-06 14:28:15 on the firewall: a gateway Apply restarted every dpinger and the
         * health mirror forced a healthy WAN's tunnels down on the fresh monitor's first reading */
        ['every dpinger just restarted, WAN reads down => nothing changes',
            $config(), $live(['status' => ['WAN_A' => 'down', 'tun_a' => 'down'], 'loss' => ['WAN_A' => 100, 'tun_a' => 100],
                              'sock_age' => ['WAN_A' => 0, 'tun_a' => 0]]), [],
            [], []],
        ['every dpinger just restarted, tunnel held, WAN reads up => still held',
            $config(['tun_a' => ['force_down' => true], 'tun_a-ipv6' => ['force_down' => true]]),
            $live(['sock_age' => ['WAN_A' => 0, 'tun_a' => 0]]), ['tun_a'],
            [], ['tun_a']],
        ['WAN forced down in config while every dpinger restarts => tunnel held at once, IPv6 follows',
            $config(['WAN_A' => ['force_down' => true]]),
            $live(['status' => ['WAN_A' => 'force_down', 'tun_a' => 'down'], 'sock_age' => ['WAN_A' => 0, 'tun_a' => 0]]), [],
            ['tun_a' => true, 'tun_a-ipv6' => true], ['tun_a']],
        ['WAN still down once settled => tunnel held',
            $config(), $live(['status' => ['WAN_A' => 'down', 'tun_a' => 'none'], 'sock_age' => ['WAN_A' => 60, 'tun_a' => 600]]), [],
            ['tun_a' => true, 'tun_a-ipv6' => true], ['tun_a']],
        ['unmonitored WAN back up (no dpinger socket) => release tunnel and IPv6',
            $config(['WAN_A' => ['monitor_disable' => true], 'tun_a' => ['force_down' => true], 'tun_a-ipv6' => ['force_down' => true]]),
            $live(['sock_age' => ['tun_a' => 600]]), ['tun_a'],
            ['tun_a' => false, 'tun_a-ipv6' => false], []],
        ['unmonitored WAN absent from status => keep holding',
            $config(['WAN_A' => ['monitor_disable' => true], 'tun_a' => ['force_down' => true], 'tun_a-ipv6' => ['force_down' => true]]),
            $live(['status' => ['tun_a' => 'none'], 'sock_age' => ['tun_a' => 600]]), ['tun_a'],
            [], ['tun_a']],
        ['monitored WAN with no socket yet => keep holding (unchanged)',
            $config(['tun_a' => ['force_down' => true], 'tun_a-ipv6' => ['force_down' => true]]),
            $live(['sock_age' => ['tun_a' => 600]]), ['tun_a'],
            [], ['tun_a']],
        ['monitored IPv6 gateway reading 100% loss while its IPv4 tunnel is healthy => pass 2 leaves it (core owns its own status)',
            $config(['tun_a-ipv6' => ['monitor_disable' => false]]),
            $live(['status' => ['WAN_A' => 'none', 'tun_a' => 'none', 'tun_a-ipv6' => 'down'],
                   'loss' => ['WAN_A' => 0, 'tun_a' => 0, 'tun_a-ipv6' => 100],
                   'sock_age' => ['WAN_A' => 600, 'tun_a' => 600, 'tun_a-ipv6' => 600]]), [],
            [], []],
    ];
    foreach ($planCases as $c) {
        [$desc, $cfg, $lv, $heldNames, $expChanges, $expHeld] = $c;
        $plan = wgct_plan($cfg, $lv, array_fill_keys($heldNames, true), null);
        $gotChanges = $plan['changes'];
        ksort($gotChanges);
        ksort($expChanges);
        $gotHeld = array_keys($plan['held']);
        sort($gotHeld);
        sort($expHeld);
        $ok = $gotChanges === $expChanges && $gotHeld === $expHeld;
        $fail += $ok ? 0 : 1;
        $total++;
        printf("[%s] plan: %s\n", $ok ? 'PASS' : 'FAIL', $desc);
        if (!$ok) {
            printf("       changes %s held %s\n", json_encode($gotChanges), json_encode($gotHeld));
        }
    }
    $unavailable = wgct_plan($config(), $live(['status' => null]), [], null);
    $ok = in_array('gateway status unavailable; underlay pass skipped this tick', $unavailable['log'], true)
        && in_array('underlay: gateway status unavailable, pass skipped', $unavailable['report'], true);
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] plan: status unavailable is logged and reported\n", $ok ? 'PASS' : 'FAIL');

    $rows = [
        'WAN_A' => ['force_down' => false], 'WAN_B' => ['force_down' => false],
        'tun_a' => ['force_down' => true], 'tun_b' => ['force_down' => false],
    ];
    $ok = wgct_mirror_replay_set(['tun_a' => true], ['WAN_A' => 'none', 'WAN_B' => 'none', 'tun_a' => 'none'],
            ['WAN_A' => 'down', 'WAN_B' => 'none', 'tun_a' => 'force_down'], $rows)
        === ['WAN_A' => false, 'tun_a' => true];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] replay: a gateway whose status changed while the mirror held the lock is replayed with its own changes\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgct_mirror_replay_set(['tun_a' => true], ['WAN_A' => 'none', 'tun_a' => 'none'],
            ['WAN_A' => 'none', 'tun_a' => 'force_down'], $rows) === ['tun_a' => true];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] replay: with nothing else changed, only the mirror's own changes are replayed\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgct_mirror_replay_set(['tun_b' => false, 'tun_a' => true], null, ['WAN_A' => 'down'], $rows)
        === ['tun_a' => true, 'tun_b' => false];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] replay: without a before-status the mirror's own changes are still replayed, as written\n", $ok ? 'PASS' : 'FAIL');

    $skipCases = [
        ['not skipped, no marker: nothing logged, no marker', false, false, null, 'keep'],
        ['skipped, no marker: the skip is logged and the marker written', true, false, 'skip', 'write'],
        ['skipped, marker present: still skipped, nothing logged', true, true, null, 'keep'],
        ['not skipped, marker present: resumed is logged and the marker removed', false, true, 'resume', 'remove'],
    ];
    foreach ($skipCases as [$label, $skipped, $marker, $log, $action]) {
        $ok = wgct_skip_log_plan($skipped, $marker) === ['log' => $log, 'marker' => $action];
        $fail += $ok ? 0 : 1;
        $total++;
        printf("[%s] skip log plan: %s\n", $ok ? 'PASS' : 'FAIL', $label);
    }

    /* ---- wgct_resolve_holds: who owns a hold record (spec 3.5) ---- */
    $live1 = 'a1b2c3d4e5f60718';
    $prev1 = '0123456789abcdef';
    $other = 'fedcba9876543210';
    $uA = '11111111-1111-4111-8111-111111111111';
    $uB = '22222222-2222-4222-8222-222222222222';
    $uC = '33333333-3333-4333-8333-333333333333';
    $hold = function (string $uuid, string $boot) {
        return ['gateway' => $uuid, 'boot' => $boot, 'underlay' => 'WAN_A', 'taken_at' => 1760000000];
    };
    $holdCases = [
        // description, rows, live, previous, force_down, expected
        ['(a) live boot, force_down=1 => owned',
            [$hold($uA, $live1)], $live1, null, [$uA => true], ['owned' => [$uA], 'pruned' => []]],
        ['(b) live boot, force_down=0 => pruned as released by hand',
            [$hold($uA, $live1)], $live1, null, [$uA => false], ['owned' => [], 'pruned' => [$uA => 'released']]],
        ['(c) previous boot at the first tick after a reboot, force_down=1 => owned',
            [$hold($uA, $prev1)], $live1, $prev1, [$uA => true], ['owned' => [$uA], 'pruned' => []]],
        ['(c2) previous boot, force_down=0 => pruned as released by hand',
            [$hold($uA, $prev1)], $live1, $prev1, [$uA => false], ['owned' => [], 'pruned' => [$uA => 'released']]],
        ['(d) the same row at a later tick (boot.json already live) => foreign',
            [$hold($uA, $prev1)], $live1, null, [$uA => true], ['owned' => [], 'pruned' => [$uA => 'foreign']]],
        ['(e) any other boot id => foreign, whatever force_down',
            [$hold($uA, $other), $hold($uB, $other)], $live1, $prev1, [$uA => true, $uB => false],
            ['owned' => [], 'pruned' => [$uA => 'foreign', $uB => 'foreign']]],
        ['(g) boot.json unreadable (no previous boot) => every non-live row is foreign',
            [$hold($uA, $prev1), $hold($uB, $live1), $hold($uC, $other)], $live1, null,
            [$uA => true, $uB => true, $uC => true],
            ['owned' => [$uB], 'pruned' => [$uA => 'foreign', $uC => 'foreign']]],
        ['(m3) the live boot id unreadable => nothing owned, every row foreign',
            [$hold($uA, $prev1), $hold($uB, $live1)], '', $prev1, [$uA => true, $uB => true],
            ['owned' => [], 'pruned' => [$uA => 'foreign', $uB => 'foreign']]],
        ['previous boot equal to the live one is not a second chance',
            [$hold($uA, $other)], $live1, $live1, [$uA => true], ['owned' => [], 'pruned' => [$uA => 'foreign']]],
        ['owned uuids come back sorted; mixed rows each take their own row of the table',
            [$hold($uC, $live1), $hold($uA, $prev1), $hold($uB, $live1)], $live1, $prev1,
            [$uA => true, $uB => false, $uC => true],
            ['owned' => [$uA, $uC], 'pruned' => [$uB => 'released']]],
        ['a row whose gateway is gone (no force_down known) on the live boot => released',
            [$hold($uA, $live1)], $live1, null, [], ['owned' => [], 'pruned' => [$uA => 'released']]],
        ['no rows => nothing owned, nothing pruned',
            [], $live1, $prev1, [$uA => true], ['owned' => [], 'pruned' => []]],
    ];
    foreach ($holdCases as [$desc, $rows, $liveBoot, $prevBoot, $fd, $exp]) {
        $got = wgct_resolve_holds($rows, $liveBoot, $prevBoot, $fd);
        ksort($got['pruned']);
        ksort($exp['pruned']);
        $ok = $got === $exp;
        $fail += $ok ? 0 : 1;
        $total++;
        printf("[%s] holds: %s\n", $ok ? 'PASS' : 'FAIL', $desc);
        if (!$ok) {
            printf("       got %s\n", json_encode($got));
        }
    }

    /* (a) and (f) through the planner: only owned rows reach its held set */
    $heldCfg = $config(['tun_a' => ['uuid' => $uA, 'force_down' => true], 'tun_a-ipv6' => ['force_down' => true]]);
    $owned = wgct_resolve_holds([$hold($uA, $live1)], $live1, null, [$uA => true])['owned'];
    $heldNames = [];
    foreach ($heldCfg['gateways'] as $name => $g) {
        if (in_array($g['uuid'], $owned, true)) {
            $heldNames[$name] = true;
        }
    }
    $plan = wgct_plan($heldCfg, $live(), $heldNames, null);
    $ok = $plan['changes'] === ['tun_a' => false, 'tun_a-ipv6' => false] && $plan['held'] === [];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] holds: (a) an owned row is released when the WAN is up\n", $ok ? 'PASS' : 'FAIL');
    $plan = wgct_plan($heldCfg, $live(), [], null);
    $ok = $plan['changes'] === [] && $plan['held'] === [];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] holds: (f) force_down=1 with no row is manual and untouched\n", $ok ? 'PASS' : 'FAIL');

    /* ---- Engine::parseBootId: kern.boot_id as sysctl -x -n prints it ---- */
    $bootCases = [
        ['sysctl -x output => the hex after Dump:0x',
            "Format: Length:16 Dump:0xa1b2c3d4e5f60718293a4b5c6d7e8f90\n", 'a1b2c3d4e5f60718293a4b5c6d7e8f90'],
        ['leading zeros are kept',
            "Format: Length:16 Dump:0x00ab03d4e5f60718293a4b5c6d7e8f90\n", '00ab03d4e5f60718293a4b5c6d7e8f90'],
        ['upper-case dump => lower case',
            "Format: Length:16 Dump:0xA1B2C3D4E5F60718293A4B5C6D7E8F90\n", 'a1b2c3d4e5f60718293a4b5c6d7e8f90'],
        ['garbage => empty', "no such oid\n", ''],
        ['empty output => empty', '', ''],
        ['0x with no digits => empty', "Format: Length:0 Dump:0x\n", ''],
        ['non-hex after 0x => empty', "Dump:0xzz\n", ''],
        ['64 hex digits, the most a hold record takes => kept',
            'Format: Length:32 Dump:0x' . str_repeat('ab', 32) . "\n", str_repeat('ab', 32)],
        ['65 hex digits, more than a hold record takes => empty',
            'Format: Length:33 Dump:0x' . str_repeat('ab', 32) . "c\n", ''],
    ];
    foreach ($bootCases as [$desc, $out, $exp]) {
        $got = OPNsense\WGClientTunnels\Engine::parseBootId($out);
        $ok = $got === $exp;
        $fail += $ok ? 0 : 1;
        $total++;
        printf("[%s] boot id: %s\n", $ok ? 'PASS' : 'FAIL', $desc);
    }

    /* ---- boot.json: the boot the mirror last ran under ---- */
    $recordCases = [
        ['a written record reads back as its boot id', wgct_boot_record_json($live1, 1760000000), $live1],
        ['absent => no boot', null, null],
        ['truncated JSON => no boot', '{"boot_id":"' . $live1, null],
        ['a boot id that is not lower-case hex => no boot', '{"boot_id":"A1B2","at":1760000000}', null],
        ['a boot id of 65 hex digits => no boot', '{"boot_id":"' . str_repeat('a', 65) . '","at":1760000000}', null],
        ['an empty boot id => no boot', '{"boot_id":"","at":1760000000}', null],
        ['no time => no boot', '{"boot_id":"' . $live1 . '"}', null],
        ['a key more => no boot', '{"boot_id":"' . $live1 . '","at":1760000000,"x":1}', null],
        ['an array, not an object => no boot', '["' . $live1 . '",1760000000]', null],
    ];
    foreach ($recordCases as [$desc, $json, $exp]) {
        $ok = wgct_parse_boot_record($json) === $exp;
        $fail += $ok ? 0 : 1;
        $total++;
        printf("[%s] boot record: %s\n", $ok ? 'PASS' : 'FAIL', $desc);
    }
    $ok = wgct_boot_record_json($live1, 1760000000) === '{"boot_id":"' . $live1 . '","at":1760000000}';
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] boot record: written as {\"boot_id\", \"at\"}\n", $ok ? 'PASS' : 'FAIL');

    /* ---- duplicate rows for one gateway: one row is kept, so a uuid is never both owned and pruned ---- */
    $dupCases = [
        ['a foreign, a live and a previous-boot row => the live one is kept, the other two go',
            [$hold($uA, $other), $hold($uA, $live1), $hold($uA, $prev1)], $live1, $prev1,
            [$hold($uA, $live1)], [$uA, $uA], ['owned' => [$uA], 'pruned' => []]],
        ['a foreign and a previous-boot row => the previous-boot one is kept',
            [$hold($uA, $other), $hold($uA, $prev1)], $live1, $prev1,
            [$hold($uA, $prev1)], [$uA], ['owned' => [$uA], 'pruned' => []]],
        ['two foreign rows => the first is kept and pruned once',
            [$hold($uA, $other), $hold($uA, $prev1)], $live1, null,
            [$hold($uA, $other)], [$uA], ['owned' => [], 'pruned' => [$uA => 'foreign']]],
        ['rows of different gateways are no duplicates',
            [$hold($uA, $live1), $hold($uB, $other)], $live1, null,
            [$hold($uA, $live1), $hold($uB, $other)], [], ['owned' => [$uA], 'pruned' => [$uB => 'foreign']]],
    ];
    foreach ($dupCases as [$desc, $rows, $liveBoot, $prevBoot, $expRows, $expDup, $expResolved]) {
        $d = wgct_dedupe_hold_rows($rows, $liveBoot, $prevBoot);
        $r = wgct_resolve_holds($d['rows'], $liveBoot, $prevBoot, [$uA => true, $uB => true]);
        $ok = $d['rows'] === $expRows && $d['duplicates'] === $expDup && $r === $expResolved
            && array_intersect($r['owned'], array_keys($r['pruned'])) === [];
        $fail += $ok ? 0 : 1;
        $total++;
        printf("[%s] duplicate holds: %s\n", $ok ? 'PASS' : 'FAIL', $desc);
        if (!$ok) {
            printf("       got %s\n", json_encode([$d, $r]));
        }
    }

    /* ---- wgct_hold_rows_next: the rows a commit writes ---- */
    $rowsCfg = function (array $rows, ?string $prevBoot = null) use ($row, $uA, $uB, $live1) {
        return [
            'gateways' => ['WAN_A' => $row(['uuid' => '99999999-9999-4999-8999-999999999999']),
                           'tun_a' => $row(['uuid' => $uA, 'force_down' => true]), 'tun_b' => $row(['uuid' => $uB, 'force_down' => true])],
            'underlays' => ['tun_a' => 'WAN_A', 'tun_b' => 'WAN_A'],
            'holds_rows' => $rows, 'live_boot' => $live1, 'previous_boot' => $prevBoot,
        ];
    };
    $at = 1760000000;
    $now = 1760009999;
    $stamped = fn (string $uuid, string $boot, int $taken, string $underlay = 'WAN_A'): array =>
        ['gateway' => $uuid, 'boot' => $boot, 'underlay' => $underlay, 'taken_at' => $taken];
    $nextCases = [
        ['an owned row the planner still holds => nothing to write',
            $rowsCfg([$stamped($uA, $live1, $at)]), ['tun_a' => true], $live1, null],
        ['the same rows in another order => nothing to write',
            $rowsCfg([$stamped($uB, $live1, $at), $stamped($uA, $live1, $at)]), ['tun_a' => true, 'tun_b' => true], $live1, null],
        ['a previous-boot row still held => re-stamped with the live boot, its time and WAN kept',
            $rowsCfg([$stamped($uA, $prev1, $at, 'WAN_X')], $prev1), ['tun_a' => true], $live1,
            [$stamped($uA, $live1, $at, 'WAN_X')]],
        ['a hold the planner takes => a new row, taken now, on the tunnel\'s WAN',
            $rowsCfg([]), ['tun_a' => true], $live1, [$stamped($uA, $live1, $now)]],
        ['a hold the planner released => its row goes',
            $rowsCfg([$stamped($uA, $live1, $at)]), [], $live1, []],
        ['a foreign row (never in the held set) => pruned',
            $rowsCfg([$stamped($uA, $other, $at)]), [], $live1, []],
        ['two rows for one held gateway => one row',
            $rowsCfg([$stamped($uA, $live1, $at), $stamped($uA, $other, $at)]), ['tun_a' => true], $live1, [$stamped($uA, $live1, $at)]],
        ['a hold taken on a gateway whose row was pruned => a new row, taken now',
            $rowsCfg([$stamped($uA, $other, $at, 'WAN_X')]), ['tun_a' => true], $live1, [$stamped($uA, $live1, $now)]],
        ['a held name with no gateway => no row',
            $rowsCfg([]), ['gone' => true], $live1, null],
        ['(R17) no live boot id => nothing written at all, not even a prune',
            $rowsCfg([$stamped($uA, $other, $at)]), ['tun_a' => true], '', null],
    ];
    foreach ($nextCases as [$desc, $cfg, $heldNames, $liveBoot, $exp]) {
        $got = wgct_hold_rows_next($cfg, $heldNames, $liveBoot, $now);
        $ok = $got === $exp;
        $fail += $ok ? 0 : 1;
        $total++;
        printf("[%s] hold rows: %s\n", $ok ? 'PASS' : 'FAIL', $desc);
        if (!$ok) {
            printf("       got %s\n", json_encode($got));
        }
    }

    /* ---- the pruned rows' log lines, in the spec's wording ---- */
    $ok = wgct_hold_prune_lines(['foreign' => ['tun_a' => 'released', 'tun_b' => 'foreign'], 'duplicates' => ['tun_c']]) === [
        'tun_a: released elsewhere; forgotten',
        'hold record for tun_b from another boot or box; not ours, left alone',
        'tun_c: a second hold record for the same gateway; forgotten',
    ] && wgct_hold_prune_lines(['foreign' => [], 'duplicates' => []]) === [];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] holds: one log line per pruned row, released and foreign in their own words\n", $ok ? 'PASS' : 'FAIL');

    /* ---- (R17) an unreadable live boot id: the tick neither takes nor releases a hold ---- */
    $frozen = ['boot_unreadable' => true];
    $plan = wgct_plan($frozen + $config(), $live(['status' => ['WAN_A' => 'down', 'tun_a' => 'none']]), [], null);
    $ok = $plan['changes'] === [] && $plan['held'] === [] && !$plan['held_changed']
        && in_array('underlay: kern.boot_id unreadable, pass skipped', $plan['report'], true) && $plan['log'] === [];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] holds: (R17) no boot id, WAN down => no hold taken, nothing logged by the plan\n", $ok ? 'PASS' : 'FAIL');
    $plan = wgct_plan($frozen + $config(['tun_a' => ['force_down' => true], 'tun_a-ipv6' => ['force_down' => true]]), $live(), ['tun_a' => true], null);
    $ok = $plan['changes'] === [] && $plan['held'] === ['tun_a' => true] && !$plan['held_changed'];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] holds: (R17) no boot id, WAN up => no hold released\n", $ok ? 'PASS' : 'FAIL');

    printf("%d/%d passed\n", $total - $fail, $total);
    return $fail === 0 ? 0 : 1;
}
