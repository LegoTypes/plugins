<?php

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
 * The apply half of every action:
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
/* core files the contract check reads (wgct_core_contract) */
const WGCT_CORE_ACTIONS_INTERFACE = '/usr/local/opnsense/service/conf/actions.d/actions_interface.conf';
const WGCT_CORE_ROUTING_SCRIPT = '/usr/local/etc/rc.routing_configure';
/*
 * Every core internal the plugin copies, with the texts in core's file that show core still does what the copy
 * assumes, as 26.7.7 holds them: each the line the copy relies on, exact enough that a similar line elsewhere in the
 * file cannot stand in for it. A file that cannot be read, or that lacks a text, is drift. With a section, the
 * texts are looked for only in the command line of that ini section, and a missing section or command is drift too.
 */
const WGCT_CORE_COPIES = [
    /* replay_alarm and the config-write order take routes.alarm's lock and run its command */
    'routes_alarm' => [
        'path' => WGCT_CORE_ACTIONS_INTERFACE, 'section' => 'routes.alarm',
        'texts' => [WGCT_GATEWAY_LOCK_FILE, 'rc.routing_configure alarm'],
    ],
    /*
     * Edit's and Rebind's kernel route deletes are core's /tmp/delete_route_<key>.todo hand-off, a file holding the
     * network (wgct_write_route_todos())
     */
    'route_todo' => [
        'path' => WGCT_CORE_ROUTING_SCRIPT,
        'texts' => ['glob("/tmp/delete_route_*.todo")', 'trim(file_get_contents($filename))'],
    ],
    /* the filter hook tells a filter reload from a rules listing by this frame (wgclienttunnels_in_filter_reload()) */
    'filter_frame' => ['path' => '/usr/local/etc/inc/filter.inc', 'texts' => ['function filter_configure_sync(']],
    /* the prime and wgct.sh read dpinger's socket, and wgct.sh its pid file, by path */
    'dpinger_socket' => [
        'path' => '/usr/local/etc/inc/plugins.inc.d/dpinger.inc',
        'texts' => ['"/var/run/dpinger_{$name}.sock"', '"/var/run/dpinger_{$name}.pid"'],
    ],
    /*
     * WGCT_PIN_PRIORITY's band 0 is the Rules page's first "Automatically generated rules" group, and the page files a
     * row under the band its sort_order's first digit names
     */
    'rules_band' => [
        'path' => '/usr/local/opnsense/mvc/app/views/OPNsense/Firewall/filter_rule.volt',
        'texts' => ['{ idx: 0, uuid: "auto0"', 'Number(sortOrder.charAt(0))'],
    ],
    /* the tunnel list's plain() undoes core's escaping of an array reply, which leaves quotes as they are */
    'reply_escape' => [
        'path' => '/usr/local/opnsense/mvc/app/library/OPNsense/Mvc/Response.php',
        'texts' => ['htmlspecialchars($result, ENT_NOQUOTES)'],
    ],
    /*
     * the no-default sentinels (wgct_plan_sentinel()) are one address-less gateway per family on a "Dynamic gateway
     * policy" loopback: getGateways() keeps each configured item's family there, and getDefaultGW() elects by exact
     * family. Core 26.7.8 (5b6ccdb592, core#10978) made that gateway family-less and the other family's defunct,
     * which neither sentinel survives
     */
    'sentinel_family' => [
        'path' => '/usr/local/opnsense/mvc/app/models/OPNsense/Routing/Gateways.php',
        'texts' => [
            "\$thisconf['gateway_interface'] = true;\n                        \$this->cached_gateways[\$gwkey] = \$thisconf;",
            "if (\$gateway['ipprotocol'] == \$ipproto) {",
        ],
    ],
    /* wgct_core_read_routes() reads the static routes raw, keeping the Routes model's view of them: enabled by default */
    'route_model' => [
        'path' => '/usr/local/opnsense/mvc/app/models/OPNsense/Routes/Route.xml',
        'texts' => [
            '<mount>//staticroutes</mount>', '<route type="ArrayField">', '<network type="NetworkField">', '<gateway type=',
            "<enabled type=\"BooleanField\">\n                <Default>1</Default>",
        ],
    ],
];
/*
 * The core defects a workaround of the plugin waits for, each with the texts of core's file before the fix. A
 * readable file that holds none of them may carry the fix: the note says the workaround is a backstop from then on.
 */
const WGCT_CORE_FIXES = [
    /*
     * The two 26.7.7 lines that skip inet6 far gateways: the far gateway host route skipped for inet6, and
     * system_interface_route()'s IPv4-only check, at its line start since the proposed fix (opnsense/core 060af78d31,
     * branch far_ipv6) keeps "} elseif (!is_ipaddrv4($gateway)) {". A fix that lands in another form may keep one;
     * the note says only what the file no longer holds.
     */
    'far_gw6' => [
        'path' => '/usr/local/etc/inc/system.inc',
        'unfixed' => ["if (!empty(\$gateway['fargw']) && \$gateway['ipprotocol'] != 'inet6') {", "\n    if (!is_ipaddrv4(\$gateway)) {"],
        'note' => "core's system.inc no longer holds the lines that skip inet6 far-gateway host routes (opnsense/core#10578),"
            . " so core may carry the fix: the plugin's IPv6 next-hop routes are a backstop",
    ],
];
/* ModelRelationField's private option caches, which wgct_reset_field_caches() clears by reflection */
const WGCT_RELATION_STATICS = ['internalCacheModelStruct', 'internalCacheOptionList'];
/* as long as the replay action's `flock -w 120` waits */
const WGCT_GATEWAY_LOCK_WAIT_MS = 120000;
const WGCT_TIMEOUT = '/usr/bin/timeout';
const WGCT_CONFIGCTL = '/usr/local/sbin/configctl';
/*
 * How long the package removal waits on one core configd action: the gateway lock's own bound
 * (WGCT_GATEWAY_LOCK_WAIT_MS), which every routing writer of the plugin already waits. A routes configure or an
 * alarm takes seconds; the bound only ends the wait of a removal stuck behind a configd that accepted the
 * connection and never answered, while configd itself finishes the action it started.
 */
const WGCT_REMOVAL_CONFIGD_SECONDS = 120;
const WGCT_ACTION_LOG_TAG = 'wgct-action';
/*
 * Instances whose Create or Edit saved but whose apply has not completed, each with the apply mode it still needs. Kept
 * in /var/db, not /var/run, so it survives a reboot: boot runs only `wireguard configure`, never `template reload`, so
 * a tunnel whose apply never ran still has no current wgN.conf after a reboot, and nothing else re-applies a saved NAT
 * or monitor change; either way it still needs Apply.
 */
const WGCT_APPLY_PENDING_FILE = WGCT_DB_DIR . '/apply_pending.json';
/* the longest an update of that record waits for another one: its critical section is a read and a rename */
const WGCT_APPLY_PENDING_LOCK_WAIT_MS = 10000;
/*
 * Create's apply: what core's WireGuard, assignment and
 * routes applies do, with the routes applied once BEFORE the device exists.
 * WireGuard keeps the source address of its first path, core's force-gateway
 * rules keep that state alive and keepalive 25 refreshes it forever: a first
 * handshake sent before the endpoint /32 or /128 is in place leaves by the
 * default route's WAN and stays there. The complete list is also what clears
 * apply-pending (wgct_pending_outcome()).
 */
const WGCT_CREATE_APPLY_STEPS = [
    ['template reload', ['OPNsense/Wireguard']],   // writes wgN.conf; `wireguard configure` alone never does
    ['interface routes configure', []],            // the endpoint /32 or /128 via the bound WAN, before the first handshake
    ['wireguard configure', []],                   // creates wgN; a first start configures its interface
    ['interface invoke registration', []],         // the device appears on Interfaces > Assignments
    ['!interface list assign-opts', []],           // and the 60 s cached device list is refreshed
    ['interface routes configure', []],            // gateways and dpinger on the new device; consumes route todo files
    ['filter reload', []],                         // outbound NAT and the rendered pins
];
/*
 * Remove's apply: registering after `wireguard configure` has
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
 * or /128 (and consumes the stale route's todo file); `wireguard restart` then
 * makes the tunnel handshake again on that route -- without it WireGuard keeps its
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
 * apply_mode, weakest first: each mode's steps do what every
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
 *   failed step), and an Edit moves the path, so both end with the restart.
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
 *              gateway lock; filter and none do not. Pure.
 */
function wgct_apply_mode_locks(string $mode): bool {
    return in_array($mode, ['first', 'tunnel', 'routes'], true);
}

/**
 * The mode the Apply button (`tunnel.php apply UUID` without a mode) runs for
 * a pending record: the recorded one, except that Create's first apply is
 * re-run as the tunnel apply, restart included; with nothing
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
 * What an action's apply means for the apply-pending record of its instance. A complete apply mode -- its exact step
 * list, every step OK -- is that mode, which settles a record of the same or a weaker mode (wgct_pending_settle()). A
 * Rebind, a Sentinel repair or a failed apply is null and settles nothing. A saved Remove is 'forget' whatever its
 * apply did: the instance is no longer in config, so the record could never be shown or cleared again. Pure.
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
 * stronger of that mode and one already recorded is kept, with the new time
 * and a new mark, which tells this record apart from every earlier one
 * (wgct_pending_settle()). Pure.
 *
 * @param array<string, array{at: int, mode: string, mark: int}> $all wgct_read_apply_pending()
 * @return array<string, array{at: int, mode: string, mark: int}>
 */
function wgct_pending_mark(array $all, string $uuid, string $mode, int $at, int $mark): array {
    $recorded = $all[$uuid]['mode'] ?? null;
    if ($recorded !== null && array_search($recorded, WGCT_APPLY_MODES, true) > array_search($mode, WGCT_APPLY_MODES, true)) {
        $mode = $recorded;
    }
    $all[$uuid] = ['at' => $at, 'mode' => $mode, 'mark' => $mark];
    return $all;
}

/**
 * Apply an outcome (wgct_pending_outcome()) to the record: 'forget' drops it;
 * a completed mode drops it only when the record is still the one this apply
 * began against ($seen: a change saved while the apply ran marked a new one,
 * whose own apply it did not run) and that mode is at least as strong as the
 * one recorded. Pure.
 *
 * @param array<string, array{at: int, mode: string, mark: int}> $all  wgct_read_apply_pending()
 * @param array{at: int, mode: string, mark: int}|null         $seen the record just before the apply's first step
 * @return array<string, array{at: int, mode: string, mark: int}>
 */
function wgct_pending_settle(array $all, string $uuid, string $outcome, ?array $seen): array {
    if (!isset($all[$uuid])) {
        return $all;
    }
    if ($outcome === 'forget') {
        unset($all[$uuid]);
    } elseif ($all[$uuid] === $seen
        && array_search($outcome, WGCT_APPLY_MODES, true) >= array_search($all[$uuid]['mode'], WGCT_APPLY_MODES, true)) {
        unset($all[$uuid]);
    }
    return $all;
}

/**
 * Mark apply-pending after a save without letting a failed mark read as a
 * failed save: the change is in config either way, so the failure is noted
 * in the result (errors['pending']) and the apply still runs.
 *
 * @param array    $result wgct_result() of a saved action
 * @param callable(): void $mark the mark
 * @return array $result, with errors['pending'] when the mark failed
 */
function wgct_mark_after_save(array $result, callable $mark): array {
    try {
        $mark();
    } catch (\Throwable $e) {
        $result['errors']['pending'] = 'saved, but its apply-pending record could not be written (' . $e->getMessage()
            . '); if the apply does not complete, run `tunnel.php apply ' . $result['uuid'] . '`';
    }
    return $result;
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
 * socket or a stripped 'Execute error', which reads as nothing happened even
 * though the action may still be running on the box; the reply is a message naming the timeout used and telling
 * the caller to reload and check the log instead. `errors`, when the action
 * supplied one, is flattened to a plain list (array_values()): the GUI
 * reads one shape regardless of whether the underlying
 * wgct_result() keyed it by request field or apply step. `status` is 'ok'
 * when the action's `ok` is true and 'failed' otherwise, the no-reply
 * failure included.
 *
 * @param string       $action
 * @param list<string> $params  uuids, gateway names and addresses only (configd shows argv in ps)
 * @param int          $timeout
 * @return array the action's decoded JSON result with its status, or a failure of the same shape
 */
function wgct_configd_json(string $action, array $params, int $timeout): array {
    $backend = new Backend();
    $raw = (string)($params === []
        ? $backend->configdRun($action, false, $timeout)
        : $backend->configdpRun($action, $params, false, $timeout));
    $data = json_decode($raw, true);
    if (!is_array($data)) {
        return ['status' => 'failed', 'ok' => false, 'errors' => [
            "no reply from the backend within {$timeout} s (timeout or configd error); "
            . 'the action may still be running — reload the list and check ' . WGCT_LOG_PAGE,
        ]];
    }
    if (isset($data['errors']) && is_array($data['errors'])) {
        $data['errors'] = array_values($data['errors']);
    }
    return ['status' => ($data['ok'] ?? false) === true ? 'ok' : 'failed'] + $data;
}

/**
 * The API's {dry: ...} flag. ajaxCall posts JSON, so a bool or int can arrive
 * where a form-encoded post only ever carried '0'/'1' strings: absent, '',
 * '0', 0 (int) and false all mean "run for real"; '1', 1 (int) and true all
 * mean "preview only"; anything else -- a stray float, a string like 'yes',
 * an array -- is refused rather than silently defaulting to either side, so a
 * malformed value can never fall through into a real Remove/Adopt/Sentinel.
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

/* the package removal's marker (+PRE_DEINSTALL.pre); entry.php checks the same file before any library loads */
const WGCT_REMOVING_FILE = WGCT_RUN_DIR . '/removing';

/**
 * A gateway-locked writer found the package removal's marker once it had the lock: it saved nothing.
 */
final class WgctRemovingException extends \RuntimeException
{
}

/**
 * @return bool whether the package removal's marker exists
 */
function wgct_removing(): bool {
    return is_file(WGCT_REMOVING_FILE);
}

/**
 * Core's gateway lock, for a writer that changes routing. The removal marker is checked again once the lock is
 * held: the removal writes it before its release-holds takes this lock, so a writer that was waiting here (up to
 * WGCT_GATEWAY_LOCK_WAIT_MS, longer than the removal waits for the mirror's lock) can never re-take a hold the
 * removal released, whatever the timing. Only release-holds passes $removal.
 *
 * @param bool $removal the caller is the package removal's own release-holds
 * @return \SplFileObject the gateway lock, held until LOCK_UN or the object is released
 * @throws WgctRemovingException when the removal marker exists (the lock is released again)
 * @throws \RuntimeException when it is still held elsewhere after WGCT_GATEWAY_LOCK_WAIT_MS
 */
function wgct_gateway_lock(bool $removal = false): \SplFileObject {
    $file = wgct_poll_lock(WGCT_GATEWAY_LOCK_FILE, WGCT_GATEWAY_LOCK_WAIT_MS, 200);
    if ($file === null) {
        $seconds = intdiv(WGCT_GATEWAY_LOCK_WAIT_MS, 1000);
        throw new \RuntimeException(
            WGCT_GATEWAY_LOCK_FILE . " is still held after {$seconds} s (fstat -f " . WGCT_GATEWAY_LOCK_FILE . ' names the holder); nothing was changed'
        );
    }
    if (!$removal && wgct_removing()) {
        $file->flock(LOCK_UN);
        throw new WgctRemovingException('the package is being removed; nothing was changed');
    }
    return $file;
}

/**
 * @param mixed $data json_decode() of the pending file -- a JSON boundary, hence mixed
 * @return array<string, array{at: int, mode: string, mark: int}> instance uuid => when its
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
            $out[$uuid] = ['at' => $record, 'mode' => 'first', 'mark' => 0];
        } elseif (is_array($record) && is_int($record['at'] ?? null) && in_array($record['mode'] ?? null, WGCT_APPLY_MODES, true)) {
            $mark = $record['mark'] ?? 0;
            $out[$uuid] = ['at' => $record['at'], 'mode' => (string)$record['mode'], 'mark' => is_int($mark) ? $mark : 0];
        }
    }
    return $out;
}

/**
 * @return array<string, array{at: int, mode: string, mark: int}> wgct_pending_from_json() of the file, [] when there is none
 */
function wgct_read_pending_file(string $path): array {
    $raw = wgct_read_state_file($path, WGCT_STATE_MAX_BYTES);
    return wgct_pending_from_json($raw === null ? null : json_decode($raw, true));
}

/**
 * @return array<string, array{at: int, mode: string, mark: int}> instance uuid => when its apply was requested, and the mode it needs
 */
function wgct_read_apply_pending(): array {
    return wgct_read_pending_file(WGCT_APPLY_PENDING_FILE);
}

/**
 * The pending record's lock: close-on-exec, beside the file, waited for at most $timeoutMs (every wait the plugin
 * makes is bounded; Config::lock() is core's).
 *
 * @param string $path      the lock file
 * @param int    $timeoutMs WGCT_APPLY_PENDING_LOCK_WAIT_MS (the self-test's shorter wait)
 * @return \SplFileObject the lock, held until LOCK_UN or the object is released
 * @throws \RuntimeException when it is still held elsewhere after $timeoutMs, or cannot be opened
 */
function wgct_apply_pending_lock(string $path, int $timeoutMs): \SplFileObject {
    $lock = wgct_poll_lock($path, $timeoutMs, 50);
    if ($lock === null) {
        throw new \RuntimeException("{$path} is still held after {$timeoutMs} ms; the apply-pending record was not changed");
    }
    return $lock;
}

/**
 * Change the pending record read-modify-write, serialized on its lock
 * (wgct_apply_pending_lock(), so a mark and a settle never lose each other's write, and
 * a settle never clears a mark it did not see: wgct_pending_settle()); written
 * atomically, and only when the change changed something. A lock still held after
 * WGCT_APPLY_PENDING_LOCK_WAIT_MS throws, as every other bounded wait does: a mark's
 * caller notes it in its result (wgct_mark_after_save()), a settle's fails its command,
 * whose record then still says apply-pending, so the next apply settles it.
 *
 * @param callable(array<string, array{at: int, mode: string, mark: int}>): array<string, array{at: int, mode: string, mark: int}> $change
 * @throws \RuntimeException when the record's directory cannot be made, its lock is still held, or it cannot be written
 */
function wgct_update_apply_pending(callable $change): void {
    $dir = dirname(WGCT_APPLY_PENDING_FILE);
    if (!wgct_state_dir($dir)) {
        throw new \RuntimeException("could not create {$dir}");
    }
    $lock = wgct_apply_pending_lock(WGCT_APPLY_PENDING_FILE . '.lock', WGCT_APPLY_PENDING_LOCK_WAIT_MS);
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
    wgct_update_apply_pending(fn (array $all): array => wgct_pending_mark($all, $uuid, $mode, time(), hrtime(true)));
}

/**
 * @return array{at: int, mode: string, mark: int}|null the instance's pending record, as an apply sees it before its first step
 */
function wgct_apply_pending_record(string $uuid): ?array {
    return wgct_read_apply_pending()[$uuid] ?? null;
}

/**
 * Settle the record with an apply's outcome (wgct_pending_outcome(), wgct_pending_settle()).
 */
function wgct_settle_apply_pending(string $uuid, string $outcome, ?array $seen): void {
    wgct_update_apply_pending(fn (array $all): array => wgct_pending_settle($all, $uuid, $outcome, $seen));
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
         * Success-only: wgct_step_summary() maps a JSON reply to 'OK', and every step in the tunnel apply lists and
         * every writer's 'steps' list answers exactly 'OK' on success, so a step failed iff its summarized result
         * is anything else. No fixed list of failure prefixes covers it: template.reload can reply 'ERR',
         * script.py can surface an arbitrary str(e), and Backend returns '' (summarized as '(no output)') on a
         * timeout, a dropped socket or an 'Execute error' reply.
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
 * The todo key for a kernel route that has no static route of its own (Edit's
 * old monitor host route): rc.routing_configure consumes every
 * /tmp/delete_route_*.todo, so any 36-character key works. Derived from the
 * gateway and the address, so the same hand-off is idempotent and two pending
 * ones for one gateway never overwrite each other. Pure.
 */
function wgct_route_todo_key(string $gatewayUuid, string $ip): string {
    $h = md5("{$gatewayUuid}|{$ip}");
    return substr($h, 0, 8) . '-' . substr($h, 8, 4) . '-' . substr($h, 12, 4) . '-' . substr($h, 16, 4) . '-' . substr($h, 20, 12);
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
        /* 'x' never opens a path that exists, a symlink included: /tmp is world-writable and
         * rc.routing_configure acts on whatever these files say */
        $path = "/tmp/delete_route_{$uuid}.todo";
        $fh = @fopen($path, 'x');
        if ($fh === false) {
            throw new \RuntimeException(file_exists($path) || is_link($path)
                ? "route hand-off file already exists: {$path}"
                : "could not write the route todo for {$network}");
        }
        $written = fwrite($fh, $network);
        fclose($fh);
        if ($written !== strlen($network)) {
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
    $set = wgct_replay_set_now($ours, $before);
    if ($set !== []) {
        wgct_replay_alarm($set, WGCT_ACTION_LOG_TAG);
    }
    return array_map('strval', array_keys($set));
}

/**
 * The replay set once the gateway lock is released (wgct_replay_set()), from config as saved and status as it is now.
 * Only the gateways are read (wgct_core_tunnel_snapshot()): the rest of the snapshot asks configd while it loads.
 *
 * @param list<string>               $ours   gateway names the action wrote
 * @param array<string, string>|null $before gateway status taken before the lock
 * @return array<string, bool> name => expected force_down, sorted by name
 */
function wgct_replay_set_now(array $ours, ?array $before): array {
    Config::getInstance()->forceReload();
    $forceDown = [];
    foreach (wgct_core_tunnel_snapshot()['gateways'] as $name => $g) {
        $forceDown[(string)$name] = $g['force_down'];
    }
    return wgct_replay_set($ours, $before, wgct_gateway_status(), $forceDown);
}

/**
 * One core configd action through configctl, bounded by timeout(1), for a caller that cannot count on the plugin's
 * own configd actions (the package removal). configd answers a script action that ran with "OK";
 * no socket, no connection, "Execute error" or no answer within $seconds all count as configd not answering. When
 * the bound runs out only this wait ends: configd finishes the action it started. configctl inherits this
 * process's open files, a held lock included, but lives only as long as the call: it starts no daemon.
 *
 * @param list<string> $words   the action and its parameters, each one argument
 * @param int          $seconds the bound
 * @return bool whether configd answered OK in time
 */
function wgct_configctl_bounded(array $words, int $seconds): bool {
    $command = WGCT_TIMEOUT . ' ' . $seconds . ' ' . WGCT_CONFIGCTL . ' ' . implode(' ', array_map('escapeshellarg', $words));
    exec($command . ' 2> /dev/null', $out, $rc);
    return $rc === 0 && trim(implode("\n", $out)) === 'OK';
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
 * API's in-process Create, whose apply then runs as the
 * configd action `wgclienttunnels apply`, which takes the lock on its own -- so
 * the lock is released before this returns, never held across that call.
 * Lock order stays gateway lock, then Config::lock() (inside $commit). Any
 * gateway alarm dropped during the hold is replayed after release, as every
 * gateway-locked action does; the tunnel's own gateways are not
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
 * The gateway-lock order for an action that changes routing. A dry run takes no gateway
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
    $seen = null;
    $pending = null;
    try {
        try {
            $result = $commit();
            if ($result['ok'] && $result['saved']) {
                $ours = $result['gateways'];
                $seen = $result['uuid'] !== '' ? wgct_apply_pending_record($result['uuid']) : null;
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
     * Always replay, once the lock is released, whether the commit refused to save, something above threw, or
     * everything succeeded: routes.alarm (flock -n) silently drops any alarm raised while we held it, for our own
     * gateways and for any other gateway whose status changed meanwhile.
     *
     * When $pending is set we are already unwinding a real failure, so a second failure out of wgct_after_apply()
     * must not replace it as the exception the caller sees: it is caught, logged (nothing replayed here carries
     * key material) and the original is rethrown. With nothing pending, an after_apply failure is the only error
     * and propagates as from a direct call.
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
        wgct_settle_apply_pending($result['uuid'], $outcome, $seen);
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
 * no gateway lock, then the reconcile. Anything but a filter
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
    $seen = $result['uuid'] !== '' ? wgct_apply_pending_record($result['uuid']) : null;
    $result['apply'] = wgct_run_steps($result['steps']);
    $result['after'] = wgct_after_apply([], null);
    $failed = wgct_failed_steps($result['apply']);
    if ($failed !== []) {
        $result['errors']['apply'] = 'saved, but these apply steps failed: ' . implode(', ', $failed)
            . '; the reconcile repairs what it can and the findings show the rest';
    }
    $outcome = wgct_pending_outcome($result['steps'], $failed);
    if ($result['uuid'] !== '' && $outcome !== null) {
        wgct_settle_apply_pending($result['uuid'], $outcome, $seen);
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
 * mode settles apply-pending. An instance missing from the engine model's
 * managed list is refused ("not a managed tunnel") before any lock or step.
 *
 * @param string      $uuid the WireGuard instance; its gateways (for the replay) are derived here
 * @param string|null $mode one of WGCT_APPLY_MODES, or null for the recorded one
 * @return array wgct_result()
 * @throws \InvalidArgumentException for an unknown mode, before anything runs
 */
function wgct_apply_only(string $uuid, ?string $mode = null): array {
    /* No apply while a migration is pending, before any lock or step. */
    if (wgct_pending_refuses('apply', WGCT_ACTION_LOG_TAG)) {
        return wgct_result(['errors' => [WGCT_MIGRATION_PENDING], 'uuid' => $uuid, 'apply_mode' => $mode ?? '']);
    }
    /* Before any lock or step, an instance the engine model does not list is not the plugin's to apply. */
    if (!in_array($uuid, wgct_managed(), true)) {
        return wgct_result(['errors' => ['not a managed tunnel'], 'uuid' => $uuid, 'apply_mode' => $mode ?? '']);
    }
    $seen = wgct_apply_pending_record($uuid);
    $mode ??= wgct_rerun_mode($seen['mode'] ?? null);
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
        wgct_settle_apply_pending($uuid, $outcome, $seen);
    }
    return $result;
}

/**
 * What no longer matches in core among the internals the plugin copies, and the fixes core may now carry for the
 * defects a workaround waits for. Reads files only.
 *
 * @param array<string, array{path: string, texts: list<string>, section?: string}> $copies WGCT_CORE_COPIES
 * @param array<string, array{path: string, unfixed: list<string>, note: string}>   $fixes  WGCT_CORE_FIXES
 * @param string $relationClass the class whose WGCT_RELATION_STATICS the writer clears (item relation_cache)
 * @return array{drift: list<string>, fixed: list<string>} one line per drifted item and per note, each starting
 *                                                          "<item>: "; drift empty when core matches
 */
function wgct_core_contract(array $copies = WGCT_CORE_COPIES, array $fixes = WGCT_CORE_FIXES,
    string $relationClass = \OPNsense\Base\FieldTypes\ModelRelationField::class): array {
    $drift = [];
    foreach ($copies as $item => $copy) {
        $problem = wgct_core_copy_drift($copy);
        if ($problem !== null) {
            $drift[] = "{$item}: {$problem}";
        }
    }
    $relation = wgct_relation_cache_drift($relationClass);
    if ($relation !== null) {
        $drift[] = $relation;
    }
    $fixed = [];
    foreach ($fixes as $item => $fix) {
        $text = wgct_core_file_text($fix['path']);
        if ($text !== null && array_filter($fix['unfixed'], fn (string $u): bool => str_contains($text, $u)) === []) {
            $fixed[] = "{$item}: {$fix['note']}";
        }
    }
    return ['drift' => $drift, 'fixed' => $fixed];
}

/**
 * The relation_cache drift line: the class missing, or without WGCT_RELATION_STATICS as statics.
 *
 * @param string $relationClass ModelRelationField, or a stand-in in a test
 * @return ?string "relation_cache: ..." when it drifted, null when the class has them
 */
function wgct_relation_cache_drift(string $relationClass = \OPNsense\Base\FieldTypes\ModelRelationField::class): ?string {
    if (!class_exists($relationClass)) {
        return "relation_cache: {$relationClass} is missing";
    }
    $class = new \ReflectionClass($relationClass);
    $gone = array_values(array_filter(WGCT_RELATION_STATICS,
        fn (string $p): bool => !$class->hasProperty($p) || !$class->getProperty($p)->isStatic()));
    return $gone === [] ? null : "relation_cache: {$relationClass} no longer has the statics " . implode(', ', $gone);
}

/**
 * The refusal of a config write when core's relation class no longer has the caches the writer clears after each
 * model it writes (wgct_reset_field_caches()); null when it has them.
 *
 * @param string $relationClass ModelRelationField, or a stand-in in a test
 * @return ?string the refusal, naming the drift
 */
function wgct_relation_cache_refusal(string $relationClass = \OPNsense\Base\FieldTypes\ModelRelationField::class): ?string {
    $drift = wgct_relation_cache_drift($relationClass);
    return $drift === null ? null : "core changed an internal the plugin's config writes rely on ({$drift}), so nothing was"
        . ' changed; install a plugin update that matches this core';
}

/**
 * One copied internal's drift: its file unreadable, its section or command gone, or the texts it no longer holds.
 *
 * @param array{path: string, texts: list<string>, section?: string} $copy a WGCT_CORE_COPIES item
 * @return ?string what drifted, null when core matches
 */
function wgct_core_copy_drift(array $copy): ?string {
    $text = wgct_core_file_text($copy['path']);
    if ($text === null) {
        return "{$copy['path']} cannot be read";
    }
    $where = $copy['path'];
    if (isset($copy['section'])) {
        if (!preg_match('/^\[' . preg_quote($copy['section'], '/') . '\]\s*$(.*?)(?=^\[|\z)/ms', $text, $section)
            || !preg_match('/^command:(.*)$/m', $section[1], $command)) {
            return "{$copy['path']} has no [{$copy['section']}] command";
        }
        $text = $command[1];
        $where = "the [{$copy['section']}] command in {$copy['path']}";
    }
    $gone = array_values(array_filter($copy['texts'], fn (string $s): bool => !str_contains($text, $s)));
    /* a text spanning lines is shown on one */
    return $gone === [] ? null : "{$where} no longer holds "
        . implode(', ', array_map(fn (string $s): string => '"' . preg_replace('/\s+/', ' ', $s) . '"', $gone));
}

/**
 * @return ?string a core file's text, null when it is not a readable file
 */
function wgct_core_file_text(string $path): ?string {
    if (!is_file($path) || !is_readable($path)) {
        return null;
    }
    $text = file_get_contents($path);
    return $text === false ? null : $text;
}

/**
 * Log a contract result once per change: the drift when it first appears or changes, and the return to a match, at
 * warning and notice; each note once, at notice, when it appears and when it clears (a core downgrade that removes a
 * fix). A note an older release kept for an item this release no longer checks (its workaround retired) is dropped
 * without a line. The last result is kept in $file as JSON; an older release kept its drift lines there, one per line.
 *
 * @param array{drift: list<string>, fixed: list<string>} $result wgct_core_contract()
 * @param callable(int, string): mixed                    $log    syslog-shaped
 * @param ?list<string>                                   $items  the items checked for a fix; null: WGCT_CORE_FIXES's
 */
function wgct_core_contract_log(array $result, string $file, callable $log, ?array $items = null): void {
    $items ??= array_keys(WGCT_CORE_FIXES);
    $now = (string)json_encode($result);
    $last = (string)wgct_read_state_file($file, WGCT_STATE_MAX_BYTES);
    if ($now === $last) {
        return;
    }
    $decoded = json_decode($last, true);
    $before = is_array($decoded) && is_array($decoded['drift'] ?? null) && is_array($decoded['fixed'] ?? null)
        ? ['drift' => $decoded['drift'], 'fixed' => $decoded['fixed']]
        : ['drift' => $last === '' ? [] : explode("\n", $last), 'fixed' => []];
    if ($result['drift'] !== $before['drift']) {
        if ($result['drift'] !== []) {
            $log(LOG_WARNING, '[wgct-contract] core changed what the plugin copies: ' . implode('; ', $result['drift']));
        } else {
            $log(LOG_NOTICE, '[wgct-contract] core matches again');
        }
    }
    $added = array_values(array_diff($result['fixed'], $before['fixed']));
    if ($added !== []) {
        $log(LOG_NOTICE, '[wgct-contract] ' . implode('; ', $added));
    }
    $cleared = array_values(array_filter(array_diff($before['fixed'], $result['fixed']),
        fn (mixed $line): bool => is_string($line) && in_array(explode(': ', $line, 2)[0], $items, true)));
    if ($cleared !== []) {
        $log(LOG_NOTICE, '[wgct-contract] no longer noted (core holds the unfixed text again, or its file cannot be read): '
            . implode('; ', $cleared));
    }
    file_put_contents($file, $now);
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
            === [$u1 => ['at' => 1700000000, 'mode' => 'first', 'mark' => 0]]);
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

    /* apply modes: tunnel is the re-run and Edit's full apply */
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

    /* apply-pending: each complete mode is its outcome; a saved Remove forgets the record */
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
    $rec = wgct_pending_mark([], $u1, 'filter', 100, 1);
    wgct_check($t, 'apply: pending mark -- the stronger of the recorded and the new mode is kept, with the new time and mark',
        $rec === [$u1 => ['at' => 100, 'mode' => 'filter', 'mark' => 1]]
        && wgct_pending_mark($rec, $u1, 'tunnel', 200, 2) === [$u1 => ['at' => 200, 'mode' => 'tunnel', 'mark' => 2]]
        && wgct_pending_mark(wgct_pending_mark($rec, $u1, 'tunnel', 200, 2), $u1, 'routes', 300, 3) === [$u1 => ['at' => 300, 'mode' => 'tunnel', 'mark' => 3]]);
    $routes = wgct_pending_mark([], $u1, 'routes', 100, 1);
    $seen = $routes[$u1];
    $tunnelRec = wgct_pending_mark([], $u1, 'tunnel', 1, 1);
    $firstRec = wgct_pending_mark([], $u1, 'first', 1, 1);
    wgct_check($t, 'apply: pending settle -- a complete mode at least as strong as the record it began against clears it; a weaker one keeps it',
        wgct_pending_settle($routes, $u1, 'filter', $seen) === $routes
        && wgct_pending_settle($routes, $u1, 'routes', $seen) === []
        && wgct_pending_settle($routes, $u1, 'tunnel', $seen) === []
        && wgct_pending_settle($tunnelRec, $u1, 'first', $tunnelRec[$u1]) !== []
        && wgct_pending_settle($firstRec, $u1, 'first', $firstRec[$u1]) === []
        && wgct_pending_settle($tunnelRec, $u1, 'forget', null) === []
        && wgct_pending_settle([], $u1, 'tunnel', null) === []);
    $remarked = wgct_pending_mark(wgct_pending_mark([], $u1, 'tunnel', 100, 1), $u1, 'filter', 100, 2);
    wgct_check($t, 'apply: pending settle -- a record re-marked (or first marked) while the apply ran is kept, even by a stronger complete apply',
        wgct_pending_settle($remarked, $u1, 'tunnel', ['at' => 100, 'mode' => 'tunnel', 'mark' => 1]) === $remarked
        && wgct_pending_settle($remarked, $u1, 'tunnel', null) === $remarked);
    $saved = wgct_result(['ok' => true, 'saved' => true, 'uuid' => $u1]);
    $failedMark = wgct_mark_after_save($saved, function (): void { throw new \RuntimeException('disk full'); });
    wgct_check($t, 'apply: a mark that fails after the save is noted in the result (saved stays true), never thrown',
        $failedMark['saved'] === true && $failedMark['ok'] === true && str_contains($failedMark['errors']['pending'] ?? '', 'disk full')
        && wgct_mark_after_save($saved, function (): void {}) === $saved);
    wgct_check($t, 'apply: the Apply button re-runs the recorded mode; Create\'s first apply and no record re-run as the tunnel apply',
        wgct_rerun_mode('filter') === 'filter' && wgct_rerun_mode('routes') === 'routes'
        && wgct_rerun_mode('first') === 'tunnel' && wgct_rerun_mode('tunnel') === 'tunnel' && wgct_rerun_mode(null) === 'tunnel');
    wgct_check($t, 'apply: pending file -- a 3.0 bare time reads as Create\'s (first); a malformed mode or uuid reads as nothing',
        wgct_pending_from_json([$u1 => 7]) === [$u1 => ['at' => 7, 'mode' => 'first', 'mark' => 0]]
        && wgct_pending_from_json([$u1 => ['at' => 7, 'mode' => 'routes', 'mark' => 5]]) === [$u1 => ['at' => 7, 'mode' => 'routes', 'mark' => 5]]
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

    /* the core contract, against this core's own files (the test VM's 26.7.7) and temporary copies of them */
    $dir = sys_get_temp_dir() . '/wgct-contract-' . getmypid();
    mkdir($dir);
    wgct_check($t, 'contract: core as of 26.7.7 has no drift', (wgct_core_contract()['drift'] ?? null) === []);
    /* $copy(path, search, replace): a copy of core's file at path with search replaced, by its path */
    $copies = 0;
    $copy = function (string $path, string $search, string $replace) use ($dir, &$copies): string {
        $copies++;
        $to = "{$dir}/copy.{$copies}";
        file_put_contents($to, str_replace($search, $replace, (string)file_get_contents($path)));
        return $to;
    };
    $drift = fn (array $copied): ?array => wgct_core_contract($copied, [])['drift'] ?? null;
    $alarm = WGCT_CORE_COPIES['routes_alarm'];
    $actions = (string)file_get_contents($alarm['path']);
    /* the lock gone from [routes.alarm]'s command, yet still in the file: another section's command holds it */
    $noLock = preg_replace('/^(\[routes\.alarm\]\s*\ncommand:[^\n]*?)' . preg_quote(WGCT_GATEWAY_LOCK_FILE, '/') . '/m',
        '$1/var/run/other.lock', $actions, -1, $replaced) . "\n[routes.elsewhere]\ncommand:/usr/local/bin/flock " . WGCT_GATEWAY_LOCK_FILE . " true\n";
    file_put_contents("{$dir}/nolock.conf", $noLock);
    $lockDrift = $drift(['routes_alarm' => ['path' => "{$dir}/nolock.conf"] + $alarm]);
    /* the section renamed: its command, lock and all, is still in the file */
    $sectionDrift = $drift(['routes_alarm' => ['path' => $copy($alarm['path'], '[routes.alarm]', '[routes.alarm_retired]')] + $alarm]);
    wgct_check($t, 'contract: routes_alarm drift is named when the lock or the command leaves its section',
        $replaced === 1 && $lockDrift === ["routes_alarm: the [routes.alarm] command in {$dir}/nolock.conf no longer holds \"" . WGCT_GATEWAY_LOCK_FILE . '"']
        && $sectionDrift !== null && count($sectionDrift) === 1 && str_starts_with($sectionDrift[0], 'routes_alarm: ')
        && str_ends_with($sectionDrift[0], ' has no [routes.alarm] command'));
    foreach (WGCT_CORE_COPIES as $item => $entry) {
        $named = true;
        foreach ($entry['texts'] as $text) {
            $gone = $drift([$item => ['path' => $copy($entry['path'], $text, '')] + $entry]);
            $named = $named && $gone !== null && count($gone) === 1 && str_starts_with($gone[0], "{$item}: ")
                && str_ends_with($gone[0], ' no longer holds "' . preg_replace('/\s+/', ' ', $text) . '"');
        }
        wgct_check($t, "contract: {$item} drift is named when its text is gone", $named);
    }
    /* the page files a row under the band its sort_order's first digit names, so band 0 needs that rule as well */
    $band = WGCT_CORE_COPIES['rules_band'];
    $bandDrift = $drift(['rules_band' => ['path' => $copy($band['path'], 'sortOrder.charAt(0)', 'sortOrder.charAt(1)')] + $band]);
    wgct_check($t, 'contract: rules_band drift is named when the band no longer comes from the first digit of sort_order',
        $bandDrift === ["rules_band: {$dir}/copy.{$copies} no longer holds \"Number(sortOrder.charAt(0))\""]);
    /* core changes a looser text would still match: each must be named */
    $moved = [
        'route_todo' => ['glob("/tmp/delete_route_*.todo")', 'glob("/var/run/delete_route_*.todo")'],
        'dpinger_socket' => ['"/var/run/dpinger_{$name}.sock"', '"/var/run/dpinger/{$name}.sock"'],
        'reply_escape' => ['htmlspecialchars($result, ENT_NOQUOTES)', 'htmlspecialchars($result, ENT_QUOTES)'],
    ];
    foreach ($moved as $item => [$from, $to]) {
        $entry = WGCT_CORE_COPIES[$item];
        $changed = $drift([$item => ['path' => $copy($entry['path'], $from, $to)] + $entry]);
        wgct_check($t, "contract: {$item} drift is named when core changes the line the plugin relies on, though similar text stays",
            $changed !== null && count($changed) === 1 && str_ends_with($changed[0], " no longer holds \"{$from}\""));
    }
    /* core 26.7.8: the family cleared between the two lines the sentinel relies on, each line still in the file */
    $sentinel = WGCT_CORE_COPIES['sentinel_family'];
    $kept = $sentinel['texts'][0];
    $familyLess = $copy($sentinel['path'], $kept,
        str_replace("\n", "\n                        \$thisconf['ipprotocol'] = '';\n", $kept));
    $familyDrift = $drift(['sentinel_family' => ['path' => $familyLess] + $sentinel]);
    $familyText = (string)file_get_contents($familyLess);
    wgct_check($t, 'contract: sentinel_family drift is named when core makes the dynamic gateway family-less',
        str_contains($familyText, "\$thisconf['gateway_interface'] = true;") && str_contains($familyText, "\$this->cached_gateways[\$gwkey] = \$thisconf;")
        && $familyDrift !== null && count($familyDrift) === 1
        && str_ends_with($familyDrift[0], ' no longer holds "' . preg_replace('/\s+/', ' ', $kept) . '"'));
    $routeModel = WGCT_CORE_COPIES['route_model'];
    /* enabled's default turned 0 while another field gains a Default 1 */
    $otherDefault = $copy($routeModel['path'], '<Default>1</Default>', '<Default>0</Default>');
    file_put_contents($otherDefault, str_replace('<descr type="DescriptionField"/>',
        "<descr type=\"DescriptionField\">\n                <Default>1</Default>\n            </descr>", (string)file_get_contents($otherDefault)));
    $defaultDrift = $drift(['route_model' => ['path' => $otherDefault] + $routeModel]);
    wgct_check($t, "contract: route_model drift is named when enabled's Default 1 goes, though another field has one",
        str_contains((string)file_get_contents($otherDefault), '<Default>1</Default>') && $defaultDrift !== null && count($defaultDrift) === 1
        && str_contains($defaultDrift[0], '<enabled type="BooleanField"> <Default>1</Default>'));
    wgct_check($t, 'contract: an unreadable file is drift',
        $drift([
            'route_todo' => ['path' => "{$dir}/absent"] + WGCT_CORE_COPIES['route_todo'],
            'routes_alarm' => ['path' => "{$dir}/absent.conf"] + $alarm,
        ]) === ["route_todo: {$dir}/absent cannot be read", "routes_alarm: {$dir}/absent.conf cannot be read"]);
    $bare = get_class(new class {
    });
    $half = get_class(new class {
        private static array $internalCacheModelStruct = [];
        public array $internalCacheOptionList = [];
    });
    $relation = fn (string $class): ?array => wgct_core_contract([], [], $class)['drift'] ?? null;
    wgct_check($t, 'contract: a relation class without the statics is drift',
        $relation($bare) === ["relation_cache: {$bare} no longer has the statics internalCacheModelStruct, internalCacheOptionList"]
        && $relation($half) === ["relation_cache: {$half} no longer has the statics internalCacheOptionList"]
        && $relation('OPNsense\\Base\\FieldTypes\\NoSuchRelationField') === ['relation_cache: OPNsense\\Base\\FieldTypes\\NoSuchRelationField is missing']);
    $notes = fn (array $fixes): ?array => wgct_core_contract([], $fixes)['fixed'] ?? null;
    $farGw6 = WGCT_CORE_FIXES['far_gw6'];
    wgct_check($t, 'contract: far_gw6 has no note on 26.7.7, nor when its file is absent',
        $notes(['far_gw6' => $farGw6]) === [] && $notes(['far_gw6' => ['path' => "{$dir}/absent"] + $farGw6]) === []);
    /* the two edits of the proposed fix's diff (opnsense/core 060af78d31) */
    $fixedV6 = $copy($farGw6['path'], "\n    if (!is_ipaddrv4(\$gateway)) {",
        "\n    if (is_ipaddrv6(\$gateway)) {\n        \$family = 'inet6';\n    } elseif (!is_ipaddrv4(\$gateway)) {");
    file_put_contents($fixedV6, str_replace($farGw6['unfixed'][0], "if (!empty(\$gateway['fargw'])) {", (string)file_get_contents($fixedV6)));
    wgct_check($t, 'contract: the far_gw6 note shows on a core with the proposed fix applied',
        $notes(['far_gw6' => ['path' => $fixedV6] + $farGw6]) === ['far_gw6: ' . $farGw6['note']]);

    $logged = [];
    $log = function (int $prio, string $msg) use (&$logged): void {
        $logged[] = [$prio, $msg];
    };
    $state = "$dir/logged";
    $items = ['fix_a', 'fix_b'];
    $both = ['drift' => ['route_todo: x changed'], 'fixed' => ['fix_a: y fixed']];
    wgct_core_contract_log($both, $state, $log, $items);
    wgct_core_contract_log($both, $state, $log, $items);
    wgct_check($t, 'contract: drift and notes are logged once each', $logged === [
        [LOG_WARNING, '[wgct-contract] core changed what the plugin copies: route_todo: x changed'],
        [LOG_NOTICE, '[wgct-contract] fix_a: y fixed'],
    ]);
    $noted = ['drift' => [], 'fixed' => ['fix_a: y fixed']];
    wgct_core_contract_log($noted, $state, $log, $items);
    wgct_core_contract_log($noted, $state, $log, $items);
    wgct_check($t, 'contract: the return to a match is logged once, and a note already logged is not logged again',
        count($logged) === 3 && $logged[2] === [LOG_NOTICE, '[wgct-contract] core matches again']);
    wgct_core_contract_log(['drift' => [], 'fixed' => []], "$dir/fresh", $log, $items);
    wgct_check($t, 'contract: a match on a fresh state logs nothing', count($logged) === 3);
    /* an older release kept its drift lines, one per line */
    file_put_contents("$dir/older", '[routes.alarm] no longer takes ' . WGCT_GATEWAY_LOCK_FILE);
    wgct_core_contract_log(['drift' => [], 'fixed' => []], "$dir/older", $log, $items);
    wgct_core_contract_log(['drift' => [], 'fixed' => []], "$dir/older", $log, $items);
    wgct_check($t, 'contract: a drift an older release recorded returns to a match once',
        count($logged) === 4 && $logged[3] === [LOG_NOTICE, '[wgct-contract] core matches again']);
    /* the notes: a second note logs only itself; a note that clears is logged once */
    $notesState = "$dir/notes";
    wgct_core_contract_log(['drift' => [], 'fixed' => ['fix_a: y fixed']], $notesState, $log, $items);
    wgct_core_contract_log(['drift' => [], 'fixed' => ['fix_a: y fixed', 'fix_b: z fixed']], $notesState, $log, $items);
    wgct_check($t, 'contract: a second note logs only itself, not the note already logged',
        count($logged) === 6 && $logged[5] === [LOG_NOTICE, '[wgct-contract] fix_b: z fixed']);
    wgct_core_contract_log(['drift' => [], 'fixed' => ['fix_b: z fixed']], $notesState, $log, $items);
    wgct_core_contract_log(['drift' => [], 'fixed' => ['fix_b: z fixed']], $notesState, $log, $items);
    wgct_check($t, 'contract: a note that clears is logged once, at notice, naming it',
        count($logged) === 7 && $logged[6][0] === LOG_NOTICE && str_starts_with($logged[6][1], '[wgct-contract] no longer noted')
        && str_ends_with($logged[6][1], ': fix_a: y fixed'));
    /* a note kept for an item no longer checked (a retired workaround) goes without a line; the rest is logged as ever */
    $retired = "$dir/retired";
    wgct_core_contract_log(['drift' => [], 'fixed' => ['fix_a: y fixed', 'fix_b: z fixed']], $retired, $log, $items);
    $count = count($logged);
    wgct_core_contract_log(['drift' => [], 'fixed' => ['fix_b: z fixed']], $retired, $log, ['fix_b']);
    wgct_core_contract_log(['drift' => [], 'fixed' => []], $retired, $log, ['fix_b']);
    wgct_check($t, 'contract: a retired item\'s note is dropped without a line; a checked item\'s note still clears once',
        count($logged) === $count + 1 && str_ends_with($logged[$count][1], ': fix_b: z fixed'));
    array_map('unlink', glob("$dir/*"));
    rmdir($dir);

    $cmd = wgct_log_command(LOG_ERR, '[wgct-x] boom');
    wgct_check($t, 'log: a line goes to logger under the program name core\'s WireGuard log matches, at its level',
        str_starts_with($cmd, '/usr/bin/logger -t wireguard -p user.err -- '));
    wgct_check($t, 'log: the message is one shell-quoted argument, never expanded',
        str_ends_with(wgct_log_command(LOG_NOTICE, "[wgct-x] it's \$(id)"), ' -- ' . escapeshellarg("[wgct-x] it's \$(id)")));
    wgct_check($t, 'log: newlines fold into "; " so a message stays one line',
        str_ends_with(wgct_log_command(LOG_NOTICE, "[wgct-x] first\n  second\r\nthird"), escapeshellarg('[wgct-x] first; second; third')));
    wgct_check($t, 'log: an unknown priority logs at notice', str_contains(wgct_log_command(99, 'x'), ' -p user.notice '));
    wgct_check($t, 'log: warning and info map to their names',
        str_contains(wgct_log_command(LOG_WARNING, 'x'), ' -p user.warning ') && str_contains(wgct_log_command(LOG_INFO, 'x'), ' -p user.info '));
    /* the apply-pending record's lock is waited for a bounded time: a temporary lock file, held by a second open */
    $lockDir = rtrim(sys_get_temp_dir(), '/') . '/wgct-pending-selftest.' . getmypid();
    @mkdir($lockDir, 0700);
    $lockPath = "{$lockDir}/apply_pending.json.lock";
    $holder = new \SplFileObject($lockPath, 'c');
    $holder->flock(LOCK_EX);
    $started = hrtime(true);
    $timedOut = null;
    try {
        wgct_apply_pending_lock($lockPath, 200);
    } catch (\RuntimeException $e) {
        $timedOut = $e->getMessage();
    }
    $waitedMs = intdiv(hrtime(true) - $started, 1000000);
    wgct_check($t, 'apply: the apply-pending lock held elsewhere => a RuntimeException naming it after the bounded wait, not a wait forever',
        $timedOut === "{$lockPath} is still held after 200 ms; the apply-pending record was not changed" && $waitedMs >= 200 && $waitedMs < 5000);
    $holder->flock(LOCK_UN);
    $taken = wgct_apply_pending_lock($lockPath, 200);
    wgct_check($t, 'apply: the lock free => taken at once', $taken->flock(LOCK_EX | LOCK_NB));
    $taken->flock(LOCK_UN);
    unset($holder, $taken);
    @unlink($lockPath);
    @rmdir($lockDir);
    $entry = (string)@file_get_contents(dirname(__DIR__) . '/entry.php');
    $shell = (string)@file_get_contents(dirname(__DIR__) . '/wgct.sh');
    wgct_check($t, 'apply: entry.php and wgct.sh name the removal marker WGCT_REMOVING_FILE names',
        WGCT_REMOVING_FILE === WGCT_RUN_DIR . '/removing' && str_contains($entry, "\$dir . '/removing'")
        && str_contains($entry, "const WGCT_ENTRY_RUN_DIR = '" . WGCT_RUN_DIR . "';")
        && str_contains($shell, 'STATE_DIR="' . WGCT_RUN_DIR . '"') && str_contains($shell, '"${STATE_DIR}/removing"'));
    return wgct_tally_report('apply', $t);
}
