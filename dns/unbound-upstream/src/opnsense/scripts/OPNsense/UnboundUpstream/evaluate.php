#!/usr/local/bin/php
<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The plugin's single entry point:
 *   evaluate.php [evaluate] [NAMES]   one evaluation (configd, cron, hooks); NAMES is ONE comma-separated list of
 *                                     the gateways the monitor hook passed (configd hands %s over as one parameter)
 *   evaluate.php start                regenerate cron (the minute job exists while enabled, or while a footprint is
 *                                     recorded), then one evaluation (Save with enabled on while the job is missing)
 *   evaluate.php stop                 regenerate cron, then leave tunnel mode and delete the plugin's routes,
 *                                     whatever the settings say (Save with enabled off)
 *   evaluate.php remove               the package's deinstall, on an upgrade too (a reload between the old files'
 *                                     removal and the new install renders none of the plugin's rules): leave the
 *                                     removal marker, stop, then core's filter reload and cron restart (configd,
 *                                     else core's own scripts, since the plugin's own actions go with its files);
 *                                     every evaluation stops while the marker exists (a cron tick or a hook between
 *                                     the deinstall's stop and the files' removal would otherwise re-enter tunnel
 *                                     mode with nothing left to undo it), until the package's post-install deletes
 *                                     it. With a run directory it cannot trust it only restarts Unbound; a marker it
 *                                     cannot make is an error, and the stop runs all the same
 *   evaluate.php status               the JSON for the page; without the lock, it changes nothing but
 *                                     the run directory (uu_run_dir()), and it never lists the ruleset
 *   evaluate.php selftest             the pure suites, from a source tree (the package carries no tests)
 *   evaluate.php record FILE          write the live snapshot and the saved state to FILE; changes nothing else
 *                                     but the run directory (uu_run_dir())
 *   evaluate.php replay FILE          plan from a recorded FILE and print every step apply would run; changes nothing
 * evaluate, start, stop and remove run under the evaluate lock, waiting as long as uu_lock_policy() says for the mode
 * (UU_LOCK_WAIT_SECONDS; remove UU_REMOVE_LOCK_WAIT_SECONDS) for an evaluation in flight, so a trigger that arrives
 * meanwhile runs after it instead of being dropped. A failure that stops the evaluation (the lock's wait running out,
 * the settings, the snapshot or the state failing) is logged and exits non-zero; a route or Unbound call that fails
 * during apply is logged at error level, its address keeps its entry for the next evaluation to try again, and the
 * evaluation still exits 0. Nothing is thrown into configd.
 */

require_once __DIR__ . '/lib/constants.php';
require_once __DIR__ . '/lib/state.php';
require_once __DIR__ . '/lib/planner.php';
require_once __DIR__ . '/lib/snapshot.php';
require_once __DIR__ . '/lib/apply.php';
require_once __DIR__ . '/lib/log.php';
require_once __DIR__ . '/lib/notify.php';
require_once __DIR__ . '/lib/corecmd.php';
require_once __DIR__ . '/lib/lock.php';

const UU_LOCK_PATH = UU_RUN_DIR . '/evaluate.lock';
const UU_REMOVING_PATH = UU_RUN_DIR . '/removing';  /* +POST_INSTALL.post deletes it by this path */

try {
    exit(uu_main(array_values(array_slice($argv, 1))));
} catch (\Throwable $e) {
    uu_log('evaluate.php failed: ' . $e->getMessage() . ' (' . basename($e->getFile()) . ':' . $e->getLine() . ')',
        LOG_ERR);
    fwrite(STDERR, $e->getMessage() . "\n");
    exit(1);
}

/**
 * @param list<string> $args
 */
function uu_main(array $args): int
{
    $mode = $args[0] ?? 'evaluate';
    if (!in_array($mode, ['evaluate', 'start', 'stop', 'remove', 'status', 'selftest', 'record', 'replay'], true)) {
        /* `evaluate.php NAMES`: the one argument is the names list */
        if (count($args) > 1) {
            fwrite(STDERR, "usage: evaluate.php [evaluate] [NAMES] | start | stop | remove | status | selftest"
                . " | record FILE | replay FILE\n");
            return 2;
        }
        $args = ['evaluate', $mode];
        $mode = 'evaluate';
    }
    switch ($mode) {
        case 'status':
            return uu_status_main();
        case 'selftest':
            return uu_selftest_main();
        case 'record':
            return uu_record_main($args[1] ?? '');
        case 'replay':
            return uu_replay_main($args[1] ?? '');
        case 'start':
            uu_cron_regenerate();
            return uu_with_lock($mode, fn (): int => uu_evaluate(null, []));
        case 'remove':
            $refused = uu_remove_prepare('uu_run_dir', 'uu_remove_marker', 'uu_core_shell', 'uu_log');
            if ($refused !== null) {
                return $refused;
            }
            return uu_with_lock($mode, 'uu_remove', fn (): string => uu_remove_timeout_remedy(UU_STATE_PATH));
        case 'stop':
            uu_cron_regenerate();
            return uu_with_lock($mode, fn (): int => uu_evaluate(UU_STOP_REQUEST, []));
        default:
            return uu_with_lock($mode, fn (): int => uu_evaluate(null, uu_names($args[1] ?? '')));
    }
}

/**
 * configd's cron restart, which reads unboundupstream_cron(): the minute job is installed while the plugin is enabled
 * or the state records a footprint (so a disabled plugin's stop that could not restore is retried), and removed
 * otherwise. A failure is logged; the evaluation still runs.
 */
function uu_cron_regenerate(): void
{
    uu_load_core();
    $out = trim((new \OPNsense\Core\Backend())->configdRun('cron restart'));
    if ($out !== 'OK') {
        uu_log("cron restart answered '$out': the minute job may not match the enabled setting and the footprint",
            LOG_WARNING);
    }
}

/**
 * The monitor hook's gateway names; anything that is not a gateway name is dropped.
 *
 * @return list<string>
 */
function uu_names(string $arg): array
{
    $names = [];
    foreach (explode(',', $arg) as $name) {
        $name = trim($name);
        if (preg_match('/^[A-Za-z0-9_.-]+$/', $name) === 1) {
            $names[] = $name;
        }
    }
    return $names;
}

/**
 * Run fn under the evaluate lock in the run directory, waiting as long as the mode's policy says (uu_lock_policy())
 * for an evaluation in flight; a wait that runs out logs timeoutText and returns 1.
 *
 * @param callable(): int $fn
 * @param string|\Closure(): string $timeoutText
 */
function uu_with_lock(string $mode, callable $fn, string|\Closure $timeoutText = 'this trigger did nothing'): int
{
    uu_run_dir();
    $policy = uu_lock_policy($mode);
    return uu_lock_run(UU_LOCK_PATH, $fn, $policy['seconds'], $policy['prio'], $timeoutText, 'uu_log');
}

/** remove's removal marker, in the run directory uu_remove_prepare() found it can trust. */
function uu_remove_marker(): void
{
    if (!touch(UU_REMOVING_PATH)) {
        throw new RuntimeException('cannot create ' . UU_REMOVING_PATH);
    }
}

/**
 * remove under the lock: the removal's stop, then core's filter reload and cron restart, which run even when the
 * stop failed, so the rules and the minute job follow whatever footprint it saved; a stop that throws before it can
 * act restarts Unbound first (uu_remove_run()). pkg sets PKG_UPGRADE in the pre-deinstall's environment on an
 * upgrade: that stop arms a lifted set before its restore and keeps the fail-closed view, refuse and file, through
 * the upgrade window.
 */
function uu_remove(): int
{
    $upgrade = getenv('PKG_UPGRADE') !== false;
    return uu_remove_run(fn (): int => uu_evaluate(UU_STOP_REMOVE, [], $upgrade), 'uu_core_shell', 'uu_log');
}

/**
 * One evaluation. stop and remove run as stops whatever the settings say, and so does every evaluation while the
 * removal marker exists, as a tick of the removal (uu_plan_causes()); the cause goes to the planner (Snapshot.stop),
 * which logs it. The settings are read under the lock, so an evaluation that waited for it acts on the last Save. A
 * Save that changed a resolver is no stop: the planner switches in place, every address the state still holds is
 * rejected, held and drained by apply, and each member's resolver-failed mark follows its own resolver
 * (uu_timers_follow_resolvers()).
 *
 * @param ?string $stop a UU_STOP_* cause, or null for an evaluation
 * @param list<string> $named
 * @param bool $upgrade remove on a package upgrade (uu_remove())
 */
function uu_evaluate(?string $stop, array $named, bool $upgrade = false): int
{
    $settings = uu_settings(true);
    $cause = uu_plan_causes($stop, is_file(UU_REMOVING_PATH))['run'];
    if ($cause === UU_STOP_REMOVING) {
        /* every minute after a deinstall that stopped partway: worth the noise */
        uu_log('the package is being removed (' . UU_REMOVING_PATH . ' exists): evaluating as stopped; delete it '
            . 'if the package is still installed', LOG_WARNING);
    }
    uu_evaluate_once($settings, $named, $cause, $upgrade);
    return 0;
}

/**
 * Snapshot (with the routes of every address the loaded state holds), the rules' verification saved when this run
 * made one, plan, apply, the view's file step (uu_view_file_follow()), the counting table's upkeep and blocked-count
 * line, save, the filter reload (and cron restart) when the footprint changed, except in remove itself
 * (uu_footprint_follow()), then the notification when the run switched or changed the fail-closed view's problem
 * (a cleared one included). A stop never lists the ruleset: it plans without the contract, and the filter reload it
 * ends with changes the checksum anyway.
 *
 * @param array{enabled: bool, dry_run: bool, group: string, default: string,
 *     rows: array<string, string>, failback_delay: int, probe_name: string} $settings
 * @param list<string> $named
 * @param ?string $stop a UU_STOP_* cause, or null for an evaluation
 * @param bool $upgrade remove on a package upgrade: the snapshot carries it, and the stop keeps the view
 */
function uu_evaluate_once(array $settings, array $named, ?string $stop, bool $upgrade = false): void
{
    $st = uu_state_load(UU_STATE_PATH);
    $before = uu_state_footprint($st);
    $viewBefore = uu_state_view_footprint($st, uu_view_file_present());
    $s = uu_snapshot($settings, $named, $stop, $stop === null, $before, true, $upgrade);
    if ($s['rules']['record'] !== null) {
        try {
            uu_rules_record_save(UU_RULES_PATH, $s['rules']['record']);
        } catch (\Throwable $e) {
            uu_log('rules: the verification could not be saved (' . $e->getMessage() . '): the next evaluation '
                . 'lists the ruleset again', LOG_WARNING);
        }
    }
    $previousSwitch = $st['last_switch'];
    $previousProblem = $st['view']['problem'];
    try {
        $want = uu_setting_addresses($s);
        $table = uu_block_table_view($s['block_table']['table'], $s['block_table']['addresses'], $want);
        $s = uu_route_adopt($s, $st['addresses']);
        $s = uu_wait_control($s, $st['mode']);
        $p = uu_plan($s, $st);
        $st = uu_apply($p, $s, uu_live_io(UU_STATE_PATH));
        $st = uu_view_file_follow($p, $s, $st);

        $blocked = null;
        if (uu_plan_stop_reason($s) === null) {
            /* the removal marker can appear while this run holds the lock: a deinstall's remove waits for it */
            if ($table['fill'] && !is_file(UU_REMOVING_PATH)) {
                uu_block_table_fill($want, 'uu_core_shell', 'uu_log');
            }
            $blocked = $table['blocked'];
            $line = uu_blocked_line($st['blocked'], $blocked);
            if ($line !== null) {
                uu_log($line, LOG_NOTICE);
            }
        }
        $st['blocked'] = $blocked;
        uu_state_save(UU_STATE_PATH, $st);
    } finally {
        uu_footprint_follow($before, $viewBefore, $settings['enabled'], $stop);
    }
    if (uu_notify_due($previousSwitch, $st['last_switch'], $previousProblem, $st['view']['problem'])) {
        uu_notify_switch($st, uu_notify_due($previousSwitch, $st['last_switch'], null, null));
    }
}

/**
 * The view's file step after apply (uu_view_file_apply(), through the real I/O): the file written only once
 * unbound-checkconf passes it, deleted when no file is wanted, Unbound restarted through core's restart only when the
 * node lines of its loaded copy differ from the file's (which also takes a deleted file's copy away), and the state's
 * view record following it. In its own try: a failure is logged at error level, the
 * record stays as apply left it, and the save and the notification still run.
 *
 * @param array{view: array{active: bool, armed: ?bool, keep: bool, zones: array<string, string>,
 *     mirror: array<string, list<string>>, problem: ?string}} $p
 * @param array{stop: ?string, settings: array{enabled: bool, dry_run: bool},
 *     unbound: array{enabled: bool, pid_alive: bool}, contract_input: array{cacheflush: bool},
 *     view: array{scope: string, nets: list<string>, notes: list<string>, acl: ?array{nodes: list<array{net: string,
 *         action: string}>, foreign: list<string>}, zones: ?array<string, string>, data: ?list<string>,
 *         loaded: string, view_zones: array<string, string>, view_data: list<string>, file: ?string,
 *         copy: ?string, file_present: bool}} $s
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
 *     view: array{refuse: string, scope: string, nets: list<string>, problem: ?string,
 *         restarted: ?string, unwritable: int}} $st
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
 *     view: array{refuse: string, scope: string, nets: list<string>, problem: ?string,
 *         restarted: ?string, unwritable: int}}
 */
function uu_view_file_follow(array $p, array $s, array $st): array
{
    try {
        return uu_view_file_apply($p, $s, $st, uu_view_file_io());
    } catch (\Throwable $e) {
        uu_log('fail closed: the view file step failed: ' . $e->getMessage() . ' (' . basename($e->getFile()) . ':'
            . $e->getLine() . ')', LOG_ERR);
        return $st;
    }
}

/**
 * The rules and the minute job follow the footprint the run saved: a footprint that changed reloads the filter
 * (uu_footprint_reload()), so its block and pass come or go at once, and one that came or went while the plugin is
 * disabled restarts cron, so the minute job that retries the stop is installed exactly while one is recorded (the
 * view's footprint counts for the job, uu_state_view_footprint()); in remove itself, both wait until its stop is over
 * (uu_remove()). The state is read back, so a run that failed after a checkpoint follows what it saved; nothing is
 * thrown, so such a run still ends in its own error.
 *
 * @param list<string> $before the footprint before the run
 * @param bool $viewBefore the view's footprint before the run
 * @param ?string $stop the run's UU_STOP_* cause, or null
 */
function uu_footprint_follow(array $before, bool $viewBefore, bool $enabled, ?string $stop): void
{
    try {
        $state = uu_state_load(UU_STATE_PATH);
        $after = uu_state_footprint($state);
        $actions = uu_footprint_actions($before, $after, $enabled, $stop, $viewBefore,
            uu_state_view_footprint($state, uu_view_file_present()));
        if ($actions['reload']) {
            uu_footprint_reload('the address the plugin last used changed from ' . uu_footprint_text($before) . ' to '
                . uu_footprint_text($after), 'uu_core_shell', 'uu_log');
        }
        if ($actions['cron']) {
            uu_cron_regenerate();
        }
    } catch (\Throwable $e) {
        uu_log('the rules or the minute job could not follow the footprint: ' . $e->getMessage(), LOG_ERR);
    }
}

function uu_status_main(): int
{
    $settings = uu_settings();
    $st = uu_state_load(UU_STATE_PATH);
    /* never lists the ruleset: the checksum and the counting table only */
    $s = uu_route_adopt(uu_snapshot($settings, [], null, false, uu_state_footprint($st)), $st['addresses']);
    $p = uu_plan($s, $st);
    $table = uu_block_table_view($s['block_table']['table'], $s['block_table']['addresses'],
        uu_setting_addresses($s));
    $doc = uu_status_doc($s, $p, $table);
    echo json_encode($doc, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\n";
    return 0;
}

/** The pure suites from the source tree's tests directory; read-only checks only. */
function uu_selftest_main(): int
{
    require_once __DIR__ . '/lib/selftest.php';
    $files = glob(dirname(__DIR__, 5) . '/tests/test_*.php') ?: [];
    if ($files === []) {
        fwrite(STDERR, "no selftests here: the package carries none; run evaluate.php selftest from the plugin's "
            . "source tree\n");
        return 1;
    }
    foreach ($files as $file) {
        require_once $file;
    }
    return uu_run_suites();
}

function uu_record_main(string $path): int
{
    if ($path === '') {
        fwrite(STDERR, "usage: evaluate.php record FILE\n");
        return 2;
    }
    /* lists the ruleset as an evaluation would (no verification of the live checksum saved, a saved fault, or a
     * listing cut short), so a replay plans on the same verdict; the verification is not saved (record changes
     * nothing) */
    $st = uu_state_load(UU_STATE_PATH);
    $doc = ['snapshot' => uu_snapshot(uu_settings(), [], null, true, uu_state_footprint($st), true, false), 'state' => $st];
    if (file_put_contents($path, json_encode($doc, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR)
        . "\n") === false) {
        throw new RuntimeException("cannot write $path");
    }
    return 0;
}

/** Plan from a recorded snapshot and state and print the steps; nothing is applied, nothing is saved. */
function uu_replay_main(string $path): int
{
    if ($path === '') {
        fwrite(STDERR, "usage: evaluate.php replay FILE\n");
        return 2;
    }
    $text = file_get_contents($path);
    if ($text === false) {
        throw new RuntimeException("cannot read $path");
    }
    $doc = json_decode($text, true, 512, JSON_THROW_ON_ERROR);
    $keys = ['now', 'wall', 'settings', 'trigger', 'tiers', 'family', 'members', 'probes', 'named', 'stop', 'unbound',
             'zone', 'routes', 'route_flags', 'fib_sync_ms', 'contract_input', 'rules', 'block_table', 'upgrade', 'view'];
    /* the snapshot is evaluate.php record's own output: its top-level shape is checked, not every field, once a
     * recording made before 1.4 has been refused by name */
    $not = "$path is not a snapshot and state written by evaluate.php record";
    if (!is_array($doc) || !is_array($doc['snapshot'] ?? null) || !is_array($doc['state'] ?? null)) {
        throw new RuntimeException($not);
    }
    $snapshot = uu_snapshot_recorded($doc['snapshot'], $path);
    if (array_keys($snapshot) !== $keys) {
        throw new RuntimeException($not);
    }
    $st = uu_state_from_doc($doc['state']);
    if ($st === null) {
        echo "the recorded state is not this version's shape: planning from a fresh state\n";
        $st = uu_state_new();
    }
    $s = uu_route_adopt($snapshot, $st['addresses']);
    $p = uu_plan($s, $st);
    uu_apply_preview($p, $s, function (string $msg, int $prio): void {
        echo $msg, "\n";
    });
    echo json_encode(['plan' => $p], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\n";
    return 0;
}
