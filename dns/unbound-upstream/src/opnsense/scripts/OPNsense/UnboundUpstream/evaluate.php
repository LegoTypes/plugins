#!/usr/local/bin/php
<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The plugin's single entry point (spec 2026-10-17 sections 3.1, 3.4, 3.7, 3.8 and 3.10):
 *   evaluate.php [evaluate] [NAMES]   one evaluation (configd, cron, hooks); NAMES is ONE comma-separated list of
 *                                     the gateways the monitor hook passed (configd hands %s over as one parameter)
 *   evaluate.php start                regenerate cron (the minute job exists only while enabled), then one
 *                                     evaluation (Save with enabled on while the job is missing)
 *   evaluate.php stop                 regenerate cron, then leave tunnel mode and delete the resolver's route,
 *                                     whatever the settings say (Save with enabled off)
 *   evaluate.php remove               the package's deinstall: leave the removal marker, then stop; every
 *                                     evaluation stops while the marker exists (a cron tick or a hook between the
 *                                     deinstall's stop and the files' removal would otherwise re-enter tunnel mode
 *                                     with nothing left to undo it), until the package's post-install deletes it
 *   evaluate.php status               the section 3.8 JSON for the page; read-only and without the lock, and it
 *                                     never lists the ruleset (section 3.6c)
 *   evaluate.php selftest             the pure suites, from a source tree (the package carries no tests)
 *   evaluate.php record FILE          write the live snapshot and the saved state to FILE; changes nothing
 *   evaluate.php replay FILE          plan from a recorded FILE and print every step apply would run; changes nothing
 * evaluate, start, stop and remove run under the evaluate lock, waiting up to UU_LOCK_WAIT_SECONDS for an
 * evaluation in flight, so a trigger that arrives meanwhile runs after it instead of being dropped. Every failure is logged and exits
 * non-zero; nothing is thrown into configd.
 */

const UU_RUN_DIR = '/var/run/unboundupstream';
const UU_STATE_PATH = UU_RUN_DIR . '/state.json';
const UU_LOCK_PATH = UU_RUN_DIR . '/evaluate.lock';
const UU_REMOVING_PATH = UU_RUN_DIR . '/removing';  /* +POST_INSTALL.post deletes it by this path */

require_once __DIR__ . '/lib/constants.php';
require_once __DIR__ . '/lib/state.php';
require_once __DIR__ . '/lib/planner.php';
require_once __DIR__ . '/lib/snapshot.php';
require_once __DIR__ . '/lib/apply.php';
require_once __DIR__ . '/lib/log.php';
require_once __DIR__ . '/lib/notify.php';

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
            return uu_with_lock(fn (): int => uu_evaluate(null, []));
        case 'remove':
            uu_run_dir();
            if (!touch(UU_REMOVING_PATH)) {
                throw new RuntimeException('cannot create ' . UU_REMOVING_PATH);
            }
            return uu_with_lock(fn (): int => uu_evaluate(UU_STOP_REMOVE, []));
        case 'stop':
            uu_cron_regenerate();
            return uu_with_lock(fn (): int => uu_evaluate(UU_STOP_REQUEST, []));
        default:
            return uu_with_lock(fn (): int => uu_evaluate(null, uu_names($args[1] ?? '')));
    }
}

/**
 * configd's cron restart, which reads unboundupstream_cron(): the minute job is installed while the plugin is enabled
 * and removed otherwise. A failure is logged; the evaluation still runs.
 */
function uu_cron_regenerate(): void
{
    uu_load_core();
    $out = trim((new \OPNsense\Core\Backend())->configdRun('cron restart'));
    if ($out !== 'OK') {
        uu_log("cron restart answered '$out': the minute job may not match the enabled setting", LOG_WARNING);
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

function uu_run_dir(): void
{
    if (!is_dir(UU_RUN_DIR) && !mkdir(UU_RUN_DIR, 0700, true) && !is_dir(UU_RUN_DIR)) {
        throw new RuntimeException('cannot create ' . UU_RUN_DIR);
    }
}

/**
 * Run fn under the evaluate lock: exclusive, blocking up to UU_LOCK_WAIT_SECONDS, never dropping a trigger at
 * once. The lock is close-on-exec, so a child (configctl unbound restart) never holds it.
 *
 * @param callable(): int $fn
 */
function uu_with_lock(callable $fn): int
{
    uu_run_dir();
    $lock = fopen(UU_LOCK_PATH, 'ce');
    if ($lock === false) {
        throw new RuntimeException('cannot open ' . UU_LOCK_PATH);
    }
    try {
        $deadline = hrtime(true) + UU_LOCK_WAIT_SECONDS * 1000000000;
        while (!flock($lock, LOCK_EX | LOCK_NB)) {
            if (hrtime(true) >= $deadline) {
                uu_log('an evaluation held the lock for ' . UU_LOCK_WAIT_SECONDS . ' s: this trigger did nothing',
                    LOG_WARNING);
                return 1;
            }
            usleep(200000);
        }
        return $fn();
    } finally {
        fclose($lock);
    }
}

/**
 * One evaluation. stop and remove run as stops whatever the settings say, and so does every evaluation while the
 * removal marker exists; the cause goes to the planner (Snapshot.stop), which logs it. The settings are read under
 * the lock, so an evaluation that waited for it acts on the last Save. When the state records a resolver address
 * other than the setting's (a Save changed it, ruling R31), that address's route and forwarders are undone first
 * by a stop for it, and the members' resolver-failed marks, which were about it, are forgotten; if that does not
 * finish, the new address waits for the next evaluation.
 *
 * @param ?string $stop a UU_STOP_* cause, or null for an evaluation
 * @param list<string> $named
 */
function uu_evaluate(?string $stop, array $named): int
{
    $settings = uu_settings();
    if ($stop === null && $settings['enabled'] && is_file(UU_REMOVING_PATH)) {
        /* every minute after a deinstall that stopped partway: worth the noise */
        uu_log('the package is being removed (' . UU_REMOVING_PATH . ' exists): evaluating as stopped; delete it '
            . 'if the package is still installed', LOG_WARNING);
        $stop = UU_STOP_REMOVE;
    }
    $old = uu_state_load(UU_STATE_PATH)['resolver'];
    if ($old !== null && $old !== $settings['resolver']) {
        uu_log("resolver changed from $old to {$settings['resolver']}: undoing the route and forwarders of $old "
            . 'first');
        $previous = $settings;
        $previous['resolver'] = $old;
        uu_evaluate_once($previous, [], UU_STOP_RESOLVER);
        $st = uu_state_load(UU_STATE_PATH);
        if ($st['resolver'] === $old) {
            uu_log("the route or forwarders of $old could not be undone: {$settings['resolver']} waits for the next "
                . 'evaluation', LOG_ERR);
            return 1;
        }
        uu_state_save(UU_STATE_PATH, uu_state_forget_resolver($st));
    }
    uu_evaluate_once($settings, $named, $stop);
    return 0;
}

/**
 * Snapshot, the rules' verification saved when this run made one, plan, apply, the counting table's upkeep and
 * blocked-count line, save, then the switch notification when the run switched (section 3.11), for one set of
 * settings. A stop never lists the ruleset: it plans without the contract, and the filter reload it ends with
 * changes the checksum anyway; the stop for a replaced resolver address would also verify the rules against an
 * address they are no longer rendered for and save that verdict under the live checksum.
 *
 * @param array{enabled: bool, dry_run: bool, group: string, resolver: string, failback_delay: int,
 *     probe_name: string} $settings
 * @param list<string> $named
 * @param ?string $stop a UU_STOP_* cause, or null for an evaluation
 */
function uu_evaluate_once(array $settings, array $named, ?string $stop): void
{
    $s = uu_snapshot($settings, $named, $stop, $stop === null);
    if ($s['rules']['record'] !== null) {
        try {
            uu_rules_record_save(UU_RULES_PATH, $s['rules']['record']);
        } catch (\RuntimeException $e) {
            uu_log('rules: the verification could not be saved (' . $e->getMessage() . '): the next evaluation '
                . 'lists the ruleset again', LOG_WARNING);
        }
    }
    $st = uu_state_load(UU_STATE_PATH);
    $table = uu_block_table_view($s['block_table']['table'], $s['block_table']['addresses'], $settings['resolver'],
        $st['resolver']);
    $previousSwitch = $st['last_switch'];
    $s = uu_route_adopt($s, $st['route_installed']);
    $s = uu_wait_control($s, $st['mode']);
    $p = uu_plan($s, $st);
    $st = uu_apply($p, $s, uu_live_io(UU_STATE_PATH));

    $blocked = null;
    if (uu_plan_stop_reason($s) === null) {
        /* the removal marker can appear while this run holds the lock: a deinstall's remove waits for it */
        if ($table['fill'] && !is_file(UU_REMOVING_PATH)) {
            uu_block_table_fill($settings['resolver']);
        }
        $blocked = $table['blocked'];
        $line = uu_blocked_line($st['blocked'], $blocked);
        if ($line !== null) {
            uu_log($line, LOG_NOTICE);
        }
    }
    $st['blocked'] = $blocked;
    uu_state_save(UU_STATE_PATH, $st);
    if (uu_notify_due($previousSwitch, $st['last_switch'])) {
        uu_notify_switch($st);
    }
}

/**
 * Section 3.6c: put the resolver back into the counting table, which the rules reference but which does not hold
 * exactly the resolver (a boot, a flush from Diagnostics, the first reload after enabling). The plugin's only pf
 * write, and in dry run too: the table is the counting block's upkeep, and the rules are rendered in dry run.
 */
function uu_block_table_fill(string $resolver): void
{
    if (filter_var($resolver, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
        return;
    }
    $out = [];
    $rc = 0;
    exec('/sbin/pfctl -t ' . escapeshellarg(UU_BLOCK_TABLE) . ' -T replace ' . escapeshellarg($resolver)
        . ' 2>/dev/null', $out, $rc);
    if ($rc === 0) {
        uu_log("rules: the counting table holds $resolver again", LOG_NOTICE);
    } else {
        uu_log("rules: the counting table could not be filled with $resolver (pfctl exit $rc): blocked packets are "
            . 'not counted until it is', LOG_WARNING);
    }
}

/**
 * Section 3.10: right after a start Unbound's control socket accepts before its workers serve it, so a silent
 * channel with a live pid is retried for up to UU_CONTROL_WAIT_SECONDS before the planner sees it as silent. Not
 * while the run is a stop (uu_plan_stop_reason) and has nothing live to undo.
 *
 * @param array{now: int, wall: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, failback_delay: int,
 *         probe_name: string},
 *     trigger: string, tiers: list<list<string>>,
 *     members: array<string, array{name: string, interface: string, if: string, next_hop: string, disabled: bool,
 *         force_down: bool, monitor_disable: bool, monitor: string, time_period: int, interval: int,
 *         loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>, stop: ?string,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool},
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, resolver_is_monitor: list<string>, resolver_in_static: list<string>,
 *         unmonitored_members: list<string>, foreign_route: bool, rules: array{state: string, problems: list<string>},
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int},
 *     rules: array{state: string, problems: list<string>, verified_at: ?int,
 *         record: ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>}},
 *     block_table: array{counting: bool, table: ?array{addresses: int, references: int, out_block: int},
 *         addresses: list<string>}} $s
 * @param string $mode the saved state's mode
 * @return array{now: int, wall: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, failback_delay: int,
 *         probe_name: string},
 *     trigger: string, tiers: list<list<string>>,
 *     members: array<string, array{name: string, interface: string, if: string, next_hop: string, disabled: bool,
 *         force_down: bool, monitor_disable: bool, monitor: string, time_period: int, interval: int,
 *         loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>, stop: ?string,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool},
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, resolver_is_monitor: list<string>, resolver_in_static: list<string>,
 *         unmonitored_members: list<string>, foreign_route: bool, rules: array{state: string, problems: list<string>},
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int},
 *     rules: array{state: string, problems: list<string>, verified_at: ?int,
 *         record: ?array{checksum: string, inputs: string, at: int, loaded: bool, problems: list<string>}},
 *     block_table: array{counting: bool, table: ?array{addresses: int, references: int, out_block: int},
 *         addresses: list<string>}}
 */
function uu_wait_control(array $s, string $mode): array
{
    $u = $s['unbound'];
    if ($u['control_ok'] || !$u['pid_alive'] || (uu_plan_stop_reason($s) !== null && $mode !== 'tunnel')) {
        return $s;
    }
    $deadline = hrtime(true) + UU_CONTROL_WAIT_SECONDS * 1000000000;
    while (hrtime(true) < $deadline) {
        sleep(1);
        $live = uu_live_root();
        if ($live !== null) {
            $s['unbound']['control_ok'] = true;
            $s['unbound']['live_root'] = $live;
            break;
        }
    }
    return $s;
}

function uu_status_main(): int
{
    $settings = uu_settings();
    $st = uu_state_load(UU_STATE_PATH);
    /* never lists the ruleset (section 3.6c): the checksum and the counting table only */
    $s = uu_route_adopt(uu_snapshot($settings, [], null, false), $st['route_installed']);
    $p = uu_plan($s, $st);
    $table = uu_block_table_view($s['block_table']['table'], $s['block_table']['addresses'], $settings['resolver'],
        $st['resolver']);
    $route = filter_var($settings['resolver'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false ? ''
        : (string)shell_exec('/sbin/route -n get -inet ' . escapeshellarg($settings['resolver']) . ' 2>/dev/null');
    $doc = uu_status_doc($s, $p, $table, $route);
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
    /* lists the ruleset when no verification of the live checksum is saved, as an evaluation would, so a replay
     * plans on the same verdict; the verification is not saved (record changes nothing) */
    $doc = ['snapshot' => uu_snapshot(uu_settings(), [], null, true), 'state' => uu_state_load(UU_STATE_PATH)];
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
    $keys = ['now', 'wall', 'settings', 'trigger', 'tiers', 'members', 'probes', 'named', 'stop', 'unbound', 'zone',
             'route', 'fib_sync_ms', 'contract_input', 'rules', 'block_table'];
    /* the snapshot is evaluate.php record's own output: its top-level shape is checked, not every field */
    if (!is_array($doc) || !is_array($doc['snapshot'] ?? null) || array_keys($doc['snapshot']) !== $keys
        || !is_array($doc['state'] ?? null)) {
        throw new RuntimeException("$path is not a snapshot and state written by evaluate.php record");
    }
    $st = uu_state_from_doc($doc['state']);
    if ($st === null) {
        echo "the recorded state is not this version's shape: planning from a fresh state\n";
        $st = uu_state_new();
    }
    $s = uu_route_adopt($doc['snapshot'], $st['route_installed']);
    $p = uu_plan($s, $st);
    uu_apply_preview($p, $s, function (string $msg, int $prio): void {
        echo $msg, "\n";
    });
    echo json_encode(['plan' => $p], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), "\n";
    return 0;
}
