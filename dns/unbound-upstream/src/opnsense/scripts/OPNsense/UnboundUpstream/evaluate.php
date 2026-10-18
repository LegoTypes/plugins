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
 *   evaluate.php stop                 leave tunnel mode and delete the resolver's route, whatever the settings say
 *                                     (Save with enabled off, the package's deinstall)
 *   evaluate.php status               the section 3.8 JSON for the page; read-only and without the lock
 *   evaluate.php selftest             the pure suites, from a source tree (the package carries no tests)
 *   evaluate.php record FILE          write the live snapshot and the saved state to FILE; changes nothing
 *   evaluate.php replay FILE          plan from a recorded FILE and print every step apply would run; changes nothing
 * evaluate and stop run under the evaluate lock, waiting up to UU_LOCK_WAIT_SECONDS for an evaluation in flight, so
 * a trigger that arrives meanwhile runs after it instead of being dropped. Every failure is logged and exits
 * non-zero; nothing is thrown into configd.
 */

const UU_RUN_DIR = '/var/run/unboundupstream';
const UU_STATE_PATH = UU_RUN_DIR . '/state.json';
const UU_LOCK_PATH = UU_RUN_DIR . '/evaluate.lock';

require_once __DIR__ . '/lib/constants.php';
require_once __DIR__ . '/lib/state.php';
require_once __DIR__ . '/lib/planner.php';
require_once __DIR__ . '/lib/snapshot.php';
require_once __DIR__ . '/lib/apply.php';
require_once __DIR__ . '/lib/log.php';

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
    if (!in_array($mode, ['evaluate', 'stop', 'status', 'selftest', 'record', 'replay'], true)) {
        /* `evaluate.php NAMES`: the one argument is the names list */
        if (count($args) > 1) {
            fwrite(STDERR, "usage: evaluate.php [evaluate] [NAMES] | stop | status | selftest | record FILE | replay FILE\n");
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
        case 'stop':
            return uu_with_lock(fn (): int => uu_evaluate(true, []));
        default:
            return uu_with_lock(fn (): int => uu_evaluate(false, uu_names($args[1] ?? '')));
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
 * Run fn under the evaluate lock: exclusive, blocking up to UU_LOCK_WAIT_SECONDS, never dropping a trigger at
 * once. The lock is close-on-exec, so a child (configctl unbound restart) never holds it.
 *
 * @param callable(): int $fn
 */
function uu_with_lock(callable $fn): int
{
    if (!is_dir(UU_RUN_DIR) && !mkdir(UU_RUN_DIR, 0700, true) && !is_dir(UU_RUN_DIR)) {
        throw new RuntimeException('cannot create ' . UU_RUN_DIR);
    }
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
 * One evaluation: snapshot, plan, apply, the blocked-count line, save. stop plans as if disabled. The settings
 * are read under the lock, so an evaluation that waited for it acts on the last Save.
 *
 * @param list<string> $named
 */
function uu_evaluate(bool $stopping, array $named): int
{
    $settings = uu_settings();
    $s = uu_snapshot($settings, $named);
    $st = uu_state_load(UU_STATE_PATH);
    $s = uu_route_adopt($s, $st['route_installed']);
    if ($stopping) {
        $s['settings']['enabled'] = false;
    }
    $s = uu_wait_control($s, $st['mode']);
    $p = uu_plan($s, $st);
    $st = uu_apply($p, $s, uu_live_io());

    $blocked = null;
    if ($s['settings']['enabled']) {
        $blocked = uu_pf_label_packets((string)shell_exec('/sbin/pfctl -vsr 2>/dev/null'))[uu_label_block()] ?? null;
        $line = uu_blocked_line($st['blocked'], $blocked);
        if ($line !== null) {
            uu_log($line, LOG_NOTICE);
        }
    }
    $st['blocked'] = $blocked;
    uu_state_save(UU_STATE_PATH, $st);
    return 0;
}

/**
 * Section 3.10: right after a start Unbound's control socket accepts before its workers serve it, so a silent
 * channel with a live pid is retried for up to UU_CONTROL_WAIT_SECONDS before the planner sees it as silent. Not
 * while the plugin is disabled and has nothing live to undo.
 *
 * @param array{now: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, failback_delay: int,
 *         probe_name: string},
 *     trigger: string, tiers: list<list<string>>,
 *     members: array<string, array{name: string, interface: string, if: string, next_hop: string, disabled: bool,
 *         force_down: bool, monitor_disable: bool, monitor: string, time_period: int, interval: int,
 *         loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool},
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, resolver_is_monitor: list<string>, resolver_in_static: list<string>,
 *         unmonitored_members: list<string>, foreign_route: bool,
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int}} $s
 * @param string $mode the saved state's mode
 * @return array{now: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, failback_delay: int,
 *         probe_name: string},
 *     trigger: string, tiers: list<list<string>>,
 *     members: array<string, array{name: string, interface: string, if: string, next_hop: string, disabled: bool,
 *         force_down: bool, monitor_disable: bool, monitor: string, time_period: int, interval: int,
 *         loss_interval: int, losshigh: int}>,
 *     probes: array<string, array{status: string, loss: string, sock_age: ?int, cached: ?string}>,
 *     named: list<string>,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool},
 *     fib_sync_ms: ?int,
 *     contract_input: array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *         status_fields: bool, resolver_is_monitor: list<string>, resolver_in_static: list<string>,
 *         unmonitored_members: list<string>, foreign_route: bool,
 *         zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *         fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int}}
 */
function uu_wait_control(array $s, string $mode): array
{
    $u = $s['unbound'];
    if ($u['control_ok'] || !$u['pid_alive'] || !($s['settings']['enabled'] || $mode === 'tunnel')) {
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
    $s = uu_route_adopt(uu_snapshot($settings, []), $st['route_installed']);
    $p = uu_plan($s, $st);
    $route = filter_var($settings['resolver'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false ? ''
        : (string)shell_exec('/sbin/route -n get -inet ' . escapeshellarg($settings['resolver']) . ' 2>/dev/null');
    $doc = uu_status_doc($s, $p, (string)shell_exec('/sbin/pfctl -vsr 2>/dev/null'), $route);
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
    $doc = ['snapshot' => uu_snapshot(uu_settings(), []), 'state' => uu_state_load(UU_STATE_PATH)];
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
    $keys = ['now', 'settings', 'trigger', 'tiers', 'members', 'probes', 'named', 'unbound', 'zone', 'route',
             'fib_sync_ms', 'contract_input'];
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
