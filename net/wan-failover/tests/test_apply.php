<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Apply order and failure handling with fake I/O.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/apply.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/pfstate.php';

/**
 * Every fake I/O's call list made so far, for checks across all of the suite's cases.
 *
 * @return list<ArrayObject>
 */
function wf_t_io_made(?ArrayObject $calls = null): array
{
    static $made = [];
    if ($calls !== null) {
        $made[] = $calls;
    }
    return $made;
}

/**
 * @param array<string, string> $configd action => result
 * @param list<array<string, string>> $statusSeq successive status() results; the last repeats
 * @return array{io: array, calls: ArrayObject}
 */
function wf_t_io(array $configd = [], bool $lock = true, bool $write = true, array $pfs = [], ?string $default = '203.0.113.1@vtnet1', array $statusSeq = []): array
{
    $calls = new ArrayObject();
    wf_t_io_made($calls);
    $pfQueue = new ArrayObject($pfs);
    $stQueue = new ArrayObject($statusSeq !== [] ? $statusSeq : [['WAN_B' => 'force_down', 'WAN_A' => 'none']]);
    $next = function (ArrayObject $q): array {
        $a = $q->getArrayCopy();
        $v = $a[0];
        if (count($a) > 1) {
            array_shift($a);
            $q->exchangeArray($a);
        }
        return $v;
    };
    $io = [
        'configd' => function (string $a, array $p) use ($calls, $configd): string {
            $calls[] = trim("configd {$a} " . implode(' ', $p));
            return $configd[$a] ?? ($a === 'filter kill state' ? 'killed 1 states' : 'OK');
        },
        'write' => function (array $c, array $expected, array $recordsAfter) use ($calls, $write): array {
            $calls[] = 'write ' . json_encode($c) . ' held=' . implode(',', array_keys($recordsAfter));
            return $write ? wf_t_written() : wf_t_written('config write failed: the fake write', LOG_ERR);
        },
        'gw_lock' => function () use ($calls, $lock): bool {
            $calls[] = 'lock';
            return $lock;
        },
        'gw_unlock' => function () use ($calls): void {
            $calls[] = 'unlock';
        },
        'status' => fn (): array => $next($stQueue),
        'pf' => fn (): array => $next($pfQueue),
        'live_default' => fn (): ?string => $default,
        'save_state' => function (array $s) use ($calls): void {
            $calls[] = 'save';
        },
        'sleep' => fn (int $s): int => 0,
        'log' => function (string $m, int $prio = LOG_NOTICE) use ($calls): void {
            $calls[] = $prio === LOG_NOTICE ? "log {$m}" : "log({$prio}) {$m}";
        },
        'crash_point' => fn (string $p): int => 0,
    ];
    return ['io' => $io, 'calls' => $calls];
}

/**
 * What the writer answers (wf_write_holds()): a write that landed, or one that did not and why.
 *
 * @param list<string> $skipped
 * @return array{ok: bool, skipped: list<string>, problem: ?string, prio: int}
 */
function wf_t_written(?string $problem = null, int $prio = LOG_NOTICE, array $skipped = []): array
{
    return ['ok' => $problem === null, 'skipped' => $skipped, 'problem' => $problem, 'prio' => $prio];
}

/** @return array{hold: list<string>, release: list<string>, held_after: list<string>, records_after: array<string, array{boot: string, since: int}>, expected: array<string, bool>, held_now: list<string>, write: bool, redo_apply: list<string>, redo_replay: list<string>, foreign: list<string>, kill_targets: list<string>, failback: array<string, array{top: bool}>, expected_default: ?string, alerts: list<string>, log: list<string>, acting: bool, stopped: bool} */
function wf_t_plan(array $over = []): array
{
    return array_merge(['hold' => [], 'release' => [], 'held_after' => [], 'records_after' => [], 'expected' => [], 'held_now' => [],
                        'write' => false, 'redo_apply' => [],
                        'redo_replay' => [], 'foreign' => [], 'kill_targets' => [], 'failback' => [],
                        'expected_default' => null, 'alerts' => [], 'log' => [], 'acting' => true, 'stopped' => false,
                        'legacy_held' => []], $over);
}

wf_register_suite('apply', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $snap = ['now' => 1000, 'release' => null, 'tailscale_restart' => false,
             'wans' => ['WAN_A' => ['gateway_ip' => '203.0.113.1', 'route_target' => '203.0.113.1@vtnet1'],
                       'WAN_B' => ['gateway_ip' => '198.51.100.254', 'route_target' => '198.51.100.254@vtnet2']]];
    $state = wf_state_new('b1');
    $plan = wf_t_plan(['hold' => ['WAN_B'], 'held_after' => ['WAN_B'], 'records_after' => ['WAN_B' => ['boot' => 'b1', 'since' => 1000]],
                       'expected' => ['WAN_B' => false], 'write' => true, 'kill_targets' => ['198.51.100.254@vtnet2']]);

    $f = wf_t_io();
    $r = wf_apply($plan, $state, $snap, $f['io']);
    $c = $f['calls']->getArrayCopy();
    wf_check($t, 'hold: save pending, lock, one write with held, routes configure, unlock, replay, kill', array_slice($c, 0, 7) === [
        'save', 'lock', 'write {"WAN_B":true} held=WAN_B', 'configd interface routes configure', 'unlock',
        'configd wanfailover replay_alarm WAN_B', 'configd wanfailover kill_states 198.51.100.254@vtnet2']);
    wf_check($t, 'hold: apply_pending cleared, last_held set', $r['ok'] && $r['state']['apply_pending'] === [] && $r['state']['last_held'] === ['WAN_B']);

    $f = wf_t_io([], true, true, [], '203.0.113.1', [['WAN_B' => 'none', 'WAN_A' => 'none'], ['WAN_B' => 'force_down', 'WAN_A' => 'down']]);
    wf_apply($plan, $state, $snap, $f['io']);
    wf_check($t, 'a gateway whose status changed during our hold is replayed with ours, so core settles it after our reconfigure too',
        in_array('configd wanfailover replay_alarm WAN_A,WAN_B', $f['calls']->getArrayCopy(), true));

    $f = wf_t_io(['wanfailover replay_alarm' => 'Execute error']);
    $r = wf_apply($plan, $state, $snap, $f['io']);
    wf_check($t, 'replay fails -> apply_pending kept for the next tick, no kill', $r['state']['apply_pending'] === ['WAN_B' => 'hold']
        && !in_array('configd wanfailover kill_states 198.51.100.254@vtnet2', $f['calls']->getArrayCopy(), true));

    $f = wf_t_io(['wanfailover kill_states' => "killed 2 states (0 failed)\n"]);
    wf_apply(array_merge($plan, ['kill_targets' => ['192.0.2.1@vtnet1']]), $state, $snap, $f['io']);
    $c = $f['calls']->getArrayCopy();
    $replayAt = array_search('configd wanfailover replay_alarm WAN_B', $c, true);
    $killAt = array_search('configd wanfailover kill_states 192.0.2.1@vtnet1', $c, true);
    wf_check($t, '(a1) after the replay, the hold kills through the plugin\'s own action by gateway@interface, and logs its answer',
        $replayAt !== false && $killAt !== false && $killAt > $replayAt
        && in_array('log kill states via 192.0.2.1@vtnet1: killed 2 states (0 failed)', $c, true));
    $f = wf_t_io(['wanfailover kill_states' => "listing failed: pfctl exited 1\n"]);
    $r = wf_apply(array_merge($plan, ['kill_targets' => ['192.0.2.1@vtnet1']]), $state, $snap, $f['io']);
    wf_check($t, '(a2) a kill whose listing failed is logged as the kill line at warning, and the hold stands',
        in_array('log(' . LOG_WARNING . ') kill states via 192.0.2.1@vtnet1: listing failed: pfctl exited 1', $f['calls']->getArrayCopy(), true)
        && $r['ok'] && $r['state']['apply_pending'] === [] && $r['state']['last_held'] === ['WAN_B']);

    $f = wf_t_io([], false);
    $r = wf_apply($plan, $state, $snap, $f['io']);
    wf_check($t, 'gateway lock busy -> not ok, nothing written, pending kept for next tick', !$r['ok']
        && count(array_filter($f['calls']->getArrayCopy(), fn (string $x): bool => str_starts_with($x, 'write'))) === 0
        && $r['state']['apply_pending'] === ['WAN_B' => 'hold'] && $r['problem'] === 'gateway lock busy for 30 s');

    $f = wf_t_io([], true, false);
    $r = wf_apply($plan, $state, $snap, $f['io']);
    wf_check($t, 'write fails -> not ok, unlock still called', !$r['ok'] && in_array('unlock', $f['calls']->getArrayCopy(), true)
        && $r['problem'] === 'config write failed: the fake write' && $r['prio'] === LOG_ERR);

    $f = wf_t_io();
    $r = wf_apply(wf_t_plan(['release' => ['WAN_B'], 'expected' => ['WAN_B' => true], 'write' => true]), $state, $snap, $f['io']);
    wf_check($t, 'release: write with empty held, then replay, pending cleared', in_array('write {"WAN_B":false} held=', $f['calls']->getArrayCopy(), true)
        && $r['state']['apply_pending'] === []);

    $f = wf_t_io();
    $r = wf_apply(wf_t_plan(['foreign' => ['WAN_B'], 'held_now' => ['WAN_B']]), $state, $snap, $f['io']);
    $c = $f['calls']->getArrayCopy();
    wf_check($t, 'a change outside the engine -> routes configure under the lock, then replay; no write; last_held follows config',
        in_array('configd interface routes configure', $c, true) && in_array('configd wanfailover replay_alarm WAN_B', $c, true)
        && count(array_filter($c, fn (string $x): bool => str_starts_with($x, 'write'))) === 0 && $r['state']['last_held'] === ['WAN_B']);

    $states = wf_parse_states((string)file_get_contents(__DIR__ . '/fixtures/states.txt'));
    $rules = wf_parse_rules((string)file_get_contents(__DIR__ . '/fixtures/rules.txt'));
    $flows = wf_flows($states, ['203.0.113.1@vtnet1' => 'WAN_A', '198.51.100.254@vtnet2' => 'WAN_B']);
    $pref = ['22222222-2222-4222-8222-222222222222' => ['WAN_B'], '33333333-3333-4333-8333-333333333333' => []];
    $pfStale = ['flows' => $flows, 'renderings' => $rules, 'pinned' => ['198.51.100.200' => true], 'rule_pref' => $pref,
                'default' => 'WAN_B', 'selfcheck' => true, 'drift' => [], 'raw_states' => '', 'raw_rules' => ''];
    $pfMoved = array_merge($pfStale, ['default' => 'WAN_A']);
    $fb = wf_state_new('b1');
    $fb['pending_failbacks']['WAN_A'] = ['since' => 990];
    $f = wf_t_io([], true, true, [$pfStale, $pfMoved]);
    $r = wf_apply(wf_t_plan(['failback' => ['WAN_A' => ['top' => true]]]), $fb, $snap, $f['io']);
    $c = $f['calls']->getArrayCopy();
    wf_check($t, 'failback: stale default -> replay, recheck, kill once moved, pending cleared',
        in_array('configd wanfailover replay_alarm WAN_A', $c, true)
        && in_array('configd filter kill state 33f6d16a00000000 4a28027f', $c, true)
        && !isset($r['state']['pending_failbacks']['WAN_A']));
    $f = wf_t_io([], true, true, [array_merge($pfMoved, ['selfcheck' => false])]);
    $r = wf_apply(wf_t_plan(['failback' => ['WAN_A' => ['top' => true]]]), $fb, $snap, $f['io']);
    wf_check($t, 'failback: pf self-check failed -> suspended, nothing killed, still pending',
        count(array_filter($f['calls']->getArrayCopy(), fn (string $x): bool => str_starts_with($x, 'configd filter kill state'))) === 0
        && isset($r['state']['pending_failbacks']['WAN_A']));
    $f = wf_t_io([], true, true, [array_merge($pfMoved, ['drift' => ['x']])]);
    $r = wf_apply(wf_t_plan(['failback' => ['WAN_A' => ['top' => true]]]), $fb, $snap, $f['io']);
    $c = $f['calls']->getArrayCopy();
    wf_check($t, "failback: a contract drift on the gate's read suspends it, kills nothing and keeps it pending",
        in_array('log failback WAN_A: x (core contract); failback suspended', $c, true)
        && array_filter($c, fn (string $x): bool => str_starts_with($x, 'configd filter kill state')
            || str_starts_with($x, 'configd wanfailover replay_alarm')) === []
        && isset($r['state']['pending_failbacks']['WAN_A']));
    $f = wf_t_io([], true, true, [$pfStale, array_merge($pfMoved, ['drift' => ['x']])]);
    $r = wf_apply(wf_t_plan(['failback' => ['WAN_A' => ['top' => true]]]), $fb, $snap, $f['io']);
    $c = $f['calls']->getArrayCopy();
    wf_check($t, 'failback: a contract drift on the read after the alarm replay kills nothing, says so once and keeps it pending',
        in_array('configd wanfailover replay_alarm WAN_A', $c, true)
        && array_values(array_filter($c, fn (string $x): bool => str_starts_with($x, 'log failback')))
            === ['log failback WAN_A: x (core contract); failback suspended']
        && array_filter($c, fn (string $x): bool => str_starts_with($x, 'configd filter kill state')) === []
        && isset($r['state']['pending_failbacks']['WAN_A']));
    $f = wf_t_io([], true, true, [$pfStale, array_merge($pfMoved, ['selfcheck' => false])]);
    $r = wf_apply(wf_t_plan(['failback' => ['WAN_A' => ['top' => true]]]), $fb, $snap, $f['io']);
    $c = $f['calls']->getArrayCopy();
    wf_check($t, 'failback: a state listing that does not parse on the read after the alarm replay kills nothing, says so once '
        . 'and keeps it pending',
        in_array('configd wanfailover replay_alarm WAN_A', $c, true)
        && array_values(array_filter($c, fn (string $x): bool => str_starts_with($x, 'log failback')))
            === ['log failback WAN_A: pf state format did not parse (core contract); failback suspended']
        && array_filter($c, fn (string $x): bool => str_starts_with($x, 'configd filter kill state')) === []
        && isset($r['state']['pending_failbacks']['WAN_A']));
    $f = wf_t_io([], true, true, [array_merge($pfMoved, ['selfcheck' => false, 'drift' => ['x', 'y']])]);
    $r = wf_apply(wf_t_plan(['failback' => ['WAN_A' => ['top' => true]]]), $fb, $snap, $f['io']);
    wf_check($t, 'failback: a contract drift and a state listing that does not parse on one read are said in one line, the '
        . 'drift first',
        array_values(array_filter($f['calls']->getArrayCopy(), fn (string $x): bool => str_starts_with($x, 'log failback')))
            === ['log failback WAN_A: x; y; pf state format did not parse (core contract); failback suspended']
        && isset($r['state']['pending_failbacks']['WAN_A']));

    $ts = wf_state_new('b1');
    $ts['ts'] = ['default_gw' => '198.51.100.254@vtnet2', 'restarted_at' => null, 'cur_default' => '198.51.100.254@vtnet2', 'cur_since' => 1,
                 'lost' => false, 'expected_default' => null];
    $f = wf_t_io([], true, true, [], '203.0.113.1@vtnet1');
    $r = wf_apply(wf_t_plan(['expected_default' => '203.0.113.1@vtnet1', 'acting' => false]), $ts, array_merge($snap, ['tailscale_restart' => true]), $f['io']);
    wf_check($t, 'tailscale: planned default change restarts through configd', in_array('configd tailscale restart', $f['calls']->getArrayCopy(), true)
        && $r['state']['ts']['default_gw'] === '203.0.113.1@vtnet1');
    $f = wf_t_io();
    wf_apply(wf_t_plan(['write' => true, 'held_after' => [], 'held_now' => ['GONE']]), wf_state_new('b1'), $snap, $f['io']);
    $c = $f['calls']->getArrayCopy();
    wf_check($t, 'a prune-only write saves but does not reconfigure routing (no dpinger restarts)',
        count(array_filter($c, fn (string $x): bool => str_starts_with($x, 'write'))) === 1
        && !in_array('configd interface routes configure', $c, true));

    $fb = wf_state_new('b1');
    $fb['pending_failbacks']['WAN_A'] = ['since' => 990];
    $f = wf_t_io(['filter kill state' => 'pfctl: DIOCKILLSTATES: Operation not permitted'], true, true, [$pfMoved]);
    wf_apply(wf_t_plan(['failback' => ['WAN_A' => ['top' => true]]]), $fb, $snap, $f['io']);
    wf_check($t, 'failback kill results are read: failed kills are reported, not counted as killed',
        count(array_filter($f['calls']->getArrayCopy(), fn (string $x): bool => str_contains($x, '0 states killed') && str_contains($x, 'failed'))) === 1);

    $ts = wf_state_new('b1');
    $ts['ts'] = ['default_gw' => '198.51.100.254@vtnet2', 'restarted_at' => null, 'cur_default' => '198.51.100.254@vtnet2', 'cur_since' => 990,
                 'lost' => false, 'expected_default' => null];
    $f = wf_t_io([], true, true, [], '203.0.113.1@vtnet1');
    $r = wf_apply(wf_t_plan(['acting' => false]), $ts, array_merge($snap, ['tailscale_restart' => true]), $f['io']);
    $f2 = wf_t_io([], true, true, [], '203.0.113.1@vtnet1');
    wf_apply(wf_t_plan(['acting' => false]), $r['state'], array_merge($snap, ['tailscale_restart' => true, 'now' => 1010]), $f2['io']);
    wf_check($t, 'a tailscale deferral is logged once, not every tick',
        count(array_filter($f2['calls']->getArrayCopy(), fn (string $x): bool => str_contains($x, 'tailscale defer'))) === 0);

    $f = wf_t_io();
    $f['io']['write'] = function (array $c, array $expected, array $recordsAfter) use ($f): array {
        $f['calls'][] = 'write ' . json_encode($c);
        return wf_t_written('force_down on WAN_A changed since the snapshot', LOG_NOTICE, ['WAN_A']);
    };
    $r = wf_apply(wf_t_plan(['hold' => ['WAN_A'], 'held_after' => ['WAN_A'], 'records_after' => ['WAN_A' => ['boot' => 'b1', 'since' => 1000]],
                             'expected' => ['WAN_A' => false], 'write' => true, 'kill_targets' => ['192.0.2.1@vtnet1']]), $state, $snap, $f['io']);
    $c = $f['calls']->getArrayCopy();
    wf_check($t, '(x1) a write skipped because force_down moved since the snapshot says so as its problem, keeps the pending '
        . 'hold, and runs neither the routing reconfigure, the replay nor a kill; the caller logs the problem, not apply',
        !$r['ok'] && $r['state']['apply_pending'] === ['WAN_A' => 'hold']
        && $r['problem'] === 'force_down on WAN_A changed since the snapshot'
        && array_filter($c, fn (string $x): bool => str_starts_with($x, 'log')) === []
        && !in_array('configd interface routes configure', $c, true)
        && array_filter($c, fn (string $x): bool => str_starts_with($x, 'configd wanfailover ')) === []
        && in_array('unlock', $c, true));

    $got = new ArrayObject();
    $f = wf_t_io();
    $f['io']['write'] = function (array $c, array $expected, array $recordsAfter) use ($got): array {
        $got[] = [$c, $expected, $recordsAfter];
        return wf_t_written();
    };
    $records = ['WAN_B' => ['boot' => 'b500', 'since' => 200], 'WAN_A' => ['boot' => 'b500', 'since' => 1000]];
    $wPlan = wf_t_plan(['hold' => ['WAN_A'], 'release' => ['WAN_C'], 'held_after' => ['WAN_B', 'WAN_A'], 'records_after' => $records,
                        'expected' => ['WAN_A' => false, 'WAN_C' => true], 'write' => true]);
    $r = wf_apply($wPlan, $state, $snap, $f['io']);
    wf_check($t, '(x2) the writer is handed the plan\'s changes, expected force_down and records after, as the plan has them',
        $r['ok'] && $got->getArrayCopy() === [[['WAN_A' => true, 'WAN_C' => false], $wPlan['expected'], $wPlan['records_after']]]);

    $f = wf_t_io();
    $s = wf_state_new('b500');
    $s['apply_pending'] = ['WAN_B' => 'hold'];
    $r = wf_apply(wf_t_plan(['redo_replay' => ['WAN_A']]), $s, $snap, $f['io']);
    wf_check($t, '(x3) a pending apply that no plan step handled (kept while kern.boot_id is unreadable) survives the apply; '
        . 'the one it resumed is finished', $r['ok'] && $r['state']['apply_pending'] === ['WAN_B' => 'hold']);

    $f = wf_t_io([], true, true, [$pfStale]);
    $r = wf_apply(wf_t_plan(['redo_replay' => ['WAN_B', 'x;y'], 'failback' => ['x;y' => ['top' => true]]]), $state, $snap, $f['io']);
    $c = $f['calls']->getArrayCopy();
    $x4 = in_array('configd wanfailover replay_alarm WAN_B', $c, true)
        && array_filter($c, fn (string $x): bool => str_starts_with($x, 'configd ') && str_contains($x, 'x;y')) === []
        && count(array_filter($c, fn (string $x): bool => $x === 'log replay skipped for an invalid gateway name')) === 1
        && count(array_filter($c, fn (string $x): bool => str_starts_with($x, 'configd wanfailover replay_alarm'))) === 2;
    wf_check($t, '(x4) a gateway name that is not plain never reaches an alarm replay, and is said once for the whole apply, '
        . 'across the hold\'s replay and the failback\'s', $x4);
    if (!$x4) {
        printf("    calls: %s\n", json_encode($c));
    }

    $f = wf_t_io();
    $s = wf_state_new('b500');
    $s['last_held'] = ['WAN_B', 'WAN_C'];
    $r = wf_apply(wf_t_plan(['hold' => ['WAN_A'], 'held_after' => ['WAN_A'], 'records_after' => ['WAN_A' => ['boot' => 'b500', 'since' => 1000]],
                             'expected' => ['WAN_A' => false], 'write' => true, 'legacy_held' => ['WAN_B']]), $s, $snap, $f['io']);
    wf_check($t, '(u4) a write while 1.3_1\'s held list waits to be carried over keeps its proven entry in last_held, and '
        . 'drops what the list does not name', $r['ok'] && $r['state']['last_held'] === ['WAN_A', 'WAN_B']);

    $line = [LOG_NOTICE, 'hold of WAN_B carried over, taken in boot b500'];
    $a = wf_legacy_import_attempt(fn (): array => ['import' => true, 'lines' => [$line]]);
    wf_check($t, '(m6) an import that decided to import and completed is imported: the migration may drop the raw list',
        $a === ['imported' => true, 'lines' => [$line], 'error' => null]);
    $a = wf_legacy_import_attempt(fn (): array => ['import' => false, 'lines' => []]);
    wf_check($t, '(m6) an import that found no list is not imported: nothing to drop',
        $a === ['imported' => false, 'lines' => [], 'error' => null]);
    $warn = [LOG_WARNING, "kern.boot_id cannot be read, so 1.3_1's held list stays in the config until it can"];
    $a = wf_legacy_import_attempt(fn (): array => ['import' => false, 'lines' => [$warn]]);
    wf_check($t, '(m6) an import that could not read kern.boot_id is not imported, so the list stays, and its line is kept to log',
        $a === ['imported' => false, 'lines' => [$warn], 'error' => null]);
    $added = new ArrayObject();
    $a = wf_legacy_import_attempt(function () use ($added): array {
        $added[] = 'WAN_A';
        throw new TypeError('setNodes(): Argument #1 must be of type array');
    });
    wf_check($t, '(m6) an import that threw part way through (an Error, not only an Exception) is not imported and says why: '
        . 'the raw list stays for the next evaluation',
        count($added) === 1 && !$a['imported'] && $a['lines'] === [] && str_contains((string)$a['error'], 'setNodes()'));

    /* the removal's core commands: configd when its line exits 0, else core's own command */
    $runs = new ArrayObject();
    $stub = function (int $ctl, int $direct) use ($runs): callable {
        return function (string $line) use ($runs, $ctl, $direct): int {
            $runs[] = $line;
            return str_contains($line, 'configctl') ? $ctl : $direct;
        };
    };
    $path = wf_core_command('interface routes configure', WF_CORE_ROUTES_CONFIGURE, $stub(1, 0));
    $lines = $runs->getArrayCopy();
    wf_check($t, '(d1) configd not answering OK: core\'s own command runs after the configctl line, and the path is direct',
        $path === 'direct' && count($lines) === 2
        && str_starts_with($lines[0], '/usr/bin/timeout ' . WF_CONFIGD_TIMEOUT_SECONDS . ' /usr/local/sbin/configctl interface routes configure')
        && str_starts_with($lines[1], WF_CORE_ROUTES_CONFIGURE . ' '));
    $runs->exchangeArray([]);
    $path = wf_core_command('interface routes configure', WF_CORE_ROUTES_CONFIGURE, $stub(0, 0));
    wf_check($t, '(d1) configd answering OK: the path is configd and core\'s own command does not run',
        $path === 'configd' && count($runs) === 1);
    $runs->exchangeArray([]);
    $path = wf_core_command('interface routes configure', WF_CORE_ROUTES_CONFIGURE, $stub(1, 1));
    wf_check($t, '(d1) both failing: the path is failed', $path === 'failed' && count($runs) === 2);

    /* the removal's apply: the base io's configd must never be reached, so every configd call it records is a defect */
    $f = wf_t_io();
    $f['io']['write'] = function (array $c, array $expected, array $recordsAfter, bool $removal = false) use ($f): array {
        $f['calls'][] = 'write ' . json_encode($c) . ' held=' . implode(',', array_keys($recordsAfter)) . ($removal ? ' removal' : '');
        return wf_t_written();
    };
    $run = function (string $line) use ($f): int {
        $f['calls'][] = "run {$line}";
        return 0;
    };
    $dio = wf_deinstall_io($f['io'], $run, true);
    $r = wf_apply(wf_t_plan(['release' => ['WAN_A'], 'expected' => ['WAN_A' => true], 'write' => true, 'stopped' => true]),
        $state, $snap, $dio);
    $c = $f['calls']->getArrayCopy();
    $at = function (callable $match) use ($c): int {
        foreach ($c as $i => $x) {
            if ($match($x)) {
                return $i;
            }
        }
        return -1;
    };
    $write = $at(fn (string $x): bool => $x === 'write {"WAN_A":false} held= removal');
    $configure = $at(fn (string $x): bool => str_starts_with($x, 'run /usr/bin/timeout ' . WF_CONFIGD_TIMEOUT_SECONDS
        . ' /usr/local/sbin/configctl interface routes configure'));
    $replay = $at(fn (string $x): bool => $x === 'run ' . WF_REPLAY_ALARM_CMD . " 'WAN_A' > /dev/null 2>&1");
    wf_check($t, '(d2) the removal writes as the removal, then reconfigures routing through core, then replays WAN_A\'s alarm '
        . 'with core\'s command run directly',
        $r['ok'] && $write >= 0 && $configure > $write && $replay > $configure && in_array('log deinstall: routing reconfigured through configd', $c, true));
    wf_check($t, '(d2) no call of the removal reaches configd: none of the plugin\'s own actions, and none of core\'s',
        array_filter($c, fn (string $x): bool => str_starts_with($x, 'configd ')) === []);
    $before = count($f['calls']);
    $out = ($dio['configd'])('wanfailover kill_states', ['192.0.2.1@vtnet1']);
    $after = array_slice($f['calls']->getArrayCopy(), $before);
    wf_check($t, '(d2) any other action is refused with one line and never run',
        $out === 'refused' && count($after) === 1 && str_starts_with($after[0], 'log(' . LOG_WARNING . ') deinstall: configd wanfailover kill_states refused'));

    wf_check($t, '(d8) the removal\'s retry: done once the release landed; another try 5 s on while it still starts within 180 s '
        . 'of the removal\'s start; then it gives up',
        wf_deinstall_retry(1000, 1000, true) === 'done' && wf_deinstall_retry(1000, 1181, true) === 'done'
        && wf_deinstall_retry(1000, 1000, false) === 'retry' && wf_deinstall_retry(1000, 1175, false) === 'retry'
        && wf_deinstall_retry(1000, 1176, false) === 'give_up' && wf_deinstall_retry(1000, 1181, false) === 'give_up');

    /* a removal whose first write finds WAN_B's force_down moved: the second try plans from a new snapshot */
    $wan = fn (string $gw, string $if, bool $down): array => ['uuid' => '', 'gateway_ip' => $gw, 'if' => $if,
        'route_target' => "{$gw}@{$if}", 'rank' => 1, 'disabled' => false, 'monitor_disable' => false, 'force_down' => $down,
        'status' => $down ? 'force_down' : 'none', 'present' => true, 'tilde' => false, 'carrier' => true, 'has_ipv4' => true,
        'loss' => 0.0, 'sock_age' => 300, 'losslow' => 10.0, 'losshigh' => 20.0, 'time_period' => 60, 'interval' => 1,
        'loss_interval' => 4];
    $dsnap = fn (int $now, bool $bDown): array => ['now' => $now, 'boot_id' => 'b500', 'release' => null, 'failback_now' => false,
        'enabled' => true, 'dry' => false, 'failback' => true, 'failback_delay' => 0, 'tailscale_restart' => true,
        'default_gw' => '192.0.2.1@vtnet1', 'unresolved' => [], 'holds_stale' => [], 'holds_dupes' => [], 'legacy_held' => [],
        'wans' => ['WAN_A' => $wan('192.0.2.1', 'vtnet1', true), 'WAN_B' => $wan('198.51.100.1', 'vtnet2', $bDown)],
        'holds' => ['WAN_A' => ['boot' => 'b500', 'since' => 900], 'WAN_B' => ['boot' => 'b500', 'since' => 900]],
        'force_down' => ['WAN_A' => true, 'WAN_B' => $bDown], 'contract' => ['judging' => [], 'command' => [], 'tailscale' => []]];
    $snaps = new ArrayObject([$dsnap(2000, true), $dsnap(2005, false)]);
    $reads = new ArrayObject();
    $read = function () use ($snaps, $reads): array {
        $s = $snaps[count($reads)];
        $reads[] = $s['now'];
        return ['snap' => $s, 'loaded' => ['state' => wf_state_new('b500'), 'corrupt' => false, 'problem' => null, 'field' => null]];
    };
    $clock = new ArrayObject([2000]);
    $slept = new ArrayObject();
    $logged = new ArrayObject();
    $sleep = function (int $s) use ($clock, $slept): void {
        $slept[] = $s;
        $clock[0] += $s;
    };
    $logTo = function (string $m, int $prio = LOG_NOTICE) use ($logged): void {
        $logged[] = $prio === LOG_NOTICE ? $m : "({$prio}) {$m}";
    };
    $f = wf_t_io();
    $writes = new ArrayObject();
    $f['io']['write'] = function (array $c, array $expected, array $recordsAfter, bool $removal = false) use ($writes): array {
        $writes[] = [$c, $expected, $removal];
        return count($writes) === 1 ? wf_t_written('force_down on WAN_B changed since the snapshot', LOG_NOTICE, ['WAN_B'])
            : wf_t_written();
    };
    $dio = wf_deinstall_io($f['io'], fn (string $line): int => 0, true);
    $ok = wf_deinstall_run(2000, $read, fn (array $snap): array => $dio, fn (): int => $clock[0], $sleep, $logTo);
    $lg = $logged->getArrayCopy();
    $retries = array_values(array_filter($lg, fn (string $x): bool => str_contains($x, 'retrying')));
    $last = $lg === [] ? '' : $lg[count($lg) - 1];
    wf_check($t, '(d9) a release whose write found force_down moved is tried again 5 s later from a fresh snapshot, as the '
        . 'removal, says why once, and ends "deinstall: released"',
        $ok && $reads->getArrayCopy() === [2000, 2005] && $slept->getArrayCopy() === [5]
        && $writes->getArrayCopy() === [[['WAN_A' => false, 'WAN_B' => false], ['WAN_A' => true, 'WAN_B' => true], true],
                                        [['WAN_A' => false], ['WAN_A' => true], true]]
        && $retries === ['deinstall: the release did not land (force_down on WAN_B changed since the snapshot); retrying every 5 s '
                         . 'for up to 180 s']
        && $last === 'deinstall: released WAN_A');
    if ($last !== 'deinstall: released WAN_A') {
        printf("    reads: %s\n    log: %s\n", json_encode($reads->getArrayCopy()), json_encode($lg));
    }

    $snaps->exchangeArray(array_map(fn (int $n): array => $dsnap($n, true), range(3000, 3200, 5)));
    $reads->exchangeArray([]);
    $clock[0] = 3000;
    $slept->exchangeArray([]);
    $logged->exchangeArray([]);
    $f['io']['write'] = fn (array $c, array $expected, array $recordsAfter, bool $removal = false): array
        => wf_t_written('config write failed: the fake write', LOG_ERR);
    $dio = wf_deinstall_io($f['io'], fn (string $line): int => 0, true);
    $ok = wf_deinstall_run(3000, $read, fn (array $snap): array => $dio, fn (): int => $clock[0], $sleep, $logTo);
    $lg = $logged->getArrayCopy();
    $last = $lg === [] ? '' : $lg[count($lg) - 1];
    $giveUp = '(' . LOG_ERR . ') deinstall: WAN_A,WAN_B still forced down by the plugin after 180 s (config write failed: the '
        . 'fake write): untick Force down on each under System: Gateways: Configuration';
    $retried = array_values(array_filter($lg, fn (string $x): bool => str_contains($x, 'retrying')));
    wf_check($t, '(d9) a release that never lands is tried every 5 s while a try still starts within 180 s, says why once at '
        . 'the writer\'s priority, then one error names the gateways still forced down by the plugin and the fix',
        !$ok && count($reads) === 37 && array_sum($slept->getArrayCopy()) === 180
        && $retried === ['(' . LOG_ERR . ') deinstall: the release did not land (config write failed: the fake write); retrying '
                         . 'every 5 s for up to 180 s'] && $last === $giveUp);
    if ($last !== $giveUp || count($reads) !== 37) {
        printf("    reads: %d, slept: %d s, last line: %s\n", count($reads), array_sum($slept->getArrayCopy()), $last);
    }

    /* the removal's last line says what its release left undone, since no plugin is left afterwards to say it; the lines
     * apply logs through the removal's I/O land in the fake I/O's calls, the removal's own in log */
    $once = function (array $snapNow, callable $write, callable $run, bool $fallback = true) use ($logTo, $logged): array {
        $logged->exchangeArray([]);
        $f = wf_t_io();
        $f['io']['write'] = $write;
        $dio = wf_deinstall_io($f['io'], $run, $fallback);
        wf_deinstall_run($snapNow['now'], fn (): array => ['snap' => $snapNow, 'loaded' => ['state' => wf_state_new('b500'),
            'corrupt' => false, 'problem' => null, 'field' => null]], fn (array $snap): array => $dio, fn (): int => $snapNow['now'],
            fn (int $s): int => 0, $logTo);
        return ['log' => $logged->getArrayCopy(), 'calls' => $f['calls']->getArrayCopy()];
    };
    $landed = fn (array $c, array $expected, array $recordsAfter, bool $removal = false): array => wf_t_written();
    $o = $once($dsnap(4000, false), $landed, fn (string $line): int => str_contains($line, '/usr/local/bin/flock') ? 1 : 0);
    $d10 = in_array('log deinstall: alarm replay failed for WAN_A,WAN_B', $o['calls'], true)
        && array_filter(array_merge($o['log'], $o['calls']), fn (string $x): bool => str_contains($x, 'next tick')) === []
        && end($o['log']) === '(' . LOG_WARNING . ') deinstall: released WAN_A, but the routing re-sync did not complete (see '
            . 'above): apply System: Gateways: Configuration to re-sync routing';
    wf_check($t, '(d10) a removal whose alarm replay failed says so without promising a next tick, and its last line says '
        . 'the release landed but the re-sync did not complete, with the fix', $d10);
    if (!$d10) {
        printf("    log: %s\n    calls: %s\n", json_encode($o['log']), json_encode($o['calls']));
    }
    $o = $once($dsnap(4100, false), $landed, fn (string $line): int => 1);
    wf_check($t, '(d10) a removal whose routing reconfigure failed both ways ends the same way',
        str_starts_with((string)end($o['log']), '(' . LOG_WARNING . ') deinstall: released WAN_A, but the routing re-sync did not complete'));
    $f = wf_t_io(['wanfailover replay_alarm' => 'Execute error']);
    $r = wf_apply(wf_t_plan(['redo_replay' => ['WAN_B']]), $state, $snap, $f['io']);
    wf_check($t, '(d10) an evaluation\'s failed replay still says the next tick resumes it, and is not resynced',
        !$r['resynced'] && $r['ok'] && in_array('log alarm replay failed for WAN_B; resuming next tick', $f['calls']->getArrayCopy(), true));

    $runs = new ArrayObject();
    $o = $once($dsnap(4200, false), $landed, function (string $line) use ($runs): int {
        $runs[] = $line;
        return str_contains($line, 'configctl') ? 1 : 0;
    }, false);
    wf_check($t, '(d11) with core\'s [routes.configure] changed and configd not answering, the removal never runs the copy of '
        . 'core\'s command: one error names the fix, and the release ends saying the re-sync did not complete',
        array_filter($runs->getArrayCopy(), fn (string $x): bool => str_starts_with($x, WF_CORE_ROUTES_CONFIGURE)) === []
        && in_array('log(' . LOG_ERR . ') deinstall: routing reconfigure failed: configd did not answer OK, and core\'s '
            . '[routes.configure] no longer runs ' . WF_CORE_ROUTES_CONFIGURE . ', so that was not run either: apply System: '
            . 'Gateways: Configuration to re-sync routing', $o['calls'], true)
        && str_contains((string)end($o['log']), 'the routing re-sync did not complete'));
    $runs->exchangeArray([]);
    wf_check($t, '(d11) without the fallback, configd not answering OK is skipped, and core\'s own command never runs',
        wf_core_command('interface routes configure', WF_CORE_ROUTES_CONFIGURE, function (string $line) use ($runs): int {
            $runs[] = $line;
            return 1;
        }, false) === 'skipped' && count($runs) === 1);

    $unread = array_merge($dsnap(4300, true), ['boot_id' => '']);
    $o = $once($unread, $landed, fn (string $line): int => 0);
    $leftLine = '(' . LOG_ERR . ') deinstall: WAN_A,WAN_B stay forced down: the plugin cannot prove whether it took those holds '
        . "(kern.boot_id unreadable, or 1.3_1's held list not yet carried over): untick Force down on each under System: "
        . 'Gateways: Configuration if it should carry traffic';
    wf_check($t, '(d12) a removal with kern.boot_id unreadable releases nothing, and its last line names each gateway left '
        . 'forced down and the fix', in_array('deinstall: nothing held', $o['log'], true) && end($o['log']) === $leftLine);
    $pendingList = array_merge($dsnap(4400, true), ['holds' => [], 'legacy_held' => ['WAN_B']]);
    $o = $once($pendingList, $landed, fn (string $line): int => 0);
    wf_check($t, '(d12) a removal while 1.3_1\'s held list waits to be carried over names its forced-down gateway the same way',
        in_array('deinstall: nothing held', $o['log'], true) && str_starts_with((string)end($o['log']),
            '(' . LOG_ERR . ') deinstall: WAN_B stays forced down: the plugin cannot prove whether it took that hold'));

    $every = array_merge(...array_map(fn (ArrayObject $c): array => $c->getArrayCopy(), wf_t_io_made()));
    wf_check($t, '(a1) no apply case runs core\'s kill by gateway address (filter kill gateway_states)',
        $every !== [] && array_filter($every, fn (string $x): bool => str_contains($x, 'filter kill gateway_states')) === []);
    return wf_tally_report('apply', $t);
});
