<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Core's own commands for a removal (spec -04 section 3.2, convention C6): through configd when it answers OK
 * within UU_CONFIGD_TIMEOUT_SECONDS, else the command core's actions file names, run directly (rulings R4, R5, R55).
 * Not the plugin's own configd actions: a removal deletes them. The runner is injected, so the order is testable;
 * uu_core_shell() is the real one.
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/logline.php';
require_once __DIR__ . '/state.php';

/**
 * Run a core configd action, or core's own command for it when configd does not answer. configd has answered a
 * synchronous action only when configctl exits 0 and prints OK (trimmed), as a script action that ran replies:
 * configctl also exits 0 on no reply, a swallowed communication error, "Error (n)", "Action not found" and "Execute
 * error". A detached one (configctl -d) is queued only when configctl exits 0 and prints the job's id, a UUID, which
 * configd sends before it runs anything. configctl exits non-zero with no socket or no connection, and 124 when
 * /usr/bin/timeout kills it. Only configctl's stdout is read, and the timeout bounds it; core's own command writes to
 * /dev/null and only its exit status counts, so a child it leaves running (a daemon a restart starts) cannot hold the
 * runner's pipe open and stall the caller. Core's own command runs synchronously, even for a detached action.
 *
 * @param string $action the configd action, words as configctl takes them ("filter reload")
 * @param string $direct the command core's actions file runs for it (a UU_CORE_* constant)
 * @param callable(string): array{rc: int, out: string} $run runs a shell command line: its exit status and stdout
 * @param bool $detached queue the action (configctl -d) instead of waiting for it
 * @return array{path: string, configd: string, rc: ?int} path is configd, direct, or failed when core's command
 *     exited non-zero too; configd is what configd did, for a log line ('' when it answered); rc is core's
 *     command's exit status, null when it did not run
 */
function uu_core_command(string $action, string $direct, callable $run, bool $detached = false): array
{
    $ctl = $run('/usr/bin/timeout ' . UU_CONFIGD_TIMEOUT_SECONDS . ' /usr/local/sbin/configctl '
        . ($detached ? '-d ' : '') . $action . ' 2> /dev/null');
    $reply = trim($ctl['out']);
    $answered = $detached
        ? preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iD', $reply) === 1
        : $reply === 'OK';
    if ($ctl['rc'] === 0 && $answered) {
        return ['path' => 'configd', 'configd' => '', 'rc' => null];
    }
    if ($ctl['rc'] === 124) {
        $configd = 'did not answer within ' . UU_CONFIGD_TIMEOUT_SECONDS . ' s (configctl exit 124)';
    } elseif ($ctl['rc'] !== 0) {
        $configd = "did not answer (configctl exit {$ctl['rc']})";
    } else {
        $first = trim(explode("\n", $reply)[0]);
        $configd = $first === '' ? 'answered nothing' : "answered '" . substr(uu_log_text($first), 0, 120) . "'";
    }
    $rc = $run($direct . ' > /dev/null 2>&1')['rc'];
    return ['path' => $rc === 0 ? 'direct' : 'failed', 'configd' => $configd, 'rc' => $rc];
}

/**
 * The production runner: the command line through sh, as uu_core_command() wrote it (its redirections included), and
 * what the line leaves on stdout.
 *
 * @return array{rc: int, out: string}
 */
function uu_core_shell(string $cmdline): array
{
    $out = [];
    $rc = 0;
    exec($cmdline, $out, $rc);
    return ['rc' => $rc, 'out' => implode("\n", $out)];
}

/**
 * Unbound's restart, for every stop that restarts and for the silent channel's escalation: core's restart through
 * configd, else core's own command, so a configd that is silent or failing still restarts Unbound onto the root
 * zone the user configured, and a hung one cannot hold the run past the timeout. Logged with the path it took; true
 * when one of the two ran.
 *
 * @param callable(string): array{rc: int, out: string} $run
 * @param callable(string, int): void $log
 */
function uu_unbound_restart(callable $run, callable $log): bool
{
    $r = uu_core_command('unbound restart', UU_CORE_UNBOUND_RESTART, $run);
    switch ($r['path']) {
        case 'configd':
            $log('unbound restart through configd', LOG_NOTICE);
            return true;
        case 'direct':
            $log("unbound restart: configd {$r['configd']}, so core's " . UU_CORE_UNBOUND_RESTART . ' ran directly',
                LOG_WARNING);
            return true;
        default:
            $log("unbound restart failed: configd {$r['configd']}, and core's " . UU_CORE_UNBOUND_RESTART
                . " exited {$r['rc']}", LOG_ERR);
            return false;
    }
}

/**
 * The filter reload an evaluation queues when the footprint it saved changed, so the footprint's block and pass
 * come or go at once: queued through configd, else core's own reload, run directly. Each path is logged with what
 * changed; when neither ran, the rules follow at the next filter reload.
 *
 * @param string $change what changed, for the log line
 * @param callable(string): array{rc: int, out: string} $run
 * @param callable(string, int): void $log
 */
function uu_footprint_reload(string $change, callable $run, callable $log): void
{
    $r = uu_core_command('filter reload', UU_CORE_FILTER_RELOAD, $run, true);
    switch ($r['path']) {
        case 'configd':
            $log("rules: $change: filter reload queued", LOG_NOTICE);
            break;
        case 'direct':
            $log("rules: $change: configd {$r['configd']}, so core's " . UU_CORE_FILTER_RELOAD . ' ran directly',
                LOG_WARNING);
            break;
        default:
            $log("rules: $change, but the filter reload failed: configd {$r['configd']}, and core's "
                . UU_CORE_FILTER_RELOAD . " exited {$r['rc']}: the rules follow at the next filter reload", LOG_ERR);
    }
}

/**
 * What remove runs after its stop (ruling R4): the filter reload, so the rules follow the footprint the stop left,
 * and the cron restart, so the minute job follows it too; each logged with the path it took, and "through
 * configd" only when configd answered OK.
 *
 * @param callable(string): array{rc: int, out: string} $run
 * @param callable(string, int): void $log
 */
function uu_remove_core_commands(callable $run, callable $log): void
{
    $commands = [
        'filter reload' => [UU_CORE_FILTER_RELOAD, 'the loaded rules stay as they are until the next filter reload'],
        'cron restart' => [UU_CORE_CRON_RESTART, 'the minute job stays as it is until cron is next restarted'],
    ];
    foreach ($commands as $action => [$direct, $left]) {
        $r = uu_core_command($action, $direct, $run);
        switch ($r['path']) {
            case 'configd':
                $log("removal: $action through configd", LOG_NOTICE);
                break;
            case 'direct':
                $log("removal: $action: configd {$r['configd']}, so core's $direct ran directly", LOG_WARNING);
                break;
            default:
                $log("removal: $action failed: configd {$r['configd']}, and core's $direct exited {$r['rc']}: $left",
                    LOG_ERR);
        }
    }
}

/**
 * A removal that cannot run its stop restarts Unbound with no state: Unbound's own start puts it back on the root
 * zone the user configured, whatever the plugin set, and a removal restarts even with cacheflush on (the alternative
 * is a package gone with Unbound possibly still on the resolver). Nothing confirms it without the stop, so one error
 * says what was found, what ran, that it is not confirmed, and the remedy.
 *
 * @param string $found what stopped the removal's stop, as a clause after "the package is being removed, but"
 * @param string $remedy more remedy after the route delete, '' for none
 * @param callable(string): array{rc: int, out: string} $run
 * @param callable(string, int): void $log
 */
function uu_remove_restart_stateless(string $found, string $remedy, callable $run, callable $log): void
{
    $r = uu_core_command('unbound restart', UU_CORE_UNBOUND_RESTART, $run);
    $done = match ($r['path']) {
        'configd' => "core's Unbound restart ran through configd",
        'direct' => "configd {$r['configd']}, so core's " . UU_CORE_UNBOUND_RESTART . ' ran directly',
        default => "Unbound was not restarted: configd {$r['configd']}, and core's " . UU_CORE_UNBOUND_RESTART
            . " exited {$r['rc']}",
    };
    $log("the package is being removed, but $found; $done. That Unbound left the resolver is not confirmed (no stop "
        . 'checked it): if unbound-control -c /var/unbound/unbound.conf forward still names the resolver, run '
        . 'configctl unbound restart; then delete the host route the plugin may have left to the resolver (route -n '
        . "get <resolver>; route delete -host <resolver>)$remedy", LOG_ERR);
}

/**
 * remove's preparation. A run directory that cannot be trusted (a symbolic link, not a directory, not made) means no
 * lock and no state, since both live there: the stateless restart, and remove exits 1. A removal marker that cannot
 * be made in a trusted directory still leaves the lock and the state usable, so the removal's own stop runs (it
 * restarts Unbound only as its own fallback, and keeps its last resort); one error says that an evaluation between
 * that stop and the removal of the files, which the marker would have stopped, may use the resolver again.
 *
 * @param callable(): void $trust makes the run directory trusted; throws when it cannot
 * @param callable(): void $mark leaves the removal marker; throws when it cannot
 * @param callable(string): array{rc: int, out: string} $run
 * @param callable(string, int): void $log
 * @return ?int null when the removal goes on, else remove's exit status
 */
function uu_remove_prepare(callable $trust, callable $mark, callable $run, callable $log): ?int
{
    try {
        $trust();
    } catch (\Throwable $e) {
        uu_remove_restart_stateless('its run directory ' . UU_RUN_DIR . ' cannot be used (' . $e->getMessage()
            . '): no lock was taken and no state read', ' and make ' . UU_RUN_DIR . ' a directory root can write',
            $run, $log);
        return 1;
    }
    try {
        $mark();
    } catch (\Throwable $e) {
        $log('the package is being removed, but the removal marker cannot be made (' . $e->getMessage() . '): the '
            . "removal's stop runs as usual, but an evaluation between it and the removal of the files may use the "
            . 'resolver again: if unbound-control -c /var/unbound/unbound.conf forward names the resolver once the '
            . 'package is removed, run configctl unbound restart, then route delete -host <resolver>', LOG_ERR);
    }
    return null;
}

/**
 * remove's body under the lock: the removal's stop, then core's filter reload and cron restart, which run whatever
 * the stop did, so the rules and the minute job follow the footprint it saved. A stop that throws (a settings,
 * snapshot or plan failure comes before it acts) restarts Unbound with no state first, so no removal ends with
 * neither a stop nor a restart, and remove exits 1.
 *
 * @param callable(): int $evaluate the removal's stop
 * @param callable(string): array{rc: int, out: string} $run
 * @param callable(string, int): void $log
 */
function uu_remove_run(callable $evaluate, callable $run, callable $log): int
{
    try {
        $rc = $evaluate();
    } catch (\Throwable $e) {
        uu_remove_restart_stateless('its stop failed (' . $e->getMessage() . ', ' . basename($e->getFile()) . ':'
            . $e->getLine() . ')', '', $run, $log);
        $rc = 1;
    }
    uu_remove_core_commands($run, $log);
    return $rc;
}

/**
 * The error remove logs when an evaluation held the lock for UU_REMOVE_LOCK_WAIT_SECONDS, with the remedy: the
 * address the saved state records, else a placeholder.
 */
function uu_remove_timeout_text(?string $resolver): string
{
    $address = $resolver ?? '<resolver>';
    return "the package is being removed while Unbound may still forward to $address over the plugin's route: once "
        . "it is removed, run configctl unbound restart, then route delete -host $address";
}

/**
 * That error as the wait runs out (Task 10 N2): the state read then, without the lock as status reads it, so the
 * remedy names the address recorded at that moment; a state that cannot be read gives the placeholder, and nothing
 * is thrown, so the error is always logged.
 */
function uu_remove_timeout_remedy(string $statePath): string
{
    try {
        $read = uu_state_read($statePath);
        $resolver = $read['problem'] === null ? uu_state_footprint($read['state']) : null;
    } catch (\Throwable $e) {
        $resolver = null;
    }
    return uu_remove_timeout_text($resolver);
}
