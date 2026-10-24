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
 * Run a core configd action, or core's own command for it when configd does not answer. configd has answered only
 * when configctl exits 0 and prints OK (trimmed), as a script action that ran replies (ruling R55): configctl also
 * exits 0 on no reply, a swallowed communication error, "Error (n)", "Action not found" and "Execute error". It exits
 * non-zero with no socket or no connection, and 124 when /usr/bin/timeout kills it. Only configctl's stdout is read,
 * and the timeout bounds it; core's own command writes to /dev/null and only its exit status counts, so a child it
 * leaves running (a daemon a restart starts) cannot hold the runner's pipe open and stall the removal (Task 10 N1).
 *
 * @param string $action the configd action, words as configctl takes them ("filter reload")
 * @param string $direct the command core's actions file runs for it (a UU_CORE_* constant)
 * @param callable(string): array{rc: int, out: string} $run runs a shell command line: its exit status and stdout
 * @return array{path: string, configd: string, rc: ?int} path is configd, direct, or failed when core's command
 *     exited non-zero too; configd is what configd did, for a log line ('' when it answered OK); rc is core's
 *     command's exit status, null when it did not run
 */
function uu_core_command(string $action, string $direct, callable $run): array
{
    $ctl = $run('/usr/bin/timeout ' . UU_CONFIGD_TIMEOUT_SECONDS . ' /usr/local/sbin/configctl ' . $action
        . ' 2> /dev/null');
    if ($ctl['rc'] === 0 && trim($ctl['out']) === 'OK') {
        return ['path' => 'configd', 'configd' => '', 'rc' => null];
    }
    if ($ctl['rc'] === 124) {
        $configd = 'did not answer within ' . UU_CONFIGD_TIMEOUT_SECONDS . ' s (configctl exit 124)';
    } elseif ($ctl['rc'] !== 0) {
        $configd = "did not answer (configctl exit {$ctl['rc']})";
    } else {
        $first = trim(explode("\n", trim($ctl['out']))[0]);
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
 * Rulings R54 and R56: a removal whose run directory cannot be trusted (a symbolic link, not a directory, not made)
 * or whose removal marker cannot be made takes no lock and reads no state, because both live there. A restart needs
 * neither: Unbound's own start puts it back on the root zone the user configured, whatever the plugin set, and a
 * removal restarts even with cacheflush on (owner decision D2). Nothing can confirm it without the state, so one
 * error says what was found, what ran, that it is not confirmed, and the remedy.
 *
 * @param callable(): void $prepare makes the run directory trusted and leaves the removal marker; throws when it
 *     cannot
 * @param callable(string): array{rc: int, out: string} $run
 * @param callable(string, int): void $log
 * @return ?int null when the removal is prepared (it goes on), else remove's exit status
 */
function uu_remove_prepare(callable $prepare, callable $run, callable $log): ?int
{
    try {
        $prepare();
        return null;
    } catch (\Throwable $e) {
        $problem = $e->getMessage();
    }
    $r = uu_core_command('unbound restart', UU_CORE_UNBOUND_RESTART, $run);
    $done = match ($r['path']) {
        'configd' => "core's Unbound restart ran through configd",
        'direct' => "configd {$r['configd']}, so core's " . UU_CORE_UNBOUND_RESTART . ' ran directly',
        default => "Unbound was not restarted: configd {$r['configd']}, and core's " . UU_CORE_UNBOUND_RESTART
            . " exited {$r['rc']}",
    };
    $log('the package is being removed, but its run directory ' . UU_RUN_DIR . " cannot be used ($problem): no lock "
        . "was taken and no state read; $done. That Unbound left the resolver is not confirmed (no state to check it "
        . 'against): if unbound-control -c /var/unbound/unbound.conf forward still names the resolver, run configctl '
        . 'unbound restart; then delete the host route the plugin may have left to the resolver (route -n get '
        . '<resolver>; route delete -host <resolver>) and make ' . UU_RUN_DIR . ' a directory root can write',
        LOG_ERR);
    return 1;
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
