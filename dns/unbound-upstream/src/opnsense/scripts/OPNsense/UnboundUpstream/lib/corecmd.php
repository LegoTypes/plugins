<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Core's own commands for a removal (spec -04 section 3.2, convention C6): through configd when it answers within
 * UU_CONFIGD_TIMEOUT_SECONDS, else the command core's actions file names, run directly (rulings R4, R5). Not the
 * plugin's own configd actions: a removal deletes them. The runner is injected, so the order is testable;
 * uu_core_shell() is the real one.
 */

require_once __DIR__ . '/constants.php';

/**
 * Run a core configd action, or core's own command for it when configd does not answer: configctl exits non-zero
 * (no socket, no reply) or is killed after UU_CONFIGD_TIMEOUT_SECONDS (124).
 *
 * @param string $action the configd action, words as configctl takes them ("filter reload")
 * @param string $direct the command core's actions file runs for it (a UU_CORE_* constant)
 * @param callable(string): int $run runs a command line, returns its exit status
 * @return string 'configd', 'direct', or 'failed' when both exited non-zero
 */
function uu_core_command(string $action, string $direct, callable $run): string
{
    if ($run('/usr/bin/timeout ' . UU_CONFIGD_TIMEOUT_SECONDS . ' /usr/local/sbin/configctl ' . $action) === 0) {
        return 'configd';
    }
    return $run($direct) === 0 ? 'direct' : 'failed';
}

/** The production runner: the command line through sh, its output discarded, its exit status returned. */
function uu_core_shell(string $cmdline): int
{
    $out = [];
    $rc = 0;
    exec($cmdline . ' > /dev/null 2>&1', $out, $rc);
    return $rc;
}

/**
 * What remove runs after its stop (ruling R4): the filter reload, so the rules follow the footprint the stop left,
 * and the cron restart, so the minute job follows it too; each logged with the path it took.
 *
 * @param callable(string): int $run
 * @param callable(string, int): void $log
 */
function uu_remove_core_commands(callable $run, callable $log): void
{
    $commands = [
        'filter reload' => [UU_CORE_FILTER_RELOAD, 'the loaded rules stay as they are until the next filter reload'],
        'cron restart' => [UU_CORE_CRON_RESTART, 'the minute job stays as it is until cron is next restarted'],
    ];
    foreach ($commands as $action => [$direct, $left]) {
        switch (uu_core_command($action, $direct, $run)) {
            case 'configd':
                $log("removal: $action through configd", LOG_NOTICE);
                break;
            case 'direct':
                $log("removal: configd did not answer $action within " . UU_CONFIGD_TIMEOUT_SECONDS
                    . " s, so core's $direct ran directly", LOG_WARNING);
                break;
            default:
                $log("removal: $action failed through configd and through core's $direct: $left", LOG_ERR);
        }
    }
}

/**
 * Ruling R54: a removal whose run directory cannot be trusted (a symbolic link, not a directory, not made) takes no
 * lock and reads no state, because both live there. A restart needs neither: Unbound's own start puts it back on
 * the root zone the user configured, whatever the plugin set, and a removal restarts even with cacheflush on
 * (owner decision D2). One error says what was found and done, and the remedy.
 *
 * @param callable(): void $runDir uu_run_dir(): throws when the run directory cannot be trusted
 * @param callable(string): int $run
 * @param callable(string, int): void $log
 * @return ?int null when the run directory is trusted (the removal goes on), else remove's exit status
 */
function uu_remove_untrusted_run_dir(callable $runDir, callable $run, callable $log): ?int
{
    try {
        $runDir();
        return null;
    } catch (\Throwable $e) {
        $problem = $e->getMessage();
    }
    $done = match (uu_core_command('unbound restart', UU_CORE_UNBOUND_RESTART, $run)) {
        'configd' => 'Unbound was restarted through configd onto its configured root zone',
        'direct' => "configd did not answer, so Unbound was restarted onto its configured root zone by core's "
            . UU_CORE_UNBOUND_RESTART,
        default => 'Unbound was not restarted (configd and core\'s ' . UU_CORE_UNBOUND_RESTART . ' both failed), '
            . 'so it may still forward to the resolver: run configctl unbound restart now',
    };
    $log('the package is being removed, but its run directory ' . UU_RUN_DIR . " cannot be trusted ($problem): no "
        . "lock was taken and no state read; $done. Then delete the host route the plugin may have left to the "
        . 'resolver (route -n get <resolver>; route delete -host <resolver>) and replace ' . UU_RUN_DIR
        . ' with a directory', LOG_ERR);
    return 1;
}
