<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The evaluate lock: how long each of evaluate.php's modes waits for it and what a wait that runs out logs, and the
 * wait itself on a lock file the caller names, so both are testable.
 */

require_once __DIR__ . '/constants.php';

/**
 * How long a mode of evaluate.php waits for the evaluate lock, and at what priority a wait that runs out is logged.
 * remove waits twice as long, and an error: the package's files go next, so a removal that gives up leaves nothing
 * to undo the plugin's route and forwarders, while an evaluation in flight is bounded by its probes and control
 * waits, and the removal marker stops every later one. Every other mode waits UU_LOCK_WAIT_SECONDS, and a trigger
 * that gives up is a warning: the next one runs.
 *
 * @return array{seconds: int, prio: int}
 */
function uu_lock_policy(string $mode): array
{
    return $mode === 'remove' ? ['seconds' => UU_REMOVE_LOCK_WAIT_SECONDS, 'prio' => LOG_ERR]
        : ['seconds' => UU_LOCK_WAIT_SECONDS, 'prio' => LOG_WARNING];
}

/**
 * Run fn holding an exclusive lock on path: blocking up to waitSeconds, so a trigger that arrives while another
 * holds it runs after it instead of being dropped; a wait that runs out logs timeoutText at timeoutPrio, never calls
 * fn and returns 1. A Closure is the text built when the wait runs out, so it can name what holds then. The lock
 * file is opened close-on-exec, so a child fn starts (configctl unbound restart) never holds it.
 *
 * @param callable(): int $fn
 * @param string|\Closure(): string $timeoutText
 * @param callable(string, int): void $log
 */
function uu_lock_run(string $path, callable $fn, int $waitSeconds, int $timeoutPrio, string|\Closure $timeoutText,
    callable $log): int
{
    $lock = fopen($path, 'ce');
    if ($lock === false) {
        throw new RuntimeException("cannot open $path");
    }
    try {
        $deadline = hrtime(true) + $waitSeconds * 1000000000;
        while (!flock($lock, LOCK_EX | LOCK_NB)) {
            if (hrtime(true) >= $deadline) {
                $text = $timeoutText instanceof \Closure ? $timeoutText() : $timeoutText;
                $log("an evaluation held the lock for $waitSeconds s: $text", $timeoutPrio);
                return 1;
            }
            usleep(200000);
        }
        return $fn();
    } finally {
        fclose($lock);
    }
}
