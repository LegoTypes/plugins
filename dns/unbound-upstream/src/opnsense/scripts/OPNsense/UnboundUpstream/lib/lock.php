<?php

declare(strict_types=1);

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
