<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The evaluate lock (lib/lock.php): each mode's wait and priority, and the wait itself against a scratch lock file
 * that a child process holds, as an evaluation in flight would.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/lock.php';
require_once __DIR__ . '/scratch.php';

/**
 * A child php holding an exclusive flock on path until its stdin closes; null when it did not say it holds the lock
 * within 10 s.
 *
 * @return ?array{proc: resource, stdin: resource, stdout: resource}
 */
function uu_test_lock_holder(string $path): ?array
{
    $code = '$f = fopen($argv[1], "c"); if ($f === false || !flock($f, LOCK_EX)) { exit(1); } echo "held\n"; '
        . 'fgets(STDIN);';
    $pipes = [];
    $proc = proc_open([PHP_BINARY, '-d', 'log_errors=0', '-r', $code, $path],
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']], $pipes);
    if (!is_resource($proc)) {
        return null;
    }
    $ready = [$pipes[1]];
    $none = null;
    $line = @stream_select($ready, $none, $none, 10) === 1 ? fgets($pipes[1]) : false;
    $holder = ['proc' => $proc, 'stdin' => $pipes[0], 'stdout' => $pipes[1]];
    if ($line !== "held\n") {
        uu_test_lock_release($holder);
        return null;
    }
    return $holder;
}

/**
 * Let the holder go: its stdin closed, it exits and the lock with it.
 *
 * @param array{proc: resource, stdin: resource, stdout: resource} $holder
 */
function uu_test_lock_release(array $holder): void
{
    fclose($holder['stdin']);
    fclose($holder['stdout']);
    proc_close($holder['proc']);
}

uu_register_suite('lock', function (): int {
    $t = ['fail' => 0, 'total' => 0];

    uu_check($t, '(C1) the removal waits 120 s for the lock',
        uu_try_case(fn (): bool => UU_REMOVE_LOCK_WAIT_SECONDS === 120 && UU_LOCK_WAIT_SECONDS === 60));
    uu_check($t, '(C1) policy: remove waits UU_REMOVE_LOCK_WAIT_SECONDS and gives up at LOG_ERR',
        uu_try_case(fn (): bool => uu_lock_policy('remove') === ['seconds' => 120, 'prio' => LOG_ERR]));
    uu_check($t, '(C1) policy: an evaluation, start and stop wait UU_LOCK_WAIT_SECONDS and give up at LOG_WARNING',
        uu_try_case(fn (): bool => uu_lock_policy('evaluate') === ['seconds' => 60, 'prio' => LOG_WARNING]
            && uu_lock_policy('start') === uu_lock_policy('evaluate')
            && uu_lock_policy('stop') === uu_lock_policy('evaluate')));

    /* a lock a child holds: the wait runs out, fn never runs, one line at the priority with the text built then */
    $held = null;
    $ok = uu_scratch_case(function (string $dir) use (&$held): bool {
        $path = "$dir/evaluate.lock";
        $holder = uu_test_lock_holder($path);
        if ($holder === null) {
            echo "  the child never held the lock\n";
            return false;
        }
        try {
            $ran = false;
            $logged = [];
            $built = [];
            $t0 = hrtime(true);
            $rc = uu_lock_run($path, function () use (&$ran): int {
                $ran = true;
                return 0;
            }, 1, LOG_ERR, function () use (&$built, $t0): string {
                $built[] = hrtime(true) - $t0;
                return 'the text built at the timeout';
            }, function (string $msg, int $prio) use (&$logged): void {
                $logged[] = [$msg, $prio];
            });
            $held = ['rc' => $rc, 'ran' => $ran, 'logged' => $logged, 'built' => $built,
                     'took' => hrtime(true) - $t0];
            return true;
        } finally {
            uu_test_lock_release($holder);
        }
    });
    uu_check($t, '(C1) a lock held by another process: after the wait uu_lock_run returns 1 and never calls fn',
        $ok && $held !== null && $held['rc'] === 1 && $held['ran'] === false
        && $held['took'] >= 1000000000 && $held['took'] < 5000000000);
    uu_check($t, '(C1) the wait that runs out logs once, at the priority given, with the text built when it ran out',
        $ok && $held !== null && $held['logged'] === [['an evaluation held the lock for 1 s: the text built at the '
            . 'timeout', LOG_ERR]] && count($held['built']) === 1 && $held['built'][0] >= 1000000000);

    /* a free lock: fn runs at once, its status comes back, nothing is logged, and the lock is free again after */
    $free = null;
    $ok = uu_scratch_case(function (string $dir) use (&$free): bool {
        $path = "$dir/evaluate.lock";
        $logged = [];
        $rc = uu_lock_run($path, fn (): int => 7, 1, LOG_ERR, 'unused',
            function (string $msg, int $prio) use (&$logged): void {
                $logged[] = [$msg, $prio];
            });
        $holder = uu_test_lock_holder($path);
        $free = ['rc' => $rc, 'logged' => $logged, 'again' => $holder !== null];
        if ($holder !== null) {
            uu_test_lock_release($holder);
        }
        return true;
    });
    uu_check($t, '(C1) a free lock: fn runs, its exit status is returned, nothing is logged, and the lock is let go',
        $ok && $free === ['rc' => 7, 'logged' => [], 'again' => true]);

    return uu_tally_report('lock', $t);
});
