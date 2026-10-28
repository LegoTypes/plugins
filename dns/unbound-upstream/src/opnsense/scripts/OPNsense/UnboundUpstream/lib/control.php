<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The unbound-control calls the snapshot and apply share: the reply of one call, and the call itself.
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/log.php';

/**
 * What an unbound-control call answered: the reply (its stdout, newline-terminated) for exit 0, an empty one
 * included (an empty list is "\n"), or for exit 1 with output, which is how the daemon reports its own `error ...`
 * replies; null for no answer: exit 1 with empty stdout (a refused connect), a timeout (124), or any other exit
 * (`status` alone exits 3).
 */
function uu_uc_result(int $rc, string $stdout): ?string
{
    if ($rc !== 0 && ($rc !== 1 || trim($stdout) === '')) {
        return null;
    }
    return rtrim($stdout, "\r\n") . "\n";
}

/**
 * Run unbound-control under UU_CONTROL_CALL_TIMEOUT_SECONDS, without a shell, stdout and stderr apart. A non-zero
 * exit logs the output and the exit at warning level, whether the daemon replied with an error or refused the
 * connect. Null when nothing answered (uu_uc_result()), including a command that could not start.
 *
 * @param list<string> $args
 */
function uu_uc_run(array $args): ?string
{
    $cmd = array_merge(['/usr/bin/timeout', (string)UU_CONTROL_CALL_TIMEOUT_SECONDS,
        '/usr/local/sbin/unbound-control', '-c', '/var/unbound/unbound.conf'], $args);
    $proc = proc_open($cmd, [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes);
    if (!is_resource($proc)) {
        uu_log('unbound-control ' . implode(' ', $args) . ': could not start', LOG_WARNING);
        return null;
    }
    $buf = [1 => '', 2 => ''];
    $open = [1 => $pipes[1], 2 => $pipes[2]];
    foreach ($open as $pipe) {
        stream_set_blocking($pipe, false);
    }
    while ($open !== []) {
        $read = array_values($open);
        $write = null;
        $except = null;
        if (stream_select($read, $write, $except, 1) === false) {
            break;
        }
        foreach ($open as $n => $pipe) {
            $chunk = fread($pipe, 8192);
            if ($chunk !== false && $chunk !== '') {
                $buf[$n] .= $chunk;
            }
            if (feof($pipe)) {
                fclose($pipe);
                unset($open[$n]);
            }
        }
    }
    foreach ($open as $pipe) {
        fclose($pipe);
    }
    $rc = proc_close($proc);
    if ($rc !== 0) {
        uu_log('unbound-control ' . implode(' ', $args) . ' (exit ' . $rc . '): '
            . implode('; ', array_filter(array_map('trim', [$buf[1], $buf[2]]), fn (string $l): bool => $l !== '')),
            LOG_WARNING);
    }
    return uu_uc_result($rc, $buf[1]);
}
