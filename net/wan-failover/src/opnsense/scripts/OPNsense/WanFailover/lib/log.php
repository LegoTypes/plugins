<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * syslog (program wanfailover; the plugin's own syslog-ng filter), the Monit event file, and the trace. The event
 * and the trace are root's alone, as every file of the plugin's (state.php).
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/state.php';

function wf_log(string $msg, int $prio = LOG_NOTICE): void
{
    static $open = false;
    if (!$open) {
        openlog('wanfailover', LOG_PID, LOG_LOCAL4);
        $open = true;
    }
    syslog($prio, $msg);
}

/**
 * @param array<string, string|bool|list<string>> $fields
 */
function wf_event(string $path, array $fields): void
{
    wf_private_dir(dirname($path));
    $lines = [];
    foreach ($fields as $k => $v) {
        $lines[] = sprintf('%s=%s', $k, is_array($v) ? implode(',', $v) : (is_bool($v) ? ($v ? 'yes' : 'no') : $v));
    }
    wf_write_private($path, implode("\n", $lines) . "\n");
}

/**
 * One JSON line appended to the day's trace file, created 0600 (an existing one put back to 0600 when its mode
 * differs). The trace is diagnostics only, so a path that cannot be trusted -- the directory or the day's file a
 * symbolic link or not what it should be -- is logged and skipped, never thrown into the evaluation.
 *
 * @param array<string, array|string|int|bool|null> $record
 */
function wf_trace(string $dir, array $record): void
{
    $file = $dir . '/trace-' . date('Ymd') . '.jsonl';
    try {
        wf_private_dir($dir);
    } catch (RuntimeException $e) {
        wf_log('trace not written: ' . $e->getMessage(), LOG_WARNING);
        return;
    }
    clearstatcache(true, $file);
    $st = @lstat($file);
    $problem = null;
    if ($st !== false && ($st['mode'] & 0170000) === 0120000) {
        $problem = 'is a symbolic link';
    } elseif ($st !== false && ($st['mode'] & 0170000) !== 0100000) {
        $problem = 'is not a regular file';
    } elseif ($st !== false && ($st['mode'] & 07777) !== 0600 && !@chmod($file, 0600)) {
        $problem = 'cannot be made mode 0600';
    }
    if ($problem === null) {
        $umask = umask(0077);
        if (@file_put_contents($file, json_encode($record, JSON_UNESCAPED_SLASHES) . "\n", FILE_APPEND | LOCK_EX) === false) {
            $problem = 'cannot be written';
        }
        umask($umask);
    }
    if ($problem !== null) {
        wf_log("trace not written: {$file} {$problem}", LOG_WARNING);
    }
}

/**
 * Remove trace files older than the keep window; runs on every evaluation, so the last files go even
 * after tracing stopped.
 */
function wf_trace_prune(string $dir, int $now, int $keepDays): void
{
    foreach (glob($dir . '/trace-*.jsonl') ?: [] as $f) {
        if (filemtime($f) < $now - $keepDays * 86400) {
            unlink($f);
        }
    }
}
