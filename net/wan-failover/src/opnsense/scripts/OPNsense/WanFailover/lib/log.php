<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * syslog (program wanfailover; the plugin's own syslog-ng filter), the Monit event file, and the trace.
 */

require_once __DIR__ . '/constants.php';

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
    if (!is_dir(dirname($path))) {
        mkdir(dirname($path), 0750, true);
    }
    $lines = [];
    foreach ($fields as $k => $v) {
        $lines[] = sprintf('%s=%s', $k, is_array($v) ? implode(',', $v) : (is_bool($v) ? ($v ? 'yes' : 'no') : $v));
    }
    file_put_contents($path, implode("\n", $lines) . "\n", LOCK_EX);
}

/**
 * @param array<string, array|string|int|bool|null> $record
 */
function wf_trace(string $dir, array $record): void
{
    if (!is_dir($dir)) {
        mkdir($dir, 0750, true);
    }
    file_put_contents($dir . '/trace-' . date('Ymd') . '.jsonl', json_encode($record, JSON_UNESCAPED_SLASHES) . "\n",
        FILE_APPEND | LOCK_EX);
    foreach (glob($dir . '/trace-*.jsonl') ?: [] as $f) {
        if (filemtime($f) < time() - WF_TRACE_KEEP_DAYS * 86400) {
            unlink($f);
        }
    }
}
