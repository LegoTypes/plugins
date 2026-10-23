<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The log line cleaner and the hooks' logger. Loaded by core's own process (the firewall and configure hooks), so it
 * pulls in nothing but the constants; log.php (the scripts' syslog and the status document) loads it.
 */

require_once __DIR__ . '/constants.php';

/**
 * A log line as one printable line (convention C7, H3): CR and LF become "; ", every other control byte
 * (0x00-0x1F, 0x7F) and every UTF-8 C1 pair (U+0080 to U+009F) becomes "?". No /u: bytes that are not UTF-8 pass
 * through untouched instead of making the result null.
 */
function uu_log_text(string $msg): string
{
    $msg = str_replace(["\r", "\n"], '; ', $msg);
    return (string)preg_replace('/[\x00-\x1F\x7F]|\xC2[\x80-\x9F]/', '?', $msg);
}

/**
 * Log from inside core's process (configure and firewall hooks) through logger(1), so core's syslog ident and
 * connection stay as they are.
 *
 * @param string $level a syslog level name: err, warning, notice, info
 */
function uu_logger(string $msg, string $level = 'notice'): void
{
    exec('/usr/bin/logger -t ' . UU_SYSLOG_IDENT . ' -p ' . escapeshellarg('local4.' . $level) . ' -- '
        . escapeshellarg(uu_log_text($msg)) . ' > /dev/null 2>&1');
}
