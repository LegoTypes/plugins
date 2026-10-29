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
 * The log line cleaner and the hooks' logger. Loaded by core's own process (the firewall and configure hooks), so it
 * pulls in nothing but the constants; log.php (the scripts' syslog and the status document) loads it.
 */

require_once __DIR__ . '/constants.php';

/**
 * A log line as one printable line, so a value from outside never forges or breaks one: CR and LF become "; ",
 * every other control byte (0x00-0x1F, 0x7F) and every UTF-8 C1 pair (U+0080 to U+009F) becomes "?". No /u: bytes
 * that are not UTF-8 pass through untouched instead of making the result null.
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
