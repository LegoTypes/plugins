#!/usr/local/bin/php
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
 */

/*
 * Monit check: exits non-zero once per new wan-failover event (hold, release, unowned force_down,
 * core-contract change), so Monit notifies without repeating itself.
 */

require_once __DIR__ . '/lib/constants.php';
require_once __DIR__ . '/lib/state.php';

/* both files are the plugin's own, root's alone: read as regular files only, and one that is not reads as absent */
$event = trim((string)wf_read_regular_file(WF_EVENT)['text']);
if ($event === '') {
    exit(0);
}
$fingerprint = hash('sha256', $event);
$sent = trim((string)wf_read_regular_file(WF_NOTIFIED)['text']);
if (hash_equals($fingerprint, $sent)) {
    exit(0);
}
echo "WAN failover event:\n{$event}\n";
try {
    wf_private_dir(WF_RUN_DIR);
    wf_write_private(WF_NOTIFIED, $fingerprint);
} catch (RuntimeException $e) {
    echo "(not recorded as notified, so it is reported again: {$e->getMessage()})\n";
}
exit(1);
