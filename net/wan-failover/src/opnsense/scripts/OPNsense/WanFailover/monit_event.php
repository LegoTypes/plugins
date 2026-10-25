#!/usr/local/bin/php
<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
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
