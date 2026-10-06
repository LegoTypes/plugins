#!/usr/local/bin/php
<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Monit check: exits non-zero once per new wan-failover event (hold, release, unowned force_down,
 * core-contract change), so Monit notifies without repeating itself.
 */

const WF_EVENT = '/var/run/wanfailover/event';
const WF_NOTIFIED = '/var/run/wanfailover/notified';

if (!is_readable(WF_EVENT)) {
    exit(0);
}
$event = trim((string)file_get_contents(WF_EVENT));
if ($event === '') {
    exit(0);
}
$fingerprint = hash('sha256', $event);
$sent = is_readable(WF_NOTIFIED) ? trim((string)file_get_contents(WF_NOTIFIED)) : '';
if (hash_equals($fingerprint, $sent)) {
    exit(0);
}
file_put_contents(WF_NOTIFIED, $fingerprint);
echo "WAN failover event:\n{$event}\n";
exit(1);
