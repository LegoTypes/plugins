#!/usr/local/bin/php
<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * configd [status]: the line ApiMutableServiceControllerBase recognises. The plugin has no daemon; it "runs"
 * while the model's enabled switch is on (its cron job and hooks are the service).
 */

require_once 'config.inc';

try {
    $enabled = (new \OPNsense\UnboundUpstream\UnboundUpstream())->enabled->isEqual('1');
} catch (\Throwable $e) {
    fwrite(STDERR, $e->getMessage() . "\n");
    $enabled = false;
}
echo $enabled ? "unboundupstream is running\n" : "unboundupstream is not running\n";
