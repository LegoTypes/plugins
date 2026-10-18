#!/usr/local/bin/php
<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * configd [status]: the line ApiMutableServiceControllerBase recognises. The plugin has no daemon; it runs while
 * its minute job is installed (start and stop regenerate cron). Reporting the enabled setting instead would turn
 * the Save that enables the plugin into a reload, which never installs the job.
 */

$cron = (string)shell_exec('/usr/bin/crontab -l 2>/dev/null');
echo str_contains($cron, '/usr/local/sbin/configctl unboundupstream evaluate')
    ? "unboundupstream is running\n" : "unboundupstream is not running\n";
