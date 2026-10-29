#!/usr/local/bin/php
<?php

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
 * Log once when core stops matching the internals the plugin copies, and once when core may carry a
 * fix a workaround of the plugin waits for (wgct_core_contract()). Run by wgct.sh reconcile. Changes
 * nothing; the tunnel list shows the core-contract and core-fixed findings. Silent while the plugin is
 * disabled, as the findings are; one run at a time (the minute cron and a queued reconcile can
 * overlap), so a drift or a note is logged once.
 */

require '/usr/local/opnsense/mvc/script/load_phalcon.php';
if (!is_readable(__DIR__ . '/entry.php')) {
    exit(0);
}
require_once __DIR__ . '/entry.php';
wgct_entry_load('core_contract.php', 'wgct-contract', ['apply.php']);

if (!(new \OPNsense\WGClientTunnels\WGClientTunnels())->enabled->isEqual('1')) {
    exit(0);
}
$state = WGCT_RUN_DIR;
if (!wgct_state_dir($state)) {
    exit(0);
}
$lock = fopen($state . '/core_contract.lock', 'ce');
if ($lock === false || !flock($lock, LOCK_EX | LOCK_NB)) {
    exit(0);
}
wgct_core_contract_log(wgct_core_contract(), $state . '/core_contract.logged', 'wgct_log');
exit(0);
