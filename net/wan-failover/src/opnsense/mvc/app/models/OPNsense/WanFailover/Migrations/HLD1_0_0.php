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
 */

namespace OPNsense\WanFailover\Migrations;

use OPNsense\Base\BaseModelMigration;
use OPNsense\Core\Config;
use OPNsense\WanFailover\Holds;

/**
 * Holds 1.0.0: the gateways the plugin holds down leave the settings model, which the API edits, for the Holds model,
 * which no API reaches. 1.3_1 kept them as a list of gateway UUIDs in the settings node; the settings model no longer
 * declares it, so the list is read from the raw config. Each UUID that still names a gateway becomes one hold record,
 * stamped with this boot's kern.boot_id. Core runs this on a new install too, as the Holds node is missing; there it
 * finds no list and does nothing.
 *
 * The import is the plugin's own (wf_holds_import_into()), the one an evaluation runs when it finds the list still
 * there, and it adds the records to the model core hands it: core saves that model after run(), so a save of the
 * migration's own would be overwritten by it. The raw list is removed, and the outcome logged, in post(), once core
 * has written the records to the config: a migration whose records cannot be written leaves the list in place. Nothing
 * is thrown into core, whose runner catches Exception only, so an Error would end run_migrations.php: a failure is
 * logged, the list stays, and the next evaluation imports it.
 */
class HLD1_0_0 extends BaseModelMigration
{
    /* the plugin's libraries: the boot id parser (parsers.php), the import and the log (apply.php) */
    private const LIB = '/usr/local/opnsense/scripts/OPNsense/WanFailover/lib';

    /** @var ?list<array{0: int, 1: string}> the lines post() logs (priority, text); null when run() imported nothing */
    private ?array $lines = null;

    /**
     * @param \OPNsense\WanFailover\Holds $model
     */
    public function run($model)
    {
        if (!$model instanceof Holds) {
            return;
        }
        parent::run($model);
        if (!isset(Config::getInstance()->object()->OPNsense->WanFailover->held)) {
            return;
        }
        try {
            foreach (['parsers.php', 'apply.php'] as $lib) {
                if (!is_readable(self::LIB . "/{$lib}")) {
                    throw new \RuntimeException(self::LIB . "/{$lib} cannot be read");
                }
                require_once self::LIB . "/{$lib}";
            }
            $bootId = wf_parse_boot_id((string)shell_exec('/sbin/sysctl -x -n kern.boot_id 2>/dev/null'));
            $this->lines = wf_holds_import_into($model, $bootId, time());
        } catch (\Throwable $e) {
            $this->lines = null;
            self::failed($e);
        }
    }

    /**
     * After core wrote the records to the config: the raw list removed, so the settings model's next save cannot
     * bring it back, and the outcome logged, all at once: wf_log() opens syslog once per process, and a log call of
     * core's in between would reopen it under core's name.
     *
     * @param \OPNsense\WanFailover\Holds $model
     */
    public function post($model)
    {
        if ($this->lines === null) {
            return;
        }
        try {
            wf_holds_drop_legacy();
            foreach ($this->lines as [$priority, $line]) {
                wf_log("migration: {$line}", $priority);
            }
        } catch (\Throwable $e) {
            self::failed($e);
        }
    }

    /** Logged under the plugin's name, whether or not its libraries could be loaded. */
    private static function failed(\Throwable $e): void
    {
        openlog('wanfailover', LOG_PID, LOG_LOCAL4);
        syslog(LOG_ERR, 'migration: the held list was not carried over (' . $e->getMessage()
            . '); it stays in the config, and the next evaluation imports it');
    }
}
