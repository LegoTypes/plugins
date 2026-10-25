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
 * declares it, so the list is read from the raw config. Each UUID whose gateway the plugin's own state proves it held
 * in this boot (its state file names this boot and the gateway in last_held, as 1.3_1 wrote them) becomes one hold
 * record, stamped with this boot's kern.boot_id. Any other entry (a restored backup's list, or one met with the state
 * file missing or damaged) makes no record, and its gateway keeps its force_down, never released on a guess. Core runs
 * this on a new install too, as the Holds node is missing; there it finds no list and does nothing.
 *
 * The import is the plugin's own (wf_holds_import_into()), the one an evaluation runs when it finds the list still
 * there, and it adds the records to the model core hands it: core saves that model after run(), so a save of the
 * migration's own would be overwritten by it. The raw list is removed, and the outcome logged, in post(), once core
 * has written the records to the config, and only when run()'s import completed (wf_legacy_import_attempt()): a run()
 * that failed, even part way through, or could not read kern.boot_id, or records that cannot be written, leave the list
 * in place. A run() that threw after adding some records still has them saved by core, beside the list it left: the
 * next evaluation imports the list again, and the records of this boot that repeat a gateway are pruned to one, the
 * newest. Nothing is thrown into core, whose runner catches Exception only, so an Error would end run_migrations.php:
 * a failure is logged, the list stays, and the next evaluation imports it.
 */
class HLD1_0_0 extends BaseModelMigration
{
    /* the plugin's libraries: the boot id parser (parsers.php), the state file, the import and the log (apply.php) */
    private const LIB = '/usr/local/opnsense/scripts/OPNsense/WanFailover/lib';

    /* set only when run()'s import completed: post() removes the raw list only then */
    private bool $imported = false;

    /** @var list<array{0: int, 1: string}> the lines post() logs (priority, text) */
    private array $lines = [];

    /**
     * @param \OPNsense\WanFailover\Holds $model
     */
    public function run($model)
    {
        if (!$model instanceof Holds) {
            return;
        }
        parent::run($model);
        $root = Config::getInstance()->object();
        if (!isset($root->OPNsense->WanFailover->held)) {
            return;
        }
        $csv = (string)$root->OPNsense->WanFailover->held;
        try {
            foreach (['parsers.php', 'apply.php'] as $lib) {
                if (!is_readable(self::LIB . "/{$lib}")) {
                    throw new \RuntimeException(self::LIB . "/{$lib} cannot be read");
                }
                require_once self::LIB . "/{$lib}";
            }
        } catch (\Throwable $e) {
            self::failed($e->getMessage());
            return;
        }
        $attempt = wf_legacy_import_attempt(fn (): array => wf_holds_import_into($model, $csv,
            wf_parse_boot_id((string)shell_exec('/sbin/sysctl -x -n kern.boot_id 2>/dev/null')), time(),
            wf_state_proof(wf_state_load(WF_STATE, ''))));
        if ($attempt['error'] !== null) {
            self::failed($attempt['error']);
        }
        $this->imported = $attempt['imported'];
        $this->lines = $attempt['lines'];
    }

    /**
     * After core wrote the records to the config: the raw list removed, once imported, so the settings model's next
     * save cannot bring it back, and the outcome logged, all at once: wf_log() opens syslog once per process, and a log
     * call of core's in between would reopen it under core's name.
     *
     * @param \OPNsense\WanFailover\Holds $model
     */
    public function post($model)
    {
        if (!$this->imported && $this->lines === []) {
            return;
        }
        try {
            if ($this->imported) {
                wf_holds_drop_legacy();
            }
            foreach ($this->lines as [$priority, $line]) {
                wf_log("migration: {$line}", $priority);
            }
        } catch (\Throwable $e) {
            self::failed($e->getMessage());
        }
    }

    /**
     * Logged under the plugin's name, whether or not its libraries could be loaded; once they are, the reason is cleaned
     * as wf_log() cleans a line.
     */
    private static function failed(string $why): void
    {
        if (function_exists('wf_log_text')) {
            $why = wf_log_text($why);
        }
        openlog('wanfailover', LOG_PID, LOG_LOCAL4);
        syslog(LOG_ERR, "migration: the held list was not carried over ({$why}); it stays in the config, and the next"
            . ' evaluation imports it');
    }
}
