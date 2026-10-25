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
use OPNsense\Routing\Gateways;
use OPNsense\WanFailover\Holds;

/**
 * Holds 1.0.0: the gateways the plugin holds down leave the settings model, which the API edits, for the Holds model,
 * which no API reaches. 1.3_1 kept them as a list of gateway UUIDs in the settings node; the settings model no longer
 * declares it, so the list is read from the raw config. Each UUID that still names a gateway becomes one hold record,
 * stamped with this boot's kern.boot_id (wf_import_legacy_held()). Core runs this on a new install too, as the Holds
 * node is missing; there it finds no list and does nothing.
 *
 * The raw list is removed, and the outcome logged, in post(), once core has written the records to the config: a
 * migration whose records cannot be written leaves the list in place for the next run.
 */
class HLD1_0_0 extends BaseModelMigration
{
    /* the plugin's libraries: the boot id parser and the import (parsers.php, state.php through log.php), the log */
    private const LIB = '/usr/local/opnsense/scripts/OPNsense/WanFailover/lib';

    /* whether run() found the legacy list, and the lines post() logs */
    private bool $legacy = false;

    /** @var list<array{0: int, 1: string}> priority and line, in order */
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
        $node = Config::getInstance()->object()->OPNsense->WanFailover;
        if (!isset($node->held)) {
            return;
        }
        foreach (['parsers.php', 'log.php'] as $lib) {
            if (!is_readable(self::LIB . "/{$lib}")) {
                throw new \RuntimeException(self::LIB . "/{$lib} cannot be read; the held list stays where it is");
            }
            require_once self::LIB . "/{$lib}";
        }
        $csv = (string)$node->held;
        $nameByUuid = [];
        foreach ((new Gateways())->gateway_item->iterateItems() as $uuid => $gw) {
            $nameByUuid[(string)$uuid] = $gw->name->getValue();
        }
        $bootId = wf_parse_boot_id((string)shell_exec('/sbin/sysctl -x -n kern.boot_id 2>/dev/null'));
        foreach (wf_import_legacy_held($csv, $nameByUuid, $bootId, time()) as $record) {
            $model->hold->Add()->setNodes(['gateway' => $record['gateway'], 'boot' => $record['boot'],
                'since' => (string)$record['since']]);
            $this->lines[] = [LOG_NOTICE, 'migration: hold of ' . $nameByUuid[$record['gateway']]
                . " carried over, taken in boot {$bootId}"];
        }
        $named = [];
        foreach (array_unique(explode(',', $csv)) as $uuid) {
            if (isset($nameByUuid[$uuid])) {
                $named[] = $nameByUuid[$uuid];
            } elseif ($uuid !== '') {
                $this->lines[] = [LOG_NOTICE, "migration: held entry {$uuid} names no gateway; dropped"];
            }
        }
        if ($bootId === '' && $named !== []) {
            $this->lines[] = [LOG_WARNING, 'migration: kern.boot_id cannot be read, so no hold is carried over; each of '
                . implode(', ', $named) . ' keeps its force_down until it is cleared by hand'];
        }
        $this->legacy = true;
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
        if (!$this->legacy) {
            return;
        }
        unset(Config::getInstance()->object()->OPNsense->WanFailover->held);
        foreach ($this->lines as [$priority, $line]) {
            wf_log($line, $priority);
        }
    }
}
