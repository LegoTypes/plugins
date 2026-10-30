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

namespace OPNsense\WanFailover;

use OPNsense\Base\BaseModel;
use OPNsense\Base\Messages\Message;
use OPNsense\Routing\Gateways;

/* in a scope of its own, so loading the model leaves no variable in the scope that loads it */
(static function (): void {
    $lib = dirname(__DIR__, 5) . '/scripts/OPNsense/WanFailover/lib/judge.php';
    if (!function_exists('wf_unjudgeable')) {
        if (!is_readable($lib)) {
            throw new \RuntimeException('plugin library missing: ' . $lib);
        }
        require_once $lib;
    }
})();

class WanFailover extends BaseModel
{
    /**
     * A Save that adds a gateway the engine can never judge (wf_unjudgeable()) to the selection is refused, naming it.
     * Only the gateways it adds are judged, so a selection saved before stays as it is on any Save, in any order.
     *
     * @param bool $validateFullModel
     * @return \OPNsense\Base\Messages\MessageCollection|\Phalcon\Messages\Messages
     */
    public function performValidation($validateFullModel = false)
    {
        $messages = parent::performValidation($validateFullModel);
        $added = self::addedWans($this->wans->getInitialValue(), $this->wans->getValue());
        if ($added === []) {
            return $messages;
        }
        $gateways = [];
        foreach ((new Gateways())->gateway_item->iterateItems() as $uuid => $gw) {
            $gateways[(string)$uuid] = [
                'name' => $gw->name->getValue(),
                'monitor_disable' => $gw->monitor_disable->isEqual('1'),
                'disabled' => $gw->disabled->isEqual('1'),
            ];
        }
        foreach (self::wanProblems($added, $gateways) as $text) {
            $messages->appendMessage(new Message($text, $this->wans->__reference));
        }
        return $messages;
    }

    /**
     * The gateways of the comma list $current that $initial does not hold, in $current's order, empty items and repeats
     * dropped: a set difference, so a reordered selection adds nothing.
     *
     * @return list<string>
     */
    public static function addedWans(string $initial, string $current): array
    {
        $saved = explode(',', $initial);
        $added = [];
        foreach (explode(',', $current) as $uuid) {
            if ($uuid !== '' && !in_array($uuid, $saved, true) && !in_array($uuid, $added, true)) {
                $added[] = $uuid;
            }
        }
        return $added;
    }

    /**
     * One message per gateway of $selected the engine can never judge, in $selected's order. A UUID that is not in
     * $gateways gets none: the relation field's own validation refuses it.
     *
     * @param list<string> $selected gateway UUIDs
     * @param array<string, array{name: string, monitor_disable: bool, disabled: bool}> $gateways by UUID
     * @return list<string>
     */
    public static function wanProblems(array $selected, array $gateways): array
    {
        $messages = [];
        foreach ($selected as $uuid) {
            $gw = $gateways[$uuid] ?? null;
            if ($gw === null) {
                continue;
            }
            $text = match (wf_unjudgeable($gw)) {
                'disabled' => gettext('%s is disabled, so the plugin can never judge it. Enable it under System: Gateways: Configuration, or deselect it.'),
                'monitor_disable' => gettext('%s has gateway monitoring disabled, so the plugin can never judge it. Enable monitoring under System: Gateways: Configuration, or deselect it.'),
                null => null,
            };
            if ($text !== null) {
                $messages[] = sprintf($text, $gw['name']);
            }
        }
        return $messages;
    }
}
