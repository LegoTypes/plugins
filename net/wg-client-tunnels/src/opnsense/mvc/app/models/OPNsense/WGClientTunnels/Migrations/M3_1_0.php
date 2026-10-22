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

namespace OPNsense\WGClientTunnels\Migrations;

use OPNsense\Base\BaseModelMigration;
use OPNsense\Core\Config;
use OPNsense\WGClientTunnels\Engine;

/**
 * Settings 3.0.0 -> 3.1.0 (spec 2026-10-20 section 3.5, convention C1): the managed list and the health mirror's
 * holds leave the settings model, which the API edits, for the engine model, which has no API. This model no
 * longer declares them, so the 3.0.0 values are read from the raw config nodes; the settings model's own
 * serialize after this run drops those nodes.
 *
 * The managed list is carried byte for byte. A held gateway becomes a hold record only when it is a managed
 * tunnel's IPv4 gateway and is forced down; the record carries this boot's kern.boot_id, since a hold active at
 * the upgrade was taken in this boot. Every other held gateway is dropped and logged, its force_down left as it
 * is for a person to clear. The engine model is brought to its own version before it is written, so the outcome
 * is the same whichever of the two models core migrates first.
 */
class M3_1_0 extends BaseModelMigration
{
    /* the plugin's derivation, which knows each tunnel's IPv4 gateway and its bound WAN */
    private const TUNNELS_LIB = '/usr/local/opnsense/scripts/OPNsense/WGClientTunnels/lib/tunnels.php';

    /* the engine model's mask for a hold record's underlay */
    private const UNDERLAY_MASK = '/^[a-zA-Z0-9_-]{1,32}$/D';

    /**
     * Which held gateways become hold records. Pure.
     *
     * @param list<string>                                             $managed      managed instance uuids, as stored
     * @param list<string>                                             $held         held gateway uuids, as stored
     * @param array<string, bool>                                      $gateways     gateway uuid => force_down
     * @param array<string, array{gateway: string, underlay: string}> $ipv4Gateways instance uuid => its tunnel's
     *                                                                               IPv4 gateway uuid and bound WAN
     * @param string                                                   $bootId       the live kern.boot_id, '' when
     *                                                                               it cannot be read
     * @return array{rows: list<array{gateway: string, boot: string, underlay: string}>, dropped: list<string>}
     *         each held uuid once, in the order held: a row, or dropped
     */
    public static function plan(array $managed, array $held, array $gateways, array $ipv4Gateways, string $bootId): array
    {
        $tunnelGateways = [];
        foreach ($managed as $instance) {
            if (isset($ipv4Gateways[$instance])) {
                $tunnelGateways[$ipv4Gateways[$instance]['gateway']] = $ipv4Gateways[$instance]['underlay'];
            }
        }
        $plan = ['rows' => [], 'dropped' => []];
        foreach (array_values(array_unique($held)) as $uuid) {
            if ($bootId !== '' && isset($tunnelGateways[$uuid]) && !empty($gateways[$uuid])) {
                $underlay = $tunnelGateways[$uuid];
                $plan['rows'][] = [
                    'gateway' => $uuid, 'boot' => $bootId,
                    'underlay' => preg_match(self::UNDERLAY_MASK, $underlay) === 1 ? $underlay : '',
                ];
            } else {
                $plan['dropped'][] = $uuid;
            }
        }
        return $plan;
    }

    /**
     * @param \OPNsense\WGClientTunnels\WGClientTunnels $model
     */
    public function run($model)
    {
        parent::run($model);
        $node = Config::getInstance()->object()->OPNsense->WGClientTunnels;
        if (!isset($node->managed) && !isset($node->held)) {
            /* nothing a 3.0.0 settings node left: a new install */
            return;
        }
        if (!is_readable(self::TUNNELS_LIB)) {
            throw new \RuntimeException(self::TUNNELS_LIB . ' cannot be read; the managed list and holds stay where they are');
        }
        require_once self::TUNNELS_LIB;
        $managedRaw = (string)$node->managed;
        $managed = wgct_split_csv($managedRaw);
        $held = wgct_split_csv((string)$node->held);
        $bootId = Engine::liveBootId();
        $gateways = [];
        $ipv4Gateways = [];
        $names = [];
        try {
            [$gateways, $ipv4Gateways, $names] = self::tunnelGateways($managed);
        } catch (\Throwable $e) {
            wgct_log(LOG_WARNING, '[wgct-migrate] the tunnels\' gateways cannot be read (' . $e->getMessage()
                . '); no hold is carried over');
        }
        $plan = self::plan($managed, $held, $gateways, $ipv4Gateways, $bootId);

        $engine = new Engine();
        $engine->runMigrations();
        if (isset($node->managed)) {
            $engine->managed = $managedRaw;
        }
        $now = time();
        $engine->setHolds(array_map(fn (array $row): array => $row + ['taken_at' => $now], $plan['rows']));
        $engine->serializeToConfig();

        $name = fn (string $uuid): string => isset($names[$uuid]) ? "{$names[$uuid]} ({$uuid})" : $uuid;
        if ($bootId === '') {
            if ($plan['dropped'] !== []) {
                wgct_log(LOG_WARNING, '[wgct-migrate] kern.boot_id cannot be read, so no hold is carried over; '
                    . implode(', ', array_map($name, $plan['dropped'])) . ' keep their force_down until it is cleared by hand');
            }
            return;
        }
        foreach ($plan['rows'] as $row) {
            wgct_log(LOG_NOTICE, '[wgct-migrate] the hold of ' . $name($row['gateway']) . " is carried over, taken in boot {$bootId}");
        }
        foreach ($plan['dropped'] as $uuid) {
            wgct_log(LOG_NOTICE, '[wgct-migrate] held gateway ' . $name($uuid)
                . ' is not held by this plugin; dropped, its force_down left as it is');
        }
    }

    /**
     * The gateway facts plan() takes, from the plugin's derivation of the managed tunnels.
     *
     * @param list<string> $managed
     * @return array{0: array<string, bool>, 1: array<string, array{gateway: string, underlay: string}>, 2: array<string, string>}
     *         gateway uuid => force_down; instance uuid => its IPv4 gateway uuid and bound WAN; gateway uuid => name
     */
    private static function tunnelGateways(array $managed): array
    {
        $core = wgct_core_snapshot();
        $forceDown = [];
        $names = [];
        foreach ($core['gateways'] as $gwName => $g) {
            $forceDown[$g['uuid']] = $g['force_down'];
            $names[$g['uuid']] = (string)$gwName;
        }
        $ipv4 = [];
        foreach (wgct_derive($core, $managed)['tunnels'] as $t) {
            $gw = $t['gw4'] !== null ? ($core['gateways'][$t['gw4']] ?? null) : null;
            if ($gw !== null) {
                $ipv4[$t['uuid']] = ['gateway' => $gw['uuid'], 'underlay' => (string)$t['bound_wan']];
            }
        }
        return [$forceDown, $ipv4, $names];
    }
}
