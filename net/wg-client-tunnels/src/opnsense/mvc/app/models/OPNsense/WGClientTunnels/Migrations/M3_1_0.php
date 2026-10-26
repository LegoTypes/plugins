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
 * is for a person to clear. A managed tunnel's IPv6 gateway that is forced down becomes a hold record too, its
 * IPv4 tunnel as underlay (spec 3.5a), but only when the 3.0.0 mirror ran (the plugin and its health mirror both
 * on): only then did it rewrite that force_down on every tick, so only then was it the mirror's. With either off,
 * such a gateway is a person's or Create's, and is left forced down as manual, logged once by name (ruling R35).
 * The engine model is brought to its own version before it is written, so the outcome is the same whichever of the
 * two models core migrates first. Once the models are serialized, the boot the rows carry is recorded in boot.json,
 * as the mirror records the boot it runs under: a reboot before the mirror's first tick then still finds the
 * carried rows to be from the boot before it, and so its own.
 */
class M3_1_0 extends BaseModelMigration
{
    /* the plugin's derivation, which knows each tunnel's IPv4 gateway and its bound WAN */
    private const TUNNELS_LIB = '/usr/local/opnsense/scripts/OPNsense/WGClientTunnels/lib/tunnels.php';

    /* the health mirror's library, whose boot.json writer the migration shares */
    private const MIRROR_LIB = '/usr/local/opnsense/scripts/OPNsense/WGClientTunnels/lib/mirror.php';

    /* the engine model's mask for a hold record's underlay */
    private const UNDERLAY_MASK = '/^[a-zA-Z0-9_-]{1,32}$/D';

    /* the boot run() stamped the carried rows with, '' when it carried nothing over or could not read it */
    private string $bootId = '';

    /**
     * Which gateways become hold records: the held ones, then the forced IPv6 pair gateways. Pure.
     *
     * @param list<string>                                             $managed      managed instance uuids, as stored
     * @param list<string>                                             $held         held gateway uuids, as stored
     * @param array<string, bool>                                      $gateways     gateway uuid => force_down
     * @param array<string, array{gateway: string, underlay: string}> $ipv4Gateways instance uuid => its tunnel's
     *                                                                               IPv4 gateway uuid and bound WAN
     * @param list<array{gateway: string, underlay: string}>          $ipv6Gateways the IPv6 gateways the mirror's
     *                                                                               pass 2 governs: uuid and the
     *                                                                               IPv4 tunnel gateway it follows
     * @param bool                                                     $enabled      the 3.0.0 plugin switch
     * @param bool                                                     $healthMirror the 3.0.0 health mirror switch
     * @param string                                                   $bootId       the live kern.boot_id, '' when
     *                                                                               it cannot be read
     * @return array{rows: list<array{gateway: string, boot: string, underlay: string}>, dropped: list<string>,
     *               manual: list<string>}
     *         each held uuid and each forced IPv6 pair gateway once, held first: a row, dropped, or (a forced IPv6
     *         pair gateway while the 3.0.0 mirror did not run) left forced down as manual
     */
    public static function plan(array $managed, array $held, array $gateways, array $ipv4Gateways, array $ipv6Gateways,
        bool $enabled, bool $healthMirror, string $bootId): array
    {
        $tunnelGateways = [];
        foreach ($managed as $instance) {
            if (isset($ipv4Gateways[$instance])) {
                $tunnelGateways[$ipv4Gateways[$instance]['gateway']] = $ipv4Gateways[$instance]['underlay'];
            }
        }
        $forced6 = [];
        foreach ($ipv6Gateways as $g) {
            if (!empty($gateways[$g['gateway']])) {
                $forced6[$g['gateway']] = $g['underlay'];
            }
        }
        $row = fn (string $uuid, string $underlay): array => [
            'gateway' => $uuid, 'boot' => $bootId, 'underlay' => preg_match(self::UNDERLAY_MASK, $underlay) === 1 ? $underlay : '',
        ];
        $plan = ['rows' => [], 'dropped' => [], 'manual' => []];
        foreach (array_values(array_unique($held)) as $uuid) {
            if (isset($forced6[$uuid])) {
                continue;
            }
            if ($bootId !== '' && isset($tunnelGateways[$uuid]) && !empty($gateways[$uuid])) {
                $plan['rows'][] = $row($uuid, $tunnelGateways[$uuid]);
            } else {
                $plan['dropped'][] = $uuid;
            }
        }
        foreach ($forced6 as $uuid => $underlay) {
            if (!$enabled || !$healthMirror) {
                $plan['manual'][] = (string)$uuid;
            } elseif ($bootId !== '') {
                $plan['rows'][] = $row((string)$uuid, $underlay);
            } else {
                $plan['dropped'][] = (string)$uuid;
            }
        }
        return $plan;
    }

    /**
     * What the migration logs for its plan. Pure.
     *
     * @param array{rows: list<array{gateway: string}>, dropped: list<string>, manual: list<string>} $plan plan()'s
     * @param list<string>          $held          held gateway uuids, as stored
     * @param string                $bootId        the live kern.boot_id, '' when it cannot be read
     * @param string|null           $gatewaysError why the tunnels' gateways cannot be read; then nothing is planned
     *                                             and each held gateway is left as it is
     * @param array<string, string> $names         gateway uuid => name
     * @return list<array{0: int, 1: string}> priority and line, in order
     */
    public static function report(array $plan, array $held, string $bootId, ?string $gatewaysError, array $names): array
    {
        $name = fn (string $uuid): string => isset($names[$uuid]) ? "{$names[$uuid]} ({$uuid})" : $uuid;
        $keep = fn (array $uuids): string => implode(', ', array_map($name, $uuids)) . ' keep their force_down until it is cleared by hand';
        if ($gatewaysError !== null) {
            $held = array_values(array_unique($held));
            return [[LOG_WARNING, "[wgct-migrate] the tunnels' gateways cannot be read ({$gatewaysError}), so no hold is carried over"
                . ($held !== [] ? '; ' . $keep($held) : '')]];
        }
        $lines = [];
        if ($plan['manual'] !== []) {
            $lines[] = [LOG_NOTICE, '[wgct-migrate] ' . implode(', ', array_map($name, $plan['manual']))
                . ' left forced down as manual: the 3.7_1 health mirror was off'];
        }
        if ($bootId === '') {
            if ($plan['dropped'] !== []) {
                $lines[] = [LOG_WARNING, '[wgct-migrate] kern.boot_id cannot be read, so no hold is carried over; ' . $keep($plan['dropped'])];
            }
            return $lines;
        }
        foreach ($plan['rows'] as $row) {
            $lines[] = [LOG_NOTICE, '[wgct-migrate] the hold of ' . $name($row['gateway']) . " is carried over, taken in boot {$bootId}"];
        }
        /* with a live boot id a forced IPv6 pair gateway has a row or is manual, so only held gateways are dropped */
        foreach ($plan['dropped'] as $uuid) {
            $lines[] = [LOG_NOTICE, '[wgct-migrate] held gateway ' . $name($uuid) . ' is not held by this plugin; dropped, its force_down left as it is'];
        }
        return $lines;
    }

    /**
     * Record in boot.json the boot the carried rows were stamped with. With no readable boot id nothing was stamped,
     * so nothing is recorded (ruling R17). Pure but for $record.
     *
     * @param string                 $bootId the boot run() stamped, '' for none
     * @param callable(string): bool $record wgct_record_boot()
     * @return string|null the warning to log when boot.json cannot record it, else null
     */
    public static function recordBoot(string $bootId, callable $record): ?string
    {
        if ($bootId === '' || $record($bootId)) {
            return null;
        }
        return "[wgct-migrate] boot {$bootId} could not be recorded in boot.json;"
            . ' a reboot before the first health mirror tick makes the carried holds foreign';
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
        $this->bootId = $bootId;
        $plan = ['rows' => [], 'dropped' => [], 'manual' => []];
        $names = [];
        $gatewaysError = null;
        try {
            [$gateways, $ipv4Gateways, $ipv6Gateways, $names] = self::tunnelGateways($managed);
            $plan = self::plan($managed, $held, $gateways, $ipv4Gateways, $ipv6Gateways,
                (string)$node->enabled === '1', (string)$node->health_mirror === '1', $bootId);
        } catch (\Throwable $e) {
            $gatewaysError = $e->getMessage();
        }

        $engine = new Engine();
        $engine->runMigrations();
        if (isset($node->managed)) {
            $engine->managed = $managedRaw;
        }
        $now = time();
        $engine->setHolds(array_map(fn (array $row): array => $row + ['taken_at' => $now], $plan['rows']));
        $engine->serializeToConfig();

        foreach (self::report($plan, $held, $bootId, $gatewaysError, $names) as [$priority, $line]) {
            wgct_log($priority, $line);
        }
    }

    /**
     * After core serialized the migrated models: boot.json (recordBoot()). Core reads a throw here as a model that
     * cannot be saved and then saves nothing, so every failure is logged instead.
     *
     * @param \OPNsense\WGClientTunnels\WGClientTunnels $model
     */
    public function post($model)
    {
        if ($this->bootId === '') {
            return;
        }
        try {
            if (!is_readable(self::MIRROR_LIB)) {
                throw new \RuntimeException(self::MIRROR_LIB . ' cannot be read');
            }
            require_once self::MIRROR_LIB;
            $warning = self::recordBoot($this->bootId, 'wgct_record_boot');
        } catch (\Throwable $e) {
            $warning = "[wgct-migrate] boot {$this->bootId} could not be recorded in boot.json (" . $e->getMessage()
                . '); a reboot before the first health mirror tick makes the carried holds foreign';
        }
        if ($warning !== null) {
            wgct_log(LOG_WARNING, $warning);
        }
    }

    /**
     * The gateway facts plan() takes, from the plugin's derivation of the managed tunnels. The IPv6 gateways are the
     * pairs the mirror's pass 2 governs (wgct_mirror_inputs()), less a disabled one, which pass 2 leaves alone.
     *
     * @param list<string> $managed
     * @return array{0: array<string, bool>, 1: array<string, array{gateway: string, underlay: string}>,
     *               2: list<array{gateway: string, underlay: string}>, 3: array<string, string>}
     *         gateway uuid => force_down; instance uuid => its IPv4 gateway uuid and bound WAN; each IPv6 pair
     *         gateway's uuid and the IPv4 tunnel gateway it follows; gateway uuid => name
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
        $derived = wgct_derive($core, $managed);
        $ipv4 = [];
        foreach ($derived['tunnels'] as $t) {
            $gw = $t['gw4'] !== null ? ($core['gateways'][$t['gw4']] ?? null) : null;
            if ($gw !== null) {
                $ipv4[$t['uuid']] = ['gateway' => $gw['uuid'], 'underlay' => (string)$t['bound_wan']];
            }
        }
        $ipv6 = [];
        foreach (wgct_mirror_inputs($derived)['pairs'] as $gw4Name => $gw6Name) {
            $gw6 = $core['gateways'][$gw6Name] ?? null;
            if ($gw6 !== null && !$gw6['disabled']) {
                $ipv6[] = ['gateway' => $gw6['uuid'], 'underlay' => (string)$gw4Name];
            }
        }
        return [$forceDown, $ipv4, $ipv6, $names];
    }
}
