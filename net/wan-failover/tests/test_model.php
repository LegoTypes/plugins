<?php

declare(strict_types=1);

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
 * The settings model's Save-time validation of the WAN gateways. Needs the OPNsense model classes, so it runs only on
 * the test VM (vm_selftest.sh) and reports a skip anywhere else. The tree's own model is loaded by path, so the class
 * tested is the one under test, and it loads this tree's scripts library.
 *
 * The suite does not write config.xml. Some cases change the saved selection and a gateway's monitoring in the
 * configuration object in memory and put them back (wf_t_model_saved()), with the file's md5 as the guard.
 */

use OPNsense\Routing\Gateways;
use OPNsense\WanFailover\WanFailover;

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/selftest.php';

/**
 * The messages on the wans field after a fresh model takes the selection $post makes of the saved one.
 *
 * @param callable(string): string $post the saved selection (a comma list of gateway UUIDs) => the posted one
 * @return list<string>
 */
function wf_t_model_wans(callable $post): array
{
    $m = new WanFailover();
    $m->setNodes(['wans' => $post($m->wans->getValue())]);
    $out = [];
    foreach ($m->performValidation() as $msg) {
        if ($msg->getField() === $m->wans->__reference) {
            $out[] = (string)$msg->getMessage();
        }
    }
    return $out;
}

/**
 * Sets monitor_disable on the gateways $values names, in the configuration object only (serialized, never saved).
 *
 * @param array<string, string> $values gateway UUID => '1' or '0'
 * @return array<string, string> what each of them held before
 */
function wf_t_model_monitor(array $values): array
{
    if ($values === []) {
        return [];
    }
    $gateways = new Gateways();
    $was = [];
    foreach ($gateways->gateway_item->iterateItems() as $uuid => $gw) {
        if (isset($values[(string)$uuid])) {
            $was[(string)$uuid] = $gw->monitor_disable->getValue();
            $gw->monitor_disable->setValue($values[(string)$uuid]);
        }
    }
    $gateways->serializeToConfig(false, true);
    return $was;
}

/**
 * $body's verdict with the saved selection set to $wans and monitoring turned off on the gateways $monitorOff, in the
 * configuration object only (serialized, never saved), and put back whatever happens. config.xml's md5 across the
 * whole is the guard: should anything have written the file, the case fails with a line saying so.
 *
 * @param string $wans the saved selection, a comma list of gateway UUIDs
 * @param list<string> $monitorOff gateway UUIDs
 * @param callable(): bool $body
 */
function wf_t_model_saved(string $wans, array $monitorOff, callable $body): bool
{
    $config = '/conf/config.xml';
    $before = md5_file($config);
    $saved = null;
    $monitor = [];
    $ok = false;
    try {
        $m = new WanFailover();
        $saved = $m->wans->getValue();
        $m->wans->setValue($wans);
        $m->serializeToConfig(false, true);
        $monitor = wf_t_model_monitor(array_fill_keys($monitorOff, '1'));
        $ok = $body();
    } finally {
        wf_t_model_monitor($monitor);
        if ($saved !== null) {
            $m = new WanFailover();
            $m->wans->setValue($saved);
            $m->serializeToConfig(false, true);
        }
        $written = md5_file($config) !== $before;
        if ($written) {
            echo "  config.xml was written while the settings were changed in memory: restore the VM to the "
                . "'wan-failover base' checkpoint before anything else runs\n";
        }
    }
    return $ok && !$written;
}

/**
 * A gateway's UUID by name, from core's Gateways model.
 */
function wf_t_model_gateway_uuid(string $name): string
{
    foreach ((new Gateways())->gateway_item->iterateItems() as $uuid => $gw) {
        if ($gw->name->getValue() === $name) {
            return (string)$uuid;
        }
    }
    return '';
}

wf_register_suite('model', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $loader = '/usr/local/opnsense/mvc/script/load_phalcon.php';
    $class = __DIR__ . '/../src/opnsense/mvc/app/models/OPNsense/WanFailover/WanFailover.php';
    if (!is_file($loader)) {
        wf_check($t, 'model: skipped, the OPNsense framework is not installed here', true);
        return wf_tally_report('model', $t);
    }
    require_once $loader;
    require_once $class;

    $dhcp = wf_t_model_gateway_uuid('WAN_DHCP');
    $b = wf_t_model_gateway_uuid('WAN_B');
    if ($dhcp === '' || $b === '') {
        printf("  the VM's gateways: WAN_DHCP %s, WAN_B %s\n", $dhcp === '' ? '(none)' : $dhcp, $b === '' ? '(none)' : $b);
    }
    $same = fn (string $saved): string => $saved;
    $reversed = fn (string $saved): string => implode(',', array_reverse(explode(',', $saved)));

    /* a selection saved before, holding a gateway whose monitoring is off since, stays as it is on any Save */
    $ok = $dhcp !== '' && $b !== '' && wf_t_model_saved("{$dhcp},{$b}", [$b],
        fn (): bool => wf_t_model_wans($same) === [] && wf_t_model_wans($reversed) === []);
    wf_check($t, 'model: an unchanged saved selection is accepted', $ok);
    $ok = $dhcp !== '' && wf_t_model_saved('', [], fn (): bool => wf_t_model_wans(fn (string $saved): string => $dhcp) === []);
    wf_check($t, 'model: a selection of monitored, enabled gateways is accepted', $ok);
    $refused = [];
    $ok = $b !== '' && wf_t_model_saved('', [$b], function () use ($b, &$refused): bool {
        $refused = wf_t_model_wans(fn (string $saved): string => $b);
        return $refused === ['WAN_B has gateway monitoring disabled, so the plugin can never judge it. Enable monitoring '
            . 'under System: Gateways: Configuration, or deselect it.'];
    });
    wf_check($t, 'model: a Save that adds a gateway with monitoring off is refused on wans, naming it', $ok);
    if (!$ok) {
        printf("  messages on wans: %s\n", json_encode($refused));
    }

    wf_check($t, 'model: a reordered saved selection adds nothing', WanFailover::addedWans('u2,u1', 'u1,u2') === []);
    wf_check($t, 'model: a deselected gateway adds nothing', WanFailover::addedWans('u1,u2,u3', 'u1,u3') === []);
    wf_check($t, 'model: a new gateway is the only addition',
        WanFailover::addedWans('u2', 'u1,u2,u3') === ['u1', 'u3'] && WanFailover::addedWans('', 'u1,,u1') === ['u1']);

    $disabled = fn (string $name): string => "{$name} is disabled, so the plugin can never judge it. Enable it under "
        . 'System: Gateways: Configuration, or deselect it.';
    $unmonitored = fn (string $name): string => "{$name} has gateway monitoring disabled, so the plugin can never judge "
        . 'it. Enable monitoring under System: Gateways: Configuration, or deselect it.';
    $gw = fn (string $name, bool $monitorOff, bool $off): array => ['name' => $name, 'monitor_disable' => $monitorOff,
        'disabled' => $off];
    wf_check($t, 'model: a disabled gateway is named',
        WanFailover::wanProblems(['u1'], ['u1' => $gw('WAN_A', false, true)]) === [$disabled('WAN_A')]);
    wf_check($t, 'model: a monitor-disabled gateway is named',
        WanFailover::wanProblems(['u2'], ['u2' => $gw('WAN_B', true, false)]) === [$unmonitored('WAN_B')]);
    wf_check($t, 'model: a disabled gateway with monitoring off gets the disabled message only',
        WanFailover::wanProblems(['u1'], ['u1' => $gw('WAN_A', true, true)]) === [$disabled('WAN_A')]);
    $gateways = ['u1' => $gw('WAN_A', false, true), 'u2' => $gw('WAN_B', true, false), 'u3' => $gw('WAN_DHCP', false, false)];
    wf_check($t, 'model: two bad gateways give two messages in selection order',
        WanFailover::wanProblems(['u2', 'u3', 'u1'], $gateways) === [$unmonitored('WAN_B'), $disabled('WAN_A')]);
    wf_check($t, 'model: an unknown UUID gives no message here', WanFailover::wanProblems(['u9'], $gateways) === []);

    return wf_tally_report('model', $t);
});
