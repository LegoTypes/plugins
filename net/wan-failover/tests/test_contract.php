<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Core-contract checks, spec section 3.12. The texts are minimal copies of the core sections the
 * plugin depends on.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/contract.php';

const WF_T_IFACE = "[routes.configure]\ncommand:/usr/local/etc/rc.routing_configure\n\n[routes.alarm]\ncommand:/usr/local/bin/flock -n -E 0 -o /tmp/filter_reload_gateway.lock /usr/local/etc/rc.routing_configure alarm\nparameters: %s\ntype:script\n";
const WF_T_FILTER = "[kill.state]\ncommand:/sbin/pfctl\nparameters: -k id -k %s/%s 2>&1\n\n[kill.gateway_states]\ncommand:/sbin/pfctl\nparameters: -k gateway -k %s 2>&1\n";
const WF_T_TS = "[restart]\ncommand:/usr/local/etc/rc.d/tailscaled restart\ntype: script\n";
const WF_T_RC = "/usr/local/etc/rc.syshook early\n# PHP starts here\n/usr/local/bin/flock -n -o \${BOOTLOCK} /usr/local/etc/rc.bootup || exit 1\n";

wf_register_suite('contract', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    wf_check($t, 'section extraction', str_contains((string)wf_ini_section(WF_T_FILTER, 'kill.gateway_states'), '-k gateway -k %s'));
    wf_check($t, 'all command dependencies match', wf_contract_commands(WF_T_IFACE, WF_T_FILTER, WF_T_RC) === []);
    $noLock = str_replace('/tmp/filter_reload_gateway.lock', '/tmp/other.lock', WF_T_IFACE);
    wf_check($t, 'routes.alarm without the gateway lock is reported', count(wf_contract_commands($noLock, WF_T_FILTER, WF_T_RC)) === 1);
    $killState = str_replace('-k id -k %s/%s', '-k key -k %s', WF_T_FILTER);
    wf_check($t, 'a changed kill.state is reported', count(wf_contract_commands(WF_T_IFACE, $killState, WF_T_RC)) === 1);
    wf_check($t, 'Tailscale not installed (no actions file) is not a drift', wf_contract_tailscale(null) === []);
    wf_check($t, 'Tailscale actions without [restart] are reported in their own class', count(wf_contract_tailscale("[start]\n")) === 1);
    wf_check($t, 'Tailscale actions with [restart] match', wf_contract_tailscale(WF_T_TS) === []);
    $swapped = "/usr/local/etc/rc.bootup\n/usr/local/etc/rc.syshook early\n";
    wf_check($t, 'early hooks after rc.bootup is reported', count(wf_contract_commands(WF_T_IFACE, WF_T_FILTER, $swapped)) === 1);
    wf_check($t, 'unreadable files are reported', count(wf_contract_commands(null, null, null)) === 3);

    $row = ['current_losslow' => '10', 'current_losshigh' => '20', 'current_time_period' => '60',
            'current_interval' => '1', 'current_loss_interval' => '4'];
    $status = ['status' => 'none', 'loss' => '0.0 %'];
    $route = "   route to: default\ndestination: default\n    gateway: 203.0.113.1\n";
    wf_check($t, 'all judging dependencies match', wf_contract_judging($row, $status, $route, true) === []);
    $short = $row;
    unset($short['current_losslow']);
    wf_check($t, 'a missing current_losslow is reported', count(wf_contract_judging($short, $status, $route, true)) === 1);
    wf_check($t, 'a status row without loss is reported', count(wf_contract_judging($row, ['status' => 'none'], $route, true)) === 1);
    wf_check($t, 'unparseable route output is reported', count(wf_contract_judging($row, $status, "garbage\n", true)) === 1);
    wf_check($t, 'no dpinger socket where expected is reported', count(wf_contract_judging($row, $status, $route, false)) === 1);

    $ok = ['judging' => [], 'command' => []];
    $bad = ['judging' => [], 'command' => ['x changed']];
    $r = wf_contract_log($ok, '');
    wf_check($t, 'log: steady match logs nothing', $r['line'] === null);
    $r = wf_contract_log($bad, '');
    wf_check($t, 'log: a new drift logs once as a warning', $r['line'] !== null && $r['prio'] === LOG_WARNING);
    $r2 = wf_contract_log($bad, $r['last']);
    wf_check($t, 'log: the same drift is not logged again', $r2['line'] === null);
    $r4 = wf_contract_log(['judging' => [], 'command' => [], 'tailscale' => ['no [restart]']], '');
    wf_check($t, 'log: a Tailscale-only drift says only Tailscale restarts are off', $r4['line'] !== null && str_contains($r4['line'], 'Tailscale restarts off'));
    $r3 = wf_contract_log($ok, $r['last']);
    wf_check($t, 'log: the return to a match is logged', $r3['line'] !== null && str_contains($r3['line'], 'matches again'));
    return wf_tally_report('contract', $t);
});
