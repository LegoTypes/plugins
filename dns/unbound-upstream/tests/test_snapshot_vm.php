<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The live snapshot against the test VM's gateways (spec section 3.2). Runs only where core and the VM's
 * proton_test_grp exist; elsewhere it registers a suite that skips. Read-only, except that a snapshot makes the
 * plugin's run directory 0700 if it is missing or another mode (ruling R10).
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/snapshot.php';

uu_register_suite('snapshot_vm', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    if (!is_readable('/usr/local/etc/inc/config.inc') || !is_readable('/usr/local/opnsense/mvc/app/models/OPNsense/Routing/GatewayGroups.php')) {
        printf("[SKIP] snapshot_vm: core is not on this machine\n");
        return uu_tally_report('snapshot_vm', $t);
    }
    uu_load_core();
    if (!isset((new \OPNsense\Routing\GatewayGroups())->getGroupsConfig()['proton_test_grp'])) {
        printf("[SKIP] snapshot_vm: the test VM's proton_test_grp is not configured\n");
        return uu_tally_report('snapshot_vm', $t);
    }
    $settings = ['enabled' => true, 'dry_run' => true, 'group' => 'proton_test_grp', 'resolver' => '10.2.0.1',
                 'failback_delay' => 120, 'probe_name' => '.'];
    $s = uu_snapshot($settings, [], null, false);
    uu_check($t, 'settings pass through, trigger is the group\'s', $s['settings'] === $settings && $s['trigger'] === 'downloss');
    uu_check($t, 'now is monotonic seconds', abs($s['now'] - intdiv(hrtime(true), 1000000000)) <= 2);
    uu_check($t, 'tiers best first', $s['tiers'] === [['wg-test-429'], ['wg-test-529']]);
    $a = $s['members']['wg-test-429'] ?? null;
    $b = $s['members']['wg-test-529'] ?? null;
    $core = (new \OPNsense\Routing\Gateways())->gatewaysIndexedByName(true)['wg-test-429'] ?? [];
    $timers = ['time_period' => (int)($core['current_time_period'] ?? -1), 'interval' => (int)($core['current_interval'] ?? -1),
               'loss_interval' => (int)($core['current_loss_interval'] ?? -1), 'losshigh' => (int)($core['current_losshigh'] ?? -1)];
    uu_check($t, 'members: device, next hop and monitor timers as core resolves them',
        $a !== null && $b !== null && array_keys($s['members']) === ['wg-test-429', 'wg-test-529']
        && $a['if'] === 'wg1' && $b['if'] === 'wg2' && $a['next_hop'] === '10.2.0.4' && $b['next_hop'] === '10.2.0.5'
        && min($timers) >= 0 && $a['time_period'] === $timers['time_period'] && $a['interval'] === $timers['interval']
        && $a['loss_interval'] === $timers['loss_interval'] && $a['losshigh'] === $timers['losshigh']
        && !$a['disabled'] && !$a['force_down'] && !$a['monitor_disable'] && $a['interface'] !== '');
    uu_check($t, 'probes for both members', array_keys($s['probes']) === ['wg-test-429', 'wg-test-529']
        && is_string($s['probes']['wg-test-429']['status']) && is_string($s['probes']['wg-test-429']['loss'])
        && is_int($s['probes']['wg-test-429']['sock_age']) && $s['probes']['wg-test-429']['sock_age'] >= 0
        && is_int($s['probes']['wg-test-529']['sock_age']) && $s['probes']['wg-test-529']['sock_age'] >= 0);
    uu_check($t, 'named and stop are what the caller passed', $s['named'] === [] && $s['stop'] === null
        && uu_snapshot($settings, ['wg-test-529'], UU_STOP_REQUEST, false)['named'] === ['wg-test-529']
        && uu_snapshot($settings, [], UU_STOP_REMOVE, false)['stop'] === UU_STOP_REMOVE);
    uu_check($t, 'unbound is running and its control channel answers with the live root',
        $s['unbound']['enabled'] && $s['unbound']['pid_alive'] && $s['unbound']['control_ok']
        && $s['unbound']['live_root'] !== null && count($s['unbound']['live_root']) >= 1);
    uu_check($t, 'zone: one forward zone with tls', $s['zone']['shape'] === 'one' && $s['zone']['tls'] && count($s['zone']['addrs']) >= 1);
    uu_check($t, 'route: the VM has no route of the resolver',
        $s['route'] === ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false, 'ours' => false]);
    uu_check($t, 'fib_sync_ms 1000', $s['fib_sync_ms'] === 1000);
    $c = $s['contract_input'];
    uu_check($t, 'contract input: group found, two members, hooks fine, order is a fault only while the hook file is not overlaid',
        $c['group_found'] === true && $c['members'] === 2 && $c['unbound_hooks_registered'] === true
        && $c['unbound_sorts_first'] === is_readable('/usr/local/etc/inc/plugins.inc.d/unboundupstream.inc') && $c['groups_have_tiers'] === true && $c['status_fields'] === true
        && $c['foreign_route'] === false && $c['unmonitored_members'] === [] && $c['resolver_is_monitor'] === []
        && $c['resolver_in_static'] === [] && $c['fib_sync_ms'] === 1000 && $c['zone'] === $s['zone']
        && $c['cacheflush'] === false);
    /* ruling R6: the constants are core's commands as this VM's core runs them, so a drift note means core changed */
    uu_check($t, 'contract input: core\'s filter reload, cron restart and unbound restart are the commands a removal falls back to',
        array_key_exists('core_commands', $c) && $c['core_commands'] === []);

    /* a status snapshot never lists the ruleset: its verdict is the saved record's for the live checksum and these
     * inputs, or verifying, and it has nothing to save; a listing would have returned this run's time and a record */
    $saved = uu_rules_record_load(UU_RULES_PATH);
    $temps = fn (): array => array_merge(glob(UU_RUN_DIR . '/uu_pfctl*') ?: [],
        glob(sys_get_temp_dir() . '/uu_pfctl*') ?: []);
    $before = $temps();
    $run = uu_pfctl_run(['-si', '-v']);
    uu_check($t, 'runner: pfctl -si -v keeps its streams apart (Checksum: on stdout only) and leaves no temp file',
        str_contains($run['out'], 'Checksum:') && !str_contains($run['err'], 'Checksum:') && $temps() === $before);
    $live = uu_pf_checksum($run['out']);
    $r = $s['rules'];
    $inputs = uu_rules_inputs($settings['resolver'], uu_ruled_members($s['members']));
    uu_check($t, 'status snapshot: no listing, so verifying or the saved record\'s verdict, and no record to save',
        $r['record'] === null && ($saved !== null && $saved['checksum'] === $live
            && $saved['inputs'] === $inputs
            ? $r['state'] === ($saved['loaded'] ? 'loaded' : 'missing') && $r['verified_at'] === $saved['at']
            : $r === ['state' => 'verifying', 'problems' => [], 'verified_at' => null, 'record' => null]));
    uu_check($t, 'contract input: the rules\' state and problems',
        $c['rules'] === ['state' => $r['state'], 'problems' => $r['problems']]);
    uu_check($t, 'block table: no addresses without the table',
        $s['block_table']['table'] !== null || $s['block_table']['addresses'] === []);
    /* an evaluation snapshot under the test settings, which the VM does not render rules for: a record made for
     * other inputs (the VM's own settings) is not reused, so these rules read missing, naming wg-test-429 */
    $e = uu_snapshot($settings, [], null, true);
    $er = $e['rules'];
    uu_check($t, 'evaluation snapshot: the test settings\' rules are missing, naming wg-test-429, and recorded under '
        . 'the live checksum and these inputs unless a record of exactly those is saved',
        $er['state'] === 'missing'
        && in_array('no pass rule for wg-test-429 (' . ($a['interface'] ?? '') . ')', $er['problems'], true)
        && ($saved !== null && $saved['checksum'] === $live && $saved['inputs'] === $inputs
            ? $er['record'] === null && $er['verified_at'] === $saved['at']
            : $er['record'] !== null && $er['record']['checksum'] === $live && $er['record']['inputs'] === $inputs
                && $er['verified_at'] === $er['record']['at']));

    $gone = uu_snapshot(['group' => 'no_such_group'] + $settings, [], null, false);
    uu_check($t, 'a group that does not exist: no tiers, no members, group_found false',
        $gone['tiers'] === [] && $gone['members'] === [] && $gone['probes'] === []
        && $gone['contract_input']['group_found'] === false && $gone['contract_input']['members'] === 0);
    $none = uu_snapshot(['group' => ''] + $settings, [], null, false);
    uu_check($t, 'no group set: group_found false', $none['contract_input']['group_found'] === false);

    return uu_tally_report('snapshot_vm', $t);
});
