<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The live snapshot against the test VM's gateways. Runs only where core and the VM's
 * proton_test_grp exist; elsewhere it registers a suite that skips. Read-only, except that a snapshot makes the
 * plugin's run directory 0700 if it is missing or another mode.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/snapshot.php';
require_once __DIR__ . '/scratch.php';

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
    $settings = ['enabled' => true, 'dry_run' => true, 'group' => 'proton_test_grp',
                 'default' => '10.2.0.1', 'rows' => [], 'failback_delay' => 120, 'probe_name' => '.',
                 'fallback' => true, 'fail_closed' => [], 'fail_closed_networks' => []];
    $s = uu_snapshot($settings, [], null, false, []);
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
        && uu_snapshot($settings, ['wg-test-529'], UU_STOP_REQUEST, false, [])['named'] === ['wg-test-529']
        && uu_snapshot($settings, [], UU_STOP_REMOVE, false, [])['stop'] === UU_STOP_REMOVE);
    uu_check($t, 'unbound is running and its control channel answers with the live root',
        $s['unbound']['enabled'] && $s['unbound']['pid_alive'] && $s['unbound']['control_ok']
        && $s['unbound']['live_root'] !== null && count($s['unbound']['live_root']) >= 1);
    uu_check($t, 'zone: one forward zone with tls', $s['zone']['shape'] === 'one' && $s['zone']['tls'] && count($s['zone']['addrs']) >= 1);
    uu_check($t, 'route: the VM has no route of the resolver',
        $s['routes']['10.2.0.1'] === ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false,
            'ours' => false]);
    uu_check($t, 'fib_sync_ms 1000', $s['fib_sync_ms'] === 1000);
    $c = $s['contract_input'];
    uu_check($t, 'contract input: group found, two members, hooks fine, order is a fault only while the hook file is not overlaid',
        $c['group_found'] === true && $c['members'] === 2 && $c['unbound_hooks_registered'] === true
        && $c['unbound_sorts_first'] === is_readable('/usr/local/etc/inc/plugins.inc.d/unboundupstream.inc') && $c['groups_have_tiers'] === true && $c['status_fields'] === true
        && $c['foreign'] === [] && $c['unmonitored_members'] === [] && $c['monitors'] === []
        && $c['statics'] === [] && $c['fib_sync_ms'] === 1000 && $c['zone'] === $s['zone']
        && $c['cacheflush'] === false);
    /* (c6) the generated configuration, read as core wrote it, on a base that allows both families */
    uu_check($t, '(c6) the live unbound.conf reads do-ip4 and do-ip6 on and no outgoing interface; the contract input '
        . 'carries them with the group\'s family and no mix or mismatch',
        uu_try_case(fn (): bool => uu_unbound_conf_facts((string)uu_conf_file_text())
                === ['do_ip4' => true, 'do_ip6' => true, 'outgoing_interface' => false]
            && $c['unbound_conf'] === ['do_ip4' => true, 'do_ip6' => true, 'outgoing_interface' => false]
            && $c['group_family'] === 'inet' && $c['mixed_family'] === false && $c['family_mismatch'] === []));
    /* a read that lands in a rewrite of the live file sees a prefix of it: none refuses what the whole does not */
    uu_check($t, '(c6) no byte prefix of the live unbound.conf reports a refusal',
        uu_try_case(function (): bool {
            $text = (string)uu_conf_file_text();
            for ($n = 0; $n <= strlen($text); $n++) {
                $f = uu_unbound_conf_facts(substr($text, 0, $n));
                if (!$f['do_ip4'] || !$f['do_ip6'] || $f['outgoing_interface']) {
                    return false;
                }
            }
            return $text !== '';
        }));
    /* the four contract inputs come from the snapshot's own reads: an IPv6 group with an IPv4 Default, and the same
     * group with an IPv4 member added in memory (config.xml is put back and compared) */
    $far6 = ['enabled' => true, 'dry_run' => true, 'group' => 'uu_far6_grp', 'default' => '10.2.0.1', 'rows' => [],
             'failback_delay' => 120, 'probe_name' => '.', 'fallback' => true, 'fail_closed' => [],
             'fail_closed_networks' => []];
    if (isset((new \OPNsense\Routing\GatewayGroups())->getGroupsConfig()['uu_far6_grp'])) {
        $v6 = uu_snapshot($far6, [], null, false, []);
        uu_check($t, '(c6) an IPv6 group with an IPv4 Default: group_family inet6, the Default listed as a mismatch, '
            . 'no mix, and the contract refuses by that address alone',
            uu_try_case(fn (): bool => $v6['contract_input']['group_family'] === 'inet6'
                && $v6['family'] === 'inet6' && $v6['contract_input']['family_mismatch'] === ['10.2.0.1']
                && $v6['contract_input']['mixed_family'] === false
                && uu_contract($v6['contract_input'])['failures']
                    === ['resolver 10.2.0.1 is IPv4 but the group is IPv6']));
        $v6ok = uu_snapshot(['default' => '2001:db8:a::53'] + $far6, [], null, false, []);
        uu_check($t, '(c6) the same group with an IPv6 Default: nothing to refuse by address',
            uu_try_case(fn (): bool => $v6ok['contract_input']['family_mismatch'] === []
                && $v6ok['contract_input']['group_family'] === 'inet6'));
        $configXml = fn (): string => (string)preg_replace('/ persisted_at="[^"]*"/', '',
            (string)\OPNsense\Core\Config::getInstance()->object()->asXML());
        $before = $configXml();
        $mixed = null;
        $node = null;
        $item2 = '';
        try {
            foreach (\OPNsense\Core\Config::getInstance()->object()->xpath('//gateways/gateway_group') ?: [] as $g) {
                if ((string)$g->name === 'uu_far6_grp') {
                    $node = $g;
                    $item2 = (string)$g->item2;
                }
            }
            if ($node !== null) {
                $node->item2 = $item2 . ',wg-test-429';
                $mixed = uu_snapshot($far6, [], null, false, []);
            }
        } finally {
            if ($node !== null) {
                $node->item2 = $item2;
            }
        }
        uu_check($t, '(c6) a group with an IPv6 and an IPv4 member: mixed_family, no per-address mismatch, and the '
            . 'contract says so; config.xml is as it was',
            uu_try_case(fn (): bool => $mixed !== null && $mixed['contract_input']['mixed_family'] === true
                && $mixed['contract_input']['family_mismatch'] === []
                && uu_contract($mixed['contract_input'])['failures'] === ['the group has IPv4 and IPv6 members']
                && $configXml() === $before));
    }
    /* the constants are core's commands as this VM's core runs them, so a drift note means core changed */
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
    $inputs = uu_rules_inputs(uu_ruled_members($s['members']), $settings['default']);
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
    $e = uu_snapshot($settings, [], null, true, []);
    $er = $e['rules'];
    uu_check($t, 'evaluation snapshot: the test settings\' rules are missing, naming wg-test-429, and recorded under '
        . 'the live checksum and these inputs unless a record of exactly those is saved',
        $er['state'] === 'missing'
        && in_array('no pass rule for wg-test-429 (' . ($a['interface'] ?? '') . ')', $er['problems'], true)
        && ($saved !== null && $saved['checksum'] === $live && $saved['inputs'] === $inputs
            ? $er['record'] === null && $er['verified_at'] === $saved['at']
            : $er['record'] !== null && $er['record']['checksum'] === $live && $er['record']['inputs'] === $inputs
                && $er['verified_at'] === $er['record']['at']));

    $gone = uu_snapshot(['group' => 'no_such_group'] + $settings, [], null, false, []);
    uu_check($t, 'a group that does not exist: no tiers, no members, group_found false',
        $gone['tiers'] === [] && $gone['members'] === [] && $gone['probes'] === []
        && $gone['contract_input']['group_found'] === false && $gone['contract_input']['members'] === 0);
    $none = uu_snapshot(['group' => ''] + $settings, [], null, false, []);
    uu_check($t, 'no group set: group_found false', $none['contract_input']['group_found'] === false);
    uu_check($t, '(g5) a group that does not exist: the Default\'s route is still read, as the planner\'s one address',
        array_keys($gone['routes']) === ['10.2.0.1'] && !array_key_exists('route', $gone)
        && $gone['contract_input']['member_resolvers'] === [] && $gone['contract_input']['foreign'] === []);

    /* (g12) an address the state alone holds, whose live route the plugin did not make: read into routes, and not
     * the contract's foreign (it is no planner address, so it excludes and refuses nothing). The route is a plain
     * host route through loopback to a documentation address, added for this case and deleted after it, and before it
     * too, so a route an interrupted earlier run left cannot stand in for this one */
    $g12 = null;
    try {
        shell_exec('/sbin/route -q delete -host 198.51.100.77 > /dev/null 2>&1');
        shell_exec('/sbin/route -q add -host 198.51.100.77 127.0.0.1 > /dev/null 2>&1');
        $g12 = uu_snapshot($settings, [], null, false, ['198.51.100.77']);
    } catch (\Throwable $e) {
        printf("  threw %s: %s\n", get_class($e), $e->getMessage());
    } finally {
        shell_exec('/sbin/route -q delete -host 198.51.100.77 > /dev/null 2>&1');
    }
    $g12Route = $g12['routes']['198.51.100.77'] ?? null;
    if ($g12 !== null && ($g12Route === null || $g12Route['ours'] || !$g12Route['present'])) {
        printf("  route read: %s\n", json_encode($g12Route));
    }
    uu_check($t, '(g12) a state-only address with a route not the plugin\'s is read, and is not the contract\'s '
        . 'foreign route',
        $g12 !== null && is_array($g12Route) && $g12Route['present'] && !$g12Route['ours']
        && $g12['contract_input']['foreign'] === []);

    uu_check($t, '(t8) static routes: an address in a network of its own family, a bare address as a host, /0 everything',
        uu_try_case(fn (): bool => uu_in_static('2001:db8:a::53', '2001:db8:a::/48')
            && uu_in_static('10.2.0.1', '10.2.0.0/24') && !uu_in_static('10.2.1.1', '10.2.0.0/24')
            && uu_in_static('10.2.0.1', '10.2.0.1') && uu_in_static('10.2.0.1', '0.0.0.0/0')
            && !uu_in_static('10.2.0.1', '10.2.0.2/32') && uu_in_static('2001:db8:a::53', '2001:db8:a::53')
            && !uu_in_static('2001:db8:a::53', '2001:db8:a::54') && !uu_in_static('2001:db8:b::53', '2001:db8:a::/48')));
    uu_check($t, '(t8) static routes: a network of the other family or a malformed one never matches',
        uu_try_case(fn (): bool => !uu_in_static('10.2.0.1', '2001:db8::/32')
            && !uu_in_static('2001:db8:a::53', '10.2.0.0/24') && !uu_in_static('10.2.0.1', 'nonsense')
            && !uu_in_static('10.2.0.1', '10.2.0.0/33') && !uu_in_static('2001:db8::1', '2001:db8::/129')
            && !uu_in_static('', '10.2.0.0/24')));
    uu_check($t, '(t8) static routes: the address is compared in canonical form',
        uu_try_case(fn (): bool => uu_in_static('2001:DB8:A:0::53', '2001:db8:a::/48')));

    /* (p18) the members' own fields and the per-address routes, as core's records and the rows give them: a row is
     * matched to its gateway by the record's uuid, a recorded address is read beside the effective ones */
    $records = (new \OPNsense\Routing\Gateways())->gatewaysIndexedByName(true);
    $uuid529 = (string)($records['wg-test-529']['uuid'] ?? '');
    $p18 = null;
    $p18ok = uu_try_case(function () use ($settings, $uuid529, &$p18): bool {
        $rowed = ['rows' => [$uuid529 => '192.0.2.9']] + $settings;
        $p18 = uu_snapshot($rowed, [], null, false, ['198.51.100.77']);
        return true;
    });
    uu_check($t, '(p18) snapshot: each member carries its ipprotocol and effective resolver (a row by its gateway\'s '
        . 'uuid, else the Default), the group\'s family, and routes over every effective resolver and the state\'s '
        . 'addresses, sorted',
        $p18ok && $p18 !== null && $uuid529 !== ''
        && ($p18['members']['wg-test-429']['ipprotocol'] ?? null) === 'inet'
        && ($p18['members']['wg-test-429']['resolver'] ?? null) === '10.2.0.1'
        && ($p18['members']['wg-test-529']['resolver'] ?? null) === '192.0.2.9'
        && $p18['family'] === 'inet'
        && array_keys($p18['routes']) === ['10.2.0.1', '192.0.2.9', '198.51.100.77']
        && $p18['routes']['192.0.2.9'] === ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false,
                                            'ours' => false]
        && !array_key_exists('route', $p18)
        && $p18['contract_input']['member_resolvers'] === ['wg-test-429' => '10.2.0.1', 'wg-test-529' => '192.0.2.9']
        && $p18['contract_input']['resolver_notes'] === [] && $p18['contract_input']['no_next_hop'] === []
        && $p18['contract_input']['foreign'] === []);
    $p18b = null;
    $p18bOk = uu_try_case(function () use ($settings, &$p18b): bool {
        $p18b = uu_snapshot(['default' => '', 'resolver' => '',
                             'rows' => ['0b6a7f9e-5c1d-4e0a-9d2b-3f8a1c4e5d60' => '192.0.2.9']] + $settings,
            [], null, false, []);
        return true;
    });
    uu_check($t, '(p18) snapshot: with no Default, a member with no row has no resolver, and a row whose uuid names '
        . 'no gateway changes nothing; both are noted',
        $p18bOk && $p18b !== null
        && $p18b['contract_input']['member_resolvers'] === ['wg-test-429' => '', 'wg-test-529' => '']
        && $p18b['contract_input']['resolver_notes'] === [
            'row for gateway 0b6a7f9e-5c1d-4e0a-9d2b-3f8a1c4e5d60 ignored: no such gateway',
            'wg-test-429 has no resolver: not a candidate', 'wg-test-529 has no resolver: not a candidate']
        && $p18b['routes'] === []);

    /* the view: LAN selected and a rendered view loaded. The view comes from a throwaway option file in Unbound's
     * directory (core empties it at every start) read by a reload, with the plugin's file beside it; both are
     * removed and Unbound restarted at the end */
    $viewConf = '/var/unbound/etc/zz-uu-view.conf';
    $viewText = UU_VIEW_BEGIN . "\nserver:\n    access-control-view: 192.168.1.0/24 " . UU_VIEW_NAME . "\nview:\n    name: \""
        . UU_VIEW_NAME . "\"\n    view-first: yes\n    local-zone: \".\" refuse\n    local-data: \"nas.internal. 3600 IN A "
        . "192.0.2.8\"\n" . UU_VIEW_END . "\n";
    $viewSnap = null;
    $viewCleanup = false;
    if (is_dir('/var/unbound/etc') && !file_exists($viewConf) && !file_exists(UU_VIEW_FILE)) {
        try {
            file_put_contents($viewConf, $viewText);
            file_put_contents(UU_VIEW_FILE, $viewText);
            shell_exec('/usr/local/sbin/unbound-control -c /var/unbound/unbound.conf reload > /dev/null 2>&1');
            $deadline = hrtime(true) + 15000000000;
            do {
                usleep(300000);
                $viewSnap = uu_snapshot(['fail_closed' => ['lan']] + $settings, [], null, false, [], true);
            } while ($viewSnap['view']['loaded'] !== 'zones' && hrtime(true) < $deadline);
        } finally {
            @unlink($viewConf);
            @unlink(UU_VIEW_FILE);
            clearstatcache(true, UU_VIEW_FILE);
            shell_exec('/usr/local/sbin/configctl unbound restart > /dev/null 2>&1');
            $deadline = hrtime(true) + 30000000000;
            while (uu_live_root() === null && hrtime(true) < $deadline) {
                usleep(500000);
            }
            /* the evaluation core's start queues must be over before the next suite reads the state: quiet once no
             * evaluation ran for two samples in a row; still running at 60 s is a FAIL with what runs */
            $idle = 0;
            $running = '';
            $deadline = hrtime(true) + 60000000000;
            while ($idle < 2 && hrtime(true) < $deadline) {
                sleep(1);
                $running = trim((string)shell_exec("/bin/pgrep -lf 'UnboundUpstream/evaluate[.]php'"));
                $idle = $running === '' ? $idle + 1 : 0;
            }
            uu_check($t, "snapshot_vm: the evaluation Unbound's restart queued is over within 60 s", $idle >= 2);
            if ($idle < 2) {
                printf("  still running at 60 s: %s\n", str_replace("\n", '; ', $running));
            }
            $viewCleanup = !file_exists($viewConf) && !file_exists(UU_VIEW_FILE);
        }
    }
    $vw = $viewSnap['view'] ?? null;
    uu_check($t, 'snapshot_vm: the LAN net, the view\'s zones and its mirrored data are read',
        $vw !== null && $viewCleanup && $vw['scope'] === 'selected' && $vw['nets'] === ['192.168.1.0/24']
        && $vw['loaded'] === 'zones' && $vw['view_zones'] === ['.' => 'refuse']
        && $vw['view_data'] === ['nas.internal. 3600 IN A 192.0.2.8'] && $vw['file'] === $viewText
        && $vw['copy'] === $viewText && $vw['acl'] !== null && $vw['zones'] !== null && $vw['data'] !== null
        && ($viewSnap['upgrade'] ?? null) === false);

    return uu_tally_report('snapshot_vm', $t);
});
