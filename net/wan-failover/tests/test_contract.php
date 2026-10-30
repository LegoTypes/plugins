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
 */

/*
 * Core-contract checks. The texts are minimal copies of the core sections the
 * plugin depends on.
 */

require_once __DIR__ . '/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/contract.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/parsers.php';

const WF_T_IFACE = "[routes.configure]\ncommand:/usr/local/etc/rc.routing_configure\n\n[routes.alarm]\ncommand:/usr/local/bin/flock -n -E 0 -o /tmp/filter_reload_gateway.lock /usr/local/etc/rc.routing_configure alarm\nparameters: %s\ntype:script\n";
const WF_T_FILTER = "[kill.state]\ncommand:/sbin/pfctl\nparameters: -k id -k %s/%s 2>&1\n\n[kill.gateway_states]\ncommand:/sbin/pfctl\nparameters: -k gateway -k %s 2>&1\n";
const WF_T_TS = "[restart]\ncommand:/usr/local/etc/rc.d/tailscaled restart\ntype: script\n";
const WF_T_CRON = "[restart]\ncommand:/usr/local/sbin/pluginctl -s cron restart\nparameters:\ntype:script\nmessage:restarting cron\n";
const WF_T_RC = "/usr/local/etc/rc.syshook early\n# PHP starts here\n/usr/local/bin/flock -n -o \${BOOTLOCK} /usr/local/etc/rc.bootup || exit 1\n";

/* stand-ins for core's GatewayGroups, as wf_contract_groups_read() is handed it: one returning the rows a case sets,
 * and three that core could become */
final class WfTGroups
{
    /** @var array<array-key, mixed> */
    public static array $rows = [];

    /** @return array<array-key, mixed> */
    public function getGroupsConfig(): array
    {
        return self::$rows;
    }
}

final class WfTGroupsThrows
{
    /** @return array<array-key, mixed> */
    public function getGroupsConfig(): array
    {
        throw new RuntimeException('core moved');
    }
}

final class WfTGroupsScalar
{
    public function getGroupsConfig(): string
    {
        return 'WAN_A';
    }
}

final class WfTGroupsRenamed
{
    /** @return array<array-key, mixed> */
    public function getGroups(): array
    {
        return [];
    }
}

wf_register_suite('contract', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    wf_check($t, 'section extraction', str_contains((string)wf_ini_section(WF_T_FILTER, 'kill.gateway_states'), '-k gateway -k %s'));
    wf_check($t, 'all command dependencies match', wf_contract_commands(WF_T_IFACE, WF_T_FILTER, WF_T_RC) === []);
    $noLock = str_replace('/tmp/filter_reload_gateway.lock', '/tmp/other.lock', WF_T_IFACE);
    wf_check($t, 'routes.alarm without the gateway lock is reported', count(wf_contract_commands($noLock, WF_T_FILTER, WF_T_RC)) === 1);
    $killState = str_replace('-k id -k %s/%s', '-k key -k %s', WF_T_FILTER);
    wf_check($t, 'a changed kill.state is reported', count(wf_contract_commands(WF_T_IFACE, $killState, WF_T_RC)) === 1);
    $stateOnly = (string)preg_replace('/\n\[kill\.gateway_states\].*\z/s', "\n", WF_T_FILTER);
    wf_check($t, '(c1) an actions_filter.conf without [kill.gateway_states] is no drift: holds no longer use it',
        !str_contains($stateOnly, 'gateway_states') && wf_contract_commands(WF_T_IFACE, $stateOnly, WF_T_RC) === []);
    $gatewayOnly = (string)preg_replace('/\A\[kill\.state\].*?(?=^\[)/ms', '', WF_T_FILTER);
    wf_check($t, '(c1) one without [kill.state] is a drift, reported as [kill.state] changed',
        !str_contains($gatewayOnly, '[kill.state]') && wf_contract_commands(WF_T_IFACE, $gatewayOnly, WF_T_RC) === ['[kill.state] changed']);
    wf_check($t, 'Tailscale not installed (no actions file) is not a drift', wf_contract_tailscale(null) === []);
    wf_check($t, 'Tailscale actions without [restart] are reported in their own class', count(wf_contract_tailscale("[start]\n")) === 1);
    wf_check($t, 'Tailscale actions with [restart] match', wf_contract_tailscale(WF_T_TS) === []);
    $swapped = "/usr/local/etc/rc.bootup\n/usr/local/etc/rc.syshook early\n";
    wf_check($t, 'early hooks after rc.bootup is reported', count(wf_contract_commands(WF_T_IFACE, WF_T_FILTER, $swapped)) === 1);
    wf_check($t, 'unreadable files are reported', count(wf_contract_commands(null, null, null)) === 3);
    $moved = str_replace("command:/usr/local/etc/rc.routing_configure\n", "command:/usr/local/etc/rc.routing_configure_v2\n", WF_T_IFACE);
    $noConfigure = (string)preg_replace('/\A\[routes\.configure\].*?(?=^\[)/ms', '', WF_T_IFACE);
    wf_check($t, '(d4) a [routes.configure] whose command differs, or none, is a removal drift, not a command drift: only the '
        . 'package removal runs that command, and no hold is blocked by it',
        $moved !== WF_T_IFACE && wf_contract_removal($moved, WF_T_CRON) === ['[routes.configure] changed']
        && !str_contains($noConfigure, 'routes.configure') && wf_contract_removal($noConfigure, WF_T_CRON) === ['[routes.configure] changed']
        && wf_contract_commands($moved, WF_T_FILTER, WF_T_RC) === [] && wf_contract_removal(WF_T_IFACE, WF_T_CRON) === []
        && wf_contract_removal(null, WF_T_CRON) === []);
    $cronMoved = str_replace('pluginctl -s cron restart', 'pluginctl -s cron reload', WF_T_CRON);
    wf_check($t, '(d10) actions_cron.conf whose [restart] command differs, has none, or cannot be read is a removal drift, '
        . 'not a command drift: only the package removal runs that command, after its files are gone',
        WF_T_CRON === "[restart]\ncommand:" . WF_CORE_CRON_RESTART . "\nparameters:\ntype:script\nmessage:restarting cron\n"
        && $cronMoved !== WF_T_CRON && wf_contract_removal(WF_T_IFACE, $cronMoved) === ['actions_cron.conf [restart] changed']
        && wf_contract_removal(WF_T_IFACE, "[start]\ncommand:/usr/sbin/service cron start\n") === ['actions_cron.conf [restart] changed']
        && wf_contract_removal(WF_T_IFACE, null) === ['actions_cron.conf [restart] changed']
        && wf_contract_removal($moved, $cronMoved) === ['[routes.configure] changed', 'actions_cron.conf [restart] changed']);
    wf_check($t, '(d10) only a [routes.configure] drift stops the removal running core\'s routing command itself; a cron drift does not',
        wf_contract_routes_fallback([]) && wf_contract_routes_fallback(['actions_cron.conf [restart] changed'])
        && !wf_contract_routes_fallback(['[routes.configure] changed'])
        && !wf_contract_routes_fallback(['[routes.configure] changed', 'actions_cron.conf [restart] changed']));
    $tree = @file_get_contents(dirname(__DIR__) . '/src/opnsense/service/conf/actions.d/actions_wanfailover.conf');
    $replay = $tree === false ? null : wf_ini_section($tree, 'replay_alarm');
    $cmd = $replay === null ? null : wf_ini_command($replay);
    wf_check($t, '(d5) the tree\'s [replay_alarm] command is WF_REPLAY_ALARM_CMD, which the package removal runs directly',
        $cmd === WF_REPLAY_ALARM_CMD);
    if ($cmd !== WF_REPLAY_ALARM_CMD) {
        printf("    tree: %s\n    ours: %s\n", $cmd ?? '(not read)', WF_REPLAY_ALARM_CMD);
    }

    $row = ['current_losslow' => '10', 'current_losshigh' => '20', 'current_time_period' => '60',
            'current_interval' => '1', 'current_loss_interval' => '4'];
    $status = ['status' => 'none', 'loss' => '0.0 %'];
    $route = "   route to: default\ndestination: default\n    gateway: 203.0.113.1\n";
    wf_check($t, 'all judging dependencies match', wf_contract_judging($row, $status, $route, true, true, true, true) === []);
    $short = $row;
    unset($short['current_losslow']);
    wf_check($t, 'a missing current_losslow is reported', count(wf_contract_judging($short, $status, $route, true, true, true, true)) === 1);
    wf_check($t, 'a status row without loss is reported', count(wf_contract_judging($row, ['status' => 'none'], $route, true, true, true, true)) === 1);
    wf_check($t, 'unparseable route output is reported', count(wf_contract_judging($row, $status, "garbage\n", true, true, true, true)) === 1);
    wf_check($t, 'no dpinger socket where expected is reported', count(wf_contract_judging($row, $status, $route, false, true, true, true)) === 1);

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
    $r5 = wf_contract_log(['judging' => [], 'command' => [], 'tailscale' => [], 'removal' => ['[routes.configure] changed']], '');
    wf_check($t, '(d4) log: a removal-only drift is logged once, saying only a package removal\'s fallback is affected',
        $r5['line'] === 'core-contract: core changed what the plugin relies on (only a package removal, when configd '
            . 'does not answer): [routes.configure] changed' && $r5['prio'] === LOG_WARNING);
    $r6 = wf_contract_log(['judging' => [], 'command' => [], 'tailscale' => [], 'removal' => ['actions_cron.conf [restart] changed']], '');
    wf_check($t, '(d10) log: a cron drift is logged in the same words as a routing one',
        $r6['line'] === 'core-contract: core changed what the plugin relies on (only a package removal, when configd '
            . 'does not answer): actions_cron.conf [restart] changed' && $r6['prio'] === LOG_WARNING);
    $r3 = wf_contract_log($ok, $r['last']);
    wf_check($t, 'log: the return to a match is logged', $r3['line'] !== null && str_contains($r3['line'], 'matches again'));
    wf_check($t, 'a disabled or unmonitored WAN has no dpinger rows or socket; not a drift',
        wf_contract_judging(null, null, $route, false, false, true, true) === []);
    wf_check($t, 'an unmonitored WAN still checks the route format', count(wf_contract_judging(null, null, "garbage\n", false, false, true, true)) === 1);

    /* Core runs a WAN's dpinger only while its interface has carrier and an IPv4 address (2026-10-07 on the
     * firewall: vtnet1 flapped, lost its address, the socket went with it, and the plugin read that as core
     * drift, released every hold and blocked new ones while core installed no IPv4 default at all). */
    $active = ['carrier' => true, 'has_ipv4' => true];
    wf_check($t, 'dpinger expected: monitored WAN with carrier and an address', wf_dpinger_expected(true, $active));
    wf_check($t, 'dpinger not expected: no carrier', !wf_dpinger_expected(true, ['carrier' => false, 'has_ipv4' => false]));
    wf_check($t, 'dpinger not expected: carrier but no IPv4 address (DHCP not answered yet)', !wf_dpinger_expected(true, ['carrier' => true, 'has_ipv4' => false]));
    wf_check($t, 'dpinger not expected: unmonitored or disabled WAN', !wf_dpinger_expected(false, $active));
    $noCarrier = "vtnet1: flags=8843<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST> metric 0 mtu 1500\n\tmedia: Ethernet autoselect\n\tstatus: no carrier\n";
    wf_check($t, 'a WAN that lost carrier and its address has no socket, rows aside: not a drift (the 2026-10-07 flap)',
        wf_contract_judging($row, $status, $route, false, wf_dpinger_expected(true, wf_parse_ifconfig($noCarrier)), true, true) === []);
    $upNoSocket = "vtnet1: flags=8843<UP,BROADCAST,RUNNING> metric 0 mtu 1500\n\tinet 203.0.113.167 netmask 0xfffffe00 broadcast 255.255.255.255\n\tstatus: active\n";
    wf_check($t, 'a WAN with carrier and an address but no socket is still a drift',
        count(wf_contract_judging($row, $status, $route, false, wf_dpinger_expected(true, wf_parse_ifconfig($upNoSocket)), true, true)) === 1);

    /* a monitored WAN's window age is its dpinger's process age: the pid from its pid file, the age from ps */
    wf_check($t, 'contract: a socket with no pid is reported',
        wf_contract_judging($row, $status, $route, true, true, false, true) === ['no dpinger pid at /var/run/dpinger_<name>.pid for a monitored WAN']
        && wf_contract_judging($row, $status, $route, true, true, false, false) === ['no dpinger pid at /var/run/dpinger_<name>.pid for a monitored WAN']);
    wf_check($t, 'contract: a pid with no age is reported',
        wf_contract_judging($row, $status, $route, true, true, true, false) === ["ps -o etimes= gives no age for a monitored WAN's dpinger"]);
    wf_check($t, 'contract: no socket means no pid or age check',
        wf_contract_judging($row, $status, $route, false, true, false, false) === ['no dpinger socket at /var/run/dpinger_<name>.sock for a monitored WAN']);
    wf_check($t, 'contract: an unmonitored WAN checks no pid or age', wf_contract_judging(null, null, $route, false, false, false, false) === []);

    $maskDrift = 'Gateways.xml gateway name Mask changed';
    $r7 = wf_contract_log(['judging' => [], 'command' => [], 'tailscale' => [], 'removal' => [], 'names' => [$maskDrift]], '');
    $r8 = wf_contract_log(['judging' => [], 'command' => [], 'tailscale' => [], 'removal' => ['[routes.configure] changed'],
        'names' => [$maskDrift]], '');
    wf_check($t, 'contract log: a names drift blocks nothing and says so',
        $r7['line'] === 'core-contract: core changed what the plugin relies on (a gateway name core now accepts may read as '
            . 'unresolved): Gateways.xml gateway name Mask changed' && $r7['prio'] === LOG_WARNING
        && $r8['line'] === 'core-contract: core changed what the plugin relies on (only a package removal, when configd does '
            . 'not answer): [routes.configure] changed; Gateways.xml gateway name Mask changed');
    $rulesDrift = 'pfctl -vvsr no longer prints rule labels or route-to targets as the failback parser reads them';
    $r9 = wf_contract_log(['judging' => [], 'command' => [], 'failback' => [$rulesDrift], 'tailscale' => ['no [restart]'],
        'removal' => [], 'names' => []], '');
    $r10 = wf_contract_log(['judging' => ['route -n get output no longer parses'], 'command' => [], 'failback' => [$rulesDrift],
        'tailscale' => [], 'removal' => [], 'names' => []], '');
    wf_check($t, 'contract log: a failback drift says failback suspended',
        $r9['line'] === 'core-contract: core changed what the plugin relies on (failback suspended): ' . $rulesDrift
            . '; no [restart]' && $r9['prio'] === LOG_WARNING
        && $r10['line'] === 'core-contract: core changed what the plugin relies on (releasing every hold if it persists for '
            . WF_UNKNOWN_MAX_SECONDS . ' s): route -n get output no longer parses; ' . $rulesDrift);

    /* the name field of core 26.7.7's Gateways.xml, as core has it */
    $gatewaysXml = '<model><items><gateway_item><name><Mask>/^[a-zA-Z0-9_\-]{1,32}$/</Mask></name></gateway_item></items></model>';
    wf_check($t, "contract: core's name mask as copied reports nothing", wf_contract_name_mask($gatewaysXml) === []);
    wf_check($t, 'contract: a changed name mask is a names drift',
        wf_contract_name_mask(str_replace('{1,32}', '{1,64}', $gatewaysXml)) === [$maskDrift]);
    wf_check($t, 'contract: an unreadable Gateways.xml is a names drift',
        wf_contract_name_mask(null) === ['Gateways.xml unreadable'] && wf_contract_name_mask('<model>') === ['Gateways.xml unreadable']);
    $internal = libxml_use_internal_errors(false);
    $kept = wf_contract_name_mask('<model>') !== [] && libxml_use_internal_errors() === false && libxml_get_errors() === [];
    libxml_use_internal_errors(true);
    $kept = $kept && wf_contract_name_mask('<model>') !== [] && libxml_use_internal_errors() === true && libxml_get_errors() === [];
    libxml_use_internal_errors($internal);
    wf_check($t, "contract: reading Gateways.xml leaves libxml's error setting as it was and its error list empty", $kept);

    /* GatewayGroups::getGroupsConfig()'s rows, read through the guarded reader from a stand-in that returns them */
    $read = function (array $rows): array {
        WfTGroups::$rows = $rows;
        return wf_contract_groups_read(WfTGroups::class, 'getGroupsConfig');
    };
    $rules = (string)file_get_contents(__DIR__ . '/fixtures/rules.txt');
    $groupsDrift = 'GatewayGroups::getGroupsConfig() rows no longer carry tiers as lists of gateway names';
    $groups = ['G1' => ['tiers' => [1 => ['WAN_A'], 2 => ['WAN_B'], 3 => ['']]]];
    wf_check($t, 'failback contract: a clean listing and groups report nothing', wf_contract_failback($rules, $read($groups)) === []);
    wf_check($t, 'failback contract: tiers that are not lists of names are a drift',
        wf_contract_failback($rules, $read(['G1' => ['tiers' => 'WAN_A']])) === [$groupsDrift]
        && wf_contract_failback($rules, $read(['G1' => []])) === [$groupsDrift]
        && wf_contract_failback($rules, $read(['G1' => ['tiers' => [1 => [7]]]])) === [$groupsDrift]);
    $rulesUnread = 'pfctl -vvsr could not be read';
    wf_check($t, 'failback contract: an unread or blank listing says it could not be read, not that the format moved',
        wf_contract_failback(null, $read($groups)) === [$rulesUnread] && wf_contract_failback('', $read($groups)) === [$rulesUnread]
        && wf_contract_failback("\n", $read($groups)) === [$rulesUnread]
        && wf_contract_failback(null, $read(['G1' => []])) === [$rulesUnread, $groupsDrift]);
    /* core 26.7.7 (GatewayGroups.php getGroupsConfig()) gives every group tiers 1-5, each explode(',') of its item
     * field, so an empty tier is [''] and a group with no members has five of them */
    $core = fn (string $name, array $named): array => ['name' => $name, 'trigger' => 'downloss', 'poolopts' => '',
        'descr' => '', 'tiers' => array_replace([1 => [''], 2 => [''], 3 => [''], 4 => [''], 5 => ['']], $named)];
    $coreRows = ['G_ONE' => $core('G_ONE', [1 => ['WAN_A']]), 'G_EMPTY' => $core('G_EMPTY', []),
                 'G_TWO' => $core('G_TWO', [1 => ['WAN_A', 'WAN_B'], 2 => ['WAN_DHCP']]), 'G_LATE' => $core('G_LATE', [3 => ['WAN_B']]),
                 'G_NONE' => ['name' => 'G_NONE', 'tiers' => []]];
    wf_check($t, "failback contract: core's own group shapes report nothing",
        $read($coreRows) === ['groups' => $coreRows, 'drift' => []] && $read([]) === ['groups' => [], 'drift' => []]
        && wf_contract_failback($rules, $read($coreRows)) === []);
    $unreadable = fn (string $why): array => ['groups' => null, 'drift' => [$why]];
    $gone = wf_contract_groups_read('WfTGroupsGone', 'getGroupsConfig');
    $renamed = wf_contract_groups_read(WfTGroupsRenamed::class, 'getGroupsConfig');
    $threw = wf_contract_groups_read(WfTGroupsThrows::class, 'getGroupsConfig');
    $scalar = wf_contract_groups_read(WfTGroupsScalar::class, 'getGroupsConfig');
    wf_check($t, 'failback contract: groups core can no longer give are a drift naming why, and the read never throws',
        $gone === $unreadable('WfTGroupsGone no longer exists')
        && $renamed === $unreadable('WfTGroupsRenamed::getGroupsConfig() no longer exists')
        && $threw === $unreadable('WfTGroupsThrows::getGroupsConfig() threw RuntimeException')
        && $scalar === $unreadable('WfTGroupsScalar::getGroupsConfig() no longer returns an array')
        && wf_contract_failback($rules, $threw) === ['WfTGroupsThrows::getGroupsConfig() threw RuntimeException']
        && wf_contract_failback(null, $scalar) === [$rulesUnread, 'WfTGroupsScalar::getGroupsConfig() no longer returns an array']);

    /* The failback contract's rule listing, read through wf_pf_listing() from a stand-in for wf_pfctl_run() that gives
     * the runs a case lists, in order. A ruleset load, an identical one too, cuts a listing short with
     * `pfctl: DIOCGETRULE: Device busy` on stderr while pfctl still exits 0 (the test VM: 3 of 200 listings during six
     * filter reloads, cut at 265 to 375 of 480 lines) */
    $pfctl = function (array $runs): array {
        $calls = new ArrayObject();
        $run = function (array $args) use ($calls, &$runs): array {
            $calls[] = $args;
            return array_shift($runs) ?? ['out' => '', 'err' => "pfctl: no run left\n", 'rc' => 1];
        };
        return ['run' => $run, 'calls' => $calls];
    };
    $altq = "No ALTQ support in kernel\nALTQ related functions disabled\n";
    $whole = ['out' => $rules, 'err' => $altq, 'rc' => 0];
    $cut = ['out' => "@0 scrub on vtnet1 all fragment reassemble\n", 'err' => $altq . "pfctl: DIOCGETRULE: Device busy\n", 'rc' => 0];
    $clean = $read($groups);
    $none = ['judging' => [], 'command' => [], 'failback' => [], 'tailscale' => [], 'removal' => [], 'names' => []];
    /* one evaluation's contract from its listing runs, the last one's contract_last and its said map: what it keeps, logs,
     * reads and counts */
    $tick = function (array $runs, string $last, array $said = []) use ($pfctl, $clean, $none): array {
        $p = $pfctl($runs);
        $kept = wf_contract_kept(array_merge($none, ['failback' => wf_contract_failback(wf_pf_listing($p['run'], ['-vvsr']),
            $clean)]), $last, $said);
        return ['failback' => $kept['contract']['failback'], 'notice' => $kept['line'], 'said' => $kept['said'],
                'log' => wf_contract_log($kept['contract'], $last), 'calls' => $p['calls']->getArrayCopy()];
    };
    $quiet = fn (string $last): array => ['line' => null, 'prio' => LOG_NOTICE, 'last' => $last];
    $notice = 'core-contract: pfctl -vvsr could not be read on two tries; the failback check keeps its last result, and '
        . 'reports the listing as a drift once 3 evaluations in a row cannot read it';
    $lastDrift = wf_contract_log(array_merge($none, ['failback' => [$rulesDrift]]), '')['last'];
    $other = ['unresolved' => 'x'];

    $r = $tick([$whole], '', $other);
    wf_check($t, 'failback contract: a whole rule listing is read once and reports nothing',
        $r['calls'] === [['-vvsr']] && $r['failback'] === [] && $r['notice'] === null && $r['log'] === $quiet('')
        && $r['said'] === $other);
    $r = $tick([$cut, $whole], '');
    wf_check($t, 'failback contract: a rule listing cut short is read once more, and the whole one reports no drift',
        $r['calls'] === [['-vvsr'], ['-vvsr']] && $r['failback'] === [] && $r['notice'] === null && $r['log'] === $quiet(''));
    $after = $tick([$cut, $cut], '', $other);
    $held = $tick([$cut, $cut], $lastDrift);
    $groupsToo = wf_contract_kept(array_merge($none, ['failback' => [$rulesUnread, $groupsDrift]]), $lastDrift, []);
    wf_check($t, 'failback contract: a rule listing cut short twice is no new drift: the last reading stands, nothing new is '
        . 'logged, and one notice says why',
        $after['calls'] === [['-vvsr'], ['-vvsr']] && $after['failback'] === [] && $after['log'] === $quiet('')
        && $after['notice'] === $notice && $after['said'] === $other + ['rules_unread_count' => '1']
        && $held['failback'] === [$rulesDrift] && $held['log'] === $quiet($lastDrift) && $held['notice'] === $notice
        && $groupsToo['contract']['failback'] === [$rulesDrift, $groupsDrift] && $groupsToo['line'] === $notice);
    $moved = ['out' => str_replace('label "', 'label:', $rules), 'err' => $altq, 'rc' => 0];
    $r = $tick([$moved], '');
    wf_check($t, 'failback contract: a whole rule listing whose format moved is read once and is a drift, logged as before',
        $r['calls'] === [['-vvsr']] && $r['failback'] === [$rulesDrift] && $r['notice'] === null
        && $r['log']['line'] === 'core-contract: core changed what the plugin relies on (failback suspended): ' . $rulesDrift
        && $r['log']['prio'] === LOG_WARNING);
    wf_check($t, 'failback contract: a contract read whole is kept as it is',
        wf_contract_kept(array_merge($none, ['failback' => [$groupsDrift]]), $lastDrift, [])
            === ['contract' => array_merge($none, ['failback' => [$groupsDrift]]), 'line' => null, 'said' => []]);

    /* evaluations one after another, each handed the last one's contract_last and said map */
    $run = function (array $ticks) use ($tick): array {
        $last = '';
        $said = [];
        $out = [];
        foreach ($ticks as $runs) {
            $r = $tick($runs, $last, $said);
            $last = $r['log']['last'];
            $said = $r['said'];
            $out[] = $r;
        }
        return $out;
    };
    $unreadDrift = 'core-contract: core changed what the plugin relies on (failback suspended): ' . $rulesUnread;
    [$u1, $u2, $u3, $u4, $back] = $run([[$cut, $cut], [$cut, $cut], [$cut, $cut], [$cut, $cut], [$whole]]);
    wf_check($t, 'failback contract: two evaluations in a row that cannot read the rule listing keep the last reading',
        $u1['failback'] === [] && $u1['log'] === $quiet('') && $u1['notice'] === $notice
        && $u1['said'] === ['rules_unread_count' => '1']
        && $u2['failback'] === [] && $u2['log'] === $quiet('') && $u2['notice'] === $notice
        && $u2['said'] === ['rules_unread_count' => '2']);
    wf_check($t, 'failback contract: the 3rd evaluation in a row that cannot read the rule listing reports it as a failback '
        . 'drift, logged once as a warning',
        $u3['failback'] === [$rulesUnread] && $u3['log']['line'] === $unreadDrift && $u3['log']['prio'] === LOG_WARNING
        && $u3['notice'] === null && $u3['said'] === ['rules_unread_count' => '3']
        && $u4['failback'] === [$rulesUnread] && $u4['log'] === $quiet($rulesUnread) && $u4['notice'] === null
        && $u4['said'] === ['rules_unread_count' => '4']);
    wf_check($t, 'failback contract: a whole read after that clears the drift with core matches again and the count',
        $back['failback'] === [] && $back['log'] === ['line' => 'core-contract: core matches again', 'prio' => LOG_NOTICE,
            'last' => ''] && $back['notice'] === null && $back['said'] === []);
    [$i1, $i2, $i3, $i4] = $run([[$cut, $cut], [$whole], [$cut, $cut], [$cut, $cut]]);
    wf_check($t, 'failback contract: a rule listing cut short now and then (unread, read, unread) never counts to 3',
        $i1['said'] === ['rules_unread_count' => '1'] && $i2['said'] === [] && $i3['said'] === ['rules_unread_count' => '1']
        && $i4['said'] === ['rules_unread_count' => '2']
        && array_map(fn (array $r): array => $r['failback'], [$i1, $i2, $i3, $i4]) === [[], [], [], []]
        && array_map(fn (array $r): ?string => $r['log']['line'], [$i1, $i2, $i3, $i4]) === [null, null, null, null]);
    wf_check($t, 'failback contract: a count the said map holds in any other form counts as none',
        wf_contract_kept(array_merge($none, ['failback' => [$rulesUnread]]), '', ['rules_unread_count' => 'x'])['said']
            === ['rules_unread_count' => '1']
        && wf_contract_kept(array_merge($none, ['failback' => [$rulesUnread]]), '', ['rules_unread_count' => '-5'])['said']
            === ['rules_unread_count' => '1']);
    return wf_tally_report('contract', $t);
});
