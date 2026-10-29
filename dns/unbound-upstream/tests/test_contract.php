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
 * Core contract: each broken input refuses tunnel mode with its own named failure; a core
 * command a removal falls back to that no longer matches core is a note, as is a core file the snapshot reads that
 * core no longer keeps there, and the package scripts run the same commands.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/constants.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/contract.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/zone.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/snapshot.php';
require_once __DIR__ . '/scratch.php';

/**
 * A contract input that passes, with a restorable single root zone; both members use the one resolver 10.2.0.1.
 *
 * @return array{unbound_hooks_registered: bool, unbound_sorts_first: bool, groups_have_tiers: bool,
 *     status_fields: bool, monitors: array<string, list<string>>, statics: array<string, list<string>>,
 *     unmonitored_members: list<string>, foreign: list<string>, member_resolvers: array<string, string>,
 *     resolver_notes: list<string>, no_next_hop: list<string>,
 *     rules: array{state: string, problems: list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int, core_commands: list<string>,
 *     core_paths: list<string>, unbound_conf: ?array{do_ip4: bool, do_ip6: bool, outgoing_interface: bool},
 *     group_family: string, mixed_family: bool, family_mismatch: list<string>}
 */
function uu_test_contract_input(): array
{
    return [
        'unbound_hooks_registered' => true,
        'unbound_sorts_first' => true,
        'groups_have_tiers' => true,
        'status_fields' => true,
        'monitors' => [],
        'statics' => [],
        'unmonitored_members' => [],
        'foreign' => [],
        'member_resolvers' => ['wg-a' => '10.2.0.1', 'wg-b' => '10.2.0.1'],
        'resolver_notes' => [],
        'no_next_hop' => [],
        'rules' => ['state' => 'loaded', 'problems' => []],
        'zone' => ['shape' => 'one', 'addrs' => ['192.0.2.53@853#dns.example'], 'tls' => true, 'problems' => []],
        'fib_sync_ms' => 100,
        'cacheflush' => false,
        'group_found' => true,
        'members' => 2,
        'core_commands' => [],
        'core_paths' => [],
        'unbound_conf' => ['do_ip4' => true, 'do_ip6' => true, 'outgoing_interface' => false],
        'group_family' => 'inet',
        'mixed_family' => false,
        'family_mismatch' => [],
    ];
}

/**
 * The lines of a package script that run something: no blank line, no comment.
 *
 * @return list<string>
 */
function uu_test_script_commands(string $text): array
{
    return array_values(array_filter(explode("\n", $text),
        fn (string $line): bool => trim($line) !== '' && !str_starts_with(ltrim($line), '#')));
}

uu_register_suite('contract', function (): int {
    $t = ['fail' => 0, 'total' => 0];

    uu_check($t, 'contract: the root-forward failure reads as in 1.5 through the shared function',
        uu_try_case(function (): bool {
            $zone = fn (array $addrs): array => ['zone' => ['shape' => 'one', 'addrs' => $addrs, 'tls' => false,
                'problems' => []]];
            $ported = uu_contract($zone(['192.0.2.53@853#dns.example', '10.2.0.1@5353']) + uu_test_contract_input());
            $two = uu_contract($zone(['2001:DB8:B:0::0053@853', '192.0.2.54'])
                + ['member_resolvers' => ['wg-a' => '2001:db8:b::53', 'wg-b' => '192.0.2.54']]
                + uu_test_contract_input());
            return $ported['failures'] === ["Unbound's root zone forwards to 10.2.0.1, the resolver of wg-a, wg-b: the "
                    . 'plugin cannot tell that forwarding from its own']
                && $two['failures'] === ["Unbound's root zone forwards to 192.0.2.54, the resolver of wg-b: the plugin "
                    . 'cannot tell that forwarding from its own', "Unbound's root zone forwards to 2001:db8:b::53, the "
                    . 'resolver of wg-a: the plugin cannot tell that forwarding from its own'];
        }));
    uu_check($t, 'contract: a changed core path is a note, never a failure',
        uu_try_case(function (): bool {
            $paths = ["dpinger's pid or socket file is not at /var/run/dpinger_<gateway>.pid or .sock while core reads "
                . 'a loss: no member can settle',
                "Unbound's pidfile is unset in unbound.conf, not /var/run/unbound.pid: Unbound reads as not running"];
            $c = uu_contract(['core_paths' => $paths] + uu_test_contract_input());
            return $c['ok'] && $c['failures'] === [] && $c['excluded'] === []
                && $c['notes'] === ['core path changed: ' . $paths[0], 'core path changed: ' . $paths[1]];
        }));

    $c = uu_contract(uu_test_contract_input());
    uu_check($t, 'a clean input is ok with no failures and no notes',
        $c['ok'] && $c['failures'] === [] && $c['notes'] === []);

    $cases = [
        ['unbound_hooks_registered', false, 'unbound_start hook missing'],
        ['unbound_sorts_first', false, 'unbound.inc no longer sorts before unboundupstream.inc'],
        ['groups_have_tiers', false, 'gateway groups lack tiers'],
        ['status_fields', false, 'gateway status lacks expected fields'],
        ['foreign', ['10.2.0.1'], 'resolver route not ours'],
        ['fib_sync_ms', null, 'fib sync delay unreadable'],
        ['group_found', false, 'group not found'],
        ['members', 0, 'group has no members'],
    ];
    foreach ($cases as [$key, $value, $failure]) {
        $in = uu_test_contract_input();
        $in[$key] = $value;
        $c = uu_contract($in);
        uu_check($t, "$key flipped alone: exactly \"$failure\"", !$c['ok'] && $c['failures'] === [$failure]);
    }

    $in = uu_test_contract_input();
    $in['rules'] = ['state' => 'missing', 'problems' => ['no pass rule for wg-b (opt2)', 'backstop block missing']];
    $c = uu_contract($in);
    uu_check($t, 'rules missing: one failure per problem, each named',
        !$c['ok'] && $c['failures'] === ['firewall rules: no pass rule for wg-b (opt2)',
            'firewall rules: backstop block missing'] && $c['notes'] === []);

    $in = uu_test_contract_input();
    $in['rules'] = ['state' => 'missing', 'problems' => []];
    $c = uu_contract($in);
    uu_check($t, 'rules missing without a named problem: still a failure',
        !$c['ok'] && $c['failures'] === ['firewall rules: not loaded']);

    $in = uu_test_contract_input();
    $in['rules'] = ['state' => 'verifying', 'problems' => []];
    $c = uu_contract($in);
    uu_check($t, 'rules verifying: a note only, never a failure',
        $c['ok'] && $c['failures'] === []
        && $c['notes'] === ['firewall rules are being verified (the ruleset changed)']);

    $in = uu_test_contract_input();
    $in['monitors'] = ['10.2.0.1' => ['wg-a', 'wg-b']];
    $c = uu_contract($in);
    uu_check($t, 'resolver is the monitor: one failure per gateway',
        !$c['ok'] && $c['failures'] === ['resolver is the monitor of wg-a', 'resolver is the monitor of wg-b']);

    $in = uu_test_contract_input();
    $in['statics'] = ['10.2.0.1' => ['10.2.0.0/24', '10.0.0.0/8']];
    $c = uu_contract($in);
    uu_check($t, 'resolver inside static routes: one failure per route',
        !$c['ok'] && $c['failures'] === ['resolver is inside static route 10.2.0.0/24',
            'resolver is inside static route 10.0.0.0/8']);

    $in = uu_test_contract_input();
    $in['unmonitored_members'] = ['wg-b'];
    $c = uu_contract($in);
    uu_check($t, 'unmonitored member: failure names it',
        !$c['ok'] && $c['failures'] === ['member wg-b is not monitored']);

    $in = uu_test_contract_input();
    $in['zone'] = ['shape' => 'unrestorable', 'addrs' => [], 'tls' => false,
        'problems' => ['second . zone', 'forward-first']];
    $c = uu_contract($in);
    uu_check($t, 'unrestorable zone: failure lists the problems',
        !$c['ok'] && $c['failures'] === ['root zone cannot be restored: second . zone, forward-first']);

    /* a zone read that failed refuses tunnel mode; it is never read as no root zone */
    $c = null;
    try {
        $in = uu_test_contract_input();
        $in['zone'] = uu_root_zone(null);
        $c = uu_contract($in);
    } catch (\Throwable $e) {
        printf("  threw %s: %s\n", get_class($e), $e->getMessage());
    }
    uu_check($t, 'zone configuration unreadable: tunnel refused, "root zone cannot be restored: configuration '
        . 'unreadable", no recursion note',
        $c !== null && !$c['ok'] && $c['failures'] === ['root zone cannot be restored: configuration unreadable']
        && $c['notes'] === []);

    $in = uu_test_contract_input();
    $in['zone'] = ['shape' => 'none', 'addrs' => [], 'tls' => false, 'problems' => []];
    $c = uu_contract($in);
    uu_check($t, 'no root zone: ok, with the recursion note',
        $c['ok'] && $c['failures'] === []
        && $c['notes'] === ['no root zone: fallback is recursion over the WAN']);

    $in = uu_test_contract_input();
    $in['zone'] = ['shape' => 'one', 'addrs' => [], 'tls' => false, 'problems' => []];
    $c = uu_contract($in);
    uu_check($t, 'root zone with no forward-addr: failure',
        !$c['ok'] && $c['failures'] === ['root zone has no forward-addr']);

    $in = uu_test_contract_input();
    $in['cacheflush'] = true;
    $c = uu_contract($in);
    uu_check($t, 'cacheflush on: a note only',
        $c['ok'] && $c['failures'] === [] && $c['notes'] === ['cacheflush on: restart escalation disabled']);

    $in = uu_test_contract_input();
    $in['foreign'] = ['10.2.0.1'];
    $in['group_found'] = false;
    $in['fib_sync_ms'] = null;
    $c = uu_contract($in);
    uu_check($t, 'several broken inputs report every failure',
        !$c['ok'] && count($c['failures']) === 3);

    // The core commands a removal falls back to when configd does not answer.
    $conf = "[reload]\ncommand:/usr/local/etc/rc.filter_configure\nparameters: %s\ntype:script\n"
        . "message:Reloading filter\n\n"
        . "[sync]\ncommand:/usr/local/etc/rc.filter_synchronize\nparameters:\ntype:script\n\n"
        . "[restart]\nparameters:\ncommand: /usr/local/sbin/pluginctl -s cron restart \ntype:script\n\n"
        . "[status]\nparameters:\ntype:script_output\n";
    uu_check($t, '(d4) the command: value of each section of a configd actions file, trimmed, wherever it stands in the section',
        uu_try_case(fn (): bool => uu_configd_action_command($conf, 'reload') === '/usr/local/etc/rc.filter_configure'
            && uu_configd_action_command($conf, 'restart') === '/usr/local/sbin/pluginctl -s cron restart'
            && uu_configd_action_command($conf, 'sync') === '/usr/local/etc/rc.filter_synchronize'));
    uu_check($t, '(d4) a section without a command, a missing section, or a command line of another section → null',
        uu_try_case(fn (): bool => uu_configd_action_command($conf, 'status') === null
            && uu_configd_action_command($conf, 'start') === null
            && uu_configd_action_command("[restart]\n[reload]\ncommand:/bin/x\n", 'restart') === null
            && uu_configd_action_command('', 'reload') === null));

    $in = uu_test_contract_input();
    $in['core_commands'] = ['filter reload'];
    $c = uu_contract($in);
    uu_check($t, '(d5) a core command that drifted → one note naming it, no failure, tunnel mode allowed',
        $c['ok'] && $c['failures'] === [] && count($c['notes']) === 1
        && str_starts_with($c['notes'][0] ?? '', 'core command changed: filter reload'));
    $in['core_commands'] = ['filter reload', 'cron restart', 'unbound restart'];
    $c = uu_contract($in);
    uu_check($t, '(d5) three drifted → three notes, each naming its command, in order, no failure',
        $c['ok'] && $c['failures'] === [] && count($c['notes']) === 3
        && str_starts_with($c['notes'][0] ?? '', 'core command changed: filter reload')
        && str_starts_with($c['notes'][1] ?? '', 'core command changed: cron restart')
        && str_starts_with($c['notes'][2] ?? '', 'core command changed: unbound restart'));

    /* the package scripts run core's two commands as remove does: configd when it says OK within the timeout, else
     * core's script */
    $scripts = [];
    foreach (['+POST_INSTALL.post', '+POST_DEINSTALL.post'] as $name) {
        $text = @file_get_contents(__DIR__ . '/../' . $name);
        $scripts[$name] = is_string($text) ? $text : null;
    }
    $fallbacks = fn (): array => [
        '[ "$(/usr/bin/timeout ' . UU_CONFIGD_TIMEOUT_SECONDS . ' /usr/local/sbin/configctl filter reload)" = OK ] || '
            . UU_CORE_FILTER_RELOAD . ' || true',
        '[ "$(/usr/bin/timeout ' . UU_CONFIGD_TIMEOUT_SECONDS . ' /usr/local/sbin/configctl cron restart)" = OK ] || '
            . UU_CORE_CRON_RESTART . ' || true',
    ];
    uu_check($t, '(d6) +POST_INSTALL.post: the removal marker deleted first, then the filter reload and the cron restart, each through configd, else core\'s own script',
        uu_try_case(fn (): bool => $scripts['+POST_INSTALL.post'] !== null
            && uu_test_script_commands($scripts['+POST_INSTALL.post'])
                === array_merge(['rm -f /var/run/unboundupstream/removing'], $fallbacks())));
    uu_check($t, '(d6) +POST_DEINSTALL.post: the filter reload and the cron restart, each through configd, else core\'s own script, then the rules record deleted',
        uu_try_case(fn (): bool => $scripts['+POST_DEINSTALL.post'] !== null
            && uu_test_script_commands($scripts['+POST_DEINSTALL.post'])
                === array_merge($fallbacks(), ['rm -f /var/run/unboundupstream/rules.json'])));
    /* each fallback line run by /bin/sh with configctl stubbed (a reply and an exit status) and core's script
     * stubbed to say it ran: core's script runs unless configctl exits 0 saying OK */
    $stubs = [
        'configctl answers OK' => ['echo OK', false],
        'configctl answers OK with blanks' => ['echo " OK"', true],
        'configctl answers Error (1)' => ["echo 'Error (1)'", true],
        'configctl answers Action not found' => ["echo 'Action not found'", true],
        'configctl answers nothing, exit 0' => ['/usr/bin/true', true],
        'configctl exits 255 (no socket)' => ['sh -c "exit 255"', true],
        'configctl times out (124)' => ['sh -c "exit 124"', true],
    ];
    foreach (['+POST_INSTALL.post', '+POST_DEINSTALL.post'] as $name) {
        $lines = $scripts[$name] === null ? [] : array_values(array_filter(uu_test_script_commands($scripts[$name]),
            fn (string $line): bool => str_contains($line, 'configctl')));
        $all = count($lines) === 2;
        $seen = [];
        foreach ($lines as $line) {
            foreach ($stubs as $what => [$stub, $direct]) {
                $sh = (string)preg_replace('#/usr/bin/timeout \d+ /usr/local/sbin/configctl [a-z ]+[a-z]#', $stub,
                    str_replace([UU_CORE_FILTER_RELOAD, UU_CORE_CRON_RESTART], 'echo DIRECT', $line));
                $out = [];
                $rc = 0;
                exec('/bin/sh -c ' . escapeshellarg($sh) . ' 2>&1', $out, $rc);
                $ran = in_array('DIRECT', $out, true);
                if ($rc !== 0 || $ran !== $direct) {
                    $all = false;
                    $seen[] = "$what: exit $rc, core's script " . ($ran ? 'ran' : 'did not run');
                }
            }
        }
        if ($seen !== []) {
            printf("  %s\n", implode("\n  ", $seen));
        }
        uu_check($t, "$name under /bin/sh: core's script runs unless configctl exits 0 saying OK (no socket, a timeout, an error reply, no reply), and the line always exits 0",
            $all);
    }
    foreach ($scripts as $name => $text) {
        uu_check($t, "(d6) $name: printable ASCII, tab and newline only, ending with a newline (verify-payload.sh step 5)",
            $text !== null && $text !== '' && preg_match('/^[\t\n\x20-\x7e]*\z/', $text) === 1
            && str_ends_with($text, "\n"));
    }
    /* the pre-deinstall under /bin/sh, logger and evaluate.php stubbed and the view file's path a scratch one: the
     * recovery commands of the spec go to the plugin log before remove runs, and only while the file exists */
    uu_check($t, '+PRE_DEINSTALL.pre: the view file\'s recovery commands are logged before remove, only while the file '
        . 'exists; printable ASCII',
        uu_scratch_case(function (string $dir): bool {
            $text = (string)@file_get_contents(__DIR__ . '/../+PRE_DEINSTALL.pre');
            $file = "$dir/unboundupstream.conf";
            $sh = str_replace(['/usr/local/etc/unbound.opnsense.d/unboundupstream.conf ]', '/usr/bin/logger',
                '/usr/local/opnsense/scripts/OPNsense/UnboundUpstream/evaluate.php'],
                ["$file ]", 'echo LOGGED', 'echo REMOVE'], $text);
            $run = function () use ($sh): array {
                $out = [];
                $rc = 0;
                exec('/bin/sh -c ' . escapeshellarg($sh) . ' 2>&1', $out, $rc);
                return [$rc, $out];
            };
            $without = $run();
            file_put_contents($file, "x\n");
            $with = $run();
            return preg_match('/^[\t\n\x20-\x7e]*\z/', $text) === 1 && str_ends_with($text, "\n")
                && $without === [0, ['REMOVE remove']]
                && $with === [0, ['LOGGED -p local4.notice -t dnsupstream fail closed: the package is being removed or '
                    . 'upgraded with the fail-closed view file in place; after a failed upgrade, a downgrade to 1.4 or '
                    . 'a removal that could not finish, recover with: rm '
                    . '/usr/local/etc/unbound.opnsense.d/unboundupstream.conf; '
                    . 'configctl unbound restart', 'REMOVE remove']];
        }));

    // Address-scoped failures exclude the members that use the address; covering every member, they refuse.
    $two = uu_test_contract_input();
    $two['member_resolvers'] = ['wg-a' => '2001:db8:a::53', 'wg-b' => '2001:db8:b::53'];
    uu_check($t, '(p13) two addresses, one foreign: its members are excluded with a note each, the contract ok',
        uu_try_case(function () use ($two): bool {
            $in = $two;
            $in['foreign'] = ['2001:db8:a::53'];
            $c = uu_contract($in);
            return $c === ['ok' => true, 'failures' => [], 'notes' => ['wg-a excluded: resolver route not ours'],
                           'excluded' => ['wg-a']];
        }));
    uu_check($t, '(p13) two addresses, one a monitor and in a static route: one note per failure for each of its '
        . 'members, in member order, the other address\'s member still a candidate',
        uu_try_case(function () use ($two): bool {
            $in = $two;
            $in['member_resolvers']['wg-c'] = '2001:db8:b::53';
            $in['monitors'] = ['2001:db8:b::53' => ['wg-x']];
            $in['statics'] = ['2001:db8:b::53' => ['2001:db8::/32']];
            $c = uu_contract($in);
            return $c['ok'] && $c['failures'] === [] && $c['excluded'] === ['wg-b', 'wg-c']
                && $c['notes'] === ['wg-b excluded: resolver is the monitor of wg-x',
                    'wg-b excluded: resolver is inside static route 2001:db8::/32',
                    'wg-c excluded: resolver is the monitor of wg-x',
                    'wg-c excluded: resolver is inside static route 2001:db8::/32'];
        }));
    uu_check($t, '(p13) two addresses whose failures between them exclude every member: each a failure in 1.3\'s words '
        . 'with its address, monitors and statics before the unmonitored members, foreign routes after, no note',
        uu_try_case(function () use ($two): bool {
            $in = $two;
            $in['foreign'] = ['2001:db8:a::53'];
            $in['monitors'] = ['2001:db8:b::53' => ['wg-x']];
            $in['unmonitored_members'] = ['wg-y'];
            $c = uu_contract($in);
            return !$c['ok'] && $c['notes'] === [] && $c['excluded'] === []
                && $c['failures'] === ['resolver is the monitor of wg-x (2001:db8:b::53)',
                    'member wg-y is not monitored', 'resolver route not ours (2001:db8:a::53)'];
        }));
    uu_check($t, '(p9) one shared address that is a monitor: 1.3\'s failure string exactly, no address, no note',
        uu_try_case(function (): bool {
            $in = uu_test_contract_input();
            $in['monitors'] = ['10.2.0.1' => ['wg-b']];
            $c = uu_contract($in);
            return $c === ['ok' => false, 'failures' => ['resolver is the monitor of wg-b'], 'notes' => [],
                           'excluded' => []];
        }));
    uu_check($t, '(p13) a foreign route of an address no member uses (one the state still holds) excludes nobody and '
        . 'refuses nothing',
        uu_try_case(function (): bool {
            $in = uu_test_contract_input();
            $in['foreign'] = ['192.0.2.77'];
            return uu_contract($in) === ['ok' => true, 'failures' => [], 'notes' => [], 'excluded' => []];
        }));
    uu_check($t, '(p8) a member with no resolver is excluded (uu_member_resolvers() wrote its note), and an address '
        . 'failure covering every member that has one still refuses in 1.3\'s words',
        uu_try_case(function (): bool {
            $in = uu_test_contract_input();
            $in['member_resolvers'] = ['wg-a' => '', 'wg-b' => '10.2.0.1'];
            $in['resolver_notes'] = ['wg-a has no resolver: not a candidate'];
            $ok = uu_contract($in);
            $in['foreign'] = ['10.2.0.1'];
            $refused = uu_contract($in);
            return $ok === ['ok' => true, 'failures' => [], 'notes' => ['wg-a has no resolver: not a candidate'],
                            'excluded' => ['wg-a']]
                && $refused['failures'] === ['resolver route not ours'] && !$refused['ok'];
        }));
    uu_check($t, '(p15) a member with no next hop is excluded with its note; the rows\' notes are carried as they are',
        uu_try_case(function (): bool {
            $in = uu_test_contract_input();
            $in['no_next_hop'] = ['wg-b'];
            $in['resolver_notes'] = ['row for wg-c ignored: not a member of the group'];
            return uu_contract($in) === ['ok' => true, 'failures' => [],
                'notes' => ['row for wg-c ignored: not a member of the group', 'wg-b has no next hop: not a candidate'],
                'excluded' => ['wg-b']];
        }));

    uu_check($t, '(r1) one failure refusing every member beside one about an address no member uses: only the first '
        . 'is listed',
        uu_try_case(function (): bool {
            $in = uu_test_contract_input();
            $in['foreign'] = ['10.2.0.1'];
            $in['monitors'] = ['192.0.2.77' => ['wg-x']];
            $c = uu_contract($in);
            return !$c['ok'] && $c['failures'] === ['resolver route not ours'] && $c['notes'] === []
                && $c['excluded'] === [];
        }));
    uu_check($t, '(g4) group deleted, the Default a monitor with a route not ours: 1.3_2\'s three failures, in order',
        uu_try_case(function (): bool {
            $in = uu_test_contract_input();
            $in['group_found'] = false;
            $in['members'] = 0;
            $in['member_resolvers'] = [];
            $in['monitors'] = ['10.2.0.1' => ['wg-x']];
            $in['foreign'] = ['10.2.0.1'];
            $c = uu_contract($in);
            return !$c['ok'] && $c['notes'] === [] && $c['excluded'] === []
                && $c['failures'] === ['resolver is the monitor of wg-x', 'resolver route not ours', 'group not found'];
        }));

    /* (c3) (c4) (c5) what Unbound's generated configuration would not send, an outgoing interface, and the family of
     * the group */
    $ipv6 = fn (array $in): array => ['group_family' => 'inet6', 'member_resolvers' => ['wg-a' => '2001:db8:a::53',
        'wg-b' => '2001:db8:b::53']] + $in;
    $refused = fn (array $over): array => uu_contract($over + uu_test_contract_input());
    $no6 = ['do_ip4' => true, 'do_ip6' => false, 'outgoing_interface' => false];
    $no4 = ['do_ip4' => false, 'do_ip6' => true, 'outgoing_interface' => false];
    $ipv6Text = "Unbound's generated configuration says do-ip6: no (IPv6 is not allowed in System: Settings: General)";
    uu_check($t, '(c3) do-ip6: no with an IPv6 group refuses with the text; with an IPv4 group it does not',
        uu_try_case(fn (): bool => $refused($ipv6(['unbound_conf' => $no6]))['failures'] === [$ipv6Text]
            && $refused(['unbound_conf' => $no6]) === uu_contract(uu_test_contract_input())
            && $refused($ipv6(['unbound_conf' => $no4]))['failures'] === []));
    uu_check($t, '(c4) do-ip4: no with an IPv4 group refuses with the text; with an IPv6 group it does not',
        uu_try_case(fn (): bool => $refused(['unbound_conf' => $no4])['failures']
                === ["Unbound's generated configuration says do-ip4: no"]
            && $refused($ipv6(['unbound_conf' => $no4]))['failures'] === []));
    uu_check($t, '(c4) a group of no family (none found) is refused by neither do-ip4 nor do-ip6',
        uu_try_case(fn (): bool => $refused(['group_family' => '', 'unbound_conf' => ['do_ip4' => false,
            'do_ip6' => false, 'outgoing_interface' => false]])['failures'] === []));
    uu_check($t, '(c4) an outgoing interface refuses either family, with its own text, beside the do-ip refusal',
        uu_try_case(fn (): bool => $refused(['unbound_conf' => ['do_ip4' => true, 'do_ip6' => true,
                'outgoing_interface' => true]])['failures']
                === ["Unbound's Outgoing Network Interfaces is set: its queries would not leave from the tunnel's "
                    . 'own address']
            && $refused($ipv6(['unbound_conf' => ['do_ip4' => true, 'do_ip6' => true,
                'outgoing_interface' => true]]))['failures']
                === ["Unbound's Outgoing Network Interfaces is set: its queries would not leave from the tunnel's "
                    . 'own address']
            && $refused($ipv6(['unbound_conf' => ['do_ip4' => true, 'do_ip6' => false,
                'outgoing_interface' => true]]))['failures'] === [$ipv6Text,
                "Unbound's Outgoing Network Interfaces is set: its queries would not leave from the tunnel's "
                . 'own address']));
    uu_check($t, '(c4) an unreadable unbound.conf (null) refuses with its own text and nothing about the families, '
        . 'whatever the group\'s family (none included)',
        uu_try_case(fn (): bool => $refused(['unbound_conf' => null])['failures'] === ['unbound.conf unreadable']
            && $refused($ipv6(['unbound_conf' => null]))['failures'] === ['unbound.conf unreadable']
            && $refused(['group_family' => '', 'unbound_conf' => null])['failures']
                === ['unbound.conf unreadable']));
    uu_check($t, '(c4) an outgoing interface refuses a group of no family too',
        uu_try_case(fn (): bool => $refused(['group_family' => '', 'unbound_conf' => ['do_ip4' => true,
            'do_ip6' => true, 'outgoing_interface' => true]])['failures']
            === ["Unbound's Outgoing Network Interfaces is set: its queries would not leave from the tunnel's own "
                . 'address']));
    uu_check($t, '(c5) a group of both families refuses with the text',
        uu_try_case(fn (): bool => $refused(['mixed_family' => true])['failures']
            === ['the group has IPv4 and IPv6 members']));
    uu_check($t, '(c5) an IPv4 resolver on an IPv6 group, and an IPv6 one on an IPv4 group, each refuse by address',
        uu_try_case(fn (): bool => $refused(['group_family' => 'inet6',
                'family_mismatch' => ['192.0.2.53']])['failures']
                === ['resolver 192.0.2.53 is IPv4 but the group is IPv6']
            && $refused(['family_mismatch' => ['2001:db8::53', '2001:db8::54']])['failures']
                === ['resolver 2001:db8::53 is IPv6 but the group is IPv4',
                    'resolver 2001:db8::54 is IPv6 but the group is IPv4']));
    uu_check($t, '(c5) the new failures come after the others in a fixed order: zone, configuration, family; '
        . 'a mismatch alone is by address',
        uu_try_case(fn (): bool => $refused(['group_found' => false, 'mixed_family' => true,
                'unbound_conf' => null,
                'zone' => ['shape' => 'unrestorable', 'addrs' => [], 'tls' => false, 'problems' => ['x']]])['failures']
            === ['root zone cannot be restored: x', 'unbound.conf unreadable',
                'the group has IPv4 and IPv6 members', 'group not found']
            && $refused(['family_mismatch' => ['192.0.2.53'], 'group_family' => 'inet6'])['failures']
                === ['resolver 192.0.2.53 is IPv4 but the group is IPv6']));

    /* Unbound's configured root zone naming an effective resolver: the plugin could not tell its own forwarding from
     * the owner's, so tunnel mode is refused as a whole */
    $zoneOf = fn (array $addrs): array => ['zone' => ['shape' => 'one', 'addrs' => $addrs, 'tls' => false,
        'problems' => []]];
    $named = fn (string $address, string $members): string => "Unbound's root zone forwards to $address, the resolver "
        . "of $members: the plugin cannot tell that forwarding from its own";
    uu_check($t, '(z5) an IPv4 configured zone naming the Default refuses, naming the address and every member '
        . 'using it, whatever port and name the zone gives',
        uu_try_case(function () use ($refused, $zoneOf, $named): bool {
            $plain = $refused($zoneOf(['10.2.0.1']));
            $ported = $refused($zoneOf(['192.0.2.53@853#dns.example', '10.2.0.1@5353']));
            return !$plain['ok'] && $plain['failures'] === [$named('10.2.0.1', 'wg-a, wg-b')]
                && $ported['failures'] === [$named('10.2.0.1', 'wg-a, wg-b')];
        }));
    uu_check($t, '(z5) an IPv6 configured zone naming a per-member row\'s address refuses in any spelling of the '
        . 'address, naming that member alone',
        uu_try_case(function () use ($refused, $zoneOf, $named): bool {
            $in = ['group_family' => 'inet6', 'member_resolvers' => ['wg-a' => '2001:db8:a::53',
                'wg-b' => '2001:db8:b::53']];
            $c = $refused($in + $zoneOf(['2001:DB8:B:0::0053@853']));
            return !$c['ok'] && $c['failures'] === [$named('2001:db8:b::53', 'wg-b')] && $c['excluded'] === [];
        }));
    uu_check($t, '(z5) a zone naming two effective resolvers refuses once for each, in address order',
        uu_try_case(function () use ($refused, $zoneOf, $named): bool {
            $in = ['member_resolvers' => ['wg-a' => '192.0.2.53', 'wg-b' => '192.0.2.54']];
            return $refused($in + $zoneOf(['192.0.2.54', '192.0.2.53']))['failures']
                === [$named('192.0.2.53', 'wg-a'), $named('192.0.2.54', 'wg-b')];
        }));
    uu_check($t, '(z5) a zone naming an address no member uses, a zone of another family, and no zone refuse nothing',
        uu_try_case(fn (): bool => $refused($zoneOf(['192.0.2.77']))['failures'] === []
            && $refused($zoneOf(['2001:db8::1']))['failures'] === []
            && $refused($zoneOf(['10.2.0.10']))['failures'] === []
            && $refused(['zone' => ['shape' => 'none', 'addrs' => [], 'tls' => false, 'problems' => []]])['ok']));
    uu_check($t, '(z5) a member resolver in a non-canonical spelling is named by the zone all the same, and printed '
        . 'canonical',
        uu_try_case(fn (): bool => $refused(['group_family' => 'inet6',
                'member_resolvers' => ['wg-a' => '2001:DB8:A:0::53']] + $zoneOf(['2001:db8:a::53@853']))['failures']
            === [$named('2001:db8:a::53', 'wg-a')]));
    uu_check($t, '(z5) a member with no resolver is no address the zone can name',
        uu_try_case(fn (): bool => $refused(['member_resolvers' => ['wg-a' => '', 'wg-b' => '192.0.2.54']]
            + $zoneOf(['192.0.2.53', '']))['failures'] === []));

    return uu_tally_report('contract', $t);
});
