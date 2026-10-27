<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Core contract: each broken input refuses tunnel mode with its own named failure; a core
 * command a removal falls back to that no longer matches core is a note, and the package scripts run the
 * same commands.
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
 *     fib_sync_ms: ?int, cacheflush: bool, group_found: bool, members: int, core_commands: list<string>}
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

    return uu_tally_report('contract', $t);
});
