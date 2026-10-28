<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Status and logging: the blocked-count log line, the route flags, durations and the status
 * document.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/log.php';
require_once __DIR__ . '/test_planner.php';
require_once __DIR__ . '/test_snapshot.php';
require_once __DIR__ . '/scratch.php';

uu_register_suite('log', function (): int {
    $t = ['fail' => 0, 'total' => 0];

    uu_check($t, 'blocked line: no counting table, or nothing blocked since it was → no line',
        uu_blocked_line(null, null) === null && uu_blocked_line(5, null) === null && uu_blocked_line(null, 0) === null
        && uu_blocked_line(7, 7) === null);
    uu_check($t, 'blocked line: a first count above zero is logged',
        uu_blocked_line(null, 5)
        === 'blocked 5 resolver packets on a non-member path since the counting table was created');
    uu_check($t, 'blocked line: a rise is logged with the difference',
        uu_blocked_line(5, 9)
        === 'blocked 4 more resolver packets on a non-member path (9 since the counting table was created)');
    uu_check($t, 'blocked line: a lower count is a recreated table (counters reset), logged only above zero',
        uu_blocked_line(9, 2) === 'blocked 2 resolver packets on a non-member path since the counting table was created'
        && uu_blocked_line(9, 0) === null);

    uu_check($t, 'log text: tab, ESC, NUL, DEL and a C1 pair each become ?',
        uu_try_case(fn (): bool => uu_log_text("a\tb") === 'a?b' && uu_log_text("a\x1Bb") === 'a?b'
            && uu_log_text("a\0b") === 'a?b' && uu_log_text("a\x7Fb") === 'a?b'
            && uu_log_text("a\xC2\x85b") === 'a?b'));
    uu_check($t, 'log text: CR and LF become "; "',
        uu_try_case(fn (): bool => uu_log_text("a\nb") === 'a; b' && uu_log_text("a\r\nb") === 'a; ; b'));
    uu_check($t, 'log text: invalid UTF-8 and plain text are unchanged, and the result is never null',
        uu_try_case(fn (): bool => uu_log_text("a\xFFb") === "a\xFFb"
            && uu_log_text('plain text, 10.2.0.1: ok') === 'plain text, 10.2.0.1: ok'
            && uu_log_text("\xC3\xA9") === "\xC3\xA9"));

    uu_check($t, 'route flags from route get', uu_status_route_flags(uu_snapshot_fixture('route_get_member.txt'))
        === ['UP', 'GATEWAY', 'HOST', 'DONE', 'STATIC']);
    uu_check($t, 'route flags: none for empty output', uu_status_route_flags('') === []);

    uu_check($t, 'duration: two largest units',
        uu_duration_text(0) === '0 s' && uu_duration_text(59) === '59 s' && uu_duration_text(60) === '1 min 0 s'
        && uu_duration_text(130) === '2 min 10 s' && uu_duration_text(40979) === '11 h 22 min'
        && uu_duration_text(273600) === '3 d 4 h' && uu_duration_text(86400) === '1 d 0 h');
    uu_check($t, 'duration: the seams where a unit changes',
        uu_duration_text(3599) === '59 min 59 s' && uu_duration_text(3600) === '1 h 0 min'
        && uu_duration_text(86399) === '23 h 59 min');

    $now = 10000;
    $s = uu_test_in_tunnel(uu_test_snapshot(), 'wg-a');
    $s['probes']['wg-b'] = uu_test_probe('down', '100.0 %', 300);
    $down = ['at' => 1792390000, 'reason' => 'settled down'];
    $timers = ['wg-a' => uu_test_timer(40919, null, $now - 60), 'wg-b' => uu_test_timer(0, $now + 30, null)];
    $timers['wg-a']['probe_failures'] = 1;
    $timers['wg-b']['last_down'] = $down;
    $st = uu_test_plan_state('wg-a', $timers);
    $st['checks'] = ['direct' => ['ok' => true, 'at' => 1760000000, 'member' => 'wg-a'], 'unbound' => null];
    $st['tls_applied'] = false;
    /* the flags the snapshot's own read of the member route printed */
    $route = uu_snapshot_fixture('route_get_member.txt');
    $s['route_flags'] = ['10.2.0.1' => uu_status_route_flags($route)];
    $plan = uu_plan($s, $st);
    $armed = ['armed' => true, 'fill' => false, 'blocked' => 37];
    $doc = uu_status_doc($s, $plan, $armed);
    uu_check($t, 'status: every field',
        array_keys($doc) === ['enabled', 'dry_run', 'resolver', 'mode', 'member', 'tier', 'unbound', 'live_root',
            'configured_root', 'tls_applied', 'route', 'routes', 'rules_loaded', 'rules', 'footprint', 'addresses',
            'counter_armed', 'blocked', 'checks', 'members', 'last_switch', 'contract', 'next']);
    uu_check($t, 'status: the resolver, mode, member and its tier; live and configured roots; the TLS flag applied',
        $doc['resolver'] === $s['settings']['default'] && $doc['mode'] === 'tunnel' && $doc['member'] === 'wg-a' && $doc['tier'] === 1
        && $doc['live_root'] === ['10.2.0.1'] && $doc['configured_root'] === $s['zone'] && $doc['tls_applied'] === false
        && $doc['unbound'] === ['enabled' => true, 'running' => true, 'control_ok' => true]);
    uu_check($t, 'status: the route with its flags',
        $doc['route'] === $s['routes']['10.2.0.1'] + ['flags' => ['UP', 'GATEWAY', 'HOST', 'DONE', 'STATIC']]);
    uu_check($t, 'status: the rules as the snapshot verified them, loaded; the counter armed with its table\'s count',
        $doc['rules_loaded'] === true
        && $doc['rules'] === ['state' => 'loaded', 'problems' => [], 'verified_at' => 1792399000]
        && $doc['counter_armed'] === true && $doc['blocked'] === 37);
    $missing = $s;
    $problem = 'no pass rule for wg-b (opt2)';
    $missing['rules'] = ['state' => 'missing', 'problems' => [$problem], 'verified_at' => 1792399500, 'record' => null];
    $missing['contract_input']['rules'] = ['state' => 'missing', 'problems' => [$problem]];
    $d = uu_status_doc($missing, uu_plan($missing, $st), $armed);
    uu_check($t, 'status: rules missing are not loaded, their problems carried and named in the contract',
        $d['rules_loaded'] === false
        && $d['rules'] === ['state' => 'missing', 'problems' => [$problem], 'verified_at' => 1792399500]
        && $d['contract']['failures'] === ['firewall rules: ' . $problem]);
    $verifying = $s;
    $verifying['rules'] = ['state' => 'verifying', 'problems' => [], 'verified_at' => null, 'record' => null];
    $verifying['contract_input']['rules'] = ['state' => 'verifying', 'problems' => []];
    $d = uu_status_doc($verifying, uu_plan($verifying, $st), $armed);
    uu_check($t, 'status: verifying is not loaded, has no time, and the contract carries the note only',
        $d['rules_loaded'] === false && $d['rules'] === ['state' => 'verifying', 'problems' => [], 'verified_at' => null]
        && $d['contract']['ok']
        && $d['contract']['notes'] === ['firewall rules are being verified (the ruleset changed)']);
    $d = uu_status_doc($s, $plan, ['armed' => false, 'fill' => true, 'blocked' => 0]);
    uu_check($t, 'status: a table that does not hold the resolver is not armed; its count is still the table\'s',
        $d['counter_armed'] === false && $d['blocked'] === 0);
    $d = uu_status_doc($s, $plan, ['armed' => false, 'fill' => false, 'blocked' => null]);
    uu_check($t, 'status: no table: not armed, no count',
        $d['counter_armed'] === false && $d['blocked'] === null);
    uu_check($t, 'status: members with tier, reading kind, verdict, health as a duration, last down, resolver-failed '
        . 'time and failures',
        $doc['members'] === [
            ['name' => 'wg-a', 'tier' => 1, 'resolver' => '10.2.0.1', 'kind' => 'settled', 'verdict' => null,
             'usable' => true, 'healthy_for' => 40979, 'healthy_for_text' => '11 h 22 min', 'last_down' => null,
             'resolver_failed_for' => null, 'probe_failures' => 1],
            ['name' => 'wg-b', 'tier' => 2, 'resolver' => '10.2.0.1', 'kind' => 'settled', 'verdict' => 'settled down',
             'usable' => false, 'healthy_for' => 0, 'healthy_for_text' => '0 s', 'last_down' => $down,
             'resolver_failed_for' => 30, 'probe_failures' => 0],
        ]);
    $contract = uu_contract($s['contract_input']);
    uu_check($t, 'status: checks, contract and the next evaluation\'s action',
        $doc['checks'] === $st['checks']
        && $doc['contract'] === ['ok' => $contract['ok'], 'failures' => $contract['failures'],
                                 'notes' => $contract['notes']]
        && $doc['next']['action'] === 'none' && $doc['last_switch'] === null);

    /* (l1) the footprint: the address the plugin last used, when the setting does not cover it */
    $fst = $st;
    $fst['addresses'] = ['192.0.2.1' => ['route' => ['kind' => 'member', 'next_hop' => '192.0.2.2', 'if' => 'wg1'],
                                          'forwarded' => true, 'released_at' => null]];
    $off = $s;
    $off['settings']['enabled'] = false;
    $same = $st;
    $same['addresses'] = [$s['settings']['default'] => ['route' => null, 'forwarded' => true, 'released_at' => null]];
    $footprint = fn (array $doc): ?string => array_key_exists('footprint', $doc) ? $doc['footprint'] : 'absent';
    uu_check($t, '(l1) status: a footprint the disabled setting does not cover is named; one equal to the enabled '
        . 'setting is null',
        $footprint(uu_status_doc($off, uu_plan($off, $fst), $armed)) === '192.0.2.1'
        && $footprint(uu_status_doc($s, uu_plan($s, $same), $armed)) === null);
    $lost = $s;
    $lost['contract_input']['group_found'] = false;
    uu_check($t, '(l1) status: a footprint is named beside another enabled resolver, or a group that is gone, and '
        . 'none recorded is null',
        $footprint(uu_status_doc($s, uu_plan($s, $fst), $armed)) === '192.0.2.1'
        && $footprint(uu_status_doc($lost, uu_plan($lost, $same), $armed)) === $s['settings']['default']
        && $footprint($doc) === null);

    uu_check($t, '(p16) status: a found group with no member, the Default recorded on its reject route: no footprint, '
        . 'and the counter armed for a table holding the Default',
        uu_try_case(function () use ($s, $st, $footprint): bool {
            $bare = $s;
            $bare['tiers'] = [];
            $bare['members'] = [];
            $bare['probes'] = [];
            $bare['contract_input']['members'] = 0;
            $bare['contract_input']['member_resolvers'] = [];
            $recorded = $st;
            $recorded['mode'] = 'fallback';
            $recorded['member'] = null;
            $recorded['addresses'] = ['10.2.0.1' => ['route' => ['kind' => 'reject', 'next_hop' => '', 'if' => 'lo0'],
                'forwarded' => false, 'released_at' => null]];
            $table = uu_block_table_view(['addresses' => 1, 'references' => 1, 'out_block' => 3], ['10.2.0.1'],
                uu_setting_addresses($bare));
            $doc = uu_status_doc($bare, uu_plan($bare, $recorded), $table);
            return $footprint($doc) === null && $doc['counter_armed'] === true;
        }));
    /* (l1) the status's resolver is the active one: in tunnel mode the live root's address, else the member's
     * resolver; otherwise the first member in tier order that has one, else the Default, else '' */
    $active = fn (array $snapshot, array $state): string => uu_status_active($snapshot, uu_plan($snapshot, $state));
    $silent = fn (array $snapshot): array => ['control_ok' => false, 'live_root' => null] + $snapshot['unbound'];
    $one = null;
    $ok = uu_try_case(function () use ($s, $st, $active, $silent, &$one): bool {
        $quiet = $s;
        $quiet['unbound'] = $silent($s);
        $fallback = uu_test_snapshot();
        $groupGone = $fallback;
        $groupGone['tiers'] = [];
        $groupGone['members'] = [];
        $groupGone['probes'] = [];
        $groupGone['contract_input']['group_found'] = false;
        $one = [$active($s, $st), $active($quiet, $st), $active($fallback, uu_test_plan_state(null)),
                $active($groupGone, uu_test_plan_state(null))];
        return true;
    });
    uu_check($t, '(l1) one address: the status\'s active resolver is the Default in tunnel mode, with the live root '
        . 'unknown, in fallback and with the group gone',
        $ok && $one === ['10.2.0.1', '10.2.0.1', '10.2.0.1', '10.2.0.1']);
    foreach (['IPv6' => ['2001:db8:a::53', '2001:DB8:B:0::53', 'fd00::3:2', 'wg3', 'fd00::4:2', 'wg4'],
              'IPv4' => ['198.51.100.10', '198.51.100.20', '10.2.0.2', 'wg1', '10.2.0.6', 'wg2']]
             as $family => [$a, $b, $hopA, $ifA, $hopB, $ifB]) {
        $got = null;
        $ok = uu_try_case(function () use ($a, $b, $hopA, $ifA, $hopB, $ifB, $active, $silent, &$got): bool {
            $pm = uu_test_default(uu_test_snapshot(), $a);
            $pm['members']['wg-a']['next_hop'] = $hopA;
            $pm['members']['wg-a']['if'] = $ifA;
            $pm['members']['wg-b']['next_hop'] = $hopB;
            $pm['members']['wg-b']['if'] = $ifB;
            $pm = uu_test_resolver($pm, 'wg-b', $b);
            $onB = uu_test_in_tunnel($pm, 'wg-b');
            $stB = uu_test_plan_state('wg-b', [], 0, null, $b, $pm);
            $midSwitch = $onB;
            $midSwitch['unbound']['live_root'] = [$a];
            $quiet = $onB;
            $quiet['unbound'] = $silent($onB);
            $noA = $pm;
            $noA['members']['wg-a']['resolver'] = '';
            $none = $noA;
            $none['members']['wg-b']['resolver'] = '';
            $none['settings']['default'] = '';
            /* the tiers in the other order than the members' keys */
            $reversed = $pm;
            $reversed['tiers'] = [['wg-b'], ['wg-a']];
            /* Unbound's own configured root zone [B] is no tunnel mode: the first member in tier order's */
            $configured = uu_test_route($pm, ['present' => true, 'gateway' => $hopB, 'interface' => $ifB,
                'reject' => false, 'ours' => true], $b);
            $configured['zone'] = ['shape' => 'one', 'addrs' => [$b], 'tls' => false, 'problems' => []];
            $configured['contract_input']['zone'] = $configured['zone'];
            $configured['unbound']['live_root'] = [$b];
            /* tunnel mode on wg-a while Unbound is back on its configured root [B]: the member's own resolver */
            $onAConfigured = $configured;
            $stA = uu_test_plan_state('wg-a', [], 0, null, $a, $pm);
            $got = [$active($onB, $stB), $active($midSwitch, $stB), $active($quiet, $stB),
                    $active($pm, uu_test_plan_state(null)), $active($noA, uu_test_plan_state(null)),
                    $active($none, uu_test_plan_state(null)), $active($reversed, uu_test_plan_state(null)),
                    $active($configured, uu_test_plan_state(null)), $active($onAConfigured, $stA)];
            $onB['route_flags'] = [uu_ip_canonical($b) ?? $b
                => uu_status_route_flags(uu_snapshot_fixture('route_get_member.txt'))];
            $doc = uu_status_doc($onB, uu_plan($onB, $stB), ['armed' => true, 'fill' => false, 'blocked' => 0]);
            $got[] = $doc['resolver'];
            $got[] = $doc['route'] === $onB['routes'][uu_ip_canonical($b)] + ['flags' => ['UP', 'GATEWAY', 'HOST',
                'DONE', 'STATIC']];
            return true;
        });
        $bc = uu_ip_canonical($b);
        uu_check($t, "(l1) $family, a resolver per member: in tunnel mode on wg-b the live root's address (also "
            . 'mid-switch), the member\'s with the live root unknown; otherwise the first member in tier order with '
            . 'one (by the tiers, not the members\' order), else none, and so with a live root that is Unbound\'s '
            . 'configured root zone, which in tunnel mode on wg-a names wg-a\'s; canonical; the status names it and '
            . 'its route',
            $ok && $got === [$bc, $a, $bc, $a, $bc, '', $bc, $a, $a, $bc, true]);
    }

    $gone = $s;
    $gone['unbound'] = ['enabled' => true, 'pid_alive' => false, 'control_ok' => false, 'live_root' => null];
    $gone['route_flags'] = [];
    $doc = uu_status_doc($gone, uu_plan($gone, $st), ['armed' => false, 'fill' => false, 'blocked' => null]);
    uu_check($t, 'status: Unbound not running is reported, with no blocked count and no route flags',
        $doc['unbound']['running'] === false && $doc['blocked'] === null && $doc['route']['flags'] === []
        && uu_test_reason_has($doc['next']['reasons'], 'Unbound not running'));

    /* 1.3_2's status for one address: the document without the keys 1.4 adds (routes, addresses and each member's
     * resolver), encoded as evaluate.php status encodes it, against what 1.3_2's own code printed for the same
     * snapshot and state (fixtures/status_1.3_2_*.json) */
    $as132 = function (array $doc): string {
        unset($doc['routes'], $doc['addresses']);
        foreach (array_keys($doc['members']) as $i) {
            unset($doc['members'][$i]['resolver']);
        }
        return json_encode($doc, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    };
    $printed = fn (string $name): string => trim(uu_snapshot_fixture("status_1.3_2_$name.json"));
    $memberFlags = ['UP', 'GATEWAY', 'HOST', 'DONE', 'STATIC'];
    $rejectFlags = ['UP', 'HOST', 'REJECT', 'DONE', 'STATIC'];
    $reject = ['present' => true, 'gateway' => '', 'interface' => 'lo0', 'reject' => true, 'ours' => true];
    $rejected = ['route' => ['kind' => 'reject', 'next_hop' => '', 'if' => 'lo0'], 'forwarded' => false,
                 'released_at' => null];

    uu_check($t, '(l2) one IPv4 address in tunnel mode: every key and value 1.3_2 printed, byte for byte',
        uu_try_case(fn (): bool => $as132(uu_status_doc($s, $plan, $armed)) === $printed('tunnel')));
    uu_check($t, '(l2) …and the keys it adds are only routes, addresses and each member\'s resolver: the one address, '
        . 'its route as route shows it',
        uu_try_case(function () use ($s, $plan, $armed, $printed, $memberFlags): bool {
            $doc = uu_status_doc($s, $plan, $armed);
            $was = json_decode($printed('tunnel'), true);
            $added = fn (array $now, array $then): array => array_values(array_diff(array_keys($now),
                array_keys($then)));
            return $added($doc, $was) === ['routes', 'addresses']
                && $added($doc['members'][0], $was['members'][0]) === ['resolver']
                && $added($doc['members'][1], $was['members'][1]) === ['resolver']
                && $doc['routes'] === ['10.2.0.1' => $s['routes']['10.2.0.1'] + ['flags' => $memberFlags,
                    'footprint' => false]]
                && $doc['addresses'] === ['10.2.0.1'] && array_column($doc['members'], 'resolver') === ['10.2.0.1',
                    '10.2.0.1'];
        }));

    foreach (['IPv6' => ['2001:db8:a::53', '2001:db8:b::53', 'fd00::3:2', 'wg3', 'fd00::4:2', 'wg4', '6'],
              'IPv4' => ['198.51.100.10', '198.51.100.20', '10.2.0.2', 'wg1', '10.2.0.6', 'wg2', '']]
             as $family => [$a, $b, $hopA, $ifA, $hopB, $ifB, $six]) {
        $docs = null;
        $ok = uu_try_case(function () use ($a, $b, $hopA, $ifA, $hopB, $ifB, $six, $reject, $rejected,
            &$docs): bool {
            $pm = uu_test_default(uu_test_snapshot(), $a);
            $pm['members']['wg-a']['next_hop'] = $hopA;
            $pm['members']['wg-a']['if'] = $ifA;
            $pm['members']['wg-b']['next_hop'] = $hopB;
            $pm['members']['wg-b']['if'] = $ifB;
            $pm = uu_test_resolver($pm, 'wg-b', $b);
            /* after a failover from wg-a to wg-b: a on its reject route, b on wg-b's; the map holds b first */
            $onB = uu_test_route(uu_test_in_tunnel($pm, 'wg-b'), $reject, $a);
            $stB = uu_test_plan_state('wg-b', [], 0, null, $b, $pm);
            $stB['addresses'][$a] = $rejected;
            $onB['route_flags'] = [$a => uu_status_route_flags(uu_snapshot_fixture("route_get_reject$six.txt")),
                                  $b => uu_status_route_flags(uu_snapshot_fixture("route_get_member$six.txt"))];
            $view = ['armed' => true, 'fill' => false, 'blocked' => 0];
            /* wg-a's own row now names b too: a, no member's resolver any more, is held */
            $held = uu_test_resolver($onB, 'wg-a', $b);
            $stHeld = $stB;
            $stHeld['addresses'][$a]['released_at'] = $held['now'] - 10;
            $docs = ['failover' => uu_status_doc($onB, uu_plan($onB, $stB), $view),
                     'held' => uu_status_doc($held, uu_plan($held, $stHeld), $view), 'onB' => $onB];
            return true;
        });
        $f = $docs['failover'] ?? [];
        $onB = $docs['onB'] ?? [];
        $routeA = $reject + ['flags' => $rejectFlags];
        $routeB = ($onB['routes'][$b] ?? []) + ['flags' => $memberFlags];
        uu_check($t, "(l3) $family, two addresses after a failover to wg-b: resolver b with its route, routes both "
            . 'with flags in sorted order, addresses sorted, no footprint (a is still wg-a\'s), each member\'s '
            . 'resolver',
            $ok && $f['resolver'] === $b && $f['route'] === $routeB
            && $f['routes'] === [$a => $routeA + ['footprint' => false], $b => $routeB + ['footprint' => false]]
            && array_keys($f['routes']) === [$a, $b] && $f['addresses'] === [$a, $b] && $f['footprint'] === null
            && array_column($f['members'], 'resolver', 'name') === ['wg-a' => $a, 'wg-b' => $b]);
        $h = $docs['held'] ?? [];
        uu_check($t, "(l4) $family, an orphan in its hold: the footprint is it, addresses both, and only its route "
            . 'entry is a footprint',
            $ok && $h['footprint'] === $a && $h['addresses'] === [$a, $b]
            && ($h['routes'][$a]['footprint'] ?? null) === true && ($h['routes'][$b]['footprint'] ?? null) === false
            && array_column($h['members'], 'resolver', 'name') === ['wg-a' => $b, 'wg-b' => $b]);
    }

    uu_check($t, '(l4) disabled, its stop leaving 10.2.0.1 recorded on its reject route: the footprint is 10.2.0.1, '
        . 'and every key and value is 1.3_2\'s',
        uu_try_case(function () use ($as132, $printed, $reject, $rejected): bool {
            $off = uu_test_route(uu_test_snapshot(), $reject);
            $off['settings']['enabled'] = false;
            $st = uu_test_plan_state(null);
            $st['addresses'] = ['10.2.0.1' => $rejected];
            $off['route_flags'] = ['10.2.0.1' => uu_status_route_flags(uu_snapshot_fixture('route_get_reject.txt'))];
            $doc = uu_status_doc($off, uu_plan($off, $st), ['armed' => false, 'fill' => false, 'blocked' => null]);
            return $doc['footprint'] === '10.2.0.1' && $as132($doc) === $printed('disabled')
                && $doc['addresses'] === ['10.2.0.1'] && $doc['routes']['10.2.0.1']['footprint'] === true;
        }));

    /* (l7) a status poll between the upgrade's post-install and the first tick: the wiring suite's version 5 file,
     * converted on read */
    uu_check($t, '(l7) a version 5 tunnel-mode file: every key and value 1.3_2 printed for it, byte for byte',
        uu_try_case(function () use ($as132, $printed, $armed, $route): bool {
            $v5 = [
                'version' => 5, 'mode' => 'tunnel', 'member' => 'wg-a',
                'timers' => ['wg-a' => ['usable_since' => 1200, 'counted' => 45, 'last_at' => 1245,
                    'resolver_failed_until' => null, 'probe_failures' => 0, 'last_down' => null]],
                'control_failures' => 0, 'control_silent_since' => null,
                'last_switch' => ['at' => 1760000000, 'from' => 'fallback', 'to' => 'wg-a',
                                  'reason' => 'member usable'],
                'checks' => ['direct' => null, 'unbound' => null], 'tls_applied' => false, 'blocked' => null,
                'route_installed' => ['kind' => 'member', 'next_hop' => '10.2.0.4', 'if' => 'wg1'],
                'resolver' => '10.2.0.1',
            ];
            $s5 = uu_test_snapshot();
            $s5['members']['wg-a']['next_hop'] = '10.2.0.4';
            $s5 = uu_test_in_tunnel($s5, 'wg-a');
            $st5 = uu_state_from_doc($v5);
            if ($st5 === null) {
                return false;
            }
            $s5['route_flags'] = ['10.2.0.1' => uu_status_route_flags($route)];
            $doc = uu_status_doc($s5, uu_plan($s5, $st5), $armed);
            return $as132($doc) === $printed('v5') && $doc['addresses'] === ['10.2.0.1']
                && $doc['routes']['10.2.0.1'] === $doc['route'] + ['footprint' => false];
        }));

    foreach (['2001:DB8:A:0::53', '2001:0db8:a::0053'] as $typed) {
        $got = null;
        $ok = uu_try_case(function () use ($typed, &$got): bool {
            $raw = ['resolver' => $typed, 'rows' => [], 'probe_name' => '.', 'failback_delay' => '120',
                    'group_uuid' => '', 'fallback' => '1', 'fail_closed' => '', 'fail_closed_networks' => ''];
            /* the snapshot as it would carry the typed form, were it not cleaned */
            $pm = uu_test_default(uu_test_snapshot(), $typed);
            $pm['members']['wg-a']['next_hop'] = 'fd00::3:2';
            $pm['members']['wg-a']['if'] = 'wg3';
            $pm['members']['wg-b']['next_hop'] = 'fd00::4:2';
            $pm['members']['wg-b']['if'] = 'wg4';
            $on = uu_test_in_tunnel($pm, 'wg-a');
            $on['unbound']['live_root'] = ['2001:db8:a::53'];
            $on['route_flags'] = ['2001:db8:a::53'
                => uu_status_route_flags(uu_snapshot_fixture('route_get_member6.txt'))];
            $doc = uu_status_doc($on, uu_plan($on, uu_test_plan_state('wg-a', [], 0, null, $typed, $pm)),
                ['armed' => true, 'fill' => false, 'blocked' => 0]);
            $got = ['cleaned' => uu_settings_clean($raw)['settings']['default'], 'doc' => $doc];
            return true;
        });
        $d = $got['doc'] ?? [];
        uu_check($t, "(l8) a Default typed $typed, the live root printed [2001:db8:a::53]: the settings clean it, the "
            . 'status names it canonical, so live_root == [resolver] holds; each member\'s resolver and the map\'s '
            . 'address canonical, with its route',
            $ok && $got['cleaned'] === '2001:db8:a::53' && $d['resolver'] === '2001:db8:a::53'
            && $d['live_root'] === [$d['resolver']]
            && array_column($d['members'], 'resolver') === ['2001:db8:a::53', '2001:db8:a::53']
            && $d['addresses'] === ['2001:db8:a::53'] && $d['route']['flags'] === $memberFlags);
    }

    /* (l2) dry run on in fallback, Unbound disabled and not running, the check through Unbound failed, the TLS flag
     * applied, the rules missing with two problems and cacheflush on, and the Default's route absent while its read
     * printed the default route's flags: every key and value 1.3_2 printed */
    uu_check($t, '(l2) dry run in fallback with Unbound off, a failed check, two rule failures and a note, and an '
        . 'absent route: every key and value 1.3_2 printed, byte for byte',
        uu_try_case(function () use ($as132, $printed): bool {
            $dry = uu_test_snapshot();
            $dry['settings']['dry_run'] = true;
            $dry['unbound'] = ['enabled' => false, 'pid_alive' => false, 'control_ok' => false, 'live_root' => null];
            $problems = ['no pass rule for wg-a (opt1)', 'no pass rule for wg-b (opt2)'];
            $dry['rules'] = ['state' => 'missing', 'problems' => $problems, 'verified_at' => 1792399500,
                             'record' => null];
            $dry['contract_input']['rules'] = ['state' => 'missing', 'problems' => $problems];
            $dry['contract_input']['cacheflush'] = true;
            $dry['route_flags'] = ['10.2.0.1' => uu_status_route_flags(uu_snapshot_fixture('route_get_default.txt'))];
            $st = uu_test_plan_state(null);
            $st['checks'] = ['direct' => ['ok' => true, 'at' => 1760000000, 'member' => 'wg-a'],
                             'unbound' => ['ok' => false, 'at' => 1760000100, 'member' => 'wg-a']];
            $st['tls_applied'] = true;
            $doc = uu_status_doc($dry, uu_plan($dry, $st), ['armed' => false, 'fill' => false, 'blocked' => null]);
            return $dry['route_flags']['10.2.0.1'] !== [] && $as132($doc) === $printed('dryrun');
        }));

    /* (l9) the active resolver has a row of its own when the map does not hold it: the map holds a and b, held, and
     * every member is on c */
    foreach (['IPv4' => ['198.51.100.10', '198.51.100.20', '198.51.100.30', ''],
              'IPv6' => ['2001:db8:a::53', '2001:db8:b::53', '2001:db8:c::53', '6']] as $family => [$a, $b, $c, $six]) {
        $doc = null;
        $ok = uu_try_case(function () use ($a, $b, $c, $six, $reject, $rejected, &$doc): bool {
            $on = uu_test_route(uu_test_route(uu_test_default(uu_test_snapshot(), $c), $reject, $a), $reject, $b);
            $on['route_flags'] = [$a => uu_status_route_flags(uu_snapshot_fixture("route_get_reject$six.txt")),
                                  $b => uu_status_route_flags(uu_snapshot_fixture("route_get_reject$six.txt")),
                                  $c => uu_status_route_flags(uu_snapshot_fixture('route_get_default.txt'))];
            $st = uu_test_plan_state(null);
            $held = $rejected;
            $held['released_at'] = $on['now'] - 10;
            $st['addresses'] = [$b => $held, $a => $held];
            $doc = uu_status_doc($on, uu_plan($on, $st), ['armed' => true, 'fill' => false, 'blocked' => 0]);
            return true;
        });
        $absent = ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false, 'ours' => false,
                   'flags' => []];
        uu_check($t, "(l9) $family, the map holding a and b and every member on c: c, the resolver, has its own row "
            . '(absent, so no flags), beside a and b, each a footprint, in sorted order; addresses stay the map\'s',
            $ok && $doc['resolver'] === $c && array_keys($doc['routes']) === [$a, $b, $c]
            && $doc['routes'][$c] === $absent + ['footprint' => false] && $doc['route'] === $absent
            && $doc['routes'][$a]['footprint'] === true && $doc['routes'][$b]['footprint'] === true
            && $doc['routes'][$a]['flags'] === ['UP', 'HOST', 'REJECT', 'DONE', 'STATIC']
            && $doc['addresses'] === [$a, $b]);
    }

    /* (l10) several footprints: the first in sorted order is the status's footprint, whatever the map's order */
    $doc = null;
    $ok = uu_try_case(function () use ($rejected, &$doc): bool {
        $off = uu_test_snapshot();
        $off['settings']['enabled'] = false;
        $st = uu_test_plan_state(null);
        $st['addresses'] = ['198.51.100.20' => $rejected, '198.51.100.10' => $rejected];
        $doc = uu_status_doc($off, uu_plan($off, $st), ['armed' => false, 'fill' => false, 'blocked' => null]);
        return true;
    });
    uu_check($t, '(l10) disabled with two addresses recorded in reverse order: the footprint is the sorted first, '
        . 'both entries are footprints, and the active Default has its own row, no footprint',
        $ok && $doc['footprint'] === '198.51.100.10'
        && array_keys($doc['routes']) === ['10.2.0.1', '198.51.100.10', '198.51.100.20']
        && $doc['routes']['198.51.100.10']['footprint'] === true
        && $doc['routes']['198.51.100.20']['footprint'] === true
        && $doc['routes']['10.2.0.1']['footprint'] === false
        && $doc['addresses'] === ['198.51.100.10', '198.51.100.20']);

    return uu_tally_report('log', $t);
});
