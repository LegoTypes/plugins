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
    $plan = uu_plan($s, $st);
    $armed = ['armed' => true, 'fill' => false, 'blocked' => 37];
    $route = uu_snapshot_fixture('route_get_member.txt');
    $doc = uu_status_doc($s, $plan, $armed, $route);
    uu_check($t, 'status: every field',
        array_keys($doc) === ['enabled', 'dry_run', 'resolver', 'mode', 'member', 'tier', 'unbound', 'live_root',
            'configured_root', 'tls_applied', 'route', 'rules_loaded', 'rules', 'footprint', 'counter_armed', 'blocked',
            'checks', 'members', 'last_switch', 'contract', 'next']);
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
    $d = uu_status_doc($missing, uu_plan($missing, $st), $armed, $route);
    uu_check($t, 'status: rules missing are not loaded, their problems carried and named in the contract',
        $d['rules_loaded'] === false
        && $d['rules'] === ['state' => 'missing', 'problems' => [$problem], 'verified_at' => 1792399500]
        && $d['contract']['failures'] === ['firewall rules: ' . $problem]);
    $verifying = $s;
    $verifying['rules'] = ['state' => 'verifying', 'problems' => [], 'verified_at' => null, 'record' => null];
    $verifying['contract_input']['rules'] = ['state' => 'verifying', 'problems' => []];
    $d = uu_status_doc($verifying, uu_plan($verifying, $st), $armed, $route);
    uu_check($t, 'status: verifying is not loaded, has no time, and the contract carries the note only',
        $d['rules_loaded'] === false && $d['rules'] === ['state' => 'verifying', 'problems' => [], 'verified_at' => null]
        && $d['contract']['ok']
        && $d['contract']['notes'] === ['firewall rules are being verified (the ruleset changed)']);
    $d = uu_status_doc($s, $plan, ['armed' => false, 'fill' => true, 'blocked' => 0], $route);
    uu_check($t, 'status: a table that does not hold the resolver is not armed; its count is still the table\'s',
        $d['counter_armed'] === false && $d['blocked'] === 0);
    $d = uu_status_doc($s, $plan, ['armed' => false, 'fill' => false, 'blocked' => null], $route);
    uu_check($t, 'status: no table: not armed, no count',
        $d['counter_armed'] === false && $d['blocked'] === null);
    uu_check($t, 'status: members with tier, reading kind, verdict, health as a duration, last down, resolver-failed '
        . 'time and failures',
        $doc['members'] === [
            ['name' => 'wg-a', 'tier' => 1, 'kind' => 'settled', 'verdict' => null, 'usable' => true,
             'healthy_for' => 40979, 'healthy_for_text' => '11 h 22 min', 'last_down' => null,
             'resolver_failed_for' => null, 'probe_failures' => 1],
            ['name' => 'wg-b', 'tier' => 2, 'kind' => 'settled', 'verdict' => 'settled down', 'usable' => false,
             'healthy_for' => 0, 'healthy_for_text' => '0 s', 'last_down' => $down,
             'resolver_failed_for' => 30, 'probe_failures' => 0],
        ]);
    uu_check($t, 'status: checks, contract and the next evaluation\'s action',
        $doc['checks'] === $st['checks'] && $doc['contract'] === uu_contract($s['contract_input'])
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
        $footprint(uu_status_doc($off, uu_plan($off, $fst), $armed, $route)) === '192.0.2.1'
        && $footprint(uu_status_doc($s, uu_plan($s, $same), $armed, $route)) === null);
    $lost = $s;
    $lost['contract_input']['group_found'] = false;
    uu_check($t, '(l1) status: a footprint is named beside another enabled resolver, or a group that is gone, and '
        . 'none recorded is null',
        $footprint(uu_status_doc($s, uu_plan($s, $fst), $armed, $route)) === '192.0.2.1'
        && $footprint(uu_status_doc($lost, uu_plan($lost, $same), $armed, $route)) === $s['settings']['default']
        && $footprint($doc) === null);

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
            $doc = uu_status_doc($onB, uu_plan($onB, $stB), ['armed' => true, 'fill' => false, 'blocked' => 0],
                uu_snapshot_fixture('route_get_member.txt'));
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
    $doc = uu_status_doc($gone, uu_plan($gone, $st), ['armed' => false, 'fill' => false, 'blocked' => null], '');
    uu_check($t, 'status: Unbound not running is reported, with no blocked count and no route flags',
        $doc['unbound']['running'] === false && $doc['blocked'] === null && $doc['route']['flags'] === []
        && uu_test_reason_has($doc['next']['reasons'], 'Unbound not running'));

    return uu_tally_report('log', $t);
});
