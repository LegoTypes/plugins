<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The fail-closed view: the set, the ACL node rule, the zone classes and mirror, the file and the reconcile diff.
 * Pure functions on plain arrays.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/address.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/views.php';
require_once __DIR__ . '/scratch.php';

uu_register_suite('views', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $begin = "# Rendered by os-unbound-upstream. Do not edit.\n";
    $end = "# End of os-unbound-upstream.\n";
    $core = "server:\n    access-control: 0.0.0.0/0 allow\n    access-control: ::/0 allow\n";
    $base = [['net' => '0.0.0.0/0', 'action' => 'allow'], ['net' => '::/0', 'action' => 'allow']];
    $withBase = fn (array $more, string $v4 = 'allow'): array => [['net' => '0.0.0.0/0', 'action' => $v4],
        ['net' => '::/0', 'action' => 'allow'], ...$more];

    /* sets */
    uu_check($t, 'set: none with fallback on and nothing chosen',
        uu_try_case(fn (): bool => uu_view_set(true, [], [], []) === ['scope' => 'none', 'nets' => []]));
    uu_check($t, 'set: all is 0/0 and ::/0',
        uu_try_case(fn (): bool => uu_view_set(false, ['lan'], ['192.0.2.0/24'], [])
            === ['scope' => 'all', 'nets' => ['0.0.0.0/0', '::/0']]));
    uu_check($t, 'set: nested and duplicate nets render once',
        uu_try_case(fn (): bool => uu_view_set(true, ['lan'], ['192.0.2.0/24'], ['192.0.2.0/25', '192.0.2.0/24'])
            === ['scope' => 'selected', 'nets' => ['192.0.2.0/24']]));
    uu_check($t, 'set: sorted, IPv4 before IPv6, then address and prefix',
        uu_try_case(fn (): bool => uu_view_set(true, ['lan'], ['2001:db8:1:2::/64', '192.0.2.0/24'],
            ['100.64.0.0/10', '2001:db8:1::/48', '2001:db8:9::/48']) === ['scope' => 'selected',
            'nets' => ['100.64.0.0/10', '192.0.2.0/24', '2001:db8:1::/48', '2001:db8:9::/48']]));
    uu_check($t, 'set: a selected interface without addresses is not empty',
        uu_try_case(fn (): bool => uu_view_set(true, ['opt1'], [], []) === ['scope' => 'selected', 'nets' => []]));
    uu_check($t, 'set: a listed network alone is not empty',
        uu_try_case(fn (): bool => uu_view_set(true, [], [], ['198.51.100.0/24'])
            === ['scope' => 'selected', 'nets' => ['198.51.100.0/24']]));
    uu_check($t, 'set: a listed 0/0 is dropped',
        uu_try_case(fn (): bool => uu_view_set(true, [], [], ['0.0.0.0/0', '192.0.2.0/24'])
            === ['scope' => 'selected', 'nets' => ['192.0.2.0/24']]
            && uu_view_set(true, [], [], ['::/0']) === ['scope' => 'none', 'nets' => []]));

    /* interface nets */
    $details = ['vlan0.65' => [
        'ipv4' => [['ipaddr' => '192.0.2.1', 'subnetbits' => 24]],
        'ipv6' => [
            ['ipaddr' => 'fe80::1', 'subnetbits' => 64, 'link-local' => true],
            ['ipaddr' => '2001:db8:1:2::1', 'subnetbits' => 64, 'link-local' => false],
            ['ipaddr' => 'fd00:0:0:5::1', 'subnetbits' => 64, 'link-local' => false],
        ]], 'igc2' => [
        'ipv4' => [['ipaddr' => '198.51.100.7', 'subnetbits' => 25]],
        'ipv6' => [['ipaddr' => 'fe80::2', 'subnetbits' => 64, 'link-local' => true]]]];
    $devices = ['lan' => 'vlan0.65', 'opt1' => 'igc2', 'opt2' => 'vlan0.99'];
    uu_check($t, 'iface: fe80 excluded, networks canonical',
        uu_try_case(fn (): bool => uu_view_iface_nets($details, ['lan'], $devices)
            === ['nets' => ['192.0.2.0/24', '2001:db8:1:2::/64', 'fd00:0:0:5::/64'], 'notes' => []]));
    uu_check($t, 'iface: no IPv6 note',
        uu_try_case(fn (): bool => uu_view_iface_nets($details, ['opt1', 'opt2'], $devices)
            === ['nets' => ['198.51.100.0/25'], 'notes' => ['no IPv6 net yet for opt1', 'no IPv6 net yet for opt2']]));

    /* ACL read */
    uu_check($t, "acl: the plugin's own block is skipped",
        uu_try_case(function () use ($core, $begin, $end): bool {
            $text = $core . $begin . "server:\n    access-control: 192.0.2.0/24 allow_snoop\n" . $end
                . "    access-control-view: 198.51.100.0/24 x\n";
            $r = uu_view_acl_parse($text);
            return $r !== null && count($r['nodes']) === 2 && $r['foreign'] === ['access-control-view: 198.51.100.0/24 x'];
        }));
    uu_check($t, 'acl: a read without core\'s default lines is null',
        uu_try_case(fn (): bool => uu_view_acl_parse("server:\n    access-control: 0.0.0.0/0 allow\n") === null
            && uu_view_acl_parse("server:\n    access-control: ::/0 allow\n") === null
            && uu_view_acl_parse('') === null));
    uu_check($t, 'acl: host bits are masked',
        uu_try_case(function () use ($core): bool {
            $r = uu_view_acl_parse($core . "    access-control: 192.0.2.5/24 allow\n    access-control: 198.51.100.9 deny\n");
            return $r !== null && $r['nodes'][2] === ['net' => '192.0.2.0/24', 'action' => 'allow']
                && $r['nodes'][3] === ['net' => '198.51.100.9/32', 'action' => 'deny'];
        }));
    uu_check($t, 'acl: a duplicate netblock takes its last line',
        uu_try_case(function () use ($core): bool {
            $r = uu_view_acl_parse($core . "    access-control: 192.0.2.0/24 allow\n    access-control: 192.0.2.9/24 deny\n");
            return $r !== null && count($r['nodes']) === 3 && $r['nodes'][2] === ['net' => '192.0.2.0/24', 'action' => 'deny'];
        }));
    uu_check($t, 'acl: view and a stray view line outside the block are foreign',
        uu_try_case(function () use ($core): bool {
            $r = uu_view_acl_parse($core . "view:\n    name: \"x\"\n    access-control-view: 192.0.2.0/24 x\n");
            return $r !== null && $r['foreign'] === ['view:', 'access-control-view: 192.0.2.0/24 x'];
        }));

    /* the node rule */
    uu_check($t, 'nodes: an allow list inside a set net gets the view',
        uu_try_case(fn (): bool => uu_view_nodes(['192.0.2.0/24'], $withBase([['net' => '192.0.2.7/32', 'action' => 'allow']]))
            === ['view' => ['192.0.2.0/24', '192.0.2.7/32'], 'access' => []]));
    uu_check($t, 'nodes: a deny list inside gets nothing',
        uu_try_case(fn (): bool => uu_view_nodes(['192.0.2.0/24'], $withBase([['net' => '192.0.2.7/32', 'action' => 'deny']]))
            === ['view' => ['192.0.2.0/24'], 'access' => []]));
    uu_check($t, 'nodes: no node of its own under allow',
        uu_try_case(fn (): bool => uu_view_nodes(['192.0.2.0/24'], $base) === ['view' => ['192.0.2.0/24'], 'access' => []]));
    uu_check($t, 'nodes: under allow_snoop an access line too',
        uu_try_case(fn (): bool => uu_view_nodes(['192.0.2.0/24'], $withBase([], 'allow_snoop'))
            === ['view' => ['192.0.2.0/24'],
                'access' => [['net' => '192.0.2.0/24', 'action' => 'allow_snoop']]]));
    uu_check($t, 'nodes: under refuse nothing',
        uu_try_case(fn (): bool => uu_view_nodes(['192.0.2.0/24'], $withBase([], 'refuse')) === ['view' => [], 'access' => []]));
    uu_check($t, 'nodes: deny_non_local gets nothing',
        uu_try_case(fn (): bool => uu_view_nodes(['192.0.2.0/24'], $withBase([], 'deny_non_local'))
            === ['view' => [], 'access' => []]
            && uu_view_nodes(['192.0.2.0/24'], $withBase([], 'refuse_non_local')) === ['view' => [], 'access' => []]
            && uu_view_nodes(['192.0.2.0/24'], $withBase([], 'deny')) === ['view' => [], 'access' => []]));
    uu_check($t, 'nodes: a netblock core lists is never repeated as access-control',
        uu_try_case(fn (): bool => uu_view_nodes(['192.0.2.0/24'], $withBase([['net' => '192.0.2.0/24', 'action' => 'allow_snoop']]))
            === ['view' => ['192.0.2.0/24'], 'access' => []]));
    uu_check($t, 'nodes: the 0/0 scope attaches to core\'s defaults and every allow-type list',
        uu_try_case(fn (): bool => uu_view_nodes(['0.0.0.0/0', '::/0'], $withBase([
            ['net' => '192.0.2.0/24', 'action' => 'allow_snoop'], ['net' => '198.51.100.0/24', 'action' => 'deny'],
            ['net' => '203.0.113.0/24', 'action' => 'allow_cookie']]))
            === ['view' => ['0.0.0.0/0', '192.0.2.0/24', '203.0.113.0/24', '::/0'], 'access' => []]));
    uu_check($t, 'nodes: a core allow_snoop list at 127.0.0.0/8 under the 0/0 scope gets no view line',
        uu_try_case(fn (): bool => uu_view_nodes(['0.0.0.0/0', '::/0'], $withBase([
            ['net' => '127.0.0.0/8', 'action' => 'allow_snoop'], ['net' => '::1/128', 'action' => 'allow'],
            ['net' => '::ffff:127.0.0.1/128', 'action' => 'allow'], ['net' => '127.0.0.9/32', 'action' => 'allow']]))
            === ['view' => ['0.0.0.0/0', '::/0'], 'access' => []]));
    uu_check($t, 'nodes: a set net inside loopback gets nothing',
        uu_try_case(fn (): bool => uu_view_nodes(['127.0.0.0/8'], $base) === ['view' => [], 'access' => []]));

    uu_check($t, 'nodes: the most specific cover decides',
        uu_try_case(function () use ($base): bool {
            $refuse = [['net' => '192.0.0.0/16', 'action' => 'refuse']];
            $snoop = [['net' => '192.0.0.0/16', 'action' => 'allow_snoop']];
            $want = ['view' => ['192.0.2.0/24'], 'access' => [['net' => '192.0.2.0/24', 'action' => 'allow_snoop']]];
            $empty = ['view' => [], 'access' => []];
            return uu_view_nodes(['192.0.2.0/24'], [...$base, ...$refuse]) === $empty
                && uu_view_nodes(['192.0.2.0/24'], [...$refuse, ...$base]) === $empty
                && uu_view_nodes(['192.0.2.0/24'], [...$base, ...$snoop]) === $want
                && uu_view_nodes(['192.0.2.0/24'], [...$snoop, ...$base]) === $want;
        }));
    uu_check($t, 'acl: a quoted value is read as Unbound reads it',
        uu_try_case(function () use ($core): bool {
            $r = uu_view_acl_parse($core . "    access-control: \"192.0.2.7/32\" 'allow_snoop'\n");
            return $r !== null && $r['nodes'][2] === ['net' => '192.0.2.7/32', 'action' => 'allow_snoop'];
        }));
    uu_check($t, 'acl: an access-control line that does not parse makes the read null',
        uu_try_case(fn (): bool => uu_view_acl_parse($core . "    access-control: 192.0.2.7/32\n") === null
            && uu_view_acl_parse($core . "    access-control: not-a-net allow\n") === null
            && uu_view_acl_parse($core . "    access-control: 192.0.2.7/32 allow extra\n") === null));
    uu_check($t, 'acl: an unterminated block of the plugin makes the read null',
        uu_try_case(fn (): bool => uu_view_acl_parse($core . $begin . "server:\n    access-control: 192.0.2.0/24 allow\n")
            === null));
    uu_check($t, 'sort: byte order, not numeric order of the packed bytes',
        uu_try_case(function (): bool {
            $want = ['10.49.48.48/32', '10.50.0.0/16', '10.57.46.57/32'];
            return uu_view_net_sort(['10.57.46.57/32', '10.49.48.48/32', '10.50.0.0/16']) === $want
                && uu_view_net_sort(['10.49.48.48/32', '10.57.46.57/32', '10.50.0.0/16']) === $want
                && uu_view_net_sort(['10.50.0.0/16', '10.57.46.57/32', '10.49.48.48/32']) === $want
                && uu_view_set(true, [], [], ['10.57.46.57/32', '10.50.0.0/16', '10.49.48.48/32'])['nets'] === $want;
        }));

    /* zone lists */
    $localOut = "localhost. redirect\n127.in-addr.arpa. static\n\nexample.internal. transparent\n. transparent\n";
    uu_check($t, 'zones: a cut list keeps nothing',
        uu_try_case(function () use ($localOut): bool {
            $ok = uu_view_zone_list($localOut, "\n", "\n");
            return $ok === ['127.in-addr.arpa.' => 'static', 'example.internal.' => 'transparent', 'localhost.' => 'redirect']
                && uu_view_zone_list(null, '', '') === null && uu_view_zone_list($localOut, null, '') === null
                && uu_view_zone_list($localOut, '', null) === null
                && uu_view_zone_list("localhost. redirect\n", '', '') === null
                && uu_view_zone_list($localOut . "foo static\n", '', '') === null
                && uu_view_zone_list($localOut . "a\"b. static\n", '', '') === null
                && uu_view_zone_list($localOut . "garbage\n", '', '') === null;
        }));
    uu_check($t, 'zones: forwards and stubs join as forward and stub, the root removed',
        uu_try_case(fn (): bool => uu_view_zone_list($localOut,
            ". IN forward 192.0.2.53 198.51.100.53\nfc.example. IN forward 203.0.113.2\n",
            ". IN stub prime A.ROOT-SERVERS.NET. 192.0.2.1\nstub.example. IN stub 192.0.2.9\n")
            === ['127.in-addr.arpa.' => 'static', 'example.internal.' => 'transparent', 'fc.example.' => 'forward',
                'localhost.' => 'redirect', 'stub.example.' => 'stub']));
    uu_check($t, 'zones: a forward line of another shape is null',
        uu_try_case(fn (): bool => uu_view_zone_list($localOut, "fc.example. forward 203.0.113.2\n", '') === null));
    uu_check($t, 'zone_ok: the name shape',
        uu_try_case(fn (): bool => uu_view_zone_ok('example.internal.') && uu_view_zone_ok('a\\.b.')
            && !uu_view_zone_ok('example') && !uu_view_zone_ok('.') && !uu_view_zone_ok('')
            && !uu_view_zone_ok('a b.') && !uu_view_zone_ok('a"b.') && !uu_view_zone_ok("a\tb.")
            && !uu_view_zone_ok("a\x01b.") && !uu_view_zone_ok("caf\xc3\xa9.")
            && uu_view_zone_ok(str_repeat('a', 254) . '.') && !uu_view_zone_ok(str_repeat('a', 255) . '.')));
    foreach (['static' => 'noview', 'redirect' => 'noview', 'deny' => 'noview', 'refuse' => 'noview',
        'always_refuse' => 'noview', 'always_nxdomain' => 'noview', 'always_nodata' => 'noview',
        'always_deny' => 'noview', 'always_null' => 'noview', 'forward' => 'noview', 'stub' => 'noview',
        'transparent' => 'static', 'inform' => 'static', 'typetransparent' => 'refuse',
        'always_transparent' => 'refuse', 'inform_deny' => 'refuse', 'nonsense' => 'refuse'] as $type => $class) {
        uu_check($t, sprintf('class: %s is %s', $type, $class),
            uu_try_case(fn (): bool => uu_view_zone_class($type) === $class));
    }
    uu_check($t, 'parse_list: name and type per line, a line of another shape is null',
        uu_try_case(fn (): bool => uu_view_parse_list(". refuse\nexample.internal. static\n\n")
            === ['.' => 'refuse', 'example.internal.' => 'static']
            && uu_view_parse_list("") === [] && uu_view_parse_list("a b c\n") === null
            && uu_view_parse_list("lonely\n") === null));

    /* local data */
    $rec = 'nas.example.internal. 3600 IN A 192.0.2.10';
    uu_check($t, 'data: records collapse, sort and drop blank lines',
        uu_try_case(fn (): bool => uu_view_data_list("b.example.internal.\t60\tIN\tA\t192.0.2.2\n\n"
                . "a.example.internal.  3600  IN  AAAA  2001:db8::1\n" . "b.example.internal.\t60\tIN\tA\t192.0.2.2\n")
            === ['a.example.internal. 3600 IN AAAA 2001:db8::1', 'b.example.internal. 60 IN A 192.0.2.2']
            && uu_view_data_list('') === []));
    uu_check($t, 'data: a record line of another shape is null',
        uu_try_case(fn (): bool => uu_view_data_list(null) === null && uu_view_data_list("nas.example.internal. 3600\n") === null
            && uu_view_data_list("nas 3600 IN A 192.0.2.10\n") === null
            && uu_view_data_list("a.example. 60 IN TXT \"x\"\n") === null
            && uu_view_data_list("a.example. x IN A 192.0.2.10\n") === null));
    uu_check($t, 'mirror: a record goes to its closest zone',
        uu_try_case(function () use ($rec): bool {
            $zones = ['example.internal.' => 'transparent', 'sub.example.internal.' => 'static', 'localhost.' => 'redirect'];
            $m = uu_view_mirror($zones, [$rec, 'x.sub.example.internal. 60 IN A 192.0.2.3',
                'EXAMPLE.internal. 60 IN A 192.0.2.4', 'other.test. 60 IN A 192.0.2.5']);
            return $m === ['example.internal.' => [$rec, 'EXAMPLE.internal. 60 IN A 192.0.2.4']];
        }));
    uu_check($t, 'mirror: a mirrored zone without records is listed empty',
        uu_try_case(fn (): bool => uu_view_mirror(['example.internal.' => 'transparent', 'a.' => 'static'], [])
            === ['example.internal.' => []]));

    /* the file */
    uu_check($t, 'render: the spec\'s file byte for byte',
        uu_try_case(function () use ($rec): bool {
            $nodes = ['view' => ['100.64.0.0/10', '192.0.2.0/24', '2001:db8:1:2::/64'], 'access' => []];
            $zones = ['168.192.in-addr.arpa.' => 'static', 'example.internal.' => 'transparent', 'localhost.' => 'redirect',
                '127.in-addr.arpa.' => 'static'];
            $want = "# Rendered by os-unbound-upstream. Do not edit.\n"
                . "server:\n"
                . "    access-control-view: 100.64.0.0/10 unboundupstream\n"
                . "    access-control-view: 192.0.2.0/24 unboundupstream\n"
                . "    access-control-view: 2001:db8:1:2::/64 unboundupstream\n"
                . "view:\n"
                . "    name: \"unboundupstream\"\n"
                . "    view-first: yes\n"
                . "    local-zone: \".\" refuse\n"
                . "    local-zone: \"127.in-addr.arpa.\" noview\n"
                . "    local-zone: \"168.192.in-addr.arpa.\" noview\n"
                . "    local-zone: \"example.internal.\" static\n"
                . "    local-data: \"nas.example.internal. 3600 IN A 192.0.2.10\"\n"
                . "    local-zone: \"localhost.\" noview\n"
                . "# End of os-unbound-upstream.\n";
            return uu_view_render($nodes, $zones, ['example.internal.' => [$rec]]) === $want;
        }));
    uu_check($t, 'render: access lines come before the view lines',
        uu_try_case(function (): bool {
            $text = uu_view_render(['view' => ['192.0.2.0/24'], 'access' => [['net' => '192.0.2.0/24', 'action' => 'allow_snoop']]], [], []);
            return str_contains($text, "server:\n    access-control: 192.0.2.0/24 allow_snoop\n"
                . "    access-control-view: 192.0.2.0/24 unboundupstream\nview:\n")
                && str_ends_with($text, "    local-zone: \".\" refuse\n# End of os-unbound-upstream.\n");
        }));
    uu_check($t, 'node_lines: the access-control and access-control-view lines as written',
        uu_try_case(function (): bool {
            $text = uu_view_render(['view' => ['192.0.2.0/24'], 'access' => [['net' => '192.0.2.0/24', 'action' => 'allow_snoop']]], [], []);
            return uu_view_node_lines($text) === ['    access-control: 192.0.2.0/24 allow_snoop',
                    '    access-control-view: 192.0.2.0/24 unboundupstream'] && uu_view_node_lines(null) === [];
        }));
    uu_check($t, 'block: the plugin\'s block with its markers, null when absent',
        uu_try_case(function () use ($core, $begin, $end): bool {
            $file = $begin . "server:\n    access-control-view: 192.0.2.0/24 unboundupstream\n" . $end;
            return uu_view_block($core . $file . "forward-zone:\n") === $file && uu_view_block($core) === null
                && uu_view_block($core . $begin . "server:\n") === null;
        }));

    /* wanted and reconcile */
    $zones = ['example.internal.' => 'transparent', 'localhost.' => 'redirect', 'pt.' => 'typetransparent'];
    $mirror = ['example.internal.' => ['nas.example.internal. 3600 IN A 192.0.2.10'], 'pt.' => []];
    uu_check($t, 'wanted: armed sets the root refuse and each mirrored zone its class',
        uu_try_case(fn (): bool => uu_view_wanted($zones, $mirror, true) === ['zones' => ['.' => 'refuse',
            'example.internal.' => 'static', 'localhost.' => 'noview', 'pt.' => 'refuse'],
            'data' => ['nas.example.internal. 3600 IN A 192.0.2.10']]));
    uu_check($t, 'wanted: lifted sets mirrored zones noview and drops the root',
        uu_try_case(fn (): bool => uu_view_wanted($zones, $mirror, false) === ['zones' => [
            'example.internal.' => 'noview', 'localhost.' => 'noview', 'pt.' => 'noview'],
            'data' => ['nas.example.internal. 3600 IN A 192.0.2.10']]));
    uu_check($t, 'reconcile: adds, retypes and removes, never the root',
        uu_try_case(function (): bool {
            $wanted = ['zones' => ['.' => 'refuse', 'a.' => 'static', 'b.' => 'noview', 'c.' => 'refuse'], 'data' => [
                'h.a. 60 IN A 192.0.2.1']];
            $loaded = ['.' => 'noview', 'b.' => 'noview', 'c.' => 'static', 'gone.' => 'noview'];
            return uu_view_reconcile($loaded, ['h.a. 60 IN A 192.0.2.1'], $wanted)
                === ['set' => ['a.' => 'static', 'c.' => 'refuse'], 'remove' => ['gone.'], 'data_add' => [],
                    'data_remove' => []]
                && uu_view_reconcile(['.' => 'refuse'], [], ['zones' => [], 'data' => []])
                === ['set' => [], 'remove' => [], 'data_add' => [], 'data_remove' => []]
                && uu_view_reconcile(['.' => 'refuse', 'x.' => 'noview'], [], ['zones' => ['.' => 'refuse'], 'data' => []])
                === ['set' => [], 'remove' => ['x.'], 'data_add' => [], 'data_remove' => []]
                && uu_view_reconcile([], [], $wanted)['set'] === ['a.' => 'static', 'b.' => 'noview', 'c.' => 'refuse'];
        }));
    uu_check($t, 'reconcile: records added, and a record that went away removes its name',
        uu_try_case(fn (): bool => uu_view_reconcile(['.' => 'refuse'], ['old.a. 60 IN A 192.0.2.8'],
            ['zones' => ['.' => 'refuse'], 'data' => ['new.a. 60 IN A 192.0.2.9']])
            === ['set' => [], 'remove' => [], 'data_add' => ['new.a. 60 IN A 192.0.2.9'], 'data_remove' => ['old.a.']]));
    uu_check($t, 'render: a zone named the root is never written',
        uu_try_case(fn (): bool => substr_count(uu_view_render(['view' => [], 'access' => []],
            ['.' => 'transparent', 'a.' => 'static'], []), 'local-zone: "."') === 1));
    uu_check($t, 'reconcile: owners match without regard to case',
        uu_try_case(fn (): bool => uu_view_reconcile(['.' => 'refuse'], ['H.a. 60 IN A 192.0.2.1', 'h.A. 60 IN A 192.0.2.2'],
            ['zones' => ['.' => 'refuse'], 'data' => ['h.A. 60 IN A 192.0.2.2']])
            === ['set' => [], 'remove' => [], 'data_add' => ['h.A. 60 IN A 192.0.2.2'], 'data_remove' => ['h.a.']]));
    uu_check($t, 'reconcile: a name losing one of two records gets the other back',
        uu_try_case(fn (): bool => uu_view_reconcile(['.' => 'refuse'],
            ['h.a. 60 IN A 192.0.2.1', 'h.a. 60 IN A 192.0.2.2', 'k.a. 60 IN A 192.0.2.3'],
            ['zones' => ['.' => 'refuse'], 'data' => ['h.a. 60 IN A 192.0.2.1', 'k.a. 60 IN A 192.0.2.3']])
            === ['set' => [], 'remove' => [], 'data_add' => ['h.a. 60 IN A 192.0.2.1'], 'data_remove' => ['h.a.']]));

    return uu_tally_report('views', $t);
});
