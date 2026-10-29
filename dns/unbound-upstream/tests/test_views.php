<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The fail-closed view: the set, the ACL node rule, the zone classes and mirror, the file and the reconcile diff, and
 * the file step: what it decides, and what it records once carried out through a recording Io. Pure functions on plain
 * arrays.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/address.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/views.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/planner.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/apply.php';
require_once __DIR__ . '/scratch.php';

uu_register_suite('views', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $begin = "# Rendered by os-unbound-upstream. Do not edit.\n";
    $end = "# End of os-unbound-upstream.\n";
    $core = "server:\n    access-control: 0.0.0.0/0 allow\n    access-control: ::/0 allow\n";
    $base = [['net' => '0.0.0.0/0', 'action' => 'allow'], ['net' => '::/0', 'action' => 'allow']];
    $withBase = fn (array $more, string $v4 = 'allow'): array => [['net' => '0.0.0.0/0', 'action' => $v4],
        ['net' => '::/0', 'action' => 'allow'], ...$more];

    uu_check($t, 'nodes: a core list inside the mapped loopback /104 gets no view line under the 0/0 scope',
        uu_try_case(fn (): bool => uu_view_nodes(['0.0.0.0/0', '::/0'], $withBase([
            ['net' => '::ffff:127.0.0.5/128', 'action' => 'allow']]))
            === ['view' => ['0.0.0.0/0', '::/0'], 'access' => []]));

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
    uu_check($t, 'parse_list: the daemon\'s error reply is no zone list, though its two words fit the shape',
        uu_try_case(fn (): bool => uu_view_parse_list("error failed\n") === null
            && uu_view_parse_list("error unknown command 'view_list_local_zones'\n") === null
            && uu_view_parse_list("errors.example. static\n") === ['errors.example.' => 'static']));

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
            && uu_view_data_list("a.example. 60 IN TXT \"x\n") === null
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

    /* TXT and other quoted local data */
    uu_check($t, 'data: a TXT record keeps its quoted text byte for byte, white space outside it collapsed',
        uu_try_case(fn (): bool => uu_view_data_list("txt.example.internal.\t3600\tIN\tTXT\t\"v=spf1  -all\" \"two\\\"q\"\n"
                . "\napo.example.internal.\t3600\tIN\tTXT\t\"it's\"\n")
            === ['apo.example.internal. 3600 IN TXT "it\'s"',
                 'txt.example.internal. 3600 IN TXT "v=spf1  -all" "two\\"q"']));
    uu_check($t, 'record line: double quotes, single quotes around a double quote, none for both quotes or a byte '
        . 'that is not printable',
        uu_try_case(fn (): bool => uu_view_record_line('a.example. 60 IN A 192.0.2.1')
                === '    local-data: "a.example. 60 IN A 192.0.2.1"'
            && uu_view_record_line("it's.example. 60 IN A 192.0.2.1") === "    local-data: \"it's.example. 60 IN A 192.0.2.1\""
            && uu_view_record_line('t.example. 60 IN TXT "a  b" "c\\"d"')
                === "    local-data: 't.example. 60 IN TXT \"a  b\" \"c\\\"d\"'"
            && uu_view_record_line('t.example. 60 IN TXT "it\'s"') === null
            && uu_view_record_line("t.example. 60 IN TXT \"caf\xc3\xa9\"") === null));
    uu_check($t, 'render: a TXT record is written in single quotes; one with both quotes is left out and counted',
        uu_try_case(function () use ($base): bool {
            $zones = ['example.internal.' => 'transparent', 'localhost.' => 'redirect'];
            $records = ['apo.example.internal. 3600 IN TXT "it\'s"', 'nas.example.internal. 3600 IN A 192.0.2.10',
                'txt.example.internal. 3600 IN TXT "v=spf1  -all"'];
            $mirror = uu_view_mirror($zones, $records);
            $text = uu_view_render(uu_view_nodes(['192.0.2.0/24'], $base), $zones, $mirror);
            return str_contains($text, "    local-zone: \"example.internal.\" static\n"
                    . "    local-data: \"nas.example.internal. 3600 IN A 192.0.2.10\"\n"
                    . "    local-data: 'txt.example.internal. 3600 IN TXT \"v=spf1  -all\"'\n")
                && !str_contains($text, 'apo.example.internal.') && uu_view_text_ok($text)
                && uu_view_unwritable($mirror) === ['apo.example.internal. 3600 IN TXT "it\'s"'];
        }));

    /* the file step: the view as the snapshot read it, the planner's view share, the record apply left, and what the
     * step decides */
    $fsZones = ['127.in-addr.arpa.' => 'static', 'example.internal.' => 'transparent', 'localhost.' => 'redirect'];
    $fsData = ['nas.example.internal. 3600 IN A 192.0.2.10'];
    $fsFile = fn (array $nets, array $zones = [], array $data = []): string => uu_view_render(uu_view_nodes($nets, $base),
        $zones === [] ? $fsZones : $zones, uu_view_mirror($zones === [] ? $fsZones : $zones, $data === [] ? $fsData : $data));
    $fsView = function (array $over = []) use ($base, $fsZones, $fsData): array {
        $v = array_merge(['scope' => 'selected', 'nets' => ['192.0.2.0/24'], 'notes' => [],
            'acl' => ['nodes' => $base, 'foreign' => []], 'zones' => $fsZones, 'data' => $fsData, 'loaded' => 'zones',
            'view_zones' => ['.' => 'refuse'], 'view_data' => [], 'file' => null, 'copy' => null], $over);
        $v['file_present'] = $over['file_present'] ?? $v['file'] !== null;
        return $v;
    };
    $fsPlan = fn (array $over = []): array => array_merge(['active' => true, 'armed' => true, 'keep' => false,
        'zones' => $fsZones, 'mirror' => [], 'problem' => null], $over);
    $fsRecord = fn (string $refuse = 'lifted', ?string $problem = null, ?string $restarted = null,
        array $nets = ['192.0.2.0/24'], string $scope = 'selected', int $unwritable = 0): array => ['refuse' => $refuse,
        'scope' => $scope, 'nets' => $nets, 'problem' => $problem, 'restarted' => $restarted,
        'unwritable' => $unwritable];
    /* the step with the defaults of a staying run: Unbound running and enabled, no dry run, no stop, no removal, no
     * cacheflush */
    $fsStep = fn (array $view, array $plan, array $record, array $flags = []): array => uu_view_file_step($view, $plan,
        $record, $flags['mode'] ?? 'fallback', $flags['running'] ?? true, $flags['enabled'] ?? true,
        $flags['dry'] ?? false, $flags['stopping'] ?? false, $flags['removal'] ?? false, $flags['cacheflush'] ?? false);
    $fsHash = fn (?string $file): string => hash('sha256', implode("\n", uu_view_node_lines($file)));
    $one = $fsFile(['192.0.2.0/24']);
    $two = $fsFile(['192.0.2.0/24', '198.51.100.0/24']);
    $three = $fsFile(['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24']);
    $nets2 = ['192.0.2.0/24', '198.51.100.0/24'];
    $none = fn (array $step): bool => $step['write'] === null && !$step['delete'] && !$step['restart']
        && $step['line'] === null;
    $line = 'fail closed: the refused nets changed (192.0.2.0/24 -> 192.0.2.0/24, 198.51.100.0/24): restarting Unbound';

    uu_check($t, 'file step: unchanged nets never restart',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsStep, $fsFile, $one, $none): bool {
            $more = ['127.in-addr.arpa.' => 'static', 'example.internal.' => 'transparent', 'localhost.' => 'redirect',
                'other.internal.' => 'static'];
            $want = $fsFile(['192.0.2.0/24'], $more);
            $r = $fsStep($fsView(['zones' => $more, 'file' => $one, 'copy' => $one]), $fsPlan(), $fsRecord());
            return $want !== $one && $r === ['write' => $want, 'delete' => false, 'restart' => false, 'line' => null,
                    'record' => $fsRecord()]
                && $none($fsStep($fsView(['file' => $one, 'copy' => $one]), $fsPlan(), $fsRecord()));
        }));
    uu_check($t, 'file step: a nets change restarts once',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsStep, $fsHash, $one, $two, $nets2, $line): bool {
            $first = $fsStep($fsView(['nets' => $nets2, 'file' => $one, 'copy' => $one]), $fsPlan(), $fsRecord());
            $flush = $fsStep($fsView(['nets' => $nets2, 'file' => $one, 'copy' => $one]), $fsPlan(), $fsRecord(),
                ['cacheflush' => true]);
            /* the restart's start copies the file: the next run finds the copy equal and the file current */
            $next = $fsStep($fsView(['nets' => $nets2, 'file' => $two, 'copy' => $two]), $fsPlan(), $first['record']);
            return $first === ['write' => $two, 'delete' => false, 'restart' => true, 'line' => $line,
                    'record' => $fsRecord('armed', null, $fsHash($two), $nets2)]
                && $flush['line'] === $line . '; the cache is flushed (cacheflush is on)'
                && $next === ['write' => null, 'delete' => false, 'restart' => false, 'line' => null,
                    'record' => $fsRecord('armed', null, null, $nets2)];
        }));
    uu_check($t, 'file step: the same file and copy twice restart once; the start that did not load the file is '
        . 'reported; a change of the node lines restarts again; the copy that holds them clears it',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsStep, $fsHash, $one, $two, $three, $nets2): bool {
            $first = $fsStep($fsView(['nets' => $nets2, 'file' => $one, 'copy' => $one]), $fsPlan(), $fsRecord());
            /* the restart ran and the file was installed, but Unbound's copy is still the old one */
            $again = $fsStep($fsView(['nets' => $nets2, 'file' => $two, 'copy' => $one]), $fsPlan(), $first['record']);
            $changed = $fsStep($fsView(['nets' => ['192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24'],
                'file' => $two, 'copy' => $one]), $fsPlan(), $again['record']);
            $loaded = $fsStep($fsView(['nets' => $nets2, 'file' => $two, 'copy' => $two]), $fsPlan(), $again['record']);
            return $first['restart'] && $first['record']['restarted'] === $fsHash($two)
                && $again === ['write' => null, 'delete' => false, 'restart' => false, 'line' => null,
                    'record' => $fsRecord('armed', UU_VIEW_NOT_LOADED, $fsHash($two), $nets2)]
                && $changed['restart'] && $changed['write'] === $three
                && $changed['record']['restarted'] === $fsHash($three) && $changed['record']['problem'] === null
                && $loaded['record'] === $fsRecord('armed', null, null, $nets2) && !$loaded['restart'];
        }));
    uu_check($t, 'file step: no restart while Unbound is not running (and not enabled)',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsStep, $one, $two, $nets2, $none): bool {
            $v = $fsView(['nets' => $nets2, 'file' => $one, 'copy' => $one]);
            $stopped = $fsStep($v, $fsPlan(), $fsRecord(), ['running' => false]);
            $disabled = $fsStep($v, $fsPlan(), $fsRecord(), ['enabled' => false]);
            return $none($stopped) && $stopped['record'] === $fsRecord()
                && $disabled['write'] === $two && !$disabled['restart'] && $disabled['line'] === null
                && $disabled['record'] === $fsRecord('lifted', null, null, $nets2);
        }));
    uu_check($t, 'file step: an unreadable zone list keeps the file (and an ACL read without core\'s defaults, and a '
        . 'cut list_local_data)',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsStep, $one, $nets2, $none): bool {
            $step = fn (array $over): array => $fsStep($fsView(array_merge(['nets' => $nets2, 'file' => $one,
                'copy' => $one], $over)), $fsPlan(), $fsRecord());
            $kept = fn (array $over, string $what): bool => $none($step($over)) && $step($over)['record']
                === $fsRecord('lifted', "Fail closed: the view file was kept ($what could not be read)");
            $acl = uu_view_acl_parse("server:\n    access-control: 0.0.0.0/0 allow\n");
            $data = uu_view_data_list("nas.example.internal. 3600\n");
            return $acl === null && $data === null
                && $kept(['zones' => null], "Unbound's local zones")
                && $kept(['acl' => $acl], "Unbound's access-control lines")
                && $kept(['data' => $data], "Unbound's local data")
                && $kept(['acl' => null, 'zones' => null, 'data' => null],
                    "Unbound's access-control lines, local zones and local data");
        }));
    uu_check($t, 'file step: a rendered file larger than the plugin reads back is never written',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsStep, $one, $none): bool {
            $data = [];
            for ($i = 0, $bytes = 0; $bytes <= UU_FILE_MAX_BYTES; $i++) {
                $data[] = sprintf('h%05d.example.internal. 3600 IN A 192.0.2.%d', $i, $i % 250 + 1);
                $bytes += strlen(end($data));
            }
            $r = $fsStep($fsView(['data' => $data, 'file' => $one, 'copy' => $one]), $fsPlan(), $fsRecord());
            return $none($r)
                && $r['record'] === $fsRecord('lifted', 'Fail closed: the view file was kept (the rendered file is '
                    . 'larger than 1 MiB)');
        }));
    uu_check($t, 'file step: an empty set deletes the file, and restarts Unbound only while a copy with node lines is '
        . 'loaded, once',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsStep, $fsFile, $one): bool {
            $empty = ['scope' => 'none', 'nets' => []];
            $lifted = $fsPlan(['active' => false, 'armed' => false]);
            $gone = $fsStep($fsView($empty + ['file' => $one, 'copy' => $one]), $lifted, $fsRecord());
            $copyOnly = $fsStep($fsView($empty + ['copy' => $one]), $lifted, $fsRecord());
            /* the restart did not drop the copy: reported, not repeated */
            $again = $fsStep($fsView($empty + ['copy' => $one]), $lifted, $gone['record']);
            $noNodes = $fsFile([]);
            $nodeless = $fsStep($fsView($empty + ['file' => $noNodes, 'copy' => $noNodes]), $lifted, $fsRecord());
            $clean = $fsStep($fsView($empty + ['loaded' => 'skipped', 'zones' => null, 'data' => null]),
                $fsPlan(['active' => false, 'armed' => null]), $fsRecord('none', null, null, [], 'none'));
            $unreadable = $fsStep($fsView($empty + ['file_present' => true]), $lifted, $fsRecord());
            $noneRecord = $fsRecord('none', null, null, [], 'none');
            $restarted = $fsRecord('none', null, hash('sha256', ''), [], 'none');
            return $gone === ['write' => null, 'delete' => true, 'restart' => true,
                    'line' => 'fail closed: the refused nets changed (192.0.2.0/24 -> none): restarting Unbound',
                    'record' => $restarted]
                && !$copyOnly['delete'] && $copyOnly['restart'] && $copyOnly['record'] === $restarted
                && !$again['delete'] && !$again['restart']
                && $again['record'] === $fsRecord('none', UU_VIEW_NOT_DROPPED, hash('sha256', ''), [], 'none')
                && uu_view_node_lines($noNodes) === [] && $nodeless['delete'] && !$nodeless['restart']
                && $nodeless['record'] === $noneRecord
                && $clean === ['write' => null, 'delete' => false, 'restart' => false, 'line' => null,
                    'record' => $noneRecord]
                && $unreadable['delete'] && !$unreadable['restart'] && $unreadable['record'] === $noneRecord;
        }));
    uu_check($t, 'file step: the delete waits while the live view may still refuse, and goes once a read shows it does '
        . 'not or Unbound is down',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsStep, $one, $none): bool {
            $v = fn (array $over = []): array => $fsView(array_merge(['scope' => 'none', 'nets' => [], 'file' => $one,
                'copy' => $one], $over));
            $stuck = 'Fail closed stuck: no answer';
            $noneRecord = $fsRecord('none', null, null, [], 'none');
            /* a lift that failed this run: the read showed the refuse, apply recorded it */
            $failed = $fsStep($v(), $fsPlan(['active' => false]), $fsRecord('armed', $stuck));
            /* a running Unbound did not answer: the record decides */
            $silent = $fsStep($v(['loaded' => 'silent', 'zones' => null, 'data' => null]),
                $fsPlan(['active' => false, 'armed' => null]), $fsRecord('armed', $stuck));
            /* Unbound is down: no live view to lift, the delete is the lift (its next start loads no view) */
            $down = $fsStep($v(['loaded' => 'skipped', 'zones' => null, 'data' => null]),
                $fsPlan(['active' => false, 'armed' => null]), $fsRecord('armed'), ['running' => false]);
            /* a record of armed that the read contradicts: the view without ".", or no view loaded */
            $without = $fsStep($v(['view_zones' => ['localhost.' => 'noview']]),
                $fsPlan(['active' => false, 'armed' => false]), $fsRecord('armed'));
            $absent = $fsStep($v(['loaded' => 'absent', 'view_zones' => []]),
                $fsPlan(['active' => false, 'armed' => null]), $fsRecord('armed'));
            /* a removal whose lift took: the read before apply was armed, the record is lifted */
            $removal = $fsStep($v(['scope' => 'selected', 'nets' => ['192.0.2.0/24']]), $fsPlan(),
                $fsRecord('lifted'), ['stopping' => true]);
            return $none($failed) && $failed['record'] === $fsRecord('armed', $stuck, null, ['192.0.2.0/24'], 'none')
                && $none($silent) && $silent['record']['refuse'] === 'armed'
                && $down['delete'] && !$down['restart'] && $down['record'] === $noneRecord
                && $without['delete'] && $without['restart']
                && $without['record'] === $fsRecord('none', null, hash('sha256', ''), [], 'none')
                && $absent['delete'] && $absent['restart']
                && $absent['record'] === $fsRecord('none', null, hash('sha256', ''), [], 'none')
                && $removal['delete'] && $removal['restart']
                && $removal['record'] === $fsRecord('none', null, hash('sha256', ''), []);
        }));
    uu_check($t, 'file step: a stop that could not restore keeps the file in place',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsStep, $one, $none): bool {
            $v = $fsView(['file' => $one, 'copy' => $one]);
            $kept = $fsStep($v, $fsPlan(['armed' => false]), $fsRecord(), ['stopping' => true, 'mode' => 'tunnel']);
            $done = $fsStep($v, $fsPlan(['armed' => false]), $fsRecord(), ['stopping' => true]);
            return $none($kept) && $kept['record'] === $fsRecord()
                && $done['delete'] && $done['restart']
                && $done['record'] === $fsRecord('none', null, hash('sha256', ''), []);
        }));
    uu_check($t, 'file step: an upgrade stop keeps the file (and a removing tick)',
        uu_try_case(function () use ($fsView, $fsRecord, $fsStep, $one, $none): bool {
            $v = $fsView(['file' => $one, 'copy' => $one]);
            $st = ['view' => $fsRecord('armed')];
            $plan = fn (?string $stop, bool $upgrade): array => uu_plan_view(['stop' => $stop, 'upgrade' => $upgrade,
                'view' => $v]);
            $fault = 'Fail closed: the view file was kept (x)';
            $step = fn (?string $stop, bool $upgrade): array => $fsStep($v, $plan($stop, $upgrade),
                $fsRecord('armed', $fault), ['stopping' => true]);
            return $plan(UU_STOP_REMOVE, true)['keep'] && $plan(UU_STOP_REMOVING, false)['keep']
                && !$plan(UU_STOP_REMOVE, false)['keep']
                && $none($step(UU_STOP_REMOVE, true)) && $step(UU_STOP_REMOVE, true)['record'] === $fsRecord('armed', $fault)
                && $none($step(UU_STOP_REMOVING, false))
                && $step(UU_STOP_REMOVING, false)['record'] === $fsRecord('armed', $fault);
        }));
    uu_check($t, 'file step: Unbound not running keeps the file',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsStep, $one, $none): bool {
            /* the planner's stop action for Unbound not running has no stop reason: it is no stop of the plugin */
            $stopping = uu_plan_stop_reason(['settings' => ['enabled' => true], 'stop' => null]) !== null;
            $v = $fsView(['nets' => ['198.51.100.0/24'], 'loaded' => 'skipped', 'zones' => null, 'data' => null,
                'file' => $one, 'copy' => $one]);
            $r = $fsStep($v, $fsPlan(['active' => false, 'armed' => null]), $fsRecord(),
                ['running' => false, 'stopping' => $stopping]);
            return !$stopping && $none($r) && $r['record'] === $fsRecord();
        }));
    uu_check($t, 'file step: a foreign view line writes nothing',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsStep, $one): bool {
            $why = UU_VIEW_FOREIGN . 'view:';
            $acl = ['nodes' => [['net' => '0.0.0.0/0', 'action' => 'allow'], ['net' => '::/0', 'action' => 'allow']],
                'foreign' => ['view:']];
            $was = $fsStep($fsView(['acl' => $acl, 'file' => $one, 'copy' => $one]), $fsPlan(['problem' => $why]),
                $fsRecord());
            $never = $fsStep($fsView(['acl' => $acl]), $fsPlan(['problem' => $why]), $fsRecord());
            $unsupported = $fsStep($fsView(['loaded' => 'unsupported', 'file' => $one]),
                $fsPlan(['problem' => UU_VIEW_UNSUPPORTED]), $fsRecord());
            return $was['write'] === null && $was['delete'] && $was['restart']
                && $was['record'] === $fsRecord('none', $why, hash('sha256', ''), [])
                && $never === ['write' => null, 'delete' => false, 'restart' => false, 'line' => null,
                    'record' => $fsRecord('lifted', $why, null, [])]
                && $unsupported['write'] === null && $unsupported['delete'] && !$unsupported['restart']
                && $unsupported['record']['problem'] === UU_VIEW_UNSUPPORTED;
        }));
    uu_check($t, 'file step: a selected interface without addresses keeps the file',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsStep, $one, $none): bool {
            $r = $fsStep($fsView(['nets' => [], 'notes' => ['no IPv6 net yet for opt1'], 'file' => $one,
                'copy' => $one]), $fsPlan(), $fsRecord());
            return $none($r) && $r['record'] === $fsRecord();
        }));
    uu_check($t, 'file step: dry run writes nothing',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsStep, $one, $nets2): bool {
            $change = $fsStep($fsView(['nets' => $nets2, 'file' => $one, 'copy' => $one]), $fsPlan(), $fsRecord(),
                ['dry' => true]);
            $empty = $fsStep($fsView(['scope' => 'none', 'nets' => [], 'file' => $one, 'copy' => $one]),
                $fsPlan(['active' => false, 'armed' => false]), $fsRecord(), ['dry' => true]);
            return $change === ['write' => null, 'delete' => false, 'restart' => false,
                    'line' => '[dry] fail closed: would write the view file; the refused nets changed (192.0.2.0/24 '
                        . '-> 192.0.2.0/24, 198.51.100.0/24): would restart Unbound', 'record' => $fsRecord()]
                && $empty === ['write' => null, 'delete' => false, 'restart' => false,
                    'line' => '[dry] fail closed: would delete the view file; the refused nets changed '
                        . '(192.0.2.0/24 -> none): would restart Unbound',
                    'record' => $fsRecord('lifted', null, null, ['192.0.2.0/24'], 'none')];
        }));
    uu_check($t, 'file step: a restart that loads a written file is the remedy for "restart Unbound to load the view"',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsStep, $one): bool {
            $v = $fsView(['loaded' => 'absent', 'view_zones' => [], 'file' => $one]);
            $plan = $fsPlan(['active' => false, 'armed' => null, 'problem' => UU_VIEW_UNLOADED]);
            $r = $fsStep($v, $plan, $fsRecord());
            $disabled = $fsStep($v, $plan, $fsRecord(), ['enabled' => false]);
            return $r['restart'] && $r['write'] === null && $r['record']['problem'] === null
                && $r['record']['refuse'] === 'armed'
                && !$disabled['restart'] && $disabled['record']['problem'] === UU_VIEW_UNLOADED;
        }));
    uu_check($t, 'file step: the planner\'s reasons last as long as the plan gives them; apply\'s faults stand',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsStep, $one): bool {
            $v = $fsView(['file' => $one, 'copy' => $one]);
            $stale = [UU_VIEW_UNSUPPORTED, UU_VIEW_FOREIGN . 'view:', UU_VIEW_UNLOADED, UU_VIEW_NOT_LOADED,
                'Fail closed: the view file was kept (x)'];
            $cleared = array_filter($stale, fn (string $p): bool => $fsStep($v, $fsPlan(), $fsRecord('lifted', $p))
                ['record']['problem'] !== null);
            $kept = array_filter(['Fail closed stuck: no answer', 'Fail closed not armed: error failed'],
                fn (string $p): bool => $fsStep($v, $fsPlan(), $fsRecord('lifted', $p))['record']['problem'] === $p);
            /* with nothing to arm and nothing on disk, nothing is left to report either */
            $empty = $fsStep($fsView(['scope' => 'none', 'nets' => [], 'loaded' => 'skipped']),
                $fsPlan(['active' => false, 'armed' => null]), $fsRecord('lifted', UU_VIEW_FOREIGN . 'view:'));
            return $cleared === [] && count($kept) === 2 && $empty['record']['problem'] === null;
        }));
    uu_check($t, 'file step: a record the file cannot carry is left to the reconcile and counted, never a problem',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsStep, $one): bool {
            $data = ['nas.example.internal. 3600 IN A 192.0.2.10', 'q.example.internal. 3600 IN TXT "it\'s"',
                't.example.internal. 3600 IN TXT "v=spf1 -all"'];
            $r = $fsStep($fsView(['data' => $data, 'file' => $one, 'copy' => $one]), $fsPlan(), $fsRecord());
            /* the next tick: the file holds what it can, the count stands */
            $next = $fsStep($fsView(['data' => $data, 'file' => $r['write'], 'copy' => $one]), $fsPlan(),
                $r['record']);
            /* the set emptied: no file, nothing to count */
            $gone = $fsStep($fsView(['scope' => 'none', 'nets' => [], 'data' => $data, 'file' => $r['write'],
                'copy' => $one]), $fsPlan(['active' => false, 'armed' => false]), $r['record']);
            return $r['write'] !== null && !$r['restart'] && str_contains($r['write'], "local-data: 't.example.internal.")
                && !str_contains($r['write'], 'q.example.internal.')
                && $r['record'] === $fsRecord('lifted', null, null, ['192.0.2.0/24'], 'selected', 1)
                && $next['write'] === null && $next['record'] === $r['record']
                && $gone['delete'] && $gone['record']['unwritable'] === 0;
        }));
    uu_check($t, 'file step: a stuck fault with one unwritable record stays the problem',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsStep, $one): bool {
            $data = ['nas.example.internal. 3600 IN A 192.0.2.10', 'q.example.internal. 3600 IN TXT "it\'s"'];
            $out = [];
            foreach (['Fail closed stuck: error failed', 'Fail closed not armed: no answer'] as $fault) {
                $r = $fsStep($fsView(['data' => $data, 'file' => $one, 'copy' => $one]), $fsPlan(),
                    $fsRecord('armed', $fault));
                $out[] = [$r['record']['problem'], $r['record']['unwritable']];
            }
            return $out === [['Fail closed stuck: error failed', 1], ['Fail closed not armed: no answer', 1]];
        }));
    uu_check($t, 'file step: a removal restarts for node lines the guard holds, its restart the last one',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsStep, $one): bool {
            /* a disable tick deleted the file and its restart was reported failed: the lifted copy is still loaded */
            $v = $fsView(['scope' => 'none', 'nets' => [], 'view_zones' => ['localhost.' => 'noview'], 'copy' => $one]);
            $failed = $fsRecord('none', UU_VIEW_RESTART_FAILED, hash('sha256', ''), [], 'none');
            $plan = $fsPlan(['active' => false, 'armed' => false]);
            $tick = $fsStep($v, $plan, $failed, ['stopping' => true]);
            $removal = $fsStep($v, $plan, $failed, ['stopping' => true, 'removal' => true]);
            return !$tick['restart'] && $tick['record']['problem'] === UU_VIEW_RESTART_FAILED
                && $removal['restart'] && $removal['line'] === 'fail closed: the refused nets changed (192.0.2.0/24 '
                    . '-> none): restarting Unbound'
                && $removal['record'] === $fsRecord('none', null, hash('sha256', ''), [], 'none');
        }));
    uu_check($t, 'text: the rendered file passes the shape check, and every line of another shape fails it',
        uu_try_case(function () use ($one, $fsFile): bool {
            $snoop = uu_view_render(['view' => ['192.0.2.0/24'], 'access' => [['net' => '192.0.2.0/24',
                'action' => 'allow_snoop']]], [], []);
            $bad = [
                str_replace('"example.internal."', '""', $one),
                str_replace('192.0.2.10"', '192.0.2.10 "x"', $one),
                str_replace("A 192.0.2.10", "A", $one),
                str_replace('local-data: "nas.example.internal. 3600 IN A 192.0.2.10"',
                    "local-data: 'nas.example.internal. 3600 IN A 192.0.2.10'", $one),
                str_replace('local-data: "nas.example.internal. 3600 IN A 192.0.2.10"',
                    'local-data: "nas.example.internal.   3600 IN A 192.0.2.10"', $one),
                str_replace('access-control-view: 192.0.2.0/24', 'access-control-view: 192.0.2.1/24', $one),
                str_replace('access-control-view: 192.0.2.0/24', 'access-control-view: 127.0.0.0/8', $one),
                str_replace('allow_snoop', 'deny', $snoop),
                str_replace("view-first: yes\n", "view-first: yes\n    include: \"/etc/passwd\"\n", $one),
                substr($one, 0, -strlen("# End of os-unbound-upstream.\n")),
                str_replace("server:\n", '', $one),
                rtrim($one, "\n"),
            ];
            return uu_view_text_ok($one) && uu_view_text_ok($snoop) && uu_view_text_ok($fsFile(['0.0.0.0/0', '::/0']))
                && array_filter($bad, 'uu_view_text_ok') === [];
        }));
    uu_check($t, 'refused nets: the access-control-view netblocks of a file, none for no file',
        uu_try_case(fn (): bool => uu_view_refused_nets($two) === ['192.0.2.0/24', '198.51.100.0/24']
            && uu_view_refused_nets(null) === []));

    /* the file step carried out: the calls it makes and the record it leaves, with a recording Io */
    $fsIo = function (array &$calls, bool $install = true, bool $delete = true, bool $restart = true): array {
        return [
            'install' => function (string $text) use (&$calls, $install): bool {
                $calls[] = 'install';
                return $install;
            },
            'delete' => function () use (&$calls, $delete): bool {
                $calls[] = 'delete';
                return $delete;
            },
            'restart' => function () use (&$calls, $restart): bool {
                $calls[] = 'restart';
                return $restart;
            },
            'log' => function (string $msg, int $prio) use (&$calls): void {
                $calls[] = "log $prio $msg";
            },
        ];
    };
    $fsS = fn (array $view, array $over = []): array => array_merge(['stop' => null,
        'settings' => ['enabled' => true, 'dry_run' => false], 'unbound' => ['enabled' => true, 'pid_alive' => true],
        'contract_input' => ['cacheflush' => false], 'view' => $view], $over);
    $fsSt = fn (array $record, string $mode = 'fallback'): array => ['mode' => $mode, 'tls_applied' => true,
        'view' => $record];
    uu_check($t, 'file step: a restart records the view armed',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsIo, $fsS, $fsSt, $fsHash, $one, $two, $nets2,
            $line): bool {
            $calls = [];
            $st = uu_view_file_apply(['view' => $fsPlan()], $fsS($fsView(['nets' => $nets2, 'file' => $one,
                'copy' => $one])), $fsSt($fsRecord()), $fsIo($calls));
            return $calls === ['install', 'log ' . LOG_WARNING . " $line", 'restart'] && $st['tls_applied'] === null
                && $st['view'] === $fsRecord('armed', null, $fsHash($two), $nets2);
        }));
    uu_check($t, 'file step: a failed install keeps the old nets and cancels the restart; a failed restart is a fault',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsIo, $fsS, $fsSt, $fsHash, $one, $two,
            $nets2): bool {
            $v = $fsView(['nets' => $nets2, 'file' => $one, 'copy' => $one]);
            $calls = [];
            $st = uu_view_file_apply(['view' => $fsPlan()], $fsS($v), $fsSt($fsRecord()), $fsIo($calls, false));
            $restartCalls = [];
            $notRestarted = uu_view_file_apply(['view' => $fsPlan()], $fsS($v), $fsSt($fsRecord()),
                $fsIo($restartCalls, true, true, false));
            return $calls === ['install']
                && $st['view'] === $fsRecord('lifted', 'Fail closed: the view file was kept (the new file was not '
                    . 'installed)') && $st['tls_applied'] === true
                && $notRestarted['view'] === $fsRecord('lifted', UU_VIEW_RESTART_FAILED, $fsHash($two), $nets2);
        }));
    uu_check($t, 'file step: a restart reported failed is not tried again for the same node lines; its fault stands '
        . 'until the copy changes',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsIo, $fsS, $fsSt, $fsHash, $one, $two,
            $nets2): bool {
            $calls = [];
            $failed = uu_view_file_apply(['view' => $fsPlan()], $fsS($fsView(['nets' => $nets2, 'file' => $one,
                'copy' => $one])), $fsSt($fsRecord()), $fsIo($calls, true, true, false));
            /* the next tick: the file installed, the copy still the old one */
            $nextCalls = [];
            $next = uu_view_file_apply(['view' => $fsPlan()], $fsS($fsView(['nets' => $nets2, 'file' => $two,
                'copy' => $one])), $fsSt($failed['view']), $fsIo($nextCalls));
            /* the restart had happened after all, or the owner's did: the copy holds the lines */
            $loadedCalls = [];
            $loaded = uu_view_file_apply(['view' => $fsPlan()], $fsS($fsView(['nets' => $nets2, 'file' => $two,
                'copy' => $two])), $fsSt($next['view']), $fsIo($loadedCalls));
            return count($calls) === 3 && end($calls) === 'restart'
                && $failed['view'] === $fsRecord('lifted', UU_VIEW_RESTART_FAILED, $fsHash($two), $nets2)
                && $nextCalls === [] && $next['view'] === $failed['view']
                && $loadedCalls === [] && $loaded['view'] === $fsRecord('lifted', null, null, $nets2);
        }));
    uu_check($t, 'file step: a removal never holds the file: it deletes it, and restarts Unbound while a copy with node '
        . 'lines is loaded',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsIo, $fsS, $fsSt, $one): bool {
            $removal = ['stop' => UU_STOP_REMOVE];
            /* Unbound down with the set armed: the lift was skipped; the delete alone keeps its next start clean */
            $downCalls = [];
            $down = uu_view_file_apply(['view' => $fsPlan(['active' => false, 'armed' => null])],
                $fsS($fsView(['file' => $one, 'copy' => $one, 'loaded' => 'skipped', 'zones' => null,
                    'data' => null]), $removal + ['unbound' => ['enabled' => true, 'pid_alive' => false]]),
                $fsSt($fsRecord('armed')), $fsIo($downCalls));
            /* a lift that failed with Unbound running: core's restart drops the view whatever the lift did */
            $stuck = 'Fail closed stuck: error failed';
            $failedCalls = [];
            $failed = uu_view_file_apply(['view' => $fsPlan()], $fsS($fsView(['file' => $one, 'copy' => $one]),
                $removal), $fsSt($fsRecord('armed', $stuck)), $fsIo($failedCalls));
            /* a removal whose stop could not restore still deletes: nothing after it would lift a held set */
            $tunnelCalls = [];
            $tunnel = uu_view_file_apply(['view' => $fsPlan()], $fsS($fsView(['file' => $one, 'copy' => $one]),
                $removal), $fsSt($fsRecord('armed', $stuck), 'tunnel'), $fsIo($tunnelCalls));
            $restarted = $fsRecord('none', null, hash('sha256', ''), []);
            return $downCalls === ['delete'] && $down['view'] === $fsRecord('none', null, null, [])
                && $failedCalls === ['delete', 'log ' . LOG_WARNING . ' fail closed: the refused nets changed '
                    . '(192.0.2.0/24 -> none): restarting Unbound', 'restart']
                && $failed['view'] === $restarted && $failed['tls_applied'] === null
                && $tunnelCalls === $failedCalls && $tunnel['view'] === $restarted;
        }));
    uu_check($t, 'file step: a failed delete cancels the restart (a foreign view line, the file still on disk)',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsIo, $fsS, $fsSt, $one): bool {
            $acl = ['nodes' => [['net' => '0.0.0.0/0', 'action' => 'allow'], ['net' => '::/0', 'action' => 'allow']],
                'foreign' => ['view:']];
            $calls = [];
            $st = uu_view_file_apply(['view' => $fsPlan(['problem' => UU_VIEW_FOREIGN . 'view:'])],
                $fsS($fsView(['acl' => $acl, 'file' => $one, 'copy' => $one])), $fsSt($fsRecord()),
                $fsIo($calls, true, false));
            return $calls === ['delete']
                && $st['view'] === $fsRecord('lifted', 'Fail closed: the view file could not be deleted');
        }));
    uu_check($t, 'file step: an empty set\'s delete waits for the lift, then deletes the file, restarts Unbound to drop '
        . 'the copy, and records none',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsIo, $fsS, $fsSt, $one): bool {
            $v = $fsView(['scope' => 'none', 'nets' => [], 'file' => $one, 'copy' => $one]);
            $stuck = 'Fail closed stuck: no answer';
            $heldCalls = [];
            $held = uu_view_file_apply(['view' => $fsPlan(['active' => false])], $fsS($v),
                $fsSt($fsRecord('armed', $stuck)), $fsIo($heldCalls));
            $calls = [];
            $done = uu_view_file_apply(['view' => $fsPlan(['active' => false, 'armed' => false])], $fsS($v),
                $fsSt($fsRecord('lifted', UU_VIEW_UNLOADED)), $fsIo($calls));
            return $heldCalls === [] && $held['view'] === $fsRecord('armed', $stuck, null, ['192.0.2.0/24'], 'none')
                && $calls === ['delete', 'log ' . LOG_WARNING . ' fail closed: the refused nets changed (192.0.2.0/24 '
                    . '-> none): restarting Unbound', 'restart']
                && $done['view'] === $fsRecord('none', null, hash('sha256', ''), [], 'none')
                && $done['tls_applied'] === null;
        }));
    uu_check($t, 'file step: an upgrade stop changes nothing',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsIo, $fsS, $fsSt, $one): bool {
            $fault = 'Fail closed: the view file was kept (x)';
            $calls = [];
            $st = uu_view_file_apply(['view' => $fsPlan(['keep' => true])],
                $fsS($fsView(['file' => $one, 'copy' => $one]), ['stop' => UU_STOP_REMOVE]),
                $fsSt($fsRecord('armed', $fault)), $fsIo($calls));
            return $calls === [] && $st === $fsSt($fsRecord('armed', $fault));
        }));
    uu_check($t, 'file step: dry run logs what it would do and calls nothing',
        uu_try_case(function () use ($fsView, $fsPlan, $fsRecord, $fsIo, $fsS, $fsSt, $one, $nets2): bool {
            $calls = [];
            $st = uu_view_file_apply(['view' => $fsPlan()], $fsS($fsView(['nets' => $nets2, 'file' => $one,
                'copy' => $one]), ['settings' => ['enabled' => true, 'dry_run' => true]]), $fsSt($fsRecord()),
                $fsIo($calls));
            return $calls === ['log ' . LOG_NOTICE . ' [dry] fail closed: would write the view file; the refused nets '
                    . 'changed (192.0.2.0/24 -> 192.0.2.0/24, 198.51.100.0/24): would restart Unbound']
                && $st === $fsSt($fsRecord());
        }));

    return uu_tally_report('views', $t);
});
