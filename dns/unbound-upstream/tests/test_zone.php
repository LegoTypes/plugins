<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Root-zone parser and shape (spec section 3.4): only shapes forward_add can restore.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/zone.php';

function uu_test_fixture(string $name): string
{
    $text = file_get_contents(__DIR__ . '/fixtures/' . $name);
    return $text === false ? '' : $text;
}

uu_register_suite('zone', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $dot = uu_test_fixture('dot_dot.conf');
    $plain = uu_test_fixture('dot_plain.conf');
    $domainsOnly = uu_test_fixture('dot_domains_only.conf');
    $comments = uu_test_fixture('dot_comments.conf');
    $addrs = ['192.0.2.53@853#dns.example', '2001:db8::53@853#dns.example'];

    $z = uu_root_zone([$dot]);
    uu_check($t, 'DoT root: shape one, tls, addresses verbatim incl. [v6]@853#name',
        $z['shape'] === 'one' && $z['tls'] && $z['addrs'] === $addrs && $z['problems'] === []);

    $z = uu_root_zone([$plain]);
    uu_check($t, 'plain root: one, no tls',
        $z['shape'] === 'one' && !$z['tls'] && $z['addrs'] === ['198.51.100.53@53', '203.0.113.53']
        && $z['problems'] === []);

    $z = uu_root_zone([uu_test_fixture('dot_two_roots.conf')]);
    uu_check($t, 'two root zones: unrestorable, problem names "second . zone"',
        $z['shape'] === 'unrestorable' && in_array('second . zone', $z['problems'], true));

    $z = uu_root_zone([uu_test_fixture('dot_first.conf')]);
    uu_check($t, 'forward-first: unrestorable, problem "forward-first"',
        $z['shape'] === 'unrestorable' && $z['problems'] === ['forward-first']);

    $z = uu_root_zone([uu_test_fixture('dot_tcp.conf')]);
    uu_check($t, 'forward-tcp-upstream: unrestorable, problem named',
        $z['shape'] === 'unrestorable' && $z['problems'] === ['forward-tcp-upstream']);

    $z = uu_root_zone([$domainsOnly]);
    uu_check($t, 'only domain zones: shape none',
        $z['shape'] === 'none' && $z['addrs'] === [] && !$z['tls'] && $z['problems'] === []);

    uu_check($t, 'no files: shape none', uu_root_zone([])['shape'] === 'none');
    uu_check($t, 'a root zone in a later file (unbound.opnsense.d copy) is found',
        uu_root_zone([$domainsOnly, $dot])['shape'] === 'one');
    $z = uu_root_zone([$dot, $plain]);
    uu_check($t, 'root zones split across files: unrestorable',
        $z['shape'] === 'unrestorable' && in_array('second . zone', $z['problems'], true));

    $z = uu_root_zone([$comments]);
    uu_check($t, 'comments and quoting do not change the result',
        $z['shape'] === 'one' && $z['tls'] && $z['addrs'] === $addrs && $z['problems'] === []);

    $zones = uu_parse_forward_zones($comments);
    uu_check($t, 'parser: zone names unquoted, lines (name excluded) are [option, value] pairs',
        count($zones) === 2 && $zones[0]['name'] === '.' && $zones[1]['name'] === 'example.net'
        && $zones[0]['lines'][0] === ['forward-tls-upstream', 'yes']
        && $zones[0]['lines'][1] === ['forward-addr', '192.0.2.53@853#dns.example']);
    $cut = uu_parse_forward_zones("forward-zone:\n  name: \".\"\nserver:\n  forward-addr: 192.0.2.1\n");
    uu_check($t, 'parser: a server: block ends a zone',
        count(uu_parse_forward_zones($dot)) === 1 && count(uu_parse_forward_zones($dot)[0]['lines']) === 3
        && count($cut) === 1 && $cut[0]['lines'] === []);

    $other = "forward-zone:\n  name: \".\"\n  forward-addr: 192.0.2.53\n  forward-no-cache: yes\n";
    $z = uu_root_zone([$other]);
    uu_check($t, 'any other option on the root zone is a problem named by its option',
        $z['shape'] === 'unrestorable' && $z['problems'] === ['forward-no-cache']);

    $z = uu_root_zone(["forward-zone:\n  name: \".\"\n  forward-tls-upstream: no\n  forward-addr: 192.0.2.53\n"]);
    uu_check($t, 'forward-tls-upstream: no is not tls', $z['shape'] === 'one' && !$z['tls']);

    $z = uu_root_zone(["server: # c\n  do-not-query-localhost: no\nforward-zone: # c\n  name: \".\"  # c\n"
        . "  forward-addr: 192.0.2.53\n"]);
    uu_check($t, 'a comment after a clause header does not hide the zone',
        $z['shape'] === 'one' && $z['addrs'] === ['192.0.2.53'] && $z['problems'] === []);

    return uu_tally_report('zone', $t);
});
