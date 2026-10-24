<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Root-zone parser and shape (spec section 3.4): only shapes forward_add can restore; and the configuration files
 * it reads, regular files only (convention C3).
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/zone.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/snapshot.php';
require_once __DIR__ . '/scratch.php';

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

    $z = uu_root_zone(["forward-zone:\n  name: \".\"\n  forward-addr: 192.0.2.53@853#x;y\n"]);
    uu_check($t, '(f2) a forward-addr that is not an address with port and name is unrestorable, the text never named',
        $z['shape'] === 'unrestorable' && $z['problems'] === ['forward-addr value']);
    $z = uu_root_zone(["forward-zone:\n  name: \".\"\n  forward-addr: 192.0.2.53\n  forward-addr: 198.51.100.1<b>\n"
        . "  forward-addr: 999.1.1.1\n"]);
    uu_check($t, '(f2) two bad forward-addr values give the one problem once',
        $z['shape'] === 'unrestorable' && $z['problems'] === ['forward-addr value']);
    $z = uu_root_zone(["forward-zone:\n  name: \".\"\n  forward-addr: \"192.0.2.53 198.51.100.1\"\n"]);
    uu_check($t, '(f2) whitespace inside a forward-addr value is unrestorable, "forward-addr value"',
        $z['shape'] === 'unrestorable' && $z['addrs'] === [] && $z['problems'] === ['forward-addr value']);
    $z = uu_root_zone(["forward-zone:\n  name: \".\"\n  forward-addr: 192.0.2.53\n  fo<o>: yes\n"]);
    uu_check($t, '(f3) an option that is not a plain name is "unknown option", the text never named',
        $z['shape'] === 'unrestorable' && $z['problems'] === ['unknown option']
        && strpos(implode(' ', $z['problems']), 'fo<o>') === false);
    $z = uu_root_zone(["forward-zone:\n  name: \".\"\n  forward-addr: 192.0.2.53\n  forward-first: yes\n"
        . "  a b: 1\n  c<d: 1\n"]);
    uu_check($t, '(f3) forward-first is still named, and two bad option names give "unknown option" once',
        $z['problems'] === ['forward-first', 'unknown option']);
    uu_check($t, '(f3) an option name is admitted by shape: a trailing LF never passes',
        uu_try_case(fn (): bool => uu_zone_option_name_ok('forward-first') && !uu_zone_option_name_ok("forward-first\n")
            && !uu_zone_option_name_ok('fo<o>')));

    $z = uu_root_zone(["forward-zone:\n  name: \".\"\n  forward-tls-upstream: no\n  forward-addr: 192.0.2.53\n"]);
    uu_check($t, 'forward-tls-upstream: no is not tls', $z['shape'] === 'one' && !$z['tls']);

    $z = uu_root_zone(["server: # c\n  do-not-query-localhost: no\nforward-zone: # c\n  name: \".\"  # c\n"
        . "  forward-addr: 192.0.2.53\n"]);
    uu_check($t, 'a comment after a clause header does not hide the zone',
        $z['shape'] === 'one' && $z['addrs'] === ['192.0.2.53'] && $z['problems'] === []);

    /* convention C3 (ruling R9): the zone files are read as regular files only, each up to 1 MiB, so a large
     * blocklist file still counts and no forward-zone lies past 1 MiB; the cut falls at a line's end, so a line
     * past it is lost whole, never shortened */
    uu_check($t, '(z1) zone texts: a symbolic link, a directory and a named pipe are skipped, the regular file read, '
        . 'and a 2 MiB file yields its first 1 MiB up to its last whole line',
        uu_scratch_case(function (string $dir): bool {
            $root = "forward-zone:\n  name: \".\"\n  forward-addr: 192.0.2.53\n";
            $line = "local-zone: \"blocked.example\" always_nxdomain\n";
            $big = substr(str_repeat($line, intdiv(2 * UU_SCRATCH_MIB, strlen($line)) + 1), 0, 2 * UU_SCRATCH_MIB);
            $head = substr($big, 0, UU_SCRATCH_MIB);
            file_put_contents($dir . '/a.conf', $root);
            file_put_contents($dir . '/elsewhere.txt', "forward-zone:\n  name: \".\"\n  forward-addr: 198.51.100.53\n");
            symlink($dir . '/elsewhere.txt', $dir . '/b.conf');
            mkdir($dir . '/c.conf');
            file_put_contents($dir . '/d.conf', $big);
            uu_scratch_place('fifo', $dir . '/e.conf', '');
            return UU_SCRATCH_MIB % strlen($line) !== 0
                && uu_zone_texts($dir) === [$root, substr($head, 0, (int)strrpos($head, "\n") + 1)];
        }));
    uu_check($t, 'zone texts: a forward-addr line that straddles the 1 MiB cut is dropped whole, never shortened to '
        . 'another address',
        uu_scratch_case(function (string $dir): bool {
            $head = "forward-zone:\n  name: \".\"\n";
            $addr = "  forward-addr: 192.0.2.53\n";
            /* comment lines up to 10 bytes short of the cut, so the address line runs past it */
            $fill = UU_SCRATCH_MIB - 10 - strlen($head);
            $pad = str_repeat(str_repeat('#', 63) . "\n", intdiv($fill, 64));
            $pad .= $fill % 64 === 0 ? '' : str_repeat('#', $fill % 64 - 1) . "\n";
            $text = $head . $pad . $addr . str_repeat("# after the cut\n", 1000);
            file_put_contents($dir . '/a.conf', $text);
            $got = uu_zone_texts($dir);
            return strlen($head . $pad) === UU_SCRATCH_MIB - 10 && $got === [$head . $pad]
                && uu_root_zone($got)['addrs'] === [];
        }));

    /* ruling R43: no path in the directory is resolved through a link, so no device is ever looked up */
    uu_check($t, '(z2) zone texts: a directory reached through a symbolic link is a failed read (null), never no '
        . 'zone; the real one is read',
        uu_scratch_case(function (string $dir): bool {
            $root = "forward-zone:\n  name: \".\"\n  forward-addr: 192.0.2.53\n";
            mkdir($dir . '/real');
            file_put_contents($dir . '/real/a.conf', $root);
            symlink($dir . '/real', $dir . '/link');
            return uu_zone_texts($dir . '/link') === null && uu_zone_texts($dir . '/real') === [$root];
        }));
    /* ruling R44: the helper tells "could not look" from "nothing there" */
    $helperRun = function (string $dir): array {
        $out = [];
        $rc = -1;
        $helper = __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/zone_read.py';
        exec(UU_PYTHON . ' -I ' . escapeshellarg($helper) . ' ' . escapeshellarg($dir) . ' 1048576 2>/dev/null', $out,
            $rc);
        return [$rc, implode("\n", $out)];
    };
    uu_check($t, 'zone_read.py: a DIR reached through a link or missing exits 1 with nothing on stdout; an empty '
        . 'directory it reaches exits 0 with []',
        uu_scratch_case(function (string $dir) use ($helperRun): bool {
            mkdir($dir . '/real');
            symlink($dir . '/real', $dir . '/link');
            return $helperRun($dir . '/link') === [1, ''] && $helperRun($dir . '/none') === [1, '']
                && $helperRun($dir . '/real') === [0, '[]'];
        }));
    uu_check($t, 'zone texts: a reachable directory with no *.conf file (only other names, a dot file) is no files '
        . '([]), shape none as before; only a failed read is null',
        uu_scratch_case(function (string $dir): bool {
            file_put_contents($dir . '/notes.txt', "forward-zone:\n  name: \".\"\n  forward-addr: 192.0.2.53\n");
            file_put_contents($dir . '/.hidden.conf', "forward-zone:\n  name: \".\"\n  forward-addr: 198.51.100.53\n");
            $got = uu_zone_texts($dir);
            return $got === [] && uu_root_zone($got)['shape'] === 'none';
        }));
    $try = function (callable $case): bool {
        try {
            return (bool)$case();
        } catch (\Throwable $e) {
            printf("  threw %s: %s\n", get_class($e), $e->getMessage());
            return false;
        }
    };
    uu_check($t, 'zone: a read that failed (null) is unrestorable, "configuration unreadable", never shape none',
        $try(fn (): bool => uu_root_zone(null) === ['shape' => 'unrestorable', 'addrs' => [], 'tls' => false,
            'problems' => ['configuration unreadable']]));
    uu_check($t, '(z3) zone texts: a *.conf link to /dev/tun is skipped and clones no tun interface',
        uu_scratch_case(function (string $dir): bool {
            $root = "forward-zone:\n  name: \".\"\n  forward-addr: 192.0.2.53\n";
            file_put_contents($dir . '/a.conf', $root);
            $ifaces = function (): ?array {
                $out = [];
                $rc = 1;
                exec('/sbin/ifconfig -l', $out, $rc);
                return $rc === 0 && count($out) === 1 ? explode(' ', trim($out[0])) : null;
            };
            /* the interfaces before the link exists, and the link made by ln(1): PHP's symlink() resolves its target,
             * and that lookup alone clones a tun interface (the VM probe in the Task 3 report) */
            $before = $ifaces();
            $rc = 1;
            exec('/bin/ln -s /dev/tun ' . escapeshellarg($dir . '/b.conf'), result_code: $rc);
            $got = $rc === 0 && is_link($dir . '/b.conf') ? uu_zone_texts($dir) : null;
            $after = $ifaces();
            $cloned = $before === null || $after === null ? [] : array_diff($after, $before);
            foreach ($cloned as $name) {
                if (preg_match('/^tun[0-9]+$/', $name) === 1) {
                    printf("  destroying %s, cloned by the read\n", $name);
                    exec('/sbin/ifconfig ' . escapeshellarg($name) . ' destroy');
                }
            }
            return $before !== null && $after === $before && $got === [$root];
        }));
    uu_check($t, 'zone texts: the bytes come back exactly (not UTF-8 too), and a dot file is not listed, as glob(3)',
        uu_scratch_case(function (string $dir): bool {
            $text = "# \xff\xfe latin-1 \xe9\n" . "forward-zone:\n  name: \".\"\n  forward-addr: 192.0.2.53\n";
            file_put_contents($dir . '/a.conf', $text);
            file_put_contents($dir . '/.hidden.conf', "forward-zone:\n  name: \".\"\n  forward-addr: 198.51.100.53\n");
            return uu_zone_texts($dir) === [$text];
        }));
    /* the helper's output, decoded strictly: a JSON list of base64 strings, anything else a failed read */
    $outputs = [
        'bad JSON' => 'not json',
        'nothing' => '',
        'null' => 'null',
        'an object, not a list' => '{"0": "eA=="}',
        'a list holding a non-string' => '[1]',
        'a nested list' => '[["eA=="]]',
        'an entry that is not base64' => '["%%%"]',
    ];
    foreach ($outputs as $what => $out) {
        uu_check($t, "(z4) zone decode: $what is a failed read (null)",
            $try(fn (): bool => uu_zone_decode($out) === null));
    }
    uu_check($t, 'zone decode: a list of base64 strings is their bytes, in order; an empty list is no files',
        $try(fn (): bool => uu_zone_decode("[\"eA==\", \"\", \"/w==\"]\n") === ['x', '', "\xff"]
            && uu_zone_decode('[]') === []));
    /* the bounded runner: each failure is null, never no files */
    $helpers = [
        'that runs past its 1 s limit is killed' => "import time\ntime.sleep(30)\n",
        'that exits non-zero' => "import sys\nprint('[]')\nsys.exit(3)\n",
        'that does not exist' => null,
    ];
    foreach ($helpers as $what => $code) {
        uu_check($t, "(z4) zone texts: a helper $what is a failed read (null), within 3 s",
            uu_scratch_case(function (string $dir) use ($code): bool {
                file_put_contents($dir . '/a.conf', "forward-zone:\n  name: \".\"\n  forward-addr: 192.0.2.53\n");
                if ($code !== null) {
                    file_put_contents($dir . '/helper.py', $code);
                }
                $t0 = hrtime(true);
                $got = uu_zone_texts($dir, $dir . '/helper.py', 1);
                return $got === null && hrtime(true) - $t0 < 3 * 1000000000;
            }));
    }

    return uu_tally_report('zone', $t);
});
