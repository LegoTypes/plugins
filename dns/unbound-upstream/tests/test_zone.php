<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Root-zone parser and shape: only shapes forward_add can restore; and the configuration files
 * it reads, regular files only.
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

    /* the zone files are read as regular files only, each up to 1 MiB, so a large
     * blocklist file still counts and no forward-zone lies past 1 MiB; the cut falls at a line's end, so a line
     * past it is lost whole, never shortened */
    uu_check($t, '(z1) zone texts: the regular files are read, and a 2 MiB file yields its first 1 MiB up to its '
        . 'last whole line',
        uu_scratch_case(function (string $dir): bool {
            $root = "forward-zone:\n  name: \".\"\n  forward-addr: 192.0.2.53\n";
            $line = "local-zone: \"blocked.example\" always_nxdomain\n";
            $big = substr(str_repeat($line, intdiv(2 * UU_SCRATCH_MIB, strlen($line)) + 1), 0, 2 * UU_SCRATCH_MIB);
            $head = substr($big, 0, UU_SCRATCH_MIB);
            file_put_contents($dir . '/a.conf', $root);
            file_put_contents($dir . '/d.conf', $big);
            return UU_SCRATCH_MIB % strlen($line) !== 0
                && uu_zone_texts($dir) === [$root, substr($head, 0, (int)strrpos($head, "\n") + 1)];
        }));
    /* a *.conf entry the helper skips may be the file that holds the root zone (core's dot.conf), so the read is
     * failed, never the files that were left: unrestorable, and never "no . zone", which restores recursion */
    $skipped = [
        'symbolic link' => function (string $path): void {
            file_put_contents($path . '.txt', "forward-zone:\n  name: \".\"\n  forward-addr: 198.51.100.53\n");
            symlink($path . '.txt', $path);
        },
        'directory' => fn (string $path): bool => mkdir($path),
        'named pipe' => fn (string $path) => uu_scratch_place('fifo', $path, ''),
    ];
    foreach ($skipped as $what => $place) {
        uu_check($t, "zone texts: a *.conf $what beside a regular root zone file is a failed read (null), so the "
            . 'zone is unrestorable, "configuration unreadable"',
            uu_scratch_case(function (string $dir) use ($place): bool {
                file_put_contents($dir . '/a.conf', "forward-zone:\n  name: \".\"\n  forward-addr: 192.0.2.53\n");
                $place($dir . '/dot.conf');
                $got = uu_zone_texts($dir);
                return $got === null && uu_root_zone($got)['problems'] === ['configuration unreadable'];
            }));
    }
    uu_check($t, 'zone texts: a *.conf that cannot be opened (a socket) is a failed read (null)',
        uu_scratch_case(function (string $dir): bool {
            file_put_contents($dir . '/a.conf', "forward-zone:\n  name: \".\"\n  forward-addr: 192.0.2.53\n");
            $sock = stream_socket_server('unix://' . $dir . '/dot.conf');
            if ($sock === false) {
                echo "  no socket made\n";
                return false;
            }
            try {
                return filetype($dir . '/dot.conf') === 'socket' && uu_zone_texts($dir) === null;
            } finally {
                fclose($sock);
            }
        }));
    uu_check($t, 'zone texts: a link or a named pipe that is a dot file or has another name is not counted: the '
        . '*.conf files are read',
        uu_scratch_case(function (string $dir): bool {
            $root = "forward-zone:\n  name: \".\"\n  forward-addr: 192.0.2.53\n";
            file_put_contents($dir . '/a.conf', $root);
            symlink($dir . '/a.conf', $dir . '/.hidden.conf');
            symlink($dir . '/a.conf', $dir . '/notes.txt');
            uu_scratch_place('fifo', $dir . '/pipe.conf.old', '');
            return uu_zone_texts($dir) === [$root];
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

    /* no path in the directory is resolved through a link, so no device is ever looked up */
    uu_check($t, '(z2) zone texts: a directory reached through a symbolic link is a failed read (null), never no '
        . 'zone; the real one is read',
        uu_scratch_case(function (string $dir): bool {
            $root = "forward-zone:\n  name: \".\"\n  forward-addr: 192.0.2.53\n";
            mkdir($dir . '/real');
            file_put_contents($dir . '/real/a.conf', $root);
            symlink($dir . '/real', $dir . '/link');
            return uu_zone_texts($dir . '/link') === null && uu_zone_texts($dir . '/real') === [$root];
        }));
    /* the helper tells "could not look" from "nothing there" */
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
                && $helperRun($dir . '/real') === [0, '{"texts": [], "skipped": 0}'];
        }));
    uu_check($t, 'zone_read.py: every *.conf entry it skips is counted, the regular files still printed',
        uu_scratch_case(function (string $dir) use ($helperRun): bool {
            file_put_contents($dir . '/a.conf', 'x');
            symlink($dir . '/a.conf', $dir . '/b.conf');
            mkdir($dir . '/c.conf');
            return $helperRun($dir) === [0, '{"texts": ["eA=="], "skipped": 2}'];
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
    uu_check($t, '(z3) zone texts: a *.conf link to /dev/tun is a failed read (null) and clones no tun interface',
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
             * and that lookup alone clones a tun interface (found by probing the VM) */
            $before = $ifaces();
            $rc = 1;
            exec('/bin/ln -s /dev/tun ' . escapeshellarg($dir . '/b.conf'), result_code: $rc);
            $got = $rc === 0 && is_link($dir . '/b.conf') ? uu_zone_texts($dir) : [];
            $after = $ifaces();
            $cloned = $before === null || $after === null ? [] : array_diff($after, $before);
            foreach ($cloned as $name) {
                if (preg_match('/^tun[0-9]+$/', $name) === 1) {
                    printf("  destroying %s, cloned by the read\n", $name);
                    exec('/sbin/ifconfig ' . escapeshellarg($name) . ' destroy');
                }
            }
            return $before !== null && $after === $before && $rc === 0 && $got === null;
        }));
    uu_check($t, 'zone texts: the bytes come back exactly (not UTF-8 too), and a dot file is not listed, as glob(3)',
        uu_scratch_case(function (string $dir): bool {
            $text = "# \xff\xfe latin-1 \xe9\n" . "forward-zone:\n  name: \".\"\n  forward-addr: 192.0.2.53\n";
            file_put_contents($dir . '/a.conf', $text);
            file_put_contents($dir . '/.hidden.conf', "forward-zone:\n  name: \".\"\n  forward-addr: 198.51.100.53\n");
            return uu_zone_texts($dir) === [$text];
        }));
    /* the helper's output, decoded strictly: an object of texts, base64 strings, and skipped, a whole number;
     * anything else a failed read */
    $outputs = [
        'bad JSON' => 'not json',
        'nothing' => '',
        'null' => 'null',
        'a list (no object)' => '["eA=="]',
        'an object without skipped' => '{"texts": []}',
        'an object with another key' => '{"texts": [], "skipped": 0, "more": 1}',
        'texts that is an object, not a list' => '{"texts": {"0": "eA=="}, "skipped": 0}',
        'texts holding a non-string' => '{"texts": [1], "skipped": 0}',
        'texts holding a nested list' => '{"texts": [["eA=="]], "skipped": 0}',
        'an entry that is not base64' => '{"texts": ["%%%"], "skipped": 0}',
        'skipped below zero' => '{"texts": [], "skipped": -1}',
        'skipped as a string' => '{"texts": [], "skipped": "0"}',
        'skipped as a fraction' => '{"texts": [], "skipped": 0.5}',
    ];
    foreach ($outputs as $what => $out) {
        uu_check($t, "(z4) zone decode: $what is a failed read (null)",
            $try(fn (): bool => uu_zone_decode($out) === null));
    }
    uu_check($t, 'zone decode: texts of base64 strings are their bytes, in order, with the skip count; an empty list '
        . 'is no files',
        $try(fn (): bool => uu_zone_decode("{\"texts\": [\"eA==\", \"\", \"/w==\"], \"skipped\": 0}\n")
            === ['texts' => ['x', '', "\xff"], 'skipped' => 0]
            && uu_zone_decode('{"skipped": 2, "texts": []}') === ['texts' => [], 'skipped' => 2]));
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

    /* (c1) the single-file mode: the file is opened as a directory's entry is, its directory reached without a link */
    $fileRun = function (string $path, string $max = '1048576'): array {
        $out = [];
        $rc = -1;
        $helper = __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/zone_read.py';
        exec(UU_PYTHON . ' -I ' . escapeshellarg($helper) . ' --file ' . escapeshellarg($path) . ' ' . $max
            . ' 2>/dev/null', $out, $rc);
        return [$rc, implode("\n", $out)];
    };
    uu_check($t, '(c1) zone_read.py --file: a regular file gives its text; a link, a directory, a named pipe, a '
        . 'device and a missing file give skipped 1; a PATH whose directory is a link or missing, and a relative '
        . 'PATH, exit 1 with nothing on stdout',
        uu_try_case(fn (): bool => uu_scratch_case(function (string $dir) use ($fileRun): bool {
            file_put_contents($dir . '/a.conf', "x\n");
            symlink($dir . '/a.conf', $dir . '/b.conf');
            mkdir($dir . '/c.conf');
            mkdir($dir . '/real');
            file_put_contents($dir . '/real/d.conf', "y\n");
            symlink($dir . '/real', $dir . '/link');
            uu_scratch_place('fifo', $dir . '/f.conf', '');
            return $fileRun($dir . '/f.conf') === [0, '{"texts": [], "skipped": 1}']
                && $fileRun('/dev/null') === [0, '{"texts": [], "skipped": 1}']
                && $fileRun($dir . '/a.conf') === [0, '{"texts": ["eAo="], "skipped": 0}']
                && $fileRun($dir . '/b.conf') === [0, '{"texts": [], "skipped": 1}']
                && $fileRun($dir . '/c.conf') === [0, '{"texts": [], "skipped": 1}']
                && $fileRun($dir . '/none.conf') === [0, '{"texts": [], "skipped": 1}']
                && $fileRun($dir . '/link/d.conf') === [1, '']
                && $fileRun($dir . '/nodir/d.conf') === [1, '']
                && $fileRun($dir . '/') === [1, '']
                && $fileRun('a.conf') === [1, ''];
        })));
    uu_check($t, '(c1) zone_read.py --file: a file over MAX_BYTES is cut after its last line end, as an entry is; '
        . 'the two-argument form is unchanged; a bad MAX_BYTES is a usage error (exit 2)',
        uu_try_case(fn (): bool => uu_scratch_case(function (string $dir) use ($fileRun, $helperRun): bool {
            file_put_contents($dir . '/a.conf', "aa\nbb\ncc\n");
            file_put_contents($dir . '/b.conf', 'x');
            return $fileRun($dir . '/a.conf', '7') === [0, '{"texts": ["YWEKYmIK"], "skipped": 0}']
                && $helperRun($dir) === [0, '{"texts": ["YWEKYmIKY2MK", "eA=="], "skipped": 0}']
                && $fileRun($dir . '/a.conf', 'x') === [2, ''];
        })));
    uu_check($t, '(c1) uu_conf_file_text: a regular file is its text; an empty file is the empty string (what a read '
        . 'between the truncate and the write of a rewrite gets), never null; a link, a directory, a missing file, a '
        . 'link in the directory path and a helper that fails or runs past its limit are null',
        uu_try_case(fn (): bool => uu_scratch_case(function (string $dir): bool {
            file_put_contents($dir . '/a.conf', "server:\n  do-ip6: no\n");
            symlink($dir . '/a.conf', $dir . '/b.conf');
            mkdir($dir . '/c.conf');
            mkdir($dir . '/real');
            file_put_contents($dir . '/real/d.conf', "y\n");
            symlink($dir . '/real', $dir . '/link');
            file_put_contents($dir . '/slow.py', "import time\ntime.sleep(30)\n");
            file_put_contents($dir . '/empty.conf', '');
            $t0 = hrtime(true);
            $slow = uu_conf_file_text($dir . '/a.conf', $dir . '/slow.py', 1);
            return uu_conf_file_text($dir . '/a.conf') === "server:\n  do-ip6: no\n"
                && uu_conf_file_text($dir . '/empty.conf') === ''
                && uu_conf_file_text($dir . '/b.conf') === null && uu_conf_file_text($dir . '/c.conf') === null
                && uu_conf_file_text($dir . '/none.conf') === null && uu_conf_file_text($dir . '/link/d.conf') === null
                && uu_conf_file_text($dir . '/a.conf', $dir . '/nohelper.py') === null
                && $slow === null && hrtime(true) - $t0 < 3 * 1000000000;
        })));

    /* (c2) the facts: the last do-ip4 / do-ip6 line wins and none means yes; an outgoing-interface line with a value */
    $facts = fn (string $text): array => uu_unbound_conf_facts($text);
    $yes = ['do_ip4' => true, 'do_ip6' => true, 'outgoing_interface' => false];
    uu_check($t, '(c2) conf facts: no line says yes for both families and no outgoing interface',
        uu_try_case(fn (): bool => $facts('') === $yes && $facts("server:\n  verbosity: 1\n") === $yes));
    uu_check($t, '(c2) conf facts: two do-ip6 lines, the last wins in either order',
        uu_try_case(fn (): bool => $facts("server:\n  do-ip6: yes\n  do-ip6: no\n")['do_ip6'] === false
            && $facts("server:\n  do-ip6: no\n  do-ip6: yes\n")['do_ip6'] === true
            && $facts("server:\n  do-ip4: yes\n  do-ip4: no\n")['do_ip4'] === false
            && $facts("server:\n  do-ip4: no\n  do-ip4: yes\n")['do_ip4'] === true));
    uu_check($t, '(c2) conf facts: each family reads its own line; indentation, tabs, CRLF and a trailing comment do '
        . 'not hide a line',
        uu_try_case(fn (): bool => $facts("do-ip4: no\ndo-ip6: yes\n") === ['do_ip4' => false, 'do_ip6' => true,
                'outgoing_interface' => false]
            && $facts("\t  do-ip6:\tno\r\n")['do_ip6'] === false && $facts("    do-ip4:no\n")['do_ip4'] === false
            && $facts("do-ip6: no # IPv6 is off\n")['do_ip6'] === false));
    uu_check($t, '(c2) conf facts: a comment line and a line that only looks like the option are no line',
        uu_try_case(fn (): bool => $facts("# do-ip6: no\n#do-ip4: no\n") === $yes
            && $facts("xdo-ip6: no\ndo-ip6-extra: no\ndo-ip6: maybe\n") === $yes));
    uu_check($t, '(c2) conf facts: the outgoing-interface keyword is set whatever follows it on the line (Unbound '
        . 'takes the value from the next line after a comment), once or more, in any indentation; a comment, a similar '
        . 'name and a quoted look-alike are not',
        uu_try_case(fn (): bool => $facts("outgoing-interface: 192.0.2.1\n")['outgoing_interface'] === true
            && $facts("server:\n    outgoing-interface:\t2001:db8::1\n")['outgoing_interface'] === true
            && $facts("outgoing-interface: 192.0.2.1\noutgoing-interface: 192.0.2.2\n")['outgoing_interface'] === true
            && $facts("outgoing-interface: # none\n192.0.2.1\n")['outgoing_interface'] === true
            && $facts("outgoing-interface:\n192.0.2.1\n")['outgoing_interface'] === true
            && $facts("# outgoing-interface: 192.0.2.1\n")['outgoing_interface'] === false
            && $facts("outgoing-interface-x: 192.0.2.1\n")['outgoing_interface'] === false
            && $facts("private-address: outgoing-interface: x\n")['outgoing_interface'] === false));
    uu_check($t, '(c2) conf facts: a quoted value is the value',
        uu_try_case(fn (): bool => $facts("do-ip6: \"no\"\n")['do_ip6'] === false
            && $facts("do-ip4: 'no'\n")['do_ip4'] === false && $facts("do-ip6: \"yes\"\n")['do_ip6'] === true
            && $facts("do-ip6: \"no'\n")['do_ip6'] === true));
    /* a read that lands in a rewrite sees a prefix of the file: no prefix of a core-shaped configuration reports a
     * refusal the whole file does not */
    $sweep = function (string $text): bool {
        $whole = uu_unbound_conf_facts($text);
        for ($n = 0; $n <= strlen($text); $n++) {
            $f = uu_unbound_conf_facts(substr($text, 0, $n));
            if (($f['do_ip4'] === false && $whole['do_ip4'] !== false)
                || ($f['do_ip6'] === false && $whole['do_ip6'] !== false)
                || ($f['outgoing_interface'] && !$whole['outgoing_interface'])) {
                printf("  a prefix of %d bytes refuses what the whole file does not\n", $n);
                return false;
            }
        }
        return true;
    };
    $core = uu_test_fixture('unbound_core.conf');
    uu_check($t, '(c2) conf facts: no prefix of a core-shaped configuration refuses (do-ip4 yes, do-ip6 yes)',
        uu_try_case(fn (): bool => $core !== '' && $sweep($core)
            && uu_unbound_conf_facts($core) === ['do_ip4' => true, 'do_ip6' => true, 'outgoing_interface' => false]));
    $refusing = str_replace("do-ip6: yes\n", "do-ip6: no\n", $core) . "outgoing-interface: 192.0.2.1\n";
    uu_check($t, '(c2) conf facts: no prefix of a configuration with do-ip6: no and an outgoing interface refuses '
        . 'what the whole does not, and the whole refuses both',
        uu_try_case(fn (): bool => $sweep($refusing)
            && uu_unbound_conf_facts($refusing) === ['do_ip4' => true, 'do_ip6' => false, 'outgoing_interface' => true]
            && $sweep("server:\n  do-ip4: no\n  do-ip6: no # c\n")));

    /* (m5) the include lines core writes, and the configuration with them spliced in, in Unbound's order */
    $expanded = function (callable $setup, string $main = ''): ?array {
        $result = null;
        uu_scratch_case(function (string $dir) use ($setup, $main, &$result): bool {
            mkdir($dir . '/etc');
            $text = $main !== '' ? $main : uu_test_fixture('unbound_core.conf');
            file_put_contents($dir . '/unbound.conf', str_replace('/var/unbound', $dir, $text));
            file_put_contents($dir . '/advanced.conf', '');
            file_put_contents($dir . '/private_domains.conf', '');
            file_put_contents($dir . '/host_entries.conf', '');
            $setup($dir);
            $text = uu_conf_expanded_text($dir . '/unbound.conf');
            $result = ['text' => $text, 'facts' => $text === null ? null : uu_unbound_conf_facts($text)];
            return true;
        });
        return $result;
    };
    $base = ['do_ip4' => true, 'do_ip6' => true, 'outgoing_interface' => false];
    uu_check($t, '(m5) no custom files: the facts are unbound.conf\'s own and no include line is left in the text',
        uu_try_case(function () use ($expanded, $base): bool {
            $r = $expanded(function (string $dir): void {
            });
            return $r !== null && $r['facts'] === $base && !str_contains((string)$r['text'], 'include:')
                && str_contains((string)$r['text'], "do-ip4: yes\ndo-ip6: yes\n");
        }));
    uu_check($t, '(m5) a custom file with do-ip6: no after core\'s yes refuses an IPv6 group; a do-ip4: no likewise',
        uu_try_case(function () use ($expanded, $base): bool {
            $six = $expanded(fn (string $dir) => file_put_contents($dir . '/etc/custom.conf', "do-ip6: no\n"));
            $four = $expanded(fn (string $dir) => file_put_contents($dir . '/etc/custom.conf',
                "server:\ndo-ip4: no\n"));
            return $six !== null && $six['facts'] === array_replace($base, ['do_ip6' => false])
                && $four !== null && $four['facts'] === array_replace($base, ['do_ip4' => false]);
        }));
    uu_check($t, '(m5) a custom outgoing-interface refuses',
        uu_try_case(function () use ($expanded, $base): bool {
            $r = $expanded(fn (string $dir) => file_put_contents($dir . '/etc/o.conf',
                "outgoing-interface: 192.0.2.1\n"));
            return $r !== null && $r['facts'] === array_replace($base, ['outgoing_interface' => true]);
        }));
    uu_check($t, '(m5) the last line in Unbound\'s order wins: files in sorted order, an include before core\'s '
        . 'line is overridden by it, a later include overrides it',
        uu_try_case(function () use ($expanded, $base): bool {
            $sorted = $expanded(function (string $dir): void {
                file_put_contents($dir . '/etc/b.conf', "do-ip6: yes\n");
                file_put_contents($dir . '/etc/a.conf', "do-ip6: no\n");
            });
            $reverse = $expanded(function (string $dir): void {
                file_put_contents($dir . '/etc/a.conf', "do-ip6: yes\n");
                file_put_contents($dir . '/etc/b.conf', "do-ip6: no\n");
            });
            $early = $expanded(fn (string $dir) => file_put_contents($dir . '/advanced.conf', "do-ip6: no\n"));
            $late = $expanded(fn (string $dir) => file_put_contents($dir . '/host_entries.conf', "do-ip6: no\n"));
            return $sorted !== null && $sorted['facts'] === $base
                && $reverse !== null && $reverse['facts'] === array_replace($base, ['do_ip6' => false])
                && $early !== null && $early['facts'] === $base
                && $late !== null && $late['facts'] === array_replace($base, ['do_ip6' => false]);
        }));
    uu_check($t, '(m5) an included file\'s own includes are followed, and a relative one is taken from '
        . 'unbound.conf\'s directory',
        uu_try_case(function () use ($expanded, $base): bool {
            $r = $expanded(function (string $dir): void {
                file_put_contents($dir . '/etc/a.conf', "include: nested.txt\n");
                file_put_contents($dir . '/nested.txt', "do-ip6: no\n");
            });
            return $r !== null && $r['facts'] === array_replace($base, ['do_ip6' => false]);
        }));
    uu_check($t, '(m5) a relative include and a dot file: taken from unbound.conf\'s directory; the dot file is not '
        . 'matched',
        uu_try_case(function () use ($expanded, $base): bool {
            $r = $expanded(function (string $dir): void {
                file_put_contents($dir . '/etc/a.conf', "do-ip4: no\n");
                file_put_contents($dir . '/etc/.hidden.conf', "outgoing-interface: 192.0.2.1\n");
            }, "do-ip6: yes\ninclude: etc/*.conf\n");
            return $r !== null && $r['facts'] === array_replace($base, ['do_ip4' => false]);
        }));
    uu_check($t, '(m5) include spellings: a quoted path, a comment after it, include-toplevel and a plain path are '
        . 'followed; a commented line, a similar keyword, a line that only holds the word and a path on the next '
        . 'line are not',
        uu_try_case(function () use ($expanded, $base): bool {
            $followed = $expanded(function (string $dir): void {
                foreach (['a', 'b', 'c', 'd'] as $n) {
                    file_put_contents("$dir/$n.txt", "# from $n\n");
                }
            }, "include: /var/unbound/a.txt\n  include:\t\"/var/unbound/b.txt\"  # c\n"
                . "include: '/var/unbound/c.txt'\ninclude-toplevel: d.txt\n");
            $ignored = $expanded(function (string $dir): void {
                file_put_contents("$dir/a.txt", "# from a\n");
            }, "# include: /var/unbound/a.txt\ninclude-x: /var/unbound/a.txt\nprivate-address: include: /x\n"
                . "include:\n/var/unbound/a.txt\n");
            $t = (string)($followed['text'] ?? '');
            return $followed !== null && strpos($t, '# from a') < strpos($t, '# from b')
                && strpos($t, '# from b') < strpos($t, '# from c') && strpos($t, '# from c') < strpos($t, '# from d')
                && $ignored !== null && $ignored['text'] !== null && $ignored['facts'] === $base
                && !str_contains($ignored['text'], '# from a');
        }));
    uu_check($t, '(m5) a relative include is taken from the last directory: line read, not unbound.conf\'s own '
        . 'directory (before any, from it)',
        uu_try_case(function () use ($expanded, $base): bool {
            $other = $expanded(function (string $dir): void {
                mkdir($dir . '/sub');
                file_put_contents($dir . '/rel.conf', "do-ip6: yes\n");
                file_put_contents($dir . '/sub/rel.conf', "do-ip6: no\n");
            }, "directory: /var/unbound/sub\ninclude: rel.conf\n");
            $plain = $expanded(function (string $dir): void {
                mkdir($dir . '/sub');
                file_put_contents($dir . '/rel.conf', "do-ip6: no\n");
                file_put_contents($dir . '/sub/rel.conf', "do-ip6: yes\n");
            }, "include: rel.conf\n");
            $later = $expanded(function (string $dir): void {
                mkdir($dir . '/sub');
                file_put_contents($dir . '/rel.conf', "directory: $dir/sub\n");
                file_put_contents($dir . '/sub/x.conf', "do-ip4: no\n");
            }, "include: rel.conf\ninclude: x.conf\n");
            $relative = $expanded(function (string $dir): void {
                mkdir($dir . '/sub');
                file_put_contents($dir . '/rel.conf', "do-ip6: yes\n");
                file_put_contents($dir . '/sub/rel.conf', "do-ip6: no\n");
            }, "directory: sub\ninclude: rel.conf\n");
            return $relative !== null && $relative['facts'] === array_replace($base, ['do_ip6' => false])
                && $other !== null && $other['facts'] === array_replace($base, ['do_ip6' => false])
                && $plain !== null && $plain['facts'] === array_replace($base, ['do_ip6' => false])
                && $later !== null && $later['facts'] === array_replace($base, ['do_ip4' => false]);
        }));
    uu_check($t, '(m5) globs: ? and [ ] match one character, braces give their alternatives, '
        . 'all matches sorted together as Unbound reads them, and a brace path that is missing is no file',
        uu_try_case(function () use ($expanded, $base): bool {
            $files = function (string $dir): void {
                file_put_contents($dir . '/etc/a1.conf', "do-ip6: yes\n");
                file_put_contents($dir . '/etc/a2.conf', "do-ip6: no\n");
                file_put_contents($dir . '/etc/ab.conf', "do-ip4: no\n");
            };
            $question = $expanded($files, "include: /var/unbound/etc/a?.conf\n");
            $class = $expanded($files, "include: /var/unbound/etc/a[12].conf\n");
            $order = $expanded($files, "include: /var/unbound/etc/{a2,a1}.conf\n");
            $reverse = $expanded($files, "include: /var/unbound/etc/{a1,a2}.conf\n");
            $three = $expanded(function (string $dir): void {
                file_put_contents($dir . '/etc/a.conf', "do-ip6: no\n");
                file_put_contents($dir . '/etc/c.conf', "do-ip6: yes\n");
                file_put_contents($dir . '/etc/b.conf', "do-ip6: no\n");
            }, "include: /var/unbound/etc/{a,c,b}.conf\n");
            $gone = $expanded($files, "include: /var/unbound/etc/{a1,nothere}.conf\n");
            return $question !== null && $question['facts'] === ['do_ip4' => false, 'do_ip6' => false,
                    'outgoing_interface' => false]
                && $class !== null && $class['facts'] === array_replace($base, ['do_ip6' => false])
                && $order !== null && $order['facts'] === array_replace($base, ['do_ip6' => false])
                && $reverse !== null && $reverse['facts'] === array_replace($base, ['do_ip6' => false])
                && $three !== null && $three['facts'] === $base
                && $gone !== null && $gone['facts'] === $base;
        }));
    uu_check($t, '(m5) a chain of five distinct files is followed (no depth bound); a leading ~ and a wildcard in a '
        . 'directory component are refused',
        uu_try_case(function () use ($expanded, $base): bool {
            $chain = $expanded(function (string $dir): void {
                for ($i = 1; $i <= 5; $i++) {
                    file_put_contents("$dir/c$i.txt", $i < 5 ? "include: c" . ($i + 1) . ".txt\n" : "do-ip6: no\n");
                }
            }, "include: c1.txt\n");
            $tilde = $expanded(fn (string $dir) => null, "include: ~/x*.conf\n");
            $dirGlob = $expanded(fn (string $dir) => mkdir($dir . '/e1'), "include: /var/unbound/e*/x.conf\n");
            return $chain !== null && $chain['facts'] === array_replace($base, ['do_ip6' => false])
                && $tilde !== null && $tilde['text'] === null && $dirGlob !== null && $dirGlob['text'] === null;
        }));
    uu_check($t, '(m5) an entry a glob lists that is gone when opened is no file (core empties and refills its '
        . 'custom directory at every start); a listed link is still refused',
        uu_try_case(function (): bool {
            $helper = __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/zone_read.py';
            return uu_scratch_case(function (string $dir) use ($helper): bool {
                mkdir($dir . '/etc');
                file_put_contents($dir . '/unbound.conf', "include: $dir/etc/*.conf\n");
                file_put_contents($dir . '/etc/a.conf', "do-ip6: no\n");
                $script = "import runpy, sys, os\nns = runpy.run_path(sys.argv[1])\nreal = os.listdir\n"
                    . "os.listdir = lambda fd: real(fd) + ['ghost.conf']\n"
                    . "sys.exit(ns['main_conf'](sys.argv[2], 1048576, 64, 8388608))\n";
                $run = function () use ($script, $helper, $dir): string {
                    $out = [];
                    exec(UU_PYTHON . ' -I -c ' . escapeshellarg($script) . ' ' . escapeshellarg($helper) . ' '
                        . escapeshellarg($dir . '/unbound.conf') . ' 2>/dev/null', $out);
                    return implode("\n", $out);
                };
                $gone = $run();
                symlink($dir . '/etc/a.conf', $dir . '/etc/ghost.conf');
                $linked = $run();
                return $gone === '{"texts": ["ZG8taXA2OiBubwo="], "skipped": 0}'
                    && $linked === '{"texts": [], "skipped": 1}';
            });
        }));
    uu_check($t, '(m5) unreadable (null): a link among the included files, a directory matched, a path that is '
        . 'missing, a glob in a linked directory, a loop, more files or bytes than the bounds, and unbound.conf '
        . 'itself missing; a glob with no match is not',
        uu_try_case(function () use ($expanded): bool {
            $link = $expanded(function (string $dir): void {
                file_put_contents($dir . '/target.txt', "do-ip6: yes\n");
                symlink($dir . '/target.txt', $dir . '/etc/l.conf');
            });
            $directory = $expanded(fn (string $dir) => mkdir($dir . '/etc/d.conf'));
            $missing = $expanded(fn (string $dir) => null, "include: /nonexistent-dir/x.conf\n");
            $loop = $expanded(fn (string $dir) => file_put_contents($dir . '/etc/a.conf',
                "include: " . $dir . "/etc/a.conf\n"));
            $many = $expanded(function (string $dir): void {
                for ($i = 0; $i < UU_CONF_MAX_FILES; $i++) {
                    file_put_contents(sprintf('%s/etc/f%03d.conf', $dir, $i), "\n");
                }
            });
            $linkedDir = $expanded(function (string $dir): void {
                file_put_contents($dir . '/etc/a.conf', "do-ip6: no\n");
                symlink($dir . '/etc', $dir . '/lnk');
            }, "include: /var/unbound/lnk/*.conf\n");
            $bytes = $expanded(function (string $dir): void {
                for ($i = 0; $i < 9; $i++) {
                    file_put_contents(sprintf('%s/etc/b%d.conf', $dir, $i),
                        str_repeat(str_repeat('#', 1022) . "\n", 1000));
                }
            });
            $none = $expanded(fn (string $dir) => null, "include: /nonexistent-dir/*.conf\ndo-ip6: no\n");
            return $link !== null && $link['text'] === null && $directory !== null && $directory['text'] === null
                && $missing !== null && $missing['text'] === null && $loop !== null && $loop['text'] === null
                && $many !== null && $many['text'] === null && $linkedDir !== null && $linkedDir['text'] === null
                && $bytes !== null && $bytes['text'] === null
                && $none !== null && $none['facts'] === ['do_ip4' => true, 'do_ip6' => false,
                    'outgoing_interface' => false]
                && uu_conf_expanded_text('/nonexistent-dir/unbound.conf') === null;
        }));

    return uu_tally_report('zone', $t);
});
