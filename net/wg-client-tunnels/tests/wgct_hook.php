<?php

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * VM test for the filter hook's fallback to the footprint (spec 2026-10-20 section 3.1 part B, cases k-n).
 * Root on the disposable test VM only (vm_selftest.sh), never on a firewall. It loads the working tree's
 * plugins.inc.d/wgclienttunnels.inc beside a stub \OPNsense\Firewall\Plugin that only records what is
 * registered, and calls wgclienttunnels_firewall_at() with a temporary library, footprint and run directory,
 * so no plugin state, pf or config is touched. Calls that stand for a real filter reload run inside a function
 * named filter_configure_sync, the frame the hook looks for; this process loads no core filter code, so the
 * name is free. The hook logs to the WireGuard log, so log counts are of lines after a marker this test logs.
 * The cases for a partly present library copy the working tree's lib files into a temporary directory and run
 * the hook in a child process each, since every copy declares the same functions.
 *
 * Usage: php wgct_hook.php /path/to/wgclienttunnels.inc /path/to/lib
 */

namespace OPNsense\Firewall {
    class Plugin
    {
        public array $rules = [];
        public array $anchors = [];
        public bool $throws = false;

        public function registerFilterRule($prio, $conf, $defaults = null)
        {
            if ($this->throws) {
                throw new \RuntimeException('hooktest register failure');
            }
            $this->rules[] = [$prio, $conf];
        }

        public function registerAnchor($name, $type = 'fw', $priority = 0, $placement = 'tail', $quick = false)
        {
            $this->anchors[] = [$name, $type, $priority, $placement];
        }
    }
}

namespace {
    const HOOKTEST_LOG = '/var/log/wireguard/latest.log';

    require_once $argv[1];

    /* stands for core's filter reload: the hook writes state and logs only from inside one */
    function filter_configure_sync(callable $call): void
    {
        $call();
    }

    /* child mode: one hook call inside a filter reload, printing what it registered */
    if (($argv[2] ?? '') === '--child') {
        $fw = new \OPNsense\Firewall\Plugin();
        filter_configure_sync(function () use ($argv, $fw): void {
            wgclienttunnels_firewall_at($argv[3], $argv[4], $argv[5], $fw);
        });
        echo json_encode(['anchors' => $fw->anchors, 'rules' => $fw->rules]), "\n";
        exit(0);
    }
    $treeLib = $argv[2];

    $tally = ['fail' => 0, 'total' => 0];
    function hooktest_check(array &$tally, string $desc, callable $case): void
    {
        try {
            $ok = $case();
        } catch (\Throwable $e) {
            printf("       threw %s: %s\n", get_class($e), $e->getMessage());
            $ok = false;
        }
        $tally['total']++;
        $tally['fail'] += $ok ? 0 : 1;
        printf("[%s] hook: %s\n", $ok ? 'PASS' : 'FAIL', $desc);
    }

    $T = rtrim(sys_get_temp_dir(), '/') . '/wgct-hook.' . getmypid();
    mkdir($T, 0700);
    $nolib = "$T/nolib";
    $run = "$T/run";
    $fp = "$T/footprint.json";
    $tag = 'wgct-hooktest-' . getmypid();

    /* a footprint as the render writes it for one tunnel pinned to opt2 with its inner block on opt3 */
    $wanRule = [
        'type' => 'block', 'direction' => 'out', 'quick' => true, 'log' => true, 'interface' => 'opt2',
        'interfacenot' => true, 'ipprotocol' => 'inet', 'protocol' => 'udp', 'to' => '192.0.2.10',
        'label' => md5('wgct-pin-wan-opt2-inet'),
        'descr' => 'WireGuard Upstream Tunnels: tunnels bound to this WAN never leave by another interface',
    ];
    $innerRule = [
        'type' => 'block', 'direction' => 'out', 'quick' => true, 'log' => true, 'interface' => 'opt3',
        'ipprotocol' => 'inet46', 'from' => 'opt3ip', 'from_not' => true, 'label' => md5('wgct-pin-inner-opt3-opt3ip'),
        'descr' => "WireGuard Upstream Tunnels: only traffic NATed to this tunnel's own address may enter it",
    ];
    $record = ['at' => 1760000000, 'priority' => 99999, 'anchor' => 'wgclienttunnels_mss',
        'rules' => [$wanRule, $innerRule], 'mss' => ['match on wg1 inet proto tcp all scrub (max-mss 1340)']];
    $fpAt = date('Y-m-d H:i:s', $record['at']);

    $put = function (string $path, string $content): void {
        @unlink($path);
        file_put_contents($path, $content);
    };
    /* every case starts from an empty run directory */
    $fresh = function () use ($run): void {
        foreach (glob("$run/*") ?: [] as $f) {
            unlink($f);
        }
        @rmdir($run);
    };
    $call = function (string $lib, string $footprint, bool $inReload = true) use ($run): \OPNsense\Firewall\Plugin {
        $fw = new \OPNsense\Firewall\Plugin();
        $hook = function () use ($lib, $footprint, $run, $fw): void {
            wgclienttunnels_firewall_at($lib, $footprint, $run, $fw);
        };
        try {
            $inReload ? filter_configure_sync($hook) : $hook();
        } catch (\Throwable $e) {
            printf("       the hook threw %s: %s\n", get_class($e), $e->getMessage());
        }
        return $fw;
    };
    /* the WireGuard log lines after this case's marker that contain $needle */
    $marker = function () use ($tag): string {
        $m = $tag . '-' . bin2hex(random_bytes(4));
        exec('/usr/bin/logger -t wireguard -- ' . escapeshellarg('[wgct-hooktest] marker ' . $m));
        return $m;
    };
    $count = function (string $m, string $needle): int {
        sleep(2);
        $lines = @file(HOOKTEST_LOG, FILE_IGNORE_NEW_LINES) ?: [];
        $after = null;
        foreach ($lines as $i => $line) {
            if (str_contains($line, 'marker ' . $m)) {
                $after = $i;
            }
        }
        if ($after === null) {
            return -1;
        }
        return count(array_filter(array_slice($lines, $after + 1), fn (string $l): bool => str_contains($l, $needle)));
    };
    $fallback = fn (): ?array => is_file("$run/fallback.json") ? json_decode((string)file_get_contents("$run/fallback.json"), true) : null;
    $registeredFootprint = fn (\OPNsense\Firewall\Plugin $fw): bool
        => $fw->anchors === [['wgclienttunnels_mss', 'fw', 0, 'head']]
        && $fw->rules === [[99999, $wanRule], [99999, $innerRule]];

    /* a stub library: its wgct_render_firewall() succeeds or fails as $GLOBALS['hooktest_render'] says */
    mkdir("$T/lib");
    file_put_contents("$T/lib/tunnels.php", "<?php\n");
    file_put_contents("$T/lib/render.php", <<<'PHP'
<?php
function wgct_render_firewall($fw, ?callable $wanted = null, bool $apply = true, ?array &$rendered = null,
    ?callable $loader = null, ?callable $writer = null, ?callable $inReload = null): bool {
    $fw->registerAnchor('wgclienttunnels_mss', 'fw', 0, 'head');
    $ok = $GLOBALS['hooktest_render'] === 'ok';
    if ($ok) {
        $fw->registerFilterRule(99999, ['type' => 'block', 'label' => str_repeat('b', 32)]);
    }
    $rendered = ['at' => time(), 'failed' => !$ok, 'error' => $ok ? '' : 'hooktest derivation failure', 'enabled' => true,
        'pins' => ['wan' => [], 'inner' => []], 'mss' => []];
    return $ok;
}
PHP);
    /* a library whose render.php throws while it loads */
    mkdir("$T/badlib");
    file_put_contents("$T/badlib/tunnels.php", "<?php\n");
    file_put_contents("$T/badlib/render.php", "<?php\nthrow new \\RuntimeException('hooktest load failure');\n");

    /* (k) the library is missing: the anchor and the rules come from the footprint */
    $fresh();
    $put($fp, json_encode($record));
    mkdir($run, 0700);
    $put("$run/rendered.json", '{}');
    $m = $marker();
    $fw = $call($nolib, $fp);
    hooktest_check($tally, '(k) library missing => the anchor and every footprint rule are registered at the pin priority',
        fn (): bool => $registeredFootprint($fw));
    $fb = $fallback();
    hooktest_check($tally, '(k) fallback.json records when, why and which footprint; rendered.json is gone',
        fn (): bool => is_array($fb) && array_keys($fb) === ['at', 'reason', 'footprint_at'] && is_int($fb['at'])
            && $fb['reason'] === 'plugin library missing' && $fb['footprint_at'] === $record['at']
            && !file_exists("$run/rendered.json"));
    hooktest_check($tally, '(k) one warning names the reason and the footprint\'s time',
        fn (): bool => $count($m, "render failed (plugin library missing); enforcing the footprint recorded at $fpAt") === 1);
    hooktest_check($tally, '(k) the run directory and the state files are root\'s alone (0700, 0600)',
        fn (): bool => (fileperms($run) & 0777) === 0700 && (fileperms("$run/fallback.json") & 0777) === 0600
            && (fileperms("$run/fallback.logged") & 0777) === 0600);

    /* (k) a rules-listing call (not inside a filter reload) shows the footprint's rules and changes no state */
    $fresh();
    mkdir($run, 0700);
    $put("$run/rendered.json", '{}');
    $m = $marker();
    $fw = $call($nolib, $fp, false);
    hooktest_check($tally, '(k) a rules listing registers the footprint too, but writes, removes and logs nothing',
        fn (): bool => $registeredFootprint($fw) && !file_exists("$run/fallback.json") && !file_exists("$run/fallback.logged")
            && file_exists("$run/rendered.json") && $count($m, 'render failed') === 0);

    /* (k) the render itself fails (it registered the anchor already): only the footprint's rules are added */
    $fresh();
    $GLOBALS['hooktest_render'] = 'fail';
    $fw = $call("$T/lib", $fp);
    hooktest_check($tally, '(k) a failed render => the footprint\'s rules, and the anchor once (the render registered it)',
        fn (): bool => $fw->anchors === [['wgclienttunnels_mss', 'fw', 0, 'head']]
            && $fw->rules === [[99999, $wanRule], [99999, $innerRule]]
            && ($fallback()['reason'] ?? null) === 'hooktest derivation failure');

    /* (k) the library throws while it loads: caught, the footprint is enforced */
    $fresh();
    $fw = $call("$T/badlib", $fp);
    hooktest_check($tally, '(k) a library that throws while loading => caught, the footprint is enforced',
        fn (): bool => $registeredFootprint($fw) && ($fallback()['reason'] ?? null) === 'hook failed: hooktest load failure');

    /* (k) the empty footprint a disabled render writes: nothing to hold, which is not "no footprint" */
    $fresh();
    $put("$T/empty.json", json_encode(['at' => 1760000000, 'priority' => 99999, 'anchor' => 'wgclienttunnels_mss',
        'rules' => [], 'mss' => []]));
    $m = $marker();
    $fw = $call($nolib, "$T/empty.json");
    hooktest_check($tally, '(k) the empty footprint => the anchor, no rules, and the footprint is what is enforced',
        fn (): bool => $fw->anchors === [['wgclienttunnels_mss', 'fw', 0, 'head']] && $fw->rules === []
            && is_array($fallback()) && $count($m, 'enforcing the footprint recorded at') === 1);

    /* (l) a footprint that is a symlink, not root's, oversized or of the wrong shape: nothing is registered */
    $link = "$T/link.json";
    @unlink($link);
    symlink($fp, $link);
    $nonroot = "$T/nonroot.json";
    $put($nonroot, json_encode($record));
    chown($nonroot, 'nobody');
    $big = $record;
    $big['rules'][0]['descr'] = str_repeat('x', 70000);
    $put("$T/big.json", json_encode($big));
    $shape = $record;
    $shape['rules'][1]['quick'] = 1;
    $put("$T/shape.json", json_encode($shape));
    foreach (['a symlink' => $link, 'not root\'s' => $nonroot, 'over 64 KiB' => "$T/big.json",
              'of the wrong shape' => "$T/shape.json"] as $what => $path) {
        $fresh();
        $m = $marker();
        $fw = $call($nolib, $path);
        hooktest_check($tally, "(l) a footprint that is $what => nothing registered, no fallback.json, one \"no footprint\" warning",
            fn (): bool => $fw->rules === [] && $fw->anchors === [] && !file_exists("$run/fallback.json")
                && $count($m, "render failed (plugin library missing); no footprint ($path is not a root-owned regular file of the expected shape), so no pins are enforced") === 1);
    }
    $fresh();
    $m = $marker();
    $fw = $call($nolib, "$T/absent.json");
    hooktest_check($tally, '(l) no footprint at all => nothing registered, one warning naming "no footprint"',
        fn (): bool => $fw->rules === [] && $fw->anchors === []
            && $count($m, 'render failed (plugin library missing); no footprint, so no pins are enforced') === 1);

    /* (m) two filter reloads 1 s apart with the same reason: one warning, and fallback.json keeps its first at */
    $fresh();
    $m = $marker();
    $call($nolib, $fp);
    $first = $fallback();
    sleep(1);
    $fw = $call($nolib, $fp);
    $second = $fallback();
    hooktest_check($tally, '(m) the second call enforces the footprint again',
        fn (): bool => $registeredFootprint($fw));
    hooktest_check($tally, '(m) two calls 1 s apart => fallback.json\'s at is unchanged',
        fn (): bool => is_array($first) && $first === $second);
    hooktest_check($tally, '(m) two calls 1 s apart => one warning',
        fn (): bool => $count($m, 'render failed (plugin library missing); enforcing the footprint') === 1);
    $m2 = $marker();
    $GLOBALS['hooktest_render'] = 'fail';
    $call("$T/lib", $fp);
    hooktest_check($tally, '(m) another reason => a second warning and a new fallback.json',
        fn (): bool => $count($m2, 'render failed (hooktest derivation failure); enforcing the footprint') === 1
            && ($fallback()['reason'] ?? null) === 'hooktest derivation failure' && $fallback()['at'] >= $first['at']);

    /* (n) a later successful render removes the fallback state and logs the recovery once */
    $GLOBALS['hooktest_render'] = 'ok';
    $m = $marker();
    $fw = $call("$T/lib", $fp);
    $call("$T/lib", $fp);
    hooktest_check($tally, '(n) a successful render registers only its own rules',
        fn (): bool => $fw->anchors === [['wgclienttunnels_mss', 'fw', 0, 'head']] && count($fw->rules) === 1
            && $fw->rules[0][1]['label'] === str_repeat('b', 32));
    hooktest_check($tally, '(n) fallback.json and fallback.logged are gone',
        fn (): bool => !file_exists("$run/fallback.json") && !file_exists("$run/fallback.logged"));
    hooktest_check($tally, '(n) two successful renders => one "render recovered" line',
        fn (): bool => $count($m, '[wgct-render] render recovered') === 1);

    /* every Throwable on the fallback path is caught: core's registry throwing must not reach core */
    $fresh();
    $m = $marker();
    $escaped = null;
    $fw = new \OPNsense\Firewall\Plugin();
    $fw->throws = true;
    try {
        filter_configure_sync(function () use ($nolib, $fp, $run, $fw): void {
            wgclienttunnels_firewall_at($nolib, $fp, $run, $fw);
        });
    } catch (\Throwable $e) {
        $escaped = $e;
    }
    hooktest_check($tally, 'a Throwable while enforcing the footprint is caught and logged, never thrown into core',
        fn (): bool => $escaped === null && $count($m, 'the footprint fallback failed: hooktest register failure') === 1);

    /* a partly present library: render.php and tunnels.php there, a file further down their require chain missing */
    foreach (['addr.php' => ['render.php', 'tunnels.php'], 'selftest.php' => ['render.php', 'tunnels.php', 'addr.php']]
             as $missing => $files) {
        $fresh();
        $part = "$T/part-" . basename($missing, '.php');
        @mkdir($part, 0700);
        foreach ($files as $f) {
            copy("$treeLib/$f", "$part/$f");
        }
        $m = $marker();
        $out = [];
        exec('/usr/local/bin/php -d log_errors=0 ' . escapeshellarg(__FILE__) . ' ' . escapeshellarg($argv[1]) . ' --child '
            . escapeshellarg($part) . ' ' . escapeshellarg($fp) . ' ' . escapeshellarg($run) . ' 2>&1', $out, $rc);
        $got = json_decode((string)end($out), true);
        if ($rc !== 0) {
            printf("       the child exited %d: %s\n", $rc, trim(implode(' ', $out)));
        }
        hooktest_check($tally, "a library without $missing => no fatal; the anchor and the footprint's rules are registered",
            fn (): bool => $rc === 0 && $got === ['anchors' => [['wgclienttunnels_mss', 'fw', 0, 'head']],
                'rules' => [[99999, $wanRule], [99999, $innerRule]]]);
        hooktest_check($tally, "a library without $missing => one warning naming the missing file",
            fn (): bool => $count($m, "render failed (hook failed: plugin library file $missing missing); enforcing the footprint") === 1);
        foreach ($files as $f) {
            @unlink("$part/$f");
        }
        @rmdir($part);
    }

    $fresh();
    foreach (['footprint.json', 'link.json', 'nonroot.json', 'big.json', 'shape.json', 'empty.json'] as $f) {
        @unlink("$T/$f");
    }
    foreach (['lib', 'badlib'] as $d) {
        @unlink("$T/$d/render.php");
        @unlink("$T/$d/tunnels.php");
        @rmdir("$T/$d");
    }
    @rmdir($T);

    printf("hook: %d/%d passed\n", $tally['total'] - $tally['fail'], $tally['total']);
    exit($tally['fail'] === 0 ? 0 : 1);
}
