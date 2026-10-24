<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The plugin's wiring on the test VM (spec sections 3.1 and 3.11): the hook table, the hook order, the privileges,
 * configd's answers and the evaluate that Unbound's own start leads to (seen in configd's log). Needs the tree overlaid onto the VM (vm_overlay.sh) with the
 * plugin disabled; elsewhere it registers a suite that skips. Changes nothing lasting: it adds a minute job by hand
 * for stop's cron restart to remove, runs one pluginctl unbound_start, which restarts Unbound, writes two
 * uu-wiring marker lines to the plugin's log, and puts a state recording a footprint in place of the saved one for
 * one read as nobody and, under the evaluate lock, for two cron restarts, then puts the saved one, the crontab and
 * cron's running state back. It also records and replays one snapshot in a scratch directory it removes.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/log.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/state.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/render.php';
require_once __DIR__ . '/scratch.php';

/** Every daily file of one log directory under /var/log, in order. */
function uu_test_log_dir(string $name): string
{
    $text = '';
    foreach (glob("/var/log/{$name}/{$name}_*.log") ?: [] as $file) {
        $text .= is_readable($file) ? (string)file_get_contents($file) : '';
    }
    return $text;
}

/**
 * The program() patterns of each filter in syslog-ng's rendered local configuration.
 *
 * @return array<string, list<string>> filter name => its program() patterns
 */
function uu_test_program_filters(string $conf): array
{
    $filters = [];
    preg_match_all('/^filter\s+(\w+)\s*\{(.*?)\};/ms', $conf, $blocks, PREG_SET_ORDER);
    foreach ($blocks as $block) {
        preg_match_all('/program\("([^"]*)"\)/', $block[2], $programs);
        if ($programs[1] !== []) {
            $filters[$block[1]] = $programs[1];
        }
    }
    return $filters;
}

/**
 * The Services > Unbound DNS entries of one Menu.xml, as entry name => order.
 *
 * @return array<string, int>
 */
function uu_test_unbound_menu(string $file): array
{
    $xml = is_readable($file) ? simplexml_load_file($file) : false;
    $entries = [];
    foreach ($xml === false ? [] : ($xml->xpath('/menu/Services/Unbound/*') ?: []) as $node) {
        $entries[$node->getName()] = (int)$node['order'];
    }
    return $entries;
}

/**
 * configd's log, every daily file: latest.log can still point at an earlier day's file (syslog-ng moves it on the
 * next rotation, and a VM restored from a checkpoint crosses midnight UTC without one).
 */
function uu_test_configd_log(): string
{
    $text = '';
    foreach (glob('/var/log/configd/configd_*.log') ?: [] as $file) {
        $text .= is_readable($file) ? (string)file_get_contents($file) : '';
    }
    return $text;
}

/**
 * How many times configd has finished the plugin's evaluate action. A disabled plugin evaluates quietly (its own
 * log stays empty), so configd's log is the witness that a hook queued one.
 */
function uu_test_evaluations(): int
{
    return substr_count(uu_test_configd_log(), '[unboundupstream evaluate] returned');
}

/** Wait up to 5 s for configd's log to show $needle more often than $before times. */
function uu_test_wait_configd(string $needle, int $before): bool
{
    $deadline = hrtime(true) + 5000000000;
    while (hrtime(true) < $deadline) {
        if (substr_count(uu_test_configd_log(), $needle) > $before) {
            return true;
        }
        usleep(200000);
    }
    return false;
}

/**
 * Run $body with the saved state at $path moved to $aside, and put it back whatever happens; $body writes its state
 * only through the callable it is given. The file at $path is removed only once that has written it, and the saved
 * one is renamed back only when it was moved aside, so a failure never deletes the real state: a move aside that
 * fails runs nothing and touches nothing. A throw is printed, as in uu_try_case().
 *
 * @param callable(callable(array<string, mixed>): void): void $body
 * @param callable(string, string): bool $rename rename(), or a stub
 */
function uu_test_state_aside(string $path, string $aside, callable $body, callable $rename): void
{
    $moved = false;
    if (file_exists($path)) {
        if (!$rename($path, $aside)) {
            printf("  cannot set the saved state aside: nothing run\n");
            return;
        }
        $moved = true;
    }
    $written = false;
    try {
        $body(function (array $state) use ($path, &$written): void {
            uu_state_save($path, $state);
            $written = true;
        });
    } catch (\Throwable $e) {
        printf("  threw %s: %s\n", get_class($e), $e->getMessage());
    } finally {
        if ($written) {
            @unlink($path);
        }
        if ($moved && !$rename($aside, $path)) {
            printf("  the saved state could not be put back from %s\n", $aside);
        }
    }
}

/** Whether cron runs (rc.d's status; the batch stops it for the scenarios and starts it at the end). */
function uu_test_cron_running(): bool
{
    $out = [];
    $rc = 1;
    exec('/usr/sbin/service cron onestatus > /dev/null 2>&1', $out, $rc);
    return $rc === 0;
}

/**
 * The evaluate lock, as evaluate.php takes it (exclusive, waiting up to UU_LOCK_WAIT_SECONDS), so no evaluation runs
 * while it is held; false when it could not be taken. Closing the handle releases it.
 *
 * @return resource|false
 */
function uu_test_evaluate_lock()
{
    $lock = fopen(UU_RUN_DIR . '/evaluate.lock', 'ce');
    if ($lock === false) {
        return false;
    }
    $deadline = hrtime(true) + UU_LOCK_WAIT_SECONDS * 1000000000;
    while (!flock($lock, LOCK_EX | LOCK_NB)) {
        if (hrtime(true) >= $deadline) {
            fclose($lock);
            return false;
        }
        usleep(200000);
    }
    return $lock;
}

/** Wait up to 60 s until cron's next minute tick is at least $margin seconds away. */
function uu_test_clear_of_tick(int $margin): bool
{
    $deadline = hrtime(true) + 60000000000;
    while (hrtime(true) < $deadline) {
        $second = (int)date('s');
        if ($second >= 1 && 60 - $second >= $margin) {
            return true;
        }
        usleep(200000);
    }
    return false;
}

uu_register_suite('wiring', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    if (!is_executable('/usr/local/sbin/configctl') || !is_readable('/usr/local/etc/inc/plugins.inc')) {
        printf("[SKIP] wiring: core is not on this machine\n");
        return uu_tally_report('wiring', $t);
    }
    $view = file_get_contents('/usr/local/opnsense/mvc/app/views/OPNsense/UnboundUpstream/index.volt');
    $view = $view === false ? '' : $view;
    uu_check($t, '(f4) the installed status view decodes only what core\'s escaping encodes, and builds no markup with .html(',
        str_contains($view, "return String(s === undefined || s === null ? '' : s).replace(/&lt;/g, '<')"
            . ".replace(/&gt;/g, '>').replace(/&amp;/g, '&');")
        && !str_contains($view, '.html('));
    $inc = '/usr/local/etc/inc/plugins.inc.d/unboundupstream.inc';
    uu_check($t, 'the hook file is installed (overlay the tree first)', is_readable($inc));
    if (!is_readable($inc)) {
        return uu_tally_report('wiring', $t);
    }
    require_once 'config.inc';
    require_once 'util.inc';
    require_once 'plugins.inc';
    require_once '/usr/local/opnsense/mvc/script/load_phalcon.php';
    require_once $inc;

    $hooks = unboundupstream_configure();
    ksort($hooks);
    uu_check($t, 'configure registers the hooks Unbound uses and the monitor hook with two arguments',
        $hooks === ['bootup' => ['unboundupstream_queue'], 'dns' => ['unboundupstream_queue'],
            'local' => ['unboundupstream_queue'], 'monitor' => ['unboundupstream_queue_monitor:2'],
            'newwanip' => ['unboundupstream_queue'], 'unbound_start' => ['unboundupstream_queue']]);
    uu_check($t, 'syslog registers the plugin log under its own program name',
        unboundupstream_syslog() === ['unboundupstream' => ['facility' => [UU_SYSLOG_IDENT]]]);

    /* the menu: the settings page right after Query Forwarding, the log right after Unbound's own Log File */
    $menu = uu_test_unbound_menu('/usr/local/opnsense/mvc/app/models/OPNsense/Unbound/Menu/Menu.xml')
        + uu_test_unbound_menu('/usr/local/opnsense/mvc/app/models/OPNsense/UnboundUpstream/Menu/Menu.xml');
    asort($menu);
    $names = array_keys($menu);
    $after = fn (string $name): ?string => ($i = array_search($name, $names, true)) === false ? null
        : ($names[$i + 1] ?? null);
    uu_check($t, 'menu: Upstream via Gateway follows Query Forwarding and its log follows Log File, no order shared',
        $after('Forward') === 'UnboundUpstream' && $after('LogFile') === 'UnboundUpstreamLog'
        && count(array_unique($menu)) === count($menu));

    /* section 3.11: the status privilege reads the state and nothing else; the page privilege keeps everything */
    $aclXml = simplexml_load_file('/usr/local/opnsense/mvc/app/models/OPNsense/UnboundUpstream/ACL/ACL.xml');
    $patterns = function (string $priv) use ($aclXml): array {
        return $aclXml === false ? [] : array_map('strval', $aclXml->xpath("/acl/{$priv}/patterns/pattern") ?: []);
    };
    $acl = new \OPNsense\Core\ACL();
    $allows = function (string $priv, string $url) use ($acl, $patterns): bool {
        foreach ($patterns($priv) as $mask) {
            if ($acl->urlMatch($url, $mask)) {
                return true;
            }
        }
        return false;
    };
    $writes = ['/api/unboundupstream/service/stop', '/api/unboundupstream/service/start',
        '/api/unboundupstream/service/reconfigure', '/api/unboundupstream/service/status',
        '/api/unboundupstream/settings/set', '/api/unboundupstream/settings/get', '/ui/unboundupstream',
        '/api/diagnostics/log/core/unboundupstream'];
    uu_check($t, 'ACL: the status privilege allows service/state and none of the other plugin endpoints',
        $allows('page-status-unboundupstream', '/api/unboundupstream/service/state')
        && array_filter($writes, fn (string $u): bool => $allows('page-status-unboundupstream', $u)) === []);
    uu_check($t, 'ACL: the page privilege still allows the state and every other plugin endpoint',
        $allows('page-services-unboundupstream', '/api/unboundupstream/service/state')
        && array_filter($writes, fn (string $u): bool => !$allows('page-services-unboundupstream', $u)) === []);

    /* finding L1: program() is an unanchored regex, and core's resolver log filter is program("unbound") */
    $conf = '/usr/local/etc/syslog-ng.conf.d/syslog-ng-local.conf';
    $filters = uu_test_program_filters(is_readable($conf) ? (string)file_get_contents($conf) : '');
    $selects = fn (string $pattern): bool => preg_match('~' . str_replace('~', '\~', $pattern) . '~', UU_SYSLOG_IDENT) === 1;
    $others = [];
    foreach ($filters as $name => $patterns) {
        foreach ($patterns as $pattern) {
            if ($name !== 'f_local_unboundupstream' && $selects($pattern)) {
                $others[] = "{$name} program(\"{$pattern}\")";
            }
        }
    }
    uu_check($t, 'only the plugin\'s own log filter selects its program name' . ($others === [] ? '' : ' (also: ' . implode(', ', $others) . ')'),
        in_array(true, array_map($selects, $filters['f_local_unboundupstream'] ?? []), true) && $others === []);

    $mark = 'uu-wiring-' . bin2hex(random_bytes(4));
    uu_log("{$mark} from evaluate");
    uu_logger("{$mark} from a hook");
    $deadline = hrtime(true) + 5000000000;
    while (substr_count(uu_test_log_dir('unboundupstream'), $mark) < 2 && hrtime(true) < $deadline) {
        usleep(200000);
    }
    uu_check($t, 'both log paths (openlog in evaluate, logger in hooks) reach the plugin log and not the resolver log',
        substr_count(uu_test_log_dir('unboundupstream'), $mark) === 2 && !str_contains(uu_test_log_dir('resolver'), $mark));
    uu_check($t, 'the hook file cleans what it logs with the same function as the scripts',
        unboundupstream_clean("a\x1bb\nc") === 'a?b; c' && unboundupstream_clean('plain') === 'plain');
    /* N1: a php whose open_basedir admits only core's inc directory loads the hook file but cannot read
     * lib/logline.php, as when the library is missing: the hook's own prefix stays, only the message is withheld */
    $code = 'require "' . $inc . '"; echo unboundupstream_error_line("cron: cannot read the settings: ", '
        . '"secret\nsecond line"), PHP_EOL, unboundupstream_error_line("render hook failed: ", "a\x1bb"), PHP_EOL;';
    $out = (string)shell_exec('/usr/local/bin/php -d log_errors=0 -d display_errors=0 -d open_basedir='
        . escapeshellarg(dirname($inc)) . ' -r ' . escapeshellarg($code));
    $withheld = 'message withheld, the plugin library is missing';
    if ($out !== "cron: cannot read the settings: $withheld\nrender hook failed: $withheld\n") {
        printf("  without the library: %s\n", uu_log_text(substr($out, 0, 400)));
    }
    uu_check($t, '(N1) without the plugin library a hook\'s error line keeps its prefix and withholds only the message',
        $out === "cron: cannot read the settings: $withheld\nrender hook failed: $withheld\n");
    uu_check($t, '(N1) with the library the error line is the prefix and the cleaned message',
        uu_try_case(fn (): bool => unboundupstream_error_line('cron: cannot read the settings: ', "a\x1bb\nc")
            === 'cron: cannot read the settings: a?b; c'));
    uu_check($t, 'cron is empty while the plugin is disabled', unboundupstream_cron() === []);
    uu_check($t, 'services is empty while the plugin is disabled', unboundupstream_services() === []);

    /* (r9) core lists the automatic rules from the web server's process, which cannot search the root-only run
     * directory: there the state reads as missing, with no problem, so the render's footprint read has nothing to log
     * and the listing shows the setting's rules only (spec -04 section 3.2) */
    $aside = UU_STATE_PATH . '.r9';
    $had = file_exists(UU_STATE_PATH);
    $saved = $had ? (string)file_get_contents(UU_STATE_PATH) : null;
    $r9 = null;
    uu_run_dir();
    uu_test_state_aside(UU_STATE_PATH, $aside, function (callable $place) use (&$r9): void {
        $recorded = uu_state_new();
        $recorded['resolver'] = '192.0.2.1';
        $place($recorded);
        /* one line per read, so a php that dies on the second still shows the first */
        $code = 'require "/usr/local/opnsense/scripts/OPNsense/UnboundUpstream/lib/render.php"; '
            . 'echo json_encode(uu_state_read(UU_STATE_PATH)), PHP_EOL; '
            . 'echo json_encode(uu_wanted_from(fn () => ["resolver" => "", "gateways" => null], fn () => [], '
            . 'UU_STATE_PATH)), PHP_EOL;';
        $out = (string)shell_exec('/usr/bin/su -m nobody -c '
            . escapeshellarg('/usr/local/bin/php -d log_errors=0 -r ' . escapeshellarg($code)) . ' 2>&1');
        $lines = explode("\n", $out);
        $r9 = ['root' => uu_state_read(UU_STATE_PATH), 'out' => $out,
               'nobody' => [json_decode($lines[0], true), json_decode($lines[1] ?? '', true)]];
        $r9['root_wanted'] = uu_wanted_from(fn (): array => ['resolver' => '', 'gateways' => null],
            fn (): array => [], UU_STATE_PATH);
    }, 'rename');
    $fresh = json_decode((string)json_encode(uu_state_new()), true);
    $nobody = $r9['nobody'] ?? [null, null];
    if ($r9 !== null && (!is_array($nobody[0]) || !is_array($nobody[1]))) {
        printf("  as nobody: %s\n", uu_log_text(substr($r9['out'], 0, 400)));
    }
    uu_check($t, '(r9) as nobody, a state recording a footprint reads as missing: a fresh state and no problem '
        . '(root reads its footprint)',
        ($r9['root']['state']['resolver'] ?? null) === '192.0.2.1'
        && array_key_exists('problem', $r9['root']) && $r9['root']['problem'] === null
        && is_array($nobody[0]) && array_key_exists('problem', $nobody[0]) && $nobody[0]['problem'] === null
        && ($nobody[0]['state'] ?? null) === $fresh);
    uu_check($t, '(r9) as nobody, the render\'s footprint read gives no footprint and nothing to log; as root, the '
        . 'footprint',
        is_array($nobody[1]) && array_key_exists('footprint', $nobody[1]) && $nobody[1]['footprint'] === null
        && array_key_exists('footprint_problem', $nobody[1]) && $nobody[1]['footprint_problem'] === null
        && ($r9['root_wanted']['footprint'] ?? null) === ['resolver' => '192.0.2.1', 'interface' => '']);
    uu_check($t, '(r9) the saved state is back as it was', file_exists(UU_STATE_PATH) === $had && !file_exists($aside)
        && ($had ? (string)file_get_contents(UU_STATE_PATH) : null) === $saved);

    /* I1: the state set aside is put back exactly, and a move aside that fails runs nothing and touches nothing */
    $savedState = uu_state_new();
    $savedState['resolver'] = '192.0.2.7';
    $mine = uu_state_new();
    $mine['resolver'] = '192.0.2.1';
    uu_check($t, '(I1) a move aside that fails: nothing runs, the saved state stays as it was, no aside file',
        uu_scratch_case(function (string $dir) use ($savedState, $mine): bool {
            $path = $dir . '/state.json';
            uu_state_save($path, $savedState);
            $ran = false;
            uu_test_state_aside($path, $path . '.aside', function (callable $place) use (&$ran, $mine): void {
                $ran = true;
                $place($mine);
            }, fn (string $from, string $to): bool => false);
            return !$ran && uu_state_read($path)['state'] === $savedState && !file_exists($path . '.aside');
        }));
    uu_check($t, '(I1) a body that writes its state and throws: the saved state is back, no aside file',
        uu_scratch_case(function (string $dir) use ($savedState, $mine): bool {
            $path = $dir . '/state.json';
            uu_state_save($path, $savedState);
            uu_test_state_aside($path, $path . '.aside', function (callable $place) use ($mine): void {
                $place($mine);
                throw new RuntimeException('test: the body throws');
            }, 'rename');
            return uu_state_read($path)['state'] === $savedState && !file_exists($path . '.aside');
        }));
    uu_check($t, '(I1) no saved state: the body\'s state is removed, nothing is left',
        uu_scratch_case(function (string $dir) use ($mine): bool {
            $path = $dir . '/state.json';
            uu_test_state_aside($path, $path . '.aside', function (callable $place) use ($mine): void {
                $place($mine);
            }, 'rename');
            return !file_exists($path) && !file_exists($path . '.aside');
        }));

    $files = array_map('strval', array_keys(plugins_scan()));
    $unbound = array_search('unbound', $files, true);
    $ours = array_search('unboundupstream', $files, true);
    uu_check($t, 'plugins_scan lists unbound.inc before unboundupstream.inc',
        $unbound !== false && $ours !== false && $unbound < $ours);

    $status = trim((string)shell_exec('/usr/local/sbin/configctl unboundupstream status'));
    uu_check($t, 'configctl status answers with the line the service base class reads (plugin disabled)',
        $status === 'unboundupstream is not running');
    /* finding D1: start and stop regenerate cron, so a minute job left behind goes even while disabled */
    $job = '/usr/local/sbin/configctl unboundupstream evaluate';
    $tab = (string)shell_exec('/usr/bin/crontab -l 2>/dev/null');
    $stale = tempnam('/tmp', 'uu_cron');
    if ($stale === false || file_put_contents($stale, $tab . "* * * * * $job\n") === false) {
        uu_check($t, 'a temporary crontab for the stale-job check', false);
        return uu_tally_report('wiring', $t);
    }
    shell_exec('/usr/bin/crontab ' . escapeshellarg($stale));
    unlink($stale);
    $running = trim((string)shell_exec('/usr/local/sbin/configctl unboundupstream status'));
    shell_exec('/usr/local/sbin/configctl unboundupstream stop > /dev/null');
    uu_check($t, 'status reads the minute job, and stop removes a stale one (plugin disabled)',
        $running === 'unboundupstream is running'
        && !str_contains((string)shell_exec('/usr/bin/crontab -l 2>/dev/null'), $job)
        && trim((string)shell_exec('/usr/local/sbin/configctl unboundupstream status')) === 'unboundupstream is not running');

    /* (e2) decision D4: with the plugin disabled, a state recording a footprint keeps the minute job, so a stop that
     * could not restore is retried; without one the job goes. The evaluate lock is held throughout and the minute's
     * tick is at least 20 s away, so no evaluation reads or replaces the hand-written state and no tick of the job
     * runs; the saved state, the crontab and cron's running state are put back as found */
    $e2 = null;
    $e2Aside = UU_STATE_PATH . '.e2';
    $e2Had = file_exists(UU_STATE_PATH);
    $e2Saved = $e2Had ? (string)file_get_contents(UU_STATE_PATH) : null;
    $e2Tab = (string)shell_exec('/usr/bin/crontab -l 2>/dev/null');
    $e2Cron = uu_test_cron_running();
    $e2Lock = false;
    try {
        uu_run_dir();
        $e2Lock = uu_test_evaluate_lock();
        if ($e2Lock === false) {
            throw new RuntimeException('an evaluation held the evaluate lock for 60 s');
        }
        if (!uu_test_clear_of_tick(20)) {
            throw new RuntimeException('the minute\'s tick did not move 20 s away within 60 s');
        }
        uu_test_state_aside(UU_STATE_PATH, $e2Aside, function (callable $place) use (&$e2): void {
            $recorded = uu_state_new();
            $recorded['resolver'] = '192.0.2.1';
            $place($recorded);
            $e2 = ['cron_with' => unboundupstream_cron()];
            shell_exec('/usr/local/sbin/configctl cron restart > /dev/null');
            $e2['status_with'] = trim((string)shell_exec('/usr/local/sbin/configctl unboundupstream status'));
            $e2['tab_with'] = (string)shell_exec('/usr/bin/crontab -l 2>/dev/null');
            unlink(UU_STATE_PATH);
            $e2['cron_without'] = unboundupstream_cron();
            shell_exec('/usr/local/sbin/configctl cron restart > /dev/null');
            $e2['status_without'] = trim((string)shell_exec('/usr/local/sbin/configctl unboundupstream status'));
        }, 'rename');
    } catch (\Throwable $e) {
        printf("  threw %s: %s\n", get_class($e), $e->getMessage());
    } finally {
        if ((string)shell_exec('/usr/bin/crontab -l 2>/dev/null') !== $e2Tab) {
            $found = tempnam('/tmp', 'uu_cron');
            if ($found !== false && file_put_contents($found, $e2Tab) !== false) {
                shell_exec('/usr/bin/crontab ' . escapeshellarg($found));
            }
            if ($found !== false) {
                unlink($found);
            }
        }
        if (uu_test_cron_running() !== $e2Cron) {
            shell_exec('/usr/sbin/service cron ' . ($e2Cron ? 'onestart' : 'onestop') . ' > /dev/null 2>&1');
        }
        if ($e2Lock !== false) {
            fclose($e2Lock);
        }
    }
    $minuteJob = [['autocron' => [$job, '*']]];
    if ($e2 !== null && ($e2['cron_with'] !== $minuteJob || $e2['status_with'] !== 'unboundupstream is running')) {
        printf("  with the footprint: cron %s, status '%s', crontab lines with the job: %d\n",
            json_encode($e2['cron_with']), $e2['status_with'], substr_count($e2['tab_with'], $job));
    }
    uu_check($t, '(e2) disabled, a state recording 192.0.2.1 → unboundupstream_cron() returns the minute job, and after a cron restart status reads running',
        $e2 !== null && $e2['cron_with'] === $minuteJob && $e2['status_with'] === 'unboundupstream is running');
    uu_check($t, '(e2) disabled, the state removed → no job, and after a cron restart status reads not running',
        $e2 !== null && ($e2['cron_without'] ?? null) === []
        && ($e2['status_without'] ?? null) === 'unboundupstream is not running');
    uu_check($t, '(e2) the saved state, the crontab and cron\'s running state are back as found',
        file_exists(UU_STATE_PATH) === $e2Had && !file_exists($e2Aside)
        && ($e2Had ? (string)file_get_contents(UU_STATE_PATH) : null) === $e2Saved
        && (string)shell_exec('/usr/bin/crontab -l 2>/dev/null') === $e2Tab && uu_test_cron_running() === $e2Cron);

    $state = json_decode(trim((string)shell_exec('/usr/local/sbin/configctl unboundupstream state')), true);
    uu_check($t, 'configctl state returns the status JSON', is_array($state) && isset($state['mode'], $state['members'])
        && $state['enabled'] === false);

    /* core calls the monitor hook with no arguments at boot (rc.bootup), and plugins_configure clamps the declared
     * two to what it has: the hook must take one argument, or none, without throwing */
    $plain = 'unbound-upstream evaluation ()';
    $before = substr_count(uu_test_configd_log(), $plain);
    $threw = false;
    try {
        unboundupstream_queue_monitor(false);
    } catch (\Throwable $e) {
        $threw = true;
    }
    uu_check($t, 'the monitor hook with one argument does not throw and queues a plain evaluate',
        !$threw && uu_test_wait_configd($plain, $before));
    /* rc.routing_configure's full reload passes null (system_routing_configure: no interface map) */
    $before = substr_count(uu_test_configd_log(), $plain);
    $threw = false;
    try {
        unboundupstream_queue_monitor(false, null);
    } catch (\Throwable $e) {
        $threw = true;
    }
    uu_check($t, 'the monitor hook with null (a full routing reload) does not throw and queues a plain evaluate',
        !$threw && uu_test_wait_configd($plain, $before));
    $named = 'unbound-upstream evaluation (wg-test-429,wg-test-529)';
    $before = substr_count(uu_test_configd_log(), $named);
    unboundupstream_queue_monitor(false, ['wg-test-429', 'wg-test-529']);
    uu_check($t, 'the monitor hook with names passes them to the action as one comma-joined parameter',
        uu_test_wait_configd($named, $before));
    /* pluginctl -c monitor NAMES passes the names as one string */
    $before = substr_count(uu_test_configd_log(), $named);
    unboundupstream_queue_monitor(false, 'wg-test-429,wg-test-529');
    uu_check($t, 'the monitor hook with a comma-separated string (pluginctl -c monitor) passes the same names',
        uu_test_wait_configd($named, $before));

    /* Task 10 M3: the installed evaluate.php replays a recording made before 1.3 (no contract_input.core_commands)
     * without a PHP warning; the recording is this box's own, written to a scratch directory and removed, and is
     * replayed as enabled, since a disabled plugin's plan stops before it reads the contract */
    $m3 = null;
    $script = '/usr/local/opnsense/scripts/OPNsense/UnboundUpstream/evaluate.php';
    $m3Dir = uu_scratch_dir();
    try {
        $rec = "$m3Dir/recording.json";
        $out = [];
        $rc = 0;
        exec('/usr/local/bin/php -d log_errors=0 ' . $script . ' record ' . escapeshellarg($rec) . ' > /dev/null 2>&1',
            $out, $rc);
        $doc = $rc === 0 ? json_decode((string)file_get_contents($rec), true) : null;
        if (is_array($doc) && is_array($doc['snapshot']['contract_input'] ?? null)) {
            unset($doc['snapshot']['contract_input']['core_commands']);
            $doc['snapshot']['settings']['enabled'] = true;
            file_put_contents($rec, json_encode($doc, JSON_THROW_ON_ERROR));
            exec('/usr/local/bin/php -d log_errors=0 -d display_errors=1 -d error_reporting=-1 ' . $script
                . ' replay ' . escapeshellarg($rec) . ' 2>&1', $out, $rc);
            $m3 = ['rc' => $rc, 'out' => implode("\n", $out)];
        } else {
            printf("  record exited %d and wrote no snapshot\n", $rc);
        }
    } finally {
        uu_scratch_remove($m3Dir);
    }
    $m3Warned = $m3 !== null && preg_match('/\b(Warning|Notice|Deprecated|Fatal error)\b/', $m3['out']) === 1;
    if ($m3 !== null && ($m3['rc'] !== 0 || $m3Warned)) {
        printf("  replay exited %d:\n%s\n", $m3['rc'], $m3['out']);
    }
    uu_check($t, '(M3) evaluate.php replay of a recording without contract_input.core_commands (the shape before 1.3) plans, exits 0 and prints no PHP warning',
        $m3 !== null && $m3['rc'] === 0 && !$m3Warned && str_contains($m3['out'], '"plan"'));

    $before = uu_test_evaluations();
    shell_exec('/usr/local/sbin/pluginctl -c unbound_start > /dev/null 2>&1');
    $seen = false;
    $deadline = hrtime(true) + 5000000000;
    while (hrtime(true) < $deadline) {
        if (uu_test_evaluations() > $before) {
            $seen = true;
            break;
        }
        usleep(200000);
    }
    uu_check($t, 'pluginctl -c unbound_start leads to an evaluate that configd runs within 5 s',
        $seen);
    return uu_tally_report('wiring', $t);
});
