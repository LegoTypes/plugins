<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The plugin's wiring on the test VM (spec section 3.1): the hook table, the hook order, configd's answers and
 * the evaluate that Unbound's own start leads to (seen in configd's log). Needs the tree overlaid onto the VM (vm_overlay.sh) with the
 * plugin disabled; elsewhere it registers a suite that skips. Changes nothing lasting: it adds a minute job by hand
 * for stop's cron restart to remove, runs one pluginctl unbound_start, which restarts Unbound, and writes two
 * uu-wiring marker lines to the plugin's log.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/log.php';

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

uu_register_suite('wiring', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    if (!is_executable('/usr/local/sbin/configctl') || !is_readable('/usr/local/etc/inc/plugins.inc')) {
        printf("[SKIP] wiring: core is not on this machine\n");
        return uu_tally_report('wiring', $t);
    }
    $inc = '/usr/local/etc/inc/plugins.inc.d/unboundupstream.inc';
    uu_check($t, 'the hook file is installed (overlay the tree first)', is_readable($inc));
    if (!is_readable($inc)) {
        return uu_tally_report('wiring', $t);
    }
    require_once 'config.inc';
    require_once 'util.inc';
    require_once 'plugins.inc';
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
    uu_check($t, 'cron is empty while the plugin is disabled', unboundupstream_cron() === []);
    uu_check($t, 'services is empty while the plugin is disabled', unboundupstream_services() === []);

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
    $named = 'unbound-upstream evaluation (wg-test-429,wg-test-529)';
    $before = substr_count(uu_test_configd_log(), $named);
    unboundupstream_queue_monitor(false, ['wg-test-429', 'wg-test-529']);
    uu_check($t, 'the monitor hook with names passes them to the action as one comma-joined parameter',
        uu_test_wait_configd($named, $before));

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
