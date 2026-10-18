<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The plugin's wiring on the test VM (spec section 3.1): the hook table, the hook order, configd's answers and
 * the evaluate that Unbound's own start leads to (seen in configd's log). Needs the tree overlaid onto the VM (vm_overlay.sh) with the
 * plugin disabled; elsewhere it registers a suite that skips. Changes nothing but runs one pluginctl
 * unbound_start, which restarts Unbound.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';

const UU_TEST_CONFIGD_LOG = '/var/log/configd/latest.log';

/**
 * How many times configd has finished the plugin's evaluate action. A disabled plugin evaluates quietly (its own
 * log stays empty), so configd's log is the witness that a hook queued one.
 */
function uu_test_evaluations(): int
{
    return substr_count((string)@file_get_contents(UU_TEST_CONFIGD_LOG), '[unboundupstream evaluate] returned');
}

/** Wait up to 5 s for configd's log to show $needle more often than $before times. */
function uu_test_wait_configd(string $needle, int $before): bool
{
    $deadline = hrtime(true) + 5000000000;
    while (hrtime(true) < $deadline) {
        if (substr_count((string)@file_get_contents(UU_TEST_CONFIGD_LOG), $needle) > $before) {
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
    uu_check($t, 'syslog registers the plugin facility',
        unboundupstream_syslog() === ['unboundupstream' => ['facility' => ['unboundupstream']]]);
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
    $state = json_decode(trim((string)shell_exec('/usr/local/sbin/configctl unboundupstream state')), true);
    uu_check($t, 'configctl state returns the status JSON', is_array($state) && isset($state['mode'], $state['members'])
        && $state['enabled'] === false);

    /* core calls the monitor hook with no arguments at boot (rc.bootup), and plugins_configure clamps the declared
     * two to what it has: the hook must take one argument, or none, without throwing */
    $plain = 'unbound-upstream evaluation ()';
    $before = substr_count((string)@file_get_contents(UU_TEST_CONFIGD_LOG), $plain);
    $threw = false;
    try {
        unboundupstream_queue_monitor(false);
    } catch (\Throwable $e) {
        $threw = true;
    }
    uu_check($t, 'the monitor hook with one argument does not throw and queues a plain evaluate',
        !$threw && uu_test_wait_configd($plain, $before));
    $named = 'unbound-upstream evaluation (wg-test-429,wg-test-529)';
    $before = substr_count((string)@file_get_contents(UU_TEST_CONFIGD_LOG), $named);
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
