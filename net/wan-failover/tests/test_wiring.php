<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The plugin's entry scripts as the box runs them, and the package scripts as the package ships them. Needs the test
 * VM: the suite runs from vm_selftest.sh, where core's files exist (evaluate.php loads core's script/load_phalcon.php),
 * and runs the tree's own scripts with the VM's php. Changes nothing lasting.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/constants.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/contract.php';

/**
 * One run of a command, stdout and stderr together.
 *
 * @param list<string> $argv
 * @return array{rc: int, out: string}
 */
function wf_t_run(array $argv): array
{
    $proc = proc_open($argv, [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['redirect', 1]], $pipes);
    if ($proc === false) {
        return ['rc' => -1, 'out' => "cannot start {$argv[0]}"];
    }
    $out = (string)stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    return ['rc' => proc_close($proc), 'out' => $out];
}

/**
 * One run of a tree script under the VM's php.
 *
 * @param list<string> $args
 * @return array{rc: int, out: string}
 */
function wf_t_run_script(string $script, array $args): array
{
    return wf_t_run(array_merge(['/usr/local/bin/php', '-d', 'log_errors=0', $script], $args));
}

/**
 * What a path holds, to tell whether a run wrote it: null when absent.
 *
 * @return ?array{ino: int, size: int, mtime: int, sha256: string}
 */
function wf_t_file_id(string $path): ?array
{
    clearstatcache(true, $path);
    $st = @lstat($path);
    if ($st === false) {
        return null;
    }
    return ['ino' => $st['ino'], 'size' => $st['size'], 'mtime' => $st['mtime'],
            'sha256' => is_file($path) ? (string)hash_file('sha256', $path) : ''];
}

wf_register_suite('wiring', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $evaluate = dirname(__DIR__) . '/src/opnsense/scripts/OPNsense/WanFailover/evaluate.php';

    /* 1.3_1 wrote the snapshot to this fixed /tmp name when no path was given */
    $old = '/tmp/wanfailover.snapshot.json';
    $before = wf_t_file_id($old);
    $r = wf_t_run_script($evaluate, ['--snapshot']);
    $after = wf_t_file_id($old);
    $ok = $r['rc'] === 1 && str_contains($r['out'], 'usage: evaluate.php --snapshot FILE') && $after === $before;
    wf_check($t, "(w1) evaluate.php --snapshot without a path exits 1, prints its usage and writes no {$old}", $ok);
    if (!$ok) {
        printf("    exit %d, output: %s\n    %s before: %s, after: %s\n", $r['rc'], trim($r['out']) === '' ? '(none)' : trim($r['out']),
            $old, json_encode($before), json_encode($after));
    }
    /* the plugin's name mask is core's own, so a name core accepts is never refused here (the D flag aside) */
    $xml = @simplexml_load_file('/usr/local/opnsense/mvc/app/models/OPNsense/Routing/Gateways.xml');
    $core = $xml === false ? '' : (string)($xml->items->gateway_item->name->Mask ?? '');
    $ours = substr(WF_GATEWAY_NAME_MASK, 0, -1);
    $ok = $core !== '' && $core === $ours;
    wf_check($t, "(w2) WF_GATEWAY_NAME_MASK equals the Mask of the name field in core's Gateways.xml", $ok);
    if (!$ok) {
        printf("    core: %s\n    ours: %s\n", $core === '' ? '(not read)' : $core, WF_GATEWAY_NAME_MASK);
    }
    /* the installed action, as a hold calls it through configd: no state routes via a documentation address on lo0 */
    $r = wf_t_run(['/usr/local/sbin/configctl', 'wanfailover', 'kill_states', '192.0.2.250@lo0']);
    $ok = trim($r['out']) === 'killed 0 states (0 failed)';
    wf_check($t, '(w3) configctl wanfailover kill_states 192.0.2.250@lo0 answers "killed 0 states (0 failed)"', $ok);
    if (!$ok) {
        printf("    exit %d, output: %s\n", $r['rc'], trim($r['out']) === '' ? '(none)' : trim($r['out']));
    }
    $r = wf_t_run_script($evaluate, ['kill-states', 'x;y']);
    $ok = $r['rc'] === 1 && trim($r['out']) === 'rejected target';
    wf_check($t, "(w3) the tree's evaluate.php kill-states 'x;y' exits 1 with \"rejected target\"", $ok);
    if (!$ok) {
        printf("    exit %d, output: %s\n", $r['rc'], trim($r['out']) === '' ? '(none)' : trim($r['out']));
    }
    /* configd answers "Execute error" for a script that exits non-zero unless its action sets errors:no; a hold
     * logs what the action answered, so a failed kill's own line must come through */
    $r = wf_t_run(['/usr/local/sbin/configctl', 'wanfailover', 'kill_states', 'x;y']);
    $ok = trim($r['out']) === 'rejected target';
    wf_check($t, '(w4) through configd, a kill that exits 1 still answers its own line ("rejected target")', $ok);
    if (!$ok) {
        printf("    exit %d, output: %s\n", $r['rc'], trim($r['out']) === '' ? '(none)' : trim($r['out']));
    }
    /* the tree's own Holds model, not the installed one: core reads a model's XML beside its class file. A settings
     * save rewrites the whole settings node from the settings model's fields, so the hold records live beside that
     * node, and the settings model declares no held list the API could post */
    $models = dirname(__DIR__) . '/src/opnsense/mvc/app/models/OPNsense/WanFailover';
    $r = wf_t_run(['/usr/local/bin/php', '-d', 'log_errors=0', '-r', 'require_once "script/load_phalcon.php"; require_once '
        . var_export("{$models}/Holds.php", true)
        . '; echo is_array((new \OPNsense\WanFailover\Holds())->records()) ? "loaded" : "no records";']);
    $holds = @simplexml_load_file("{$models}/Holds.xml");
    $mount = $holds === false ? '' : (string)$holds->mount;
    $settings = @simplexml_load_file("{$models}/WanFailover.xml");
    $ok = trim($r['out']) === 'loaded' && $mount !== '' && !str_starts_with("{$mount}/", '//OPNsense/WanFailover/')
        && $settings !== false && !isset($settings->items->held);
    wf_check($t, "(w5) the tree's Holds model loads, its mount is not under //OPNsense/WanFailover, and the settings model has no held", $ok);
    if (!$ok) {
        printf("    load: exit %d, output: %s\n    mount: %s\n    settings model: %s\n", $r['rc'],
            trim($r['out']) === '' ? '(none)' : trim($r['out']), $mount === '' ? '(not read)' : $mount,
            $settings === false ? '(not read)' : (isset($settings->items->held) ? 'declares held' : 'no held'));
    }
    /* the package scripts as the package ships them (vm_selftest.sh uploads them beside src/): pkg's payload check
     * refuses anything but printable ASCII with a final newline */
    $scripts = [];
    foreach (['+PRE_DEINSTALL.pre', '+POST_DEINSTALL.post', '+POST_INSTALL.pre', '+POST_INSTALL.post'] as $name) {
        $text = @file_get_contents(dirname(__DIR__) . "/{$name}");
        $scripts[$name] = $text === false ? '' : $text;
        $ok = $text !== false && preg_match('/\A[\x20-\x7e\n]*\n\z/', $text) === 1;
        wf_check($t, "(d6) {$name} is printable ASCII and ends with a newline", $ok);
    }
    $guard = 'if [ -z "${PKG_UPGRADE:-}" ]';
    $pre = $scripts['+PRE_DEINSTALL.pre'];
    $mk = strpos($pre, "\n    mkdir -p -m 700 " . WF_RUN_DIR . "\n");
    $touch = strpos($pre, "\n    touch " . WF_REMOVING . " || true\n");
    $php = strpos($pre, "\n    /usr/local/bin/php -d log_errors=0 /usr/local/opnsense/scripts/OPNsense/WanFailover/evaluate.php deinstall"
        . " > /dev/null 2>&1 || true\n");
    wf_check($t, '(d6) +PRE_DEINSTALL.pre runs on a real removal only: the guard, then the run directory, the marker and the deinstall, in that order',
        str_starts_with($pre, "#!/bin/sh\n")
        && str_contains($pre, $guard . ' && [ -f /usr/local/opnsense/scripts/OPNsense/WanFailover/evaluate.php ]; then')
        && $mk !== false && $touch !== false && $php !== false && $mk < $touch && $touch < $php
        && strpos($pre, $guard) < $mk);
    wf_check($t, '(d6) +POST_DEINSTALL.post removes the plugin\'s directories on a real removal only',
        str_contains($scripts['+POST_DEINSTALL.post'], $guard . "; then\n    rm -rf " . WF_RUN_DIR . ' /var/db/wanfailover ' . WF_TRACE . "\nfi\n")
        && dirname(WF_STATE) === '/var/db/wanfailover');
    $cron = "\n/usr/bin/timeout " . WF_CONFIGD_TIMEOUT_SECONDS . ' /usr/local/sbin/configctl cron restart | grep -qx OK || '
        . WF_CORE_CRON_RESTART . " || true\n";
    $post = $scripts['+POST_DEINSTALL.post'];
    $fi = strpos($post, "\nfi\n");
    $restart = strpos($post, $cron);
    wf_check($t, '(d11) +POST_DEINSTALL.post then restarts cron, outside the guard, through configd read for OK, else core\'s own '
        . 'command: core\'s removal step leaves the minute job in crontab otherwise',
        $fi !== false && $restart !== false && $restart > $fi && str_ends_with($post, $cron)
        && WF_CORE_CRON_RESTART === '/usr/local/sbin/pluginctl -s cron restart');
    if ($restart === false) {
        printf("    wanted the line: %s", ltrim($cron, "\n"));
    }
    wf_check($t, '(d13) +POST_INSTALL.post ends with the same cron restart: core\'s install step leaves a reinstall that comes '
        . 'back enabled without its minute job otherwise',
        str_ends_with($scripts['+POST_INSTALL.post'], $cron));
    /* the box's own core, as the removal finds it */
    $actions = @file_get_contents('/usr/local/opnsense/service/conf/actions.d/actions_cron.conf');
    $section = $actions === false ? null : wf_ini_section($actions, 'restart');
    $core = $section === null ? null : wf_ini_command($section);
    wf_check($t, "(d11) WF_CORE_CRON_RESTART is the command of core's [restart] in actions_cron.conf", $core === WF_CORE_CRON_RESTART);
    if ($core !== WF_CORE_CRON_RESTART) {
        printf("    core: %s\n    ours: %s\n", $core ?? '(not read)', WF_CORE_CRON_RESTART);
    }
    wf_check($t, '(d6) +POST_INSTALL.pre removes the removal marker',
        preg_match('/^rm -f ' . preg_quote(WF_REMOVING, '/') . '$/m', $scripts['+POST_INSTALL.pre']) === 1);
    /* the marker's gate in evaluate.php: kill-states must stay above it, since a hold's evaluation calls it while it
     * holds the lock; every mode that acts or writes, and the held list's import, below it */
    $src = (string)@file_get_contents($evaluate);
    $gate = strpos($src, "\n    if (wf_removing()) {\n");
    $above = ["if (\$mode === '--plan-from')", "if (\$mode === 'kill-states')", "if (\$mode === 'status')",
              "if (\$mode === 'holds')", "if (\$mode === 'deinstall')"];
    $below = ["if (\$mode === 'start' || \$mode === 'stop')", "if (\$mode === '--snapshot')", "if (\$mode === '--dry')",
              "\$lock = wf_lock_open(WF_RUN_DIR . '/evaluate.lock');", 'wf_holds_import_legacy('];
    $misplaced = [];
    foreach ($above as $needle) {
        $at = strpos($src, $needle);
        if ($gate === false || $at === false || $at > $gate) {
            $misplaced[] = $needle;
        }
    }
    foreach ($below as $needle) {
        $at = strpos($src, $needle);
        if ($gate === false || $at === false || $at < $gate) {
            $misplaced[] = $needle;
        }
    }
    wf_check($t, '(d7) evaluate.php\'s removal gate comes after --plan-from, kill-states, status, holds and deinstall, and '
        . 'before start, stop, --snapshot, --dry, the lock and the held list\'s import', $misplaced === []);
    if ($misplaced !== []) {
        printf("    gate at %s; misplaced: %s\n", $gate === false ? '(not found)' : (string)$gate, implode(' | ', $misplaced));
    }
    wf_check($t, "evaluate.php's dry run says what the failback gate would do, through wf_failback_dry()",
        str_contains($src, 'wf_log(wf_failback_dry($n, wf_snapshot_pf($wanTargets), $wanTargets, $fb[\'top\']));')
        && !str_contains($src, 'would kill'));
    /* a cron-only drift is a removal drift too, and must not stop the removal running core's routing command itself */
    wf_check($t, '(d12) the removal decides its routing fallback with wf_contract_routes_fallback(), not from an empty removal list',
        str_contains($src, "wf_contract_routes_fallback(\$snap['contract']['removal'])")
        && !str_contains($src, "\$snap['contract']['removal'] === []"));
    $boot = (string)@file_get_contents(dirname($evaluate) . '/boot.php');
    wf_check($t, '(d7) boot.php checks the removal marker before it reads or writes anything',
        str_contains($boot, "\ntry {\n    if (wf_removing()) {\n        exit(0);\n    }\n    \$bootId = wf_boot_id();\n"));
    $service = (string)@file_get_contents(dirname(__DIR__)
        . '/src/opnsense/mvc/app/controllers/OPNsense/WanFailover/Api/ServiceController.php');
    wf_check($t, 'the service controller names its actions failbackNowAction and wanStatusAction',
        str_contains($service, 'function failbackNowAction(') && str_contains($service, 'function wanStatusAction(')
        && !str_contains($service, 'function failbacknowAction(') && !str_contains($service, 'function holdsAction('));
    /* the tree's snapshot, as an evaluation takes it, of WAN_DHCP and WAN_B selected with WAN_B's monitoring off: both
     * changed in the child's configuration object only (serialized, never saved), with config.xml's md5 as the guard */
    $config = '/conf/config.xml';
    $before = md5_file($config);
    $r = wf_t_run(['/usr/local/bin/php', '-d', 'log_errors=0', '-r', 'require_once "script/load_phalcon.php"; require_once '
        . var_export(dirname($evaluate) . '/lib/snapshot.php', true) . ';
        $ids = [];
        $gateways = new \OPNsense\Routing\Gateways();
        foreach ($gateways->gateway_item->iterateItems() as $uuid => $gw) {
            $ids[$gw->name->getValue()] = (string)$uuid;
            if ($gw->name->getValue() === "WAN_B") {
                $gw->monitor_disable->setValue("1");
            }
        }
        $gateways->serializeToConfig(false, true);
        $m = new \OPNsense\WanFailover\WanFailover();
        $m->wans->setValue(($ids["WAN_DHCP"] ?? "") . "," . ($ids["WAN_B"] ?? ""));
        $m->serializeToConfig(false, true);
        $s = wf_snapshot();
        $wans = [];
        foreach ($s["wans"] as $n => $w) {
            $wans[$n] = [$w["disabled"], $w["monitor_disable"], wf_unjudgeable($w)];
        }
        echo json_encode(["wans" => $wans, "judging" => $s["contract"]["judging"]]);']);
    $written = md5_file($config) !== $before;
    $got = json_decode(trim($r['out']), true);
    $ok = $r['rc'] === 0 && !$written && $got === ['wans' => ['WAN_DHCP' => [false, false, null],
        'WAN_B' => [false, true, 'monitor_disable']], 'judging' => []];
    wf_check($t, "the tree's snapshot of WAN_DHCP and WAN_B with WAN_B's monitoring off carries each WAN's disabled and "
        . 'monitor_disable, and reads no judging drift', $ok);
    if (!$ok) {
        printf("    exit %d, config.xml %s, output: %s\n", $r['rc'], $written ? 'WRITTEN: restore the VM to the '
            . "'wan-failover base' checkpoint" : 'unchanged', trim($r['out']) === '' ? '(none)' : trim($r['out']));
    }
    /* the run-time names check against the box's own core, at the path the snapshot reads */
    $names = wf_contract_name_mask(is_readable(WF_CORE_GATEWAYS_XML) ? (string)file_get_contents(WF_CORE_GATEWAYS_XML) : null);
    wf_check($t, "the box's own Gateways.xml mask reports no drift", $names === []);
    if ($names !== []) {
        printf("    %s: %s\n", WF_CORE_GATEWAYS_XML, implode('; ', $names));
    }
    return wf_tally_report('wiring', $t);
});
