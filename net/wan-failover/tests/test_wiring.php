<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The plugin's entry scripts as the box runs them. Needs the test VM: the suite runs from vm_selftest.sh, where
 * core's files exist (evaluate.php loads core's script/load_phalcon.php), and runs the tree's own scripts with the
 * VM's php. Changes nothing lasting.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/constants.php';

/**
 * One run of a tree script under the VM's php, stdout and stderr together.
 *
 * @param list<string> $args
 * @return array{rc: int, out: string}
 */
function wf_t_run_script(string $script, array $args): array
{
    $proc = proc_open(array_merge(['/usr/local/bin/php', '-d', 'log_errors=0', $script], $args),
        [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['redirect', 1]], $pipes);
    if ($proc === false) {
        return ['rc' => -1, 'out' => "cannot start {$script}"];
    }
    $out = (string)stream_get_contents($pipes[1]);
    fclose($pipes[1]);
    return ['rc' => proc_close($proc), 'out' => $out];
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
    return wf_tally_report('wiring', $t);
});
