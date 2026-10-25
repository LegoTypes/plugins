<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Runtime state, held reconciliation and boot reset, spec 3.8 and 3.11; the plugin's files: root's alone, read as
 * regular files only, the state's shape checked on load, and the crash-test flag.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/state.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/log.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/judge.php';

/** A fresh, empty scratch directory under the system's temporary directory. */
function wf_t_scratch(string $case): string
{
    $dir = rtrim(sys_get_temp_dir(), '/') . "/wf-test-{$case}-" . getmypid();
    wf_t_rmtree($dir);
    mkdir($dir, 0755);
    return $dir;
}

/** Remove a scratch tree; a symbolic link is removed itself, never followed. */
function wf_t_rmtree(string $path): void
{
    clearstatcache(true, $path);
    $st = @lstat($path);
    if ($st === false) {
        return;
    }
    if (($st['mode'] & 0170000) === 0040000) {
        foreach (scandir($path) ?: [] as $name) {
            if ($name !== '.' && $name !== '..') {
                wf_t_rmtree("{$path}/{$name}");
            }
        }
        rmdir($path);
    } else {
        unlink($path);
    }
}

function wf_t_mode(string $path): int
{
    clearstatcache(true, $path);
    $st = @lstat($path);
    return $st === false ? -1 : $st['mode'] & 07777;
}

wf_register_suite('state', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $fd = ['PRIMARY_WAN' => false, 'WAN2' => true];
    /* hold records as the snapshot resolves them, each stamped with a boot id: b500 is the live boot */
    $rec = function (string $boot, string ...$names): array {
        return array_fill_keys($names, ['boot' => $boot, 'since' => 100]);
    };

    $r = wf_reconcile($rec('b500', 'WAN2'), $fd, [], ['WAN2'], 'b500');
    wf_check($t, 'held with force_down=1 is owned', $r['owned'] === ['WAN2'] && $r['foreign'] === []);
    $r = wf_reconcile($rec('b500', 'WAN2'), ['WAN2' => false], [], ['WAN2'], 'b500');
    wf_check($t, 'held with force_down=0 was released by hand', $r['owned'] === [] && $r['manual_released'] === ['WAN2']);
    $r = wf_reconcile($rec('b500', 'WAN2'), $fd, ['WAN2' => 'hold'], [], 'b500');
    wf_check($t, 'pending hold that landed: redo replay and kill (N5a), not foreign', $r['redo_apply'] === ['WAN2']
        && $r['apply_pending'] === ['WAN2' => 'hold'] && $r['foreign'] === []);
    $r = wf_reconcile([], $fd, ['WAN2' => 'hold'], [], 'b500');
    wf_check($t, 'pending hold that never saved: dropped', $r['redo_apply'] === [] && $r['apply_pending'] === []);
    $r = wf_reconcile([], ['WAN2' => false], ['WAN2' => 'release'], ['WAN2'], 'b500');
    wf_check($t, 'pending release that landed: redo replay, not foreign', $r['redo_replay'] === ['WAN2'] && $r['foreign'] === []);
    $r = wf_reconcile($rec('b500', 'WAN2'), $fd, ['WAN2' => 'release'], ['WAN2'], 'b500');
    wf_check($t, 'pending release that never saved: dropped', $r['redo_replay'] === [] && $r['apply_pending'] === []);
    $r = wf_reconcile($rec('b500', 'WAN2'), $fd, [], [], 'b500');
    wf_check($t, 'held gained outside the engine (a revert): foreign (R3-8)', $r['foreign'] === ['WAN2']);
    $r = wf_reconcile([], $fd, [], ['WAN2'], 'b500');
    wf_check($t, 'held lost outside the engine: foreign', $r['foreign'] === ['WAN2']);
    $r = wf_reconcile($rec('b500', 'GONE'), $fd, [], ['GONE'], 'b500');
    wf_check($t, 'a held name with no gateway in config is neither owned nor manual', $r['owned'] === [] && $r['manual_released'] === []);

    $fdB = ['WAN_A' => false, 'WAN_B' => true];
    $foreignLine = 'hold record for WAN_B from another boot or box; not ours, left alone';
    $r = wf_reconcile($rec('b500', 'WAN_B'), $fdB, [], ['WAN_B'], 'b500');
    wf_check($t, '(o1) a record of the live boot whose gateway reads force_down 1 is owned',
        $r['owned'] === ['WAN_B'] && $r['foreign_records'] === [] && $r['unproven'] === [] && $r['manual_released'] === []);
    $r = wf_reconcile($rec('deadbeef', 'WAN_B'), $fdB, [], ['WAN_B'], 'b500');
    wf_check($t, '(o2) a record of another boot is foreign: not owned, not released by hand, logged with the spec\'s line',
        $r['foreign_records'] === ['WAN_B'] && $r['owned'] === [] && $r['manual_released'] === []
        && $r['log'] === [$foreignLine]);
    $r = wf_reconcile($rec('b400', 'WAN_B'), $fdB, [], ['WAN_B'], 'b500');
    wf_check($t, '(o3) at runtime a record of the previous boot proves nothing: foreign',
        $r['foreign_records'] === ['WAN_B'] && $r['owned'] === []);
    $r = wf_reconcile($rec('b400', 'WAN_B'), $fdB, [], ['WAN_B'], 'b500', 'b400');
    wf_check($t, '(o3) the previous boot passed by the boot detector proves it: owned',
        $r['owned'] === ['WAN_B'] && $r['foreign_records'] === []);
    $r = wf_reconcile($rec('b500', 'WAN_B'), ['WAN_A' => false, 'WAN_B' => false], [], ['WAN_B'], 'b500');
    wf_check($t, '(o4) a record of the live boot whose gateway reads force_down 0 was released by hand',
        $r['manual_released'] === ['WAN_B'] && $r['owned'] === [] && $r['foreign_records'] === []);
    $r = wf_reconcile($rec('deadbeef', 'WAN_B'), $fdB, [], [], 'b500');
    $r2 = wf_reconcile([], $fdB, [], ['WAN_B'], 'b500');
    wf_check($t, '(o5) a record that appeared outside the engine, and one that vanished, each re-sync routing once',
        $r['foreign'] === ['WAN_B'] && $r2['foreign'] === ['WAN_B']
        && count(array_filter($r['log'], fn (string $l): bool => str_contains($l, 'outside the engine'))) === 1);
    $three = $rec('b400', 'WAN_A') + $rec('b500', 'WAN_B') + $rec('deadbeef', 'WAN_C');
    wf_check($t, '(o6) the boot release set is the records stamped with the state\'s boot id, and none for an unread one',
        wf_boot_release_set($three, 'b400') === ['WAN_A'] && wf_boot_release_set($three, '') === []
        && wf_boot_release_set($three, 'corrupt') === []);
    $r = wf_reconcile($three, ['WAN_A' => true, 'WAN_B' => true, 'WAN_C' => false], [], ['WAN_A', 'WAN_B', 'WAN_C'], '');
    wf_check($t, '(o7) with the live boot id unreadable every record is unproven: kept, neither owned, released by hand nor foreign '
        . '(the planner says so once)',
        $r['unproven'] === ['WAN_A', 'WAN_B', 'WAN_C'] && $r['owned'] === [] && $r['manual_released'] === []
        && $r['foreign_records'] === [] && $r['log'] === []);

    $noList = ['present' => false, 'release' => [], 'left' => [], 'unknown' => 0];
    $b = wf_boot_outcome($three, 0, 'b400', $noList);
    wf_check($t, '(b1) at boot the previous boot\'s records are released and the others pruned, in one note',
        $b['release'] === ['WAN_A'] && $b['pruned'] === ['WAN_B', 'WAN_C']
        && $b['note'] === "boot: released WAN_A; pruned WAN_B,WAN_C (not this plugin's)");
    $b = wf_boot_outcome($rec('b400', 'WAN_A'), 2, 'b400', $noList);
    wf_check($t, '(b1) stale or duplicate rows are dropped and counted in the note',
        $b['release'] === ['WAN_A'] && $b['pruned'] === []
        && $b['note'] === 'boot: released WAN_A; dropped 2 records that name no gateway or repeat one');
    $b = wf_boot_outcome($three, 0, 'corrupt', $noList);
    $b2 = wf_boot_outcome($three, 0, '', $noList);
    wf_check($t, '(b2) at boot with the state unreadable nothing is released or pruned, and the note says so',
        $b['release'] === [] && $b['pruned'] === [] && $b['note'] === 'boot: state unreadable; no hold released' && $b2 === $b);

    $s = wf_state_new('b500');
    $s['installed_at'] = 400;
    $s['judgements']['WAN2'] = ['value' => 'bad'] + wf_judgement_new(400);
    $s['apply_pending'] = ['WAN2' => 'hold'];
    $s['last_held'] = ['WAN2'];
    $s['foreign_pruned'] = ['WAN_B' => 390];
    $b = wf_boot_reset($s, 'b900');
    wf_check($t, 'boot reset clears judgements, apply_pending, last_held; keeps installed_at', $b['judgements'] === []
        && $b['apply_pending'] === [] && $b['last_held'] === [] && $b['installed_at'] === 400 && $b['boot_id'] === 'b900');
    wf_check($t, '(b3) boot reset keeps the foreign records pruned within the hour, for the page', $b['foreign_pruned'] === ['WAN_B' => 390]);
    unset($s['foreign_pruned']);

    $dir = sys_get_temp_dir() . '/wf-test-' . getmypid();
    $path = "{$dir}/state.json";
    wf_state_save($path, $s);
    $l = wf_state_load($path, 'b500');
    wf_check($t, 'save creates the directory and round-trips', !$l['corrupt'] && $l['state']['apply_pending'] === ['WAN2' => 'hold']);
    file_put_contents($path, '{"version":3,"judgements":');
    $l = wf_state_load($path, 'b500');
    wf_check($t, 'RF2: truncated file loads fresh, flagged corrupt', $l['corrupt'] && $l['state']['judgements'] === []);
    file_put_contents($path, '{"version":2,"boot_time":1791270672}');
    $l = wf_state_load($path, 'b500');
    wf_check($t, 'another state version loads fresh with the live boot id, not flagged corrupt (no release on upgrade)',
        !$l['corrupt'] && $l['state']['version'] === 3 && $l['state']['boot_id'] === 'b500');
    unlink($path);
    $l = wf_state_load($path, 'b500');
    wf_check($t, 'missing file loads fresh, not corrupt', !$l['corrupt'] && $l['state']['boot_id'] === 'b500');
    @rmdir($dir);
    $tdir = sys_get_temp_dir() . '/wf-trace-' . getmypid();
    mkdir($tdir);
    touch("{$tdir}/trace-20260901.jsonl", 1000);
    touch("{$tdir}/trace-20260930.jsonl", 1000 + 6 * 86400);
    wf_trace_prune($tdir, 1000 + 8 * 86400, 7);
    wf_check($t, 'trace prune removes files older than the keep window, keeps newer ones',
        !is_file("{$tdir}/trace-20260901.jsonl") && is_file("{$tdir}/trace-20260930.jsonl"));
    unlink("{$tdir}/trace-20260930.jsonl");
    rmdir($tdir);

    $fresh = fn (array $l): bool => $l['state']['boot_id'] === 'b500' && $l['state']['judgements'] === [];
    $d = wf_t_scratch('s1');
    file_put_contents("{$d}/real.json", json_encode(wf_state_new('b100')));
    symlink("{$d}/real.json", "{$d}/state.json");
    $l = wf_state_load("{$d}/state.json", 'b500');
    wf_check($t, '(s1) a symbolic link to a valid state file loads fresh, corrupt, as a symbolic link',
        $fresh($l) && $l['corrupt'] && $l['problem'] === 'a symbolic link');
    wf_t_rmtree($d);
    $d = wf_t_scratch('s2');
    mkdir("{$d}/state.json");
    $l = wf_state_load("{$d}/state.json", 'b500');
    wf_check($t, '(s2) a directory at the path loads fresh, corrupt, as not a regular file',
        $fresh($l) && $l['corrupt'] && $l['problem'] === 'not a regular file');
    wf_t_rmtree($d);
    $d = wf_t_scratch('s3');
    $json = json_encode(wf_state_new('b100'));
    file_put_contents("{$d}/state.json", $json . str_repeat(' ', 1048577 - strlen($json)));
    $l = wf_state_load("{$d}/state.json", 'b500');
    wf_check($t, '(s3) a state file of 1 MiB + 1 byte (valid JSON) loads fresh, corrupt, as larger than 1 MiB',
        filesize("{$d}/state.json") === 1048577 && $fresh($l) && $l['corrupt'] && $l['problem'] === 'larger than 1 MiB');
    $l = wf_state_load("{$d}/missing.json", 'b500');
    wf_check($t, '(s3) a missing path loads fresh, not corrupt, with no problem', $fresh($l) && !$l['corrupt'] && $l['problem'] === null);
    file_put_contents("{$d}/state.json", '{"version":3,"judgements":');
    $l = wf_state_load("{$d}/state.json", 'b500');
    wf_check($t, '(s3) a truncated file is named as not JSON', $l['corrupt'] && $l['problem'] === 'not JSON');
    wf_t_rmtree($d);

    $d = wf_t_scratch('s4');
    file_put_contents("{$d}/state.json", '{"version":3,"boot_id":"b500","gateway_ips":{"WAN_A":"not-an-ip","WAN_B":"198.51.100.1"}}');
    $l = wf_state_load("{$d}/state.json", 'b500');
    wf_check($t, '(s4) a gateway_ips entry that is no IPv4 address is dropped, the others kept, not corrupt',
        !$l['corrupt'] && $l['problem'] === null && $l['state']['gateway_ips'] === ['WAN_B' => '198.51.100.1']);
    file_put_contents("{$d}/state.json", '{"version":3,"boot_id":"b100","installed_at":null,"boot_note":"boot: released WAN_B"}');
    $l = wf_state_load("{$d}/state.json", 'b500');
    wf_check($t, '(s4) a nullable field may be null or its type; a field the file lacks takes its default',
        !$l['corrupt'] && $l['state']['boot_id'] === 'b100' && $l['state']['installed_at'] === null
        && $l['state']['boot_note'] === 'boot: released WAN_B' && $l['state']['last_held'] === []);
    foreach (['"judgements":"x"' => 'judgements a string', '"last_held":"WAN_A"' => 'last_held a string',
              '"installed_at":"400"' => 'installed_at a string'] as $field => $what) {
        file_put_contents("{$d}/state.json", '{"version":3,' . $field . '}');
        $l = wf_state_load("{$d}/state.json", 'b500');
        wf_check($t, "(s5) {$what} loads fresh, corrupt, as not this version's shape",
            $fresh($l) && $l['corrupt'] && $l['problem'] === "not this version's shape");
    }
    foreach (['{"version":"3"}' => 'a string version', '{"judgements":[]}' => 'no version', '"x"' => 'a JSON string'] as $text => $what) {
        file_put_contents("{$d}/state.json", $text);
        $l = wf_state_load("{$d}/state.json", 'b500');
        wf_check($t, "(s5) {$what} loads fresh, corrupt, as not this version's shape",
            $fresh($l) && $l['corrupt'] && $l['problem'] === "not this version's shape");
    }

    $jv = wf_judgement_new(100);
    $tsv = wf_ts_new();
    $without = function (array $a, string $key): array {
        unset($a[$key]);
        return $a;
    };
    $nested = [
        'a judgement whose since is "x"' => ['judgements' => ['WAN_A' => ['since' => 'x'] + $jv]],
        'a judgement without recovering' => ['judgements' => ['WAN_A' => $without($jv, 'recovering')]],
        'a judgement that is a number' => ['judgements' => ['WAN_A' => 5]],
        'a pending failback whose since is "x"' => ['pending_failbacks' => ['WAN_A' => ['since' => 'x']]],
        'a pending failback whose due is "x"' => ['pending_failbacks' => ['WAN_A' => ['since' => 100, 'due' => 'x']]],
        'a pending failback without since' => ['pending_failbacks' => ['WAN_A' => ['due' => 100]]],
        'ts whose cur_since is "x"' => ['ts' => ['cur_since' => 'x'] + $tsv],
        'ts without lost' => ['ts' => $without($tsv, 'lost')],
        'a no_rehold value false' => ['no_rehold' => ['WAN_A' => false]],
        'an unowned_alerted_at value "x"' => ['unowned_alerted_at' => ['WAN_A' => 'x']],
        'an apply_pending value "maybe"' => ['apply_pending' => ['WAN_A' => 'maybe']],
        'a last_held of [1]' => ['last_held' => [1]],
        'a dry_held of [1]' => ['dry_held' => [1]],
        'a dry_held that is no list' => ['dry_held' => ['x' => 'WAN_A']],
        'a said value 1' => ['said' => ['unresolved' => 1]],
        'a foreign_pruned value "x"' => ['foreign_pruned' => ['WAN_B' => 'x']],
    ];
    foreach ($nested as $what => $fields) {
        file_put_contents("{$d}/state.json", json_encode(['version' => 3] + $fields));
        $l = wf_state_load("{$d}/state.json", 'b500');
        wf_check($t, "(s11) {$what} loads fresh, corrupt, as not this version's shape",
            $fresh($l) && $l['corrupt'] && $l['problem'] === "not this version's shape");
    }
    $kept = [
        "1.1's pending failback, which records only since" => ['pending_failbacks' => ['WAN_A' => ['since' => 100]]],
        'a settled loss JSON wrote without a fraction (0.0 as 0), and one with' =>
            ['judgements' => ['WAN_A' => ['last_settled_loss' => 0] + $jv, 'WAN_B' => ['last_settled_loss' => 12.5] + $jv]],
        'keys the plugin does not read, at every level' => ['judgements' => ['WAN_A' => $jv + ['note' => 1]],
            'ts' => $tsv + ['note' => 1], 'note' => 1],
    ];
    foreach ($kept as $what => $fields) {
        file_put_contents("{$d}/state.json", json_encode(['version' => 3] + $fields));
        $l = wf_state_load("{$d}/state.json", 'b500');
        wf_check($t, "(s11) {$what}: loads as written, not corrupt", !$l['corrupt'] && $l['problem'] === null
            && array_intersect_key($l['state'], $fields) == $fields);
    }
    file_put_contents("{$d}/state.json", '{"version":3,"gateway_ips":{"WAN_A":5,"WAN_B":"198.51.100.1"}}');
    $l = wf_state_load("{$d}/state.json", 'b500');
    wf_check($t, '(s11) a gateway_ips value that is no string is dropped, not corrupt',
        !$l['corrupt'] && $l['state']['gateway_ips'] === ['WAN_B' => '198.51.100.1']);
    wf_t_rmtree($d);

    $d = wf_t_scratch('s6');
    wf_state_save("{$d}/db/state.json", $s);
    wf_check($t, '(s6) a save makes the directory 0700 and the file 0600',
        wf_t_mode("{$d}/db") === 0700 && wf_t_mode("{$d}/db/state.json") === 0600
        && glob("{$d}/db/state.json.*") === [] && !wf_state_load("{$d}/db/state.json", 'b500')['corrupt']);
    mkdir("{$d}/old", 0750);
    chmod("{$d}/old", 0750);
    file_put_contents("{$d}/old/state.json", '{}');
    chmod("{$d}/old/state.json", 0644);
    wf_state_save("{$d}/old/state.json", $s);
    wf_check($t, "(s6) 1.3_1's 0750 directory becomes 0700 and its 0644 file 0600 at the next save",
        wf_t_mode("{$d}/old") === 0700 && wf_t_mode("{$d}/old/state.json") === 0600);
    wf_t_rmtree($d);

    $d = wf_t_scratch('s7');
    mkdir("{$d}/real", 0700);
    symlink("{$d}/real", "{$d}/link");
    touch("{$d}/file");
    $throws = function (string $dir): bool {
        try {
            wf_private_dir($dir);
            return false;
        } catch (RuntimeException) {
            return true;
        }
    };
    wf_check($t, '(s7) wf_private_dir() throws on a symbolic link to a directory, and on a file',
        $throws("{$d}/link") && $throws("{$d}/file") && !$throws("{$d}/real"));
    wf_t_rmtree($d);

    $d = wf_t_scratch('s8');
    wf_event("{$d}/run/event", ['time' => 'now', 'dry' => false, 'hold' => ['WAN_B']]);
    wf_check($t, "(s8) wf_event()'s file is 0600 in a 0700 directory, with its fields",
        wf_t_mode("{$d}/run/event") === 0600 && wf_t_mode("{$d}/run") === 0700
        && file_get_contents("{$d}/run/event") === "time=now\ndry=no\nhold=WAN_B\n");
    $day = 'trace-' . date('Ymd') . '.jsonl';
    wf_trace("{$d}/trace", ['n' => 1]);
    wf_trace("{$d}/trace", ['n' => 2]);
    wf_check($t, "(s8) wf_trace()'s file is 0600 in a 0700 directory, one line per record",
        wf_t_mode("{$d}/trace/{$day}") === 0600 && wf_t_mode("{$d}/trace") === 0700
        && file_get_contents("{$d}/trace/{$day}") === "{\"n\":1}\n{\"n\":2}\n");
    mkdir("{$d}/old", 0750);
    file_put_contents("{$d}/old/{$day}", "{\"n\":0}\n");
    chmod("{$d}/old/{$day}", 0644);
    wf_trace("{$d}/old", ['n' => 1]);
    wf_check($t, "(s8) 1.3_1's 0644 trace file becomes 0600 and keeps its lines",
        wf_t_mode("{$d}/old/{$day}") === 0600 && wf_t_mode("{$d}/old") === 0700
        && file_get_contents("{$d}/old/{$day}") === "{\"n\":0}\n{\"n\":1}\n");
    mkdir("{$d}/linked", 0700);
    file_put_contents("{$d}/target", "kept\n");
    chmod("{$d}/target", 0644);
    symlink("{$d}/target", "{$d}/linked/{$day}");
    wf_trace("{$d}/linked", ['n' => 1]);
    wf_check($t, '(s8) a symbolic link at the trace file is refused: its target unchanged, the link kept',
        file_get_contents("{$d}/target") === "kept\n" && wf_t_mode("{$d}/target") === 0644 && is_link("{$d}/linked/{$day}"));
    mkdir("{$d}/dangling", 0700);
    symlink("{$d}/absent", "{$d}/dangling/{$day}");
    wf_trace("{$d}/dangling", ['n' => 1]);
    wf_check($t, '(s8) a symbolic link at the trace file to a missing file is refused: nothing is created there',
        !file_exists("{$d}/absent") && is_link("{$d}/dangling/{$day}"));
    wf_t_rmtree($d);

    $d = wf_t_scratch('s9');
    file_put_contents("{$d}/crash_at", "after-save\n");
    $other = wf_crash_due("{$d}/crash_at", 'after-pending');
    $kept = is_file("{$d}/crash_at");
    $due = wf_crash_due("{$d}/crash_at", 'after-save');
    wf_check($t, '(s9) a crash flag naming another point is not due and is kept; at its own point it is due and consumed',
        !$other && $kept && $due && !file_exists("{$d}/crash_at"));
    wf_check($t, '(s9) a missing crash flag is not due', !wf_crash_due("{$d}/crash_at", 'after-save'));
    file_put_contents("{$d}/target", "after-save\n");
    symlink("{$d}/target", "{$d}/crash_at");
    wf_check($t, '(s9) a symbolic link as the crash flag is not due, and nothing is removed',
        !wf_crash_due("{$d}/crash_at", 'after-save') && is_link("{$d}/crash_at") && is_file("{$d}/target"));
    wf_t_rmtree($d);

    $src = dirname(__DIR__) . '/src';
    $calls = [];
    $php = 0;
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($src, FilesystemIterator::SKIP_DOTS)) as $info) {
        if ($info instanceof SplFileInfo && $info->isFile() && $info->getExtension() === 'php') {
            $php++;
            if (str_contains((string)file_get_contents($info->getPathname()), 'getenv(')) {
                $calls[] = substr($info->getPathname(), strlen($src) + 1);
            }
        }
    }
    wf_check($t, '(s10) no PHP file under src reads the environment (getenv): ' . ($calls === [] ? "none of {$php}" : implode(', ', $calls)),
        $php > 0 && $calls === []);

    $keys = fn (array $spec): array => array_map(fn (string $k): string => ltrim($k, '?'), array_keys($spec));
    $spec = wf_state_spec();
    $new = wf_state_new('b500');
    wf_check($t, "(s12) the shape check names exactly wf_state_new()'s fields, wf_judgement_new()'s and wf_ts_new()'s",
        $keys($spec) === array_keys($new) && $keys($spec['judgements']['*']) === array_keys(wf_judgement_new(0))
        && $keys($spec['ts']) === array_keys(wf_ts_new()));
    $bad = array_keys(array_filter($spec, fn (array|string $f, string $k): bool => !wf_shape_ok($new[$k], $f), ARRAY_FILTER_USE_BOTH));
    wf_check($t, "(s12) every default of wf_state_new() fits the shape check" . ($bad === [] ? '' : ': not ' . implode(', ', $bad)),
        $bad === [] && wf_shape_ok(wf_judgement_new(0), $spec['judgements']['*']));

    /* 1.3_1's held list: the state 1.3_1 wrote names this boot (b500) and the gateways it held in last_held */
    $proves = ['boot' => 'b500', 'held' => ['WAN_A']];
    $r = wf_import_legacy_held('u1,u2,u1', ['u1' => 'WAN_A'], 'b500', 1000, $proves);
    wf_check($t, '(m1) the legacy held list gives one record per UUID that names a gateway the state proves, each once, '
        . 'stamped with this boot and now', $r === [['gateway' => 'u1', 'boot' => 'b500', 'since' => 1000]]);
    wf_check($t, '(m2) with the boot id unreadable no hold record is made',
        wf_import_legacy_held('u1', ['u1' => 'WAN_A'], '', 1000, $proves) === []);
    wf_check($t, '(m3) an empty legacy held list gives no hold record',
        wf_import_legacy_held('', ['u1' => 'WAN_A'], 'b500', 1000, $proves) === []);
    $p = wf_legacy_import_plan(null, ['u1' => 'WAN_A'], 'b500', 1000, $proves);
    wf_check($t, '(m4) with no legacy held node there is nothing to import', !$p['import'] && $p['records'] === [] && $p['lines'] === []);
    $p = wf_legacy_import_plan('', ['u1' => 'WAN_A'], 'b500', 1000, $proves);
    wf_check($t, '(m4) an empty legacy held node (1.3_1 holding nothing) is imported: no record, the node removed',
        $p['import'] && $p['records'] === [] && $p['lines'] === []);
    $p = wf_legacy_import_plan('u1,u9', ['u1' => 'WAN_A'], 'b500', 1000, $proves);
    wf_check($t, '(m5) a legacy list is imported with one line per carried hold and per dropped entry',
        $p['import'] && $p['records'] === [['gateway' => 'u1', 'boot' => 'b500', 'since' => 1000]]
        && $p['lines'] === [[LOG_NOTICE, 'hold of WAN_A carried over, taken in boot b500'],
                            [LOG_NOTICE, 'held entry u9 names no gateway; dropped']]);
    $p = wf_legacy_import_plan('u1', ['u1' => 'WAN_A'], '', 1000, $proves);
    wf_check($t, '(m5) with the boot id unreadable nothing is imported and the node stays, for an evaluation that can read it; '
        . 'one warning says so',
        !$p['import'] && $p['records'] === [] && $p['lines'] === [[LOG_WARNING,
            "kern.boot_id cannot be read, so 1.3_1's held list stays in the config until it can"]]);

    /* a restored backup carries a held list the plugin's state does not prove: never carried over as the plugin's */
    $map = ['u1' => 'WAN_A', 'u2' => 'WAN_B'];
    $notProven = [LOG_WARNING, "held entry for WAN_B not proven by this plugin's state; left as it is"];
    $p = wf_legacy_import_plan('u2', $map, 'b500', 1000, $proves);
    wf_check($t, '(l1) a restored list naming a gateway the state of this boot did not hold (not in last_held) makes no record: '
        . 'the node goes, one line says the entry is left as it is',
        $p['import'] && $p['records'] === [] && $p['lines'] === [$notProven]);
    $p = wf_legacy_import_plan('u1,u2', $map, 'b500', 1000, $proves);
    wf_check($t, '(l1) a list with a proven and an unproven entry carries over the proven one only',
        $p['import'] && $p['records'] === [['gateway' => 'u1', 'boot' => 'b500', 'since' => 1000]]
        && $p['lines'] === [[LOG_NOTICE, 'hold of WAN_A carried over, taken in boot b500'], $notProven]);
    $p = wf_legacy_import_plan('u2', $map, 'b500', 1000, ['boot' => 'b499', 'held' => ['WAN_B']]);
    wf_check($t, '(l2) a state of another boot proves nothing, even naming the gateway in last_held',
        $p['import'] && $p['records'] === [] && $p['lines'] === [$notProven]);
    $p = wf_legacy_import_plan('u2', $map, 'b500', 1000, ['boot' => '', 'held' => []]);
    $p2 = wf_legacy_import_plan('u2', $map, 'b500', 1000, ['boot' => 'corrupt', 'held' => ['WAN_B']]);
    wf_check($t, '(l3) with the state file missing or damaged nothing is proven: no record, the gateway left as it is',
        $p['import'] && $p['records'] === [] && $p['lines'] === [$notProven] && $p2 === $p);

    wf_check($t, '(g1) a changed gateway whose force_down moved since the snapshot is named',
        wf_write_guard(['WAN_A' => true], ['WAN_A' => false], ['WAN_A' => true]) === ['WAN_A']);
    wf_check($t, '(g2) force_down as the snapshot read it names nothing',
        wf_write_guard(['WAN_A' => true, 'WAN_B' => false], ['WAN_A' => false, 'WAN_B' => true], ['WAN_A' => false, 'WAN_B' => true]) === []);
    wf_check($t, '(g3) a changed gateway gone from the config is named',
        wf_write_guard(['WAN_A' => true, 'WAN_B' => false], ['WAN_A' => false, 'WAN_B' => true], ['WAN_A' => false]) === ['WAN_B']);
    wf_check($t, '(g4) a changed gateway with no snapshot value to compare is named; an unchanged one is not compared',
        wf_write_guard(['WAN_A' => true], [], ['WAN_A' => false, 'WAN_B' => true]) === ['WAN_A']);

    $uuidA = 'aaaaaaaa-0000-4000-8000-00000000000a';
    $uuidB = 'aaaaaaaa-0000-4000-8000-00000000000b';
    $w = wf_holds_rows(['WAN_B' => ['boot' => 'b500', 'since' => 200], 'WAN_A' => ['boot' => 'b400', 'since' => 100]],
        ['WAN_A' => $uuidA, 'WAN_B' => $uuidB]);
    wf_check($t, '(k1) the rows a write leaves are the records after it, one per gateway by its UUID, boot and since as given',
        $w === ['rows' => [['gateway' => $uuidB, 'boot' => 'b500', 'since' => 200], ['gateway' => $uuidA, 'boot' => 'b400', 'since' => 100]],
                'missing' => []]);
    wf_check($t, '(k2) a record whose gateway has no UUID now is missing, so the writer writes nothing',
        wf_holds_rows(['WAN_A' => ['boot' => 'b500', 'since' => 100], 'WAN_C' => ['boot' => 'b500', 'since' => 100]], ['WAN_A' => $uuidA])
            === ['rows' => [['gateway' => $uuidA, 'boot' => 'b500', 'since' => 100]], 'missing' => ['WAN_C']]);
    wf_check($t, '(k3) no record after the write leaves no row', wf_holds_rows([], ['WAN_A' => $uuidA]) === ['rows' => [], 'missing' => []]);

    $good = wf_state_new('b500');
    $good['last_held'] = ['WAN_A'];
    wf_check($t, '(l4) the state proves the boot it names and its last_held; a damaged one proves nothing',
        wf_state_proof(['state' => $good, 'corrupt' => false]) === ['boot' => 'b500', 'held' => ['WAN_A']]
        && wf_state_proof(['state' => wf_state_new(''), 'corrupt' => true]) === ['boot' => '', 'held' => []]
        && wf_boot_unread('') && wf_boot_unread('corrupt') && !wf_boot_unread('b500'));
    $d = wf_t_scratch('l4');
    $l = wf_state_load("{$d}/state.json", '');
    wf_check($t, '(l4) a missing state file, loaded without the live boot id, names no boot and proves nothing',
        wf_state_proof($l) === ['boot' => '', 'held' => []]);
    wf_t_rmtree($d);

    /* at boot: b400 is the boot before, the one the state names; WAN_A was held in it, WAN_B was not */
    $before = ['boot' => 'b400', 'held' => ['WAN_A']];
    $legacy = wf_boot_legacy('u1,u2,u9', $map, $before);
    $b = wf_boot_outcome([], 0, 'b400', $legacy);
    wf_check($t, '(l5) at boot 1.3_1\'s held list still in the config: the entry the state proves for the boot before is '
        . 'released, the other left as it is, the one naming no gateway dropped, and the list goes in the same write',
        $legacy === ['present' => true, 'release' => ['WAN_A'], 'left' => ['WAN_B'], 'unknown' => 1]
        && $b['release'] === ['WAN_A'] && $b['pruned'] === [] && $b['drop_legacy']
        && $b['note'] === "boot: released WAN_A; 1.3_1's held entry for WAN_B not proven by this plugin's state, left as it is; "
            . "dropped 1 entry of 1.3_1's held list that names no gateway");
    $b = wf_boot_outcome($rec('b400', 'WAN_B'), 0, 'b400', wf_boot_legacy('u1', $map, $before));
    wf_check($t, '(l5) a record and a list entry of the boot before are released together',
        $b['release'] === ['WAN_B', 'WAN_A'] && $b['drop_legacy'] && $b['note'] === 'boot: released WAN_B,WAN_A');
    $b = wf_boot_outcome([], 0, '', wf_boot_legacy('u1', $map, ['boot' => '', 'held' => []]));
    wf_check($t, '(l5) at boot with the state unreadable the list\'s entries are not released, and nothing is written',
        $b['release'] === [] && !$b['drop_legacy'] && $b['note'] === 'boot: state unreadable; no hold released');
    $b = wf_boot_outcome([], 0, 'b400', wf_boot_legacy('', $map, $before));
    wf_check($t, '(l5) an empty list at boot is removed with a note, and nothing is released',
        $b['release'] === [] && $b['drop_legacy'] && $b['note'] === "boot: 1.3_1's empty held list removed"
        && wf_boot_legacy(null, $map, $before) === ['present' => false, 'release' => [], 'left' => [], 'unknown' => 0]);
    return wf_tally_report('state', $t);
});
