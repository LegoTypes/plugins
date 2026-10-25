<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Runtime state (spec 2026-10-05 section 3.8): what does not belong in config. Ownership itself -- the
 * hold records -- is in the plugin's Holds model, saved with force_down, and a record proves a hold by the boot id it
 * carries (wf_reconcile()); this file only resumes an apply a crash interrupted, notices held changes the engine did
 * not make and knows the boot before, which the early hook releases. The file is root's alone and read as a regular file
 * only, and a field of the wrong type discards it: wrong-typed state would throw a TypeError every minute, which
 * stops failover. The file helpers below touch the paths they are given; the rest is pure.
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/tailscale.php';

const WF_STATE_VERSION = 3;

/**
 * @return array{version: int, boot_id: string, installed_at: ?int, last_now: ?int, judgements: array<string, array>,
 *               no_rehold: array<string, true>, pending_failbacks: array<string, array{since: int, clean_since: ?int, due: ?int}>, ts: array,
 *               unowned_alerted_at: array<string, int>, apply_pending: array<string, string>, last_held: list<string>,
 *               contract_last: string, contract_judging_since: ?int, boot_note: ?string, dry_held: list<string>,
 *               said: array<string, string>, gateway_ips: array<string, string>, foreign_pruned: array<string, int>}
 *
 * gateway_ips holds each WAN's last known gateway address: a DHCP WAN loses its address with its link, while
 * the states it carried still route to the old one. foreign_pruned holds when a hold record the plugin did not take
 * was pruned, by gateway, for the page while that gateway stays forced down. A field added later merges in from these
 * defaults, so it needs no version change.
 */
function wf_state_new(string $bootId): array
{
    return ['version' => WF_STATE_VERSION, 'boot_id' => $bootId, 'installed_at' => null, 'last_now' => null,
            'judgements' => [], 'no_rehold' => [], 'pending_failbacks' => [], 'ts' => wf_ts_new(),
            'unowned_alerted_at' => [], 'apply_pending' => [], 'last_held' => [], 'contract_last' => '',
            'contract_judging_since' => null, 'boot_note' => null, 'dry_held' => [], 'said' => [], 'gateway_ips' => [],
            'foreign_pruned' => []];
}

/**
 * A directory of the plugin's, root's alone, since what it holds is trusted: created 0700 when missing, put back to
 * 0700 when its mode differs (1.3_1 made them 0750), refused when the path is a symbolic link or not a directory.
 */
function wf_private_dir(string $dir): void
{
    clearstatcache(true, $dir);
    if (@lstat($dir) === false) {
        /* a failure, or another process's mkdir in between, is judged by the checks below */
        @mkdir($dir, 0700, true);
        clearstatcache(true, $dir);
    }
    $st = @lstat($dir);
    if ($st === false) {
        throw new RuntimeException("cannot create {$dir}");
    }
    if (($st['mode'] & 0170000) === 0120000) {
        throw new RuntimeException("{$dir} is a symbolic link");
    }
    if (($st['mode'] & 0170000) !== 0040000) {
        throw new RuntimeException("{$dir} is not a directory");
    }
    if (($st['mode'] & 07777) !== 0700 && !@chmod($dir, 0700)) {
        throw new RuntimeException("cannot make {$dir} mode 0700");
    }
}

/**
 * A file the plugin trusts, read as a regular file only: the path is no symbolic link and a regular file (lstat), and
 * the file opened is the one checked (the same device and inode), so a swap between the check and the open is refused,
 * and the open never blocks. The open still follows a link swapped in after the lstat, so this reader is for files in a
 * directory only root can write (wf_private_dir()). A missing path has no text and no problem; with a problem there is
 * no text either.
 *
 * @return array{text: ?string, problem: ?string} problem: 'a symbolic link', 'not a regular file', 'larger than
 *     1 MiB' (the default limit) or 'unreadable'
 */
function wf_read_regular_file(string $path, int $maxBytes = WF_FILE_MAX_BYTES): array
{
    clearstatcache(true, $path);
    $link = @lstat($path);
    if ($link === false) {
        return ['text' => null, 'problem' => null];
    }
    if (($link['mode'] & 0170000) === 0120000) {
        return ['text' => null, 'problem' => 'a symbolic link'];
    }
    if (($link['mode'] & 0170000) !== 0100000) {
        return ['text' => null, 'problem' => 'not a regular file'];
    }
    /* n is O_NONBLOCK (the plain-files wrapper): a FIFO or device swapped in after the lstat opens at once, and the
     * identity check below refuses it, instead of the open blocking until a writer appears; a regular file ignores
     * the flag */
    $fh = @fopen($path, 'rbn');
    if ($fh === false) {
        return ['text' => null, 'problem' => 'unreadable'];
    }
    try {
        $st = fstat($fh);
        if ($st === false || $st['dev'] !== $link['dev'] || $st['ino'] !== $link['ino']) {
            return ['text' => null, 'problem' => 'unreadable'];
        }
        $text = stream_get_contents($fh, $maxBytes + 1);
        if ($text === false) {
            return ['text' => null, 'problem' => 'unreadable'];
        }
        if (strlen($text) > $maxBytes) {
            $limit = $maxBytes > 0 && $maxBytes % 1048576 === 0
                ? intdiv($maxBytes, 1048576) . ' MiB' : "{$maxBytes} bytes";
            return ['text' => null, 'problem' => "larger than {$limit}"];
        }
        return ['text' => $text, 'problem' => null];
    } finally {
        fclose($fh);
    }
}

/**
 * Replace a file of the plugin's whole: the data goes to a new file beside it (tempnam, in the same directory, so the
 * rename is atomic), made 0600, then renamed over the path, so a reader sees the old file or the new one and a link at
 * the path is replaced, never followed. The caller makes the directory first (wf_private_dir()).
 */
function wf_write_private(string $path, string $data): void
{
    $dir = dirname($path);
    $tmp = @tempnam($dir, basename($path) . '.');
    /* tempnam falls back to the system's temporary directory when it cannot create the file in $dir */
    if ($tmp === false || dirname($tmp) !== realpath($dir)) {
        if ($tmp !== false) {
            @unlink($tmp);
        }
        throw new RuntimeException("cannot write {$path}");
    }
    if (@file_put_contents($tmp, $data) !== strlen($data) || !@chmod($tmp, 0600) || !@rename($tmp, $path)) {
        @unlink($tmp);
        throw new RuntimeException("cannot write {$path}");
    }
}

/**
 * The test hook for a crash at one point of an apply: the flag file names the point. It fires once, at that point:
 * the flag is removed first, and a point it cannot remove does not fire. A flag naming another point is kept for that
 * one; a link or anything but a regular file never fires.
 */
function wf_crash_due(string $flagPath, string $point): bool
{
    $flag = wf_read_regular_file($flagPath);
    if ($flag['text'] === null || trim($flag['text']) !== $point) {
        return false;
    }
    return @unlink($flagPath);
}

/**
 * A recurring condition is logged once when it appears or changes, and forgotten when it clears.
 *
 * @param array<string, string> $said the state's said map
 * @return ?string the line to log now, if any
 */
function wf_once(array &$said, string $key, ?string $line): ?string
{
    if ($line === null) {
        unset($said[$key]);
        return null;
    }
    if (($said[$key] ?? null) === $line) {
        return null;
    }
    $said[$key] = $line;
    return $line;
}

/**
 * The shape the plugin writes, for wf_shape_ok(): the fields of wf_state_new(), each judgement as wf_judgement_new()
 * (judge.php), ts as wf_ts_new(). A field is a string of get_debug_type() names joined by |, or an array: ['*' => F]
 * maps names to F, ['#' => F] is a list of F, ['=' => [...]] one of those values, and any other array a record of the
 * fields named (a key starting with ? may be absent, as where the code reads it with ??). gateway_ips is only an array
 * here: an entry that is no IPv4 address is dropped, not corrupt.
 *
 * @return array<string, string|array>
 */
function wf_state_spec(): array
{
    $at = 'int|null';
    $name = 'string|null';
    return [
        'version' => 'int', 'boot_id' => 'string', 'installed_at' => $at, 'last_now' => $at,
        /* JSON writes a float with no fraction as an integer: a settled 5.0 % loss comes back as 5 */
        'judgements' => ['*' => ['value' => $name, 'since' => 'int', 'last_settled_at' => $at,
                                 'last_settled_loss' => 'float|int|null', 'unknown_since' => $at, 'recovering' => 'bool']],
        'no_rehold' => ['*' => ['=' => [true]]],
        /* a failback queued by 1.1 records only since */
        'pending_failbacks' => ['*' => ['since' => 'int', '?clean_since' => $at, '?due' => $at]],
        'ts' => ['default_gw' => $name, 'restarted_at' => $at, 'cur_default' => $name, 'cur_since' => $at,
                 'lost' => 'bool', 'expected_default' => $name],
        'unowned_alerted_at' => ['*' => 'int'],
        'apply_pending' => ['*' => ['=' => ['hold', 'release']]],
        'last_held' => ['#' => 'string'],
        'contract_last' => 'string', 'contract_judging_since' => $at, 'boot_note' => $name,
        'dry_held' => ['#' => 'string'],
        'said' => ['*' => 'string'],
        'gateway_ips' => 'array',
        'foreign_pruned' => ['*' => 'int'],
    ];
}

/**
 * @param string|array $spec a field of wf_state_spec()
 */
function wf_shape_ok(mixed $value, string|array $spec): bool
{
    if (is_string($spec)) {
        return in_array(get_debug_type($value), explode('|', $spec), true);
    }
    if (isset($spec['='])) {
        return in_array($value, $spec['='], true);
    }
    if (!is_array($value) || (isset($spec['#']) && !array_is_list($value))) {
        return false;
    }
    if (isset($spec['*']) || isset($spec['#'])) {
        foreach ($value as $item) {
            if (!wf_shape_ok($item, $spec['*'] ?? $spec['#'])) {
                return false;
            }
        }
        return true;
    }
    foreach ($spec as $key => $field) {
        $name = ltrim($key, '?');
        if (!array_key_exists($name, $value)) {
            if ($name === $key) {
                return false;
            }
        } elseif (!wf_shape_ok($value[$name], $field)) {
            return false;
        }
    }
    return true;
}

/**
 * A decoded state file of this version in the shape the plugin writes (wf_state_spec()): its version must be an int,
 * and every field it has must have that shape to its depth, or the whole file is corrupt; a field it lacks takes its
 * default, and keys the plugin does not read are kept. A gateway_ips entry that is not an IPv4 address is dropped,
 * which costs only a state kill's fallback address.
 *
 * @param array<array-key, mixed> $data
 * @return array{state: array, corrupt: bool}
 */
function wf_state_shape(array $data, string $bootId): array
{
    $new = wf_state_new($bootId);
    if (!is_int($data['version'] ?? null)) {
        return ['state' => $new, 'corrupt' => true];
    }
    foreach (wf_state_spec() as $key => $spec) {
        if (array_key_exists($key, $data) && !wf_shape_ok($data[$key], $spec)) {
            return ['state' => $new, 'corrupt' => true];
        }
    }
    $ips = [];
    foreach ($data['gateway_ips'] ?? [] as $name => $ip) {
        if (is_string($name) && is_string($ip) && filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            $ips[$name] = $ip;
        }
    }
    $data['gateway_ips'] = $ips;
    return ['state' => array_merge($new, $data), 'corrupt' => false];
}

/**
 * A file that cannot be read as a regular file, or holds no state of this version's shape, loads fresh and corrupt,
 * with the problem named; a missing file loads fresh and not corrupt.
 *
 * @return array{state: array, corrupt: bool, problem: ?string}
 */
function wf_state_load(string $path, string $bootId): array
{
    $corrupt = fn (string $problem): array => ['state' => wf_state_new($bootId), 'corrupt' => true, 'problem' => $problem];
    $read = wf_read_regular_file($path);
    if ($read['problem'] !== null) {
        return $corrupt($read['problem']);
    }
    if ($read['text'] === null) {
        return ['state' => wf_state_new($bootId), 'corrupt' => false, 'problem' => null];
    }
    try {
        $data = json_decode($read['text'], true, 64, JSON_THROW_ON_ERROR);
    } catch (JsonException) {
        return $corrupt('not JSON');
    }
    if (!is_array($data)) {
        return $corrupt("not this version's shape");
    }
    /* another version (an upgrade): start fresh in this boot; ownership lives in config, so nothing is
     * released and held gateways stay held until they read loss-free */
    if (is_int($data['version'] ?? null) && $data['version'] !== WF_STATE_VERSION) {
        return ['state' => wf_state_new($bootId), 'corrupt' => false, 'problem' => null];
    }
    $shaped = wf_state_shape($data, $bootId);
    return $shaped['corrupt'] ? $corrupt("not this version's shape") : $shaped + ['problem' => null];
}

/**
 * @param array $state the shape returned by wf_state_new()
 */
function wf_state_save(string $path, array $state): void
{
    wf_private_dir(dirname($path));
    wf_write_private($path, json_encode($state, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR) . "\n");
}

/**
 * Which hold records are the plugin's. A record proves a hold only by the boot that took it: this boot, or, passed
 * by the planner's boot detector alone, the boot before. A proven record is owned while its gateway reads force_down
 * 1, and was released by hand once it reads 0. Any other record (a restored backup, a hand-edited config) is foreign:
 * pruned, and its gateway's force_down left as it is. With the live boot id unreadable nothing can be proven, so
 * every record is kept as it is, neither released nor pruned (unproven; the planner says so). Names with no
 * configured gateway are skipped.
 *
 * @param array<string, array{boot: string, since: int}> $records the hold records by gateway name (wf_resolve_records())
 * @param array<string, bool> $forceDown every configured gateway name => force_down
 * @param array<string, string> $applyPending name => hold|release, written before an engine save
 * @param list<string> $lastHeld the record names the engine last wrote (or last saw after a foreign change)
 * @return array{owned: list<string>, manual_released: list<string>, redo_apply: list<string>, redo_replay: list<string>,
 *               foreign: list<string>, apply_pending: array<string, string>, log: list<string>,
 *               foreign_records: list<string>, unproven: list<string>}
 */
function wf_reconcile(array $records, array $forceDown, array $applyPending, array $lastHeld, string $liveBoot,
                      string $prevBoot = ''): array
{
    $out = ['owned' => [], 'manual_released' => [], 'redo_apply' => [], 'redo_replay' => [], 'foreign' => [],
            'apply_pending' => [], 'log' => [], 'foreign_records' => [], 'unproven' => []];
    $proven = [];
    foreach ($records as $name => $r) {
        if (!array_key_exists($name, $forceDown)) {
            continue;
        }
        if ($liveBoot === '') {
            $out['unproven'][] = $name;
        } elseif ($r['boot'] !== $liveBoot && ($prevBoot === '' || $r['boot'] !== $prevBoot)) {
            $out['foreign_records'][] = $name;
            $out['log'][] = "hold record for {$name} from another boot or box; not ours, left alone";
        } else {
            $proven[$name] = true;
            if ($forceDown[$name]) {
                $out['owned'][] = $name;
            } else {
                $out['manual_released'][] = $name;
                $out['log'][] = "{$name} released by hand; it leaves held and is not re-held until it reads up and then over threshold";
            }
        }
    }
    foreach ($applyPending as $name => $what) {
        /* a hold is finished (replay, state kill) only on a record this plugin wrote; a release, once no record is left */
        $inHeld = $what === 'hold' ? isset($proven[$name]) : isset($records[$name]);
        if ($what === 'hold' && $inHeld) {
            $out['redo_apply'][] = $name;
            $out['apply_pending'][$name] = 'hold';
            $out['log'][] = "apply-resumed {$name}: hold was saved, finishing replay and state kill";
        } elseif ($what === 'release' && !$inHeld) {
            $out['redo_replay'][] = $name;
            $out['apply_pending'][$name] = 'release';
            $out['log'][] = "apply-resumed {$name}: release was saved, finishing replay";
        } else {
            $out['log'][] = "apply-resumed {$name}: the {$what} was never saved; dropped";
        }
    }
    $names = array_keys($records);
    $changed = array_merge(array_diff($names, $lastHeld), array_diff($lastHeld, $names));
    $out['foreign'] = array_values(array_diff(array_unique($changed), array_keys($applyPending)));
    foreach ($out['foreign'] as $name) {
        $out['log'][] = "held changed outside the engine for {$name} (a config revert or restore); re-syncing routing";
    }
    return $out;
}

/**
 * The records the early hook releases: those the boot before took, by the state's boot id. A state with no boot id,
 * or one that could not be read, proves none.
 *
 * @param array<string, array{boot: string, since: int}> $records by gateway name
 * @return list<string>
 */
function wf_boot_release_set(array $records, string $stateBootId): array
{
    if ($stateBootId === '' || $stateBootId === 'corrupt') {
        return [];
    }
    return array_keys(array_filter($records, fn (array $r): bool => $r['boot'] === $stateBootId));
}

/**
 * What the early hook does with the hold records, and the note the first evaluation logs for it: the boot before's
 * records released, every other one pruned with its gateway left as it is, all in one write. With the state unreadable
 * nothing is proven and nothing is written; the first evaluation then prunes the records as foreign.
 *
 * @param array<string, array{boot: string, since: int}> $records by gateway name
 * @param int $dropped rows that name no gateway or repeat one (wf_resolve_records()'s stale and dupes)
 * @return array{release: list<string>, pruned: list<string>, note: string}
 */
function wf_boot_outcome(array $records, int $dropped, string $stateBootId): array
{
    if ($stateBootId === '' || $stateBootId === 'corrupt') {
        return ['release' => [], 'pruned' => [], 'note' => 'boot: state unreadable; no hold released'];
    }
    $release = wf_boot_release_set($records, $stateBootId);
    $pruned = array_values(array_diff(array_keys($records), $release));
    $parts = [];
    if ($release !== []) {
        $parts[] = 'released ' . implode(',', $release);
    }
    if ($pruned !== []) {
        $parts[] = 'pruned ' . implode(',', $pruned) . " (not this plugin's)";
    }
    if ($dropped > 0) {
        $parts[] = "dropped {$dropped} " . ($dropped === 1 ? 'record that names no gateway or repeats one'
            : 'records that name no gateway or repeat one');
    }
    return ['release' => $release, 'pruned' => $pruned, 'note' => 'boot: ' . implode('; ', $parts)];
}

/**
 * The changed gateways whose force_down moved since the snapshot the plan decided on (a settings save, a restored
 * config): the writer compares under its lock, with the config as it is now, and writes nothing when one is named. A
 * changed gateway gone from the config, or with no snapshot value to compare, is named too.
 *
 * @param array<string, bool> $changes gateway name => the force_down to write
 * @param array<string, bool> $expected gateway name => the force_down the snapshot read
 * @param array<string, bool> $current every configured gateway name => its force_down now
 * @return list<string>
 */
function wf_write_guard(array $changes, array $expected, array $current): array
{
    $moved = [];
    foreach (array_keys($changes) as $name) {
        if (!isset($expected[$name], $current[$name]) || $current[$name] !== $expected[$name]) {
            $moved[] = (string)$name;
        }
    }
    return $moved;
}

/**
 * The hold rows a write leaves: exactly the plan's records after it, one per gateway, each with the boot and since the
 * plan gave it, and no other row. A gateway is named by its UUID in the config as it is under the writer's lock; a
 * record whose gateway has none there (renamed or deleted since the snapshot) is missing, and the writer then writes
 * nothing, as a row left out would leave that gateway's hold unowned.
 *
 * @param array<string, array{boot: string, since: int}> $recordsAfter the plan's, by gateway name
 * @param array<string, string> $uuidByName every configured gateway's name => its UUID
 * @return array{rows: list<array{gateway: string, boot: string, since: int}>, missing: list<string>}
 */
function wf_holds_rows(array $recordsAfter, array $uuidByName): array
{
    $rows = [];
    $missing = [];
    foreach ($recordsAfter as $name => $r) {
        if (isset($uuidByName[$name])) {
            $rows[] = ['gateway' => $uuidByName[$name], 'boot' => $r['boot'], 'since' => $r['since']];
        } else {
            $missing[] = (string)$name;
        }
    }
    return ['rows' => $rows, 'missing' => $missing];
}

/**
 * The hold records an upgrade makes of 1.3_1's held list, a comma list of gateway UUIDs in the settings model: one
 * per UUID that names a gateway, each UUID once, stamped with this boot and the upgrade's time. A hold in place at
 * the upgrade was taken in this boot (the early hook releases every hold at boot), so the plugin goes on owning it.
 * With the boot id unreadable none is made: a record has to say which boot took it.
 *
 * @param array<string, string> $nameByUuid every configured gateway's UUID => its name
 * @return list<array{gateway: string, boot: string, since: int}>
 */
function wf_import_legacy_held(string $csv, array $nameByUuid, string $bootId, int $now): array
{
    if ($bootId === '') {
        return [];
    }
    $records = [];
    foreach (array_unique(explode(',', $csv)) as $uuid) {
        if (isset($nameByUuid[$uuid])) {
            $records[] = ['gateway' => $uuid, 'boot' => $bootId, 'since' => $now];
        }
    }
    return $records;
}

/**
 * The import of 1.3_1's held list, decided: whether there is one (its raw config node; null when absent), the records
 * it makes (wf_import_legacy_held()) and the lines to log. A node that is there is imported even when empty, as
 * 1.3_1 left it with nothing held, so that the node is removed. Both the migration and an evaluation that finds the
 * node still there apply this one decision.
 *
 * @param array<string, string> $nameByUuid every configured gateway's UUID => its name
 * @return array{import: bool, records: list<array{gateway: string, boot: string, since: int}>,
 *               lines: list<array{0: int, 1: string}>} lines: priority and text
 */
function wf_legacy_import_plan(?string $csv, array $nameByUuid, string $bootId, int $now): array
{
    if ($csv === null) {
        return ['import' => false, 'records' => [], 'lines' => []];
    }
    $records = wf_import_legacy_held($csv, $nameByUuid, $bootId, $now);
    $lines = [];
    foreach ($records as $r) {
        $lines[] = [LOG_NOTICE, 'hold of ' . $nameByUuid[$r['gateway']] . " carried over, taken in boot {$bootId}"];
    }
    $named = [];
    foreach (array_unique(explode(',', $csv)) as $uuid) {
        if (isset($nameByUuid[$uuid])) {
            $named[] = $nameByUuid[$uuid];
        } elseif ($uuid !== '') {
            $lines[] = [LOG_NOTICE, "held entry {$uuid} names no gateway; dropped"];
        }
    }
    if ($bootId === '' && $named !== []) {
        $lines[] = [LOG_WARNING, 'kern.boot_id cannot be read, so no hold is carried over; each of ' . implode(', ', $named)
            . ' keeps its force_down until it is cleared by hand'];
    }
    return ['import' => true, 'records' => $records, 'lines' => $lines];
}

/**
 * Discard everything measured before a reboot (spec 3.11). Ownership in config is released by the
 * caller (boot.php, or evaluate's own boot detector); this resets the runtime side only. The foreign records pruned
 * within the hour stay, for the page, while their gateways stay forced down.
 *
 * @param array $state the shape returned by wf_state_new()
 * @return array the shape returned by wf_state_new()
 */
function wf_boot_reset(array $state, string $bootId): array
{
    $new = wf_state_new($bootId);
    $new['installed_at'] = $state['installed_at'] ?? null;
    $new['unowned_alerted_at'] = $state['unowned_alerted_at'] ?? [];
    $new['contract_last'] = $state['contract_last'] ?? '';
    $new['foreign_pruned'] = $state['foreign_pruned'] ?? [];
    return $new;
}
