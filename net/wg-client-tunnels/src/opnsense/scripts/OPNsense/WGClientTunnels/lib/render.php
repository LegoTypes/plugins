<?php

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Rendered enforcement (spec 2026-09-24 sections 4.4, 4.5): WAN pins and
 * inner-source blocks registered as filter rules, and the MSS clamp as match
 * rules in a head anchor, all derived from the managed tunnels at every filter
 * reload -- never stored in config. The hook records what it rendered in
 * WGCT_RENDERED_FILE; the reconcile (freshness.php) compares against it.
 *
 * core calls every *_firewall hook (this file's entry point) not only during
 * a real filter reload but also just to list rules for display
 * (scripts/filter/list_non_mvc_rules.php, www/firewall_rule_lookup.php).
 * wgct_in_filter_reload() tells the two apart from the call stack: rules
 * and the anchor are always registered (so they show up on the Rules page
 * either way), but pfctl and the rendered.json write only happen inside a
 * real filter_configure_sync.
 */

if (!is_readable(__DIR__ . '/tunnels.php')) {
    /* thrown during file inclusion, not a compile error: the hook's
     * require_once + try/catch around it can and does catch this. */
    throw new \RuntimeException('[wgct-render] tunnels.php library missing');
}
require_once __DIR__ . '/tunnels.php';

const WGCT_RUN_DIR = '/var/run/wgclienttunnels';

/** the state that must survive a reboot */
const WGCT_DB_DIR = '/var/db/wgclienttunnels';

/* what each state file may hold before it reads as absent (wgct_read_state_file()); 64 KiB covers every small JSON
 * record, the rendered record carries the pin rules of every tunnel */
const WGCT_RENDERED_MAX_BYTES = 1048576;
const WGCT_STATE_MAX_BYTES = 65536;

const WGCT_RENDERED_FILE = WGCT_RUN_DIR . '/rendered.json';

/* freshness.php's own small state: the last filter-reload request it made,
 * so repeated staleness (e.g. a render that keeps failing) does not flood
 * configd with reload requests every reconcile tick. */
const WGCT_FRESHNESS_STATE_FILE = WGCT_RUN_DIR . '/freshness.json';
const WGCT_RELOAD_SUPPRESS_SECONDS = 300;
const WGCT_RELOAD_MAX_WINDOW_SECONDS = 3600;

/* The last pfctl -sr listing's result: pf's ruleset checksum and the pin-label hash it was made for, and how
 * many of those labels pf did not hold. While both are unchanged the count is reused instead of listing again. */
const WGCT_OBSERVED_FILE = WGCT_RUN_DIR . '/observed.json';

/* Serializes freshness.php runs (cron minute, config syshook, monitor and
 * newwanip hooks can overlap): one run's derive -> observe -> plan -> act
 * must not interleave with another's. A run waits for the lock at most
 * WGCT_FRESHNESS_LOCK_TIMEOUT_MS, polling every WGCT_FRESHNESS_LOCK_POLL_MS. */
const WGCT_FRESHNESS_LOCK_FILE = WGCT_RUN_DIR . '/freshness.lock';
const WGCT_FRESHNESS_LOCK_TIMEOUT_MS = 30000;
const WGCT_FRESHNESS_LOCK_POLL_MS = 200;

/* The hash of the failure freshness.php last reported, so a failure that
 * repeats every reconcile tick is logged once, and its recovery once. */
const WGCT_FRESHNESS_ERROR_FILE = WGCT_RUN_DIR . '/freshness.err';

/**
 * @return array ['enabled' => bool, 'pins' => wgct_pin_set(), 'mss' => list<string>]
 */
function wgct_wanted_render(): array {
    $mdl = new \OPNsense\WGClientTunnels\WGClientTunnels();
    $enabled = $mdl->enabled->isEqual('1');
    if (!$enabled) {
        return ['enabled' => false, 'pins' => ['wan' => [], 'inner' => []], 'mss' => []];
    }
    $derived = wgct_derive(wgct_core_snapshot(), wgct_split_csv((string)$mdl->managed));
    return [
        'enabled' => true,
        'pins' => wgct_pin_set($derived, $mdl->wan_pins->isEqual('1'), $mdl->inner_source->isEqual('1')),
        'mss' => wgct_mss_lines($derived, $mdl->mss_clamp->isEqual('1')),
    ];
}

/**
 * @param array $lines
 * @param bool  $quiet when true, suppress the LOG_ERR on failure -- freshness.php
 *                       retries this every reconcile tick and does its own
 *                       hash-deduplicated logging (wgct_anchor_log_plan) so a
 *                       persistently failing anchor does not flood syslog.
 * @return bool
 */
function wgct_load_mss_anchor(array $lines, bool $quiet = false): bool {
    $proc = proc_open(
        ['/sbin/pfctl', '-a', WGCT_MSS_ANCHOR, '-f', '-'],
        [0 => ['pipe', 'r'], 1 => ['file', '/dev/null', 'w'], 2 => ['pipe', 'w']],
        $pipes
    );
    if (!is_resource($proc)) {
        return false;
    }
    fwrite($pipes[0], implode("\n", $lines) . "\n");
    fclose($pipes[0]);
    $err = stream_get_contents($pipes[2]);
    fclose($pipes[2]);
    $rc = proc_close($proc);
    if ($rc !== 0 && !$quiet) {
        wgct_log(LOG_ERR, '[wgct-render] loading anchor ' . WGCT_MSS_ANCHOR . ' failed: ' . trim((string)$err));
    }
    return $rc === 0;
}

/**
 * @param mixed $v any decoded JSON value
 * @return bool true iff $v is a list (0..n-1 keys) of strings
 */
function wgct_is_string_list(mixed $v): bool {
    if (!is_array($v) || !array_is_list($v)) {
        return false;
    }
    foreach ($v as $item) {
        if (!is_string($item)) {
            return false;
        }
    }
    return true;
}

/**
 * @param array $a
 * @param array $keys the exact key set expected, in any order
 * @return bool
 */
function wgct_has_exact_keys(array $a, array $keys): bool {
    $have = array_keys($a);
    sort($have);
    sort($keys);
    return $have === $keys;
}

/**
 * Pure shape check for a decoded rendered.json, matching exactly what
 * wgct_render_firewall() records and wgct_write_rendered() writes (and
 * freshness.php's anchor-retry update, which keeps the same shape): 'at'
 * int, 'failed' bool, 'error' string, 'enabled' bool, 'pins' with 'wan' a
 * list of {wan_if string, family string, endpoints list<string>} and 'inner'
 * list<string>, 'mss' list<string> -- and no other keys at either level. A
 * record of any other shape (hand-edited, truncated, from another version)
 * reads as no record at all, so every reader sees either this shape or
 * null, never a TypeError or a key that is not there.
 *
 * @param mixed $data whatever json_decode(..., true) returned for
 *                     rendered.json: arbitrary decoded JSON at the file
 *                     boundary, which is why it is mixed
 * @return array|null $data unchanged when well-formed, else null
 */
function wgct_validate_rendered(mixed $data): ?array {
    if (!is_array($data) || !wgct_has_exact_keys($data, ['at', 'failed', 'error', 'enabled', 'pins', 'mss'])) {
        return null;
    }
    if (!is_int($data['at']) || !is_bool($data['failed']) || !is_string($data['error'])
        || !is_bool($data['enabled']) || !wgct_is_string_list($data['mss'])) {
        return null;
    }
    $pins = $data['pins'];
    if (!is_array($pins) || !wgct_has_exact_keys($pins, ['wan', 'inner'])
        || !is_array($pins['wan']) || !array_is_list($pins['wan']) || !wgct_is_string_list($pins['inner'])) {
        return null;
    }
    foreach ($pins['wan'] as $w) {
        if (!is_array($w) || !wgct_has_exact_keys($w, ['wan_if', 'family', 'endpoints'])
            || !is_string($w['wan_if']) || !is_string($w['family']) || !wgct_is_string_list($w['endpoints'])) {
            return null;
        }
    }
    return $data;
}

/**
 * The only reader of rendered.json: every caller (freshness.php, lib/view.php,
 * the Tunnels API, site tooling) goes through here and so through
 * wgct_validate_rendered().
 *
 * @return array|null the record, or null when there is none or it is malformed
 */
function wgct_read_rendered(): ?array {
    $raw = wgct_read_state_file(WGCT_RENDERED_FILE, WGCT_RENDERED_MAX_BYTES);
    return $raw !== null ? wgct_validate_rendered(json_decode($raw, true)) : null;
}

/**
 * The only reader of a state file the plugin trusts (C3). The file must be a regular file (never a
 * symlink), owned by root and no larger than $maxBytes; anything else reads as absent. PHP has no
 * O_NOFOLLOW, so the check comes before the read; the state directories being root 0700 is what makes the
 * remaining race unreachable.
 *
 * @param string $path
 * @param int    $maxBytes
 * @return string|null the content, or null when the file is absent or not trustworthy
 */
function wgct_read_state_file(string $path, int $maxBytes): ?string {
    clearstatcache(true, $path);
    if (is_link($path) || !is_file($path) || @fileowner($path) !== 0) {
        return null;
    }
    $size = @filesize($path);
    if ($size === false || $size > $maxBytes) {
        return null;
    }
    $content = @file_get_contents($path);
    return $content === false ? null : $content;
}

/**
 * Create a state directory 0700 (mkdir() honours the umask, so chmod() follows), and tighten one that
 * already exists. A path that is not a plain directory is refused.
 *
 * @param string $dir
 * @return bool true when $dir is a directory with mode 0700
 */
function wgct_state_dir(string $dir): bool {
    if (is_link($dir) || (file_exists($dir) && !is_dir($dir))) {
        return false;
    }
    if (!is_dir($dir) && !@mkdir($dir, 0700, true) && !is_dir($dir)) {
        return false;
    }
    return @chmod($dir, 0700);
}

/**
 * Atomic write via a same-directory temp file (tempnam() creates it 0600,
 * and rename() keeps that mode). Never throws; a temp-file, write or rename
 * failure is logged and reported through the return value instead.
 *
 * @param string $path
 * @param string $data
 * @return bool
 */
function wgct_write_file_atomic(string $path, string $data): bool {
    $dir = dirname($path);
    if (!wgct_state_dir($dir)) {
        wgct_log(LOG_ERR, '[wgct-render] could not create ' . $dir . ' as a 0700 directory');
        return false;
    }
    $tmp = tempnam($dir, pathinfo($path, PATHINFO_FILENAME));
    if ($tmp === false) {
        wgct_log(LOG_ERR, '[wgct-render] could not create a temp file in ' . $dir);
        return false;
    }
    if (file_put_contents($tmp, $data) === false) {
        wgct_log(LOG_ERR, '[wgct-render] could not write ' . $tmp);
        @unlink($tmp);
        return false;
    }
    if (!rename($tmp, $path)) {
        wgct_log(LOG_ERR, '[wgct-render] could not rename ' . $tmp . ' to ' . $path);
        @unlink($tmp);
        return false;
    }
    return true;
}

/**
 * Never throws; every failure (encode, temp file, write, rename) is logged
 * and reported through the return value instead.
 *
 * @param array $r the rendered record
 * @return bool
 */
function wgct_write_rendered(array $r): bool {
    $json = json_encode($r);
    if ($json === false) {
        wgct_log(LOG_ERR, '[wgct-render] could not encode the rendered record: ' . json_last_error_msg());
        return false;
    }
    return wgct_write_file_atomic(WGCT_RENDERED_FILE, $json);
}

/**
 * Deterministic fingerprint of an array (a wanted pin set, or a set of MSS
 * lines), so freshness.php can tell "still waiting on the reload/anchor
 * retry I already asked for" apart from "what I'm waiting on moved while I
 * was waiting".
 *
 * @param array $x
 * @return string
 */
function wgct_hash_array(array $x): string {
    return md5(json_encode($x));
}

/**
 * @param array $pins wgct_wanted_render()['pins'] or a rendered record's 'pins'
 * @return bool true iff there is at least one WAN pin or inner-source block
 */
function wgct_pins_nonempty(array $pins): bool {
    return !empty($pins['wan']) || !empty($pins['inner']);
}

/**
 * The MSS anchor's rule count, for wgct_live_observation() and for a run that
 * reuses the recorded missing_labels (it still lists the anchor, which is cheap).
 *
 * @param array $anchorLines `pfctl -a wgclienttunnels_mss -sr` lines; blank lines are not rules
 * @return int
 */
function wgct_anchor_rule_count(array $anchorLines): int {
    $count = 0;
    foreach ($anchorLines as $line) {
        if (trim((string)$line) !== '') {
            $count++;
        }
    }
    return $count;
}

/**
 * What pf is actually enforcing, from the output of `pfctl -a
 * WGCT_MSS_ANCHOR -sr` and `pfctl -sr` (stdout lines, as exec() returns
 * them). Pure, so it is directly testable; freshness.php runs the two
 * commands and hands the result to wgct_freshness_plan() as $live.
 *
 * @param array $anchorLines `pfctl -a wgclienttunnels_mss -sr` lines; blank lines are not rules
 * @param array $ruleLines   `pfctl -sr` lines; pf prints each rule's label as label "<32 hex>"
 * @param array $pins        the rendered record's 'pins'
 * @return array ['anchor_count' => int, 'missing_labels' => int] -- the
 *               anchor's rule count, and how many of the distinct labels
 *               wgct_pin_rules() builds for $pins pf does not hold
 */
function wgct_live_observation(array $anchorLines, array $ruleLines, array $pins): array {
    $anchorCount = wgct_anchor_rule_count($anchorLines);
    $ruleText = implode("\n", $ruleLines);
    $missing = 0;
    foreach (array_unique(array_column(wgct_pin_rules($pins), 'label')) as $label) {
        if (strpos($ruleText, 'label "' . $label . '"') === false) {
            $missing++;
        }
    }
    return ['anchor_count' => $anchorCount, 'missing_labels' => $missing];
}

/**
 * Whether /tmp/rules.debug.error (already confirmed present and non-empty by
 * the caller) counts as evidence that the render at $renderedAt never
 * actually reached pf. filter.inc stamps this file, then restores the old
 * ruleset, when `pfctl -f /tmp/rules.debug` fails; the hook stamps
 * rendered.json's 'at' from inside the same filter_configure_sync, usually
 * in the same second as the pfctl call, so the comparison must not require
 * the error file to be strictly newer.
 *
 * @param int $mtime      mtime of /tmp/rules.debug.error
 * @param int $renderedAt rendered.json's 'at'
 * @return bool
 */
function wgct_error_file_stale(int $mtime, int $renderedAt): bool {
    return $mtime >= $renderedAt;
}

/* the most /tmp/rules.debug.error may hold to count as evidence (filter.inc writes one pfctl message) */
const WGCT_RULES_ERROR_MAX_BYTES = 65536;

/**
 * Whether the text of /tmp/rules.debug.error has the shape filter.inc leaves there (spec 3.4): not empty, and
 * its first line names pfctl. The caller has already read it through wgct_read_state_file(), so it is a
 * root-owned regular file of at most WGCT_RULES_ERROR_MAX_BYTES. Pure.
 *
 * @param string $content
 * @return bool
 */
function wgct_rules_error_shape(string $content): bool {
    $first = strstr($content, "\n", true);
    return $content !== '' && str_contains($first === false ? $content : $first, 'pfctl');
}

/**
 * Pure normaliser for whatever json_decode() hands back for freshness.json
 * (including garbage: a hand-edited or truncated file, or one from a future
 * version of this plugin). wgct_freshness_plan()'s $state parameter is
 * type-hinted ?array; handing it anything else (a string, an int, ...) is a
 * TypeError that the try/catch in freshness.php would catch and log every
 * tick, but since freshness.php would exit before ever rewriting the file,
 * a corrupt freshness.json would wedge the reconcile forever. Normalising on
 * read means a corrupt/malformed field is simply treated as absent, and the
 * very next successful run overwrites the file with something well-formed.
 *
 * @param mixed $raw whatever json_decode(..., true) returned: arbitrary
 *                    decoded JSON at the file boundary, which is why it is mixed
 * @return array ['reload' => array|null, 'anchor_fail_hash' => string|null]
 *               'reload', if present, always has 'window' clamped to
 *               [WGCT_RELOAD_SUPPRESS_SECONDS, WGCT_RELOAD_MAX_WINDOW_SECONDS].
 */
function wgct_normalize_freshness_state(mixed $raw): array {
    $reload = null;
    $anchorFailHash = null;
    if (is_array($raw)) {
        if (isset($raw['reload']) && is_array($raw['reload'])) {
            $reload = $raw['reload'];
            $window = (int)($reload['window'] ?? WGCT_RELOAD_SUPPRESS_SECONDS);
            $reload['window'] = max(WGCT_RELOAD_SUPPRESS_SECONDS, min($window, WGCT_RELOAD_MAX_WINDOW_SECONDS));
        }
        if (isset($raw['anchor_fail_hash']) && is_string($raw['anchor_fail_hash'])) {
            $anchorFailHash = $raw['anchor_fail_hash'];
        }
    }
    return ['reload' => $reload, 'anchor_fail_hash' => $anchorFailHash];
}

/**
 * @return array ['reload' => array|null, 'anchor_fail_hash' => string|null],
 *               already normalised -- see wgct_normalize_freshness_state().
 */
function wgct_read_freshness_state(): array {
    $raw = wgct_read_state_file(WGCT_FRESHNESS_STATE_FILE, WGCT_STATE_MAX_BYTES);
    $data = $raw !== null ? json_decode($raw, true) : null;
    return wgct_normalize_freshness_state($data);
}

/**
 * Atomic write via a same-directory temp file, like wgct_write_rendered().
 * $s === null means there is nothing left worth remembering (current, or an
 * anchor-only retry that never touched the rate limit) -- the state file is
 * removed instead of written.
 *
 * @param array|null $s
 * @return bool
 */
function wgct_write_freshness_state(?array $s): bool {
    if ($s === null) {
        @unlink(WGCT_FRESHNESS_STATE_FILE);
        return true;
    }
    $json = json_encode($s);
    if ($json === false) {
        wgct_log(LOG_ERR, '[wgct-render] could not encode the freshness state: ' . json_last_error_msg());
        return false;
    }
    return wgct_write_file_atomic(WGCT_FRESHNESS_STATE_FILE, $json);
}

/**
 * pf's ruleset checksum from `pfctl -si -v` (stdout lines, as exec() returns
 * them). pf recomputes it whenever the main ruleset is loaded, so an unchanged
 * value means the rules pfctl -sr would list are unchanged. It does not say a
 * listing is whole: a load that keeps it (an identical one) still cuts short a
 * listing running at that moment, which only pfctl's stderr shows
 * (wgct_pf_listing_usable()).
 *
 * @param array $siLines
 * @return string|null the value after "Checksum: " (e.g. 0x0123...), null when no such line
 */
function wgct_pf_checksum(array $siLines): ?string {
    foreach ($siLines as $line) {
        if (preg_match('/^Checksum:\s+(0x[0-9a-f]+)\s*$/', (string)$line, $m) === 1) {
            return $m[1];
        }
    }
    return null;
}

/**
 * Whether a `pfctl -sr` listing is whole, from its stderr. Every load, an
 * identical one too, makes pfctl stop a listing running at that moment with
 * `pfctl: DIOCGETRULE: Device busy` and exit 0, so a line beginning `pfctl:`
 * makes the listing unusable. pf's ALTQ notices ("No ALTQ support in kernel")
 * do not begin so and change nothing.
 *
 * @param string $stderr the listing's stderr, kept apart from its lines
 * @return bool
 */
function wgct_pf_listing_usable(string $stderr): bool {
    foreach (preg_split('/\R/', $stderr) ?: [] as $line) {
        if (str_starts_with(ltrim($line), 'pfctl:')) {
            return false;
        }
    }
    return true;
}

/**
 * /sbin/pfctl with $args and no shell, its stdout lines split as exec() would
 * and its stderr apart: stderr goes to a temporary file (so a long listing
 * cannot block on a full pipe) and never reaches the lines. A pfctl that
 * cannot be started, or no temporary file for its stderr, reads as a failed
 * run (rc -1), not as a listing cut short.
 *
 * @param array $args list<string>
 * @return array ['rc' => int, 'lines' => list<string>, 'err' => string]
 */
function wgct_pfctl_run(array $args): array {
    $errFile = tempnam(sys_get_temp_dir(), 'wgct_pfctl');
    if ($errFile === false) {
        return ['rc' => -1, 'lines' => [], 'err' => 'pfctl: no temporary file for its stderr'];
    }
    try {
        $pipes = [];
        $proc = proc_open(
            array_merge(['/sbin/pfctl'], $args),
            [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['file', $errFile, 'w']],
            $pipes
        );
        if (!is_resource($proc)) {
            return ['rc' => -1, 'lines' => [], 'err' => 'pfctl: could not be started'];
        }
        $out = (string)stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        $rc = proc_close($proc);
        $err = (string)@file_get_contents($errFile);
    } finally {
        @unlink($errFile);
    }
    /* as exec() returns them: one entry per line, trailing whitespace stripped, no final empty line */
    $lines = $out === '' ? [] : array_map('rtrim', explode("\n", rtrim($out, "\n")));
    return ['rc' => $rc, 'lines' => $lines, 'err' => $err];
}

/**
 * The failure text for a wgct_pfctl_run() whose rc is not 0: pfctl's exit
 * status, or for a run that never started (rc -1) the reason when one is
 * known, so a log line reads "exit -1" only when nothing better exists.
 *
 * @param string $what the command as the text names it, e.g. 'pfctl -sr'
 * @param array  $run  wgct_pfctl_run()'s result
 * @return string
 */
function wgct_pfctl_failure(string $what, array $run): string {
    $reason = trim($run['err']);
    return $run['rc'] === -1 && $reason !== ''
        ? $what . ' failed (' . $reason . ')'
        : $what . ' failed (exit ' . $run['rc'] . ')';
}

/**
 * Identifies the pin labels the rendered pins make freshness look for.
 *
 * @param array $pins the rendered record's 'pins'
 * @return string md5 of the sorted distinct labels of wgct_pin_rules($pins), one per line
 */
function wgct_pin_labels_hash(array $pins): string {
    $labels = array_values(array_unique(array_column(wgct_pin_rules($pins), 'label')));
    sort($labels, SORT_STRING);
    return md5(implode("\n", $labels));
}

/**
 * Whether the last listing's result still holds: pf's ruleset and the labels
 * looked for are both the ones the record was made from, and pf held every
 * label. A recorded miss is never reused: it is what freshness acts on, and
 * the listing that counted it may have been cut short by a load that kept the
 * checksum, so while it stands every run lists again.
 *
 * @param array|null  $record     wgct_read_observed()
 * @param string|null $checksum   pf's checksum now, null when unreadable
 * @param string      $labelsHash wgct_pin_labels_hash() of the rendered pins
 * @return int|null the recorded missing_labels (0) to reuse, null when pf must be listed
 */
function wgct_observed_reuse(?array $record, ?string $checksum, string $labelsHash): ?int {
    if ($record === null || $checksum === null || $record['missing_labels'] > 0
        || $record['checksum'] !== $checksum || $record['labels_hash'] !== $labelsHash) {
        return null;
    }
    return $record['missing_labels'];
}

/**
 * Lists pf's rules and proves no ruleset load ran meanwhile: the checksum read
 * before the listing must equal the one read after it, and the listing must be
 * whole (an identical load keeps the checksum but still cuts it short, which
 * $listing reports as null), else it is retried (once, by default) and never
 * used.
 *
 * The caller has already read the checksum for the reuse decision and passes
 * that read as $first, so the first pair costs one read before the listing,
 * not two. A caller whose first read failed does not call this (an unreadable
 * checksum lists as before and records nothing). A listing that failed is
 * $listing throwing, left to the caller. An empty listing is a valid one.
 *
 * @param string   $first    the checksum the caller read before calling
 * @param callable $checksum (): ?string, pf's checksum now, null when unreadable
 * @param callable $listing  (): ?list<string>, the `pfctl -sr` lines, null when
 *                           pfctl cut the listing short (wgct_pf_listing_usable())
 * @param int      $pairs    how many reads-around-a-listing to try
 * @return array|null ['checksum' => string, 'lines' => list<string>] of the first
 *                    whole listing the reads around it agree on; null when a read
 *                    is unreadable or $pairs listings were all cut short or
 *                    straddled a load
 */
function wgct_observe_listing(string $first, callable $checksum, callable $listing, int $pairs = 2): ?array {
    $before = $first;
    for ($i = 0; $i < $pairs; $i++) {
        if ($i > 0) {
            $before = $checksum();
        }
        if ($before === null) {
            return null;
        }
        $lines = $listing();
        if ($lines === null) {
            continue;
        }
        $after = $checksum();
        if ($after === null) {
            return null;
        }
        if ($after === $before) {
            return ['checksum' => $after, 'lines' => $lines];
        }
    }
    return null;
}

/**
 * Why no listing could be used, and whether that is a fault. Both listings
 * cut short or straddled by a ruleset load is expected in a reload burst and
 * clears itself (the next run lists again), so it is no failure to report; a
 * checksum that turned unreadable seconds after it was read is one.
 *
 * @param bool $checksumUnreadable whether a checksum read inside wgct_observe_listing() was unreadable
 * @return array ['error' => string, 'transient' => bool]
 */
function wgct_unobserved_listing(bool $checksumUnreadable): array {
    return $checksumUnreadable
        ? ['error' => 'pf\'s ruleset checksum became unreadable around pfctl -sr', 'transient' => false]
        : ['error' => 'pfctl -sr listed twice, each time during a ruleset load', 'transient' => true];
}

/**
 * Pure normaliser for whatever json_decode() hands back for observed.json, as
 * wgct_normalize_freshness_state() is for freshness.json: a corrupt record
 * reads as none, so freshness lists and the next run rewrites it.
 *
 * @param mixed $data arbitrary decoded JSON at the file boundary, which is why it is mixed
 * @return array|null array{checksum: string, labels_hash: string, missing_labels: int}
 */
function wgct_normalize_observed(mixed $data): ?array {
    if (!is_array($data) || !wgct_has_exact_keys($data, ['checksum', 'labels_hash', 'missing_labels'])
        || !is_string($data['checksum']) || !is_string($data['labels_hash'])
        || !is_int($data['missing_labels']) || $data['missing_labels'] < 0) {
        return null;
    }
    return [
        'checksum' => $data['checksum'],
        'labels_hash' => $data['labels_hash'],
        'missing_labels' => $data['missing_labels'],
    ];
}

/**
 * @return array|null array{checksum: string, labels_hash: string, missing_labels: int}, null when absent or corrupt
 */
function wgct_read_observed(): ?array {
    $raw = wgct_read_state_file(WGCT_OBSERVED_FILE, WGCT_STATE_MAX_BYTES);
    return wgct_normalize_observed($raw !== null ? json_decode($raw, true) : null);
}

/**
 * Atomic write via a same-directory temp file, like wgct_write_freshness_state().
 *
 * @param array $record array{checksum: string, labels_hash: string, missing_labels: int}
 * @return bool
 */
function wgct_write_observed(array $record): bool {
    $json = json_encode($record);
    if ($json === false) {
        wgct_log(LOG_ERR, '[wgct-render] could not encode the observed record: ' . json_last_error_msg());
        return false;
    }
    return wgct_write_file_atomic(WGCT_OBSERVED_FILE, $json);
}

/**
 * Poll for an exclusive flock on $path: retry LOCK_EX|LOCK_NB every $pollMs
 * for up to $timeoutMs rather than blocking without bound. Shared by
 * freshness.php (which can run inside a configd action, via the monitor hook) and
 * the gateway lock in lib/apply.php (which waits at most 120 s, ruling 22).
 * The lock is held for as long as the returned object is referenced; the
 * process exiting releases it.
 *
 * @param string $path
 * @param int    $timeoutMs
 * @param int    $pollMs
 * @return \SplFileObject|null the open, locked file, or null when another
 *                             holder still held the lock at the timeout
 * @throws \RuntimeException when the lock file cannot be opened
 */
function wgct_poll_lock(string $path, int $timeoutMs, int $pollMs): ?\SplFileObject {
    if (dirname($path) === WGCT_RUN_DIR) {
        wgct_state_dir(WGCT_RUN_DIR);
    }
    /* 'e' = close-on-exec: a caller that exec()s or leaves a detached child
     * running (freshness's filter reload; anything the gateway-locked apply
     * starts) must not have that child inherit the lock */
    $file = new \SplFileObject($path, 'ce');
    $waited = 0;
    while (!$file->flock(LOCK_EX | LOCK_NB)) {
        if ($waited >= $timeoutMs) {
            return null;
        }
        usleep($pollMs * 1000);
        $waited += $pollMs;
    }
    return $file;
}

/**
 * @return string|null the hash of the failure freshness.php last reported, or null
 */
function wgct_read_freshness_error_hash(): ?string {
    $raw = wgct_read_state_file(WGCT_FRESHNESS_ERROR_FILE, WGCT_STATE_MAX_BYTES);
    $hash = $raw !== null ? trim($raw) : '';
    return $hash !== '' ? $hash : null;
}

/**
 * @param string|null $hash the failure hash to remember (written 0600), or
 *                          null to remove the file
 * @return bool
 */
function wgct_write_freshness_error_hash(?string $hash): bool {
    if ($hash === null) {
        if (is_file(WGCT_FRESHNESS_ERROR_FILE)) {
            return unlink(WGCT_FRESHNESS_ERROR_FILE);
        }
        return true;
    }
    return wgct_write_file_atomic(WGCT_FRESHNESS_ERROR_FILE, $hash . "\n");
}

/**
 * Report how a freshness.php run ended, hash-deduplicated through
 * WGCT_FRESHNESS_ERROR_FILE (wgct_failure_log_plan): LOG_ERR once per
 * distinct failure rather than every reconcile tick, and LOG_NOTICE
 * "freshness recovered" once, removing the file, on the next clean run.
 *
 * @param string|null $error what went wrong this run, or null for a clean run
 */
function wgct_report_freshness_outcome(?string $error): void {
    $prior = wgct_read_freshness_error_hash();
    $plan = wgct_failure_log_plan($prior, $error !== null ? md5($error) : null);
    if ($plan['log_error']) {
        wgct_log(LOG_ERR, '[wgct-render] ' . $error);
    }
    if ($plan['log_recovery']) {
        wgct_log(LOG_NOTICE, '[wgct-render] freshness recovered');
    }
    if ($plan['fail_hash'] !== $prior) {
        wgct_write_freshness_error_hash($plan['fail_hash']);
    }
}

/**
 * The freshness decision (spec 4.4, 4.7; controller rulings 2026-09-24), pure
 * over its inputs so it is directly testable -- freshness.php only does I/O
 * around it: read rendered.json, stat /tmp/rules.debug.error (through
 * wgct_error_file_stale()), read pf's live state (through
 * wgct_live_observation()), read freshness.json, call this, then act on
 * the plan and persist $plan['state'].
 *
 * Priority, most urgent first:
 *   1. no rendered record at all -> reload, but only if there is anything to
 *      render (non-empty pins, or MSS lines wanted even with no pins -- e.g.
 *      the clamp switch on with no WAN-pin tunnels): a disabled/empty plugin
 *      with no record yet has nothing to enforce and must not spin on this
 *      forever
 *   2. rendered pins differ from wanted -> reload (this includes going from
 *      pins to none, e.g. the plugin was just disabled: the stale pins still
 *      need removing)
 *   3. /tmp/rules.debug.error is at least as new as the render (main ruleset
 *      load failed and the old ruleset was restored; the rendered pins may
 *      never have reached pf) -> reload, but only when the pins at stake are
 *      non-empty: an unrelated ruleset failure while this plugin renders
 *      nothing is not this plugin's problem to fix by reloading
 *   4. the render is marked failed for any other reason than the MSS anchor
 *      load specifically, again only when the pins are non-empty -> reload;
 *      an anchor-only failure retries just the anchor instead
 *   5. the render is not failed but pf does not hold every label the
 *      rendered pins produce ($live['missing_labels'] > 0: e.g. a filter
 *      reload ran while the hook could not render, so pf lost the pins while
 *      rendered.json still describes them) -> reload
 *   6. otherwise, the MSS anchor's live rule count differs from the rendered
 *      MSS line count -> reload the anchor directly
 *   7. otherwise, MSS lines differ -> reload the anchor directly
 *   8. otherwise -> nothing to do: "current" means the record matches what
 *      is wanted and, when $live is known, pf holds what the record says
 * A filter reload re-renders both the pins and the anchor, so cases 1-5 never
 * also need a separate anchor step. With $live null (pf could not be read)
 * cases 5 and 6 are skipped and the decision rests on the record alone.
 * Anchor loads (cases 6, 7 and the anchor-only retry) are not rate-limited:
 * they are cheap and idempotent.
 *
 * Reload requests are rate-limited with exponential back-off: repeating the
 * same wanted-pins hash within the current window of the last request is
 * suppressed rather than asking configd again; the window starts at
 * WGCT_RELOAD_SUPPRESS_SECONDS and doubles (capped at
 * WGCT_RELOAD_MAX_WINDOW_SECONDS) each time a request repeats for the same
 * hash, so a render that keeps failing asks configd less and less often. A
 * change to the wanted-pins hash resets the window to the base. A negative
 * elapsed time (the clock stepped back) is never treated as "within the
 * window" -- it cannot be trusted, so the safer default is to allow the
 * request. $plan['state'] is what freshness.php should now persist as the
 * reload half of freshness.json (null clears it -- nothing left to
 * remember); the caller can tell a first suppression from a repeat by
 * comparing $state['notified'] (input) against $plan['state']['notified']
 * (output) -- false-to-true is the moment to log.
 *
 * @param array      $wanted     wgct_wanted_render()'s ['enabled','pins','mss']
 * @param array|null $rendered   wgct_read_rendered()'s record, or null
 * @param int|null   $errorMtime mtime of /tmp/rules.debug.error, or null
 *                                unless the caller has already established
 *                                the file exists, is non-empty, and
 *                                wgct_error_file_stale() of it and
 *                                $rendered['at'] is true
 * @param array|null $state      the reload half of the last freshness.json
 *                                record, or null
 * @param int        $now        current time
 * @param array|null $live       wgct_live_observation()'s
 *                                ['anchor_count' => int, 'missing_labels' => int]
 *                                (missing_labels possibly the recorded count,
 *                                see wgct_observed_reuse()), or null when pf
 *                                could not be read (pfctl exited non-zero, or
 *                                every listing straddled a ruleset load)
 * @return array ['reload' => bool, 'anchor' => bool, 'reason' => string, 'state' => array|null]
 */
function wgct_freshness_plan(array $wanted, ?array $rendered, ?int $errorMtime, ?array $state, int $now, ?array $live): array {
    $anchorOnlyError = $rendered !== null && $rendered['failed']
        && strpos((string)($rendered['error'] ?? ''), 'MSS anchor load failed') === 0;

    if ($rendered === null) {
        $needReload = wgct_pins_nonempty($wanted['pins']) || !empty($wanted['mss']);
        $reason = $needReload ? 'no rendered record' : 'nothing rendered yet';
    } elseif ($rendered['pins'] !== $wanted['pins']) {
        $needReload = true;
        $reason = 'pins changed';
    } elseif ($errorMtime !== null && wgct_pins_nonempty($rendered['pins'])) {
        $needReload = true;
        $reason = 'main ruleset load failed since the last render';
    } elseif ($rendered['failed'] && !$anchorOnlyError && wgct_pins_nonempty($rendered['pins'])) {
        $needReload = true;
        $reason = 'previous render failed';
    } elseif (!$rendered['failed'] && $live !== null && $live['missing_labels'] > 0) {
        $needReload = true;
        $reason = 'rendered pins missing from pf';
    } else {
        $needReload = false;
        $reason = '';
    }

    if ($needReload) {
        $hash = wgct_hash_array($wanted['pins']);
        $sameHash = $state !== null && ($state['pins_hash'] ?? null) === $hash;
        $priorWindow = $sameHash
            ? (int)($state['window'] ?? WGCT_RELOAD_SUPPRESS_SECONDS)
            : WGCT_RELOAD_SUPPRESS_SECONDS;
        $elapsed = $sameHash ? $now - (int)($state['requested_at'] ?? 0) : null;
        $withinWindow = $sameHash && $elapsed !== null && $elapsed >= 0 && $elapsed < $priorWindow;
        if ($withinWindow) {
            return [
                'reload' => false,
                'anchor' => false,
                'reason' => $reason . '; filter reload suppressed (rate-limited)',
                'state' => [
                    'requested_at' => $state['requested_at'],
                    'pins_hash' => $hash,
                    'notified' => true,
                    'window' => $priorWindow,
                ],
            ];
        }
        $newWindow = $sameHash
            ? min($priorWindow * 2, WGCT_RELOAD_MAX_WINDOW_SECONDS)
            : WGCT_RELOAD_SUPPRESS_SECONDS;
        return [
            'reload' => true,
            'anchor' => false,
            'reason' => $reason,
            'state' => [
                'requested_at' => $now,
                'pins_hash' => $hash,
                'notified' => false,
                'window' => $newWindow,
            ],
        ];
    }

    if ($rendered === null) {
        /* disabled/empty and nothing was ever rendered: no anchor to check
         * against, nothing to do. */
        return ['reload' => false, 'anchor' => false, 'reason' => $reason, 'state' => null];
    }
    if ($anchorOnlyError) {
        return [
            'reload' => false,
            'anchor' => true,
            'reason' => 'anchor-only failure; retrying the MSS anchor load',
            'state' => null,
        ];
    }
    if ($live !== null && $live['anchor_count'] !== count($rendered['mss'])) {
        return ['reload' => false, 'anchor' => true, 'reason' => 'MSS anchor differs from the last render', 'state' => null];
    }
    if ($rendered['mss'] !== $wanted['mss']) {
        return ['reload' => false, 'anchor' => true, 'reason' => 'MSS lines changed', 'state' => null];
    }
    return ['reload' => false, 'anchor' => false, 'reason' => 'current', 'state' => null];
}

/**
 * Hash-deduplicated logging decision for something retried every reconcile
 * tick: a failure that keeps recurring with the same hash logs once (not
 * every tick), a different failure logs again, and the first success after
 * a failure logs a recovery once. Only the logging is throttled; the caller
 * retries regardless.
 *
 * @param string|null $priorHash the failure hash last persisted, or null
 * @param string|null $failHash  this attempt's failure hash, or null when it succeeded
 * @return array ['log_error' => bool, 'log_recovery' => bool, 'fail_hash' => string|null]
 *               fail_hash is what the caller should now persist (null
 *               clears it, on success).
 */
function wgct_failure_log_plan(?string $priorHash, ?string $failHash): array {
    if ($failHash === null) {
        return ['log_error' => false, 'log_recovery' => $priorHash !== null, 'fail_hash' => null];
    }
    return ['log_error' => $priorHash !== $failHash, 'log_recovery' => false, 'fail_hash' => $failHash];
}

/**
 * How freshness.php should log an MSS-anchor load attempt it just made:
 * wgct_failure_log_plan() keyed by the hash of the lines loaded. The retry
 * itself (calling wgct_load_mss_anchor) always runs every tick regardless
 * of this decision -- only the logging is throttled.
 *
 * @param string|null $priorFailHash the anchor_fail_hash last persisted in
 *                                     freshness.json, or null
 * @param bool        $success       whether this tick's wgct_load_mss_anchor() call succeeded
 * @param array       $mssLines      the lines that were (re)loaded
 * @return array ['log_error' => bool, 'log_recovery' => bool, 'fail_hash' => string|null]
 *               fail_hash is what freshness.php should now persist as
 *               anchor_fail_hash (null clears it, on success).
 */
function wgct_anchor_log_plan(?string $priorFailHash, bool $success, array $mssLines): array {
    return wgct_failure_log_plan($priorFailHash, $success ? null : wgct_hash_array($mssLines));
}

/**
 * True iff the call stack contains filter_configure_sync -- i.e. this is a
 * real filter reload, not a rules-listing call that only wants the hook to
 * enumerate rules for display. Pure over the frames debug_backtrace() gives
 * it, so it is directly testable with a fake frame list.
 *
 * @param array $frames debug_backtrace()-shaped frames
 * @return bool
 */
function wgct_in_filter_reload(array $frames): bool {
    foreach ($frames as $frame) {
        if (($frame['function'] ?? null) === 'filter_configure_sync') {
            return true;
        }
    }
    return false;
}

/**
 * The plugins_firewall hook body. Never throws.
 *
 * $wanted, $loader, $writer and $inReload are injectable so the self-test can
 * exercise every path without config, pf or the filesystem -- in particular,
 * $inReload lets a case force "inside a real filter reload" true or false
 * without a stand-in for core's filter_configure_sync (defining one globally
 * would collide with the real function in a process that has filter.inc
 * loaded, and risks triggering an actual reload).
 *
 * @param \OPNsense\Firewall\Plugin $fw       core's firewall plugin registry
 * @param callable|null             $wanted   returns wgct_wanted_render()'s shape; default wgct_wanted_render
 * @param bool                      $apply    false keeps pfctl and the rendered.json write off
 * @param array|null                $rendered out: the record this call rendered
 * @param callable|null             $loader   (array $lines): bool; default wgct_load_mss_anchor
 * @param callable|null             $writer   (array $record): bool; default wgct_write_rendered
 * @param callable|null             $inReload (): bool; default checks the call stack for filter_configure_sync
 */
function wgct_render_firewall(
    \OPNsense\Firewall\Plugin $fw,
    ?callable $wanted = null,
    bool $apply = true,
    ?array &$rendered = null,
    ?callable $loader = null,
    ?callable $writer = null,
    ?callable $inReload = null
): void {
    $rendered = ['at' => time(), 'failed' => false, 'error' => '', 'enabled' => false,
                 'pins' => ['wan' => [], 'inner' => []], 'mss' => []];
    $loader = $loader ?? 'wgct_load_mss_anchor';
    $writer = $writer ?? 'wgct_write_rendered';
    $inReload = $inReload ?? function () {
        return wgct_in_filter_reload(debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS));
    };
    /* $apply already lets the self-test force pfctl/write off; it is also
     * gated on actually being inside a filter reload, so a rules-listing
     * call (list_non_mvc_rules.php, firewall_rule_lookup.php) that merely
     * enumerates rules for display never touches pf or rendered.json. */
    $apply = $apply && $inReload();
    try {
        /* register the anchor first: a later failure (derivation, malformed
         * pins) still leaves it in the ruleset, with whatever it last
         * loaded, instead of vanishing along with the rules. */
        $fw->registerAnchor(WGCT_MSS_ANCHOR, 'fw', 0, 'head');
        $w = $wanted !== null ? $wanted() : wgct_wanted_render();
        if ($w['enabled']) {
            foreach (wgct_pin_rules($w['pins']) as $conf) {
                $fw->registerFilterRule(WGCT_PIN_PRIORITY, $conf);
            }
        }
        $rendered['enabled'] = $w['enabled'];
        $rendered['pins'] = $w['enabled'] ? $w['pins'] : ['wan' => [], 'inner' => []];
        $rendered['mss'] = $w['enabled'] ? $w['mss'] : [];
        if ($apply && !$loader($rendered['mss'])) {
            $rendered['failed'] = true;
            $rendered['error'] = 'MSS anchor load failed (see syslog)';
        }
    } catch (\Throwable $e) {
        $rendered = ['at' => time(), 'failed' => true, 'error' => $e->getMessage(), 'enabled' => false,
                     'pins' => ['wan' => [], 'inner' => []], 'mss' => []];
        wgct_log(LOG_ERR, '[wgct-render] rules not rendered: ' . $e->getMessage());
    }
    if ($apply) {
        try {
            $writer($rendered);
        } catch (\Throwable $e) {
            wgct_log(LOG_ERR, '[wgct-render] could not write ' . WGCT_RENDERED_FILE . ': ' . $e->getMessage());
        }
    }
}

/**
 * Self-test for the render wrapper. No config, no pf, no /var/run.
 *
 * @return int exit code, 0 when every case passes
 */
function wgct_render_selftest(): int {
    $fail = 0;
    $total = 0;

    /* A stand-in for core's \OPNsense\Firewall\Plugin: a subclass, so it
     * satisfies wgct_render_firewall()'s parameter type, whose constructor
     * skips the parent's (which reads config) and which only records what is
     * registered. The parent's own $anchors is private, so this class's
     * public $anchors is a separate property. */
    $makeFw = function (): \OPNsense\Firewall\Plugin {
        return new class extends \OPNsense\Firewall\Plugin {
            public array $rules = [];
            public array $anchors = [];
            public function __construct() {}
            public function registerFilterRule($prio, $conf, $defaults = null) { $this->rules[] = [$prio, $conf]; }
            public function registerAnchor($name, $type = 'fw', $priority = 0, $placement = 'tail', $quick = false) { $this->anchors[] = [$name, $type, $placement]; }
        };
    };

    /* $inReload stubs stand in for "inside a real filter reload"; never
     * force it true without also stubbing $loader and $writer, or the case
     * would run the real pfctl call and/or write the real rendered.json. */
    $inReloadTrue = function () { return true; };

    $pins = ['wan' => [['wan_if' => 'opt1', 'family' => 'inet', 'endpoints' => ['198.51.100.10']]], 'inner' => ['opt11']];
    $mss = ['match on wg1 inet proto tcp all scrub (max-mss 1336)'];

    /* case 1: a wanted set with one WAN pin, one inner opt and MSS lines */
    $fw = $makeFw();
    $rendered = null;
    wgct_render_firewall($fw, function () use ($pins, $mss) {
        return ['enabled' => true, 'pins' => $pins, 'mss' => $mss];
    }, false, $rendered);
    $ok = count($fw->rules) === 2
        && $fw->rules[0][0] === WGCT_PIN_PRIORITY && $fw->rules[1][0] === WGCT_PIN_PRIORITY
        && $fw->anchors === [[WGCT_MSS_ANCHOR, 'fw', 'head']]
        && $rendered['failed'] === false && $rendered['enabled'] === true
        && $rendered['pins'] === $pins && $rendered['mss'] === $mss;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] render_firewall: enabled with pins and MSS => rules, anchor, rendered record\n", $ok ? 'PASS' : 'FAIL');

    /* core's Rules page (Firewall/filter_rule.volt) files a row by the first digit of its sort_order,
     * sprintf("%06d.1%06d", priority, sequence): 0 automatic (early), 2 floating, 3 group, 4 interface,
     * 5 automatic (late), 6 defunct. A row in any other band has no group, the page's grouping throws,
     * and it shows no rules at all. The pins belong after core's early automatic rules (up to 10000) and
     * before every floating rule, i.e. at the top of band 0. */
    $band = substr(sprintf('%06d', WGCT_PIN_PRIORITY), 0, 1);
    $ok = $band === '0' && WGCT_PIN_PRIORITY > 10000;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] render_firewall: pins sit in core's early automatic band (sort_order digit %s), after its own early rules\n", $ok ? 'PASS' : 'FAIL', $band);

    /* case 2: $wanted throws => anchor is kept (registered before $wanted()
     * runs), no rules, failed with the message */
    $fw = $makeFw();
    $rendered = null;
    wgct_render_firewall($fw, function () {
        throw new \TypeError('boom');
    }, false, $rendered);
    $ok = $fw->rules === [] && $fw->anchors === [[WGCT_MSS_ANCHOR, 'fw', 'head']]
        && $rendered['failed'] === true && $rendered['error'] === 'boom';
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] render_firewall: \$wanted throws => no rules, anchor kept, failed recorded\n", $ok ? 'PASS' : 'FAIL');

    /* case 3: enabled => false => no rules, anchor still registered (harmless), empty MSS */
    $fw = $makeFw();
    $rendered = null;
    wgct_render_firewall($fw, function () {
        return ['enabled' => false, 'pins' => ['wan' => [], 'inner' => []], 'mss' => []];
    }, false, $rendered);
    $ok = $fw->rules === [] && $fw->anchors === [[WGCT_MSS_ANCHOR, 'fw', 'head']]
        && $rendered['failed'] === false && $rendered['enabled'] === false && $rendered['mss'] === [];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] render_firewall: disabled => no rules, anchor still registered, empty MSS\n", $ok ? 'PASS' : 'FAIL');

    /* case 4: malformed pins make wgct_pin_rules() throw building the
     * rules => anchor is still kept, no rules, failed */
    $fw = $makeFw();
    $rendered = null;
    $badPins = ['wan' => [['wan_if' => 'opt1', 'family' => 'inet', 'endpoints' => 'not-an-array']], 'inner' => []];
    wgct_render_firewall($fw, function () use ($badPins) {
        return ['enabled' => true, 'pins' => $badPins, 'mss' => []];
    }, false, $rendered);
    $ok = $fw->rules === [] && $fw->anchors === [[WGCT_MSS_ANCHOR, 'fw', 'head']] && $rendered['failed'] === true;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] render_firewall: malformed pins throw building rules => anchor kept, failed recorded\n", $ok ? 'PASS' : 'FAIL');

    /* case 5: apply=true but $inReload says no (the default would also say
     * no here, since the self-test itself is not inside a real filter
     * reload) => neither the loader nor the writer is invoked */
    $fw = $makeFw();
    $rendered = null;
    $loaderCalls = 0;
    $writerCalls = 0;
    $loader = function ($lines) use (&$loaderCalls) { $loaderCalls++; return true; };
    $writer = function ($r) use (&$writerCalls) { $writerCalls++; return true; };
    wgct_render_firewall($fw, function () use ($pins, $mss) {
        return ['enabled' => true, 'pins' => $pins, 'mss' => $mss];
    }, true, $rendered, $loader, $writer, function () { return false; });
    $ok = $loaderCalls === 0 && $writerCalls === 0 && $rendered['failed'] === false;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] render_firewall: apply=true, not in a filter reload => loader and writer not called\n", $ok ? 'PASS' : 'FAIL');

    /* case 6: inside a (stubbed) real filter reload, the loader fails =>
     * failed true, with pins/mss/rules kept. The writer is stubbed too, so
     * this case cannot reach the real wgct_write_rendered(). */
    $fw = $makeFw();
    $rendered = null;
    $loader = function ($lines) { return false; };
    $writer = function ($r) { return true; };
    wgct_render_firewall($fw, function () use ($pins, $mss) {
        return ['enabled' => true, 'pins' => $pins, 'mss' => $mss];
    }, true, $rendered, $loader, $writer, $inReloadTrue);
    $ok = $rendered['failed'] === true && $rendered['pins'] === $pins && $rendered['mss'] === $mss
        && count($fw->rules) === 2 && $fw->anchors === [[WGCT_MSS_ANCHOR, 'fw', 'head']];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] render_firewall: inside a filter reload, loader fails => failed true, pins/mss/rules kept\n", $ok ? 'PASS' : 'FAIL');

    /* case 7: inside a (stubbed) real filter reload, the writer throws =>
     * caught, no exception escapes. The loader is stubbed too, so this case
     * cannot reach the real pfctl. */
    $fw = $makeFw();
    $rendered = null;
    $loader = function ($lines) { return true; };
    $writer = function ($r) { throw new \RuntimeException('write boom'); };
    $escaped = null;
    try {
        wgct_render_firewall($fw, function () use ($pins, $mss) {
            return ['enabled' => true, 'pins' => $pins, 'mss' => $mss];
        }, true, $rendered, $loader, $writer, $inReloadTrue);
    } catch (\Throwable $e) {
        $escaped = $e;
    }
    $ok = $escaped === null && $rendered['failed'] === false && $rendered['pins'] === $pins;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] render_firewall: writer throws inside a filter reload => caught, no exception escapes\n", $ok ? 'PASS' : 'FAIL');

    /* wgct_in_filter_reload: pure helper over debug_backtrace-shaped frames */
    $ok = wgct_in_filter_reload([['function' => 'foo'], ['function' => 'filter_configure_sync'], ['function' => 'bar']]) === true;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] in_filter_reload: frame present => true\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgct_in_filter_reload([['function' => 'foo'], ['function' => 'bar']]) === false;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] in_filter_reload: frame absent => false\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgct_in_filter_reload([]) === false;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] in_filter_reload: no frames => false\n", $ok ? 'PASS' : 'FAIL');

    /* wgct_freshness_plan: pure over its five arguments, no I/O */
    $wanted = ['enabled' => true, 'pins' => $pins, 'mss' => $mss];
    $emptyPins = ['wan' => [], 'inner' => []];
    $wantedDisabled = ['enabled' => false, 'pins' => $emptyPins, 'mss' => []];
    $otherPins = ['wan' => [['wan_if' => 'opt2', 'family' => 'inet', 'endpoints' => ['198.51.100.20']]], 'inner' => []];
    $thirdPins = ['wan' => [['wan_if' => 'opt3', 'family' => 'inet', 'endpoints' => ['198.51.100.30']]], 'inner' => []];
    $otherMss = ['match on wg2 inet proto tcp all scrub (max-mss 1200)'];
    $current = ['at' => 1000, 'failed' => false, 'error' => '', 'enabled' => true, 'pins' => $pins, 'mss' => $mss];
    $currentEmpty = ['at' => 1000, 'failed' => false, 'error' => '', 'enabled' => false, 'pins' => $emptyPins, 'mss' => []];

    $p = wgct_freshness_plan($wanted, null, null, null, 1000, null);
    $ok = $p['reload'] === true && $p['anchor'] === false && $p['state'] !== null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: no rendered record, wanted has pins => reload\n", $ok ? 'PASS' : 'FAIL');

    $p = wgct_freshness_plan($wantedDisabled, null, null, null, 1000, null);
    $ok = $p['reload'] === false && $p['anchor'] === false && $p['state'] === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: no rendered record, wanted disabled/empty => nothing\n", $ok ? 'PASS' : 'FAIL');

    $wantedMssOnly = ['enabled' => true, 'pins' => $emptyPins, 'mss' => $mss];
    $p = wgct_freshness_plan($wantedMssOnly, null, null, null, 1000, null);
    $ok = $p['reload'] === true && $p['anchor'] === false && $p['state'] !== null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: no rendered record, wanted has no pins but wants MSS => reload\n", $ok ? 'PASS' : 'FAIL');

    $r = $current;
    $r['pins'] = $otherPins;
    $p = wgct_freshness_plan($wanted, $r, null, null, 1000, null);
    $ok = $p['reload'] === true && $p['anchor'] === false;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: pins differ => reload\n", $ok ? 'PASS' : 'FAIL');

    $p = wgct_freshness_plan($wantedDisabled, $current, null, null, 1000, null);
    $ok = $p['reload'] === true && $p['anchor'] === false;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: wanted disabled but rendered still carries pins => reload (removes them)\n", $ok ? 'PASS' : 'FAIL');

    $r = $current;
    $r['mss'] = $otherMss;
    $p = wgct_freshness_plan($wanted, $r, null, null, 1000, null);
    $ok = $p['reload'] === false && $p['anchor'] === true && $p['state'] === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: mss only differs => anchor retry\n", $ok ? 'PASS' : 'FAIL');

    /* wgct_error_file_stale: pure boundary check, same-second counts as stale */
    $ok = wgct_error_file_stale(1000, 1000) === true;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] error_file_stale: equal seconds => stale\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgct_error_file_stale(999, 1000) === false;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] error_file_stale: one second earlier => not stale\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgct_error_file_stale(1001, 1000) === true;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] error_file_stale: one second later => stale\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgct_rules_error_shape("pfctl: Syntax error in config file\n/tmp/rules.debug:12: x\n") === true
        && wgct_rules_error_shape('pfctl: no newline') === true
        && wgct_rules_error_shape('') === false
        && wgct_rules_error_shape("some other text\npfctl: second line\n") === false
        && wgct_rules_error_shape("\npfctl: after an empty first line") === false;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] rules_error_shape: non-empty with pfctl on the first line only\n", $ok ? 'PASS' : 'FAIL');

    $p = wgct_freshness_plan($wanted, $current, 1000, null, 1000, null);
    $ok = $p['reload'] === true && $p['anchor'] === false;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: rules.debug.error at the same second as the render => reload\n", $ok ? 'PASS' : 'FAIL');

    $p = wgct_freshness_plan($wanted, $current, 1500, null, 1600, null);
    $ok = $p['reload'] === true && $p['anchor'] === false;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: rules.debug.error newer than the render => reload\n", $ok ? 'PASS' : 'FAIL');

    $p = wgct_freshness_plan($wantedDisabled, $currentEmpty, 1500, null, 1600, null);
    $ok = $p['reload'] === false && $p['anchor'] === false && $p['state'] === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: rules.debug.error present but rendered/wanted pins are empty => nothing\n", $ok ? 'PASS' : 'FAIL');

    $r = $current;
    $r['failed'] = true;
    $r['error'] = 'MSS anchor load failed (see syslog)';
    $p = wgct_freshness_plan($wanted, $r, null, null, 1000, null);
    $ok = $p['reload'] === false && $p['anchor'] === true && $p['state'] === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: anchor-only failure (pins match) => anchor retry, no reload\n", $ok ? 'PASS' : 'FAIL');

    $r = $current;
    $r['failed'] = true;
    $r['error'] = 'boom, something else broke';
    $p = wgct_freshness_plan($wanted, $r, null, null, 1000, null);
    $ok = $p['reload'] === true && $p['anchor'] === false;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: failed for a non-anchor reason, pins non-empty => reload\n", $ok ? 'PASS' : 'FAIL');

    $r = $currentEmpty;
    $r['failed'] = true;
    $r['error'] = 'boom, something else broke';
    $p = wgct_freshness_plan($wantedDisabled, $r, null, null, 1000, null);
    $ok = $p['reload'] === false && $p['anchor'] === false;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: failed for a non-anchor reason, but pins empty => nothing\n", $ok ? 'PASS' : 'FAIL');

    /* rate limiting with exponential back-off */
    $r = $current;
    $r['pins'] = $otherPins;
    $p1 = wgct_freshness_plan($wanted, $r, null, null, 1000, null);
    $ok = $p1['reload'] === true && $p1['state']['notified'] === false && $p1['state']['window'] === WGCT_RELOAD_SUPPRESS_SECONDS;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: first reload request => state recorded, window = base, not yet notified\n", $ok ? 'PASS' : 'FAIL');

    $p2 = wgct_freshness_plan($wanted, $r, null, $p1['state'], 1010, null);
    $ok = $p2['reload'] === false && $p2['anchor'] === false
        && $p1['state']['notified'] === false && $p2['state']['notified'] === true
        && $p2['state']['requested_at'] === $p1['state']['requested_at']
        && $p2['state']['window'] === $p1['state']['window'];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: repeat within the window, same pins => suppressed, first-time notify, window unchanged\n", $ok ? 'PASS' : 'FAIL');

    $p3 = wgct_freshness_plan($wanted, $r, null, $p2['state'], 1020, null);
    $ok = $p3['reload'] === false && $p3['state']['notified'] === true;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: further repeat, already notified => suppressed quietly (no new notify transition)\n", $ok ? 'PASS' : 'FAIL');

    $now = 1000 + $p1['state']['window'];
    $p4 = wgct_freshness_plan($wanted, $r, null, $p1['state'], $now, null);
    $ok = $p4['reload'] === true && $p4['state']['window'] === 2 * WGCT_RELOAD_SUPPRESS_SECONDS;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: repeat after the window elapses, same hash => reload allowed, window doubles\n", $ok ? 'PASS' : 'FAIL');

    /* keep doubling until it hits the cap: 300 -> 600 -> 1200 -> 2400 -> 3600 -> 3600 */
    $state = $p4['state'];
    $now += $state['window'];
    $expected = [1200, 2400, 3600, 3600];
    $backoffOk = true;
    foreach ($expected as $want) {
        $pn = wgct_freshness_plan($wanted, $r, null, $state, $now, null);
        if ($pn['reload'] !== true || $pn['state']['window'] !== $want) {
            $backoffOk = false;
        }
        $state = $pn['state'];
        $now += $state['window'];
    }
    $fail += $backoffOk ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: back-off keeps doubling, capped at %d\n", $backoffOk ? 'PASS' : 'FAIL', WGCT_RELOAD_MAX_WINDOW_SECONDS);

    $wanted2 = ['enabled' => true, 'pins' => $thirdPins, 'mss' => $mss];
    $p5 = wgct_freshness_plan($wanted2, $r, null, $p1['state'], 1010, null);
    $ok = $p5['reload'] === true && $p5['state']['window'] === WGCT_RELOAD_SUPPRESS_SECONDS;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: repeat within the window but the wanted pins changed => reload allowed, window resets to base\n", $ok ? 'PASS' : 'FAIL');

    $backStepped = ['requested_at' => 5000, 'pins_hash' => wgct_hash_array($wanted['pins']), 'notified' => false, 'window' => 300];
    $p = wgct_freshness_plan($wanted, $r, null, $backStepped, 1000, null);
    $ok = $p['reload'] === true;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: negative elapsed (clock stepped back) => never suppressed\n", $ok ? 'PASS' : 'FAIL');

    $noRequestedAt = ['pins_hash' => wgct_hash_array($wanted['pins']), 'notified' => false, 'window' => 300];
    $p = wgct_freshness_plan($wanted, $r, null, $noRequestedAt, 1000, null);
    $ok = $p['reload'] === true;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: state missing requested_at => allowed\n", $ok ? 'PASS' : 'FAIL');

    $p = wgct_freshness_plan($wanted, $current, null, $p1['state'], 1010, null);
    $ok = $p['reload'] === false && $p['anchor'] === false && $p['reason'] === 'current' && $p['state'] === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: pins and mss both current => nothing, stale state cleared\n", $ok ? 'PASS' : 'FAIL');

    /* wgct_anchor_log_plan: pure, hash-deduplicated anchor logging decision */
    $mssHash = wgct_hash_array($mss);
    $otherMssHash = wgct_hash_array($otherMss);

    $lp = wgct_anchor_log_plan(null, false, $mss);
    $ok = $lp['log_error'] === true && $lp['log_recovery'] === false && $lp['fail_hash'] === $mssHash;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] anchor_log_plan: first failure => log_error, hash recorded\n", $ok ? 'PASS' : 'FAIL');

    $lp = wgct_anchor_log_plan($mssHash, false, $mss);
    $ok = $lp['log_error'] === false && $lp['log_recovery'] === false && $lp['fail_hash'] === $mssHash;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] anchor_log_plan: repeat failure, same hash => quiet\n", $ok ? 'PASS' : 'FAIL');

    $lp = wgct_anchor_log_plan($mssHash, false, $otherMss);
    $ok = $lp['log_error'] === true && $lp['fail_hash'] === $otherMssHash;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] anchor_log_plan: failure with different lines => logs again, hash updated\n", $ok ? 'PASS' : 'FAIL');

    $lp = wgct_anchor_log_plan($mssHash, true, $mss);
    $ok = $lp['log_error'] === false && $lp['log_recovery'] === true && $lp['fail_hash'] === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] anchor_log_plan: recovers after failing => log_recovery, hash cleared\n", $ok ? 'PASS' : 'FAIL');

    $lp = wgct_anchor_log_plan(null, true, $mss);
    $ok = $lp['log_error'] === false && $lp['log_recovery'] === false && $lp['fail_hash'] === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] anchor_log_plan: success with no prior failure => quiet\n", $ok ? 'PASS' : 'FAIL');

    /* freshness.php's "plan is current" branch clears a stale anchor_fail_hash
     * by calling wgct_anchor_log_plan(..., true, ...) -- the exact same
     * pure call an actual anchor-retry success makes. This composes the
     * already-tested "current" signal (reload=false, anchor=false,
     * state=null) with the already-tested recovery behaviour to prove the
     * two pieces line up the way freshness.php relies on. */
    $p = wgct_freshness_plan($wanted, $current, null, null, 1000, null);
    $isCurrent = $p['reload'] === false && $p['anchor'] === false && $p['state'] === null;
    $lp = wgct_anchor_log_plan($mssHash, true, $wanted['mss']);
    $ok = $isCurrent && $lp['log_recovery'] === true && $lp['fail_hash'] === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan + anchor_log_plan: plan current with a pending anchor failure => recovery, hash cleared\n", $ok ? 'PASS' : 'FAIL');

    /* wgct_normalize_freshness_state: pure, so a corrupt freshness.json
     * (hand-edited, truncated, or from an incompatible future version) never
     * reaches wgct_freshness_plan()'s ?array-typed $state as anything but
     * a well-formed array or null -- no TypeError, no forever-wedged reconcile. */
    $ok = wgct_normalize_freshness_state(null) === ['reload' => null, 'anchor_fail_hash' => null];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] normalize_freshness_state: not decodable (null) => reload null, hash null\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgct_normalize_freshness_state('garbage') === ['reload' => null, 'anchor_fail_hash' => null];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] normalize_freshness_state: root not an array (a string) => reload null, hash null\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgct_normalize_freshness_state(['reload' => 'garbage', 'anchor_fail_hash' => null])
        === ['reload' => null, 'anchor_fail_hash' => null];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] normalize_freshness_state: 'reload' not an array => treated as absent\n", $ok ? 'PASS' : 'FAIL');

    $huge = ['requested_at' => 100, 'pins_hash' => 'x', 'notified' => false, 'window' => 999999999];
    $r = wgct_normalize_freshness_state(['reload' => $huge, 'anchor_fail_hash' => 'abc']);
    $ok = $r['reload']['window'] === WGCT_RELOAD_MAX_WINDOW_SECONDS && $r['anchor_fail_hash'] === 'abc';
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] normalize_freshness_state: window far above the cap => clamped down\n", $ok ? 'PASS' : 'FAIL');

    $negative = ['requested_at' => 100, 'pins_hash' => 'x', 'notified' => false, 'window' => -5];
    $r = wgct_normalize_freshness_state(['reload' => $negative, 'anchor_fail_hash' => 123]);
    $ok = $r['reload']['window'] === WGCT_RELOAD_SUPPRESS_SECONDS && $r['anchor_fail_hash'] === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] normalize_freshness_state: window below the base, non-string hash => clamped up, hash dropped\n", $ok ? 'PASS' : 'FAIL');

    $r = wgct_normalize_freshness_state(['reload' => null, 'anchor_fail_hash' => 'xyz']);
    $ok = $r === ['reload' => null, 'anchor_fail_hash' => 'xyz'];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] normalize_freshness_state: no reload state but a pending anchor failure => both preserved correctly\n", $ok ? 'PASS' : 'FAIL');

    /* wgct_live_observation: pure over pfctl's output lines. The rule
     * lines stand in for `pfctl -sr`, which prints each rule's label as
     * label "<32 hex>". */
    $pinLabels = array_values(array_unique(array_column(wgct_pin_rules($pins), 'label')));
    $ruleLines = ['scrub on em0 all fragment reassemble'];
    foreach ($pinLabels as $label) {
        $ruleLines[] = 'block drop out log quick on ! em1 inet proto udp from any to 198.51.100.10 label "' . $label . '"';
    }

    $obs = wgct_live_observation([$mss[0], '', '   '], $ruleLines, $pins);
    $ok = $obs === ['anchor_count' => 1, 'missing_labels' => 0];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] live_observation: every rendered label in pf, blank anchor lines dropped => 1 rule, 0 missing\n", $ok ? 'PASS' : 'FAIL');

    $obs = wgct_live_observation([], array_slice($ruleLines, 0, 2), $pins);
    $ok = count($pinLabels) === 2 && $obs === ['anchor_count' => 0, 'missing_labels' => 1];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] live_observation: one of two rendered labels absent from pf, empty anchor => 0 rules, 1 missing\n", $ok ? 'PASS' : 'FAIL');

    /* pf still enforcing the inner-source rule as 3.5_1 rendered it (from ! (self), labelled by interface only):
     * the label differs, so freshness sees the current rule missing and reloads the filter after an upgrade */
    $oldInnerLines = [$ruleLines[0], $ruleLines[1],
        'block drop out log quick on wg1 inet6 from ! (self) to any label "' . md5('wgct-pin-inner-' . $pins['inner'][0]) . '"'];
    $obs = wgct_live_observation([], $oldInnerLines, $pins);
    $ok = $obs === ['anchor_count' => 0, 'missing_labels' => 1];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] live_observation: pf holds the 3.5_1 inner-source rule => its replacement counts as missing\n", $ok ? 'PASS' : 'FAIL');

    $obs = wgct_live_observation([], [], $emptyPins);
    $ok = $obs === ['anchor_count' => 0, 'missing_labels' => 0];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] live_observation: nothing rendered, nothing in pf => 0 rules, 0 missing\n", $ok ? 'PASS' : 'FAIL');

    /* wgct_freshness_plan with a live pf observation */
    $liveGood = ['anchor_count' => count($mss), 'missing_labels' => 0];

    $p = wgct_freshness_plan($wanted, $current, null, null, 1000, $liveGood);
    $ok = $p['reload'] === false && $p['anchor'] === false && $p['reason'] === 'current' && $p['state'] === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: record current and pf holds every label and the anchor's rule count => current\n", $ok ? 'PASS' : 'FAIL');

    $liveMissing = ['anchor_count' => count($mss), 'missing_labels' => 2];
    $pm1 = wgct_freshness_plan($wanted, $current, null, null, 1000, $liveMissing);
    $ok = $pm1['reload'] === true && $pm1['anchor'] === false
        && $pm1['reason'] === 'rendered pins missing from pf' && $pm1['state'] !== null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: record current but rendered labels missing from pf => reload\n", $ok ? 'PASS' : 'FAIL');

    $pm2 = wgct_freshness_plan($wanted, $current, null, $pm1['state'], 1010, $liveMissing);
    $ok = $pm2['reload'] === false && $pm2['anchor'] === false
        && $pm2['reason'] === 'rendered pins missing from pf; filter reload suppressed (rate-limited)';
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: labels still missing within the window => reload suppressed by the same rate limit\n", $ok ? 'PASS' : 'FAIL');

    $r = $current;
    $r['failed'] = true;
    $r['error'] = 'MSS anchor load failed (see syslog)';
    $p = wgct_freshness_plan($wanted, $r, null, null, 1000, $liveMissing);
    $ok = $p['reload'] === false && $p['anchor'] === true;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: labels missing but the record is failed (anchor-only) => anchor retry, no reload\n", $ok ? 'PASS' : 'FAIL');

    $p = wgct_freshness_plan($wanted, $current, null, null, 1000, ['anchor_count' => 0, 'missing_labels' => 0]);
    $ok = $p['reload'] === false && $p['anchor'] === true
        && $p['reason'] === 'MSS anchor differs from the last render' && $p['state'] === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: anchor rule count differs from the rendered MSS lines => anchor reload\n", $ok ? 'PASS' : 'FAIL');

    $p = wgct_freshness_plan($wanted, $current, null, null, 1000, null);
    $ok = $p['reload'] === false && $p['anchor'] === false && $p['reason'] === 'current' && $p['state'] === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: live observation failed (null) => decided from the record alone, as before\n", $ok ? 'PASS' : 'FAIL');

    $wantedNoClamp = ['enabled' => true, 'pins' => $pins, 'mss' => []];
    $r = $current;
    $r['mss'] = [];
    $p = wgct_freshness_plan($wantedNoClamp, $r, null, null, 1000, ['anchor_count' => 0, 'missing_labels' => 0]);
    $ok = $p['reload'] === false && $p['anchor'] === false && $p['reason'] === 'current';
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] freshness_plan: mss_clamp off, rendered mss empty, anchor empty => current\n", $ok ? 'PASS' : 'FAIL');

    /* wgct_validate_rendered: pure shape check between json_decode() and
     * every reader of rendered.json */
    $ok = wgct_validate_rendered($current) === $current;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] validate_rendered: a well-formed record => returned unchanged\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgct_validate_rendered(json_decode(json_encode($currentEmpty), true)) === $currentEmpty;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] validate_rendered: an empty record after a JSON round trip => returned unchanged\n", $ok ? 'PASS' : 'FAIL');

    $bad = $current;
    unset($bad['error']);
    $ok = wgct_validate_rendered($bad) === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] validate_rendered: a missing key => null\n", $ok ? 'PASS' : 'FAIL');

    $bad = $current;
    $bad['extra'] = 1;
    $ok = wgct_validate_rendered($bad) === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] validate_rendered: an unexpected key => null\n", $ok ? 'PASS' : 'FAIL');

    $bad = $current;
    $bad['at'] = '1000';
    $ok = wgct_validate_rendered($bad) === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] validate_rendered: a wrong type ('at' a string) => null\n", $ok ? 'PASS' : 'FAIL');

    $bad = $current;
    $bad['pins']['wan'][0]['endpoints'] = '198.51.100.10';
    $ok = wgct_validate_rendered($bad) === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] validate_rendered: a wrong nested type (endpoints not a list) => null\n", $ok ? 'PASS' : 'FAIL');

    $bad = $current;
    $bad['mss'] = ['a' => $mss[0]];
    $ok = wgct_validate_rendered($bad) === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] validate_rendered: mss keyed, not a list => null\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgct_validate_rendered('garbage') === null && wgct_validate_rendered(null) === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] validate_rendered: not an array at all => null\n", $ok ? 'PASS' : 'FAIL');

    /* wgct_failure_log_plan: the generic hash-deduplicated logging decision
     * behind both the anchor retry and freshness.php's own failures */
    $lp = wgct_failure_log_plan(null, 'h1');
    $ok = $lp === ['log_error' => true, 'log_recovery' => false, 'fail_hash' => 'h1'];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] failure_log_plan: first failure => log_error, hash recorded\n", $ok ? 'PASS' : 'FAIL');

    $lp = wgct_failure_log_plan('h1', 'h1');
    $ok = $lp === ['log_error' => false, 'log_recovery' => false, 'fail_hash' => 'h1'];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] failure_log_plan: the same failure again => quiet\n", $ok ? 'PASS' : 'FAIL');

    $lp = wgct_failure_log_plan('h1', 'h2');
    $ok = $lp === ['log_error' => true, 'log_recovery' => false, 'fail_hash' => 'h2'];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] failure_log_plan: a different failure => logs again, hash updated\n", $ok ? 'PASS' : 'FAIL');

    $lp = wgct_failure_log_plan('h1', null);
    $ok = $lp === ['log_error' => false, 'log_recovery' => true, 'fail_hash' => null];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] failure_log_plan: success after a failure => log_recovery, hash cleared\n", $ok ? 'PASS' : 'FAIL');

    $lp = wgct_failure_log_plan(null, null);
    $ok = $lp === ['log_error' => false, 'log_recovery' => false, 'fail_hash' => null];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] failure_log_plan: success with no prior failure => quiet\n", $ok ? 'PASS' : 'FAIL');

    /* the pf ruleset checksum, the pin-label hash and the observation record */
    $siText = [
        'Status: Enabled for 0 days 01:02:03           Debug: Urgent',
        '',
        'Hostid:   0x12345678',
        'Checksum: 0x0123456789abcdef0123456789abcdef',
        '',
        'State Table                          Total             Rate',
        '  current entries                       42',
    ];
    $ok = wgct_pf_checksum($siText) === '0x0123456789abcdef0123456789abcdef';
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] checksum: parsed\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgct_pf_checksum(array_slice($siText, 0, 3)) === null && wgct_pf_checksum([]) === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] checksum: absent is null\n", $ok ? 'PASS' : 'FAIL');

    $pinsA = ['wan' => [['wan_if' => 'opt1', 'family' => 'inet', 'endpoints' => ['198.51.100.10']]], 'inner' => ['opt11']];
    $pinsB = ['wan' => [['wan_if' => 'opt1', 'family' => 'inet', 'endpoints' => ['198.51.100.10', '198.51.100.11']]], 'inner' => ['opt11']];
    $pinsC = ['wan' => [['wan_if' => 'opt2', 'family' => 'inet', 'endpoints' => ['198.51.100.10']]], 'inner' => ['opt11']];
    /* the same labels, built in another order and with repeats: the precondition proves the order differs */
    $pinsD = [
        'wan' => [['wan_if' => 'opt1', 'family' => 'inet', 'endpoints' => ['198.51.100.10']],
            ['wan_if' => 'opt2', 'family' => 'inet', 'endpoints' => ['198.51.100.20']]],
        'inner' => ['opt11', 'opt12'],
    ];
    $pinsE = [
        'wan' => [['wan_if' => 'opt2', 'family' => 'inet', 'endpoints' => ['198.51.100.20']],
            ['wan_if' => 'opt1', 'family' => 'inet', 'endpoints' => ['198.51.100.10']],
            ['wan_if' => 'opt1', 'family' => 'inet', 'endpoints' => ['198.51.100.11']]],
        'inner' => ['opt12', 'opt11', 'opt12'],
    ];
    $ok = array_values(array_unique(array_column(wgct_pin_rules($pinsD), 'label')))
            !== array_values(array_unique(array_column(wgct_pin_rules($pinsE), 'label')))
        && wgct_pin_labels_hash($pinsD) === wgct_pin_labels_hash($pinsE)
        && wgct_pin_labels_hash($pinsA) === wgct_pin_labels_hash($pinsB)
        && preg_match('/^[0-9a-f]{32}$/', wgct_pin_labels_hash($pinsA)) === 1;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] labels hash: order and duplicates do not matter\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgct_pin_labels_hash($pinsA) !== wgct_pin_labels_hash($pinsC);
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] labels hash: another label changes it\n", $ok ? 'PASS' : 'FAIL');

    $rec = ['checksum' => '0xaa', 'labels_hash' => 'h1', 'missing_labels' => 3];
    $recWhole = ['checksum' => '0xaa', 'labels_hash' => 'h1', 'missing_labels' => 0];
    $ok = wgct_observed_reuse($recWhole, '0xaa', 'h1') === 0;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] reuse: equal keys reuse the count\n", $ok ? 'PASS' : 'FAIL');

    /* a miss is what freshness acts on, and an identical reload (which keeps the checksum) can be the
     * very listing that miscounted it: never trusted, always listed again */
    $ok = wgct_observed_reuse($rec, '0xaa', 'h1') === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] reuse: a recorded miss lists again\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgct_observed_reuse($recWhole, '0xbb', 'h1') === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] reuse: another checksum lists\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgct_observed_reuse($recWhole, '0xaa', 'h2') === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] reuse: another labels hash lists\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgct_observed_reuse(null, '0xaa', 'h1') === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] reuse: no record lists\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgct_observed_reuse($recWhole, null, 'h1') === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] reuse: no checksum lists\n", $ok ? 'PASS' : 'FAIL');

    /* $reads feeds the checksum reads in turn (the first is passed in by the caller); every listing
     * returns the next element of $lists (null: pfctl cut it short) and counts itself in $listed */
    $listed = 0;
    $makeObserve = function (array $reads, array $lists) use (&$listed): array {
        $listed = 0;
        return [
            function () use (&$reads): ?string { return array_shift($reads); },
            function () use (&$lists, &$listed): ?array { $listed++; return array_shift($lists); },
        ];
    };

    [$cs, $ls] = $makeObserve(['0xaa'], [['rule one']]);
    $ok = wgct_observe_listing('0xaa', $cs, $ls) === ['checksum' => '0xaa', 'lines' => ['rule one']] && $listed === 1;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] listing: agreeing reads use the listing\n", $ok ? 'PASS' : 'FAIL');

    [$cs, $ls] = $makeObserve(['0xaa', '0xaa'], [[]]);
    $ok = wgct_observe_listing('0xaa', $cs, $ls) === ['checksum' => '0xaa', 'lines' => []] && $listed === 1;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] listing: an empty ruleset is a listing\n", $ok ? 'PASS' : 'FAIL');

    [$cs, $ls] = $makeObserve(['0xcc', '0xcc', '0xcc'], [['old'], ['new']]);
    $ok = wgct_observe_listing('0xbb', $cs, $ls) === ['checksum' => '0xcc', 'lines' => ['new']] && $listed === 2;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] listing: a reload during the listing lists again\n", $ok ? 'PASS' : 'FAIL');

    [$cs, $ls] = $makeObserve(['0xbb', '0xcc', '0xdd'], [['a'], ['b']]);
    $ok = wgct_observe_listing('0xaa', $cs, $ls) === null && $listed === 2;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] listing: two straddled pairs give none\n", $ok ? 'PASS' : 'FAIL');

    [$cs, $ls] = $makeObserve([null], [['a']]);
    $ok = wgct_observe_listing('0xaa', $cs, $ls) === null && $listed === 1;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] listing: an unreadable checksum gives none\n", $ok ? 'PASS' : 'FAIL');

    [$cs, $ls] = $makeObserve(['0xbb', null], [['a'], ['b']]);
    $ok = wgct_observe_listing('0xaa', $cs, $ls) === null && $listed === 1;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] listing: an unreadable checksum before the second listing gives none\n", $ok ? 'PASS' : 'FAIL');

    /* an identical load keeps the checksum yet cuts a listing short: the reads agree and only
     * pfctl's stderr tells (the listing callable returns null) */
    [$cs, $ls] = $makeObserve(['0xaa', '0xaa', '0xaa'], [null, ['whole']]);
    $ok = wgct_observe_listing('0xaa', $cs, $ls) === ['checksum' => '0xaa', 'lines' => ['whole']] && $listed === 2;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] listing: a listing cut short with agreeing reads is listed again\n", $ok ? 'PASS' : 'FAIL');

    [$cs, $ls] = $makeObserve(['0xaa', '0xaa', '0xaa', '0xaa'], [null, null]);
    $ok = wgct_observe_listing('0xaa', $cs, $ls) === null && $listed === 2;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] listing: two listings cut short give none\n", $ok ? 'PASS' : 'FAIL');

    $altq = "No ALTQ support in kernel\nALTQ related functions disabled\n";
    $ok = wgct_pf_listing_usable('') && wgct_pf_listing_usable($altq)
        && !wgct_pf_listing_usable($altq . "pfctl: DIOCGETRULE: Device busy\n")
        && !wgct_pf_listing_usable('pfctl: DIOCGETRULE: Device busy');
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] listing: a pfctl: line on stderr makes it unusable, the ALTQ notices alone do not\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgct_pfctl_failure('pfctl -sr', ['rc' => 1, 'lines' => [], 'err' => 'pfctl: x']) === 'pfctl -sr failed (exit 1)'
        && wgct_pfctl_failure('pfctl -sr', ['rc' => -1, 'lines' => [], 'err' => "pfctl: could not be started\n"])
            === 'pfctl -sr failed (pfctl: could not be started)'
        && wgct_pfctl_failure('pfctl -sr', ['rc' => -1, 'lines' => [], 'err' => ''])
            === 'pfctl -sr failed (exit -1)';
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] pfctl failure: the exit status, or the reason for a run that never started (the status when none is known)\n", $ok ? 'PASS' : 'FAIL');

    $straddled = wgct_unobserved_listing(false);
    $unreadable = wgct_unobserved_listing(true);
    $ok = $straddled['transient'] === true && $unreadable['transient'] === false
        && $straddled['error'] !== $unreadable['error']
        && strpbrk($straddled['error'] . $unreadable['error'], '()') === false;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] listing: two straddled pairs are transient, an unreadable checksum is a failure\n", $ok ? 'PASS' : 'FAIL');

    $ok = wgct_normalize_observed($rec) === $rec
        && wgct_normalize_observed('x') === null
        && wgct_normalize_observed(null) === null
        && wgct_normalize_observed(['checksum' => '0xaa', 'labels_hash' => 'h1']) === null
        && wgct_normalize_observed(['checksum' => '0xaa', 'labels_hash' => 'h1', 'missing_labels' => '3']) === null
        && wgct_normalize_observed(['checksum' => '0xaa', 'labels_hash' => 'h1', 'missing_labels' => 1.5]) === null
        && wgct_normalize_observed(['checksum' => '0xaa', 'labels_hash' => 'h1', 'missing_labels' => -1]) === null
        && wgct_normalize_observed(['checksum' => 5, 'labels_hash' => 'h1', 'missing_labels' => 0]) === null;
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] record: corrupt reads as none\n", $ok ? 'PASS' : 'FAIL');

    /* the C3 reader and the state directories, on temporary files */
    $tmp = sys_get_temp_dir() . '/wgct-state-' . getmypid();
    mkdir($tmp, 0700);
    file_put_contents("$tmp/good", '{"a":1}');
    file_put_contents("$tmp/big", str_repeat('x', 100));
    symlink("$tmp/good", "$tmp/link");
    mkdir("$tmp/dir");
    file_put_contents("$tmp/empty", '');
    $read = function (string $path, int $max) {
        return function_exists('wgct_read_state_file') ? wgct_read_state_file($path, $max) : 'undefined';
    };
    $cases = [
        'state reader: a good root-owned regular file reads as its content' => $read("$tmp/good", 64) === '{"a":1}',
        'state reader: an empty file reads as the empty string' => $read("$tmp/empty", 64) === '',
        'state reader: a file exactly at the limit reads' => $read("$tmp/big", 100) === str_repeat('x', 100),
        'state reader: a file over the limit reads as absent' => $read("$tmp/big", 99) === null,
        'state reader: a symlink to a good file reads as absent' => $read("$tmp/link", 64) === null,
        'state reader: a directory reads as absent' => $read("$tmp/dir", 64) === null,
        'state reader: a missing file reads as absent' => $read("$tmp/missing", 64) === null,
    ];
    $ok = function_exists('wgct_state_dir')
        && wgct_state_dir("$tmp/new/sub") && is_dir("$tmp/new/sub")
        && (fileperms("$tmp/new/sub") & 0777) === 0700;
    $cases['state dir: a new directory is created 0700 whatever the umask'] = $ok;
    mkdir("$tmp/loose", 0755);
    chmod("$tmp/loose", 0755);
    $cases['state dir: an existing directory is tightened to 0700']
        = function_exists('wgct_state_dir') && wgct_state_dir("$tmp/loose") && (fileperms("$tmp/loose") & 0777) === 0700;
    $cases['state dir: a regular file in its place is refused']
        = function_exists('wgct_state_dir') && wgct_state_dir("$tmp/good") === false;
    $cases['state dir: a symlink in its place is refused']
        = function_exists('wgct_state_dir') && wgct_state_dir("$tmp/link") === false;
    foreach ($cases as $desc => $ok) {
        $fail += $ok ? 0 : 1;
        $total++;
        printf("[%s] %s\n", $ok ? 'PASS' : 'FAIL', $desc);
    }
    foreach (['new/sub', 'new', 'loose', 'dir'] as $d) {
        @rmdir("$tmp/$d");
    }
    foreach (['good', 'big', 'link', 'empty'] as $f) {
        @unlink("$tmp/$f");
    }
    @rmdir($tmp);

    printf("%d/%d passed\n", $total - $fail, $total);
    return $fail === 0 ? 0 : 1;
}
