<?php

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The plugin library load of every cron and configd entry script. A package upgrade replaces lib/ while cron
 * runs, so a lib file can be missing or half there for a moment, or for good after a failed deploy. Required
 * unchecked, it ends the script as an uncaught fatal, which lands in PHP's error log and so in core's GUI crash
 * reporter. Loaded through here, it ends the script quietly instead, with one line to the WireGuard log per
 * state: the failure once (a marker under the run directory holds its hash, as wgct_note_lock() does for a
 * skipped mirror tick), the recovery once. Self-contained, because the library is what may be missing; each
 * entry script checks that this file is readable before it requires it.
 *
 * While the package removal's marker exists (WGCT_ENTRY_RUN_DIR/removing, written by +PRE_DEINSTALL.pre and
 * deleted by +POST_INSTALL.post), every entry script ends here at once, before any library file is loaded, so
 * nothing re-takes a hold or rebuilds what the removal takes away (spec 2026-10-20 section 3.11, ruling R30).
 * It logs nothing (the minute reconcile says each minute that the marker is there); a command that answers its
 * caller prints its failure. Only the removal's own release-holds runs on.
 */

/* the plugin's run directory; the removal marker lives in it */
const WGCT_ENTRY_RUN_DIR = '/var/run/wgclienttunnels';
const WGCT_ENTRY_REMOVING = 'the package is being removed';

/**
 * Require the entry script's lib/ files, or end the script.
 *
 * @param string        $script   the entry script's file name: it names the marker and the log lines
 * @param string        $tag      the script's log prefix without brackets (wgct-health, ...)
 * @param list<string>  $files    lib/ file names, in require order
 * @param callable|null $failure  (string $error): string, what to print on stdout when the load fails; null
 *                                prints nothing
 * @param int           $exitCode the exit code when the load fails: 0, a quiet end, unless the command must fail
 * @param bool          $removal  the command is the package removal's own, which runs on while the marker exists
 */
function wgct_entry_load(string $script, string $tag, array $files, ?callable $failure = null, int $exitCode = 0,
    bool $removal = false): void
{
    $dir = WGCT_ENTRY_RUN_DIR;
    if (!$removal && is_file($dir . '/removing')) {
        if ($failure !== null) {
            echo $failure(WGCT_ENTRY_REMOVING), "\n";
        }
        exit($exitCode);
    }
    $marker = $dir . '/' . $script . '.libfail';
    $error = null;
    try {
        foreach ($files as $file) {
            if (!is_readable(__DIR__ . '/lib/' . $file)) {
                throw new \RuntimeException('plugin library file ' . $file . ' missing');
            }
            require_once __DIR__ . '/lib/' . $file;
        }
    } catch (\Throwable $e) {
        $error = $e->getMessage();
    }
    $prior = !is_link($marker) && is_file($marker) ? trim((string)@file_get_contents($marker)) : null;
    if ($error === null) {
        if ($prior !== null) {
            @unlink($marker);
            wgct_entry_log('notice', $tag, $script . ' loads the plugin library again');
        }
        return;
    }
    $hash = md5($error);
    if ($hash !== $prior) {
        wgct_entry_log('warning', $tag, $script . ' cannot load the plugin library (' . $error
            . '); it does nothing until the library is back');
        if (!is_link($dir) && (is_dir($dir) || @mkdir($dir, 0700, true)) && @chmod($dir, 0700)) {
            $tmp = @tempnam($dir, $script);
            if ($tmp !== false && (@file_put_contents($tmp, $hash . "\n") === false || !@rename($tmp, $marker))) {
                @unlink($tmp);
            }
        }
    }
    if ($failure !== null) {
        echo $failure($error), "\n";
    }
    exit($exitCode);
}

/**
 * One line to core's WireGuard log, as the library's wgct_log() writes it.
 *
 * @param string $level   a syslog level name
 * @param string $tag     the log prefix without brackets
 * @param string $message
 */
function wgct_entry_log(string $level, string $tag, string $message): void
{
    $line = '[' . $tag . '] ' . trim((string)preg_replace('/\s*\R\s*/', '; ', $message));
    exec('/usr/bin/logger -t wireguard -p user.' . $level . ' -- ' . escapeshellarg($line) . ' > /dev/null 2>&1');
}
