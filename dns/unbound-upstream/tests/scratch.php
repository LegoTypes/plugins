<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Scratch directories for the cases that read files the plugin trusts (convention C3): a fresh, randomly named
 * 0700 directory per case, the four kinds of path that are not a regular file within the read limit, and the runner
 * that turns a case's throw into a failure.
 */

const UU_SCRATCH_MIB = 1048576;           /* the spec's limit (section 5.3), pinned here apart from UU_FILE_MAX_BYTES */

/** A new 0700 directory under the system temporary directory, by its real path (tempnam() resolves its dir). */
function uu_scratch_dir(): string
{
    $dir = (realpath(sys_get_temp_dir()) ?: sys_get_temp_dir()) . '/uu_scratch_' . bin2hex(random_bytes(6));
    if (!mkdir($dir, 0700)) {
        throw new RuntimeException("cannot make the scratch directory $dir");
    }
    return $dir;
}

/** Remove path and everything below it; a symbolic link is removed, never followed, and so is a named pipe. */
function uu_scratch_remove(string $path): void
{
    if (is_link($path) || (file_exists($path) && !is_dir($path))) {
        unlink($path);
        return;
    }
    if (!is_dir($path)) {
        return;
    }
    foreach (scandir($path) ?: [] as $name) {
        if ($name !== '.' && $name !== '..') {
            uu_scratch_remove($path . '/' . $name);
        }
    }
    rmdir($path);
}

/**
 * Run a case that needs no directory. A case that throws (a function not there yet, on the red run) is false, and the
 * throwable's message is printed under it.
 *
 * @param callable(): bool $case
 */
function uu_try_case(callable $case): bool
{
    try {
        return (bool)$case();
    } catch (\Throwable $e) {
        printf("  threw %s: %s\n", get_class($e), $e->getMessage());
        return false;
    }
}

/**
 * Run case in a fresh scratch directory, removed afterwards whatever happens; a throw is false, as in uu_try_case().
 *
 * @param callable(string): bool $case gets the scratch directory
 */
function uu_scratch_case(callable $case): bool
{
    return uu_try_case(function () use ($case): bool {
        $dir = uu_scratch_dir();
        try {
            return (bool)$case($dir);
        } finally {
            uu_scratch_remove($dir);
        }
    });
}

/**
 * Put at path one of the four things a trusted file must not be, each holding (or pointing at) valid where it can:
 * 'link', a symbolic link to a regular file of valid beside it; 'dir', a directory; 'fifo', a named pipe, which an
 * open without O_NONBLOCK would block on until a writer appears; 'large', valid padded with spaces to one byte over
 * 1 MiB (still valid JSON, so only the size refuses it).
 */
function uu_scratch_place(string $kind, string $path, string $valid): void
{
    $rc = 1;
    $ok = match ($kind) {
        'link' => file_put_contents($path . '.target', $valid) !== false && symlink($path . '.target', $path),
        'dir' => mkdir($path, 0700),
        'fifo' => exec('/usr/bin/mkfifo ' . escapeshellarg($path), result_code: $rc) !== false && $rc === 0,
        'large' => file_put_contents($path, str_pad($valid, UU_SCRATCH_MIB + 1, ' ')) !== false,
    };
    if (!$ok) {
        throw new RuntimeException("cannot place a $kind at $path");
    }
}
