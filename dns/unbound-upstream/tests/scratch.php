<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Scratch directories for the cases that read files the plugin trusts (convention C3): a fresh, randomly named
 * 0700 directory per case, and the three kinds of path that are not a regular file within the read limit.
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

/** Remove path and everything below it; a symbolic link is removed, never followed. */
function uu_scratch_remove(string $path): void
{
    if (is_link($path) || is_file($path)) {
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
 * Run case in a fresh scratch directory, removed afterwards whatever happens. A case that throws (a function not
 * there yet, on the red run) is false, and the throwable's message is printed under it.
 *
 * @param callable(string): bool $case gets the scratch directory
 */
function uu_scratch_case(callable $case): bool
{
    $dir = null;
    try {
        $dir = uu_scratch_dir();
        return (bool)$case($dir);
    } catch (\Throwable $e) {
        printf("  threw %s: %s\n", get_class($e), $e->getMessage());
        return false;
    } finally {
        if ($dir !== null) {
            uu_scratch_remove($dir);
        }
    }
}

/**
 * Put at path one of the three things a trusted file must not be, each holding (or pointing at) valid: 'link', a
 * symbolic link to a regular file of valid beside it; 'dir', a directory; 'large', valid padded with spaces to one
 * byte over 1 MiB (still valid JSON, so only the size refuses it).
 */
function uu_scratch_place(string $kind, string $path, string $valid): void
{
    $ok = match ($kind) {
        'link' => file_put_contents($path . '.target', $valid) !== false && symlink($path . '.target', $path),
        'dir' => mkdir($path, 0700),
        'large' => file_put_contents($path, str_pad($valid, UU_SCRATCH_MIB + 1, ' ')) !== false,
    };
    if (!$ok) {
        throw new RuntimeException("cannot place a $kind at $path");
    }
}
