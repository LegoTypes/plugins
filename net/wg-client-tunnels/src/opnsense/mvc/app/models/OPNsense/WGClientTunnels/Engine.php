<?php

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

namespace OPNsense\WGClientTunnels;

use OPNsense\Base\BaseModel;

/**
 * The engine's own state: what the plugin manages and which gateway holds it took.
 * Kept out of the settings model so the API cannot edit it.
 */
class Engine extends BaseModel
{
    /**
     * Read the boot id out of what `sysctl -x -n kern.boot_id` prints, e.g.
     * "Format: Length:16 Dump:0x<32 hex digits>". Pure.
     *
     * @return string lower-case hex, or '' when the output holds no dump
     */
    public static function parseBootId(string $sysctlOut): string
    {
        if (preg_match('/Dump:0x([0-9a-f]+)/i', $sysctlOut, $m) !== 1) {
            return '';
        }
        return strtolower($m[1]);
    }

    /**
     * This boot's id. The value is opaque and only -x prints it as hex.
     *
     * @return string lower-case hex, or '' when it cannot be read
     */
    public static function liveBootId(): string
    {
        $out = shell_exec('/sbin/sysctl -x -n kern.boot_id');
        return is_string($out) ? self::parseBootId($out) : '';
    }
}
