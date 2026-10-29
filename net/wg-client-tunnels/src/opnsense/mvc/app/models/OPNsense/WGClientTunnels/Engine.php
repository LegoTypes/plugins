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
use OPNsense\Base\FieldTypes\ArrayField;

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
        /* at most 64 digits, the most a hold record's boot takes; a longer dump is no boot id */
        if (preg_match('/Dump:0x([0-9a-f]{1,64})(?![0-9a-f])/i', $sysctlOut, $m) !== 1) {
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

    /**
     * The managed instances: each `tunnels` row's instance, in document order.
     *
     * @return list<string> instance uuids
     */
    public function managedList(): array
    {
        $uuids = [];
        foreach ($this->tunnels->iterateItems() as $node) {
            $uuids[] = $node->instance->getValue();
        }
        return $uuids;
    }

    /**
     * Replace the `tunnels` rows with one row per uuid, in order. A row whose instance stays keeps its item uuid,
     * so Config History shows only the rows that changed.
     *
     * @param list<string> $uuids instance uuids
     */
    public function setManaged(array $uuids): void
    {
        $stored = [];
        foreach ($this->tunnels->iterateItems() as $item => $node) {
            $stored[(string)$item] = $node->instance->getValue();
        }
        $kept = self::keptItems($stored, $uuids, fn (string $old, string $new): bool => $old === $new);
        self::rewrite($this->tunnels, $kept, array_map(fn (string $uuid): array => ['instance' => $uuid], $uuids));
    }

    /**
     * The hold records as they are, duplicates and all.
     *
     * @return array<string, array{gateway: string, boot: string, underlay: string, taken_at: int}> by item uuid
     */
    public function holdRows(): array
    {
        $rows = [];
        foreach ($this->holds->iterateItems() as $item => $node) {
            $rows[(string)$item] = [
                'gateway' => $node->gateway->getValue(),
                'boot' => $node->boot->getValue(),
                'underlay' => $node->underlay->getValue(),
                'taken_at' => (int)$node->taken_at->getValue(),
            ];
        }
        return $rows;
    }

    /**
     * Replace every hold record with $rows, in order. A record of a gateway still held keeps its item uuid (the
     * stored record equal to the new one first, else the first of that gateway's), its fields set to the new row's,
     * so Config History shows only the records that changed.
     *
     * @param list<array{gateway: string, boot: string, underlay: string, taken_at: int}> $rows
     */
    public function setHolds(array $rows): void
    {
        $kept = self::keptItems($this->holdRows(), $rows,
            fn (array $old, array $new): bool => $old === $new,
            fn (array $old, array $new): bool => $old['gateway'] === $new['gateway']);
        self::rewrite($this->holds, $kept, array_map(fn (array $row): array => self::holdNodes($row), $rows));
    }

    /**
     * Add one hold record.
     *
     * @param array{gateway: string, boot: string, underlay: string, taken_at: int} $row
     */
    public function addHold(array $row): void
    {
        $this->holds->Add()->setNodes(self::holdNodes($row));
    }

    /**
     * Which stored row each wanted row keeps, in the wanted order: each test in turn lets a wanted row that has
     * none yet take the first stored row it accepts that no other wanted row took. Pure.
     *
     * @template T
     * @param array<string, T>       $stored  item uuid => row, in document order
     * @param list<T>                $wanted  the rows to store, in order
     * @param callable(T, T): bool   ...$tests (stored row, wanted row) => whether the wanted row may keep it
     * @return list<string|null> for each wanted row, the item uuid it keeps, or null for a new item
     */
    private static function keptItems(array $stored, array $wanted, callable ...$tests): array
    {
        $kept = array_fill(0, count($wanted), null);
        foreach ($tests as $test) {
            foreach ($wanted as $i => $row) {
                if ($kept[$i] !== null) {
                    continue;
                }
                foreach ($stored as $item => $old) {
                    if ($test($old, $row)) {
                        $kept[$i] = (string)$item;
                        unset($stored[$item]);
                        break;
                    }
                }
            }
        }
        return $kept;
    }

    /**
     * Rewrite $field's items as $nodes, in order, each under the item uuid $kept gives it or a new one. An item kept
     * with the same fields serializes as it was; only its place can move.
     *
     * @param ArrayField                  $field
     * @param list<string|null>           $kept  keptItems()
     * @param list<array<string, string>> $nodes each item's fields
     */
    private static function rewrite(ArrayField $field, array $kept, array $nodes): void
    {
        foreach (array_keys(iterator_to_array($field->iterateItems())) as $item) {
            $field->del((string)$item);
        }
        foreach ($nodes as $i => $fields) {
            $field->Add($kept[$i])->setNodes($fields);
        }
    }

    /**
     * A hold record's fields as the model stores them. Pure.
     *
     * @param array{gateway: string, boot: string, underlay: string, taken_at: int} $row
     * @return array{gateway: string, boot: string, underlay: string, taken_at: string}
     */
    private static function holdNodes(array $row): array
    {
        return [
            'gateway' => $row['gateway'], 'boot' => $row['boot'],
            'underlay' => $row['underlay'], 'taken_at' => (string)$row['taken_at'],
        ];
    }
}
