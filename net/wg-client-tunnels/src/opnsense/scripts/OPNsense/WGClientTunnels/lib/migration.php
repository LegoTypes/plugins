<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Model 3.0.0 (spec 2026-09-24 section 8.4). Up to 2.2 the plugin was
 * os-wg-ipv6-gateway, with its settings at //OPNsense/WGIPv6Gateway;
 * Migrations/M3_0_0.php copies them into //OPNsense/WGClientTunnels and
 * removes the old section, in the one save migrate.php (or convert_config()
 * at boot) makes. The readers, the mapping, the summary, the reports and the
 * removal live here so that `migrate.php`, the migration and the self-test
 * share them. The mapping, the summary and the reports are pure; the readers
 * and the removal touch only the tree they are given.
 */

require_once __DIR__ . '/selftest.php';

/* the old section under <OPNsense> -- the one place the old name remains */
const WGCT_LEGACY_NODE = 'WGIPv6Gateway';
/* this model's section under <OPNsense>, and the version this migration brings it to */
const WGCT_MODEL_NODE = 'WGClientTunnels';
const WGCT_MIGRATION_TARGET = '3.0.0';
/* the switches in model order; 'enabled' first, since the pin switches may follow it */
const WGCT_MIGRATED_SWITCHES = ['enabled', 'health_mirror', 'ipv6_routes', 'default_guard', 'wan_pins', 'inner_source', 'mss_clamp'];
/* added by model 2.1.0: a 2.0.x section lacks them, and 2.1.0's migration set them to 'enabled' */
const WGCT_MIGRATED_PIN_SWITCHES = ['wan_pins', 'inner_source', 'mss_clamp'];
const WGCT_MIGRATED_LISTS = ['managed', 'held'];
const WGCT_MIGRATED_FIELDS = ['enabled', 'health_mirror', 'ipv6_routes', 'default_guard', 'wan_pins', 'inner_source', 'mss_clamp', 'managed', 'held'];
/* the model's Mask for one managed or held item */
const WGCT_MIGRATED_ITEM = '/^[0-9a-fA-F-]{36}$/';

/**
 * @param \SimpleXMLElement $root a config root (<opnsense>)
 * @return array{version: string, fields: array<string, string>, rows: int}|null
 *         null when there is no old section; fields are its leaf children,
 *         rows the 1.x per-gateway rows it still holds
 */
function wgct_read_legacy_node(\SimpleXMLElement $root): ?array {
    if (!isset($root->OPNsense->{WGCT_LEGACY_NODE})) {
        return null;
    }
    $node = $root->OPNsense->{WGCT_LEGACY_NODE};
    $fields = [];
    foreach ($node->children() as $child) {
        if ($child->count() === 0) {
            $fields[$child->getName()] = trim((string)$child);
        }
    }
    return [
        'version' => trim((string)($node['version'] ?? '')),
        'fields' => $fields,
        'rows' => isset($node->gateways->gateway) ? count($node->gateways->gateway) : 0,
    ];
}

/**
 * @param \SimpleXMLElement $root a config root (<opnsense>)
 * @return string|null the version attribute of this model's section ('' when
 *         it has none), null when there is no section yet
 */
function wgct_read_model_version(\SimpleXMLElement $root): ?string {
    if (!isset($root->OPNsense->{WGCT_MODEL_NODE})) {
        return null;
    }
    return trim((string)($root->OPNsense->{WGCT_MODEL_NODE}['version'] ?? ''));
}

/**
 * @param string $csv a CSVListField value
 * @return list<string> its items, trimmed, empty ones dropped. Pure.
 */
function wgct_migration_items(string $csv): array {
    return array_values(array_filter(array_map('trim', explode(',', $csv)), fn (string $i): bool => $i !== ''));
}

/**
 * The new model's values from the old section. Pure.
 *
 * @param array{version: string, fields: array<string, string>, rows: int}|null $old wgct_read_legacy_node()
 * @return array{values: array<string, string>|null, error: string|null, notes: list<string>}
 *         values null: nothing to copy (no old section), or refused (error set)
 */
function wgct_legacy_settings(?array $old): array {
    if ($old === null) {
        return ['values' => null, 'error' => null, 'notes' => []];
    }
    $version = $old['version'];
    if ($version === '' || $old['rows'] > 0
        || version_compare($version, '2.0.0', '<') || version_compare($version, '3.0.0', '>=')) {
        return ['values' => null, 'notes' => [], 'error' => sprintf(
            'the %s section is model %s%s; only a 2.x section is migrated -- migrate it with os-wg-ipv6-gateway 2.x first',
            WGCT_LEGACY_NODE,
            $version === '' ? '(unversioned)' : $version,
            $old['rows'] > 0 ? " with {$old['rows']} per-gateway row(s)" : ''
        )];
    }
    $f = $old['fields'];
    $values = [];
    $notes = [];
    foreach (WGCT_MIGRATED_SWITCHES as $name) {
        if (array_key_exists($name, $f)) {
            $values[$name] = $f[$name] === '1' ? '1' : '0';
            if ($f[$name] !== '1' && $f[$name] !== '0') {
                /* the value is not echoed: notes reach the summary, which prints no config content */
                $notes[] = "{$name} is neither 0 nor 1 in the {$version} section; off";
            }
        } elseif (in_array($name, WGCT_MIGRATED_PIN_SWITCHES, true)) {
            $values[$name] = $values['enabled'];
            $notes[] = "{$name} is not in the {$version} section; it follows enabled ({$values['enabled']}), as the 2.1.0 migration set it";
        } else {
            $values[$name] = '0';
            $notes[] = "{$name} is not in the {$version} section; off";
        }
    }
    foreach (WGCT_MIGRATED_LISTS as $name) {
        $kept = [];
        foreach (wgct_migration_items($f[$name] ?? '') as $i => $item) {
            if (preg_match(WGCT_MIGRATED_ITEM, $item) === 1) {
                $kept[] = $item;
            } else {
                $notes[] = sprintf('%s: item %d is not a uuid; dropped', $name, $i + 1);
            }
        }
        $values[$name] = implode(',', $kept);
    }
    return ['values' => $values, 'error' => null, 'notes' => $notes];
}

/**
 * @param array{values: array<string, string>|null, error: string|null, notes: list<string>} $plan wgct_legacy_settings()
 * @return string one line, plus one per note: switches as 0/1 and list sizes, never a uuid. Pure.
 */
function wgct_migration_summary(array $plan): string {
    if ($plan['error'] !== null) {
        return 'REFUSED: ' . $plan['error'];
    }
    if ($plan['values'] === null) {
        return 'no ' . WGCT_LEGACY_NODE . ' section: nothing to copy';
    }
    $parts = [];
    foreach (WGCT_MIGRATED_SWITCHES as $name) {
        $parts[] = "{$name}={$plan['values'][$name]}";
    }
    foreach (WGCT_MIGRATED_LISTS as $name) {
        $parts[] = $name . '=' . count(wgct_migration_items($plan['values'][$name]));
    }
    $lines = ['settings from ' . WGCT_LEGACY_NODE . ': ' . implode(' ', $parts)];
    foreach ($plan['notes'] as $note) {
        $lines[] = "  note: {$note}";
    }
    return implode("\n", $lines);
}

/**
 * The warning for an old section left beside a section already at 3.0.0 --
 * restored from a pre-3.0 backup, say. No migration applies it. Pure.
 *
 * @param string                                                             $modelVersion this model's version in the config
 * @param array{version: string, fields: array<string, string>, rows: int}|null $old         wgct_read_legacy_node()
 * @return string|null one line naming both sections and their versions, never a uuid; null when there is no old section
 */
function wgct_stale_legacy_warning(string $modelVersion, ?array $old): ?string {
    if ($old === null) {
        return null;
    }
    return sprintf(
        'WARNING: new section %s already at %s; old section %s (model %s) is stale -- no migration applies it, '
            . 'and it stays in config.xml until removed by hand',
        WGCT_MODEL_NODE,
        $modelVersion,
        WGCT_LEGACY_NODE,
        $old['version'] === '' ? 'unversioned' : $old['version']
    );
}

/**
 * What `migrate.php --dry` prints and its exit code. Pure.
 *
 * @param string|null                                                        $modelVersion wgct_read_model_version()
 * @param array{version: string, fields: array<string, string>, rows: int}|null $old         wgct_read_legacy_node()
 * @return array{text: string, rc: int} once this model is at 3.0.0: the stale
 *         warning, or "nothing to migrate", rc 0; before: the mapping's
 *         summary, rc 1 on a refusal
 */
function wgct_dry_report(?string $modelVersion, ?array $old): array {
    if ($modelVersion !== null && $modelVersion !== ''
        && version_compare($modelVersion, WGCT_MIGRATION_TARGET, '>=')) {
        return [
            'text' => wgct_stale_legacy_warning($modelVersion, $old)
                ?? WGCT_MODEL_NODE . " already at {$modelVersion}: nothing to migrate",
            'rc' => 0,
        ];
    }
    $plan = wgct_legacy_settings($old);
    return ['text' => wgct_migration_summary($plan), 'rc' => $plan['error'] === null ? 0 : 1];
}

/**
 * @param \SimpleXMLElement $root a config root (<opnsense>), changed in place
 * @return bool whether there was an old section to remove
 */
function wgct_remove_legacy_node(\SimpleXMLElement $root): bool {
    if (!isset($root->OPNsense->{WGCT_LEGACY_NODE})) {
        return false;
    }
    $dom = dom_import_simplexml($root->OPNsense->{WGCT_LEGACY_NODE});
    $parent = $dom->parentNode;
    if ($parent === null) {
        return false;
    }
    $parent->removeChild($dom);
    return true;
}

/**
 * Self-tests for the readers, the mapping, the summary, the dry report and
 * the removal. Pure:
 * every config tree is parsed from a string in memory.
 *
 * @return int exit code, 0 when every case passes
 */
function wgct_migration_selftest(): int {
    $t = ['fail' => 0, 'total' => 0];
    $u1 = '00000000-0000-4000-8000-000000000001';
    $u2 = '00000000-0000-4000-8000-000000000002';
    $g1 = '00000000-0000-4000-8000-00000000000a';
    $tree = fn (string $xml): \SimpleXMLElement => new \SimpleXMLElement($xml);
    $section = fn (string $attrs, string $body): string =>
        "<opnsense><OPNsense><Sibling><x>1</x></Sibling><WGIPv6Gateway{$attrs}>{$body}</WGIPv6Gateway></OPNsense></opnsense>";
    $full = '<enabled>1</enabled><health_mirror>1</health_mirror><ipv6_routes>0</ipv6_routes><default_guard>1</default_guard>'
        . '<wan_pins>1</wan_pins><inner_source>0</inner_source><mss_clamp>1</mss_clamp>'
        . "<managed>{$u1},{$u2}</managed><held>{$g1}</held>";

    /* the reader */
    wgct_check($t, 'migration: read -- a config without the old section => null',
        wgct_read_legacy_node($tree('<opnsense><OPNsense><Sibling/></OPNsense></opnsense>')) === null);
    $read = wgct_read_legacy_node($tree($section(' version="2.1.0"', $full)));
    wgct_check($t, 'migration: read -- a 2.1.0 section => its version, nine leaf fields as strings, no rows',
        $read !== null && $read['version'] === '2.1.0' && $read['rows'] === 0 && count($read['fields']) === 9
        && $read['fields']['managed'] === "{$u1},{$u2}" && $read['fields']['ipv6_routes'] === '0');
    $read1x = wgct_read_legacy_node($tree($section(' version="1.1.0"',
        '<enabled>1</enabled><gateways><gateway uuid="a"><enabled>1</enabled></gateway><gateway uuid="b"><enabled>0</enabled></gateway></gateways>')));
    wgct_check($t, 'migration: read -- a 1.x section => its gateway rows counted, the row container not taken for a field',
        $read1x !== null && $read1x['rows'] === 2 && $read1x['version'] === '1.1.0' && !isset($read1x['fields']['gateways']));
    $both = $tree('<opnsense><OPNsense><WGClientTunnels version="3.0.0"><enabled>1</enabled></WGClientTunnels>'
        . "<WGIPv6Gateway version=\"2.1.0\">{$full}</WGIPv6Gateway></OPNsense></opnsense>");
    wgct_check($t, 'migration: read -- the new section: none => null, unversioned => empty, versioned => its version',
        wgct_read_model_version($tree($section(' version="2.1.0"', $full))) === null
        && wgct_read_model_version($tree('<opnsense><OPNsense><WGClientTunnels/></OPNsense></opnsense>')) === ''
        && wgct_read_model_version($both) === '3.0.0');

    /* the mapping */
    wgct_check($t, 'migration: map -- no old section => nothing to copy, the defaults stay',
        wgct_legacy_settings(null) === ['values' => null, 'error' => null, 'notes' => []]);
    $m = wgct_legacy_settings($read);
    wgct_check($t, 'migration: map -- a 2.1.0 section => all nine values copied exactly',
        $m['error'] === null && $m['notes'] === [] && $m['values'] === [
            'enabled' => '1', 'health_mirror' => '1', 'ipv6_routes' => '0', 'default_guard' => '1',
            'wan_pins' => '1', 'inner_source' => '0', 'mss_clamp' => '1', 'managed' => "{$u1},{$u2}", 'held' => $g1,
        ]);
    $off = wgct_legacy_settings(['version' => '2.1.0', 'rows' => 0, 'fields' => array_merge(
        array_fill_keys(WGCT_MIGRATED_SWITCHES, '0'), ['managed' => '', 'held' => ''])]);
    wgct_check($t, 'migration: map -- everything off and empty lists => copied as off and empty',
        $off['error'] === null && $off['notes'] === []
        && $off['values'] === array_merge(array_fill_keys(WGCT_MIGRATED_SWITCHES, '0'), ['managed' => '', 'held' => '']));
    $v20 = ['version' => '2.0.0', 'rows' => 0, 'fields' => [
        'enabled' => '1', 'health_mirror' => '1', 'ipv6_routes' => '1', 'default_guard' => '0', 'managed' => $u1, 'held' => '']];
    $m20 = wgct_legacy_settings($v20);
    wgct_check($t, 'migration: map -- a 2.0.0 section lacks the pin switches => each follows enabled (on), one note each',
        $m20['error'] === null && count($m20['notes']) === 3 && $m20['values']['default_guard'] === '0'
        && $m20['values']['wan_pins'] === '1' && $m20['values']['inner_source'] === '1' && $m20['values']['mss_clamp'] === '1');
    $v20['fields']['enabled'] = '0';
    $m20off = wgct_legacy_settings($v20);
    wgct_check($t, 'migration: map -- the same with enabled off => the pin switches off',
        $m20off['values'] !== null && $m20off['values']['wan_pins'] === '0' && $m20off['values']['inner_source'] === '0'
        && $m20off['values']['mss_clamp'] === '0');
    $noEnabled = wgct_legacy_settings(['version' => '2.0.0', 'rows' => 0, 'fields' => ['managed' => $u1, 'held' => '']]);
    wgct_check($t, 'migration: map -- a 2.0.0 section without enabled => every switch off, the pin switches following it, one note each',
        $noEnabled['error'] === null && $noEnabled['values'] !== null
        && array_intersect_key($noEnabled['values'], array_flip(WGCT_MIGRATED_SWITCHES)) === array_fill_keys(WGCT_MIGRATED_SWITCHES, '0')
        && $noEnabled['values']['managed'] === $u1 && count($noEnabled['notes']) === 7
        && count(array_filter($noEnabled['notes'], fn (string $n): bool => str_contains($n, 'follows enabled (0)'))) === 3);
    $odd = $read['fields'];
    $odd['ipv6_routes'] = '';
    $odd['health_mirror'] = 'yes';
    $mOdd = wgct_legacy_settings(['version' => '2.1.0', 'rows' => 0, 'fields' => $odd]);
    wgct_check($t, 'migration: map -- a switch that is neither 0 nor 1 (empty, yes) => off, one note each, the value never echoed',
        $mOdd['error'] === null && $mOdd['values'] !== null && $mOdd['values']['ipv6_routes'] === '0'
        && $mOdd['values']['health_mirror'] === '0' && $mOdd['values']['enabled'] === '1' && count($mOdd['notes']) === 2
        && !str_contains(implode("\n", $mOdd['notes']), 'yes'));
    $e1 = wgct_legacy_settings($read1x);
    wgct_check($t, 'migration: map -- a 1.x section => refused, naming its version and os-wg-ipv6-gateway 2.x, nothing copied',
        $e1['values'] === null && str_contains((string)$e1['error'], '1.1.0') && str_contains((string)$e1['error'], 'os-wg-ipv6-gateway 2.x'));
    $eNone = wgct_legacy_settings(['version' => '', 'rows' => 0, 'fields' => ['enabled' => '1']]);
    $e3 = wgct_legacy_settings(['version' => '3.0.0', 'rows' => 0, 'fields' => []]);
    $eRows = wgct_legacy_settings(['version' => '2.1.0', 'rows' => 1, 'fields' => []]);
    wgct_check($t, 'migration: map -- an unversioned section, a 3.x section and a 2.x version with 1.x rows => refused',
        $eNone['values'] === null && $eNone['error'] !== null && $e3['values'] === null && $e3['error'] !== null
        && $eRows['values'] === null && $eRows['error'] !== null);
    $fields = $read['fields'];
    $fields['managed'] = "{$u1}, nonsense ,{$u2},";
    $fields['held'] = 'x';
    $bad = wgct_legacy_settings(['version' => '2.1.0', 'rows' => 0, 'fields' => $fields]);
    wgct_check($t, 'migration: map -- list items that are not uuids are dropped with one note each, the rest kept in order',
        $bad['error'] === null && $bad['values'] !== null && $bad['values']['managed'] === "{$u1},{$u2}"
        && $bad['values']['held'] === '' && count($bad['notes']) === 2);
    wgct_check($t, 'migration: map -- the values are exactly the model fields, in model order, all strings',
        $m['values'] !== null && array_keys($m['values']) === WGCT_MIGRATED_FIELDS
        && array_filter($m['values'], 'is_string') === $m['values']);

    /* the summary */
    $sum = wgct_migration_summary($m);
    wgct_check($t, 'migration: summary -- switches as 0/1 and list sizes, never a uuid',
        str_contains($sum, 'enabled=1') && str_contains($sum, 'ipv6_routes=0') && str_contains($sum, 'managed=2')
        && str_contains($sum, 'held=1') && !str_contains($sum, $u1) && !str_contains($sum, $g1));
    wgct_check($t, 'migration: summary -- no section reads as nothing to copy, a refusal as REFUSED',
        str_contains(wgct_migration_summary(wgct_legacy_settings(null)), 'nothing to copy')
        && str_starts_with(wgct_migration_summary($e1), 'REFUSED: '));

    /* the dry report */
    $stale = wgct_dry_report('3.0.0', wgct_read_legacy_node($both));
    wgct_check($t, 'migration: dry -- the new section already at 3.0.0 beside the old one => the stale WARNING, no mapping, never a uuid, rc 0',
        $stale['rc'] === 0 && str_starts_with($stale['text'], 'WARNING: ') && str_contains($stale['text'], 'already at 3.0.0')
        && str_contains($stale['text'], 'stale') && !str_contains($stale['text'], 'settings from') && !str_contains($stale['text'], $u1)
        && $stale['text'] === wgct_stale_legacy_warning('3.0.0', wgct_read_legacy_node($both)));
    wgct_check($t, 'migration: dry -- the new section already at 3.0.0 alone => nothing to migrate, no warning, rc 0',
        wgct_dry_report('3.0.0', null) === ['text' => 'WGClientTunnels already at 3.0.0: nothing to migrate', 'rc' => 0]
        && wgct_stale_legacy_warning('3.0.0', null) === null);
    $e1dry = wgct_dry_report(null, $read1x);
    wgct_check($t, 'migration: dry -- no new section, or an unversioned or older one => the mapping, rc 0; a refusal => rc 1',
        wgct_dry_report(null, $read) === ['text' => $sum, 'rc' => 0] && wgct_dry_report('', $read) === ['text' => $sum, 'rc' => 0]
        && wgct_dry_report('2.1.0', $read) === ['text' => $sum, 'rc' => 0]
        && $e1dry['rc'] === 1 && str_starts_with($e1dry['text'], 'REFUSED: '));

    /* the removal */
    $live = $tree($section(' version="2.1.0"', $full));
    $removed = wgct_remove_legacy_node($live);
    wgct_check($t, 'migration: remove -- drops the old section only; a second call finds nothing',
        $removed && !isset($live->OPNsense->WGIPv6Gateway) && (string)$live->OPNsense->Sibling->x === '1'
        && wgct_remove_legacy_node($live) === false);

    return wgct_tally_report('migration', $t);
}
