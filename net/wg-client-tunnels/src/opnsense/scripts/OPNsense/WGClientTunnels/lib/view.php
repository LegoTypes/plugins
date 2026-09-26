<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The Tunnels view (spec 7), shared by `tunnel.php list|status` and the API:
 * managed tunnels derived from core with their clamps and findings (the
 * render-failed finding included), and the WireGuard instances the plugin
 * does not manage, for Adopt. A tunnel whose Create or Edit saved but whose apply
 * has not completed carries the apply-pending finding (ruling 20). Reads
 * config; writes nothing. The pure helpers below it turn the view into the
 * API's tunnel records and the Tunnels grid's flat rows.
 */

require_once __DIR__ . '/tunnels.php';
require_once __DIR__ . '/apply.php';

/**
 * @return array{tunnels: list<array>, global: list<array>, unmanaged: list<array{uuid: string, name: string, device: string, enabled: bool, endpoint: string}>, held: list<string>, core: array}
 */
function wgct_tunnel_view(): array {
    $mdl = new \OPNsense\WGClientTunnels\WGClientTunnels();
    $core = wgct_core_snapshot();
    $managed = wgct_split_csv((string)$mdl->managed);
    $derived = wgct_derive($core, $managed);
    $mssClamp = (string)$mdl->mss_clamp === '1';
    $pending = wgct_read_apply_pending();
    $tunnels = [];
    foreach ($derived['tunnels'] as $t) {
        $t['clamp'] = wgct_clamp_for($t, $mssClamp);
        if (isset($pending[$t['uuid']])) {
            $record = $pending[$t['uuid']];
            $t['findings'][] = wgct_finding('apply-pending', 'saved at ' . date('Y-m-d H:i', $record['at'])
                . "; its {$record['mode']} apply has not completed");
        }
        $tunnels[] = $t;
    }
    $global = $derived['global'];
    $renderLib = __DIR__ . '/render.php';
    if ((string)$mdl->enabled === '1' && is_readable($renderLib)) {
        require_once $renderLib;
        $rendered = wgct_read_rendered();
        if ($rendered === null || $rendered['failed']) {
            $global[] = wgct_finding(
                'render-failed',
                $rendered === null ? 'no render recorded since boot or deploy, or the last filter reload could not run the plugin' : $rendered['error']
            );
        }
    }
    $unmanaged = [];
    foreach ($core['instances'] as $uuid => $inst) {
        if (in_array((string)$uuid, $managed, true)) {
            continue;
        }
        $endpoint = '';
        if (count($inst['peers']) === 1 && isset($core['peers'][$inst['peers'][0]])) {
            $peer = $core['peers'][$inst['peers'][0]];
            $endpoint = $peer['serveraddress'] . ($peer['serverport'] !== '' ? ':' . $peer['serverport'] : '');
        }
        $unmanaged[] = [
            'uuid' => (string)$uuid, 'name' => $inst['name'], 'device' => 'wg' . $inst['instance'],
            'enabled' => $inst['enabled'], 'endpoint' => $endpoint,
        ];
    }
    return ['tunnels' => $tunnels, 'global' => $global, 'unmanaged' => $unmanaged, 'held' => wgct_split_csv((string)$mdl->held), 'core' => $core];
}

/**
 * gateway_status.php's reply as two maps by gateway name. Pure.
 *
 * @param mixed $raw the decoded configd reply -- a JSON boundary, hence mixed; anything but an array is no status
 * @return array{status: array<string, string>, text: array<string, string>} status code and its translated text
 */
function wgct_gateway_status_maps(mixed $raw): array {
    $maps = ['status' => [], 'text' => []];
    if (!is_array($raw)) {
        return $maps;
    }
    $str = fn (mixed $v): string => is_scalar($v) ? (string)$v : '';
    foreach ($raw as $key => $row) {
        $row = is_array($row) ? $row : [];
        $name = is_scalar($row['name'] ?? null) ? (string)$row['name'] : (string)$key;
        $maps['status'][$name] = $str($row['status'] ?? '');
        $maps['text'][$name] = $str($row['status_translated'] ?? ($row['status'] ?? ''));
    }
    return $maps;
}

/**
 * The Tunnels tab's record of each managed tunnel: the derived record plus the
 * live status of its gateways ('unknown' when gateway_status.php does not list
 * one, null without the gateway), whether the health mirror holds its IPv4
 * gateway, and its outbound NAT sources by interface description. Pure.
 *
 * @param array $view wgct_tunnel_view()
 * @param array{status: array<string, string>, text: array<string, string>} $gw wgct_gateway_status_maps()
 * @return list<array> the tunnel records, with gw4_status, gw4_status_text, gw4_uuid, gw6_status,
 *                     gw6_status_text, gw6_uuid, held and nat_display added
 */
function wgct_tunnel_rows(array $view, array $gw): array {
    $core = $view['core'];
    $held = array_flip($view['held']);
    $natName = fn (string $src): string => ($core['interfaces'][$src]['descr'] ?? '') !== ''
        ? $core['interfaces'][$src]['descr']
        : $src;
    $rows = [];
    foreach ($view['tunnels'] as $t) {
        foreach (['gw4', 'gw6'] as $key) {
            $t[$key . '_status'] = $t[$key] !== null ? ($gw['status'][$t[$key]] ?? 'unknown') : null;
            $t[$key . '_status_text'] = $t[$key] !== null ? ($gw['text'][$t[$key]] ?? 'unknown') : null;
            /* for core's Gateways page deep link, #edit=<uuid> */
            $t[$key . '_uuid'] = $t[$key] !== null ? ($core['gateways'][$t[$key]]['uuid'] ?? '') : '';
        }
        $t['held'] = $t['gw4'] !== null && isset($held[$core['gateways'][$t['gw4']]['uuid'] ?? '']);
        $t['nat_display'] = [
            'inet' => array_map($natName, $t['nat']['inet']),
            'inet6' => array_map($natName, $t['nat']['inet6']),
        ];
        $rows[] = $t;
    }
    return $rows;
}

/* the grid row fields the Tunnels grid searches: its text columns, never uuids or flags */
const WGCT_GRID_SEARCH_FIELDS = [
    'name', 'device', 'interface', 'interface_descr', 'endpoint', 'bound_wan', 'mtu', 'clamp_text',
    'gw4', 'gw4_status_text', 'gw6', 'gw6_status_text', 'nat_text', 'groups_text', 'findings_text',
];

/**
 * The status icon's classes for a gateway, the same mapping core's gateway
 * page uses (Routing/Api/SettingsController.php searchGatewayAction): a plug
 * that is red when the status holds "down" (force_down included), orange for
 * loss or delay, green for "none", grey when there is no status. Pure.
 *
 * @param string $status the gateway's raw status ('' when it has none)
 * @return string the icon's classes
 */
function wgct_gateway_label_class(string $status): string {
    if ($status === '' || $status === 'unknown') {
        return 'fa fa-plug text-default';
    }
    if (str_contains($status, 'down')) {
        return 'fa fa-plug text-danger';
    }
    if (str_contains($status, 'loss') || str_contains($status, 'delay')) {
        return 'fa fa-plug text-warning';
    }
    if (str_contains($status, 'none')) {
        return 'fa fa-plug text-success';
    }
    return 'fa fa-plug text-default';
}

/**
 * One flat row of the Tunnels grid: every column a scalar the grid can sort
 * and search on ('' where the record has null), the findings for the badges,
 * and the flags that decide the row's Rebind and Apply commands. Pure.
 *
 * @param array $t a wgct_tunnel_rows() record
 * @return array<string, string|int|bool|list<array>> the grid row
 */
function wgct_grid_row(array $t): array {
    $codes = array_column($t['findings'], 'code');
    $clamp = [];
    foreach (['v4', 'v6'] as $family) {
        if ($t['clamp'] !== null && $t['clamp'][$family] !== null) {
            $clamp[] = $family . ' ' . $t['clamp'][$family];
        }
    }
    $nat = [];
    foreach (['inet' => 'v4', 'inet6' => 'v6'] as $family => $label) {
        if ($t['nat_display'][$family] !== []) {
            $nat[] = $label . ': ' . implode(', ', $t['nat_display'][$family]);
        }
    }
    return [
        'uuid' => $t['uuid'],
        'name' => $t['name'] !== '' ? $t['name'] : $t['uuid'],
        /* '0' mutes the row, as core grids do for a disabled item */
        'enabled' => $t['enabled'] ? '1' : '0',
        'device' => $t['device'],
        'interface' => $t['interface'] ?? '',
        'interface_descr' => $t['interface_descr'],
        'endpoint' => $t['endpoint'],
        'bound_wan' => $t['bound_wan'] ?? '',
        'mtu' => (int)$t['mtu'],
        'clamp_text' => $clamp === [] ? '' : 'MSS ' . implode(' / ', $clamp),
        'gw4' => $t['gw4'] ?? '',
        'gw4_status' => $t['gw4_status'] ?? '',
        'gw4_status_text' => $t['gw4_status_text'] ?? '',
        'gw4_label_class' => $t['gw4'] === null ? '' : wgct_gateway_label_class($t['gw4_status'] ?? ''),
        'gw4_uuid' => $t['gw4_uuid'] ?? '',
        'held' => $t['held'],
        'gw6' => $t['gw6'] ?? '',
        'gw6_status' => $t['gw6_status'] ?? '',
        'gw6_status_text' => $t['gw6_status_text'] ?? '',
        'gw6_label_class' => $t['gw6'] === null ? '' : wgct_gateway_label_class($t['gw6_status'] ?? ''),
        'gw6_uuid' => $t['gw6_uuid'] ?? '',
        'nat_text' => implode('; ', $nat),
        'groups_text' => implode(', ', $t['groups']),
        'findings' => $t['findings'],
        'findings_text' => implode(' ', $codes),
        'unbound' => in_array('unbound', $codes, true),
        'apply_pending' => in_array('apply-pending', $codes, true),
    ];
}

/**
 * Self-tests for the view's pure helpers. No config, no processes.
 *
 * @return int exit code, 0 when every case passes
 */
function wgct_view_selftest(): int {
    $t = ['fail' => 0, 'total' => 0];

    $maps = wgct_gateway_status_maps([
        'k1' => ['name' => 'tun_a', 'status' => 'none', 'status_translated' => 'Online'],
        'tun_b' => ['status' => 'down'],
        'k3' => ['name' => ['not', 'a', 'name'], 'status' => ['x'], 'status_translated' => null],
        'k4' => 'not a row',
    ]);
    wgct_check($t, 'view: a gateway status row is keyed by its name, with its status and translated text',
        $maps['status']['tun_a'] === 'none' && $maps['text']['tun_a'] === 'Online');
    wgct_check($t, 'view: a row without a name is keyed by its key; the text falls back to the status',
        $maps['status']['tun_b'] === 'down' && $maps['text']['tun_b'] === 'down');
    wgct_check($t, 'view: non-scalar name/status values and a non-array row read as empty, never as "Array"',
        $maps['status']['k3'] === '' && $maps['text']['k3'] === '' && $maps['status']['k4'] === '');
    wgct_check($t, 'view: a reply that is not an array is no status at all',
        wgct_gateway_status_maps(null) === ['status' => [], 'text' => []]
        && wgct_gateway_status_maps('Execute error') === ['status' => [], 'text' => []]);

    $tunnel = fn (array $o): array => $o + [
        'uuid' => 'i-a', 'name' => 'tun_a', 'enabled' => true, 'device' => 'wg1', 'interface' => 'opt11',
        'interface_descr' => 'TUN_A', 'endpoint' => '198.51.100.10:51820', 'bound_wan' => 'WAN_A', 'mtu' => 1376,
        'gw4' => 'tun_a', 'gw6' => 'tun_a-ipv6', 'nat' => ['inet' => ['lan', 'hosts_alias'], 'inet6' => ['lan']],
        'groups' => ['g1', 'g2'], 'findings' => [], 'clamp' => ['v4' => 1336, 'v6' => 1316],
    ];
    $view = [
        'tunnels' => [
            $tunnel([]),
            $tunnel([
                'uuid' => 'i-b', 'name' => '', 'enabled' => false, 'device' => 'wg2', 'interface' => null,
                'interface_descr' => '', 'endpoint' => '', 'bound_wan' => null, 'mtu' => 1420, 'gw4' => null, 'gw6' => null,
                'nat' => ['inet' => [], 'inet6' => []], 'groups' => [], 'clamp' => null,
                'findings' => [wgct_finding('unbound', 'x'), wgct_finding('apply-pending', 'y')],
            ]),
        ],
        'held' => ['gw-a-uuid'],
        'core' => [
            'interfaces' => ['lan' => ['descr' => 'LAN'], 'opt11' => ['descr' => 'TUN_A']],
            'gateways' => ['tun_a' => ['uuid' => 'gw-a-uuid'], 'tun_a-ipv6' => ['uuid' => 'gw-a6-uuid']],
        ],
    ];
    $rows = wgct_tunnel_rows($view, ['status' => ['tun_a' => 'none'], 'text' => ['tun_a' => 'Online']]);
    wgct_check($t, 'view: a listed gateway carries its status; an unlisted one reads unknown',
        $rows[0]['gw4_status'] === 'none' && $rows[0]['gw4_status_text'] === 'Online'
        && $rows[0]['gw6_status'] === 'unknown' && $rows[0]['gw6_status_text'] === 'unknown');
    wgct_check($t, 'view: a tunnel without gateways has null statuses and is never held',
        $rows[1]['gw4_status'] === null && $rows[1]['gw6_status_text'] === null && $rows[1]['held'] === false);
    wgct_check($t, 'view: the IPv4 gateway uuid on the held list marks the tunnel held', $rows[0]['held'] === true);
    wgct_check($t, 'view: NAT sources show the interface description, an alias or bare key as itself',
        $rows[0]['nat_display'] === ['inet' => ['LAN', 'hosts_alias'], 'inet6' => ['LAN']]);

    $a = wgct_grid_row($rows[0]);
    $b = wgct_grid_row($rows[1]);
    wgct_check($t, 'view: a grid row carries each gateway\'s uuid for core\'s #edit= deep link, empty when there is none',
        $a['gw4_uuid'] === 'gw-a-uuid' && $a['gw6_uuid'] === 'gw-a6-uuid' && $b['gw4_uuid'] === '' && $b['gw6_uuid'] === '');
    wgct_check($t, 'view: a grid row flattens clamps, NAT and groups into sortable text',
        $a['clamp_text'] === 'MSS v4 1336 / v6 1316' && $a['nat_text'] === 'v4: LAN, hosts_alias; v6: LAN'
        && $a['groups_text'] === 'g1, g2' && $a['mtu'] === 1376 && $a['enabled'] === '1');
    wgct_check($t, 'view: a grid row has only scalars outside findings, with empty strings for missing values',
        $b['interface'] === '' && $b['bound_wan'] === '' && $b['gw4'] === '' && $b['gw4_status'] === ''
        && $b['gw6_status_text'] === '' && $b['clamp_text'] === '' && $b['nat_text'] === '' && $b['groups_text'] === ''
        && array_filter($b, fn (mixed $v, string $k): bool => $k !== 'findings' && !is_scalar($v), ARRAY_FILTER_USE_BOTH) === []);
    wgct_check($t, 'view: a nameless tunnel is named by its uuid; a disabled one has enabled 0',
        $b['name'] === 'i-b' && $b['enabled'] === '0');
    wgct_check($t, 'view: the unbound and apply-pending findings set the Rebind and Apply flags, and only they',
        $b['unbound'] === true && $b['apply_pending'] === true && $a['unbound'] === false && $a['apply_pending'] === false
        && $b['findings_text'] === 'unbound apply-pending');
    wgct_check($t, 'view: status icons follow core gateway page colours (down/force_down red, loss/delay orange, none green, else grey)',
        wgct_gateway_label_class('none') === 'fa fa-plug text-success'
        && wgct_gateway_label_class('down') === 'fa fa-plug text-danger'
        && wgct_gateway_label_class('force_down') === 'fa fa-plug text-danger'
        && wgct_gateway_label_class('loss') === 'fa fa-plug text-warning'
        && wgct_gateway_label_class('delay+loss') === 'fa fa-plug text-warning'
        && wgct_gateway_label_class('') === 'fa fa-plug text-default'
        && wgct_gateway_label_class('unknown') === 'fa fa-plug text-default');
    wgct_check($t, 'view: a grid row carries each gateway\'s icon class, and none for a missing gateway',
        $a['gw4_label_class'] === 'fa fa-plug text-success' && $a['gw6_label_class'] === 'fa fa-plug text-default'
        && $b['gw4_label_class'] === '' && $b['gw6_label_class'] === '');
    wgct_check($t, 'view: every searched field is a grid row field',
        array_diff(WGCT_GRID_SEARCH_FIELDS, array_keys($a)) === []);
    return wgct_tally_report('view', $t);
}
