<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 */

namespace OPNsense\WGClientTunnels\Api;

use OPNsense\Base\ApiControllerBase;
use OPNsense\Core\Backend;

/**
 * The Tunnels tab (spec 6, 7). search and options are views derived from core
 * on every request. Create is the one write done in-process, because only it
 * may see the private key (spec 6.1); it then runs the keyless configd action
 * `wgclienttunnels apply`. Every other action runs in its own process through
 * configd, with uuids, gateway names and addresses as its only parameters.
 */
class TunnelsController extends ApiControllerBase
{
    private const LIB = '/usr/local/opnsense/scripts/OPNsense/WGClientTunnels/lib';
    private const UUID = '/^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$/';
    private const GATEWAY_NAME = '/^[a-zA-Z0-9_-]{1,32}$/';
    private const NAT_ALIAS_TYPES = ['host', 'network', 'networkgroup', 'dynipv6host'];

    public function searchAction(): array
    {
        require_once self::LIB . '/view.php';
        $view = wgct_tunnel_view();
        $core = $view['core'];
        $status = [];
        $statusText = [];
        /* configd output: a JSON boundary, decoded to mixed and checked row by row */
        $raw = json_decode((string)(new Backend())->configdRun('interface gateways status'), true);
        if (is_array($raw)) {
            foreach ($raw as $key => $row) {
                $name = is_array($row) && isset($row['name']) ? (string)$row['name'] : (string)$key;
                $status[$name] = is_array($row) ? (string)($row['status'] ?? '') : '';
                $statusText[$name] = is_array($row) ? (string)($row['status_translated'] ?? ($row['status'] ?? '')) : '';
            }
        }
        $held = array_flip($view['held']);
        $natName = function (string $src) use ($core): string {
            return isset($core['interfaces'][$src]) && $core['interfaces'][$src]['descr'] !== ''
                ? $core['interfaces'][$src]['descr']
                : $src;
        };
        $tunnels = [];
        foreach ($view['tunnels'] as $t) {
            $t['gw4_status'] = $t['gw4'] !== null ? ($status[$t['gw4']] ?? 'unknown') : null;
            $t['gw4_status_text'] = $t['gw4'] !== null ? ($statusText[$t['gw4']] ?? 'unknown') : null;
            $t['gw6_status'] = $t['gw6'] !== null ? ($status[$t['gw6']] ?? 'unknown') : null;
            $t['gw6_status_text'] = $t['gw6'] !== null ? ($statusText[$t['gw6']] ?? 'unknown') : null;
            $t['held'] = $t['gw4'] !== null && isset($held[$core['gateways'][$t['gw4']]['uuid']]);
            $t['nat_display'] = [
                'inet' => array_map($natName, $t['nat']['inet']),
                'inet6' => array_map($natName, $t['nat']['inet6']),
            ];
            $tunnels[] = $t;
        }
        return ['status' => 'ok', 'tunnels' => $tunnels, 'global' => $view['global'], 'unmanaged' => $view['unmanaged']];
    }

    public function optionsAction(): array
    {
        require_once self::LIB . '/actions.php';
        require_once self::LIB . '/view.php';
        $view = wgct_tunnel_view();
        $core = $view['core'];
        $wans = [];
        foreach ($core['gateways'] as $name => $g) {
            if (wgct_wan_error($core, (string)$name) === null) {
                $descr = $core['interfaces'][$g['interface']]['descr'] ?? '';
                $wans[] = ['value' => (string)$name, 'label' => $name . ' (' . ($descr !== '' ? $descr : $g['interface']) . ')'];
            }
        }
        $templates = [];
        foreach ($view['tunnels'] as $t) {
            if ($t['interface'] !== null && $t['gw4'] !== null) {
                $templates[] = ['value' => $t['uuid'], 'label' => $t['name']];
            }
        }
        $wgDevices = wgct_wg_devices($core);
        $sources = [];
        foreach ($core['interfaces'] as $key => $if) {
            if (wgct_is_nat_interface_key((string)$key) && $if['enable'] && !isset($wgDevices[$if['if']])
                && strncmp($if['if'], 'lo', 2) !== 0) {
                $sources[] = ['value' => (string)$key, 'label' => ($if['descr'] !== '' ? $if['descr'] : strtoupper((string)$key)) . ' net'];
            }
        }
        foreach ((new \OPNsense\Firewall\Alias())->aliases->alias->iterateItems() as $alias) {
            if (in_array((string)$alias->type, self::NAT_ALIAS_TYPES, true)) {
                $sources[] = ['value' => (string)$alias->name, 'label' => (string)$alias->name . ' (alias)'];
            }
        }
        $stale = [];
        foreach (wgct_stale_candidates($core) as $uuid => $b) {
            $stale[] = ['value' => (string)$uuid, 'label' => "{$b['ip']}/32 via {$b['gateway']}"];
        }
        return [
            'status' => 'ok', 'wans' => $wans, 'templates' => $templates, 'nat_sources' => $sources,
            'instance_ipv6' => array_keys(wgct_instance_ipv6($core)),
            'unique_convention' => wgct_unique_convention(['tunnels' => $view['tunnels'], 'global' => []]),
            'stale_routes' => $stale,
        ];
    }

    public function createAction(): array
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        $this->throwReadOnly();
        require_once self::LIB . '/writer.php';
        /* a form boundary: create.* arrives as an array of strings; wgct_create_request() checks every value */
        $raw = $this->request->getPost('create');
        if (!is_array($raw)) {
            return ['result' => 'failed', 'errors' => ['the create form was empty']];
        }
        $secrets = [];
        /* the saved instance's uuid, once wgct_create_commit() has returned one */
        $uuid = '';
        try {
            $prep = wgct_create_prepare($raw, true);
            $secrets = array_values($prep['secret']);
            if ($prep['errors'] !== []) {
                return $this->formFailure($prep['errors'], $prep['notes']);
            }
            /* spec 4.6: gateway lock (bounded, ruling 22), then Config::lock() inside the commit; the lock is
             * released before the configd apply below, which takes it itself (holding it across would deadlock) */
            $result = wgct_gateway_locked_commit(function () use ($prep, &$uuid): array {
                $created = wgct_create_commit($prep, false);
                $uuid = $created['saved'] ? $created['uuid'] : '';
                return $created;
            });
        } catch (\Throwable $e) {
            syslog(LOG_ERR, '[wgct-action] create failed: ' . wgct_redact(get_class($e) . ': ' . $e->getMessage(), $secrets));
            return ['result' => 'failed', 'uuid' => $uuid, 'errors' => [
                'Create failed; the system log has the reason (never the key). ' . wgct_failure_footer('create', $uuid)
                . ' A saved tunnel shows the apply-pending finding and an Apply button once the list is reloaded.',
            ]];
        }
        unset($prep, $raw, $secrets);
        if (!$result['ok']) {
            return $this->formFailure($result['errors'], $result['changes']);
        }
        /* the tunnel is saved and marked apply-pending by wgct_create_commit() itself, before this
         * call (ruling 20); 'ok' below reflects only whether this apply succeeded, so a timeout or a
         * failed step is never reported as success -- the uuid and the apply-pending finding are what
         * let the GUI offer Apply again */
        $apply = wgct_configd_json('wgclienttunnels apply', [$result['uuid']], 300);
        $applyErrors = is_array($apply['errors'] ?? null) ? $apply['errors'] : [];
        return [
            'result' => 'saved', 'ok' => ($apply['ok'] ?? false) === true && $applyErrors === [],
            'saved' => true, 'uuid' => $result['uuid'], 'changes' => $result['changes'],
            'apply' => $apply['apply'] ?? [], 'after' => $apply['after'] ?? [], 'errors' => $applyErrors,
        ];
    }

    public function measureMtuAction(): array
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        require_once self::LIB . '/apply.php';
        $wan = $this->postString('wan');
        $endpoint = $this->postString('endpoint');
        if (preg_match(self::GATEWAY_NAME, $wan) !== 1 || filter_var($endpoint, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
            return ['ok' => false, 'errors' => ['choose the WAN and paste a config with an IPv4 endpoint first']];
        }
        return wgct_configd_json('wgclienttunnels measure_mtu', [$wan, $endpoint], 120);
    }

    public function removeAction(string $uuid = ''): array
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        require_once self::LIB . '/apply.php';
        if (preg_match(self::UUID, $uuid) !== 1) {
            return ['ok' => false, 'errors' => ['not a tunnel uuid']];
        }
        $dry = wgct_dry_flag($this->request->getPost('dry'));
        if ($dry === null) {
            return ['ok' => false, 'errors' => ['dry must be 1 (preview) or omitted/0 (run for real)']];
        }
        if ($dry) {
            return wgct_configd_json('wgclienttunnels remove_dry', [$uuid], 120);
        }
        $this->throwReadOnly();
        return wgct_configd_json('wgclienttunnels remove', [$uuid], 300);
    }

    public function applyAction(string $uuid = ''): array
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        $this->throwReadOnly();
        require_once self::LIB . '/apply.php';
        if (preg_match(self::UUID, $uuid) !== 1) {
            return ['ok' => false, 'errors' => ['not a tunnel uuid']];
        }
        return wgct_configd_json('wgclienttunnels apply', [$uuid], 300);
    }

    public function rebindAction(string $uuid = ''): array
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        $this->throwReadOnly();
        require_once self::LIB . '/apply.php';
        /* a form boundary: rebind.* as strings */
        $form = $this->request->getPost('rebind');
        $wan = is_array($form) && is_string($form['wan'] ?? null) ? $form['wan'] : '';
        $stale = is_array($form) && is_string($form['stale'] ?? null) ? $form['stale'] : '';
        if (preg_match(self::UUID, $uuid) !== 1 || preg_match(self::GATEWAY_NAME, $wan) !== 1
            || ($stale !== '' && preg_match(self::UUID, $stale) !== 1)) {
            return ['ok' => false, 'errors' => ['choose a WAN (and, optionally, a stale route to delete)']];
        }
        return wgct_configd_json('wgclienttunnels rebind', [$uuid, $wan, $stale], 300);
    }

    public function adoptAction(string $uuid = ''): array
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        require_once self::LIB . '/apply.php';
        if (preg_match(self::UUID, $uuid) !== 1) {
            return ['ok' => false, 'errors' => ['not an instance uuid']];
        }
        $dry = wgct_dry_flag($this->request->getPost('dry'));
        if ($dry === null) {
            return ['ok' => false, 'errors' => ['dry must be 1 (preview) or omitted/0 (run for real)']];
        }
        if ($dry) {
            return wgct_configd_json('wgclienttunnels adopt_dry', [$uuid], 120);
        }
        $this->throwReadOnly();
        return wgct_configd_json('wgclienttunnels adopt', [$uuid], 120);
    }

    /**
     * @param array        $errors  Create's errors, keyed by request field or 'general'
     * @param list<string> $changes
     * @return array the form failure: field messages for handleFormValidation(), the rest as a list
     */
    private function formFailure(array $errors, array $changes): array
    {
        $validations = [];
        $general = [];
        foreach ($errors as $field => $message) {
            if (is_string($field) && in_array($field, WGCT_CREATE_FIELDS, true)) {
                $validations['create.' . $field] = $message;
            } else {
                $general[] = $message;
            }
        }
        return ['result' => 'failed', 'validations' => $validations, 'errors' => $general, 'changes' => $changes];
    }

    /**
     * @return string the POST value, or '' when absent or not a string (a form boundary)
     */
    private function postString(string $key): string
    {
        $value = $this->request->getPost($key);
        return is_string($value) ? $value : '';
    }
}
