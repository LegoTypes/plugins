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
 * The Upstream tunnels page (spec 6, 7). search, search_grid, options and edit_form are
 * views derived from core on every request. Create and Edit are the writes
 * done in-process, because only they may see a private key (spec 6.1, 6.5);
 * each then runs the keyless configd action `wgclienttunnels apply_mode`.
 * Every other action runs in its own process through configd, with uuids,
 * gateway names and addresses as its only parameters.
 */
class TunnelsController extends ApiControllerBase
{
    private const LIB = '/usr/local/opnsense/scripts/OPNsense/WGClientTunnels/lib';
    private const UUID = '/^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$/';
    private const GATEWAY_NAME = '/^[a-zA-Z0-9_-]{1,32}$/';
    private const NAT_ALIAS_TYPES = ['host', 'network', 'networkgroup', 'dynipv6host'];

    /**
     * The whole view: the managed tunnels, the global findings and the unmanaged
     * instances. GET or POST; the tunnel list posts it for its banners and the
     * unmanaged list.
     */
    public function searchAction(): array
    {
        require_once self::LIB . '/view.php';
        $view = wgct_tunnel_view();
        return [
            'status' => 'ok', 'tunnels' => wgct_tunnel_rows($view, $this->gatewayStatus()),
            'global' => $view['global'], 'unmanaged' => $view['unmanaged'],
        ];
    }

    /**
     * The Tunnels grid: one flat row per managed tunnel (wgct_grid_row()), paged,
     * sorted and searched by core's recordset search from the grid's POST
     * (rowCount, current, sort, searchPhrase).
     */
    public function searchGridAction(): array
    {
        require_once self::LIB . '/view.php';
        $rows = array_map('wgct_grid_row', wgct_tunnel_rows(wgct_tunnel_view(), $this->gatewayStatus()));
        return $this->searchRecordsetBase($rows, WGCT_GRID_SEARCH_FIELDS, 'name');
    }

    public function optionsAction(): array
    {
        return ['status' => 'ok'] + $this->choices();
    }

    /**
     * The Edit dialog: the tunnel's current values (wgct_edit_prefill()) and the choices.
     */
    public function editFormAction(string $uuid = ''): array
    {
        require_once self::LIB . '/writer.php';
        if (preg_match(self::UUID, $uuid) !== 1) {
            return ['status' => 'failed', 'errors' => ['not a tunnel uuid']];
        }
        $prefill = wgct_edit_prefill(wgct_action_snapshot(), $uuid);
        if ($prefill['errors'] !== []) {
            return ['status' => 'failed', 'errors' => $prefill['errors']];
        }
        return ['status' => 'ok', 'form' => $prefill['form']] + $this->choices();
    }

    /**
     * Create's and Edit's choices: the WANs that can bind a tunnel, the template
     * tunnels, the NAT sources (interfaces and aliases), the IPv6 addresses on
     * instances, the fd00::N:1 convention and the stale routes.
     *
     * @return array<string, list<array<string, string>>|list<string>|bool>
     */
    private function choices(): array
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
            'wans' => $wans, 'templates' => $templates, 'nat_sources' => $sources,
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
                return $this->formFailure($prep['errors'], $prep['notes'], 'create', WGCT_CREATE_FIELDS);
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
            return $this->formFailure($result['errors'], $result['changes'], 'create', WGCT_CREATE_FIELDS);
        }
        /* the tunnel is saved and marked apply-pending by wgct_create_commit() itself, before this
         * call (ruling 20); 'ok' below reflects only whether this apply succeeded, so a timeout or a
         * failed step is never reported as success -- the uuid and the apply-pending finding are what
         * let the GUI offer Apply again */
        $apply = wgct_configd_json('wgclienttunnels apply_mode', [$result['uuid'], 'first'], 300);
        /* the save's own notes (a failed apply-pending mark) first, then the apply's */
        $applyErrors = array_merge(array_values($result['errors']), is_array($apply['errors'] ?? null) ? array_values($apply['errors']) : []);
        return [
            'result' => 'saved', 'ok' => ($apply['ok'] ?? false) === true && $applyErrors === [],
            'saved' => true, 'uuid' => $result['uuid'], 'changes' => $result['changes'],
            'apply' => $apply['apply'] ?? [], 'after' => $apply['after'] ?? [], 'errors' => $applyErrors,
        ];
    }

    /**
     * Edit (spec 6.5): {edit: {...}, dry: 1} previews; without dry it saves the
     * differences in-process (the only step that sees a key) and hands the
     * apply to `apply_mode <uuid> <mode>`. The gateway lock is held for the save
     * only when the edit changes routing (spec 4.6), and released before configd.
     */
    public function editAction(string $uuid = ''): array
    {
        if (!$this->request->isPost()) {
            return ['result' => 'failed'];
        }
        require_once self::LIB . '/writer.php';
        if (preg_match(self::UUID, $uuid) !== 1) {
            return ['result' => 'failed', 'errors' => ['not a tunnel uuid']];
        }
        $dry = wgct_dry_flag($this->request->getPost('dry'));
        if ($dry === null) {
            return ['result' => 'failed', 'errors' => ['dry must be 1 (preview) or omitted/0 (run for real)']];
        }
        if (!$dry) {
            $this->throwReadOnly();
        }
        /* a form boundary: edit.* arrives as an array of strings; wgct_edit_request() checks every value */
        $raw = $this->request->getPost('edit');
        if (!is_array($raw)) {
            return ['result' => 'failed', 'errors' => ['the edit form was empty']];
        }
        $secrets = [];
        $saved = false;
        try {
            $prep = wgct_edit_prepare($raw, $uuid);
            $secrets = array_values($prep['secret']);
            if ($prep['errors'] !== []) {
                return $this->formFailure($prep['errors'], $prep['notes'], 'edit', WGCT_EDIT_FIELDS);
            }
            if ($dry) {
                $result = wgct_edit_commit($prep, true, false);
            } else {
                $routing = wgct_apply_mode_locks(wgct_edit_mode_unlocked($prep));
                $commit = function () use ($prep, $routing, &$saved): array {
                    $r = wgct_edit_commit($prep, false, $routing);
                    $saved = $r['saved'];
                    if ($r['saved']) {
                        /* core's kernel-route hand-off for a deleted endpoint route, before the apply's routes configure */
                        wgct_write_route_todos($r['route_todos']);
                    }
                    return $r;
                };
                $result = $routing ? wgct_gateway_locked_commit($commit) : $commit();
            }
        } catch (\Throwable $e) {
            syslog(LOG_ERR, '[wgct-action] edit failed: ' . wgct_redact(get_class($e) . ': ' . $e->getMessage(), $secrets));
            return ['result' => 'failed', 'saved' => $saved, 'errors' => [
                'Edit failed; the system log has the reason (never the key). ' . wgct_failure_footer('edit', $uuid),
            ]];
        }
        unset($prep, $raw, $secrets);
        if (!$result['ok']) {
            return $this->formFailure($result['errors'], $result['changes'], 'edit', WGCT_EDIT_FIELDS);
        }
        if ($dry || !$result['saved']) {
            return [
                'result' => $dry ? 'preview' : 'unchanged', 'ok' => true, 'saved' => false, 'dry' => $dry,
                'changes' => $result['changes'], 'errors' => [],
            ];
        }
        /* saved, and marked apply-pending with its mode by wgct_edit_commit() until an apply of at least
         * that mode completes (S5 review I2); 'ok' reflects only whether this apply succeeded */
        $apply = wgct_configd_json('wgclienttunnels apply_mode', [$uuid, $result['apply_mode']], 300);
        /* the save's own notes (a failed apply-pending mark) first, then the apply's */
        $applyErrors = array_merge(array_values($result['errors']), is_array($apply['errors'] ?? null) ? array_values($apply['errors']) : []);
        return [
            'result' => 'saved', 'ok' => ($apply['ok'] ?? false) === true && $applyErrors === [],
            'saved' => true, 'uuid' => $uuid, 'changes' => $result['changes'],
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
     * @param array        $errors  keyed by request field or 'general'
     * @param list<string> $changes
     * @param string       $form    the form id prefix: create or edit
     * @param list<string> $fields  the form's request fields (WGCT_CREATE_FIELDS, WGCT_EDIT_FIELDS)
     * @return array the form failure: field messages for handleFormValidation(), the rest as a list
     */
    private function formFailure(array $errors, array $changes, string $form, array $fields): array
    {
        $validations = [];
        $general = [];
        foreach ($errors as $field => $message) {
            if (is_string($field) && in_array($field, $fields, true)) {
                $validations[$form . '.' . $field] = $message;
            } else {
                $general[] = $message;
            }
        }
        return ['result' => 'failed', 'validations' => $validations, 'errors' => $general, 'changes' => $changes];
    }

    /**
     * @return array{status: array<string, string>, text: array<string, string>}
     *         wgct_gateway_status_maps() of core's gateway status
     */
    private function gatewayStatus(): array
    {
        /* configd output: a JSON boundary, decoded to mixed and checked row by row */
        return wgct_gateway_status_maps(json_decode((string)(new Backend())->configdRun('interface gateways status'), true));
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
