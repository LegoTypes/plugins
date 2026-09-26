<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The action writers (spec 2026-09-24 sections 4.6 and 6). Each runs its
 * planner on a snapshot taken under Config::lock(), writes the models in the
 * order core needs, validates every one and saves once. With --dry, or on any
 * error, it saves nothing and re-reads config, so no half-written tree stays
 * in this process (the API's Create request goes on to the apply after the
 * write, and the CLI to the reconcile). The
 * apply is not done here: each result names its configd steps for
 * wgct_routing_action() (apply.php) or, for the API's Create, for the
 * keyless configd action `wgclienttunnels apply`. Edit (wgct_edit_commit())
 * re-plans under the lock and writes only the differences.
 */

use OPNsense\Core\Config;

require_once __DIR__ . '/tunnels.php';
require_once __DIR__ . '/wgconf.php';
require_once __DIR__ . '/refs.php';
require_once __DIR__ . '/actions.php';
require_once __DIR__ . '/edit.php';
require_once __DIR__ . '/mtu.php';
require_once __DIR__ . '/apply.php';
require_once __DIR__ . '/mirror.php';

/**
 * Forget the per-process field caches, so the next model built sees what was
 * just written into the config tree (spec 6.1). ModelRelationField keeps the
 * related models' option lists in private statics (reset by reflection, as
 * the retired scripts did). InterfaceField keeps the interface list --
 * filtered by `enable` for gateways -- in BaseListField's statics
 * (resetStaticOptions()). DeviceField is never involved: the assignment is
 * written into the tree, not through the NetworkInterface model.
 */
function wgct_reset_field_caches(): void {
    $relation = new \ReflectionClass(\OPNsense\Base\FieldTypes\ModelRelationField::class);
    foreach (['internalCacheModelStruct', 'internalCacheOptionList'] as $property) {
        $relation->getProperty($property)->setValue(null, []);
    }
    (new \OPNsense\Base\FieldTypes\InterfaceField())->resetStaticOptions();
}

/**
 * @param \OPNsense\Base\BaseModel $mdl   a model with pending changes
 * @param string                   $label what to call it in a message
 * @return list<string> its validation messages; a privkey/psk field's text is never shown
 */
function wgct_model_errors(\OPNsense\Base\BaseModel $mdl, string $label): array {
    $out = [];
    foreach ($mdl->performValidation() as $msg) {
        $field = (string)$msg->getField();
        $text = preg_match('/(^|\.)(privkey|psk)$/', $field) === 1 ? 'rejected (the value is not shown)' : (string)$msg->getMessage();
        $out[] = "{$label}: {$field}: {$text}";
    }
    return $out;
}

/**
 * Everything the planners read. Call under Config::lock() in a writer.
 *
 * @return array the action snapshot (Task 3 Interfaces)
 */
function wgct_action_snapshot(): array {
    $root = Config::getInstance()->object();
    $mdl = new \OPNsense\WGClientTunnels\WGClientTunnels();
    $ports = [];
    $instancePubkeys = [];
    foreach ((new \OPNsense\Wireguard\Server())->servers->server->iterateItems() as $uuid => $server) {
        $ports[(string)$uuid] = (string)$server->port;
        $instancePubkeys[(string)$uuid] = (string)$server->pubkey;
    }
    $peerFields = [];
    foreach ((new \OPNsense\Wireguard\Client())->clients->client->iterateItems() as $uuid => $client) {
        $peerFields[(string)$uuid] = ['tunneladdress' => (string)$client->tunneladdress, 'pubkey' => (string)$client->pubkey];
    }
    $gatewayFields = [];
    foreach ((new \OPNsense\Routing\Gateways())->gateway_item->iterateItems() as $gw) {
        $row = [];
        foreach (WGCT_GATEWAY_COPY_FIELDS as $field) {
            $row[$field] = (string)$gw->{$field};
        }
        $gatewayFields[(string)$gw->name] = $row;
    }
    $snat = [];
    foreach ((new \OPNsense\Firewall\Filter())->snatrules->rule->iterateItems() as $uuid => $rule) {
        $fields = [];
        foreach ($rule->iterateItems() as $field => $node) {
            if (!in_array((string)$field, WGCT_SNAT_SKIP_FIELDS, true) && !$node->getInternalIsVolatile()) {
                $fields[(string)$field] = (string)$node;
            }
        }
        $snat[(string)$uuid] = [
            'interface' => (string)$rule->interface, 'ipprotocol' => (string)$rule->ipprotocol,
            'enabled' => (string)$rule->enabled, 'sequence' => (string)$rule->sequence, 'fields' => $fields,
        ];
    }
    $aliases = [];
    foreach ((new \OPNsense\Firewall\Alias())->aliases->alias->iterateItems() as $alias) {
        $aliases[] = (string)$alias->name;
    }
    $groups = [];
    foreach (wgct_xml_list($root, 'ifgroups', 'ifgroupentry') as $group) {
        $groups[] = (string)$group->ifname;
    }
    return [
        'core' => wgct_core_snapshot(),
        'managed' => wgct_split_csv((string)$mdl->managed),
        'held' => wgct_split_csv((string)$mdl->held),
        'ports' => $ports,
        'gateway_fields' => $gatewayFields,
        'snat_rules' => $snat,
        'aliases' => $aliases,
        'ifgroup_names' => $groups,
        'wireguard_enabled' => (string)$root->OPNsense->wireguard->general->enabled === '1',
        'peer_fields' => $peerFields,
        'instance_pubkeys' => $instancePubkeys,
    ];
}

/**
 * wgct_locked_commit() for an action. $mutate returns ['save' => bool,
 * 'result' => wgct_result()]. Unless it saved, config is re-read.
 *
 * @param callable(): array $mutate
 * @param string            $description the config-history text of the save (ruling 23)
 * @return array wgct_result()
 */
function wgct_action_commit(callable $mutate, string $description): array {
    try {
        $commit = wgct_locked_commit($mutate, 'wg upstream tunnels: ' . $description);
    } catch (\Throwable $e) {
        Config::getInstance()->forceReload();
        throw $e;
    }
    if (empty($commit['save'])) {
        Config::getInstance()->forceReload();
    }
    return $commit['result'];
}

/**
 * Everything Create does before it touches config (spec 6.1): check the
 * request, parse the config, derive our public key, and measure the MTU when
 * none was given. Holds no lock: the MTU probe alone can take ~30 s.
 *
 * @param array $raw         the API form or the CLI JSON (see wgct_create_request())
 * @param bool  $mtuRequired the API requires an MTU; the CLI measures one
 * @return array{errors: array<string, string>, req: array, public: array, secret: array{privkey: string, psk: string, pubkey: string}, notes: list<string>}
 */
function wgct_create_prepare(#[\SensitiveParameter] array $raw, bool $mtuRequired): array {
    $in = wgct_create_request($raw, $mtuRequired);
    $prep = ['errors' => $in['errors'], 'req' => $in['req'], 'public' => [], 'secret' => ['privkey' => '', 'psk' => '', 'pubkey' => ''], 'notes' => []];
    if ($in['text'] !== '') {
        $conf = wgct_parse_wgquick($in['text']);
        if ($conf['errors'] !== []) {
            $prep['errors']['config'] = implode('; ', $conf['errors']);
        }
        $prep['public'] = $conf['public'];
        $prep['secret']['privkey'] = $conf['secret']['privkey'];
        $prep['secret']['psk'] = $conf['secret']['psk'];
    }
    if ($prep['errors'] !== []) {
        return $prep;
    }
    $pubkey = wgct_derive_pubkey($prep['secret']['privkey']);
    if ($pubkey === null) {
        $prep['errors']['config'] = 'wg pubkey rejected the private key';
        return $prep;
    }
    $prep['secret']['pubkey'] = $pubkey;
    if ($prep['req']['mtu'] === null) {
        $m = wgct_measure_mtu($prep['req']['wan'], $prep['public']['endpoint_ip']);
        if (!$m['ok']) {
            $prep['errors']['mtu'] = implode('; ', $m['errors']);
            return $prep;
        }
        $prep['req']['mtu'] = $m['mtu'];
        $prep['notes'][] = "mtu {$m['mtu']}: {$m['why']}";
    }
    return $prep;
}

/**
 * Write a Create plan into the models. Call only inside Config::lock(). The
 * assignment goes into the config tree first -- core's MVC NetworkInterface
 * cannot take a wgN that is not saved yet, and a gateway may only name an
 * enabled interface (spec 6.1 ruling) -- then each model is validated,
 * serialized, and the caches reset, so the next one validates against it.
 *
 * @param array $plan   wgct_plan_create() without errors
 * @param array $secret ['privkey', 'psk', 'pubkey']
 * @return array{errors: list<string>, uuid: string}
 */
function wgct_write_create(array $plan, #[\SensitiveParameter] array $secret): array {
    $root = Config::getInstance()->object();
    $if = $root->interfaces->addChild($plan['opt']);
    $if->addChild('if', $plan['device']);
    $if->addChild('descr', $plan['descr']);
    $if->addChild('enable', '1');
    $if->addChild('lock', '1');
    $if->addChild('spoofmac');
    wgct_reset_field_caches();

    /* the peer, then the instance naming it: core's ClientController order */
    $client = new \OPNsense\Wireguard\Client();
    $peer = $client->clients->client->Add();
    $peer->setNodes($secret['psk'] !== '' ? $plan['peer'] + ['psk' => $secret['psk']] : $plan['peer']);
    $peerUuid = (string)$peer->getAttribute('uuid');
    $errors = wgct_model_errors($client, 'wireguard peer');
    if ($errors !== []) {
        return ['errors' => $errors, 'uuid' => ''];
    }
    $client->serializeToConfig();
    wgct_reset_field_caches();

    $server = new \OPNsense\Wireguard\Server();
    $instance = $server->servers->server->Add();
    $instance->setNodes($plan['instance'] + ['privkey' => $secret['privkey'], 'pubkey' => $secret['pubkey'], 'peers' => $peerUuid]);
    $uuid = (string)$instance->getAttribute('uuid');
    $errors = wgct_model_errors($server, 'wireguard instance');
    if ($errors !== []) {
        return ['errors' => $errors, 'uuid' => ''];
    }
    $server->serializeToConfig();
    wgct_reset_field_caches();

    $gateways = new \OPNsense\Routing\Gateways();
    foreach ($plan['gateways'] as $g) {
        $gateways->gateway_item->Add()->setNodes($g['fields']);
    }
    $errors = wgct_model_errors($gateways, 'gateways');
    if ($errors !== []) {
        return ['errors' => $errors, 'uuid' => ''];
    }
    $gateways->serializeToConfig();
    wgct_reset_field_caches();

    $routes = new \OPNsense\Routes\Route();
    if ($plan['route']['action'] === 'add') {
        $routes->route->Add()->setNodes($plan['route']['fields']);
    } elseif ($plan['route']['action'] === 'update') {
        $node = $routes->getNodeByReference('route.' . $plan['route']['uuid']);
        if ($node === null) {
            return ['errors' => ["static routes: route {$plan['route']['uuid']} vanished"], 'uuid' => ''];
        }
        $node->setNodes($plan['route']['fields']);
    }
    $errors = wgct_model_errors($routes, 'static routes');
    if ($errors !== []) {
        return ['errors' => $errors, 'uuid' => ''];
    }
    $routes->serializeToConfig();

    $filter = new \OPNsense\Firewall\Filter();
    foreach ($plan['nat'] as $fields) {
        $filter->snatrules->rule->Add()->setNodes(array_merge($fields, ['interface' => $plan['opt']]));
    }
    $errors = wgct_model_errors($filter, 'outbound NAT');
    if ($errors !== []) {
        return ['errors' => $errors, 'uuid' => ''];
    }
    $filter->serializeToConfig();
    wgct_reset_field_caches();

    $mdl = new \OPNsense\WGClientTunnels\WGClientTunnels();
    $managed = wgct_split_csv((string)$mdl->managed);
    $managed[] = $uuid;
    $mdl->managed = implode(',', $managed);
    $errors = wgct_model_errors($mdl, 'plugin');
    if ($errors !== []) {
        return ['errors' => $errors, 'uuid' => ''];
    }
    $mdl->serializeToConfig();
    return ['errors' => [], 'uuid' => $uuid];
}

/**
 * Create's config write (spec 4.6 steps 2-5).
 *
 * @param array $prep wgct_create_prepare() without errors
 * @return array wgct_result(): steps WGCT_CREATE_APPLY_STEPS, gateways the new tunnel's.
 *               A saved Create is marked apply-pending until an apply completes (ruling 20).
 */
function wgct_create_commit(#[\SensitiveParameter] array $prep, bool $dry): array {
    $result = wgct_action_commit(function () use ($prep, $dry): array {
        $plan = wgct_plan_create(wgct_action_snapshot(), $prep['req'], $prep['public']);
        $changes = array_merge($prep['notes'], $plan['changes']);
        if ($plan['errors'] !== []) {
            return ['save' => false, 'result' => wgct_result(['errors' => $plan['errors'], 'changes' => $changes, 'dry' => $dry])];
        }
        $written = wgct_write_create($plan, $prep['secret']);
        if ($written['errors'] !== []) {
            return ['save' => false, 'result' => wgct_result(['errors' => ['general' => implode('; ', $written['errors'])], 'changes' => $changes, 'dry' => $dry])];
        }
        return ['save' => !$dry, 'result' => wgct_result([
            'ok' => true, 'saved' => !$dry, 'dry' => $dry, 'changes' => $changes, 'uuid' => $written['uuid'],
            'gateways' => array_column($plan['gateways'], 'name'), 'steps' => WGCT_CREATE_APPLY_STEPS,
        ])];
    }, 'create ' . $prep['req']['name']);
    if ($result['saved']) {
        $result = wgct_mark_after_save($result, fn () => wgct_mark_apply_pending($result['uuid'], 'first'));
    }
    return $result;
}

/**
 * Rebind's config write (spec 6.2). The stale route's kernel route goes by
 * core's todo hand-off; the apply is wgct_rebind_apply_steps():
 * `interface routes configure` (which ends with its own filter reload), then
 * `wireguard restart` so the tunnel handshakes again on the new route.
 *
 * @return array wgct_result()
 */
function wgct_rebind_commit(string $uuid, string $wan, string $staleUuid, bool $dry): array {
    return wgct_action_commit(function () use ($uuid, $wan, $staleUuid, $dry): array {
        $plan = wgct_plan_rebind(wgct_action_snapshot(), $uuid, $wan, $staleUuid);
        if ($plan['errors'] !== []) {
            return ['save' => false, 'result' => wgct_result(['errors' => $plan['errors'], 'changes' => $plan['changes'], 'dry' => $dry, 'uuid' => $uuid])];
        }
        $routes = new \OPNsense\Routes\Route();
        if ($plan['route']['action'] === 'add') {
            $routes->route->Add()->setNodes($plan['route']['fields']);
        } else {
            $node = $routes->getNodeByReference('route.' . $plan['route']['uuid']);
            if ($node === null) {
                return ['save' => false, 'result' => wgct_result(['errors' => ['the route to update vanished'], 'dry' => $dry, 'uuid' => $uuid])];
            }
            $node->setNodes($plan['route']['fields']);
        }
        if ($plan['delete'] !== null) {
            $routes->route->del($plan['delete']['uuid']);
        }
        $errors = wgct_model_errors($routes, 'static routes');
        if ($errors !== []) {
            return ['save' => false, 'result' => wgct_result(['errors' => $errors, 'changes' => $plan['changes'], 'dry' => $dry, 'uuid' => $uuid])];
        }
        if (!$dry) {
            $routes->serializeToConfig();
        }
        return ['save' => !$dry, 'result' => wgct_result([
            'ok' => true, 'saved' => !$dry, 'dry' => $dry, 'changes' => $plan['changes'], 'uuid' => $uuid,
            'gateways' => $plan['gateways'], 'steps' => wgct_rebind_apply_steps($uuid),
            'route_todos' => $plan['delete'] !== null ? [$plan['delete']['uuid'] => $plan['delete']['network']] : [],
        ])];
    }, 'rebind ' . $uuid . ' to ' . $wan);
}

/**
 * Adopt's config write: the uuid joins the managed list. No routing change.
 *
 * @return array wgct_result()
 */
function wgct_adopt_commit(string $uuid, bool $dry): array {
    return wgct_action_commit(function () use ($uuid, $dry): array {
        $plan = wgct_plan_adopt(wgct_action_snapshot(), $uuid);
        if ($plan['errors'] !== []) {
            return ['save' => false, 'result' => wgct_result(['errors' => $plan['errors'], 'dry' => $dry, 'uuid' => $uuid])];
        }
        $mdl = new \OPNsense\WGClientTunnels\WGClientTunnels();
        $mdl->managed = implode(',', $plan['managed']);
        $errors = wgct_model_errors($mdl, 'plugin');
        if ($errors !== []) {
            return ['save' => false, 'result' => wgct_result(['errors' => $errors, 'dry' => $dry, 'uuid' => $uuid])];
        }
        if (!$dry) {
            $mdl->serializeToConfig();
        }
        return ['save' => !$dry, 'result' => wgct_result([
            'ok' => true, 'saved' => !$dry, 'dry' => $dry, 'changes' => $plan['changes'], 'uuid' => $uuid,
        ])];
    }, 'adopt ' . $uuid);
}

/**
 * Remove's config write (spec 6.3), after the refusal check. The assignment
 * is taken out of the tree directly (ruling 2026-09-25): core's MVC path
 * refuses lock=1 and queues deletes in the todo file shared with pending GUI
 * edits. interface_reset() runs later, as the first apply hand-off.
 *
 * @return array wgct_result()
 */
function wgct_remove_commit(string $uuid, bool $dry): array {
    return wgct_action_commit(function () use ($uuid, $dry): array {
        $snap = wgct_action_snapshot();
        $plan = wgct_plan_remove($snap, wgct_refs_snapshot($snap['core']['groups']), $uuid);
        if ($plan['errors'] !== []) {
            return ['save' => false, 'result' => wgct_result(['errors' => $plan['errors'], 'changes' => $plan['changes'], 'dry' => $dry, 'uuid' => $uuid])];
        }
        $client = new \OPNsense\Wireguard\Client();
        foreach ($plan['peers'] as $peerUuid) {
            $client->clients->client->del($peerUuid);
        }
        $server = new \OPNsense\Wireguard\Server();
        if ($plan['instance'] !== null) {
            $server->servers->server->del($plan['instance']);
        }
        $gateways = new \OPNsense\Routing\Gateways();
        foreach ($plan['gateways'] as $gwUuid) {
            $gateways->gateway_item->del($gwUuid);
        }
        $routes = new \OPNsense\Routes\Route();
        foreach (array_keys($plan['routes']) as $routeUuid) {
            $routes->route->del((string)$routeUuid);
        }
        $filter = new \OPNsense\Firewall\Filter();
        foreach ($plan['snat'] as $ruleUuid) {
            $filter->snatrules->rule->del($ruleUuid);
        }
        $mdl = new \OPNsense\WGClientTunnels\WGClientTunnels();
        $mdl->managed = implode(',', $plan['managed']);
        $mdl->held = implode(',', $plan['held']);
        $models = [
            'wireguard peers' => $client, 'wireguard instances' => $server, 'gateways' => $gateways,
            'static routes' => $routes, 'outbound NAT' => $filter, 'plugin' => $mdl,
        ];
        $errors = [];
        foreach ($models as $label => $model) {
            $errors = array_merge($errors, wgct_model_errors($model, $label));
        }
        if ($errors !== []) {
            return ['save' => false, 'result' => wgct_result(['errors' => $errors, 'changes' => $plan['changes'], 'dry' => $dry, 'uuid' => $uuid])];
        }
        if (!$dry) {
            foreach ($models as $model) {
                $model->serializeToConfig();
            }
            if ($plan['opt'] !== null) {
                unset(Config::getInstance()->object()->interfaces->{$plan['opt']});
            }
        }
        return ['save' => !$dry, 'result' => wgct_result([
            'ok' => true, 'saved' => !$dry, 'dry' => $dry, 'changes' => $plan['changes'], 'uuid' => $uuid,
            'steps' => WGCT_REMOVE_APPLY_STEPS, 'route_todos' => $plan['routes'], 'reset_interface' => $plan['opt'],
        ])];
    }, 'remove ' . $uuid);
}

/**
 * The sentinel's config write (spec 4.3), ported from
 * setup_default_sentinel.php: loopback, its assignment (written into the tree
 * before the gateways, as in Create), both gateways; idempotent. Its apply
 * steps come from the plan and match what changed (ruling 19): a
 * description-only repair is saved and applies nothing.
 *
 * @return array wgct_result()
 */
function wgct_sentinel_commit(bool $dry): array {
    return wgct_action_commit(function () use ($dry): array {
        $root = Config::getInstance()->object();
        $changes = [];
        $loopbacks = new \OPNsense\Interfaces\Loopback();
        $loopback = null;
        foreach ($loopbacks->loopback->iterateItems() as $node) {
            if ((string)$node->description === WGCT_SENTINEL_LOOPBACK_DESCR) {
                $loopback = $node;
            }
        }
        $loopbackAdded = $loopback === null;
        if ($loopback === null) {
            $loopback = $loopbacks->loopback->Add();
            $loopback->description = WGCT_SENTINEL_LOOPBACK_DESCR;
            $changes[] = 'loopback device (' . WGCT_SENTINEL_LOOPBACK_DESCR . ')';
        }
        $errors = wgct_model_errors($loopbacks, 'loopback');
        $device = 'lo' . (string)$loopback->deviceId;
        $interfaces = [];
        foreach ($root->interfaces->children() as $key => $if) {
            $interfaces[(string)$key] = [
                'if' => (string)$if->if, 'descr' => (string)$if->descr, 'gateway_interface' => (string)$if->gateway_interface,
                'ipaddr' => (string)$if->ipaddr, 'ipaddrv6' => (string)$if->ipaddrv6,
            ];
        }
        $gateways = [];
        foreach ((new \OPNsense\Routing\Gateways())->gateway_item->iterateItems() as $gw) {
            $row = [];
            foreach (['disabled', 'name', 'descr', 'interface', 'ipprotocol', 'gateway', 'defaultgw', 'monitor_disable',
                      'monitor_killstates', 'force_down', 'priority'] as $field) {
                $row[$field] = (string)$gw->{$field};
            }
            $gateways[(string)$gw->name] = $row;
        }
        $plan = wgct_plan_sentinel($interfaces, $gateways, $device, $loopbackAdded);
        $changes = array_merge($changes, $plan['changes']);
        $errors = array_merge($errors, $plan['errors']);
        if ($errors !== []) {
            return ['save' => false, 'result' => wgct_result(['errors' => $errors, 'changes' => $changes, 'dry' => $dry])];
        }
        if ($changes === []) {
            return ['save' => false, 'result' => wgct_result(['ok' => true, 'dry' => $dry])];
        }
        $opt = $plan['opt'];
        if ($plan['assignment'] === 'add') {
            $node = $root->interfaces->addChild($opt);
            $node->addChild('if', $device);
            $node->addChild('descr', WGCT_SENTINEL_IF_DESCR);
            $node->addChild('enable', '1');
            $node->addChild('lock', '1');
            $node->addChild('gateway_interface', '1');
            $node->addChild('spoofmac');
        } elseif ($plan['assignment'] === 'policy') {
            $root->interfaces->{$opt}->gateway_interface = '1';
        }
        $loopbacks->serializeToConfig();
        wgct_reset_field_caches();
        $model = new \OPNsense\Routing\Gateways();
        $byName = [];
        foreach ($model->gateway_item->iterateItems() as $gw) {
            $byName[(string)$gw->name] = $gw;
        }
        foreach ($plan['gateways'] as $name => $g) {
            if ($g['action'] === 'add') {
                $model->gateway_item->Add()->setNodes($g['set']);
            } elseif ($g['action'] === 'update') {
                $byName[$name]->setNodes($g['set']);
            }
        }
        $errors = wgct_model_errors($model, 'gateways');
        if ($errors !== []) {
            return ['save' => false, 'result' => wgct_result(['errors' => $errors, 'changes' => $changes, 'dry' => $dry])];
        }
        $model->serializeToConfig();
        /* the replay concerns the sentinels only when their routing changed */
        $routing = in_array(['interface routes configure', []], $plan['steps'], true);
        return ['save' => !$dry, 'result' => wgct_result([
            'ok' => true, 'saved' => !$dry, 'dry' => $dry, 'changes' => $changes,
            'gateways' => $routing ? array_values(WGCT_SENTINELS) : [], 'steps' => $plan['steps'],
        ])];
    }, 'default-route exclusion (sentinel)');
}

/**
 * Everything Edit does before it touches config: check the request, parse a
 * replacement config and derive our public key. Holds no lock.
 *
 * @param array  $raw  the API form's edit.* or the CLI's JSON
 * @param string $uuid the managed instance
 * @return array{errors: array<string, string>, req: array, swap: ?array{public: array, own_pubkey: string}, secret: array{privkey: string, psk: string}, notes: list<string>}
 */
function wgct_edit_prepare(#[\SensitiveParameter] array $raw, string $uuid): array {
    $in = wgct_edit_request($raw, $uuid);
    $prep = ['errors' => $in['errors'], 'req' => $in['req'], 'swap' => null, 'secret' => ['privkey' => '', 'psk' => ''], 'notes' => []];
    if (trim($in['text']) === '') {
        return $prep;
    }
    $conf = wgct_parse_wgquick($in['text']);
    if ($conf['errors'] !== []) {
        $prep['errors']['config'] = implode('; ', $conf['errors']);
    }
    $prep['secret'] = $conf['secret'];
    if ($prep['errors'] !== []) {
        return $prep;
    }
    $pubkey = wgct_derive_pubkey($prep['secret']['privkey']);
    if ($pubkey === null) {
        $prep['errors']['config'] = 'wg pubkey rejected the private key';
        return $prep;
    }
    $prep['swap'] = ['public' => $conf['public'], 'own_pubkey' => $pubkey];
    return $prep;
}

/**
 * The planner's view of a swap (ruling 11): the public parts, our public key,
 * and whether the config's preshared key equals the stored one -- compared
 * here, in-process, so the planner never holds a key.
 *
 * @param array $snap the action snapshot
 * @param array $prep wgct_edit_prepare() without errors
 * @return array|null null without a replacement config
 */
function wgct_edit_swap_state(array $snap, #[\SensitiveParameter] array $prep): ?array {
    if ($prep['swap'] === null) {
        return null;
    }
    $peers = $snap['core']['instances'][$prep['req']['uuid']]['peers'] ?? [];
    $same = false;
    if (count($peers) === 1) {
        $node = (new \OPNsense\Wireguard\Client())->getNodeByReference('clients.client.' . $peers[0]);
        $same = $node !== null && hash_equals((string)$node->psk, $prep['secret']['psk']);
    }
    return ['public' => $prep['swap']['public'], 'own_pubkey' => $prep['swap']['own_pubkey'], 'psk_same' => $same];
}

/**
 * Write an Edit plan into the models. Call only inside Config::lock(). Core's
 * order, as Create writes: peer, instance, gateways, routes, outbound NAT;
 * each model validated and serialized, the relation caches reset after it.
 * Only models the plan changes are built.
 *
 * @param array $plan   wgct_plan_edit() without errors, mode not none
 * @param array $secret ['privkey', 'psk'], written only when the plan swaps keys
 * @return list<string> validation errors; [] when everything is written
 */
function wgct_write_edit(array $plan, #[\SensitiveParameter] array $secret): array {
    if ($plan['peer'] !== [] || $plan['swap_keys']) {
        $client = new \OPNsense\Wireguard\Client();
        $node = $client->getNodeByReference('clients.client.' . $plan['peer_uuid']);
        if ($node === null) {
            return ["wireguard peer {$plan['peer_uuid']} vanished"];
        }
        $node->setNodes($plan['swap_keys'] ? $plan['peer'] + ['psk' => $secret['psk']] : $plan['peer']);
        $errors = wgct_model_errors($client, 'wireguard peer');
        if ($errors !== []) {
            return $errors;
        }
        $client->serializeToConfig();
        wgct_reset_field_caches();
    }
    if ($plan['instance'] !== [] || $plan['swap_keys']) {
        $server = new \OPNsense\Wireguard\Server();
        $node = $server->getNodeByReference('servers.server.' . $plan['uuid']);
        if ($node === null) {
            return ["wireguard instance {$plan['uuid']} vanished"];
        }
        $node->setNodes($plan['swap_keys'] ? $plan['instance'] + ['privkey' => $secret['privkey']] : $plan['instance']);
        $errors = wgct_model_errors($server, 'wireguard instance');
        if ($errors !== []) {
            return $errors;
        }
        $server->serializeToConfig();
        wgct_reset_field_caches();
    }
    $g = $plan['gateways'];
    if ($g['update'] !== [] || $g['add'] !== [] || $g['delete'] !== []) {
        $gateways = new \OPNsense\Routing\Gateways();
        $updated = [];
        foreach ($gateways->gateway_item->iterateItems() as $node) {
            $name = (string)$node->name;
            if (isset($g['update'][$name])) {
                $node->setNodes($g['update'][$name]);
                $updated[] = $name;
            }
        }
        $missing = array_diff(array_map('strval', array_keys($g['update'])), $updated);
        if ($missing !== []) {
            return ['gateways: ' . implode(', ', $missing) . ' vanished'];
        }
        foreach ($g['add'] as $fields) {
            $gateways->gateway_item->Add()->setNodes($fields);
        }
        foreach ($g['delete'] as $gwUuid) {
            $gateways->gateway_item->del($gwUuid);
        }
        $errors = wgct_model_errors($gateways, 'gateways');
        if ($errors !== []) {
            return $errors;
        }
        $gateways->serializeToConfig();
        wgct_reset_field_caches();
    }
    $r = $plan['routes'];
    if ($r['add'] !== [] || $r['update'] !== [] || $r['delete'] !== []) {
        $routes = new \OPNsense\Routes\Route();
        foreach ($r['update'] as $routeUuid => $fields) {
            $node = $routes->getNodeByReference('route.' . $routeUuid);
            if ($node === null) {
                return ["static routes: route {$routeUuid} vanished"];
            }
            $node->setNodes($fields);
        }
        foreach ($r['add'] as $fields) {
            $routes->route->Add()->setNodes($fields);
        }
        foreach (array_keys($r['delete']) as $routeUuid) {
            $routes->route->del((string)$routeUuid);
        }
        $errors = wgct_model_errors($routes, 'static routes');
        if ($errors !== []) {
            return $errors;
        }
        $routes->serializeToConfig();
    }
    if ($plan['nat']['add'] !== [] || $plan['nat']['delete'] !== []) {
        $filter = new \OPNsense\Firewall\Filter();
        foreach ($plan['nat']['add'] as $fields) {
            $filter->snatrules->rule->Add()->setNodes(array_merge($fields, ['interface' => $plan['opt']]));
        }
        foreach ($plan['nat']['delete'] as $ruleUuid) {
            $filter->snatrules->rule->del($ruleUuid);
        }
        $errors = wgct_model_errors($filter, 'outbound NAT');
        if ($errors !== []) {
            return $errors;
        }
        $filter->serializeToConfig();
        wgct_reset_field_caches();
    }
    return [];
}

/**
 * Edit's config write (spec 6.5, 4.6 steps 2-5): re-plan on a snapshot taken
 * under Config::lock(), write only the differences, save once. A plan that
 * needs a routing apply is refused, nothing written, when the caller does not
 * hold the gateway lock (it classified the edit before the lock and config
 * changed meanwhile). Every saved Edit is marked apply-pending with its mode
 * until an apply of at least that mode completes (S5 review I2).
 *
 * @param array $prep        wgct_edit_prepare() without errors
 * @param bool  $dry         validate and preview only
 * @param bool  $gatewayHeld whether the caller holds the gateway lock
 * @return array wgct_result(): steps and apply_mode from the plan's mode; route_todos its deleted
 *               routes and the old monitor's host route (S5 review I3)
 */
function wgct_edit_commit(#[\SensitiveParameter] array $prep, bool $dry, bool $gatewayHeld): array {
    $uuid = $prep['req']['uuid'];
    $result = wgct_action_commit(function () use ($prep, $dry, $gatewayHeld, $uuid): array {
        $snap = wgct_action_snapshot();
        $plan = wgct_plan_edit($snap, wgct_refs_snapshot($snap['core']['groups']), $prep['req'], wgct_edit_swap_state($snap, $prep));
        $fail = fn (array $errors): array => ['save' => false, 'result' => wgct_result([
            'errors' => $errors, 'changes' => $plan['changes'], 'dry' => $dry, 'uuid' => $uuid,
        ])];
        if ($plan['errors'] !== []) {
            return $fail($plan['errors']);
        }
        if ($plan['mode'] === 'none') {
            return ['save' => false, 'result' => wgct_result(['ok' => true, 'dry' => $dry, 'uuid' => $uuid])];
        }
        if (!$dry && !$gatewayHeld && wgct_apply_mode_locks($plan['mode'])) {
            return $fail(['general' => 'the configuration changed while the edit was prepared, and it now needs a routing apply; nothing was written, try again']);
        }
        $errors = wgct_write_edit($plan, $prep['secret']);
        if ($errors !== []) {
            return $fail(['general' => implode('; ', $errors)]);
        }
        return ['save' => !$dry, 'result' => wgct_result([
            'ok' => true, 'saved' => !$dry, 'dry' => $dry, 'changes' => $plan['changes'], 'uuid' => $uuid,
            'gateways' => $plan['replay'], 'steps' => wgct_apply_mode_steps($plan['mode'], $uuid),
            'route_todos' => $plan['routes']['delete'] + $plan['kernel_routes'], 'apply_mode' => $plan['mode'],
        ])];
    }, 'edit ' . $uuid);
    if ($result['saved']) {
        $result = wgct_mark_after_save($result, fn () => wgct_mark_apply_pending($uuid, $result['apply_mode']));
    }
    return $result;
}

/**
 * The edit's apply mode on the current config, read without any lock, to
 * decide whether to take the gateway lock before wgct_edit_commit() (spec 4.6
 * lock order). A refused plan reads as none; the locked re-plan then refuses
 * it again, or refuses a routing change it does not hold the lock for.
 *
 * @param array $prep wgct_edit_prepare() without errors
 * @return string none, filter, routes or tunnel
 */
function wgct_edit_mode_unlocked(#[\SensitiveParameter] array $prep): string {
    $snap = wgct_action_snapshot();
    $plan = wgct_plan_edit($snap, wgct_refs_snapshot($snap['core']['groups']), $prep['req'], wgct_edit_swap_state($snap, $prep));
    return $plan['errors'] === [] ? $plan['mode'] : 'none';
}

/**
 * Edit from the command line: preview, or the whole pipeline with the lock
 * its apply needs -- routes/tunnel through wgct_routing_action() (gateway
 * lock, route todos, apply, replay, reconcile), filter/none through
 * wgct_filter_action() (config lock only).
 *
 * @param array $prep wgct_edit_prepare() without errors
 * @return array wgct_result()
 */
function wgct_edit_action(#[\SensitiveParameter] array $prep, bool $dry): array {
    if ($dry) {
        return wgct_edit_commit($prep, true, false);
    }
    if (wgct_apply_mode_locks(wgct_edit_mode_unlocked($prep))) {
        return wgct_routing_action(fn (): array => wgct_edit_commit($prep, false, true), false);
    }
    return wgct_filter_action(fn (): array => wgct_edit_commit($prep, false, false));
}
