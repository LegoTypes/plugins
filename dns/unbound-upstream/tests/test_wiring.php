<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The plugin's wiring on the test VM: the hook table, the hook order, the privileges,
 * configd's answers and the evaluate that Unbound's own start leads to (seen in configd's log). Needs the tree overlaid onto the VM (vm_overlay.sh) with the
 * plugin disabled; elsewhere it registers a suite that skips. Changes nothing lasting: it adds a minute job by hand
 * for stop's cron restart to remove, runs one pluginctl unbound_start and one configctl unbound restart (reading
 * unbound.conf all the while), which restart Unbound, swaps a do-ip6 line of unbound.conf under the evaluate lock and
 * puts it back, writes two
 * uu-wiring marker lines to the plugin's log, and puts a state recording a footprint in place of the saved one for
 * one read as nobody and, under the evaluate lock, for two cron restarts, then puts the saved one, the crontab and
 * cron's running state back. It also records two snapshots and replays each, in scratch directories it removes, and
 * runs the settings controller's resolver actions over a row it adds to the controller's model in memory only (no
 * action it runs saves).
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/log.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/state.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/render.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/snapshot.php';
require_once __DIR__ . '/scratch.php';

/** Every daily file of one log directory under /var/log, in order. */
function uu_test_log_dir(string $name): string
{
    $text = '';
    foreach (glob("/var/log/{$name}/{$name}_*.log") ?: [] as $file) {
        $text .= is_readable($file) ? (string)file_get_contents($file) : '';
    }
    return $text;
}

/**
 * The program() patterns of each filter in syslog-ng's rendered local configuration.
 *
 * @return array<string, list<string>> filter name => its program() patterns
 */
function uu_test_program_filters(string $conf): array
{
    $filters = [];
    preg_match_all('/^filter\s+(\w+)\s*\{(.*?)\};/ms', $conf, $blocks, PREG_SET_ORDER);
    foreach ($blocks as $block) {
        preg_match_all('/program\("([^"]*)"\)/', $block[2], $programs);
        if ($programs[1] !== []) {
            $filters[$block[1]] = $programs[1];
        }
    }
    return $filters;
}

/**
 * The Services > Unbound DNS entries of one Menu.xml, as entry name => order.
 *
 * @return array<string, int>
 */
function uu_test_unbound_menu(string $file): array
{
    $xml = is_readable($file) ? simplexml_load_file($file) : false;
    $entries = [];
    foreach ($xml === false ? [] : ($xml->xpath('/menu/Services/Unbound/*') ?: []) as $node) {
        $entries[$node->getName()] = (int)$node['order'];
    }
    return $entries;
}

/**
 * configd's log, every daily file: latest.log can still point at an earlier day's file (syslog-ng moves it on the
 * next rotation, and a VM restored from a checkpoint crosses midnight UTC without one).
 */
function uu_test_configd_log(): string
{
    $text = '';
    foreach (glob('/var/log/configd/configd_*.log') ?: [] as $file) {
        $text .= is_readable($file) ? (string)file_get_contents($file) : '';
    }
    return $text;
}

/**
 * How many times configd has finished the plugin's evaluate action. A disabled plugin evaluates quietly (its own
 * log stays empty), so configd's log is the witness that a hook queued one.
 */
function uu_test_evaluations(): int
{
    return substr_count(uu_test_configd_log(), '[unboundupstream evaluate] returned');
}

/** Wait up to 5 s for configd's log to show $needle more often than $before times. */
function uu_test_wait_configd(string $needle, int $before): bool
{
    $deadline = hrtime(true) + 5000000000;
    while (hrtime(true) < $deadline) {
        if (substr_count(uu_test_configd_log(), $needle) > $before) {
            return true;
        }
        usleep(200000);
    }
    return false;
}

/**
 * Run $body with the saved state at $path moved to $aside, and put it back whatever happens; $body writes its state
 * only through the callable it is given. The file at $path is removed only once that has written it, and the saved
 * one is renamed back only when it was moved aside, so a failure never deletes the real state: a move aside that
 * fails runs nothing and touches nothing. A throw is printed, as in uu_try_case().
 *
 * @param callable(callable(array<string, mixed>): void): void $body
 * @param callable(string, string): bool $rename rename(), or a stub
 */
function uu_test_state_aside(string $path, string $aside, callable $body, callable $rename): void
{
    $moved = false;
    if (file_exists($path)) {
        if (!$rename($path, $aside)) {
            printf("  cannot set the saved state aside: nothing run\n");
            return;
        }
        $moved = true;
    }
    $written = false;
    try {
        $body(function (array $state) use ($path, &$written): void {
            uu_state_save($path, $state);
            $written = true;
        });
    } catch (\Throwable $e) {
        printf("  threw %s: %s\n", get_class($e), $e->getMessage());
    } finally {
        if ($written) {
            @unlink($path);
        }
        if ($moved && !$rename($aside, $path)) {
            printf("  the saved state could not be put back from %s\n", $aside);
        }
    }
}

/** Whether cron runs (rc.d's status; the batch stops it for the scenarios and starts it at the end). */
function uu_test_cron_running(): bool
{
    $out = [];
    $rc = 1;
    exec('/usr/sbin/service cron onestatus > /dev/null 2>&1', $out, $rc);
    return $rc === 0;
}

/**
 * The evaluate lock, as evaluate.php takes it (exclusive, waiting up to UU_LOCK_WAIT_SECONDS), so no evaluation runs
 * while it is held; false when it could not be taken. Closing the handle releases it.
 *
 * @return resource|false
 */
function uu_test_evaluate_lock()
{
    $lock = fopen(UU_RUN_DIR . '/evaluate.lock', 'ce');
    if ($lock === false) {
        return false;
    }
    $deadline = hrtime(true) + UU_LOCK_WAIT_SECONDS * 1000000000;
    while (!flock($lock, LOCK_EX | LOCK_NB)) {
        if (hrtime(true) >= $deadline) {
            fclose($lock);
            return false;
        }
        usleep(200000);
    }
    return $lock;
}

/** Wait up to 60 s until cron's next minute tick is at least $margin seconds away. */
function uu_test_clear_of_tick(int $margin): bool
{
    $deadline = hrtime(true) + 60000000000;
    while (hrtime(true) < $deadline) {
        $second = (int)date('s');
        if ($second >= 1 && 60 - $second >= $margin) {
            return true;
        }
        usleep(200000);
    }
    return false;
}

uu_register_suite('wiring', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    if (!is_executable('/usr/local/sbin/configctl') || !is_readable('/usr/local/etc/inc/plugins.inc')) {
        printf("[SKIP] wiring: core is not on this machine\n");
        return uu_tally_report('wiring', $t);
    }
    $view = file_get_contents('/usr/local/opnsense/mvc/app/views/OPNsense/UnboundUpstream/index.volt');
    $view = $view === false ? '' : $view;
    uu_check($t, '(f4) the installed status view decodes only what core\'s escaping encodes, and builds no markup with .html(',
        str_contains($view, "return String(s === undefined || s === null ? '' : s).replace(/&lt;/g, '<')"
            . ".replace(/&gt;/g, '>').replace(/&amp;/g, '&');")
        && !str_contains($view, '.html('));
    uu_check($t, 'the installed status view sets each refusal and note as text on its own line, not joined into one',
        str_contains($view, "box.append($('<div/>').text(n));") && !str_contains($view, 'notes.join('));

    /* (l5) the per-member resolvers: the dialog's two fields, the grid on the page over the five actions, the member
     * table's Resolver column, and the route row and footprint text for several addresses */
    $dialog = @simplexml_load_file('/usr/local/opnsense/mvc/app/controllers/OPNsense/UnboundUpstream/forms/'
        . 'dialogResolver.xml');
    $fields = [];
    foreach ($dialog === false ? [] : ($dialog->xpath('/form/field') ?: []) as $field) {
        $fields[(string)$field->id] = [(string)$field->type, (string)$field->help];
    }
    uu_check($t, '(l5) the installed dialogResolver.xml names the member\'s gateway (a dropdown) and its address '
        . '(text), with their help',
        $fields === ['resolver.gateway' => ['dropdown', 'The member this resolver is for.'],
                     'resolver.address' => ['text',
                         "The resolver's address inside this member's tunnel. IPv4 or IPv6."]]);
    $index = (string)@file_get_contents('/usr/local/opnsense/mvc/app/controllers/OPNsense/UnboundUpstream/'
        . 'IndexController.php');
    $members = preg_match('~<table[^>]*id="unboundupstream-members".*?</thead>~s', $view, $m) === 1 ? $m[0] : '';
    uu_check($t, '(l5) the installed view has the grid-resolvers grid under its heading, over the five resolver '
        . 'actions, with the dialog the page controller supplies',
        str_contains($view, '<table id="grid-resolvers" class="table table-condensed table-hover table-striped"'
            . "\n                   data-editDialog=\"DialogResolver\">")
        && str_contains($view, "{{ lang._('Per-member resolvers') }}")
        && str_contains($view, "$('#grid-resolvers').UIBootgrid({\n"
            . "            search: '/api/unboundupstream/settings/search_resolver',\n"
            . "            get: '/api/unboundupstream/settings/get_resolver/',\n"
            . "            set: '/api/unboundupstream/settings/set_resolver/',\n"
            . "            add: '/api/unboundupstream/settings/add_resolver/',\n"
            . "            del: '/api/unboundupstream/settings/del_resolver/'\n")
        && str_contains($view, "{{ partial('layout_partials/base_dialog', ['fields': resolverForm, 'id': "
            . "'DialogResolver',")
        && str_contains($index, "\$this->view->resolverForm = \$this->getForm('dialogResolver');"));
    uu_check($t, '(l5) the member table has the Resolver column after Tier, each member\'s resolver set as text, and '
        . 'the view still builds no markup with .html(',
        str_contains($members, "<th>{{ lang._('Tier') }}</th>\n                <th>{{ lang._('Resolver') }}</th>")
        && str_contains($view, ".append($('<td/>').text(m.tier))\n                        "
            . ".append($('<td/>').text(plain(m.resolver)))")
        && !str_contains($view, '.html('));
    uu_check($t, '(l5) with at most one address the route row and the footprint text are 1.3_2\'s, from route and '
        . 'footprint; with more, a row per address and the footprints joined with ", "',
        substr_count($view, 'if ((data.addresses || []).length <= 1) {') === 2
        && str_contains($view, "body.append(row(\"{{ lang._('Resolver route') }}\", routeText(route)));")
        && str_contains($view, "body.append(row(\"{{ lang._('Resolver route') }} (\" + plain(addr) + ')', "
            . 'routeText(r)));')
        && str_contains($view, 'footprints = data.footprint ? [data.footprint] : [];')
        && str_contains($view, "if (entry.footprint) {\n                        footprints.push(addr);")
        && str_contains($view, "plain(footprints.join(', '))"));
    uu_check($t, '(l5) a row the grid saves or deletes is applied at once through the reconfigure Apply runs, and the '
        . 'page says so',
        str_contains($view, "\$(document).on('settings-changed', function () {\n"
            . "            ajaxCall('/api/unboundupstream/service/reconfigure', {}, function (data, status) {")
        && str_contains($view, "{{ lang._('A row takes effect once saved or deleted. The settings above still need "
            . "Apply.') }}"));
    $inc = '/usr/local/etc/inc/plugins.inc.d/unboundupstream.inc';
    uu_check($t, 'the hook file is installed (overlay the tree first)', is_readable($inc));
    if (!is_readable($inc)) {
        return uu_tally_report('wiring', $t);
    }
    require_once 'config.inc';
    require_once 'util.inc';
    require_once 'plugins.inc';
    require_once '/usr/local/opnsense/mvc/script/load_phalcon.php';
    require_once $inc;

    $hooks = unboundupstream_configure();
    ksort($hooks);
    uu_check($t, 'configure registers the hooks Unbound uses and the monitor hook with two arguments',
        $hooks === ['bootup' => ['unboundupstream_queue'], 'dns' => ['unboundupstream_queue'],
            'local' => ['unboundupstream_queue'], 'monitor' => ['unboundupstream_queue_monitor:2'],
            'newwanip' => ['unboundupstream_queue'], 'unbound_start' => ['unboundupstream_queue']]);
    uu_check($t, 'syslog registers the plugin log under its own program name',
        unboundupstream_syslog() === ['unboundupstream' => ['facility' => [UU_SYSLOG_IDENT]]]);

    /* the menu: the settings page right after Query Forwarding, the log right after Unbound's own Log File */
    $menu = uu_test_unbound_menu('/usr/local/opnsense/mvc/app/models/OPNsense/Unbound/Menu/Menu.xml')
        + uu_test_unbound_menu('/usr/local/opnsense/mvc/app/models/OPNsense/UnboundUpstream/Menu/Menu.xml');
    asort($menu);
    $names = array_keys($menu);
    $after = fn (string $name): ?string => ($i = array_search($name, $names, true)) === false ? null
        : ($names[$i + 1] ?? null);
    uu_check($t, 'menu: Upstream via Gateway follows Query Forwarding and its log follows Log File, no order shared',
        $after('Forward') === 'UnboundUpstream' && $after('LogFile') === 'UnboundUpstreamLog'
        && count(array_unique($menu)) === count($menu));

    /* The status privilege reads the state and nothing else; the page privilege keeps everything */
    $aclXml = simplexml_load_file('/usr/local/opnsense/mvc/app/models/OPNsense/UnboundUpstream/ACL/ACL.xml');
    $patterns = function (string $priv) use ($aclXml): array {
        return $aclXml === false ? [] : array_map('strval', $aclXml->xpath("/acl/{$priv}/patterns/pattern") ?: []);
    };
    $acl = new \OPNsense\Core\ACL();
    $allows = function (string $priv, string $url) use ($acl, $patterns): bool {
        foreach ($patterns($priv) as $mask) {
            if ($acl->urlMatch($url, $mask)) {
                return true;
            }
        }
        return false;
    };
    $writes = ['/api/unboundupstream/service/stop', '/api/unboundupstream/service/start',
        '/api/unboundupstream/service/reconfigure', '/api/unboundupstream/service/status',
        '/api/unboundupstream/settings/set', '/api/unboundupstream/settings/get', '/ui/unboundupstream',
        '/api/diagnostics/log/core/unboundupstream', '/api/unboundupstream/settings/search_resolver',
        '/api/unboundupstream/settings/get_resolver', '/api/unboundupstream/settings/add_resolver',
        '/api/unboundupstream/settings/set_resolver', '/api/unboundupstream/settings/del_resolver'];
    uu_check($t, 'ACL: the status privilege allows service/state and none of the other plugin endpoints',
        $allows('page-status-unboundupstream', '/api/unboundupstream/service/state')
        && array_filter($writes, fn (string $u): bool => $allows('page-status-unboundupstream', $u)) === []);
    uu_check($t, 'ACL: the page privilege still allows the state and every other plugin endpoint',
        $allows('page-services-unboundupstream', '/api/unboundupstream/service/state')
        && array_filter($writes, fn (string $u): bool => !$allows('page-services-unboundupstream', $u)) === []);

    /* (l5) the five resolver actions, run as the API runs them over rows added to the controller's model in memory
     * only, with the controller's save counted instead of run (the controller's own validation and actions, only save()
     * replaced), so no case and no broken action writes config.xml: search lists a row with its member's name, get
     * reads it, add and set refuse what fails validation, del finds no row by an unknown id. Then, with the plugin
     * enabled on proton_test_grp in memory, every row change is checked against the whole model as a Save is: a
     * non-member's row, a second row for one gateway (the message lands on the other row) and a delete that leaves a
     * member with no resolver are refused unsaved; a member's row and a delete that leaves the model valid are saved.
     * A copy of config.xml is taken first: should anything write it all the same, the copy is put back, core's Config
     * reloads it, and the guard case fails */
    $ctl = null;
    $config = '/conf/config.xml';
    $configBefore = md5_file($config);
    $configCopy = sys_get_temp_dir() . '/uu_wiring_config_' . bin2hex(random_bytes(6)) . '.xml';
    $copied = copy($config, $configCopy);
    $configChanged = null;
    $saved = ['server' => $_SERVER, 'post' => $_POST, 'request' => $_REQUEST];
    $controller = fn (): object => new class extends \OPNsense\UnboundUpstream\Api\SettingsController {
        public int $saves = 0;

        protected function save($validateFullModel = false, $disable_validation = false)
        {
            $this->saves++;
            return ['result' => 'saved'];
        }
    };
    $model = fn (object $c): object => (new ReflectionMethod($c, 'getModel'))->invoke($c);
    $addRow = function (object $c, string $gateway) use ($model): string {
        $node = $model($c)->resolvers->resolver->Add();
        $node->setNodes(['gateway' => $gateway, 'address' => '10.2.0.1']);
        return (string)$node->getAttribute('uuid');
    };
    /* a POST of $post to $call, the config lock released after it as the end of a request releases it */
    $post = function (array $post, callable $call): mixed {
        $_SERVER['REQUEST_METHOD'] = 'POST';
        $_POST = $post;
        $_REQUEST = $post;
        try {
            return $call();
        } catch (\OPNsense\Base\UserException $e) {
            return ['refused' => $e->getMessage()];
        } finally {
            \OPNsense\Core\Config::getInstance()->unlock();
            $_POST = [];
            $_REQUEST = [];
        }
    };
    try {
        $c = $controller();
        $c->request = new \OPNsense\Mvc\Request();
        $_SERVER['REQUEST_METHOD'] = 'GET';
        $_POST = [];
        $_REQUEST = [];
        $gwUuid = '';
        $gwName = '';
        foreach ((new \OPNsense\Routing\Gateways())->gateway_item->iterateItems() as $key => $gw) {
            $gwUuid = (string)$key;
            $gwName = $gw->name->getValue();
            break;
        }
        $node = $model($c)->resolvers->resolver->Add();
        $node->setNodes(['gateway' => $gwUuid, 'address' => '192.0.2.10']);
        $row = (string)$node->getAttribute('uuid');
        $cn = $controller();
        $cn->request = $c->request;
        $ctl = ['row' => $row, 'gateway' => $gwUuid, 'name' => $gwName, 'search' => $c->searchResolverAction(),
                'get' => $c->getResolverAction($row), 'new' => $cn->getResolverAction()];
        /* the grid's search box finds a row by its member's name and by its address */
        foreach (['byName' => $gwName, 'byAddress' => '192.0.2.10', 'byNothing' => '198.51.100.99'] as $k => $phrase) {
            $_REQUEST = ['searchPhrase' => $phrase];
            $ctl[$k] = array_column($c->searchResolverAction()['rows'], 'uuid');
        }
        $_REQUEST = [];
        /* each request on its own controller, as the web server runs them: a new row's fields (get with no id) and a
         * refused add leave their row in the model of the request that made it */
        $ca = $controller();
        $ca->request = $c->request;
        $ctl['add'] = $post(['resolver' => ['gateway' => '', 'address' => 'not an address']],
            fn (): array => $ca->addResolverAction());
        $ctl['set'] = $post(['resolver' => ['address' => 'not an address']],
            fn (): array => $c->setResolverAction($row));
        $cd = $controller();
        $cd->request = $c->request;
        $ctl['del'] = $post([], fn (): array => $cd->delResolverAction('00000000-0000-4000-8000-000000000000'));
        $ctl['saves'] = $c->saves + $ca->saves + $cd->saves;

        /* the group's members and a gateway that is none */
        $groupUuid = '';
        $memberNames = [];
        foreach ((new \OPNsense\Routing\GatewayGroups())->gateway_group->iterateItems() as $key => $g) {
            if ($g->name->getValue() === 'proton_test_grp') {
                $groupUuid = (string)$key;
                foreach (['item', 'item2', 'item3', 'item4', 'item5'] as $tier) {
                    foreach (explode(',', $g->$tier->getValue()) as $entry) {
                        $memberNames[] = explode('|', $entry)[0];
                    }
                }
            }
        }
        $byName = [];
        foreach ((new \OPNsense\Routing\Gateways())->gateway_item->iterateItems() as $key => $gw) {
            $byName[$gw->name->getValue()] = (string)$key;
        }
        $outsider = (string)(array_values(array_diff(array_keys($byName), $memberNames))[0] ?? '');
        $enabled = function (string $default) use ($controller, $model, $groupUuid): object {
            $e = $controller();
            $e->request = new \OPNsense\Mvc\Request();
            $m = $model($e);
            $m->enabled->setValue('1');
            $m->gateway_group->setValue($groupUuid);
            $m->resolver->setValue($default);
            return $e;
        };
        $a = $byName['wg-test-429'] ?? '';
        $b = $byName['wg-test-529'] ?? '';
        $ctl['outsider'] = $outsider;
        $e1 = $enabled('10.2.0.1');
        $ctl['nonMember'] = [$post(['resolver' => ['gateway' => $byName[$outsider] ?? '', 'address' => '10.2.0.1']],
            fn (): array => $e1->addResolverAction()), $e1->saves];
        $e2 = $enabled('10.2.0.1');
        $ctl['member'] = [$post(['resolver' => ['gateway' => $a, 'address' => '10.2.0.1']],
            fn (): array => $e2->addResolverAction()), $e2->saves];
        $e3 = $enabled('10.2.0.1');
        $r1 = $addRow($e3, $a);
        $addRow($e3, $b);
        $ctl['second'] = [$post(['resolver' => ['gateway' => $b]], fn (): array => $e3->setResolverAction($r1)),
            $e3->saves];
        $e4 = $enabled('');
        $r4 = $addRow($e4, $a);
        $addRow($e4, $b);
        $ctl['noResolver'] = [$post([], fn (): array => $e4->delResolverAction($r4)), $e4->saves];
        $e5 = $enabled('10.2.0.1');
        $r5 = $addRow($e5, $a);
        $ctl['delete'] = [$post([], fn (): array => $e5->delResolverAction($r5)), $e5->saves];
    } catch (\Throwable $e) {
        printf("  threw %s: %s\n", get_class($e), $e->getMessage());
        \OPNsense\Core\Config::getInstance()->unlock();
    } finally {
        $_SERVER = $saved['server'];
        $_POST = $saved['post'];
        $_REQUEST = $saved['request'];
        $configChanged = md5_file($config) !== $configBefore;
        if ($configChanged && $copied) {
            $plugin = @simplexml_load_file($config);
            printf("  config.xml was written during the resolver actions; its plugin settings were %s; putting the "
                . "copy back\n", preg_replace('/\s+/', ' ', (string)($plugin === false ? 'unreadable'
                    : $plugin->OPNsense->UnboundUpstream->asXML())));
            if (!copy($configCopy, $config)) {
                printf("  the copy %s could not be put back\n", $configCopy);
            }
            \OPNsense\Core\Config::getInstance()->forceReload();
        }
        if ($copied && md5_file($config) === $configBefore) {
            unlink($configCopy);
        }
    }
    uu_check($t, '(l5) config.xml was not written by the resolver actions (a copy is put back when it was)',
        $copied && $configChanged === false);
    $gwOption = $ctl['get']['resolver']['gateway'][$ctl['gateway'] ?? ''] ?? null;
    uu_check($t, '(l5) search_resolver lists the row with its member\'s name and address and searches both; '
        . 'get_resolver reads it, and with no id a new row\'s fields',
        $ctl !== null && $ctl['gateway'] !== ''
        && ($ctl['search']['rows'] ?? null) === [['uuid' => $ctl['row'], 'gateway' => $ctl['gateway'],
            '%gateway' => $ctl['name'], 'address' => '192.0.2.10']]
        && $ctl['byName'] === [$ctl['row']] && $ctl['byAddress'] === [$ctl['row']] && $ctl['byNothing'] === []
        && $gwOption === ['value' => $ctl['name'], 'selected' => 1]
        && ($ctl['get']['resolver']['address'] ?? null) === '192.0.2.10'
        && array_keys($ctl['new']['resolver'] ?? []) === ['gateway', 'address']
        && ($ctl['new']['resolver']['address'] ?? null) === '');
    $refused = $ctl !== null
        && ($ctl['add']['result'] ?? null) === 'failed'
        && array_keys($ctl['add']['validations'] ?? []) === ['resolver.gateway', 'resolver.address']
        && ($ctl['set'] ?? null) === ['result' => 'failed',
            'validations' => ['resolver.address' => 'Enter a single IPv4 or IPv6 address.']]
        && ($ctl['del'] ?? null) === ['result' => 'not found'] && ($ctl['saves'] ?? null) === 0;
    if ($ctl !== null && !$refused) {
        printf("  add %s, set %s, del %s, saves %s\n", json_encode($ctl['add'] ?? null),
            json_encode($ctl['set'] ?? null), json_encode($ctl['del'] ?? null), json_encode($ctl['saves'] ?? null));
    }
    uu_check($t, '(l5) add_resolver and set_resolver refuse a row that fails validation, naming its fields; '
        . 'del_resolver finds no row by an unknown id; nothing is saved', $refused);
    $outsider = $ctl['outsider'] ?? '';
    $nonMember = $outsider !== ''
        && ($ctl['nonMember'] ?? null) === [['result' => 'failed', 'validations' => ['resolver.gateway' =>
            'Gateway ' . $outsider . ' is not a member of the selected group.']], 0]
        && ($ctl['member'][0]['result'] ?? null) === 'saved' && ($ctl['member'][1] ?? null) === 1;
    $wholeModel = ($ctl['second'] ?? null) === [['result' => 'failed', 'validations' => ['resolver.gateway' =>
            'Gateway wg-test-529 has more than one resolver row.']], 0]
        && ($ctl['noResolver'] ?? null) === [['refused' =>
            'Enter the default resolver address, or one for every member of the group.'], 0]
        && ($ctl['delete'] ?? null) === [['result' => 'deleted'], 1]
        && $configChanged === false;
    if ($ctl !== null && (!$nonMember || !$wholeModel)) {
        foreach (['nonMember', 'member', 'second', 'noResolver', 'delete'] as $k) {
            printf("  %s: %s\n", $k, json_encode($ctl[$k] ?? null));
        }
    }
    uu_check($t, '(l5) enabled: a grid add of a non-member\'s row is refused on its gateway, as a Save refuses it, and '
        . 'nothing is saved; a member\'s row is saved', $nonMember);
    uu_check($t, '(l5) enabled: a row changed to another row\'s gateway is refused (the message is the other row\'s, '
        . 'shown on this one\'s gateway), and a delete that leaves a member with no resolver is refused; neither is '
        . 'saved, while a delete that leaves the model valid is; config.xml is unchanged', $wholeModel);

    /* program() is an unanchored regex, and core's resolver log filter is program("unbound") */
    $conf = '/usr/local/etc/syslog-ng.conf.d/syslog-ng-local.conf';
    $filters = uu_test_program_filters(is_readable($conf) ? (string)file_get_contents($conf) : '');
    $selects = fn (string $pattern): bool => preg_match('~' . str_replace('~', '\~', $pattern) . '~', UU_SYSLOG_IDENT) === 1;
    $others = [];
    foreach ($filters as $name => $patterns) {
        foreach ($patterns as $pattern) {
            if ($name !== 'f_local_unboundupstream' && $selects($pattern)) {
                $others[] = "{$name} program(\"{$pattern}\")";
            }
        }
    }
    uu_check($t, 'only the plugin\'s own log filter selects its program name' . ($others === [] ? '' : ' (also: ' . implode(', ', $others) . ')'),
        in_array(true, array_map($selects, $filters['f_local_unboundupstream'] ?? []), true) && $others === []);

    $mark = 'uu-wiring-' . bin2hex(random_bytes(4));
    uu_log("{$mark} from evaluate");
    uu_logger("{$mark} from a hook");
    $deadline = hrtime(true) + 5000000000;
    while (substr_count(uu_test_log_dir('unboundupstream'), $mark) < 2 && hrtime(true) < $deadline) {
        usleep(200000);
    }
    uu_check($t, 'both log paths (openlog in evaluate, logger in hooks) reach the plugin log and not the resolver log',
        substr_count(uu_test_log_dir('unboundupstream'), $mark) === 2 && !str_contains(uu_test_log_dir('resolver'), $mark));
    uu_check($t, 'the hook file cleans what it logs with the same function as the scripts',
        uu_try_case(fn (): bool => unboundupstream_clean("a\x1bb\nc") === 'a?b; c'
            && unboundupstream_clean('plain') === 'plain'));
    /* A php whose open_basedir admits only core's inc directory loads the hook file but cannot read
     * lib/logline.php, as when the library is missing: the hook's own prefix stays, only the message is withheld */
    $code = 'require "' . $inc . '"; echo unboundupstream_error_line("cron: cannot read the settings: ", '
        . '"secret\nsecond line"), PHP_EOL, unboundupstream_error_line("render hook failed: ", "a\x1bb"), PHP_EOL;';
    $out = (string)shell_exec('/usr/local/bin/php -d log_errors=0 -d display_errors=0 -d open_basedir='
        . escapeshellarg(dirname($inc)) . ' -r ' . escapeshellarg($code));
    $withheld = 'message withheld, the plugin library is missing';
    if ($out !== "cron: cannot read the settings: $withheld\nrender hook failed: $withheld\n") {
        printf("  without the library: %s\n", preg_replace('/[^\x20-\x7e]/', '?', substr($out, 0, 400)));
    }
    uu_check($t, 'without the plugin library a hook\'s error line keeps its prefix and withholds only the message',
        $out === "cron: cannot read the settings: $withheld\nrender hook failed: $withheld\n");
    uu_check($t, 'with the library the error line is the prefix and the cleaned message',
        uu_try_case(fn (): bool => unboundupstream_error_line('cron: cannot read the settings: ', "a\x1bb\nc")
            === 'cron: cannot read the settings: a?b; c'));
    uu_check($t, 'cron is empty while the plugin is disabled', unboundupstream_cron() === []);
    uu_check($t, 'services is empty while the plugin is disabled', unboundupstream_services() === []);

    /* (r9) core lists the automatic rules from the web server's process, which cannot search the root-only run
     * directory: there the state reads as missing, with no problem, so the render's footprint read has nothing to log
     * and the listing shows the setting's rules only */
    $aside = UU_STATE_PATH . '.r9';
    $had = file_exists(UU_STATE_PATH);
    $saved = $had ? (string)file_get_contents(UU_STATE_PATH) : null;
    $r9 = null;
    try {
        uu_run_dir();
        uu_test_state_aside(UU_STATE_PATH, $aside, function (callable $place) use (&$r9): void {
            $recorded = uu_state_new();
            $recorded['addresses'] = ['192.0.2.1' => ['route' => null, 'forwarded' => false, 'released_at' => null]];
            $place($recorded);
            /* one line per read, so a php that dies on the second still shows the first */
            $code = 'require "/usr/local/opnsense/scripts/OPNsense/UnboundUpstream/lib/render.php"; '
                . 'echo json_encode(uu_state_read(UU_STATE_PATH)), PHP_EOL; '
                . 'echo json_encode(uu_wanted_from(fn () => ["default" => "", "rows" => [], "gateways" => null], '
                . 'fn () => [], '
                . 'UU_STATE_PATH)), PHP_EOL;';
            $out = (string)shell_exec('/usr/bin/su -m nobody -c '
                . escapeshellarg('/usr/local/bin/php -d log_errors=0 -r ' . escapeshellarg($code)) . ' 2>&1');
            $lines = explode("\n", $out);
            $r9 = ['root' => uu_state_read(UU_STATE_PATH), 'out' => $out,
                   'nobody' => [json_decode($lines[0], true), json_decode($lines[1] ?? '', true)]];
            $r9['root_wanted'] = uu_wanted_from(fn (): array => ['default' => '', 'rows' => [], 'gateways' => null],
                fn (): array => [], UU_STATE_PATH);
        }, 'rename');
    } catch (\Throwable $e) {
        printf("  threw %s: %s\n", get_class($e), $e->getMessage());
    }
    $fresh = json_decode((string)json_encode(uu_state_new()), true);
    $nobody = $r9['nobody'] ?? [null, null];
    if ($r9 !== null && (!is_array($nobody[0]) || !is_array($nobody[1]))) {
        printf("  as nobody: %s\n", preg_replace('/[^\x20-\x7e]/', '?', substr($r9['out'], 0, 400)));
    }
    uu_check($t, '(r9) as nobody, a state recording a footprint reads as missing: a fresh state and no problem '
        . '(root reads its footprint)',
        array_keys($r9['root']['state']['addresses'] ?? []) === ['192.0.2.1']
        && array_key_exists('problem', $r9['root']) && $r9['root']['problem'] === null
        && is_array($nobody[0]) && array_key_exists('problem', $nobody[0]) && $nobody[0]['problem'] === null
        && ($nobody[0]['state'] ?? null) === $fresh);
    uu_check($t, '(r9) as nobody, the render\'s footprint read gives no footprint and nothing to log; as root, the '
        . 'footprint',
        is_array($nobody[1]) && array_key_exists('footprints', $nobody[1]) && $nobody[1]['footprints'] === []
        && array_key_exists('footprint_problem', $nobody[1]) && $nobody[1]['footprint_problem'] === null
        && ($r9['root_wanted']['footprints'] ?? null) === [['resolver' => '192.0.2.1', 'interface' => '']]);
    uu_check($t, '(r9) the saved state is back as it was', file_exists(UU_STATE_PATH) === $had && !file_exists($aside)
        && ($had ? (string)file_get_contents(UU_STATE_PATH) : null) === $saved);

    /* The state set aside is put back exactly, and a move aside that fails runs nothing and touches nothing */
    $savedState = uu_state_new();
    $savedState['addresses'] = ['192.0.2.7' => ['route' => null, 'forwarded' => false, 'released_at' => null]];
    $mine = uu_state_new();
    $mine['addresses'] = ['192.0.2.1' => ['route' => null, 'forwarded' => false, 'released_at' => null]];
    uu_check($t, 'a move aside that fails: nothing runs, the saved state stays as it was, no aside file',
        uu_scratch_case(function (string $dir) use ($savedState, $mine): bool {
            $path = $dir . '/state.json';
            uu_state_save($path, $savedState);
            $ran = false;
            uu_test_state_aside($path, $path . '.aside', function (callable $place) use (&$ran, $mine): void {
                $ran = true;
                $place($mine);
            }, fn (string $from, string $to): bool => false);
            return !$ran && uu_state_read($path)['state'] === $savedState && !file_exists($path . '.aside');
        }));
    uu_check($t, 'a body that writes its state and throws: the saved state is back, no aside file',
        uu_scratch_case(function (string $dir) use ($savedState, $mine): bool {
            $path = $dir . '/state.json';
            uu_state_save($path, $savedState);
            uu_test_state_aside($path, $path . '.aside', function (callable $place) use ($mine): void {
                $place($mine);
                throw new RuntimeException('test: the body throws');
            }, 'rename');
            return uu_state_read($path)['state'] === $savedState && !file_exists($path . '.aside');
        }));
    uu_check($t, 'no saved state: the body\'s state is removed, nothing is left',
        uu_scratch_case(function (string $dir) use ($mine): bool {
            $path = $dir . '/state.json';
            uu_test_state_aside($path, $path . '.aside', function (callable $place) use ($mine): void {
                $place($mine);
            }, 'rename');
            return !file_exists($path) && !file_exists($path . '.aside');
        }));

    $files = array_map('strval', array_keys(plugins_scan()));
    $unbound = array_search('unbound', $files, true);
    $ours = array_search('unboundupstream', $files, true);
    uu_check($t, 'plugins_scan lists unbound.inc before unboundupstream.inc',
        $unbound !== false && $ours !== false && $unbound < $ours);

    $status = trim((string)shell_exec('/usr/local/sbin/configctl unboundupstream status'));
    uu_check($t, 'configctl status answers with the line the service base class reads (plugin disabled)',
        $status === 'unboundupstream is not running');
    /* Start and stop regenerate cron, so a minute job left behind goes even while disabled */
    $job = '/usr/local/sbin/configctl unboundupstream evaluate';
    $tab = (string)shell_exec('/usr/bin/crontab -l 2>/dev/null');
    $stale = tempnam('/tmp', 'uu_cron');
    if ($stale === false || file_put_contents($stale, $tab . "* * * * * $job\n") === false) {
        uu_check($t, 'a temporary crontab for the stale-job check', false);
        return uu_tally_report('wiring', $t);
    }
    shell_exec('/usr/bin/crontab ' . escapeshellarg($stale));
    unlink($stale);
    $running = trim((string)shell_exec('/usr/local/sbin/configctl unboundupstream status'));
    shell_exec('/usr/local/sbin/configctl unboundupstream stop > /dev/null');
    uu_check($t, 'status reads the minute job, and stop removes a stale one (plugin disabled)',
        $running === 'unboundupstream is running'
        && !str_contains((string)shell_exec('/usr/bin/crontab -l 2>/dev/null'), $job)
        && trim((string)shell_exec('/usr/local/sbin/configctl unboundupstream status')) === 'unboundupstream is not running');

    /* (e2) with the plugin disabled, a state recording a footprint keeps the minute job, so a stop that
     * could not restore is retried; without one the job goes. The evaluate lock is held throughout and the minute's
     * tick is at least 20 s away, so no evaluation reads or replaces the hand-written state and no tick of the job
     * runs; the saved state, the crontab and cron's running state are put back as found */
    $e2 = null;
    $e2Aside = UU_STATE_PATH . '.e2';
    $e2Had = file_exists(UU_STATE_PATH);
    $e2Saved = $e2Had ? (string)file_get_contents(UU_STATE_PATH) : null;
    $e2Tab = (string)shell_exec('/usr/bin/crontab -l 2>/dev/null');
    $e2Cron = uu_test_cron_running();
    $e2Lock = false;
    try {
        uu_run_dir();
        $e2Lock = uu_test_evaluate_lock();
        if ($e2Lock === false) {
            throw new RuntimeException('an evaluation held the evaluate lock for 60 s');
        }
        if (!uu_test_clear_of_tick(20)) {
            throw new RuntimeException('the minute\'s tick did not move 20 s away within 60 s');
        }
        uu_test_state_aside(UU_STATE_PATH, $e2Aside, function (callable $place) use (&$e2): void {
            $recorded = uu_state_new();
            $recorded['addresses'] = ['192.0.2.1' => ['route' => null, 'forwarded' => false, 'released_at' => null]];
            $place($recorded);
            $e2 = ['cron_with' => unboundupstream_cron()];
            shell_exec('/usr/local/sbin/configctl cron restart > /dev/null');
            $e2['status_with'] = trim((string)shell_exec('/usr/local/sbin/configctl unboundupstream status'));
            $e2['tab_with'] = (string)shell_exec('/usr/bin/crontab -l 2>/dev/null');
            unlink(UU_STATE_PATH);
            $e2['cron_without'] = unboundupstream_cron();
            shell_exec('/usr/local/sbin/configctl cron restart > /dev/null');
            $e2['status_without'] = trim((string)shell_exec('/usr/local/sbin/configctl unboundupstream status'));
        }, 'rename');
    } catch (\Throwable $e) {
        printf("  threw %s: %s\n", get_class($e), $e->getMessage());
    } finally {
        if ((string)shell_exec('/usr/bin/crontab -l 2>/dev/null') !== $e2Tab) {
            $found = tempnam('/tmp', 'uu_cron');
            if ($found !== false && file_put_contents($found, $e2Tab) !== false) {
                shell_exec('/usr/bin/crontab ' . escapeshellarg($found));
            }
            if ($found !== false) {
                unlink($found);
            }
        }
        if (uu_test_cron_running() !== $e2Cron) {
            shell_exec('/usr/sbin/service cron ' . ($e2Cron ? 'onestart' : 'onestop') . ' > /dev/null 2>&1');
        }
        if ($e2Lock !== false) {
            fclose($e2Lock);
        }
    }
    $minuteJob = [['autocron' => [$job, '*']]];
    if ($e2 !== null && ($e2['cron_with'] !== $minuteJob || $e2['status_with'] !== 'unboundupstream is running')) {
        printf("  with the footprint: cron %s, status '%s', crontab lines with the job: %d\n",
            json_encode($e2['cron_with']), $e2['status_with'], substr_count($e2['tab_with'], $job));
    }
    uu_check($t, '(e2) disabled, a state recording 192.0.2.1 → unboundupstream_cron() returns the minute job, and after a cron restart status reads running',
        $e2 !== null && $e2['cron_with'] === $minuteJob && $e2['status_with'] === 'unboundupstream is running');
    uu_check($t, '(e2) disabled, the state removed → no job, and after a cron restart status reads not running',
        $e2 !== null && ($e2['cron_without'] ?? null) === []
        && ($e2['status_without'] ?? null) === 'unboundupstream is not running');
    uu_check($t, '(e2) the saved state, the crontab and cron\'s running state are back as found',
        file_exists(UU_STATE_PATH) === $e2Had && !file_exists($e2Aside)
        && ($e2Had ? (string)file_get_contents(UU_STATE_PATH) : null) === $e2Saved
        && (string)shell_exec('/usr/bin/crontab -l 2>/dev/null') === $e2Tab && uu_test_cron_running() === $e2Cron);

    /* (s9) a status poll between the upgrade's post-install and the first tick reads 1.3's version 5 file: it prints
     * what 1.3 printed for it, logs nothing, and leaves the file as it was (bytes and modification time). The evaluate
     * lock is held, so no evaluation replaces the hand-written file; the saved state is put back */
    $s9 = null;
    $s9Aside = UU_STATE_PATH . '.s9';
    $s9Had = file_exists(UU_STATE_PATH);
    $s9Saved = $s9Had ? (string)file_get_contents(UU_STATE_PATH) : null;
    $s9Lock = false;
    $s9Script = '/usr/local/opnsense/scripts/OPNsense/UnboundUpstream/evaluate.php';
    try {
        uu_run_dir();
        $s9Lock = uu_test_evaluate_lock();
        if ($s9Lock === false) {
            throw new RuntimeException('an evaluation held the evaluate lock for 60 s');
        }
        uu_test_state_aside(UU_STATE_PATH, $s9Aside, function (callable $place) use (&$s9, $s9Script): void {
            $v5 = [
                'version' => 5, 'mode' => 'tunnel', 'member' => 'wg-a',
                'timers' => ['wg-a' => ['usable_since' => 1200, 'counted' => 45, 'last_at' => 1245,
                    'resolver_failed_until' => null, 'probe_failures' => 0, 'last_down' => null]],
                'control_failures' => 0, 'control_silent_since' => null,
                'last_switch' => ['at' => 1760000000, 'from' => 'fallback', 'to' => 'wg-a', 'reason' => 'member usable'],
                'checks' => ['direct' => null, 'unbound' => null], 'tls_applied' => false, 'blocked' => null,
                'route_installed' => ['kind' => 'member', 'next_hop' => '10.2.0.4', 'if' => 'wg1'],
                'resolver' => '10.2.0.1',
            ];
            $place($v5);
            /* an old modification time, so a rewrite shows even within the clock's second */
            touch(UU_STATE_PATH, time() - 120);
            clearstatcache(true, UU_STATE_PATH);
            $bytes = (string)file_get_contents(UU_STATE_PATH);
            $mtime = filemtime(UU_STATE_PATH);
            $first = 'uu-wiring-s9a-' . bin2hex(random_bytes(4));
            $last = 'uu-wiring-s9b-' . bin2hex(random_bytes(4));
            $wait = function (string $mark): void {
                $deadline = hrtime(true) + 5000000000;
                while (substr_count(uu_test_log_dir('unboundupstream'), $mark) < 1 && hrtime(true) < $deadline) {
                    usleep(200000);
                }
            };
            uu_log($first);
            $wait($first);
            $docs = [];
            for ($i = 0; $i < 2; $i++) {
                $docs[] = json_decode((string)shell_exec('/usr/local/bin/php -d log_errors=0 ' . $s9Script
                    . ' status'), true);
            }
            uu_log($last);
            $wait($last);
            $lines = explode("\n", uu_test_log_dir('unboundupstream'));
            $at = fn (string $mark): int => (int)key(array_filter($lines, fn (string $l): bool => str_contains($l, $mark)));
            clearstatcache(true, UU_STATE_PATH);
            $s9 = ['docs' => $docs, 'between' => array_slice($lines, $at($first) + 1, $at($last) - $at($first) - 1),
                   'same' => (string)file_get_contents(UU_STATE_PATH) === $bytes && filemtime(UU_STATE_PATH) === $mtime];
        }, 'rename');
    } catch (\Throwable $e) {
        printf("  threw %s: %s\n", get_class($e), $e->getMessage());
    } finally {
        if ($s9Lock !== false) {
            fclose($s9Lock);
        }
    }
    $s9Docs = $s9['docs'] ?? [null, null];
    if ($s9 !== null && $s9['between'] !== []) {
        printf("  plugin log lines between the marks: %s\n", implode(' | ', array_slice($s9['between'], 0, 3)));
    }
    uu_check($t, '(s9) status twice over a version 5 tunnel-mode file prints its mode, member, last switch and footprint, '
        . 'the same both times',
        is_array($s9Docs[0]) && $s9Docs[0] === $s9Docs[1] && $s9Docs[0]['mode'] === 'tunnel'
        && $s9Docs[0]['member'] === 'wg-a' && $s9Docs[0]['footprint'] === '10.2.0.1'
        && $s9Docs[0]['last_switch']['to'] === 'wg-a' && $s9Docs[0]['resolver'] === uu_settings()['default']);
    uu_check($t, '(s9) …without a plugin log line between the marks, and the file\'s bytes and modification time unchanged',
        $s9 !== null && $s9['between'] === [] && $s9['same']);
    uu_check($t, '(s9) the saved state is back as it was', file_exists(UU_STATE_PATH) === $s9Had && !file_exists($s9Aside)
        && ($s9Had ? (string)file_get_contents(UU_STATE_PATH) : null) === $s9Saved);

    $s9Doc = is_array($s9Docs[0]) ? $s9Docs[0] : [];
    $entry = $s9Doc['routes']['10.2.0.1'] ?? null;
    $l6 = ($s9Doc['addresses'] ?? null) === ['10.2.0.1'] && array_keys($s9Doc['routes'] ?? []) === ['10.2.0.1']
        && is_array($entry) && array_keys($entry) === ['present', 'gateway', 'interface', 'reject', 'ours', 'flags',
            'footprint']
        && is_array($entry['flags']) && $entry['footprint'] === true;
    if (!$l6) {
        printf("  resolver %s, addresses %s, route %s, routes %s\n", json_encode($s9Doc['resolver'] ?? null),
            json_encode($s9Doc['addresses'] ?? null), json_encode($s9Doc['route'] ?? null),
            json_encode($s9Doc['routes'] ?? null));
    }
    uu_check($t, '(l6) status over the version 5 file: its one address with its route as the status reads one, a '
        . 'footprint while the plugin is disabled', $l6);

    $state = json_decode(trim((string)shell_exec('/usr/local/sbin/configctl unboundupstream state')), true);
    uu_check($t, 'configctl state returns the status JSON', is_array($state) && isset($state['mode'], $state['members'])
        && $state['enabled'] === false);
    uu_check($t, '(l6) configctl state with the plugin disabled carries routes and addresses, an entry and a route per '
        . 'address the state holds',
        is_array($state) && array_key_exists('routes', $state) && array_key_exists('addresses', $state)
        && is_array($state['routes']) && is_array($state['addresses'])
        && array_keys($state['routes']) === $state['addresses']);

    /* core calls the monitor hook with no arguments at boot (rc.bootup), and plugins_configure clamps the declared
     * two to what it has: the hook must take one argument, or none, without throwing */
    $plain = 'unbound-upstream evaluation ()';
    $before = substr_count(uu_test_configd_log(), $plain);
    $threw = false;
    try {
        unboundupstream_queue_monitor(false);
    } catch (\Throwable $e) {
        $threw = true;
    }
    uu_check($t, 'the monitor hook with one argument does not throw and queues a plain evaluate',
        !$threw && uu_test_wait_configd($plain, $before));
    /* rc.routing_configure's full reload passes null (system_routing_configure: no interface map) */
    $before = substr_count(uu_test_configd_log(), $plain);
    $threw = false;
    try {
        unboundupstream_queue_monitor(false, null);
    } catch (\Throwable $e) {
        $threw = true;
    }
    uu_check($t, 'the monitor hook with null (a full routing reload) does not throw and queues a plain evaluate',
        !$threw && uu_test_wait_configd($plain, $before));
    $named = 'unbound-upstream evaluation (wg-test-429,wg-test-529)';
    $before = substr_count(uu_test_configd_log(), $named);
    unboundupstream_queue_monitor(false, ['wg-test-429', 'wg-test-529']);
    uu_check($t, 'the monitor hook with names passes them to the action as one comma-joined parameter',
        uu_test_wait_configd($named, $before));
    /* pluginctl -c monitor NAMES passes the names as one string */
    $before = substr_count(uu_test_configd_log(), $named);
    unboundupstream_queue_monitor(false, 'wg-test-429,wg-test-529');
    uu_check($t, 'the monitor hook with a comma-separated string (pluginctl -c monitor) passes the same names',
        uu_test_wait_configd($named, $before));

    /* The installed evaluate.php replays a recording made before 1.3 (no contract_input.core_commands)
     * without a PHP warning; the recording is this box's own, written to a scratch directory and removed, and is
     * replayed as enabled, since a disabled plugin's plan stops before it reads the contract */
    $m3 = null;
    $script = '/usr/local/opnsense/scripts/OPNsense/UnboundUpstream/evaluate.php';
    $m3Dir = uu_scratch_dir();
    try {
        $rec = "$m3Dir/recording.json";
        $out = [];
        $rc = 0;
        exec('/usr/local/bin/php -d log_errors=0 ' . $script . ' record ' . escapeshellarg($rec) . ' > /dev/null 2>&1',
            $out, $rc);
        $doc = $rc === 0 ? json_decode((string)file_get_contents($rec), true) : null;
        if (is_array($doc) && is_array($doc['snapshot']['contract_input'] ?? null)) {
            unset($doc['snapshot']['contract_input']['core_commands']);
            $doc['snapshot']['settings']['enabled'] = true;
            file_put_contents($rec, json_encode($doc, JSON_THROW_ON_ERROR));
            exec('/usr/local/bin/php -d log_errors=0 -d display_errors=1 -d error_reporting=-1 ' . $script
                . ' replay ' . escapeshellarg($rec) . ' 2>&1', $out, $rc);
            $m3 = ['rc' => $rc, 'out' => implode("\n", $out)];
        } else {
            printf("  record exited %d and wrote no snapshot\n", $rc);
        }
    } finally {
        uu_scratch_remove($m3Dir);
    }
    $m3Warned = $m3 !== null && preg_match('/\b(Warning|Notice|Deprecated|Fatal error)\b/', $m3['out']) === 1;
    if ($m3 !== null && ($m3['rc'] !== 0 || $m3Warned)) {
        printf("  replay exited %d:\n%s\n", $m3['rc'], $m3['out']);
    }
    uu_check($t, 'evaluate.php replay of a recording without contract_input.core_commands (the shape before 1.3) plans, exits 0 and prints no PHP warning',
        $m3 !== null && $m3['rc'] === 0 && !$m3Warned && str_contains($m3['out'], '"plan"'));

    /* (p17) A recording made before 1.4 (a route and no routes) is refused by name, never planned from: this box's own
     * recording with routes taken out, in a scratch directory that is removed */
    $p17 = null;
    $p17Dir = uu_scratch_dir();
    try {
        $rec = "$p17Dir/recording.json";
        $out = [];
        $rc = 0;
        exec('/usr/local/bin/php -d log_errors=0 ' . $script . ' record ' . escapeshellarg($rec) . ' > /dev/null 2>&1',
            $out, $rc);
        $doc = $rc === 0 ? json_decode((string)file_get_contents($rec), true) : null;
        if (is_array($doc) && is_array($doc['snapshot'] ?? null)) {
            unset($doc['snapshot']['routes'], $doc['snapshot']['family']);
            file_put_contents($rec, json_encode($doc, JSON_THROW_ON_ERROR));
            $out = [];
            exec('/usr/local/bin/php -d log_errors=0 ' . $script . ' replay ' . escapeshellarg($rec) . ' 2>&1',
                $out, $rc);
            $p17 = ['rc' => $rc, 'out' => implode("\n", $out), 'rec' => $rec];
        } else {
            printf("  record exited %d and wrote no snapshot\n", $rc);
        }
    } finally {
        uu_scratch_remove($p17Dir);
    }
    $p17Refused = $p17 !== null && $p17['rc'] !== 0
        && str_contains($p17['out'], $p17['rec'] . ' was recorded before 1.4: record it again')
        && !str_contains($p17['out'], '"plan"');
    if ($p17 !== null && !$p17Refused) {
        printf("  replay exited %d:\n%s\n", $p17['rc'], $p17['out']);
    }
    uu_check($t, '(p17) evaluate.php replay of a recording made before 1.4 (no routes) is refused, naming the file, '
        . 'and plans nothing', $p17Refused);

    /* (p18) record reads the route of every address the saved state holds, beside the effective resolvers: a state
     * holding an address no member uses is placed under the evaluate lock (record takes none, and no evaluation
     * acts on the placed state) and put back */
    $p18 = null;
    $p18Dir = uu_scratch_dir();
    $p18Lock = false;
    try {
        uu_run_dir();
        $p18Lock = uu_test_evaluate_lock();
        if ($p18Lock === false) {
            throw new RuntimeException('an evaluation held the evaluate lock for 60 s');
        }
        uu_test_state_aside(UU_STATE_PATH, UU_STATE_PATH . '.p18',
            function (callable $place) use (&$p18, $p18Dir, $script): void {
                $placed = uu_state_new();
                $placed['addresses'] = ['198.51.100.77' => ['route' => null, 'forwarded' => false,
                                                            'released_at' => null]];
                $place($placed);
                $rec = "$p18Dir/recording.json";
                $out = [];
                $rc = 0;
                exec('/usr/local/bin/php -d log_errors=0 ' . $script . ' record ' . escapeshellarg($rec)
                    . ' > /dev/null 2>&1', $out, $rc);
                $doc = $rc === 0 ? json_decode((string)file_get_contents($rec), true) : null;
                $p18 = is_array($doc) ? $doc : null;
            }, 'rename');
    } catch (\Throwable $e) {
        printf("  threw %s: %s\n", get_class($e), $e->getMessage());
    } finally {
        if ($p18Lock !== false) {
            fclose($p18Lock);
        }
        uu_scratch_remove($p18Dir);
    }
    $p18Routes = $p18['snapshot']['routes'] ?? null;
    if (!is_array($p18Routes) || !array_key_exists('198.51.100.77', $p18Routes)) {
        printf("  recorded routes: %s\n", json_encode($p18Routes));
    }
    uu_check($t, '(p18) evaluate.php record reads the route of an address the saved state holds and no member uses, '
        . 'and records that state',
        is_array($p18Routes) && ($p18Routes['198.51.100.77'] ?? null) === ['present' => false, 'gateway' => '',
            'interface' => '', 'reject' => false, 'ours' => false]
        && array_keys($p18['state']['addresses'] ?? []) === ['198.51.100.77']);

    /* A disabled plugin whose resolver has a member route that no member explains: only the state's record makes
     * that route the plugin's own, so the replay plans its delete. The recording is this box's own, rewritten in a
     * scratch directory and removed. */
    $e5 = null;
    $e5Dir = uu_scratch_dir();
    try {
        $rec = "$e5Dir/recording.json";
        $out = [];
        $rc = 0;
        exec('/usr/local/bin/php -d log_errors=0 ' . $script . ' record ' . escapeshellarg($rec) . ' > /dev/null 2>&1',
            $out, $rc);
        $doc = $rc === 0 ? json_decode((string)file_get_contents($rec), true) : null;
        if (is_array($doc) && is_array($doc['snapshot'] ?? null)) {
            $hop = ['kind' => 'member', 'next_hop' => '198.51.100.9', 'if' => 'wg9'];
            $doc['snapshot']['settings']['enabled'] = false;
            $doc['snapshot']['settings']['default'] = '192.0.2.1';
            $doc['snapshot']['settings']['rows'] = [];
            $doc['snapshot']['stop'] = null;
            $doc['snapshot']['members'] = [];
            $doc['snapshot']['tiers'] = [];
            $doc['snapshot']['unbound'] = ['enabled' => true, 'pid_alive' => true, 'control_ok' => true,
                'live_root' => ['192.0.2.53']];
            $doc['snapshot']['routes'] = ['192.0.2.1' => ['present' => true, 'gateway' => '198.51.100.9',
                'interface' => 'wg9', 'reject' => false, 'ours' => false]];
            $doc['state'] = ['version' => 6, 'mode' => 'fallback', 'member' => null, 'timers' => [],
                'control_failures' => 0, 'control_silent_since' => null, 'last_switch' => null,
                'checks' => ['direct' => null, 'unbound' => null], 'tls_applied' => null, 'blocked' => null,
                'addresses' => ['192.0.2.1' => ['route' => $hop, 'forwarded' => false, 'released_at' => null]]];
            file_put_contents($rec, json_encode($doc, JSON_THROW_ON_ERROR));
            $out = [];
            exec('/usr/local/bin/php -d log_errors=0 ' . $script . ' replay ' . escapeshellarg($rec) . ' 2>&1',
                $out, $rc);
            $e5 = ['rc' => $rc, 'out' => implode("\n", $out)];
        } else {
            printf("  record exited %d and wrote no snapshot\n", $rc);
        }
    } finally {
        uu_scratch_remove($e5Dir);
    }
    if ($e5 !== null && !str_contains($e5['out'], '[dry] would run: route -n delete -inet -host 192.0.2.1')) {
        printf("  replay exited %d:\n%s\n", $e5['rc'], $e5['out']);
    }
    uu_check($t, 'replay: a member route that only the state\'s record explains is the plugin\'s: a disabled '
        . 'plugin\'s replay plans its reject, drain and delete',
        $e5 !== null && $e5['rc'] === 0
        && str_contains($e5['out'], '[dry] would run: route -n delete -inet -host 192.0.2.1'));

    /* (c7) core rewrites unbound.conf in place while the unbound_start hook's evaluation reads it, and empties and
     * refills the custom option directory (/var/unbound/etc) at every start. A read in the gap sees an empty or short
     * file or a file that is gone, never an unreadable configuration (the units pin those). Here the expanded read,
     * the snapshot's, runs continuously across 8 real restarts: the inode never changes, reads fall before and after
     * the first rewrite's mtime, none is unreadable or refuses, the host Unbound (by its pid file, not the far end's
     * jail) runs again after each, and the restarts' evaluations are done before the case ends */
    $conf = '/var/unbound/unbound.conf';
    $pidFile = '/var/run/unbound.pid';
    clearstatcache(true, $conf);
    $mtime = (int)filemtime($conf);
    $inode = (int)fileinode($conf);
    $evaluations = uu_test_evaluations();
    $unreadable = 0;
    $reads = 0;
    $wrong = [];
    $sides = ['before' => 0, 'after' => 0];
    $restarted = 0;
    $evaluated = false;
    $runningAtEnd = false;
    try {
        uu_try_case(function () use ($conf, $mtime, $pidFile, $evaluations, &$unreadable, &$reads, &$wrong, &$sides,
                                     &$restarted, &$evaluated, &$runningAtEnd): bool {
            for ($round = 0; $round < 8; $round++) {
                $pidBefore = (string)@file_get_contents($pidFile);
                shell_exec('/usr/local/sbin/configctl unbound restart > /dev/null 2>&1 &');
                $up = false;
                for ($i = 0; $i < 600 && (!$up || $i < 10); $i++) {
                    clearstatcache(true, $conf);
                    if ($round === 0) {
                        $sides[(int)filemtime($conf) === $mtime ? 'before' : 'after']++;
                    }
                    $text = uu_conf_expanded_text();
                    $reads++;
                    if ($text === null) {
                        $unreadable++;
                    } else {
                        $facts = uu_unbound_conf_facts($text);
                        if (!$facts['do_ip4'] || $facts['outgoing_interface']) {
                            $wrong[] = $facts;
                        }
                    }
                    usleep(50000);
                    $now = (string)@file_get_contents($pidFile);
                    $up = $now !== '' && $now !== $pidBefore && isvalidpid($pidFile);
                }
                if (!$up) {
                    return false;
                }
                $restarted++;
            }
            $last = -1;
            for ($deadline = hrtime(true) + 90000000000; hrtime(true) < $deadline; usleep(3000000)) {
                $count = uu_test_evaluations();
                if ($count > $evaluations && $count === $last) {
                    $evaluated = true;
                    break;
                }
                $last = $count;
            }
            $runningAtEnd = isvalidpid($pidFile);
            return true;
        });
    } finally {
        if (!isvalidpid($pidFile)) {
            shell_exec('/usr/local/sbin/configctl unbound start > /dev/null 2>&1');
        }
    }
    clearstatcache(true, $conf);
    printf("  c7: %d restarts, %d reads, %d unreadable, %d wrong, reads before/after the first rewrite %d/%d, "
        . "inode %s\n", $restarted, $reads, $unreadable, count($wrong), $sides['before'], $sides['after'],
        (int)fileinode($conf) === $inode ? 'kept' : 'CHANGED');
    uu_check($t, '(c7) the expanded read of the configuration across 8 Unbound restarts: never unreadable, never '
        . 'do-ip4 off or an outgoing interface, on both sides of the first rewrite, the inode kept, and the host '
        . 'Unbound runs again after each with the restarts\' evaluations done',
        $restarted === 8 && $unreadable === 0 && $wrong === [] && $sides['before'] > 0 && $sides['after'] > 0
        && (int)fileinode($conf) === $inode && (int)filemtime($conf) !== $mtime && $runningAtEnd
        && $evaluated);

    /* (c6) the snapshot reads the expanded configuration: with a custom option file saying do-ip6: no, an IPv6 group
     * is refused by the text, which unbound.conf alone does not say. Core empties the directory at every start, and
     * the file is removed again here; unbound.conf is not touched */
    $lock = uu_test_evaluate_lock();
    $custom = '/var/unbound/etc/zz-uu-selftest.conf';
    $swapped = null;
    $removed = false;
    if ($lock !== false && is_dir('/var/unbound/etc') && !file_exists($custom)
        && isset((new \OPNsense\Routing\GatewayGroups())->getGroupsConfig()['uu_far6_grp'])) {
        try {
            file_put_contents($custom, "server:\ndo-ip6: no\n");
            $swapped = uu_try_case(function (): bool {
                $s = uu_snapshot(['enabled' => true, 'dry_run' => true, 'group' => 'uu_far6_grp',
                    'default' => '2001:db8:a::53', 'rows' => [], 'failback_delay' => 120, 'probe_name' => '.'],
                    [], null, false, []);
                return ($s['contract_input']['unbound_conf'] ?? null) === ['do_ip4' => true, 'do_ip6' => false,
                        'outgoing_interface' => false]
                    && in_array("Unbound's generated configuration says do-ip6: no (IPv6 is not allowed in System: "
                        . 'Settings: General)', uu_contract($s['contract_input'])['failures'], true);
            });
        } finally {
            @unlink($custom);
            clearstatcache(true, $custom);
            $removed = !file_exists($custom);
        }
    }
    if ($lock !== false) {
        fclose($lock);
    }
    uu_check($t, '(c6) a custom option file with do-ip6: no gives the snapshot do_ip6 false and the contract refuses '
        . 'an IPv6 group by the text; the file is removed again',
        $swapped === true && $removed);

    $before = uu_test_evaluations();
    shell_exec('/usr/local/sbin/pluginctl -c unbound_start > /dev/null 2>&1');
    $seen = false;
    $deadline = hrtime(true) + 5000000000;
    while (hrtime(true) < $deadline) {
        if (uu_test_evaluations() > $before) {
            $seen = true;
            break;
        }
        usleep(200000);
    }
    uu_check($t, 'pluginctl -c unbound_start leads to an evaluate that configd runs within 5 s',
        $seen);
    return uu_tally_report('wiring', $t);
});
