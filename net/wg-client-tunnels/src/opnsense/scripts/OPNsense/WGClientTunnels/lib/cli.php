<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The command line of tunnel.php (spec 6.4).
 * --json prints one JSON object and returns 0 whatever happened: configd's
 * script_output turns a non-zero exit into a bare "Execute error", so
 * failures travel inside the JSON. create reads its request as JSON on stdin;
 * the key is never on argv.
 */

require_once __DIR__ . '/view.php';
require_once __DIR__ . '/writer.php';
require_once __DIR__ . '/apply.php';
require_once __DIR__ . '/selftest.php';

const WGCT_CLI_USAGE = <<<'TXT'
Usage: tunnel.php [--json] [--dry] COMMAND   (--dry: create, remove, rebind, adopt, ensure-sentinel)
  list                                managed tunnels, and WireGuard instances the plugin does not manage
  status                              findings only
  reconcile                           run the reconcile now
  create                              create a tunnel from a JSON request on stdin (see the README)
  remove UUID                         remove a managed tunnel and everything it owns
  rebind UUID WAN [STALE_ROUTE_UUID]  bind an unbound tunnel to WAN, optionally deleting a stale route
  adopt UUID                          manage an existing WireGuard instance
  ensure-sentinel                     create or repair the NO_DEFAULT4/NO_DEFAULT6 sentinel
  measure-mtu WAN ENDPOINT            measure the tunnel MTU for WAN -> ENDPOINT
  apply UUID                          run Create's tunnel apply again (the API's step after Create; clears apply-pending)
       tunnel.php --selftest
TXT;
/* the write actions, whose --dry validates and writes nothing; any other command refuses --dry */
const WGCT_CLI_DRY_COMMANDS = ['create', 'remove', 'rebind', 'adopt', 'ensure-sentinel'];
const WGCT_CLI_OTHER_COMMANDS = ['list', 'status', 'reconcile', 'measure-mtu', 'apply'];

/**
 * @param list<string> $args argv without the script name
 * @return int exit code
 */
function wgct_cli_main(array $args): int {
    if (in_array('--selftest', $args, true)) {
        return wgct_cli_selftest();
    }
    $json = in_array('--json', $args, true);
    $dry = in_array('--dry', $args, true);
    $pos = array_values(array_filter($args, fn (string $a): bool => strncmp($a, '--', 2) !== 0));
    $cmd = $pos[0] ?? '';
    $secrets = [];
    /* the tunnel a failure concerns, once known: the apply argument, or the uuid a Create saved */
    $uuid = '';
    if ($dry && in_array($cmd, WGCT_CLI_OTHER_COMMANDS, true)) {
        return wgct_cli_emit(wgct_result(['dry' => true, 'errors' => [
            'general' => "--dry applies to the write actions only (" . implode(', ', WGCT_CLI_DRY_COMMANDS) . "); {$cmd} has no dry run",
        ]]), $json);
    }
    try {
        switch ($cmd) {
            case 'list':
            case 'status':
                return wgct_cli_list($json, $cmd === 'status');
            case 'reconcile':
                $out = (string)(new \OPNsense\Core\Backend())->configdRun('wgclienttunnels reconcile', false, 300);
                return wgct_cli_emit(wgct_result(['ok' => true, 'after' => ['replayed' => [], 'reconcile' => wgct_step_summary($out)]]), $json);
            case 'create':
                /* a JSON boundary: json_decode yields mixed; wgct_create_request() type-checks every value */
                $raw = json_decode((string)stream_get_contents(STDIN), true);
                if (!is_array($raw)) {
                    return wgct_cli_emit(wgct_result(['errors' => ['config' => 'stdin is not a JSON object'], 'dry' => $dry]), $json);
                }
                $prep = wgct_create_prepare($raw, false);
                unset($raw);
                $secrets = array_values($prep['secret']);
                if ($prep['errors'] !== []) {
                    return wgct_cli_emit(wgct_result(['errors' => $prep['errors'], 'changes' => $prep['notes'], 'dry' => $dry]), $json);
                }
                $commit = function () use ($prep, $dry, &$uuid): array {
                    $created = wgct_create_commit($prep, $dry);
                    $uuid = $created['saved'] ? $created['uuid'] : '';
                    return $created;
                };
                return wgct_cli_emit(wgct_routing_action($commit, $dry), $json);
            case 'remove':
                $uuid = wgct_cli_uuid($pos[1] ?? '');
                return wgct_cli_emit(wgct_routing_action(fn (): array => wgct_remove_commit($uuid, $dry), $dry), $json);
            case 'rebind':
                $uuid = wgct_cli_uuid($pos[1] ?? '');
                $wan = $pos[2] ?? '';
                $stale = ($pos[3] ?? '') === '' ? '' : wgct_cli_uuid($pos[3]);
                return wgct_cli_emit(wgct_routing_action(fn (): array => wgct_rebind_commit($uuid, $wan, $stale, $dry), $dry), $json);
            case 'adopt':
                $uuid = wgct_cli_uuid($pos[1] ?? '');
                return wgct_cli_emit(wgct_config_action(fn (): array => wgct_adopt_commit($uuid, $dry), $dry), $json);
            case 'ensure-sentinel':
                return wgct_cli_emit(wgct_routing_action(fn (): array => wgct_sentinel_commit($dry), $dry), $json);
            case 'measure-mtu':
                return wgct_cli_emit_mtu(wgct_measure_mtu($pos[1] ?? '', $pos[2] ?? ''), $json);
            case 'apply':
                $uuid = wgct_cli_uuid($pos[1] ?? '');
                return wgct_cli_emit(wgct_apply_only($uuid), $json);
            default:
                fwrite(STDERR, WGCT_CLI_USAGE . "\n");
                return 2;
        }
    } catch (\Throwable $e) {
        $msg = wgct_redact(get_class($e) . ': ' . $e->getMessage(), $secrets);
        syslog(LOG_ERR, '[' . WGCT_ACTION_LOG_TAG . "] {$cmd} failed: {$msg}");
        /*
         * wgct_cli_uuid() is the only thing that throws InvalidArgumentException,
         * and it runs before any writer is called: that failure can never
         * follow a save, so any "after the save" footer would be misleading
         * there (controller review, 2026-09-25). Everything else reaches
         * here from inside or after an action function, which may have
         * already saved. A dry run saves nothing either.
         */
        $canFollowSave = !($e instanceof \InvalidArgumentException) && !$dry;
        return wgct_cli_emit(wgct_result(['dry' => $dry, 'errors' => ['general' => wgct_cli_failure_message($cmd, $msg, $canFollowSave, $uuid)]]), $json);
    }
}

/**
 * The text for a caught command failure. A pre-write input error (an
 * invalid uuid) or a dry run ($canFollowSave false) can never have saved
 * anything, so it gets no footer; anything that may have run after an action
 * function started -- and so may have saved before failing -- gets its
 * command's footer (wgct_failure_footer(): `tunnel.php apply` only for
 * create and apply). Pure: $msg is text the caller has already redacted.
 *
 * @param string $cmd           the command that failed
 * @param string $msg           the redacted exception text
 * @param bool   $canFollowSave whether the failure could have happened after a save
 * @param string $uuid          the tunnel's instance uuid when known, else ''
 * @return string
 */
function wgct_cli_failure_message(string $cmd, string $msg, bool $canFollowSave, string $uuid): string {
    $text = "{$cmd} failed: {$msg}.";
    $footer = $canFollowSave ? wgct_failure_footer($cmd, $uuid) : '';
    return $footer === '' ? $text : "{$text} {$footer}";
}

/**
 * @return bool whether $cmd takes --dry (a write action); `apply` and
 *              `reconcile` act for real and the read commands write nothing,
 *              so --dry on any of them is refused, never silently ignored. Pure.
 */
function wgct_cli_takes_dry(string $cmd): bool {
    return in_array($cmd, WGCT_CLI_DRY_COMMANDS, true);
}

/**
 * @return string $value when it is a uuid
 * @throws \InvalidArgumentException otherwise
 */
function wgct_cli_uuid(string $value): string {
    if (preg_match('/^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$/', $value) !== 1) {
        throw new \InvalidArgumentException('not a uuid: ' . substr($value, 0, 40));
    }
    return $value;
}

/**
 * @param array $r    wgct_result()
 * @param bool  $json one JSON object instead of text
 * @return int 0 when there are no errors (always 0 with --json)
 */
function wgct_cli_emit(array $r, bool $json): int {
    if ($json) {
        echo json_encode($r, JSON_UNESCAPED_SLASHES), "\n";
        return 0;
    }
    foreach ($r['changes'] as $line) {
        echo "  {$line}\n";
    }
    foreach ($r['errors'] as $key => $message) {
        printf("ERROR%s: %s\n", is_string($key) && $key !== 'general' ? " ({$key})" : '', $message);
    }
    if ($r['ok'] && !$r['saved'] && $r['errors'] === [] && $r['changes'] === [] && $r['after'] === []) {
        echo "nothing to change\n";
    } elseif ($r['dry'] && $r['errors'] === []) {
        echo "DRY RUN - validated, nothing written\n";
    }
    foreach ($r['apply'] as $step) {
        printf("  configctl %s: %s\n", $step['action'], $step['result']);
    }
    if ($r['after'] !== []) {
        printf("  alarm replayed for: %s\n", $r['after']['replayed'] === [] ? '(none)' : implode(', ', $r['after']['replayed']));
        printf("  reconcile: %s\n", $r['after']['reconcile']);
    }
    if ($r['ok'] && $r['saved']) {
        echo "APPLIED\n";
    }
    return $r['errors'] === [] ? 0 : 1;
}

/**
 * @param array $m    wgct_measure_mtu()
 * @param bool  $json
 * @return int
 */
function wgct_cli_emit_mtu(array $m, bool $json): int {
    if ($json) {
        echo json_encode($m, JSON_UNESCAPED_SLASHES), "\n";
        return 0;
    }
    if (!$m['ok']) {
        foreach ($m['errors'] as $error) {
            echo "ERROR: {$error}\n";
        }
        return 1;
    }
    printf("mtu %d (%s)\n", $m['mtu'], $m['why']);
    return 0;
}

/**
 * @param bool $json
 * @param bool $findingsOnly `status`: findings only
 * @return int
 */
function wgct_cli_list(bool $json, bool $findingsOnly): int {
    $view = wgct_tunnel_view();
    unset($view['core']);
    if ($json) {
        $out = $findingsOnly
            ? ['global' => $view['global'], 'tunnels' => array_map(
                fn (array $t): array => ['uuid' => $t['uuid'], 'name' => $t['name'], 'findings' => $t['findings']],
                $view['tunnels']
            )]
            : $view;
        echo json_encode($out, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
        return 0;
    }
    foreach ($view['global'] as $f) {
        printf("GLOBAL %s: %s -- %s\n", $f['code'], $f['detail'], $f['fix']);
    }
    foreach ($view['tunnels'] as $t) {
        if (!$findingsOnly) {
            $clamp = $t['clamp'] !== null
                ? sprintf(' clamp v4 %s v6 %s', $t['clamp']['v4'] ?? '-', $t['clamp']['v6'] ?? '-')
                : '';
            printf(
                "%-18s %-5s %-6s endpoint %-22s WAN %-12s mtu %d gw4 %s gw6 %s%s%s%s  %s\n",
                $t['name'] !== '' ? $t['name'] : $t['uuid'], $t['device'], (string)$t['interface'], $t['endpoint'],
                (string)$t['bound_wan'], $t['mtu'], (string)$t['gw4'], (string)$t['gw6'],
                $t['enabled'] ? '' : ' (disabled)', $t['enforceable'] ? '' : ' (not enforced)', $clamp, $t['uuid']
            );
        } elseif ($t['findings'] !== []) {
            printf("%s:\n", $t['name'] !== '' ? $t['name'] : $t['uuid']);
        }
        foreach ($t['findings'] as $f) {
            printf("    %s%s: %s -- %s\n", $f['blocking'] ? '[B] ' : '', $f['code'], $f['detail'], $f['fix']);
        }
    }
    if (!$findingsOnly && $view['unmanaged'] !== []) {
        echo "not managed (tunnel.php adopt UUID):\n";
        foreach ($view['unmanaged'] as $u) {
            printf("  %-18s %-5s %-22s %s%s\n", $u['name'], $u['device'], $u['endpoint'], $u['uuid'], $u['enabled'] ? '' : ' (disabled)');
        }
    }
    return 0;
}

/**
 * Self-tests for cli.php's own pure helpers: uuid validation and the
 * per-command failure footer. No syslog, no files, no config, no processes.
 *
 * @return int exit code, 0 when every case passes
 */
function wgct_cli_own_selftest(): int {
    $t = ['fail' => 0, 'total' => 0];
    $lower = '00000000-0000-4000-8000-000000000001';
    $upper = strtoupper($lower);
    wgct_check($t, 'cli: a lower-case uuid is accepted as itself', wgct_cli_uuid($lower) === $lower);
    wgct_check($t, 'cli: an upper-case uuid is accepted as itself', wgct_cli_uuid($upper) === $upper);
    foreach (['not-a-uuid', ''] as $bad) {
        $rejected = false;
        try {
            wgct_cli_uuid($bad);
        } catch (\InvalidArgumentException) {
            $rejected = true;
        }
        wgct_check($t, "cli: '{$bad}' is rejected as not a uuid", $rejected);
    }
    wgct_check($t, 'cli: a pre-write input error (cannot follow a save) carries no footer',
        wgct_cli_failure_message('remove', 'InvalidArgumentException: not a uuid: x', false, '')
        === 'remove failed: InvalidArgumentException: not a uuid: x.');
    $create = wgct_cli_failure_message('create', 'RuntimeException: boom', true, $lower);
    wgct_check($t, 'cli: a create failure that may follow a save names `tunnel.php apply <its uuid>`',
        str_starts_with($create, 'create failed: RuntimeException: boom. ') && str_contains($create, "`tunnel.php apply {$lower}`"));
    wgct_check($t, 'cli: an apply failure names `tunnel.php apply <uuid>` again',
        str_contains(wgct_cli_failure_message('apply', 'RuntimeException: boom', true, $lower), "`tunnel.php apply {$lower}` again"));
    $remove = wgct_cli_failure_message('remove', 'RuntimeException: boom', true, $lower);
    wgct_check($t, 'cli: a remove failure that may follow a save points to status and the list, not to apply',
        str_starts_with($remove, 'remove failed: RuntimeException: boom. ') && !str_contains($remove, 'tunnel.php apply')
        && str_contains($remove, '`tunnel.php status`'));
    wgct_check($t, 'cli: rebind, adopt and ensure-sentinel failures never suggest apply',
        !str_contains(wgct_cli_failure_message('rebind', 'x', true, $lower), 'tunnel.php apply')
        && !str_contains(wgct_cli_failure_message('adopt', 'x', true, $lower), 'tunnel.php apply')
        && !str_contains(wgct_cli_failure_message('ensure-sentinel', 'x', true, ''), 'tunnel.php apply'));
    wgct_check($t, 'cli: --dry is taken by create, remove, rebind, adopt and ensure-sentinel',
        array_filter(['create', 'remove', 'rebind', 'adopt', 'ensure-sentinel'], fn (string $c): bool => !wgct_cli_takes_dry($c)) === []);
    wgct_check($t, 'cli: --dry is refused, not ignored, by apply, reconcile, list, status and measure-mtu',
        array_filter(WGCT_CLI_OTHER_COMMANDS, 'wgct_cli_takes_dry') === [] && count(WGCT_CLI_OTHER_COMMANDS) === 5);
    wgct_check($t, 'cli: a list or measure-mtu failure carries no footer',
        wgct_cli_failure_message('list', 'x', true, '') === 'list failed: x.'
        && wgct_cli_failure_message('measure-mtu', 'x', true, '') === 'measure-mtu failed: x.');
    return wgct_tally_report('cli', $t);
}

/**
 * Every self-test suite of the plugin. Pure.
 *
 * @return int 0 when every suite passes
 */
function wgct_cli_selftest(): int {
    require_once __DIR__ . '/render.php';
    require_once __DIR__ . '/migration.php';
    $codes = [
        wgct_cli_own_selftest(), wgct_tunnels_selftest(), wgct_render_selftest(), wgct_wgconf_selftest(),
        wgct_refs_selftest(), wgct_actions_selftest(), wgct_mtu_selftest(), wgct_apply_selftest(),
        wgct_migration_selftest(),
    ];
    return max($codes) === 0 ? 0 : 1;
}
