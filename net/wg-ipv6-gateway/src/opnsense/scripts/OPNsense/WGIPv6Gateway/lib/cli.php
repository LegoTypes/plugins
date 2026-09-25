<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The command line (spec 6.4), shared by tunnel.php and its alias tunnels.php.
 * --json prints one JSON object and returns 0 whatever happened: configd's
 * script_output turns a non-zero exit into a bare "Execute error", so
 * failures travel inside the JSON. create reads its request as JSON on stdin;
 * the key is never on argv.
 */

require_once __DIR__ . '/view.php';
require_once __DIR__ . '/writer.php';
require_once __DIR__ . '/apply.php';
require_once __DIR__ . '/selftest.php';

const WGIPV6_CLI_USAGE = <<<'TXT'
Usage: tunnel.php [--json] [--dry] COMMAND
  list                                managed tunnels, and WireGuard instances the plugin does not manage
  status                              findings only
  reconcile                           run the reconcile now
  create                              create a tunnel from a JSON request on stdin (see the README)
  remove UUID                         remove a managed tunnel and everything it owns
  rebind UUID WAN [STALE_ROUTE_UUID]  bind an unbound tunnel to WAN, optionally deleting a stale route
  adopt UUID                          manage an existing WireGuard instance
  ensure-sentinel                     create or repair the NO_DEFAULT4/NO_DEFAULT6 sentinel
  measure-mtu WAN ENDPOINT            measure the tunnel MTU for WAN -> ENDPOINT
  apply UUID                          run the tunnel apply again (the API's step after Create; clears apply-pending)
       tunnel.php --selftest
TXT;

/**
 * @param list<string> $args argv without the script name
 * @return int exit code
 */
function wgipv6_cli_main(array $args): int {
    if (in_array('--selftest', $args, true)) {
        return wgipv6_cli_selftest();
    }
    $json = in_array('--json', $args, true);
    $dry = in_array('--dry', $args, true);
    $pos = array_values(array_filter($args, fn (string $a): bool => strncmp($a, '--', 2) !== 0));
    $cmd = $pos[0] ?? '';
    $secrets = [];
    try {
        switch ($cmd) {
            case 'list':
            case 'status':
                return wgipv6_cli_list($json, $cmd === 'status');
            case 'reconcile':
                $out = (string)(new \OPNsense\Core\Backend())->configdRun('wgipv6gateway reconcile', false, 300);
                return wgipv6_cli_emit(wgipv6_result(['ok' => true, 'after' => ['replayed' => [], 'reconcile' => wgipv6_step_summary($out)]]), $json);
            case 'create':
                /* a JSON boundary: json_decode yields mixed; wgipv6_create_request() type-checks every value */
                $raw = json_decode((string)stream_get_contents(STDIN), true);
                if (!is_array($raw)) {
                    return wgipv6_cli_emit(wgipv6_result(['errors' => ['config' => 'stdin is not a JSON object'], 'dry' => $dry]), $json);
                }
                $prep = wgipv6_create_prepare($raw, false);
                unset($raw);
                $secrets = array_values($prep['secret']);
                if ($prep['errors'] !== []) {
                    return wgipv6_cli_emit(wgipv6_result(['errors' => $prep['errors'], 'changes' => $prep['notes'], 'dry' => $dry]), $json);
                }
                return wgipv6_cli_emit(wgipv6_routing_action(fn (): array => wgipv6_create_commit($prep, $dry), $dry), $json);
            case 'remove':
                $uuid = wgipv6_cli_uuid($pos[1] ?? '');
                return wgipv6_cli_emit(wgipv6_routing_action(fn (): array => wgipv6_remove_commit($uuid, $dry), $dry), $json);
            case 'rebind':
                $uuid = wgipv6_cli_uuid($pos[1] ?? '');
                $wan = $pos[2] ?? '';
                $stale = ($pos[3] ?? '') === '' ? '' : wgipv6_cli_uuid($pos[3]);
                return wgipv6_cli_emit(wgipv6_routing_action(fn (): array => wgipv6_rebind_commit($uuid, $wan, $stale, $dry), $dry), $json);
            case 'adopt':
                $uuid = wgipv6_cli_uuid($pos[1] ?? '');
                return wgipv6_cli_emit(wgipv6_config_action(fn (): array => wgipv6_adopt_commit($uuid, $dry), $dry), $json);
            case 'ensure-sentinel':
                return wgipv6_cli_emit(wgipv6_routing_action(fn (): array => wgipv6_sentinel_commit($dry), $dry), $json);
            case 'measure-mtu':
                return wgipv6_cli_emit_mtu(wgipv6_measure_mtu($pos[1] ?? '', $pos[2] ?? ''), $json);
            case 'apply':
                return wgipv6_cli_emit(wgipv6_apply_only(wgipv6_cli_uuid($pos[1] ?? '')), $json);
            default:
                fwrite(STDERR, WGIPV6_CLI_USAGE . "\n");
                return 2;
        }
    } catch (\Throwable $e) {
        $msg = wgipv6_redact(get_class($e) . ': ' . $e->getMessage(), $secrets);
        syslog(LOG_ERR, '[' . WGIPV6_ACTION_LOG_TAG . "] {$cmd} failed: {$msg}");
        /*
         * wgipv6_cli_uuid() is the only thing that throws InvalidArgumentException,
         * and it runs before any writer is called: that failure can never
         * follow a save, so the "apply again" footer would be misleading
         * there (controller review, 2026-09-25). Everything else reaches
         * here from inside or after an action function, which may have
         * already saved.
         */
        $canFollowSave = !($e instanceof \InvalidArgumentException);
        return wgipv6_cli_emit(wgipv6_result(['dry' => $dry, 'errors' => ['general' => wgipv6_cli_failure_message($cmd, $msg, $canFollowSave)]]), $json);
    }
}

/**
 * The text for a caught command failure. A pre-write input error (an
 * invalid uuid; $canFollowSave false) can never have saved anything, so it
 * gets no "apply again" footer; anything that may have run after an action
 * function started -- and so may have saved before failing -- does. Pure:
 * $msg is text the caller has already redacted.
 *
 * @param string $cmd           the command that failed
 * @param string $msg           the redacted exception text
 * @param bool   $canFollowSave whether the failure could have happened after a save
 * @return string
 */
function wgipv6_cli_failure_message(string $cmd, string $msg, bool $canFollowSave): string {
    $text = "{$cmd} failed: {$msg}.";
    if (!$canFollowSave) {
        return $text;
    }
    return $text . ' If this happened after the save, the change is in config and only its apply is incomplete: '
        . 'run `tunnel.php apply UUID` and check `tunnel.php status`.';
}

/**
 * @return string $value when it is a uuid
 * @throws \InvalidArgumentException otherwise
 */
function wgipv6_cli_uuid(string $value): string {
    if (preg_match('/^[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}$/', $value) !== 1) {
        throw new \InvalidArgumentException('not a uuid: ' . substr($value, 0, 40));
    }
    return $value;
}

/**
 * @param array $r    wgipv6_result()
 * @param bool  $json one JSON object instead of text
 * @return int 0 when there are no errors (always 0 with --json)
 */
function wgipv6_cli_emit(array $r, bool $json): int {
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
 * @param array $m    wgipv6_measure_mtu()
 * @param bool  $json
 * @return int
 */
function wgipv6_cli_emit_mtu(array $m, bool $json): int {
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
function wgipv6_cli_list(bool $json, bool $findingsOnly): int {
    $view = wgipv6_tunnel_view();
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
 * apply-again footer decision. No syslog, no files, no config, no processes.
 *
 * @return int exit code, 0 when every case passes
 */
function wgipv6_cli_own_selftest(): int {
    $t = ['fail' => 0, 'total' => 0];
    $lower = '00000000-0000-4000-8000-000000000001';
    $upper = strtoupper($lower);
    wgipv6_check($t, 'cli: a lower-case uuid is accepted as itself', wgipv6_cli_uuid($lower) === $lower);
    wgipv6_check($t, 'cli: an upper-case uuid is accepted as itself', wgipv6_cli_uuid($upper) === $upper);
    foreach (['not-a-uuid', ''] as $bad) {
        $rejected = false;
        try {
            wgipv6_cli_uuid($bad);
        } catch (\InvalidArgumentException) {
            $rejected = true;
        }
        wgipv6_check($t, "cli: '{$bad}' is rejected as not a uuid", $rejected);
    }
    wgipv6_check($t, 'cli: a pre-write input error (cannot follow a save) carries no apply-again footer',
        wgipv6_cli_failure_message('remove', 'InvalidArgumentException: not a uuid: x', false)
        === 'remove failed: InvalidArgumentException: not a uuid: x.');
    wgipv6_check($t, 'cli: a failure that may follow a save carries the apply-again footer',
        str_contains(wgipv6_cli_failure_message('remove', 'RuntimeException: boom', true), 'run `tunnel.php apply UUID`')
        && str_contains(wgipv6_cli_failure_message('remove', 'RuntimeException: boom', true), 'remove failed: RuntimeException: boom.'));
    return wgipv6_tally_report('cli', $t);
}

/**
 * Every self-test suite of the plugin. Pure.
 *
 * @return int 0 when every suite passes
 */
function wgipv6_cli_selftest(): int {
    require_once __DIR__ . '/render.php';
    $codes = [
        wgipv6_cli_own_selftest(), wgipv6_tunnels_selftest(), wgipv6_render_selftest(), wgipv6_wgconf_selftest(),
        wgipv6_refs_selftest(), wgipv6_actions_selftest(), wgipv6_mtu_selftest(), wgipv6_apply_selftest(),
    ];
    return max($codes) === 0 ? 0 : 1;
}
