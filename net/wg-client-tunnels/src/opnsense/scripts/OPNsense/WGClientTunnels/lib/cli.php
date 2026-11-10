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
 *
 * The command line of tunnel.php.
 * --json prints one JSON object and returns 0 whatever happened: configd's
 * script_output turns a non-zero exit into a bare "Execute error", so
 * failures travel inside the JSON. create reads its request as JSON on stdin;
 * the key is never on argv. The arguments are read by position (wgct_cli_parse()):
 * the options before the command, and every word after it as the command's own.
 */

require_once __DIR__ . '/view.php';
require_once __DIR__ . '/writer.php';
require_once __DIR__ . '/apply.php';
require_once __DIR__ . '/addr.php';
require_once __DIR__ . '/selftest.php';

const WGCT_CLI_USAGE = <<<'TXT'
Usage: tunnel.php [--json] [--dry] COMMAND [ARGUMENT ...]   (--dry: create, edit, remove, rebind, adopt, ensure-sentinel)
  The options stand before COMMAND. Every word after COMMAND is its argument, whatever it starts with.
  list                                managed tunnels, and WireGuard instances the plugin does not manage
  status                              findings only
  reconcile                           run the reconcile now
  create                              create a tunnel from a JSON request on stdin (see the README)
  edit                                edit a managed tunnel from a JSON request on stdin: uuid and only what changes (see the README)
  remove UUID                         remove a managed tunnel and everything it owns
  rebind UUID WAN [STALE_ROUTE_UUID]  bind an unbound tunnel to WAN, optionally deleting a stale route
  adopt UUID                          manage an existing WireGuard instance
  ensure-sentinel                     check the default-route exclusion: create or repair the NO_DEFAULT4/NO_DEFAULT6 gateways
  measure-mtu WAN ENDPOINT            measure the tunnel MTU for WAN -> ENDPOINT
  apply UUID [MODE]                   run a tunnel's apply again; without MODE, the apply its saved change still
                                      needs (apply-pending), else tunnel (Create's apply, then wireguard restart);
                                      MODE: filter, routes, first (Create's apply alone) or tunnel
  release-holds                       the package removal's: release the gateways the health mirror's own hold
                                      records prove it holds down (an IPv6 gateway only when its tunnel is
                                      healthy), forget every other record; exits 0 even when it fails or is refused
       tunnel.php --selftest               the self-tests; --selftest takes no other argument
TXT;
/* the write actions, whose --dry validates and writes nothing; any other command refuses --dry */
const WGCT_CLI_DRY_COMMANDS = ['create', 'edit', 'remove', 'rebind', 'adopt', 'ensure-sentinel'];
const WGCT_CLI_OTHER_COMMANDS = ['list', 'status', 'reconcile', 'measure-mtu', 'apply', 'release-holds'];
/* every command, and the most arguments it takes after its name */
const WGCT_CLI_ARGUMENTS = [
    'list' => 0, 'status' => 0, 'reconcile' => 0, 'create' => 0, 'edit' => 0, 'ensure-sentinel' => 0, 'release-holds' => 0,
    'remove' => 1, 'adopt' => 1, 'measure-mtu' => 2, 'apply' => 2, 'rebind' => 3,
];

/**
 * tunnel.php's arguments, read by position. Pure.
 *
 *  - Exactly --selftest: the self-tests.
 *  - Else the leading words that start with "--" are the options, --json and --dry, each at most once. Any other one
 *    is refused, --selftest among them.
 *  - The first word that does not start with "--" is the command, which must be a known one.
 *  - Every word after the command is its argument, whatever it starts with, the empty word included. None is read as
 *    an option, so a value a configd action hands on is never one. The arguments are returned as given and never
 *    padded: a command reads an absent one itself. More than the command takes (WGCT_CLI_ARGUMENTS) is refused.
 *  - --dry on a command without a dry run is refused.
 *
 * @param list<string> $args argv without the script name
 * @return array{selftest: bool, json: bool, dry: bool, command: string, arguments: list<string>, error: ?string}
 *         error says why the arguments are refused, null when they are taken; json and dry are what the leading
 *         options said, and command the known command after them, also beside a refusal, so a refusal can be
 *         answered as its caller asked (wgct_cli_refused_status())
 */
function wgct_cli_parse(array $args): array {
    $parsed = ['selftest' => false, 'json' => false, 'dry' => false, 'command' => '', 'arguments' => [], 'error' => null];
    if ($args === ['--selftest']) {
        $parsed['selftest'] = true;
        return $parsed;
    }
    $count = count($args);
    $at = 0;
    for (; $at < $count && str_starts_with($args[$at], '--'); $at++) {
        $option = $args[$at];
        if ($option === '--selftest') {
            $parsed['error'] ??= '--selftest takes no other argument';
        } elseif ($option !== '--json' && $option !== '--dry') {
            $parsed['error'] ??= 'unknown option ' . substr($option, 0, 40);
        } elseif ($parsed[substr($option, 2)]) {
            $parsed['error'] ??= "{$option} is given twice";
        } else {
            $parsed[substr($option, 2)] = true;
        }
    }
    $command = $args[$at] ?? null;
    if ($command !== null && isset(WGCT_CLI_ARGUMENTS[$command])) {
        $parsed['command'] = $command;
    }
    if ($parsed['error'] !== null) {
        return $parsed;
    }
    if ($command === null) {
        $parsed['error'] = 'no command';
        return $parsed;
    }
    if ($parsed['command'] === '') {
        $parsed['error'] = 'unknown command ' . substr($command, 0, 40);
        return $parsed;
    }
    $arguments = array_slice($args, $at + 1);
    $most = WGCT_CLI_ARGUMENTS[$command];
    if (count($arguments) > $most) {
        $parsed['error'] = "{$command} takes " . ($most === 0 ? 'no argument' : "at most {$most} argument" . ($most === 1 ? '' : 's'))
            . ', ' . count($arguments) . ' given';
        return $parsed;
    }
    if ($parsed['dry'] && !wgct_cli_takes_dry($command)) {
        $parsed['error'] = '--dry applies to the write actions only (' . implode(', ', WGCT_CLI_DRY_COMMANDS) . "); {$command} has no dry run";
        return $parsed;
    }
    $parsed['arguments'] = $arguments;
    return $parsed;
}

/**
 * The exit status of an argument list wgct_cli_parse() refused. With --json it is 0, as for every reply (the file
 * header says why). release-holds is the package removal's and exits 0 whatever happens, a refusal included.
 * Anything else is a usage error. Pure.
 *
 * @param array{json: bool, command: string} $parsed wgct_cli_parse() with an error
 * @return int
 */
function wgct_cli_refused_status(array $parsed): int {
    return $parsed['json'] || $parsed['command'] === 'release-holds' ? 0 : 2;
}

/**
 * The MODE `apply UUID [MODE]` hands on: null when the word is absent, which selects the mode the tunnel's pending
 * record still needs (wgct_apply_only()), else the word as given, the empty one included, which is no apply mode.
 * Pure.
 *
 * @param list<string> $arguments the apply command's arguments (wgct_cli_parse())
 * @return ?string
 */
function wgct_cli_apply_mode(array $arguments): ?string {
    return $arguments[1] ?? null;
}

/**
 * @param list<string> $args argv without the script name
 * @return int exit code
 */
function wgct_cli_main(array $args): int {
    $parsed = wgct_cli_parse($args);
    if ($parsed['selftest']) {
        return wgct_cli_selftest();
    }
    $json = $parsed['json'];
    $dry = $parsed['dry'];
    if ($parsed['error'] !== null) {
        /* refused before anything ran: the JSON failure for configd's callers, the reason and the usage for a person */
        if ($json) {
            wgct_cli_emit(wgct_result(['dry' => $dry, 'errors' => ['general' => $parsed['error']]]), true);
        } else {
            fwrite(STDERR, 'tunnel.php: ' . $parsed['error'] . "\n" . WGCT_CLI_USAGE . "\n");
        }
        return wgct_cli_refused_status($parsed);
    }
    $cmd = $parsed['command'];
    $arguments = $parsed['arguments'];
    $secrets = [];
    /* the tunnel a failure concerns, once known: the apply or edit argument, or the uuid a Create saved */
    $uuid = '';
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
            case 'edit':
                /* a JSON boundary: json_decode yields mixed; wgct_edit_request() type-checks every value */
                $raw = json_decode((string)stream_get_contents(STDIN), true);
                if (!is_array($raw)) {
                    return wgct_cli_emit(wgct_result(['errors' => ['config' => 'stdin is not a JSON object'], 'dry' => $dry]), $json);
                }
                $uuid = wgct_cli_uuid(is_string($raw['uuid'] ?? null) ? $raw['uuid'] : '');
                $prep = wgct_edit_prepare($raw, $uuid);
                unset($raw);
                $secrets = array_values($prep['secret']);
                if ($prep['errors'] !== []) {
                    return wgct_cli_emit(wgct_result(['errors' => $prep['errors'], 'dry' => $dry, 'uuid' => $uuid]), $json);
                }
                return wgct_cli_emit(wgct_edit_action($prep, $dry), $json);
            case 'remove':
                $uuid = wgct_cli_uuid($arguments[0] ?? '');
                return wgct_cli_emit(wgct_routing_action(fn (): array => wgct_remove_commit($uuid, $dry), $dry), $json);
            case 'rebind':
                $uuid = wgct_cli_uuid($arguments[0] ?? '');
                $wan = $arguments[1] ?? '';
                $stale = ($arguments[2] ?? '') === '' ? '' : wgct_cli_uuid($arguments[2]);
                return wgct_cli_emit(wgct_routing_action(fn (): array => wgct_rebind_commit($uuid, $wan, $stale, $dry), $dry), $json);
            case 'adopt':
                $uuid = wgct_cli_uuid($arguments[0] ?? '');
                return wgct_cli_emit(wgct_config_action(fn (): array => wgct_adopt_commit($uuid, $dry), $dry), $json);
            case 'ensure-sentinel':
                return wgct_cli_emit(wgct_routing_action(fn (): array => wgct_sentinel_commit($dry), $dry), $json);
            case 'measure-mtu':
                return wgct_cli_emit_mtu(wgct_measure_mtu($arguments[0] ?? '', $arguments[1] ?? ''), $json);
            case 'apply':
                $uuid = wgct_cli_uuid($arguments[0] ?? '');
                return wgct_cli_emit(wgct_apply_only($uuid, wgct_cli_apply_mode($arguments)), $json);
            case 'release-holds':
                return wgct_cli_release_holds($json);
            default:
                throw new \LogicException("no handler for the command {$cmd}");
        }
    } catch (WgctRemovingException $e) {
        /* the removal marker appeared while the command waited for the gateway lock: nothing was saved */
        return wgct_cli_emit(wgct_result(['dry' => $dry, 'errors' => ['general' => "{$cmd}: " . $e->getMessage()]]), $json);
    } catch (\Throwable $e) {
        $msg = wgct_redact(get_class($e) . ': ' . $e->getMessage(), $secrets);
        wgct_log(LOG_ERR, '[' . WGCT_ACTION_LOG_TAG . "] {$cmd} failed: {$msg}");
        /*
         * wgct_cli_uuid() and wgct_apply_mode_steps() (an unknown apply mode)
         * are the only things that throw InvalidArgumentException, and both
         * run before any writer or step is called: that failure can never
         * follow a save, so any "after the save" footer would be misleading
         * there. Everything else reaches
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
    if (!wgct_valid_uuid($value)) {
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

/* release-holds' line when hold records exist but kern.boot_id cannot be read */
const WGCT_RELEASE_BOOT_UNREADABLE = 'deinstall: kern.boot_id cannot be read, so no hold record can be shown to be ours;'
    . ' nothing released or forgotten, every gateway left as it is';
/* release-holds' line when configd does not answer the routing re-sync */
const WGCT_RELEASE_CONFIGD_DOWN = 'deinstall: configd not answering; routing applies the release at its next configure';

/**
 * `release-holds`, which +PRE_DEINSTALL runs on a real removal, while
 * the removal marker keeps every other entry point of the plugin stopped:
 *
 * 1. Under the gateway lock, outside Config::lock(): the dpinger readings, from their sockets alone (no configd).
 *    Then under Config::lock(): force_down=0 on the gateway of every owned hold record, except an IPv6 gateway
 *    whose tunnel pass 2 would not bring up now (wgct_release_plan()): that one stays forced down and
 *    keeps its record. Every other record is forgotten with its gateway untouched, saved once. With records but no
 *    live boot id it changes nothing: leaving a gateway forced down is the safe side, releasing one it
 *    cannot prove it holds is not.
 * 2. One line to the WireGuard log says what it released and forgot, and names the IPv6 gateways it leaves forced
 *    down.
 * 3. Only when something was released: core's `interface routes configure` through configctl, still under the
 *    gateway lock, as the mirror runs its reconfigure. Then the lock is released and the alarms dropped while it was
 *    held, the released gateways' own included, are replayed through core's `interface routes alarm`. Each configd
 *    call is bounded (wgct_configctl_bounded()); when configd does not answer the re-sync, both are skipped with one
 *    line, and routing applies the saved release at its next configure. The plugin's own configd
 *    actions are never used: the removal deletes them. With nothing released no configd call is made.
 *
 * Never throws: a failure is logged and returned.
 *
 * @return array{ok: bool, saved: bool, released: list<string>, pruned: list<string>, left_down: list<string>,
 *               routing: string, replayed: list<string>, logged: string, errors: list<string>} gateway names;
 *               routing is 'configd', 'skipped' (configd not answering) or '' (nothing released)
 */
function wgct_release_holds(): array {
    $out = ['ok' => false, 'saved' => false, 'released' => [], 'pruned' => [], 'left_down' => [], 'routing' => '',
        'replayed' => [], 'logged' => '', 'errors' => []];
    $lock = null;
    try {
        /* until a pending migration has run, the managed list or the hold records are where an older version
         * stored them: nothing can be shown to be ours, so every gateway is left as it is */
        if (wgct_pending_refuses('release-holds', WGCT_ACTION_LOG_TAG)) {
            $out['errors'][] = 'deinstall: ' . WGCT_MIGRATION_PENDING . '; every gateway left as it is';
            return $out;
        }
        $before = wgct_gateway_status();
        $lock = wgct_gateway_lock(true);
        $readings = wgct_collect_dpinger();
        $commit = wgct_locked_commit(function () use ($readings): array {
            $engine = new \OPNsense\WGClientTunnels\Engine();
            /*
             * The tunnels' part alone: the rest asks configd while it loads, which may not answer.
             * The pairs are the mirror's: every finding that blocks a tunnel comes from this part.
             */
            $core = wgct_core_tunnel_snapshot();
            $pairs = wgct_mirror_inputs(wgct_derive($core, wgct_managed()))['pairs'];
            $holds = wgct_engine_holds($engine, $core['gateways']);
            $names = [];
            foreach ($core['gateways'] as $name => $g) {
                $names[$g['uuid']] = (string)$name;
            }
            $plan = wgct_release_plan($holds['rows'], $holds['live_boot'], $holds['previous_boot'], $core['gateways'], $pairs, $readings);
            /* an owned record's gateway is forced down, so it exists */
            $kept = array_map(fn (string $uuid): string => $names[$uuid], $plan['keep']);
            sort($kept);
            /* the kept records, re-stamped with the live boot as a tick would; every other record goes */
            $rows = wgct_hold_rows_next(['gateways' => $core['gateways'], 'underlays' => [], 'pairs' => $pairs,
                'holds_rows' => $holds['rows'], 'previous_boot' => $holds['previous_boot']],
                array_fill_keys($kept, true), $holds['live_boot'], time());
            $result = [
                'unreadable' => $holds['live_boot'] === '' && $holds['rows'] !== [],
                'released' => array_map(fn (string $uuid): string => $names[$uuid], $plan['release']),
                'pruned' => array_map(fn (string $uuid): string => $names[$uuid] ?? $uuid, $plan['prune']),
                'left_down' => $kept,
            ];
            if ($result['released'] !== []) {
                $routing = new \OPNsense\Routing\Gateways();
                wgct_apply_changes($routing, array_fill_keys($result['released'], false));
                $routing->serializeToConfig();
            }
            if ($rows !== null) {
                $engine->setHolds($rows);
                $engine->serializeToConfig();
            }
            return ['save' => $result['released'] !== [] || $rows !== null] + $result;
        }, 'wg upstream tunnels: release holds (package removal)');
        $out['saved'] = $commit['save'];
        $out['released'] = $commit['released'];
        $out['pruned'] = $commit['pruned'];
        $out['left_down'] = $commit['left_down'];
        $out['logged'] = $commit['unreadable']
            ? WGCT_RELEASE_BOOT_UNREADABLE
            : wgct_release_log_line($commit['released'], $commit['pruned'], $commit['left_down']);
        wgct_log(LOG_NOTICE, '[' . WGCT_ACTION_LOG_TAG . '] ' . $out['logged']);
        $answered = null;
        if ($commit['released'] !== []) {
            $answered = wgct_configctl_bounded(['interface', 'routes', 'configure'], WGCT_REMOVAL_CONFIGD_SECONDS);
            $out['routing'] = $answered ? 'configd' : 'skipped';
        }
        $lock->flock(LOCK_UN);
        $lock = null;
        if ($answered === false) {
            wgct_log(LOG_WARNING, '[' . WGCT_ACTION_LOG_TAG . '] ' . WGCT_RELEASE_CONFIGD_DOWN);
        } elseif ($answered === true) {
            /* every alarm routes.alarm dropped while the lock was held, the released gateways' own included */
            $set = wgct_replay_set_now($commit['released'], $before);
            if ($set !== []) {
                wgct_await_gateway_status($set, WGCT_ACTION_LOG_TAG);
                $names = implode(',', array_keys($set));
                if (wgct_configctl_bounded(['interface', 'routes', 'alarm', $names], WGCT_REMOVAL_CONFIGD_SECONDS)) {
                    $out['replayed'] = array_map('strval', array_keys($set));
                } else {
                    $out['errors'][] = "deinstall: configd did not answer the alarm replay for {$names}";
                }
            }
        }
    } catch (\Throwable $e) {
        $lock?->flock(LOCK_UN);
        $out['errors'][] = 'deinstall: release-holds failed: ' . get_class($e) . ': ' . $e->getMessage();
    }
    foreach ($out['errors'] as $error) {
        wgct_log(LOG_WARNING, '[' . WGCT_ACTION_LOG_TAG . '] ' . $error);
    }
    $out['ok'] = $out['errors'] === [];
    return $out;
}

/**
 * release-holds' log line. Pure.
 *
 * @param list<string> $released gateway names released
 * @param list<string> $pruned   names (uuids for gateways that are gone) whose record went without a release
 * @param list<string> $leftDown the IPv6 gateways kept forced down with their record (wgct_release_plan()'s keep)
 * @return string
 */
function wgct_release_log_line(array $released, array $pruned, array $leftDown): string {
    $line = $released !== [] ? 'deinstall: released ' . implode(', ', $released)
        : ($leftDown === [] ? 'deinstall: nothing held' : 'deinstall: nothing released');
    if ($pruned !== []) {
        $line .= '; hold records forgotten, their gateways left as they are: ' . implode(', ', $pruned);
    }
    if ($leftDown !== []) {
        $line .= '; left forced down (IPv6, its tunnel is not healthy): ' . implode(', ', $leftDown);
    }
    return $line;
}

/**
 * @param bool $json one JSON object instead of text
 * @return int 0, whatever happened: the package removal must complete
 */
function wgct_cli_release_holds(bool $json): int {
    $r = wgct_release_holds();
    if ($json) {
        echo json_encode($r, JSON_UNESCAPED_SLASHES), "\n";
        return 0;
    }
    if ($r['logged'] !== '') {
        echo $r['logged'], "\n";
    }
    foreach ($r['errors'] as $error) {
        echo "ERROR: {$error}\n";
    }
    return 0;
}

/**
 * The list line's state note: what a tunnel that is not enforced still has. A blocked tunnel is skipped by the
 * health mirror and the IPv6 prime, and keeps its pins while pf holds any for it (`pinned`, wgct_pins_in_pf():
 * the render's, the footprint's while the hook enforces it, none while render-failed shows). Pure.
 *
 * @param array $t a wgct_tunnel_view() tunnel
 * @return string '' or a parenthesised note with a leading space
 */
function wgct_cli_state_note(array $t): string {
    if ($t['enforceable']) {
        return '';
    }
    if (!wgct_blocked($t)) {
        return ' (not enforced)';
    }
    return ' (blocked: mirror and prime skip it' . ($t['pinned'] ? '; pins in place)' : ')');
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
                $t['enabled'] ? '' : ' (disabled)', wgct_cli_state_note($t), $clamp, $t['uuid']
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
 * Self-tests for the self-tests' own fixture helpers (lib/selftest.php) and for cli.php's pure helpers: the argument
 * parser, uuid validation and the per-command failure footer. No syslog, no config, no processes; its files lie in
 * fixture directories of its own, and the one file it reads beside them is the installed configd action file.
 *
 * @return int exit code, 0 when every case passes
 */
function wgct_cli_own_selftest(): int {
    $t = ['fail' => 0, 'total' => 0];

    /* the runner first, while this suite holds no fixture directory: its cleanup removes every one of this process */
    $made = '';
    ob_start();
    $code = wgct_selftest_run([
        'thrown' => function () use (&$made): int {
            $made = wgct_selftest_dir('cli-run');
            throw new \RuntimeException("no directory\n  for the fixture");
        },
        'passing' => fn (): int => 0,
    ]);
    $printed = (string)ob_get_clean();
    clearstatcache();
    wgct_check($t, 'selftest: a suite that throws is one failed case with a summary line of its own; the run fails, the next suite still runs, and the fixture directory it made is removed',
        $code === 1 && $printed === "[FAIL] selftest: RuntimeException: no directory; for the fixture\nthrown: 0/1 passed\n"
        && $made !== '' && !file_exists($made));
    /* a directory on record that does not lie directly under its root is one the cleanup never removes */
    $stray = wgct_selftest_root() . '/cli-stray/one';
    ob_start();
    $code = wgct_selftest_run(['leaving' => function () use ($stray): int {
        wgct_selftest_made(wgct_selftest_made() + [$stray => wgct_selftest_root()]);
        return 0;
    }]);
    $printed = (string)ob_get_clean();
    $recorded = wgct_selftest_made();
    wgct_selftest_made(array_diff_key($recorded, [$stray => true]));
    wgct_check($t, 'selftest: a fixture directory the cleanup leaves is one failed case naming it and fails the run, though every suite passed; it stays on record',
        $code === 1 && $printed === "[FAIL] selftest: left {$stray}\n" && ($recorded[$stray] ?? null) === wgct_selftest_root());

    /* the fixture directories, under a root of this suite's own inside a fixture */
    $fixture = wgct_selftest_dir('cli-fixture');
    $root = "{$fixture}/root";
    $first = wgct_selftest_dir('one', $root);
    $second = wgct_selftest_dir('one', $root);
    clearstatcache();
    $shaped = fn (string $dir): bool => preg_match('#^' . preg_quote($root, '#') . '/one\.[0-9a-f]{32}$#D', $dir) === 1
        && is_dir($dir) && !is_link($dir) && (fileperms($dir) & 07777) === 0700 && fileowner($dir) === 0;
    wgct_check($t, 'selftest: a fixture directory is <root>/<label>.<32 hex digits>, root\'s, mode 0700, under a root made 0700 when absent; two calls give two directories',
        $shaped($first) && $shaped($second) && $first !== $second && (fileperms($root) & 07777) === 0700
        && str_starts_with($fixture, wgct_selftest_root() . '/cli-fixture.'));
    $refused = function (string $label, string $under): bool {
        try {
            wgct_selftest_dir($label, $under);
        } catch (\RuntimeException $e) {
            return str_contains($e->getMessage(), $under);
        } catch (\InvalidArgumentException $e) {
            return str_contains($e->getMessage(), $label);
        }
        return false;
    };
    mkdir("{$fixture}/loose", 0755);
    chmod("{$fixture}/loose", 0755);
    file_put_contents("{$fixture}/file", '');
    symlink($root, "{$fixture}/link");
    wgct_check($t, 'selftest: a root that is a link, a file or a directory of another mode is refused with its path, and nothing is made in it or through it',
        $refused('one', "{$fixture}/link") && $refused('one', "{$fixture}/file") && $refused('one', "{$fixture}/loose")
        && scandir("{$fixture}/loose") === ['.', '..'] && count((array)scandir($root)) === 4);
    wgct_check($t, 'selftest: a label that could name a path outside the root is refused',
        $refused('../one', $root) && $refused('one/two', $root) && $refused('', $root) && count((array)scandir($root)) === 4);
    $umask = umask(0277);
    try {
        $tight = wgct_selftest_dir('one', "{$fixture}/umask");
    } finally {
        umask($umask);
    }
    clearstatcache();
    wgct_check($t, 'selftest: a root made here and the fixture directory get mode 0700 whatever the umask (0277 here)',
        (fileperms("{$fixture}/umask") & 07777) === 0700 && (fileperms($tight) & 07777) === 0700
        && wgct_selftest_cleanup("{$fixture}/umask") === []);
    mkdir("{$fixture}/outside");
    file_put_contents("{$fixture}/outside/kept", 'kept');
    mkdir("{$first}/sub");
    file_put_contents("{$first}/sub/file", 'x');
    symlink("{$fixture}/outside", "{$first}/sub/link");
    symlink("{$fixture}/outside/kept", "{$second}/link");
    $linked = is_link("{$first}/sub/link") && is_dir("{$first}/sub/link") && is_link("{$second}/link") && is_file("{$second}/link");
    $left = wgct_selftest_cleanup($root);
    clearstatcache();
    wgct_check($t, 'selftest: the cleanup removes the directories made under a root with all they hold and leaves none; a link in them is unlinked and never followed, and a directory made under another root stays',
        $linked && $left === [] && !file_exists($first) && !file_exists($second) && scandir($root) === ['.', '..']
        && file_get_contents("{$fixture}/outside/kept") === 'kept' && is_dir($fixture)
        && wgct_selftest_remove_tree("{$fixture}/absent"));

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
    $rejected = false;
    try {
        wgct_cli_uuid($lower . "\n");
    } catch (\InvalidArgumentException) {
        $rejected = true;
    }
    wgct_check($t, 'cli: a uuid followed by a line break is rejected as not a uuid', $rejected);
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
    wgct_check($t, 'cli: --dry is taken by create, edit, remove, rebind, adopt and ensure-sentinel',
        array_filter(['create', 'edit', 'remove', 'rebind', 'adopt', 'ensure-sentinel'], fn (string $c): bool => !wgct_cli_takes_dry($c)) === []);
    wgct_check($t, 'cli: --dry is refused, not ignored, by apply, reconcile, list, status, measure-mtu and release-holds',
        array_filter(WGCT_CLI_OTHER_COMMANDS, 'wgct_cli_takes_dry') === [] && count(WGCT_CLI_OTHER_COMMANDS) === 6
        && in_array('release-holds', WGCT_CLI_OTHER_COMMANDS, true));
    wgct_check($t, 'cli: a list or measure-mtu failure carries no footer',
        wgct_cli_failure_message('list', 'x', true, '') === 'list failed: x.'
        && wgct_cli_failure_message('measure-mtu', 'x', true, '') === 'measure-mtu failed: x.');
    $row = fn (bool $enforceable, bool $pinned, array $findings): array
        => ['enforceable' => $enforceable, 'pinned' => $pinned, 'findings' => $findings];
    $blocking = [wgct_finding('not-single-peer', '2 peers')];
    wgct_check($t, 'cli: list notes nothing for an enforced tunnel and "(not enforced)" for an unblocked one that is not',
        wgct_cli_state_note($row(true, true, [])) === ''
        && wgct_cli_state_note($row(false, false, [wgct_finding('unbound', 'x')])) === ' (not enforced)');
    wgct_check($t, 'cli: list says a blocked tunnel is skipped by the mirror and the prime, and that its pins stay only when it is pinned',
        wgct_cli_state_note($row(false, true, $blocking)) === ' (blocked: mirror and prime skip it; pins in place)'
        && wgct_cli_state_note($row(false, false, $blocking)) === ' (blocked: mirror and prime skip it)');
    wgct_check($t, 'cli: release-holds logs the gateways it released, by name',
        wgct_release_log_line(['rehearse', 'tun_b'], [], []) === 'deinstall: released rehearse, tun_b');
    wgct_check($t, 'cli: release-holds with no hold record logs "nothing held"',
        wgct_release_log_line([], [], []) === 'deinstall: nothing held');
    wgct_check($t, 'cli: release-holds names the records it forgot without touching their gateways',
        wgct_release_log_line([], ['tun_c'], []) === 'deinstall: nothing held; hold records forgotten, their gateways left as they are: tun_c'
        && wgct_release_log_line(['rehearse'], ['tun_c', 'tun_d'], [])
            === 'deinstall: released rehearse; hold records forgotten, their gateways left as they are: tun_c, tun_d');
    wgct_check($t, 'cli: release-holds names the IPv6 gateways it keeps forced down because their tunnel is not healthy',
        wgct_release_log_line(['tun_a'], [], ['tun_a-ipv6']) === 'deinstall: released tun_a; left forced down (IPv6, its tunnel is not healthy): tun_a-ipv6'
        && wgct_release_log_line([], ['tun_c'], ['tun_a-ipv6', 'tun_b-ipv6'])
            === 'deinstall: nothing released; hold records forgotten, their gateways left as they are: tun_c; left forced down (IPv6, its tunnel is not healthy): tun_a-ipv6, tun_b-ipv6');

    /* tunnel.php's arguments, read by position */
    $taken = fn (bool $json, bool $dry, string $command, array $arguments): array
        => ['selftest' => false, 'json' => $json, 'dry' => $dry, 'command' => $command, 'arguments' => $arguments, 'error' => null];
    $error = fn (array $args): ?string => wgct_cli_parse($args)['error'];
    wgct_check($t, 'parse: --selftest as the only argument asks for the self-tests',
        wgct_cli_parse(['--selftest'])
        === ['selftest' => true, 'json' => false, 'dry' => false, 'command' => '', 'arguments' => [], 'error' => null]);
    $beside = [['--selftest', 'list'], ['--json', '--selftest'], ['--selftest', '--json', 'list'], ['--selftest', '--selftest'],
               ['--json', '--selftest', 'apply', $lower]];
    wgct_check($t, 'parse: --selftest beside anything else is refused and asks for no self-test',
        array_filter($beside, fn (array $a): bool => wgct_cli_parse($a)['selftest']
            || wgct_cli_parse($a)['error'] !== '--selftest takes no other argument') === []);
    wgct_check($t, 'parse: --json and --dry are read before the command, in either order; without them neither is set',
        wgct_cli_parse(['--json', '--dry', 'remove', $lower]) === $taken(true, true, 'remove', [$lower])
        && wgct_cli_parse(['--dry', '--json', 'remove', $lower]) === $taken(true, true, 'remove', [$lower])
        && wgct_cli_parse(['--json', 'list']) === $taken(true, false, 'list', [])
        && wgct_cli_parse(['list']) === $taken(false, false, 'list', []));
    $unknown = wgct_cli_parse(['--verbose', '--json', 'list']);
    wgct_check($t, 'parse: an unknown option and an option given twice are refused; a --json among the leading options still shapes the refusal',
        $unknown['error'] === 'unknown option --verbose' && $unknown['json'] === true
        && $error(['--json', '--json', 'list']) === '--json is given twice' && $error(['--dry', '--dry', 'remove', $lower]) === '--dry is given twice'
        && $error(['--', 'list']) === 'unknown option --');
    wgct_check($t, 'parse: a word after the command is its argument, never an option, whatever it starts with',
        wgct_cli_parse(['--json', 'apply', '--selftest']) === $taken(true, false, 'apply', ['--selftest'])
        && wgct_cli_parse(['--json', 'remove', '--dry']) === $taken(true, false, 'remove', ['--dry'])
        && wgct_cli_parse(['measure-mtu', '--json', '--dry']) === $taken(false, false, 'measure-mtu', ['--json', '--dry'])
        && wgct_cli_parse(['--json', 'rebind', '-x', '--json', '--selftest']) === $taken(true, false, 'rebind', ['-x', '--json', '--selftest']));
    wgct_check($t, 'parse: `apply UUID` has one argument (its MODE absent) and `apply UUID \'\'` two (an empty MODE): none is added or dropped',
        wgct_cli_parse(['--json', 'apply', $lower]) === $taken(true, false, 'apply', [$lower])
        && wgct_cli_parse(['--json', 'apply', $lower, '']) === $taken(true, false, 'apply', [$lower, ''])
        && wgct_cli_parse(['--json', 'apply']) === $taken(true, false, 'apply', []));
    wgct_check($t, 'parse: rebind keeps an empty third argument (no stale route), and an empty argument anywhere',
        wgct_cli_parse(['--json', 'rebind', $lower, 'WAN_A', '']) === $taken(true, false, 'rebind', [$lower, 'WAN_A', ''])
        && wgct_cli_parse(['--json', 'rebind', '', '', '']) === $taken(true, false, 'rebind', ['', '', '']));
    wgct_check($t, 'parse: more arguments than the command takes are refused, an option word after a command without arguments among them',
        $error(['--json', 'remove', $lower, 'x']) === 'remove takes at most 1 argument, 2 given'
        && $error(['--json', 'rebind', $lower, 'WAN_A', '', 'x']) === 'rebind takes at most 3 arguments, 4 given'
        && $error(['--json', 'apply', $lower, 'tunnel', '']) === 'apply takes at most 2 arguments, 3 given'
        && $error(['list', '--json']) === 'list takes no argument, 1 given' && wgct_cli_parse(['list', '--json'])['json'] === false
        && $error(['--json', 'ensure-sentinel', '']) === 'ensure-sentinel takes no argument, 1 given');
    wgct_check($t, 'parse: no command and an unknown command are refused',
        $error([]) === 'no command' && $error(['--json']) === 'no command' && $error(['--json', 'bogus', $lower]) === 'unknown command bogus'
        && $error(['']) === 'unknown command ' && $error(['-json', 'list']) === 'unknown command -json');
    $dryApply = wgct_cli_parse(['--json', '--dry', 'apply', $lower]);
    wgct_check($t, 'parse: --dry on a command without a dry run is refused, and the refusal says it was a dry run',
        $dryApply['error'] === '--dry applies to the write actions only (create, edit, remove, rebind, adopt, ensure-sentinel); apply has no dry run'
        && $dryApply['dry'] === true && $dryApply['json'] === true
        && array_filter(WGCT_CLI_OTHER_COMMANDS, fn (string $c): bool => $error(['--dry', $c]) === null) === []
        && array_filter(WGCT_CLI_DRY_COMMANDS, fn (string $c): bool => $error(['--dry', $c]) !== null) === []);
    $status = fn (array $args): int => wgct_cli_refused_status(wgct_cli_parse($args));
    wgct_check($t, 'parse: a refusal names the known command after the options, also beside a refused option; an unknown word is no command',
        wgct_cli_parse(['release-holds', 'x'])['command'] === 'release-holds' && wgct_cli_parse(['--bogus', 'release-holds'])['command'] === 'release-holds'
        && wgct_cli_parse(['--dry', 'release-holds'])['command'] === 'release-holds' && wgct_cli_parse(['--json', '--json', 'list'])['command'] === 'list'
        && wgct_cli_parse(['--bogus', 'bogus'])['command'] === '' && wgct_cli_parse(['--bogus'])['command'] === '');
    wgct_check($t, 'parse: a refused argument list exits 2 by hand and 0 with --json; release-holds, the package removal\'s, exits 0 either way',
        $status(['list', 'x']) === 2 && $status(['--bogus', 'list']) === 2 && $status([]) === 2 && $status(['--dry', 'apply', $lower]) === 2
        && $status(['--json', 'list', 'x']) === 0 && $status(['--json']) === 0
        && $status(['release-holds', 'x']) === 0 && $status(['--dry', 'release-holds']) === 0 && $status(['--bogus', 'release-holds']) === 0
        && $error(['--json', 'release-holds']) === null && $error(['release-holds']) === null);
    wgct_check($t, 'apply: `apply UUID` hands on no MODE (null), `apply UUID MODE` the word, and `apply UUID \'\'` the empty word, which is not null',
        wgct_cli_apply_mode(wgct_cli_parse(['--json', 'apply', $lower])['arguments']) === null
        && wgct_cli_apply_mode(wgct_cli_parse(['--json', 'apply', $lower, 'tunnel'])['arguments']) === 'tunnel'
        && wgct_cli_apply_mode(wgct_cli_parse(['--json', 'apply', $lower, ''])['arguments']) === ''
        && wgct_cli_apply_mode([]) === null);
    $commands = array_merge(WGCT_CLI_DRY_COMMANDS, WGCT_CLI_OTHER_COMMANDS);
    sort($commands);
    $known = array_keys(WGCT_CLI_ARGUMENTS);
    sort($known);
    wgct_check($t, 'parse: the commands with an argument count are the write actions and the other commands, each once', $known === $commands);
    /*
     * Every configd action that hands caller values to tunnel.php, read from the installed action file: its fixed
     * words and its number of %s slots (wgct_cli_selftest_actions()). configd fills a slot the caller left out with
     * '' and refuses a parameter beyond the slots itself, so tunnel.php gets the fixed words and then exactly as
     * many values as the action has slots, whatever they are. An action whose parameters line holds more slots than
     * its command takes arguments, or a word that is no slot, fails its case here.
     */
    $actionFile = '/usr/local/opnsense/service/conf/actions.d/actions_wgclienttunnels.conf';
    $actions = wgct_cli_selftest_actions(is_readable($actionFile) ? (string)file_get_contents($actionFile) : '');
    wgct_check($t, 'parse: the installed action file runs tunnel.php from ten actions, each with --json before its command',
        array_keys($actions) === ['apply', 'apply_mode', 'remove', 'remove_dry', 'rebind', 'adopt', 'adopt_dry', 'ensure_sentinel',
            'ensure_sentinel_dry', 'measure_mtu']
        && array_filter($actions, fn (array $a): bool => ($a['words'][0] ?? '') !== '--json') === []);
    foreach ($actions as $action => ['words' => $words, 'slots' => $slots, 'parameters' => $parameters]) {
        $isDry = in_array('--dry', $words, true);
        $command = $words === [] ? '' : $words[count($words) - 1];
        $ok = $slots !== null && $slots <= (WGCT_CLI_ARGUMENTS[$command] ?? -1);
        for ($given = 0; $ok && $given <= $slots; $given++) {
            foreach (['--selftest', '--json', '--dry', '-x', $lower] as $value) {
                $values = array_merge(array_fill(0, $given, $value), array_fill(0, $slots - $given, ''));
                $ok = $ok && wgct_cli_parse(array_merge($words, $values)) === $taken(true, $isDry, $command, $values);
            }
        }
        wgct_check($t, "parse: configd's {$action} action (parameters \"{$parameters}\"): %s slots only, no more than its command takes, and "
            . 'given or left out they arrive as the command\'s arguments and change no option', $ok);
    }
    $slotsOf = fn (string $conf): array => array_column(wgct_cli_selftest_actions($conf), 'slots');
    wgct_check($t, 'parse: the action file is read by section: the words after `wgct.sh tunnel`, the %s slots of its parameters line (none for a word that is no slot), and no other action',
        wgct_cli_selftest_actions("[start]\ncommand:/x/wgct.sh start\nparameters:\n\n[rebind]\n# a comment\ncommand:/x/wgct.sh tunnel --json rebind\nparameters:%s %s %s\ntype:script_output\n")
            === ['rebind' => ['words' => ['--json', 'rebind'], 'slots' => 3, 'parameters' => '%s %s %s']]
        && $slotsOf("[a]\ncommand:/x/wgct.sh tunnel --json adopt\nparameters:\n") === [0]
        && $slotsOf("[a]\ncommand:/x/wgct.sh tunnel --json adopt\nparameters: %s \n") === [1]
        && $slotsOf("[a]\ncommand:/x/wgct.sh tunnel --json adopt\nparameters:%s --dry\n") === [null]
        && $slotsOf("[a]\ncommand:/x/wgct.sh tunnel --json adopt\nparameters:'%s'\n") === [null]
        && wgct_cli_selftest_actions('') === []);

    /* the other entry scripts' --selftest (lib/selftest.php), on arguments without the script name */
    wgct_check($t, 'selftest argument: --selftest as the only argument asks for the self-tests', wgct_selftest_requested(['--selftest']) === true);
    wgct_check($t, 'selftest argument: without --selftest none is asked for, whatever else is given',
        wgct_selftest_requested([]) === false && wgct_selftest_requested(['--dry']) === false
        && wgct_selftest_requested(['--settle=0', '--dry']) === false && wgct_selftest_requested(['--selftest=1']) === false);
    wgct_check($t, 'selftest argument: --selftest beside anything else is refused, wherever it stands',
        wgct_selftest_requested(['--selftest', '--dry']) === null && wgct_selftest_requested(['--dry', '--selftest']) === null
        && wgct_selftest_requested(['--selftest', '--selftest']) === null && wgct_selftest_requested(['x', '--selftest']) === null
        && wgct_selftest_requested(['--selftest', '']) === null);
    return wgct_tally_report('cli', $t);
}

/**
 * The configd actions of an action file that run tunnel.php, for the self-test. Pure.
 *
 * @param string $conf the text of actions_wgclienttunnels.conf
 * @return array<string, array{words: list<string>, slots: ?int, parameters: string}> action name => the words its
 *         command line hands to tunnel.php (those after `wgct.sh tunnel`), the number of %s slots of its parameters
 *         line, null when that line holds anything but %s words, and the line's text
 */
function wgct_cli_selftest_actions(string $conf): array {
    $sections = [];
    $name = null;
    foreach (preg_split('/\R/', $conf) ?: [] as $line) {
        if (preg_match('/^\[([a-z_.]+)\]\s*\z/', $line, $m) === 1) {
            $name = $m[1];
            $sections[$name] = ['command' => '', 'parameters' => ''];
        } elseif ($name !== null) {
            foreach (['command', 'parameters'] as $key) {
                if (str_starts_with($line, $key . ':')) {
                    $sections[$name][$key] = trim(substr($line, strlen($key) + 1));
                }
            }
        }
    }
    $actions = [];
    foreach ($sections as $name => $section) {
        if (preg_match('/\/wgct\.sh tunnel\b(.*)\z/', $section['command'], $m) !== 1) {
            continue;
        }
        $slots = preg_split('/\s+/', $section['parameters'], -1, PREG_SPLIT_NO_EMPTY) ?: [];
        $actions[(string)$name] = [
            'words' => preg_split('/\s+/', $m[1], -1, PREG_SPLIT_NO_EMPTY) ?: [],
            'slots' => array_filter($slots, fn (string $word): bool => $word !== '%s') === [] ? count($slots) : null,
            'parameters' => $section['parameters'],
        ];
    }
    return $actions;
}

/**
 * Every self-test suite of the plugin, in the order their summaries are printed (wgct_selftest_run()).
 *
 * @return int 0 when every suite passes
 */
function wgct_cli_selftest(): int {
    require_once __DIR__ . '/render.php';
    require_once __DIR__ . '/edit.php';
    require_once __DIR__ . '/prime.php';
    return wgct_selftest_run([
        'addr' => 'wgct_addr_selftest', 'cli' => 'wgct_cli_own_selftest', 'tunnels' => 'wgct_tunnels_selftest',
        'render' => 'wgct_render_selftest', 'wgconf' => 'wgct_wgconf_selftest', 'refs' => 'wgct_refs_selftest',
        'actions' => 'wgct_actions_selftest', 'mtu' => 'wgct_mtu_selftest', 'apply' => 'wgct_apply_selftest',
        'view' => 'wgct_view_selftest', 'edit' => 'wgct_edit_selftest', 'prime' => 'wgct_prime_selftest',
        'engine' => 'wgct_engine_selftest',
    ]);
}
