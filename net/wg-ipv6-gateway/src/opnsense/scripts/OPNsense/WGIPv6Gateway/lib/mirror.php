<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Health mirror library. The decisions are pure functions of a snapshot:
 *
 *   config.enabled    bool, plugin enabled AND the health_mirror switch
 *   config.gateways   name => [uuid, ipprotocol, interface, disabled, force_down,
 *                              losshigh, losslow, time_period]
 *   config.underlays  IPv4 tunnel gateway name => WAN gateway name
 *   config.pairs      IPv4 tunnel gateway name => its IPv6 gateway name
 *   config.held       gateway names held down by pass 1
 *   config.held_raw   sorted gateway UUIDs as stored in the model
 *   live.status       name => gateway_status.php status, null when unavailable
 *   live.loss         name => dpinger loss percent, null without data
 *   live.sock_age     name => dpinger socket age in seconds, null when absent
 *
 * Collectors build the snapshot; wgipv6_locked_commit() is the only way the
 * mirror writes config (spec 2026-09-24 section 4.6).
 */

use OPNsense\Core\Config;

require_once __DIR__ . '/tunnels.php';

/* Used only when a gateway has no time_period configured. */
const SETTLE_FALLBACK_SECONDS = 60;

function logMsg($tag, $msg) {
    syslog(LOG_NOTICE, "[$tag] $msg");
}

/**
 * Seconds since a dpinger control socket was created, or null if it is absent.
 *
 * @param string $sock path to the dpinger control socket
 * @return int|null age in seconds, null when the socket does not exist
 */
function wgipv6_socket_age($sock) {
    clearstatcache(true, $sock);
    $mtime = @filemtime($sock);
    if ($mtime === false) {
        return null;
    }
    return max(0, time() - $mtime);
}

/**
 * Decide whether the IPv6 gateway should be forced down, given the paired IPv4
 * gateway's current loss and its own loss watermarks. Mirrors dpinger's
 * hysteresis: trip at losshigh, recover at losslow, hold in between.
 *
 * @param int|null $lossVal     current IPv4 loss percent, or null if no data
 * @param int      $lossHigh    high watermark (force down at/above)
 * @param int      $lossLow     low watermark (recover at/below)
 * @param bool     $currentDown current force_down state (hysteresis memory)
 * @param bool     $settled     false while dpinger has not filled its averaging
 *                              window, which makes a healthy reading unreliable
 * @return bool    true => force_down
 */
function wgipv6_decide_down($lossVal, $lossHigh, $lossLow, $currentDown, $settled = true) {
    if ($lossVal === null) {
        return true;                // no dpinger data => treat tunnel as down
    }
    if ($lossVal >= $lossHigh) {
        return true;                // at/above high watermark => down
    }
    if ($lossVal <= $lossLow) {
        // A just-restarted dpinger reports 0% because it has no samples yet.
        // Trust "down" from it, never "up": hold instead of releasing.
        return $settled ? false : $currentDown;
    }
    return $currentDown;            // between watermarks => hold (hysteresis)
}

/**
 * Is a WAN gateway status "down" for a downloss gateway group? Same semantics
 * as GatewayGroups::gatewayIsUp('downloss', ...): latency alone never counts.
 *
 * @param string|null $status gateway_status.php status, null when absent
 * @return bool true => down
 */
function wgipv6_wan_status_down($status) {
    return $status === null || in_array($status, ['down', 'force_down', 'loss', 'delay+loss'], true);
}

/**
 * Underlay decision for one tunnel.
 *
 * @param array $wan  ['disabled' => bool, 'force_down' => bool,
 *                     'status' => string|null, 'settled' => bool]
 * @param bool  $held this pass currently holds the tunnel down
 * @return bool true => the tunnel must be held down
 */
function wgipv6_decide_underlay(array $wan, $held) {
    if ($wan['disabled'] || $wan['force_down'] || wgipv6_wan_status_down($wan['status'])) {
        return true;
    }
    // WAN reads up. A dpinger restarted by the last reconfigure reads up with
    // no samples, so only a settled reading may release a held tunnel.
    return $wan['settled'] ? false : $held;
}

/**
 * Current dpinger loss for a gateway, read from its control socket.
 *
 * @param string $name gateway name
 * @return int|null loss percent, null when the socket is absent or unreadable
 */
function wgipv6_read_loss($name) {
    $sock = "/var/run/dpinger_{$name}.sock";
    if (!file_exists($sock)) {
        return null;
    }
    $fp = @stream_socket_client("unix://{$sock}", $errno, $errstr, 1);
    if (!$fp) {
        return null;
    }
    fwrite($fp, "\n");
    $line = fgets($fp, 1024);
    fclose($fp);
    if (!$line) {
        return null;
    }
    $parts = preg_split('/\s+/', trim($line));
    $loss = end($parts);
    return is_numeric($loss) ? (int)$loss : null;
}

/**
 * Live status of every monitored gateway, as the GUI and the groups see it.
 *
 * @return array|null name => status string, null when status is unavailable
 */
function wgipv6_gateway_status() {
    $json = shell_exec('/usr/local/opnsense/scripts/routes/gateway_status.php');
    $data = is_string($json) ? json_decode($json, true) : null;
    if (!is_array($data)) {
        return null;
    }
    $status = [];
    foreach ($data as $name => $row) {
        $status[$name] = (string)($row['status'] ?? '');
    }
    return $status;
}

/**
 * Replay the gateway alarm OPNsense dropped for our own force_down changes.
 *
 * The reconfigure below restarts dpinger and SIGHUPs gateway_watcher, which
 * then raises "none -> force_down" (or back) for the gateways we changed and
 * calls the routes.alarm action. That action is
 * `flock -n -E 0 /tmp/filter_reload_gateway.lock rc.routing_configure alarm`:
 * non-blocking, so while we still hold the lock it silently does nothing. The
 * filter is then never rebuilt with the new status of dpinger-monitored
 * gateways -- their status comes from the watcher, which had not re-read
 * config when our reconfigure generated the ruleset -- and 20-recover never
 * kills their states. Observed 2026-09-22: a forced-down tunnel stayed the
 * group's route-to until an unrelated reconfigure.
 *
 * So, lock released: wait until gateway status shows what we wrote, then run
 * the alarm path ourselves, blocking on the lock. It reconfigures routing
 * without restarting monitors, runs the monitor syshooks (state kill) for the
 * named gateways, and rebuilds the filter.
 *
 * @param array $expected name => bool force_down for every gateway we changed
 */
function wgipv6_replay_alarm(array $expected, $logTag) {
    $deadline = time() + 20;
    do {
        $status = wgipv6_gateway_status() ?? [];
        $pending = [];
        foreach ($expected as $name => $down) {
            if (isset($status[$name]) && (($status[$name] === 'force_down') !== $down)) {
                $pending[] = $name;
            }
        }
        if (empty($pending)) {
            break;
        }
        sleep(1);
    } while (time() < $deadline);
    if (!empty($pending)) {
        logMsg($logTag, 'gateway status still stale for ' . implode(',', $pending) . ' after 20s; replaying alarm anyway');
    }
    /*
     * Run it through configd, never exec() from here: PHP opens files without
     * close-on-exec, so anything this process starts inherits its open lock
     * files -- including the single-instance lock -- and a daemon the
     * reconfigure (re)starts keeps them for as long as it lives. Both happened
     * on 2026-09-22: a restarted filterlog held first the gateway lock
     * (blocking every reconfigure, dropping every alarm) and then this
     * script's own lock (every later tick exited at the guard). configd starts
     * the action from its own process, which holds neither.
     */
    $result = trim((new OPNsense\Core\Backend())->configdpRun(
        'wgipv6gateway replay_alarm',
        [implode(',', array_keys($expected))]
    ));
    if ($result !== 'OK') {
        logMsg($logTag, 'alarm replay for ' . implode(',', array_keys($expected)) . " failed: {$result}");
    }
}

/**
 * Loss watermarks for a gateway, normalised. Empty/zero losshigh means the
 * gateway has no loss alarm, so only a fully-dead path counts as down.
 *
 * @param array $row gateway row from wgipv6_collect_config()
 * @return array [int $lossLow, int $lossHigh]
 */
function wgipv6_watermarks(array $row) {
    $high = (int)$row['losshigh'];
    if ($high <= 0) {
        $high = 100;
    }
    $low = (int)$row['losslow'];
    if ($low < 0 || $low > $high) {
        $low = $high;
    }
    return [$low, $high];
}

/**
 * How long this gateway's dpinger needs before a healthy reading means
 * anything: its own loss averaging window, unless overridden.
 *
 * @param array    $row      gateway row
 * @param int|null $override --settle=N, or null to use the gateway's own
 * @return int seconds
 */
function wgipv6_settle_window(array $row, $override) {
    if ($override !== null) {
        return $override;
    }
    $window = (int)$row['time_period'];
    return $window > 0 ? $window : SETTLE_FALLBACK_SECONDS;
}

/**
 * Is this gateway's dpinger old enough for a healthy reading to count?
 *
 * @param array    $row      gateway row
 * @param int|null $age      dpinger socket age in seconds, null when absent
 * @param int|null $override --settle=N
 * @return array [bool $settled, int|null $ageSeconds, int $windowSeconds]
 */
function wgipv6_settled(array $row, $age, $override) {
    $window = wgipv6_settle_window($row, $override);
    return [($window === 0) || ($age !== null && $age >= $window), $age, $window];
}

/**
 * Everything the decisions read from config, derived from core (spec 4.1).
 * Builds fresh models, so called after Config::lock() it reflects config.xml
 * as it is now.
 *
 * @return array ['enabled', 'gateways', 'underlays', 'pairs',
 *                'held' => names, 'held_raw' => sorted uuids from config]
 */
function wgipv6_collect_config() {
    $mdl = new OPNsense\WGIPv6Gateway\WGIPv6Gateway();
    $core = wgipv6_core_snapshot();
    $inputs = wgipv6_mirror_inputs(wgipv6_derive($core, wgipv6_split_csv((string)$mdl->managed)));
    $nameByUuid = [];
    foreach ($core['gateways'] as $name => $g) {
        $nameByUuid[$g['uuid']] = $name;
    }
    $heldRaw = wgipv6_split_csv((string)$mdl->held);
    sort($heldRaw);
    $held = [];
    foreach ($heldRaw as $uuid) {
        if (isset($nameByUuid[$uuid])) {
            $held[] = $nameByUuid[$uuid];
        }
    }
    return [
        'enabled' => (string)$mdl->enabled === '1' && (string)$mdl->health_mirror === '1',
        'gateways' => $core['gateways'],
        'underlays' => $inputs['underlays'],
        'pairs' => $inputs['pairs'],
        'held' => $held,
        'held_raw' => $heldRaw,
    ];
}

/**
 * @param array $heldNames name => true (the planner's held set)
 * @param array $gateways  name => row with 'uuid'
 * @return array sorted gateway uuids; names with no gateway drop out
 */
function wgipv6_held_uuids(array $heldNames, array $gateways) {
    $uuids = [];
    foreach (array_keys($heldNames) as $name) {
        if (isset($gateways[$name])) {
            $uuids[] = $gateways[$name]['uuid'];
        }
    }
    sort($uuids);
    return $uuids;
}

/**
 * Serialize the held set into the plugin model when it differs from config.
 * Call only inside wgipv6_locked_commit(), with $config from a collection
 * made under that lock.
 *
 * @param array $heldNames name => true
 * @param array $config    wgipv6_collect_config() made under the lock
 * @return bool whether the model was serialized (the caller must save)
 */
function wgipv6_commit_held(array $heldNames, array $config) {
    $uuids = wgipv6_held_uuids($heldNames, $config['gateways']);
    if ($uuids === $config['held_raw']) {
        return false;
    }
    $mdl = new OPNsense\WGIPv6Gateway\WGIPv6Gateway();
    $mdl->held = implode(',', $uuids);
    $mdl->serializeToConfig();
    return true;
}

/**
 * Everything the decisions read from the running system. Runs
 * gateway_status.php as a subprocess. Config::lock() only holds a shared lock
 * after its reload, so a plain reader would still succeed while this process
 * holds it -- the hazard is starting or waiting on anything that may itself
 * write config: it would wait for exclusive access while this process waits
 * for it to finish. So this must never be called while holding
 * Config::lock(); simplest is to call it only outside lock()/unlock().
 *
 * @return array see the file header
 */
function wgipv6_collect_live() {
    $loss = [];
    $age = [];
    foreach (glob('/var/run/dpinger_*.sock') ?: [] as $sock) {
        $name = substr(basename($sock, '.sock'), strlen('dpinger_'));
        $loss[$name] = wgipv6_read_loss($name);
        $age[$name] = wgipv6_socket_age($sock);
    }
    return ['status' => wgipv6_gateway_status(), 'loss' => $loss, 'sock_age' => $age];
}

/**
 * Decide every force_down change for one tick. Pure: reads only its arguments.
 *
 * @param array    $config         wgipv6_collect_config()
 * @param array    $live           wgipv6_collect_live()
 * @param array    $held           name => true, tunnels pass 1 holds down
 * @param int|null $settleOverride --settle=N
 * @return array ['changes' => name => bool force_down, 'held' => name => true,
 *                'held_changed' => bool, 'report' => string[], 'log' => string[]]
 */
function wgipv6_plan(array $config, array $live, array $held, $settleOverride) {
    $gws = $config['gateways'];
    $forced = [];               // force_down as it stands after the decisions so far
    foreach ($gws as $name => $row) {
        $forced[$name] = $row['force_down'];
    }
    $changes = [];
    $report = [];
    $log = [];
    $heldChanged = false;

    /* ---- pass 1: underlay ---- */
    if ($live['status'] === null) {
        /* Without status every WAN would read absent and every tunnel would be
         * forced down on a transient read failure. Skip the pass this tick. */
        $log[] = 'gateway status unavailable; underlay pass skipped this tick';
        $report[] = 'underlay: gateway status unavailable, pass skipped';
    } else {
        foreach ($config['underlays'] as $tunnelName => $wanName) {
            $tunnel = $gws[$tunnelName] ?? null;
            if ($tunnel === null || $tunnel['disabled']) {
                continue;
            }
            $wanGw = $gws[$wanName] ?? null;
            [$wanSettled, $wanAge, $wanWindow] = $wanGw !== null
                ? wgipv6_settled($wanGw, $live['sock_age'][$wanName] ?? null, $settleOverride)
                : [true, null, 0];
            $wan = [
                'disabled' => $wanGw === null || $wanGw['disabled'],
                'force_down' => $wanGw !== null && $wanGw['force_down'],
                'status' => $live['status'][$wanName] ?? null,
                'settled' => $wanSettled,
            ];
            $isHeld = isset($held[$tunnelName]);
            $manual = $tunnel['force_down'] && !$isHeld;
            $down = wgipv6_decide_underlay($wan, $isHeld);

            $wanDesc = $wan['disabled'] ? 'disabled' : ($wan['force_down'] ? 'force_down'
                : ($wan['status'] ?? 'absent') . ($wanSettled ? '' : " settling {$wanAge}/{$wanWindow}s"));
            $report[] = sprintf(
                'underlay %-18s on %-12s WAN %-24s -> %s',
                $tunnelName,
                $wanName,
                $wanDesc,
                $manual ? 'manual force_down, left alone' : ($down ? 'held down' : 'up')
            );
            if ($manual) {
                continue;
            }
            if ($down && !$isHeld) {
                $held[$tunnelName] = true;
                $heldChanged = true;
                $forced[$tunnelName] = true;
                $changes[$tunnelName] = true;
                $log[] = "{$tunnelName}: force_down (underlay {$wanName} {$wanDesc})";
            } elseif (!$down && $isHeld) {
                unset($held[$tunnelName]);
                $heldChanged = true;
                $forced[$tunnelName] = false;
                $changes[$tunnelName] = false;
                $log[] = "{$tunnelName}: online (underlay {$wanName} {$wanDesc})";
            }
        }
        /* forget tunnels that no longer exist */
        foreach (array_keys($held) as $name) {
            if (!isset($gws[$name])) {
                unset($held[$name]);
                $heldChanged = true;
            }
        }
    }

    /* ---- pass 2: IPv6 follows its own IPv4 tunnel ---- */
    foreach ($config['pairs'] as $ipv4Name => $ipv6Name) {
        $ipv4 = $gws[$ipv4Name] ?? null;
        $gw6 = $gws[$ipv6Name] ?? null;
        /*
         * A disabled gateway is already out of the default-gateway election and out
         * of every gateway group, so force_down would not change its effect, and
         * writing it would reconfigure routing for nothing. Leave it alone.
         */
        if ($ipv4 === null || $gw6 === null || $gw6['disabled']) {
            continue;
        }
        [$lossLow, $lossHigh] = wgipv6_watermarks($ipv4);
        [$settled, $sockAge, $settleWindow] = wgipv6_settled(
            $ipv4,
            $live['sock_age'][$ipv4Name] ?? null,
            $settleOverride
        );
        $lossVal = $live['loss'][$ipv4Name] ?? null;
        $currentDown = $forced[$ipv6Name];
        $ipv4Forced = $forced[$ipv4Name];     // includes pass 1's decisions
        $down = $ipv4Forced || wgipv6_decide_down($lossVal, $lossHigh, $lossLow, $currentDown, $settled);
        $lossStr = $lossVal === null ? 'no-data' : "{$lossVal}% loss";
        $why = $ipv4Forced ? 'IPv4 force_down' : ($down ? 'IPv4 unhealthy' : 'IPv4 healthy');

        $report[] = sprintf(
            'ipv6     %-22s force_down %s -> %s  (%s; %s %s%s)',
            $ipv6Name,
            $currentDown ? '1' : '0',
            $down ? '1' : '0',
            $why,
            $ipv4Name,
            $lossStr,
            $settled ? '' : "; settling {$sockAge}/{$settleWindow}s"
        );
        if ($down !== $currentDown) {
            $forced[$ipv6Name] = $down;
            $changes[$ipv6Name] = $down;
            $log[] = sprintf(
                '%s: %s (%s; %s %s; watermarks %d/%d%s)',
                $ipv6Name,
                $down ? 'force_down' : 'online',
                $why,
                $ipv4Name,
                $lossStr,
                $lossLow,
                $lossHigh,
                $settled ? '' : "; dpinger settling {$sockAge}/{$settleWindow}s"
            );
        }
    }

    return [
        'changes' => $changes,
        'held' => $held,
        'held_changed' => $heldChanged,
        'report' => $report,
        'log' => $log,
    ];
}

/**
 * Write planned force_down values into a Gateways model.
 *
 * @param \OPNsense\Routing\Gateways $mdl     freshly built after Config::lock()
 * @param array                      $changes name => bool force_down
 */
function wgipv6_apply_changes($mdl, array $changes) {
    foreach ($mdl->gateway_item->iterateItems() as $gw) {
        $name = (string)$gw->name;
        if (array_key_exists($name, $changes)) {
            $gw->force_down = $changes[$name] ? '1' : '0';
        }
    }
}

/**
 * The only way the mirror writes config. Config::lock() re-reads config.xml, so
 * $mutate builds its models from what is on disk now, never from a snapshot
 * loaded before a concurrent GUI save. lock() only holds a shared lock after
 * that reload, so a plain reader would still succeed inside $mutate -- the
 * real hazard is a writer (a configd action, another script's lock()/save(),
 * plugins_configure): it would wait for exclusive access while this process
 * waits for it to finish. Never start or wait on anything that may write
 * config inside $mutate; simplest is to start or wait on nothing at all.
 *
 * @param callable $mutate builds models, changes and serializes them; returns an
 *                         array whose 'save' key says whether to save
 * @return array whatever $mutate returned
 */
function wgipv6_locked_commit(callable $mutate) {
    $cfg = Config::getInstance();
    $cfg->lock();
    try {
        $result = $mutate();
        if (!empty($result['save'])) {
            $cfg->save();
        }
        return $result;
    } finally {
        $cfg->unlock();
    }
}

/**
 * Run the decision self-tests. No config, no sockets, no processes.
 *
 * @return int exit code, 0 when every case passes
 */
function wgipv6_selftest() {
    $fail = 0;
    $total = 0;

    /* ---- wgipv6_decide_down / wgipv6_decide_underlay (unchanged cases) ---- */
    $cases = [
        // description, lossVal, high, low, currentDown, settled, expectedDown
        ['no data => down',              null, 20,  10,  false, true,  true],
        ['no data => down (was up)',     null, 20,  10,  true,  true,  true],
        ['0% => up',                     0,    20,  10,  false, true,  false],
        ['at low (10) => up',            10,   20,  10,  true,  true,  false],
        ['below low, was down => up',    5,    20,  10,  true,  true,  false],
        ['in band (15), was up => up',   15,   20,  10,  false, true,  false],
        ['in band (15), was down => dn', 15,   20,  10,  true,  true,  true],
        ['at high (20) => down',         20,   20,  10,  false, true,  true],
        ['above high (30) => down',      30,   20,  10,  false, true,  true],
        ['no threshold: 50% => up',      50,   100, 100, false, true,  false],
        ['no threshold: 100% => down',   100,  100, 100, false, true,  true],
        // Settle guard: a fresh dpinger may trip down, but may not release.
        ['unsettled 0%, was down => dn', 0,    20,  10,  true,  false, true],
        ['unsettled 0%, was up => up',   0,    20,  10,  false, false, false],
        ['unsettled 100% => down',       100,  20,  10,  false, false, true],
        ['unsettled no data => down',    null, 20,  10,  false, false, true],
        ['unsettled in band => hold',    15,   20,  10,  true,  false, true],
    ];
    $up = ['disabled' => false, 'force_down' => false, 'status' => 'none', 'settled' => true];
    $underlayCases = [
        // description, wan, held, expectedDown
        ['WAN up, settled => up',              $up, false, false],
        ['WAN up, settled, was held => up',    $up, true,  false],
        ['WAN delay only => up',               ['status' => 'delay'] + $up, false, false],
        ['WAN disabled => down',               ['disabled' => true] + $up, false, true],
        ['WAN force_down => down',             ['force_down' => true] + $up, false, true],
        ['WAN absent from status => down',     ['status' => null] + $up, false, true],
        ['WAN down => down',                   ['status' => 'down'] + $up, false, true],
        ['WAN loss => down',                   ['status' => 'loss'] + $up, false, true],
        ['WAN delay+loss => down',             ['status' => 'delay+loss'] + $up, false, true],
        ['WAN up, unsettled, held => hold',    ['settled' => false] + $up, true,  true],
        ['WAN up, unsettled, not held => up',  ['settled' => false] + $up, false, false],
    ];
    foreach ($cases as $c) {
        [$desc, $lv, $hi, $lo, $cur, $settled, $exp] = $c;
        $got = wgipv6_decide_down($lv, $hi, $lo, $cur, $settled);
        $fail += $got === $exp ? 0 : 1;
        $total++;
        printf("[%s] ipv6: %s\n", $got === $exp ? 'PASS' : 'FAIL', $desc);
    }
    foreach ($underlayCases as $c) {
        [$desc, $wan, $held, $exp] = $c;
        $got = wgipv6_decide_underlay($wan, $held);
        $fail += $got === $exp ? 0 : 1;
        $total++;
        printf("[%s] underlay: %s\n", $got === $exp ? 'PASS' : 'FAIL', $desc);
    }

    /* ---- wgipv6_plan over synthetic snapshots ---- */
    $row = function (array $o = []) {
        return $o + [
            'uuid' => 'u', 'ipprotocol' => 'inet', 'interface' => 'optX',
            'disabled' => false, 'force_down' => false,
            'losshigh' => '20', 'losslow' => '10', 'time_period' => '60',
        ];
    };
    $config = function (array $gwOverrides = []) use ($row) {
        $gws = [
            'WAN_A' => $row(),
            'tun_a' => $row(),
            'tun_a-ipv6' => $row(['ipprotocol' => 'inet6']),
        ];
        foreach ($gwOverrides as $name => $o) {
            $gws[$name] = $row($o + $gws[$name]);
        }
        return [
            'enabled' => true,
            'gateways' => $gws,
            'underlays' => ['tun_a' => 'WAN_A'],
            'pairs' => ['tun_a' => 'tun_a-ipv6'],
        ];
    };
    $live = function (array $o = []) {
        return $o + [
            'status' => ['WAN_A' => 'none', 'tun_a' => 'none'],
            'loss' => ['WAN_A' => 0, 'tun_a' => 0],
            'sock_age' => ['WAN_A' => 600, 'tun_a' => 600],
        ];
    };
    $planCases = [
        // description, config, live, held (names), expected changes, expected held (names)
        ['healthy => no change',
            $config(), $live(), [], [], []],
        ['WAN down => tunnel held, IPv6 follows',
            $config(), $live(['status' => ['WAN_A' => 'down', 'tun_a' => 'none']]), [],
            ['tun_a' => true, 'tun_a-ipv6' => true], ['tun_a']],
        ['WAN back, settled => release tunnel and IPv6',
            $config(['tun_a' => ['force_down' => true], 'tun_a-ipv6' => ['force_down' => true]]),
            $live(), ['tun_a'],
            ['tun_a' => false, 'tun_a-ipv6' => false], []],
        ['WAN back, unsettled => keep holding',
            $config(['tun_a' => ['force_down' => true], 'tun_a-ipv6' => ['force_down' => true]]),
            $live(['sock_age' => ['WAN_A' => 5, 'tun_a' => 600]]), ['tun_a'],
            [], ['tun_a']],
        ['manual force_down on tunnel => left alone, IPv6 follows it',
            $config(['tun_a' => ['force_down' => true]]),
            $live(['status' => ['WAN_A' => 'down', 'tun_a' => 'none']]), [],
            ['tun_a-ipv6' => true], []],
        ['status unavailable => pass 1 skipped, pass 2 still runs',
            $config(), $live(['status' => null, 'loss' => ['tun_a' => 30]]), ['tun_a'],
            ['tun_a-ipv6' => true], ['tun_a']],
        ['held gateway that no longer exists => forgotten',
            $config(), $live(), ['gone'], [], []],
        ['disabled IPv6 gateway => untouched',
            $config(['tun_a-ipv6' => ['disabled' => true]]),
            $live(['loss' => ['tun_a' => 100]]), [], [], []],
        ['IPv4 loss in band, IPv6 down => hold',
            $config(['tun_a-ipv6' => ['force_down' => true]]),
            $live(['loss' => ['tun_a' => 15]]), [], [], []],
        ['no dpinger data for IPv4 => IPv6 down',
            $config(), $live(['loss' => [], 'sock_age' => ['WAN_A' => 600]]), [],
            ['tun_a-ipv6' => true], []],
    ];
    foreach ($planCases as $c) {
        [$desc, $cfg, $lv, $heldNames, $expChanges, $expHeld] = $c;
        $plan = wgipv6_plan($cfg, $lv, array_fill_keys($heldNames, true), null);
        $gotChanges = $plan['changes'];
        ksort($gotChanges);
        ksort($expChanges);
        $gotHeld = array_keys($plan['held']);
        sort($gotHeld);
        sort($expHeld);
        $ok = $gotChanges === $expChanges && $gotHeld === $expHeld;
        $fail += $ok ? 0 : 1;
        $total++;
        printf("[%s] plan: %s\n", $ok ? 'PASS' : 'FAIL', $desc);
        if (!$ok) {
            printf("       changes %s held %s\n", json_encode($gotChanges), json_encode($gotHeld));
        }
    }
    $unavailable = wgipv6_plan($config(), $live(['status' => null]), [], null);
    $ok = in_array('gateway status unavailable; underlay pass skipped this tick', $unavailable['log'], true)
        && in_array('underlay: gateway status unavailable, pass skipped', $unavailable['report'], true);
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] plan: status unavailable is logged and reported\n", $ok ? 'PASS' : 'FAIL');

    $gws = ['tun_a' => ['uuid' => 'bbb'], 'tun_b' => ['uuid' => 'aaa']];
    $ok = wgipv6_held_uuids(['tun_a' => true, 'tun_b' => true], $gws) === ['aaa', 'bbb']
        && wgipv6_held_uuids(['gone' => true], $gws) === []
        && wgipv6_held_uuids([], $gws) === [];
    $fail += $ok ? 0 : 1;
    $total++;
    printf("[%s] held: names map to sorted uuids, unknown names drop\n", $ok ? 'PASS' : 'FAIL');

    printf("%d/%d passed\n", $total - $fail, $total);
    return $fail === 0 ? 0 : 1;
}
