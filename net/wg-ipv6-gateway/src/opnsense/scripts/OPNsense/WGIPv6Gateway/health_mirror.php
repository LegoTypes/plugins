#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Health mirror for the WireGuard tunnel gateways. Two passes, one save:
 *
 * 1. Underlay: a tunnel is bound to exactly one WAN -- the gateway of the /32
 *    static route to its peer's endpoint -- and is forced down whenever that WAN
 *    is not up: disabled, force_down, absent from gateway status, or in a state
 *    a downloss gateway group treats as down (down, loss, delay+loss). A tunnel
 *    never migrates to the other WAN. Only a force_down this pass set itself is
 *    ever released, so an operator's manual force_down on a tunnel is left alone.
 *
 * 2. IPv6: each IPv6 tunnel gateway follows its own IPv4 tunnel and nothing
 *    else. IPv6 rides inside the IPv4 tunnel and Proton NATs it server-side, so
 *    it depends on no native IPv6 upstream. It is forced down when its IPv4
 *    tunnel's loss crosses that gateway's losshigh (recovering at losslow,
 *    holding in between, exactly as dpinger does), when its dpinger socket is
 *    missing, or when the IPv4 gateway itself is force_down (pass 1, or by hand).
 *
 * Keeping tunnel gateways out of the default-gateway election is NOT this
 * script's job: the sentinel gateways and default_guard.php do that.
 *
 * Settle guard: a dpinger that has just started reports 0% loss because it has
 * no samples yet, not because the path is healthy. Every routing reconfigure
 * restarts all dpingers -- including the reconfigure this script itself triggers
 * when it changes a gateway -- so without this the mirror releases gateways in
 * the middle of an outage and forces them down again on the next tick. While a
 * gateway's dpinger socket is younger than the settle window, a healthy reading
 * is ignored: it can still trip a gateway DOWN, never bring one back UP. The
 * window is the gateway's own time_period (SETTLE_FALLBACK_SECONDS if unset);
 * --settle=N overrides it and --settle=0 disables the guard. It applies to the
 * WAN reading in pass 1 and the tunnel reading in pass 2.
 *
 * --dry reports every decision against live config and live gateway status
 * without writing or reconfiguring anything. --selftest exercises the decision
 * logic without touching config.
 *
 * Runs from /etc/cron.d/wgipv6gateway four times a minute (offsets 0/15/30/45s).
 */

require "/usr/local/opnsense/mvc/script/load_phalcon.php";

use OPNsense\Core\Config;

$logTag = 'wgipv6gw-health';

/* Used only when a gateway has no time_period configured. */
const SETTLE_FALLBACK_SECONDS = 60;

/* IPv4 tunnel gateways whose force_down pass 1 set, and so may release. */
const UNDERLAY_HELD_FILE = '/var/db/wgipv6gateway/underlay_held.json';

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
 * Loss watermarks for a gateway, normalised. Empty/zero losshigh means the
 * gateway has no loss alarm, so only a fully-dead path counts as down.
 *
 * @param object $gw gateway_item node
 * @return array [int $lossLow, int $lossHigh]
 */
function wgipv6_watermarks($gw) {
    $high = (int)(string)$gw->losshigh;
    if ($high <= 0) {
        $high = 100;
    }
    $low = (int)(string)$gw->losslow;
    if ($low < 0 || $low > $high) {
        $low = $high;
    }
    return [$low, $high];
}

/**
 * How long this gateway's dpinger needs before a healthy reading means
 * anything: its own loss averaging window, unless overridden.
 *
 * @param object   $gw       gateway_item node
 * @param int|null $override --settle=N, or null to use the gateway's own
 * @return int seconds
 */
function wgipv6_settle_window($gw, $override) {
    if ($override !== null) {
        return $override;
    }
    $window = (int)(string)$gw->time_period;
    return $window > 0 ? $window : SETTLE_FALLBACK_SECONDS;
}

/**
 * Is this gateway's dpinger old enough for a healthy reading to count?
 *
 * @param object   $gw       gateway_item node
 * @param int|null $override --settle=N
 * @return array [bool $settled, int|null $ageSeconds, int $windowSeconds]
 */
function wgipv6_settled($gw, $override) {
    $window = wgipv6_settle_window($gw, $override);
    $age = wgipv6_socket_age("/var/run/dpinger_{$gw->name}.sock");
    return [($window === 0) || ($age !== null && $age >= $window), $age, $window];
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
 * The WAN each tunnel gateway is bound to, keyed by IPv4 tunnel gateway name.
 * The binding is declared once: the /32 static route to the tunnel peer's
 * endpoint names the WAN gateway. Tunnels with no such route are absent.
 *
 * @param object $routingMdl OPNsense\Routing\Gateways
 * @return array name => WAN gateway name
 */
function wgipv6_tunnel_underlays($routingMdl) {
    $root = Config::getInstance()->object();
    $routeByNet = [];
    foreach ((new OPNsense\Routes\Route())->route->iterateItems() as $route) {
        if ((string)$route->enabled === '1') {
            $routeByNet[(string)$route->network] = (string)$route->gateway;
        }
    }
    $endpointByUuid = [];
    foreach ((new OPNsense\Wireguard\Client())->clients->client->iterateItems() as $uuid => $peer) {
        $endpointByUuid[$uuid] = (string)$peer->serveraddress;
    }
    $wanByDevice = [];
    foreach ((new OPNsense\Wireguard\Server())->servers->server->iterateItems() as $server) {
        foreach (array_filter(explode(',', (string)$server->peers)) as $peerUuid) {
            $net = ($endpointByUuid[$peerUuid] ?? '') . '/32';
            if (isset($routeByNet[$net])) {
                $wanByDevice['wg' . (string)$server->instance] = $routeByNet[$net];
            }
        }
    }
    $result = [];
    foreach ($routingMdl->gateway_item->iterateItems() as $gw) {
        if ((string)$gw->ipprotocol !== 'inet') {
            continue;
        }
        $if = (string)$gw->interface;
        $device = isset($root->interfaces->$if) ? (string)$root->interfaces->$if->if : '';
        if (isset($wanByDevice[$device])) {
            $result[(string)$gw->name] = $wanByDevice[$device];
        }
    }
    return $result;
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
 * Tunnels this script holds down, persisted so ownership survives reboots.
 *
 * @return array name => true
 */
function wgipv6_load_held() {
    $data = @json_decode((string)@file_get_contents(UNDERLAY_HELD_FILE), true);
    return is_array($data) ? array_fill_keys(array_filter($data, 'is_string'), true) : [];
}

function wgipv6_save_held(array $held) {
    @mkdir(dirname(UNDERLAY_HELD_FILE), 0700, true);
    $tmp = UNDERLAY_HELD_FILE . '.tmp';
    file_put_contents($tmp, json_encode(array_keys($held)));
    rename($tmp, UNDERLAY_HELD_FILE);
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

// Self-test: validate the decision logic in isolation, no config access.
if (in_array('--selftest', $argv ?? [], true)) {
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
    $fail = 0;
    foreach ($cases as $c) {
        [$desc, $lv, $hi, $lo, $cur, $settled, $exp] = $c;
        $got = wgipv6_decide_down($lv, $hi, $lo, $cur, $settled);
        $fail += $got === $exp ? 0 : 1;
        printf("[%s] ipv6: %s\n", $got === $exp ? 'PASS' : 'FAIL', $desc);
    }
    foreach ($underlayCases as $c) {
        [$desc, $wan, $held, $exp] = $c;
        $got = wgipv6_decide_underlay($wan, $held);
        $fail += $got === $exp ? 0 : 1;
        printf("[%s] underlay: %s\n", $got === $exp ? 'PASS' : 'FAIL', $desc);
    }
    $total = count($cases) + count($underlayCases);
    printf("%d/%d passed\n", $total - $fail, $total);
    exit($fail === 0 ? 0 : 1);
}

$settleOverride = null;
$dryRun = false;
foreach ($argv ?? [] as $arg) {
    if (strpos($arg, '--settle=') === 0) {
        $settleOverride = max(0, (int)substr($arg, strlen('--settle=')));
    } elseif ($arg === '--dry') {
        $dryRun = true;
    }
}

/*
 * Single-instance guard. Cron fires this script four times a minute
 * (0/15/30/45s). A tick that changes a gateway blocks below until a full
 * routing reconfigure completes (dpinger torn down and rebuilt), which can
 * outlast the 15s spacing. Two overlapping runs would issue overlapping
 * reconfigures, and those race dpinger's teardown against another's rebuild
 * and leave it dead -- at which point every gateway reads a false "down".
 * If another run holds the lock, skip this tick; the next one catches up.
 */
$selfLock = fopen('/tmp/wgipv6gw_health.lock', 'c');
if ($selfLock === false || !flock($selfLock, LOCK_EX | LOCK_NB)) {
    exit(0);
}

$mdl = new OPNsense\WGIPv6Gateway\WGIPv6Gateway();
if ((string)$mdl->enabled !== '1') {
    exit(0);
}

$routingMdl = new OPNsense\Routing\Gateways();
$gwByName = [];
foreach ($routingMdl->gateway_item->iterateItems() as $gw) {
    $gwByName[(string)$gw->name] = $gw;
}
$configChanged = false;
$alarmExpected = [];    // name => force_down we wrote, for wgipv6_replay_alarm()

/* ---- pass 1: underlay -------------------------------------------------- */

$status = wgipv6_gateway_status();
$held = wgipv6_load_held();
$heldChanged = false;

if ($status === null) {
    /* Without status every WAN would read absent and every tunnel would be
     * forced down on a transient read failure. Skip the pass this tick. */
    logMsg($logTag, 'gateway status unavailable; underlay pass skipped this tick');
    if ($dryRun) {
        echo "underlay: gateway status unavailable, pass skipped\n";
    }
} else {
    foreach (wgipv6_tunnel_underlays($routingMdl) as $tunnelName => $wanName) {
        $tunnel = $gwByName[$tunnelName] ?? null;
        if ($tunnel === null || (string)$tunnel->disabled === '1') {
            continue;
        }
        $wanGw = $gwByName[$wanName] ?? null;
        [$wanSettled, $wanAge, $wanWindow] = $wanGw !== null
            ? wgipv6_settled($wanGw, $settleOverride) : [true, null, 0];
        $wan = [
            'disabled' => $wanGw === null || (string)$wanGw->disabled === '1',
            'force_down' => $wanGw !== null && (string)$wanGw->force_down === '1',
            'status' => $status[$wanName] ?? null,
            'settled' => $wanSettled,
        ];
        $isHeld = isset($held[$tunnelName]);
        $manual = (string)$tunnel->force_down === '1' && !$isHeld;
        $down = wgipv6_decide_underlay($wan, $isHeld);

        $wanDesc = $wan['disabled'] ? 'disabled' : ($wan['force_down'] ? 'force_down'
            : ($wan['status'] ?? 'absent') . ($wanSettled ? '' : " settling {$wanAge}/{$wanWindow}s"));

        if ($dryRun) {
            printf(
                "underlay %-18s on %-12s WAN %-24s -> %s\n",
                $tunnelName,
                $wanName,
                $wanDesc,
                $manual ? 'manual force_down, left alone' : ($down ? 'held down' : 'up')
            );
        }
        if ($manual) {
            continue;
        }
        if ($down && !$isHeld) {
            $held[$tunnelName] = true;
            $heldChanged = true;
            $tunnel->force_down = '1';
            $configChanged = true;
            $alarmExpected[$tunnelName] = true;
            if (!$dryRun) {
                logMsg($logTag, "{$tunnelName}: force_down (underlay {$wanName} {$wanDesc})");
            }
        } elseif (!$down && $isHeld) {
            unset($held[$tunnelName]);
            $heldChanged = true;
            $tunnel->force_down = '0';
            $configChanged = true;
            $alarmExpected[$tunnelName] = false;
            if (!$dryRun) {
                logMsg($logTag, "{$tunnelName}: online (underlay {$wanName} {$wanDesc})");
            }
        }
    }
    /* forget tunnels that no longer exist */
    foreach (array_keys($held) as $name) {
        if (!isset($gwByName[$name])) {
            unset($held[$name]);
            $heldChanged = true;
        }
    }
}

/* ---- pass 2: IPv6 follows its own IPv4 tunnel -------------------------- */

foreach ($mdl->gateways->gateway->iterateItems() as $item) {
    if ((string)$item->enabled !== '1') {
        continue;
    }
    $ipv4Gw = $routingMdl->getNodeByReference('gateway_item.' . (string)$item->ipv4_gateway);
    if ($ipv4Gw === null) {
        continue;
    }
    $ipv4Name = (string)$ipv4Gw->name;
    $gw6 = $gwByName[$ipv4Name . '-ipv6'] ?? null;
    /*
     * A disabled gateway is already out of the default-gateway election and out
     * of every gateway group, so force_down would not change its effect, and
     * writing it would reconfigure routing for nothing. Leave it alone.
     */
    if ($gw6 === null || (string)$gw6->disabled === '1') {
        continue;
    }

    [$lossLow, $lossHigh] = wgipv6_watermarks($ipv4Gw);
    [$settled, $sockAge, $settleWindow] = wgipv6_settled($ipv4Gw, $settleOverride);
    $lossVal = wgipv6_read_loss($ipv4Name);
    $currentDown = (string)$gw6->force_down === '1';
    $ipv4Forced = (string)$ipv4Gw->force_down === '1';     // includes pass 1's writes
    $down = $ipv4Forced || wgipv6_decide_down($lossVal, $lossHigh, $lossLow, $currentDown, $settled);
    $lossStr = $lossVal === null ? 'no-data' : "{$lossVal}% loss";
    $why = $ipv4Forced ? 'IPv4 force_down' : ($down ? 'IPv4 unhealthy' : 'IPv4 healthy');

    if ($dryRun) {
        printf(
            "ipv6     %-22s force_down %s -> %s  (%s; %s %s%s)\n",
            (string)$gw6->name,
            $currentDown ? '1' : '0',
            $down ? '1' : '0',
            $why,
            $ipv4Name,
            $lossStr,
            $settled ? '' : "; settling {$sockAge}/{$settleWindow}s"
        );
        continue;
    }
    if ($down !== $currentDown) {
        $gw6->force_down = $down ? '1' : '0';
        $configChanged = true;
        $alarmExpected[(string)$gw6->name] = $down;
        $settleStr = $settled ? '' : "; dpinger settling {$sockAge}/{$settleWindow}s";
        logMsg($logTag, sprintf(
            '%s: %s (%s; %s %s; watermarks %d/%d%s)',
            (string)$gw6->name,
            $down ? 'force_down' : 'online',
            $why,
            $ipv4Name,
            $lossStr,
            $lossLow,
            $lossHigh,
            $settleStr
        ));
    }
}

if ($dryRun) {
    exit(0);
}

if ($configChanged) {
    /*
     * Applying a gateway change means a full routing reconfigure, which
     * restarts every dpinger on the box. It must not run concurrently with
     * another routing reconfigure: overlapping reconfigures race dpinger's
     * teardown against another's rebuild and leave it dead, showing every
     * gateway as a false "down". Serialize on the same lock OPNsense's own
     * gateway-alarm reconfigure uses (interface routes alarm ->
     * flock /tmp/filter_reload_gateway.lock). configdRun is synchronous, so
     * the lock covers the whole reconfigure.
     *
     * Acquire the lock BEFORE persisting so config and applied state stay
     * consistent: if we cannot serialize, leave the change for the next tick
     * rather than saving a force_down we would not apply. The held set is
     * written only once the config it describes has been saved.
     */
    $gwLock = fopen('/tmp/filter_reload_gateway.lock', 'c');
    if ($gwLock !== false && flock($gwLock, LOCK_EX)) {
        $routingMdl->serializeToConfig();
        Config::getInstance()->save();
        if ($heldChanged) {
            wgipv6_save_held($held);
        }
        (new OPNsense\Core\Backend())->configdRun('interface routes configure');
        flock($gwLock, LOCK_UN);
        fclose($gwLock);
        wgipv6_replay_alarm($alarmExpected, $logTag);
    } elseif ($gwLock !== false) {
        fclose($gwLock);
    }
} elseif ($heldChanged) {
    wgipv6_save_held($held);
}
