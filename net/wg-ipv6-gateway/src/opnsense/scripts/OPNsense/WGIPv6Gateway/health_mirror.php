#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Health mirror daemon: watches each IPv4 WireGuard gateway's dpinger loss and
 * toggles the paired IPv6 gateway's force_down state so the IPv6 side fails over
 * in lockstep with IPv4.
 *
 * Threshold-aware: an IPv6 gateway is forced down when its IPv4 gateway crosses
 * that gateway's own losshigh watermark (its Packet Loss failover point), and
 * brought back when loss falls to losslow, holding state in between (hysteresis)
 * exactly as dpinger does. A missing/unreadable socket counts as down. Gateways
 * with no loss threshold configured fall back to 100%-loss (fully-dead) only.
 *
 * Settle guard: a dpinger that has just started reports 0% loss because it has
 * no samples yet, not because the path is healthy. Every routing reconfigure
 * restarts all dpingers -- including the reconfigure this script itself triggers
 * when it changes a gateway -- so without this the mirror releases gateways in
 * the middle of a WAN outage and then forces them down again on the next tick.
 * While a gateway's dpinger socket is younger than the settle window, a healthy
 * reading is ignored: it can still trip a gateway DOWN, but it can never bring
 * one back UP. Failover speed is unaffected; only spurious recovery is blocked.
 *
 * The window defaults to the IPv4 gateway's own time_period (dpinger's loss
 * averaging window -- the interval it must fill before loss means anything),
 * falling back to SETTLE_FALLBACK_SECONDS when that is unset. Override with
 * --settle=N seconds, or --settle=0 to disable the guard entirely.
 *
 * Runs from /etc/cron.d/wgipv6gateway four times a minute (offsets 0/15/30/45s).
 * Run with --selftest to exercise the decision logic without touching config.
 */

require "/usr/local/opnsense/mvc/script/load_phalcon.php";

use OPNsense\Core\Config;

$logTag = 'wgipv6gw-health';

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
    $fail = 0;
    foreach ($cases as $c) {
        [$desc, $lv, $hi, $lo, $cur, $settled, $exp] = $c;
        $got = wgipv6_decide_down($lv, $hi, $lo, $cur, $settled);
        if ($got !== $exp) {
            $fail++;
        }
        printf("[%s] %s\n", $got === $exp ? 'PASS' : 'FAIL', $desc);
    }
    printf("%d/%d passed\n", count($cases) - $fail, count($cases));
    exit($fail === 0 ? 0 : 1);
}

/*
 * Settle window override: --settle=N seconds, 0 disables the guard. Without it
 * each gateway uses its own time_period.
 */
$settleOverride = null;
foreach ($argv ?? [] as $arg) {
    if (strpos($arg, '--settle=') === 0) {
        $settleOverride = max(0, (int)substr($arg, strlen('--settle=')));
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

// Read our plugin config to get mappings
$mdl = new OPNsense\WGIPv6Gateway\WGIPv6Gateway();
if ((string)$mdl->enabled !== '1') {
    exit(0);
}

$routingMdl = new OPNsense\Routing\Gateways();
$configChanged = false;

foreach ($mdl->gateways->gateway->iterateItems() as $uuid => $item) {
    if ((string)$item->enabled !== '1') {
        continue;
    }

    $ipv4Ref = (string)$item->ipv4_gateway;

    // Resolve IPv4 gateway name
    $ipv4Gw = $routingMdl->getNodeByReference('gateway_item.' . $ipv4Ref);
    if ($ipv4Gw == null) {
        continue;
    }
    $ipv4Name = (string)$ipv4Gw->name;
    $ipv6GwName = $ipv4Name . '-ipv6';

    // Loss watermarks from the IPv4 gateway. Empty/zero losshigh means the
    // gateway has no loss alarm, so only a fully-dead tunnel forces the IPv6
    // side down (preserves the original 100%-loss behavior).
    $lossHigh = (int)(string)$ipv4Gw->losshigh;
    if ($lossHigh <= 0) {
        $lossHigh = 100;
    }
    $lossLow = (int)(string)$ipv4Gw->losslow;
    if ($lossLow < 0 || $lossLow > $lossHigh) {
        $lossLow = $lossHigh;
    }

    /*
     * Settle window for this gateway: how long dpinger needs before a healthy
     * reading means anything. time_period is dpinger's loss averaging window.
     */
    $settleWindow = $settleOverride;
    if ($settleWindow === null) {
        $settleWindow = (int)(string)$ipv4Gw->time_period;
        if ($settleWindow <= 0) {
            $settleWindow = SETTLE_FALLBACK_SECONDS;
        }
    }

    // Read current IPv4 dpinger loss from its control socket (null if no data).
    $sock = "/var/run/dpinger_{$ipv4Name}.sock";
    $sockAge = wgipv6_socket_age($sock);
    $settled = ($settleWindow === 0) || ($sockAge !== null && $sockAge >= $settleWindow);
    $lossVal = null;
    if (file_exists($sock)) {
        $fp = @stream_socket_client("unix://{$sock}", $errno, $errstr, 1);
        if ($fp) {
            fwrite($fp, "\n");
            $line = fgets($fp, 1024);
            fclose($fp);
            if ($line) {
                $parts = preg_split('/\s+/', trim($line));
                $loss = end($parts);
                if (is_numeric($loss)) {
                    $lossVal = (int)$loss;
                }
            }
        }
    }

    // Find the corresponding IPv6 gateway and toggle force_down (with hysteresis).
    foreach ($routingMdl->gateway_item->iterateItems() as $gwUuid => $gw6) {
        if ((string)$gw6->name === $ipv6GwName) {
            /*
             * A disabled gateway is already out of the default-gateway election
             * and out of every gateway group, so force_down would not change
             * its effect. Writing it anyway saves config and reconfigures
             * routing, which restarts every dpinger on the box -- the same
             * churn the settle guard above exists to absorb. Leave it alone.
             */
            if ((string)$gw6->disabled === '1') {
                break;
            }

            $currentDown = ((string)$gw6->force_down === '1');
            $down = wgipv6_decide_down($lossVal, $lossHigh, $lossLow, $currentDown, $settled);
            $shouldForceDown = $down ? '1' : '0';

            if ((string)$gw6->force_down !== $shouldForceDown) {
                $gw6->force_down = $shouldForceDown;
                $configChanged = true;
                $lossStr = ($lossVal === null) ? 'no-data' : "{$lossVal}% loss";
                $state = $down ? 'force_down' : 'online';
                $settleStr = $settled ? '' : "; dpinger settling {$sockAge}/{$settleWindow}s";
                logMsg($logTag, "{$ipv6GwName}: {$state} (IPv4 {$ipv4Name} {$lossStr}; watermarks {$lossLow}/{$lossHigh}{$settleStr})");
            }
            break;
        }
    }
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
     * rather than saving a force_down we would not apply.
     */
    $gwLock = fopen('/tmp/filter_reload_gateway.lock', 'c');
    if ($gwLock !== false && flock($gwLock, LOCK_EX)) {
        $routingMdl->serializeToConfig();
        Config::getInstance()->save();
        (new OPNsense\Core\Backend())->configdRun('interface routes configure');
        flock($gwLock, LOCK_UN);
        fclose($gwLock);
    } elseif ($gwLock !== false) {
        fclose($gwLock);
    }
}
