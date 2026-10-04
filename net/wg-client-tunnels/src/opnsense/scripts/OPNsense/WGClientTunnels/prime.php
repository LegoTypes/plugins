#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Teach the provider each tunnel's IPv6 address (spec 2026-10-03). Run by the cron right after each health mirror
 * tick, four times a minute; never from a hook. When a managed tunnel's IPv6 gateway is down while its WireGuard
 * session is up, send one TCP connect from the tunnel's own IPv6 address to its IPv6 monitor: a provider
 * that learns the client address from non-ICMP traffic then sends the replies back to it. No config write, no
 * gateway lock. The decisions are lib/prime.php's; this file reads, connects and logs.
 *
 * --dry prints each watched tunnel's judgement and sends nothing; --selftest runs the decision tests.
 */

require_once 'config.inc';
require_once 'util.inc';
require_once 'interfaces.inc';
require_once '/usr/local/opnsense/mvc/script/load_phalcon.php';
require_once __DIR__ . '/lib/apply.php';
require_once __DIR__ . '/lib/prime.php';

/**
 * One TCP connect from $source to [$dst]:$port, bound explicitly: a source that will not bind is reported, never
 * replaced by one the kernel picks (stream_socket_client() ignores a failed bindto and connects anyway).
 *
 * @return array{bound: bool, connected: bool, errno: int, error: string}
 */
function wgct_prime_connect(string $source, string $dst, int $port, int $timeout): array {
    $sock = @socket_create(AF_INET6, SOCK_STREAM, SOL_TCP);
    if ($sock === false) {
        return ['bound' => false, 'connected' => false, 'errno' => socket_last_error(), 'error' => socket_strerror(socket_last_error())];
    }
    try {
        /* failures are read back with socket_last_error(); their PHP warnings would surface as a GUI crash notice */
        if (!@socket_bind($sock, $source, 0)) {
            $errno = socket_last_error($sock);
            return ['bound' => false, 'connected' => false, 'errno' => $errno, 'error' => socket_strerror($errno)];
        }
        socket_set_nonblock($sock);
        if (@socket_connect($sock, $dst, $port)) {
            return ['bound' => true, 'connected' => true, 'errno' => 0, 'error' => ''];
        }
        $errno = socket_last_error($sock);
        if ($errno !== SOCKET_EINPROGRESS) {
            return ['bound' => true, 'connected' => false, 'errno' => $errno, 'error' => socket_strerror($errno)];
        }
        $read = null;
        $write = [$sock];
        $except = null;
        if (@socket_select($read, $write, $except, $timeout) !== 1) {
            return ['bound' => true, 'connected' => false, 'errno' => SOCKET_ETIMEDOUT, 'error' => socket_strerror(SOCKET_ETIMEDOUT)];
        }
        $errno = (int)socket_get_option($sock, SOL_SOCKET, SO_ERROR);
        return ['bound' => true, 'connected' => $errno === 0, 'errno' => $errno, 'error' => $errno === 0 ? '' : socket_strerror($errno)];
    } finally {
        socket_close($sock);
    }
}

$args = $argv ?? [];
if (in_array('--selftest', $args, true)) {
    exit(wgct_prime_selftest());
}
$dry = in_array('--dry', $args, true);

$stateDir = getenv('WGCT_STATE_DIR') ?: '/var/run/wgclienttunnels';
$mdl = new \OPNsense\WGClientTunnels\WGClientTunnels();
if (!$mdl->enabled->isEqual('1')) {
    if ($dry) {
        echo "the plugin is disabled\n";
    }
    exit(0);
}
$log = function (string $msg) use ($dry): void {
    if ($dry) {
        echo "would log: {$msg}\n";
        return;
    }
    wgct_log(LOG_NOTICE, "[wgct-prime] {$msg}");
};
/* one tick at a time: a tick whose connects run long must not overlap the next on the state file */
if (!$dry) {
    try {
        $self = wgct_poll_lock("{$stateDir}/prime.lock", 0, 50);
    } catch (\Throwable $e) {
        $log('cannot open the single-instance lock: ' . $e->getMessage());
        exit(0);
    }
    if ($self === null) {
        exit(0);
    }
}

$stateFile = "{$stateDir}/prime.json";
$state = wgct_prime_state(json_decode((string)@file_get_contents($stateFile), true));
$read = $state;
$now = time();

$core = wgct_core_snapshot();
$watch = wgct_repair_watch(wgct_derive($core, wgct_split_csv((string)$mdl->managed)), $core);
$status = wgct_gateway_status();
if ($status === null) {
    if ($dry) {
        echo "gateway status unavailable; nothing judged\n";
    }
    exit(0);
}

/* probe each tunnel only as far as its IPv6 status makes worth it: an up gateway costs no exec at all */
$probes = [];
foreach ($watch as $w) {
    $p = ['status6' => $status[$w['gw6']] ?? null, 'handshake_age' => null];
    if (in_array($p['status6'], WGCT_PRIME_DOWN, true)) {
        $out = [];
        exec('/usr/bin/wg show ' . escapeshellarg($w['device']) . ' latest-handshakes 2>/dev/null', $out);
        $p['handshake_age'] = wgct_prime_handshake_age($out, time());
        if ($p['handshake_age'] !== null && $p['handshake_age'] <= WGCT_PRIME_SESSION) {
            $ifconfig = [];
            exec('/sbin/ifconfig ' . escapeshellarg($w['device']) . ' inet6 2>/dev/null', $ifconfig);
            $route = [];
            exec('/sbin/route -n get -inet6 ' . escapeshellarg($w['monitor']) . ' 2>/dev/null', $route);
            $routed = interfaces_routed_address6($w['interface'])[0] ?? null;
            $p += [
                'age6' => wgct_socket_age("/var/run/dpinger_{$w['gw6']}.sock"),
                'routed' => is_string($routed) && $routed !== '' ? $routed : null,
                'duplicated' => wgct_repair_is_duplicated($ifconfig, $w['address']),
                'route_dev' => wgct_repair_route_dev($route, $w['monitor']),
            ];
        }
    }
    $probes[$w['gw6']] = $p;
}

$settled = wgct_prime_settle($state, $watch, $status, wgct_prime_resets($probes));
$state = $settled['state'];
foreach ($settled['lines'] as $line) {
    $log($line);
}
foreach ($watch as $w) {
    $p = $probes[$w['gw6']];
    $judged = wgct_prime_judge($w, $p, wgct_prime_allows($state, $w['gw6'], $now));
    if ($dry) {
        echo "{$w['gw6']}: ", $judged['candidate']
            ? "would send TCP from {$w['address']} to [{$w['monitor']}]:" . WGCT_PRIME_PORT : $judged['why'], "\n";
        continue;
    }
    if (!$judged['candidate']) {
        continue;
    }
    $sent = wgct_prime_connect($w['address'], $w['monitor'], WGCT_PRIME_PORT, WGCT_PRIME_TIMEOUT);
    if (!$sent['bound']) {
        $log(wgct_prime_bind_line($w, $sent['error']));
        continue;
    }
    $recorded = wgct_prime_record($state, $w['gw6'], $now);
    $state = $recorded['state'];
    $count = $state[$w['gw6']]['count'];
    $log(wgct_prime_line($w, (int)$p['handshake_age'], wgct_prime_outcome($sent['connected'], $sent['errno'], $sent['error']), $count));
    if ($recorded['capped_now']) {
        $log("{$w['gw6']} still down after {$count} primes; retrying every " . (WGCT_PRIME_CAP / 60) . ' minutes');
    }
}
if (!$dry && $state !== $read) {
    wgct_write_file_atomic($stateFile, json_encode($state) . "\n");
}
