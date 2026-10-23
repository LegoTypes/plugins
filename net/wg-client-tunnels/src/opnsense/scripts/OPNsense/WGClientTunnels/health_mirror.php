#!/usr/local/bin/php
<?php

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Health mirror for the WireGuard tunnel gateways. Two passes, one save:
 *
 * 1. Underlay: a tunnel is bound to exactly one WAN -- the gateway of the /32
 *    or /128 static route to its peer's endpoint -- and is forced down whenever
 *    that WAN is not up: disabled, force_down, absent from gateway status, or in
 *    a state a downloss gateway group treats as down (down, loss, delay+loss).
 *    A tunnel never migrates to the other WAN. Only a force_down this pass set
 *    itself is ever released, so an operator's manual force_down on a tunnel is
 *    left alone.
 *
 * 2. IPv6: each IPv6 tunnel gateway follows its own IPv4 tunnel and nothing
 *    else. IPv6 rides inside the IPv4 tunnel and Proton NATs it server-side, so
 *    it depends on no native IPv6 upstream. It is forced down when its IPv4
 *    tunnel's loss crosses that gateway's losshigh (recovering at losslow,
 *    holding in between, exactly as dpinger does), when its dpinger socket is
 *    missing, or when the IPv4 gateway itself is force_down (pass 1, or by hand).
 *    As in pass 1, only a force_down this pass set itself is ever released: an
 *    IPv6 gateway forced down by hand is left alone (spec 2026-10-20 3.5a).
 *
 * Keeping tunnel gateways out of the default-gateway election is NOT this
 * script's job: the sentinel gateways and default_guard.php do that.
 *
 * Tunnels come from the plugin's managed list, not a fixed naming convention:
 * lib/tunnels.php derives each one (WireGuard instance, peer, interface
 * assignment, WAN binding, gateways) from core config every time it is
 * needed. The held set -- which IPv4 tunnels pass 1 and which IPv6 gateways
 * pass 2 is holding down -- lives in the engine model as hold records (gateway,
 * the boot it was taken in, its underlay: the WAN of an IPv4 tunnel, the IPv4
 * tunnel of an IPv6 gateway; when), saved in the same Config::lock()/save()
 * write as the force_down values they explain. A record is ours only when its boot is the
 * live one, or the one boot.json names at the first tick after a reboot (that
 * tick re-stamps it); any other record is pruned with one log line and its
 * force_down left alone (spec 2026-10-20 section 3.5). Each tick ends by
 * recording the live boot id in boot.json, written only when it names another
 * boot. A tick that cannot read kern.boot_id takes, releases and records no
 * hold, and says so once per state. So does a tick while the plugin settings
 * wait for their 3.1.0 migration (ruling R37): the hold records are not in the
 * engine model yet.
 *
 * Settle guard: a dpinger that has just started has no samples yet, so what it
 * reports -- 0% or 100% loss, a gateway status of down or up -- says nothing about
 * the path. Every routing reconfigure restarts all dpingers -- any gateway Apply,
 * and the reconfigure this script itself triggers when it changes a gateway -- so
 * without this the mirror releases gateways in the middle of an outage, or holds a
 * healthy WAN's tunnels down (seen on the firewall 2026-10-06: a gateway Apply
 * took WAN2's tunnels down for 1 min 45 s), and each change restarts the dpingers
 * again. While a gateway's dpinger socket is younger than the settle window, or
 * absent, its reading changes nothing: the previous decision stands. A WAN that
 * is disabled or forced down in configuration still holds its tunnels at once;
 * that is not a reading. A real outage that coincides with a restart is acted on
 * once the window has passed. The window is the gateway's own time_period
 * (SETTLE_FALLBACK_SECONDS if unset); --settle=N overrides it and --settle=0
 * disables the guard. It applies to the WAN reading in pass 1 and the tunnel
 * reading in pass 2. A bound WAN gateway with monitoring disabled counts as
 * settled at once: it has no dpinger to wait for.
 *
 * --dry reports every decision against live config and live gateway status
 * without writing or reconfiguring anything. --selftest exercises the decision
 * logic without touching config. --snapshot prints the decision input
 * (config, live status, held tunnels) as JSON and writes nothing; --plan-from=FILE
 * decides from a snapshot saved that way and prints what --dry would.
 *
 * Runs from /etc/cron.d/wgclienttunnels four times a minute (offsets 0/15/30/45s).
 */

require "/usr/local/opnsense/mvc/script/load_phalcon.php";
if (!is_readable(__DIR__ . '/entry.php')) {
    exit(0);
}
require_once __DIR__ . '/entry.php';
wgct_entry_load('health_mirror.php', 'wgct-health', ['mirror.php', 'apply.php']);

$logTag = 'wgct-health';

// Self-test: validate the decision logic in isolation, no config access.
if (in_array('--selftest', $argv ?? [], true)) {
    exit(wgct_selftest());
}

$settleOverride = null;
$dryRun = false;
$snapshotOut = false;
$planFrom = null;
foreach ($argv ?? [] as $arg) {
    if (strpos($arg, '--settle=') === 0) {
        $settleOverride = max(0, (int)substr($arg, strlen('--settle=')));
    } elseif ($arg === '--dry') {
        $dryRun = true;
    } elseif ($arg === '--snapshot') {
        $snapshotOut = true;
    } elseif (strpos($arg, '--plan-from=') === 0) {
        $planFrom = substr($arg, strlen('--plan-from='));
    }
}

/* --plan-from=FILE: decide from a saved snapshot, print what --dry would. */
if ($planFrom !== null) {
    $snap = json_decode((string)@file_get_contents($planFrom), true);
    if (!is_array($snap) || !isset($snap['config'], $snap['live'], $snap['held'])) {
        fwrite(STDERR, "not a snapshot: {$planFrom}\n");
        exit(1);
    }
    $plan = wgct_plan($snap['config'], $snap['live'], array_fill_keys($snap['held'], true), $settleOverride);
    foreach ($plan['report'] as $line) {
        echo $line, "\n";
    }
    exit(0);
}

/* --snapshot: print the decision input as JSON, write nothing. */
if ($snapshotOut) {
    $snapConfig = wgct_collect_config();
    echo json_encode([
        'config' => $snapConfig,
        'live' => wgct_collect_live(),
        'held' => $snapConfig['held'],
    ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES), "\n";
    exit(0);
}

/*
 * The 3.1.0 migration pending (between pkg installing these files and the
 * package's run_migrations.php): the hold records are still 3.7_1's list in the
 * settings node, so the tick takes, releases and records nothing, said once per
 * state (ruling R37). --dry only says so.
 */
if ($dryRun ? wgct_migration_pending() : wgct_pending_refuses('tick', $logTag)) {
    if ($dryRun) {
        echo 'the tick refuses: ', WGCT_MIGRATION_PENDING, "\n";
    }
    exit(0);
}

/*
 * Single-instance guard (health.lock under /var/run). Cron fires this script four times a minute
 * (0/15/30/45s). A tick that changes a gateway blocks below until a full
 * routing reconfigure completes (dpinger torn down and rebuilt), which can
 * outlast the 15s spacing. Two overlapping runs would issue overlapping
 * reconfigures, and those race dpinger's teardown against another's rebuild
 * and leave it dead -- at which point every gateway reads a false "down".
 * If another run holds the lock, skip this tick (logged once per state); the next one catches up.
 */
$tickMsg = 'tick skipped: another run holds health.lock';
try {
    $selfLock = wgct_poll_lock(WGCT_HEALTH_LOCK_FILE, 0, 50);
} catch (\RuntimeException | \LogicException $e) {
    /* the lock file cannot be opened (SplFileObject throws a LogicException for a directory): quiet exit, logged once */
    wgct_note_lock(WGCT_HEALTH_UNOPENABLE_FILE, true, 'tick skipped: health.lock cannot be opened: ' . $e->getMessage(), 'health.lock opens again');
    exit(0);
}
/*
 * The package removal writes its marker while it holds health.lock (+PRE_DEINSTALL.pre), so a tick that passed
 * entry.php's check just before the marker appeared finds the lock taken, or the marker once it has the lock:
 * either way it ends here, and no tick re-takes a hold after the removal released it (ruling R30).
 */
if (wgct_removing()) {
    exit(0);
}
if ($selfLock === null) {
    wgct_note_lock(WGCT_HEALTH_SKIPPED_FILE, true, $tickMsg, 'health resumed');
    exit(0);
}
wgct_note_lock(WGCT_HEALTH_UNOPENABLE_FILE, false, '', 'health.lock opens again');
wgct_note_lock(WGCT_HEALTH_SKIPPED_FILE, false, $tickMsg, 'health resumed');

$config = wgct_collect_config();
if (!$config['enabled']) {
    if ($dryRun) {
        echo "health mirror is off in the plugin settings\n";
    }
    exit(0);
}
$held = array_fill_keys($config['held'], true);
$plan = wgct_plan($config, wgct_collect_live(), $held, $settleOverride);

if ($dryRun) {
    foreach ($plan['report'] as $line) {
        echo $line, "\n";
    }
    exit(0);
}

wgct_note_lock(WGCT_BOOT_UNREADABLE_FILE, $config['boot_unreadable'],
    'kern.boot_id cannot be read: no hold is taken, released or recorded until it can',
    'kern.boot_id can be read again; holds are taken and released again');

if (empty($plan['changes'])) {
    foreach ($plan['log'] as $msg) {
        logMsg($logTag, $msg);
    }
    if (wgct_hold_rows_next($config, $plan['held'], $config['live_boot'], time()) !== null) {
        /*
         * Hold records only (a re-stamp after a reboot, a prune, a tunnel that
         * no longer exists): a config write with no routing change, so no
         * gateway lock. Re-plan under the config lock; if config changed
         * meanwhile and the re-plan now wants a force_down change, save
         * nothing -- that needs the gateway lock and an apply, which the next
         * tick does -- and leave boot.json as it is, so a previous-boot record
         * not yet re-stamped is still recognised.
         */
        $live = wgct_collect_live();
        $commit = wgct_locked_commit(function () use ($live, $settleOverride) {
            /* config as re-read under the lock: a migration pending again (a restored 3.7_1 backup) saves nothing */
            if (wgct_migration_pending()) {
                return ['save' => false, 'deferred' => true];
            }
            $now = wgct_collect_config();
            $replan = wgct_plan($now, $live, array_fill_keys($now['held'], true), $settleOverride);
            if (!empty($replan['changes'])) {
                return ['save' => false, 'deferred' => true];
            }
            return ['save' => wgct_commit_held($replan['held'], $now, $now['live_boot']), 'deferred' => false, 'config' => $now];
        });
        if ($commit['deferred']) {
            exit(0);
        }
        if ($commit['save']) {
            foreach (wgct_hold_prune_lines($commit['config']) as $msg) {
                logMsg($logTag, $msg);
            }
        }
    }
    if (!$config['boot_unreadable']) {
        wgct_record_boot($config['live_boot']);
    }
    exit(0);
}

/*
 * A change is needed. Commit it in the order every config writer follows
 * (spec 2026-09-24 section 4.6):
 *
 *   1. core's gateway lock (/tmp/filter_reload_gateway.lock) -- applying force_down is a full
 *      routing reconfigure, which restarts every dpinger; overlapping
 *      reconfigures leave dpinger dead. Same lock routes.alarm uses.
 *   2. Live readings, collected again: the wait for the lock can be long, and
 *      gateway_status.php reads config, so it must never run inside the
 *      config lock taken in step 3.
 *   3. Config::lock(), which re-reads config.xml; the decisions are planned
 *      again from fresh models, including the hold records, so a GUI save
 *      made while this run waited is kept. The force_down values and the hold
 *      records are saved together, once.
 *   4. Unlock, then apply and replay the alarms the hold dropped: our own
 *      and any other gateway's whose status changed meanwhile.
 *
 * If the gateway lock is still held after wgct_gateway_lock()'s bounded wait, leave
 * the change for the next tick rather than save a force_down we would not apply.
 */
/* status before the lock, so an alarm routes.alarm drops while we hold it can be replayed after */
$before = wgct_gateway_status();
try {
    $gwLock = wgct_gateway_lock();
} catch (WgctRemovingException $e) {
    /* the removal marker appeared while this tick waited for the gateway lock: it saves nothing (ruling R30) */
    exit(0);
} catch (\RuntimeException $e) {
    wgct_note_lock(WGCT_GATEWAY_SKIPPED_FILE, true, 'gateway change left for the next tick: ' . $e->getMessage(), 'gateway lock available again');
    exit(0);
}
wgct_note_lock(WGCT_GATEWAY_SKIPPED_FILE, false, '', 'gateway lock available again');
$live = wgct_collect_live();
$commit = wgct_locked_commit(function () use ($live, $settleOverride) {
    /* config as re-read under the lock: a migration pending again (a restored 3.7_1 backup) saves nothing */
    if (wgct_migration_pending()) {
        return ['save' => false, 'pending' => true];
    }
    $now = wgct_collect_config();
    $plan = wgct_plan($now, $live, array_fill_keys($now['held'], true), $settleOverride);
    $save = false;
    if (!empty($plan['changes'])) {
        $routingMdl = new OPNsense\Routing\Gateways();
        wgct_apply_changes($routingMdl, $plan['changes']);
        $routingMdl->serializeToConfig();
        $save = true;
    }
    $held = wgct_commit_held($plan['held'], $now, $now['live_boot']);
    return ['save' => $held || $save, 'plan' => $plan, 'held' => $held, 'config' => $now];
});
if (!empty($commit['pending'])) {
    $gwLock->flock(LOCK_UN);
    exit(0);
}
$plan = $commit['plan'];
foreach ($plan['log'] as $msg) {
    logMsg($logTag, $msg);
}
if ($commit['held']) {
    foreach (wgct_hold_prune_lines($commit['config']) as $msg) {
        logMsg($logTag, $msg);
    }
}
if (!empty($plan['changes'])) {
    (new OPNsense\Core\Backend())->configdRun('interface routes configure');
}
$gwLock->flock(LOCK_UN);
if (!empty($plan['changes'])) {
    wgct_mirror_replay($plan['changes'], $before, $logTag);
}
if (!$commit['config']['boot_unreadable']) {
    wgct_record_boot($commit['config']['live_boot']);
}
