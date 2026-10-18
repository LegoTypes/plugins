<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Apply a plan (spec 2026-10-17 sections 3.4, 3.5, 3.7 and 3.10) through injected I/O, so order and failure
 * handling are testable. uu_live_io() binds the real commands.
 *
 * Io = array{route: callable(string $verb, list<string> $args): bool, sleep_ms: callable(int $ms): void,
 *            probe_direct: callable(string $resolver, string $name): bool, probe_unbound: callable(string $name): bool,
 *            uc: callable(list<string> $args): ?string, restart_unbound: callable(): bool,
 *            log: callable(string $msg, int $prio): void, save: callable(array $state): void}
 *   route runs route(8) with the verb (add, change or delete); uc runs unbound-control and returns its output, null
 *   when it failed or timed out; each probe is one `drill -D <name> @<server> SOA` tried UU_PROBE_TRIES times and
 *   passes on NOERROR with the ad flag; log takes a syslog priority; save writes the State (state.php) the run has
 *   reached, after every successful route or forwarder change and when an exception escapes (ruling R26), so the
 *   route record of ruling R22 survives a failure partway through.
 *
 * Every path keeps these:
 *   - a route is changed in place (change, or add when absent), never deleted and added: in the gap the resolver
 *     would follow the default route;
 *   - nothing probes before a route change reached the data path (fib_sync_ms + UU_FIB_SYNC_MARGIN_MS);
 *   - forward_add is decided by Unbound's live root, never by the state's mode;
 *   - the reject route never replaces a route the plugin did not make, and is never installed while Unbound may
 *     still forward to the resolver (it would black-hole every query); the resolver's route is never deleted then
 *     either (the queries would follow the default route out a WAN);
 *   - the state's mode and member change only when the step that makes them true succeeded;
 *   - Unbound's caches are never flushed: flush_infra <resolver> and flush_type <probe_name> SOA only.
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/choose.php';
require_once __DIR__ . '/state.php';
require_once __DIR__ . '/planner.php';
require_once __DIR__ . '/snapshot.php';
require_once __DIR__ . '/log.php';

/**
 * Addresses as `unbound-control forward` prints them, for comparing as sets: "@port" and "#name" dropped, IPv6 in
 * its canonical form, sorted, each once.
 *
 * @param list<string> $addrs
 * @return list<string>
 */
function uu_apply_bare(array $addrs): array
{
    $out = [];
    foreach ($addrs as $addr) {
        $ip = (string)preg_replace('/[@#].*$/', '', $addr);
        if (filter_var($ip, FILTER_VALIDATE_IP) !== false) {
            $packed = inet_pton($ip);
            $text = $packed === false ? false : inet_ntop($packed);
            $ip = $text === false ? $ip : $text;
        }
        $out[] = strtolower($ip);
    }
    $out = array_values(array_unique($out));
    sort($out);
    return $out;
}

/**
 * Whether the live root forwarders are the wanted ones; an unknown live root never is.
 *
 * @param ?list<string> $live
 * @param list<string> $want
 */
function uu_apply_same(?array $live, array $want): bool
{
    return $live !== null && uu_apply_bare($live) === uu_apply_bare($want);
}

/** A mode and member for a switch line: the member's name, 'tunnel' with no member, or 'fallback'. */
function uu_apply_where(string $mode, ?string $member): string
{
    return $mode === 'tunnel' ? ($member ?? 'tunnel') : 'fallback';
}

/** drill's answer passes on NOERROR with the ad flag, so a resolver that answers but does not validate fails. */
function uu_drill_passed(string $out): bool
{
    if (preg_match('/^;;\s*->>HEADER<<-.*\brcode:\s*NOERROR\b/m', $out) !== 1) {
        return false;
    }
    if (preg_match('/^;;\s*flags:([^;]*);/m', $out, $m) !== 1) {
        return false;
    }
    return in_array('ad', preg_split('/\s+/', trim($m[1])) ?: [], true);
}

/**
 * One apply: the plan's steps in order against the injected I/O, tracking what this run itself changed (route,
 * live root) so each later step decides on the current facts rather than the snapshot's.
 */
final class UuApplyRun
{
    /**
     * @var array{action: string, candidates: list<string>, reassert: bool, route_repair: bool,
     *     escalate_restart: bool,
     *     state: array{version: int, mode: string, member: ?string,
     *         timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int,
     *         resolver_failed_until: ?int, probe_failures: int}>, control_failures: int,
     *         control_silent_since: ?int, last_switch: ?array{at: int, from: string, to: string, reason: string},
     *         checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
     *         member: string}}, tls_applied: ?bool, blocked: ?int,
     *         route_installed: ?array{kind: string, next_hop: string, if: string}},
     *     reasons: list<string>}
     */
    private array $p;
    /**
     * @var array{now: int,
     *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, failback_delay: int,
     *         probe_name: string},
     *     members: array<string, array{name: string, interface: string, if: string, next_hop: string,
     *         disabled: bool, force_down: bool, monitor_disable: bool, monitor: string, time_period: int,
     *         interval: int, loss_interval: int, losshigh: int}>,
     *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
     *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
     *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool},
     *     fib_sync_ms: ?int, contract_input: array{cacheflush: bool}}
     */
    private array $s;
    /**
     * @var array{route: callable(string, list<string>): bool, sleep_ms: callable(int): void,
     *     probe_direct: callable(string, string): bool, probe_unbound: callable(string): bool,
     *     uc: callable(list<string>): ?string, restart_unbound: callable(): bool, log: callable(string, int): void,
     *     save: callable(array): void}
     */
    private array $io;
    /**
     * @var array{version: int, mode: string, member: ?string,
     *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
     *     probe_failures: int}>, control_failures: int, control_silent_since: ?int,
     *     last_switch: ?array{at: int, from: string, to: string, reason: string},
     *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
     *     member: string}}, tls_applied: ?bool, blocked: ?int,
     *     route_installed: ?array{kind: string, next_hop: string, if: string}}
     */
    private array $st;
    /** @var ?list<string> Unbound's live root as last read or set; null while unknown */
    private ?array $live;
    /** this run sent forward_add . <resolver>, so Unbound may be on the resolver although the reply was lost */
    private bool $maybeResolver = false;
    /** @var array{present: bool, gateway: string, interface: string, reject: bool, ours: bool} */
    private array $route;
    private bool $fibPending = false;
    /** an unbound-control call of this run got no answer (timeout or no channel) */
    private bool $silent = false;
    private bool $reasonsLogged = false;
    /** @var list<string> what this run found on the way, for the switch reason */
    private array $notes = [];
    private string $resolver;
    private string $probe;

    /**
     * @param array{action: string, candidates: list<string>, reassert: bool, route_repair: bool,
     *     escalate_restart: bool,
     *     state: array{version: int, mode: string, member: ?string,
     *         timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int,
     *         resolver_failed_until: ?int, probe_failures: int}>, control_failures: int,
     *         control_silent_since: ?int, last_switch: ?array{at: int, from: string, to: string, reason: string},
     *         checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
     *         member: string}}, tls_applied: ?bool, blocked: ?int,
     *         route_installed: ?array{kind: string, next_hop: string, if: string}},
     *     reasons: list<string>} $p
     * @param array{now: int,
     *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, failback_delay: int,
     *         probe_name: string},
     *     members: array<string, array{name: string, interface: string, if: string, next_hop: string,
     *         disabled: bool, force_down: bool, monitor_disable: bool, monitor: string, time_period: int,
     *         interval: int, loss_interval: int, losshigh: int}>,
     *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
     *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
     *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool},
     *     fib_sync_ms: ?int, contract_input: array{cacheflush: bool}} $s
     * @param array{route: callable(string, list<string>): bool, sleep_ms: callable(int): void,
     *     probe_direct: callable(string, string): bool, probe_unbound: callable(string): bool,
     *     uc: callable(list<string>): ?string, restart_unbound: callable(): bool,
     *     log: callable(string, int): void,
     *     save: callable(array): void} $io
     */
    public function __construct(array $p, array $s, array $io)
    {
        $this->p = $p;
        $this->s = $s;
        $this->io = $io;
        $this->st = $p['state'];
        $this->live = $s['unbound']['live_root'];
        $this->route = $s['route'];
        $this->resolver = $s['settings']['resolver'];
        $this->probe = $s['settings']['probe_name'];
    }

    /**
     * Run the plan; the action decides, never the candidates alone (they are filled under every action).
     *
     * @return array{version: int, mode: string, member: ?string,
     *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
     *     probe_failures: int}>, control_failures: int, control_silent_since: ?int,
     *     last_switch: ?array{at: int, from: string, to: string, reason: string},
     *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
     *     member: string}}, tls_applied: ?bool, blocked: ?int,
     *     route_installed: ?array{kind: string, next_hop: string, if: string}}
     */
    public function run(): array
    {
        try {
            switch ($this->p['action']) {
                case 'stop':
                    $this->stop();
                    break;
                case 'skip':
                    $this->skip();
                    break;
                case 'fallback':
                    $this->reasons();
                    $this->fallback();
                    break;
                case 'tunnel':
                    $this->reasons();
                    $this->tryCandidates($this->p['candidates']);
                    break;
                default:
                    $this->none();
            }
        } catch (\Throwable $e) {
            /* ruling R26: what this run changed (the route record above all) is saved before the failure escapes */
            try {
                $this->checkpoint();
            } catch (\Throwable $saveError) {
                $this->log('saving the state after a failure failed too: ' . $saveError->getMessage(), LOG_ERR);
            }
            throw $e;
        }
        return $this->st;
    }

    /**
     * Section 3.7: the configured forwarders back if Unbound may be on the resolver, then the route drained and
     * deleted. A restore that failed only because the control channel is silent ends in a restart (ruling R24): a
     * one-shot stop (Save with enabled off, deinstall) has no later evaluation to escalate from.
     */
    private function stop(): void
    {
        $ours = $this->route['present'] && $this->route['ours'];
        if (!$this->needsRestore() && !$ours && $this->st['mode'] === 'fallback' && $this->st['member'] === null) {
            return;
        }
        $this->reasons();
        if (!$this->restore() && !$this->restartForStop()) {
            $this->log('stop: Unbound may still forward to the resolver, so its route stays (without it the '
                . 'queries would follow the default route)', LOG_ERR);
            return;
        }
        $this->drainAndDelete();
        $this->switchTo('fallback', null);
    }

    /**
     * Restart Unbound when this run's restore met a silent control channel with Unbound running and cacheflush off
     * (the restart then keeps the cache, section 3.4), and confirm through `forward`, polled for up to
     * UU_CONTROL_WAIT_SECONDS, that Unbound came back on its configured root. True only when that is confirmed.
     */
    private function restartForStop(): bool
    {
        if (!$this->silent || !$this->s['unbound']['pid_alive']) {
            return false;
        }
        if ($this->s['contract_input']['cacheflush']) {
            $this->log("stop: Unbound's control channel is silent, and with cacheflush on a restart would wipe its "
                . 'cache: no restart', LOG_ERR);
            return false;
        }
        $this->log("stop: Unbound's control channel is silent, so only a restart brings back its configured root "
            . 'zone (section 3.7): restarting Unbound', LOG_WARNING);
        if (!($this->io['restart_unbound'])()) {
            $this->log('stop: the Unbound restart failed', LOG_ERR);
            return false;
        }
        for ($try = 0; $try < UU_CONTROL_WAIT_SECONDS; $try++) {
            if ($try > 0) {
                ($this->io['sleep_ms'])(1000);
            }
            $out = ($this->io['uc'])(['forward']);
            $live = $out === null ? null : uu_parse_forward($out);
            if ($live === null) {
                continue;
            }
            $this->live = $live;
            if (uu_apply_same($live, [$this->resolver])) {
                $this->log('stop: Unbound restarted but still forwards to the resolver', LOG_ERR);
                return false;
            }
            /* Unbound's own start applied the configured TLS flag, not the plugin */
            $this->st['tls_applied'] = null;
            $this->checkpoint();
            $this->log('stop: Unbound restarted on its configured root zone (' . $this->liveText() . ')',
                LOG_WARNING);
            return true;
        }
        $this->log('stop: Unbound\'s control channel is still silent ' . UU_CONTROL_WAIT_SECONDS
            . ' s after the restart', LOG_ERR);
        return false;
    }

    /**
     * Ruling R25: a member route goes to the reject route first and is held there for the drain, so retries Unbound
     * still has in flight to the resolver fail locally instead of following the default route out a WAN once the
     * route is gone and the filter reload has removed the block rule. A stopped Unbound has nothing in flight.
     */
    private function drainAndDelete(): void
    {
        if ($this->route['present'] && $this->route['ours'] && !$this->route['reject']
            && $this->s['unbound']['pid_alive']) {
            $this->routeReject();
            if ($this->route['reject']) {
                ($this->io['sleep_ms'])(($this->s['fib_sync_ms'] ?? 1000) + UU_FIB_SYNC_MARGIN_MS
                    + UU_STOP_DRAIN_SECONDS * 1000);
                $this->fibPending = false;
            }
        }
        $this->routeDelete();
    }

    /** Control channel silent: nothing can be read or set; only the section 3.10 escalation acts. */
    private function skip(): void
    {
        $this->reasons(LOG_WARNING);
        if (!$this->p['escalate_restart']) {
            return;
        }
        $this->log('restarting Unbound: its control channel stayed silent in tunnel mode, and a restart is the only '
            . 'way back to its configured root zone (the cache is dumped and reloaded)', LOG_WARNING);
        $ok = ($this->io['restart_unbound'])();
        $this->log($ok ? 'Unbound restarted on its configured root zone' : 'Unbound restart failed',
            $ok ? LOG_WARNING : LOG_ERR);
    }

    /** Staying: the reconcile (route, then reassert) and the per-evaluation checks of section 3.5 on M. */
    private function none(): void
    {
        $member = $this->st['member'];
        if ($this->st['mode'] !== 'tunnel' || $member === null) {
            if ($this->p['route_repair']) {
                $this->reasons();
                $this->routeReject();
            }
            return;
        }
        if ($this->p['reassert'] || $this->p['route_repair']) {
            $this->reasons();
        }
        $rest = array_values(array_filter($this->p['candidates'], fn (string $n): bool => $n !== $member));
        if ($this->p['route_repair'] && !$this->routeVia($member)) {
            $this->note("route via $member failed");
            $this->tryCandidates($rest);
            return;
        }
        if ($this->p['reassert'] && !$this->toResolver()) {
            return;
        }
        if (!$this->check($member)) {
            $this->tryCandidates($rest);
        }
    }

    /**
     * Section 3.4 "entering tunnel mode" for each candidate in order; the first that passes is the member. None
     * left, or Unbound refusing the resolver (no other member would change that): fallback.
     *
     * @param list<string> $names
     */
    private function tryCandidates(array $names): void
    {
        foreach ($names as $name) {
            $result = $this->enter($name);
            if ($result === 'ok') {
                return;
            }
            if ($result === 'unbound') {
                break;
            }
        }
        $this->fallback();
    }

    /** 'ok', 'member' (this member failed: try the next) or 'unbound' (Unbound did not take the resolver). */
    private function enter(string $name): string
    {
        if (!$this->routeVia($name)) {
            $this->note("route via $name failed");
            return 'member';
        }
        if (!$this->probeDirect($name)) {
            $this->markFailed($name, 'direct probe of ' . $this->resolver . ' failed');
            return 'member';
        }
        if (!$this->toResolver()) {
            $this->note('Unbound did not take ' . $this->resolver);
            return 'unbound';
        }
        /* toResolver() just flushed the resolver's infra entry, so a failure here counts at once */
        $ok = uu_probe_outcome(true, $this->probeUnbound($name), true) === 'ok';
        $this->setFailures($name, $ok ? 0 : 1);
        if (!$ok) {
            $this->log(sprintf('%s: the check through Unbound failed right after entry (1 of %d)', $name,
                UU_PROBE_FAILURES), LOG_WARNING);
        }
        $this->switchTo('tunnel', $name);
        return 'ok';
    }

    /** The section 3.5 table for the current member; false when it reached UU_PROBE_FAILURES and was marked. */
    private function check(string $name): bool
    {
        $direct = $this->probeDirect($name);
        $outcome = uu_probe_outcome(false, null, false);
        if ($direct) {
            $outcome = uu_probe_outcome(true, $this->probeUnbound($name), false);
            if ($outcome === 'flush_infra') {
                $this->flushInfra();
                $outcome = uu_probe_outcome(true, $this->probeUnbound($name), true);
            }
        }
        if ($outcome === 'ok') {
            $this->setFailures($name, 0);
            return true;
        }
        $failures = ($this->st['timers'][$name]['probe_failures'] ?? 0) + 1;
        $what = $direct ? 'the check through Unbound failed, also after flush_infra'
            : 'direct probe of ' . $this->resolver . ' failed';
        if ($failures < UU_PROBE_FAILURES) {
            $this->setFailures($name, $failures);
            $this->log(sprintf('%s: %s (%d of %d)', $name, $what, $failures, UU_PROBE_FAILURES), LOG_WARNING);
            return true;
        }
        $this->markFailed($name, sprintf('%s (%d of %d)', $what, $failures, UU_PROBE_FAILURES));
        return false;
    }

    /** Fallback steps 1 to 3 (section 3.4); the reject route only once Unbound is off the resolver. */
    private function fallback(): void
    {
        if (!$this->restore()) {
            $this->log('fallback incomplete: Unbound may still forward to the resolver, so no reject route; the next '
                . 'evaluation tries again', LOG_ERR);
            return;
        }
        $this->routeReject();
        $this->switchTo('fallback', null);
    }

    /** Whether Unbound is, or may be, on the resolver. A stopped Unbound restarts on its configured root anyway. */
    private function needsRestore(): bool
    {
        if (!$this->s['unbound']['pid_alive']) {
            return false;
        }
        if ($this->live === null) {
            return $this->st['mode'] === 'tunnel' || $this->maybeResolver;
        }
        return uu_apply_same($this->live, [$this->resolver]);
    }

    /**
     * Unbound's configured root forwarders back, confirmed by `forward`; true when there was nothing to restore. A
     * configured zone forward_add cannot express is never re-added.
     */
    private function restore(): bool
    {
        if (!$this->needsRestore()) {
            return true;
        }
        $zone = $this->s['zone'];
        if ($zone['shape'] === 'unrestorable' || ($zone['shape'] === 'one' && $zone['addrs'] === [])) {
            $problems = $zone['problems'] === [] ? 'no forward-addr' : implode(', ', $zone['problems']);
            $this->log("Unbound's configured root zone cannot be restored through forward_add ($problems): Unbound "
                . 'stays on the resolver until it restarts', LOG_ERR);
            return false;
        }
        if ($zone['shape'] === 'none') {
            $args = ['forward_remove', '.'];
            $what = 'recursion from the root (no . zone configured)';
        } else {
            $args = array_merge(['forward_add'], $zone['tls'] ? ['+t'] : [], ['.'], $zone['addrs']);
            $what = implode(' ', $zone['addrs']) . ($zone['tls'] ? ' with +t' : ' without +t');
        }
        $this->live = null;
        $this->silent = false;
        if (!$this->ucOk($args)) {
            $this->log('unbound-control ' . implode(' ', $args) . ' failed', LOG_ERR);
            return false;
        }
        if (!$this->confirm($zone['addrs'])) {
            $this->log("Unbound's live root is " . $this->liveText() . ' after the restore, not the configured '
                . ($zone['addrs'] === [] ? 'recursion' : implode(' ', uu_apply_bare($zone['addrs']))), LOG_ERR);
            return false;
        }
        $this->st['tls_applied'] = $zone['shape'] === 'one' && $zone['tls'];
        $this->checkpoint();
        $this->log("forwarders: . -> $what (Unbound's configured root zone)");
        return true;
    }

    /** Steps 3 and 4 of entering: forward_add only when the live root is not the resolver, flush_infra, confirm. */
    private function toResolver(): bool
    {
        $this->fibWait();
        if (!uu_apply_same($this->live, [$this->resolver])) {
            $this->maybeResolver = true;
            $this->live = null;
            if (!$this->ucOk(['forward_add', '.', $this->resolver])) {
                $this->log('unbound-control forward_add . ' . $this->resolver . ' failed', LOG_ERR);
                return false;
            }
            $this->st['tls_applied'] = false;
            $this->checkpoint();
            $this->log('forwarders: . -> ' . $this->resolver . ', plain DNS inside the tunnel (no +t)');
        }
        $this->flushInfra();
        if (!$this->confirm([$this->resolver])) {
            $this->log("Unbound's live root is " . $this->liveText() . ', not ' . $this->resolver, LOG_ERR);
            return false;
        }
        return true;
    }

    private function routeVia(string $name): bool
    {
        $m = $this->s['members'][$name] ?? null;
        if ($m === null) {
            $this->log("$name has no gateway record: no route through it", LOG_ERR);
            return false;
        }
        if (uu_plan_route_via($this->route, $m)) {
            return true;
        }
        if ($this->route['present'] && !$this->route['ours']) {
            $this->log("the resolver's route is not ours: it is not replaced by one via $name", LOG_ERR);
            return false;
        }
        /* -ifp pins the device: members may share a next hop */
        if (!$this->routeSet(['-host', $this->resolver, $m['next_hop'], '-ifp', $m['if']])) {
            $this->log("route: {$this->resolver} via $name ({$m['next_hop']} on {$m['if']}) failed", LOG_ERR);
            return false;
        }
        $this->route = ['present' => true, 'gateway' => $m['next_hop'], 'interface' => $m['if'], 'reject' => false,
                        'ours' => true];
        $this->st['route_installed'] = ['kind' => 'member', 'next_hop' => $m['next_hop'], 'if' => $m['if']];
        $this->checkpoint();
        $this->log("route: {$this->resolver} via $name ({$m['next_hop']} on {$m['if']})");
        return true;
    }

    private function routeReject(): void
    {
        if ($this->route['present'] && !$this->route['ours']) {
            $this->log("the resolver's route is not ours: no reject route over it", LOG_WARNING);
            return;
        }
        if ($this->route['present'] && $this->route['reject']) {
            return;
        }
        if (!$this->routeSet(['-host', $this->resolver, '127.0.0.1', '-reject'])) {
            $this->log("route: the reject route for {$this->resolver} failed", LOG_ERR);
            return;
        }
        $this->route = ['present' => true, 'gateway' => '', 'interface' => 'lo0', 'reject' => true, 'ours' => true];
        $this->st['route_installed'] = ['kind' => 'reject', 'next_hop' => '', 'if' => 'lo0'];
        $this->checkpoint();
        $this->log("route: {$this->resolver} rejected locally");
    }

    private function routeDelete(): void
    {
        if (!$this->route['present'] || !$this->route['ours']) {
            return;
        }
        if (!($this->io['route'])('delete', ['-host', $this->resolver])) {
            $this->log("route: deleting the route of {$this->resolver} failed", LOG_ERR);
            return;
        }
        $this->route = ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false, 'ours' => false];
        $this->st['route_installed'] = null;
        $this->checkpoint();
        $this->log("route: {$this->resolver} deleted");
    }

    /**
     * change when the route is present, add when absent, never delete and add.
     *
     * @param list<string> $args
     */
    private function routeSet(array $args): bool
    {
        $verb = $this->route['present'] ? 'change' : 'add';
        $ok = ($this->io['route'])($verb, $args);
        if (!$ok && $verb === 'change') {
            /* the route went after the snapshot (its device was recreated): add it */
            $ok = ($this->io['route'])('add', $args);
        }
        if ($ok) {
            $this->fibPending = true;
        }
        return $ok;
    }

    /** A changed route reaches the data path up to fib_max_sync_delay_ms later (section 3.4 step 1). */
    private function fibWait(): void
    {
        if (!$this->fibPending) {
            return;
        }
        /* 1000 is FreeBSD's default; the contract refuses tunnel mode when the sysctl is unreadable */
        ($this->io['sleep_ms'])(($this->s['fib_sync_ms'] ?? 1000) + UU_FIB_SYNC_MARGIN_MS);
        $this->fibPending = false;
    }

    private function probeDirect(string $name): bool
    {
        $this->fibWait();
        $ok = ($this->io['probe_direct'])($this->resolver, $this->probe);
        $this->st['checks']['direct'] = ['ok' => $ok, 'at' => time(), 'member' => $name];
        return $ok;
    }

    /** flush_type first: with serve-expired and aggressive-nsec a cached answer would pass without the upstream. */
    private function probeUnbound(string $name): bool
    {
        $this->fibWait();
        $flushed = $this->ucOk(['flush_type', $this->probe, 'SOA']);
        if (!$flushed) {
            $this->log("unbound-control flush_type {$this->probe} SOA failed: the check through Unbound counts as "
                . 'failed (a cached answer proves nothing)', LOG_WARNING);
        }
        $ok = $flushed && ($this->io['probe_unbound'])($this->probe);
        $this->st['checks']['unbound'] = ['ok' => $ok, 'at' => time(), 'member' => $name];
        return $ok;
    }

    private function flushInfra(): void
    {
        if (!$this->ucOk(['flush_infra', $this->resolver])) {
            $this->log('unbound-control flush_infra ' . $this->resolver . ' failed', LOG_WARNING);
        }
    }

    /**
     * Read the live root back and compare it as a set; `forward` prints bare addresses in its own order.
     *
     * @param list<string> $want
     */
    private function confirm(array $want): bool
    {
        $out = ($this->io['uc'])(['forward']);
        $this->silent = $this->silent || $out === null;
        $this->live = $out === null ? null : uu_parse_forward($out);
        return uu_apply_same($this->live, $want);
    }

    /**
     * @param list<string> $args
     */
    private function ucOk(array $args): bool
    {
        $out = ($this->io['uc'])($args);
        $this->silent = $this->silent || $out === null;
        return $out !== null && trim($out) === 'ok';
    }

    private function liveText(): string
    {
        if ($this->live === null) {
            return 'unknown';
        }
        return $this->live === [] ? 'off (recursion)' : implode(' ', $this->live);
    }

    private function markFailed(string $name, string $why): void
    {
        $timer = $this->st['timers'][$name] ?? uu_timer_new();
        $timer['resolver_failed_until'] = $this->s['now'] + $this->s['settings']['failback_delay'];
        $timer['probe_failures'] = 0;
        $this->st['timers'][$name] = $timer;
        $this->note("$name: $why");
        $this->log(sprintf('%s: %s; resolver-failed for %d s', $name, $why, $this->s['settings']['failback_delay']),
            LOG_WARNING);
    }

    private function setFailures(string $name, int $failures): void
    {
        $timer = $this->st['timers'][$name] ?? uu_timer_new();
        $timer['probe_failures'] = $failures;
        $this->st['timers'][$name] = $timer;
    }

    /** Record a mode or member change with wall time (display only) and its reasons. */
    private function switchTo(string $mode, ?string $member): void
    {
        if ($this->st['mode'] === $mode && $this->st['member'] === $member) {
            return;
        }
        $from = uu_apply_where($this->st['mode'], $this->st['member']);
        $to = uu_apply_where($mode, $member);
        $reason = implode('; ', array_merge($this->p['reasons'], $this->notes));
        $this->st['mode'] = $mode;
        $this->st['member'] = $member;
        $this->st['last_switch'] = ['at' => time(), 'from' => $from, 'to' => $to, 'reason' => $reason];
        $this->checkpoint();
        $this->log("switch $from -> $to: $reason");
    }

    private function reasons(int $prio = LOG_NOTICE): void
    {
        if ($this->reasonsLogged) {
            return;
        }
        $this->reasonsLogged = true;
        foreach ($this->p['reasons'] as $reason) {
            $this->log($reason, $prio);
        }
    }

    /** Save what the run has reached (ruling R26). */
    private function checkpoint(): void
    {
        ($this->io['save'])($this->st);
    }

    private function note(string $text): void
    {
        $this->notes[] = $text;
    }

    private function log(string $msg, int $prio = LOG_NOTICE): void
    {
        ($this->io['log'])($msg, $prio);
    }
}

/**
 * Apply the plan and return the state to save. In dry run nothing is applied: every step is logged through a
 * simulated I/O that takes each probe as passing, and the plan's own state comes back. A dry run that finds the
 * plugin's changes live (dry run turned on in tunnel mode, or the plugin's route) first undoes them for real, as
 * stop does, so dry run never leaves Unbound on the resolver.
 *
 * @param array{action: string, candidates: list<string>, reassert: bool, route_repair: bool,
 *     escalate_restart: bool,
 *     state: array{version: int, mode: string, member: ?string,
 *         timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int,
 *         resolver_failed_until: ?int, probe_failures: int}>, control_failures: int,
 *         control_silent_since: ?int, last_switch: ?array{at: int, from: string, to: string, reason: string},
 *         checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *         member: string}}, tls_applied: ?bool, blocked: ?int,
 *         route_installed: ?array{kind: string, next_hop: string, if: string}},
 *     reasons: list<string>} $p uu_plan()
 * @param array{now: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, failback_delay: int,
 *         probe_name: string},
 *     members: array<string, array{name: string, interface: string, if: string, next_hop: string, disabled: bool,
 *         force_down: bool, monitor_disable: bool, monitor: string, time_period: int, interval: int,
 *         loss_interval: int, losshigh: int}>,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool},
 *     fib_sync_ms: ?int, contract_input: array{cacheflush: bool}} $s the snapshot the plan was made from
 * @param array{route: callable(string, list<string>): bool, sleep_ms: callable(int): void,
 *     probe_direct: callable(string, string): bool, probe_unbound: callable(string): bool,
 *     uc: callable(list<string>): ?string, restart_unbound: callable(): bool, log: callable(string, int): void,
 *     save: callable(array): void} $io
 * @return array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int}>, control_failures: int, control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     route_installed: ?array{kind: string, next_hop: string, if: string}}
 */
function uu_apply(array $p, array $s, array $io): array
{
    if (!$s['settings']['dry_run']) {
        return (new UuApplyRun($p, $s, $io))->run();
    }
    $changed = $p['state']['mode'] === 'tunnel' || ($s['route']['present'] && $s['route']['ours']);
    if ($changed && $p['action'] === 'skip') {
        /* ruling R24: through a silent channel nothing can be undone; the skip runs as planned, its escalation
         * included, and the undo waits for the channel to answer */
        return (new UuApplyRun($p, $s, $io))->run();
    }
    if ($p['action'] === 'stop' || $changed) {
        if ($changed) {
            ($io['log'])('dry run: undoing the plugin\'s live changes first (forwarders and route), as stop does',
                LOG_NOTICE);
        }
        $p['action'] = 'stop';
        return (new UuApplyRun($p, $s, $io))->run();
    }
    uu_apply_preview($p, $s, $io['log']);
    return $p['state'];
}

/**
 * Log every step the plan would run, as uu_apply() would run it with every probe passing; calls nothing but log.
 * Dry run and evaluate.php's replay.
 *
 * @param array{action: string, candidates: list<string>, reassert: bool, route_repair: bool,
 *     escalate_restart: bool,
 *     state: array{version: int, mode: string, member: ?string,
 *         timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int,
 *         resolver_failed_until: ?int, probe_failures: int}>, control_failures: int,
 *         control_silent_since: ?int, last_switch: ?array{at: int, from: string, to: string, reason: string},
 *         checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *         member: string}}, tls_applied: ?bool, blocked: ?int,
 *         route_installed: ?array{kind: string, next_hop: string, if: string}},
 *     reasons: list<string>} $p
 * @param array{now: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, resolver: string, failback_delay: int,
 *         probe_name: string},
 *     members: array<string, array{name: string, interface: string, if: string, next_hop: string, disabled: bool,
 *         force_down: bool, monitor_disable: bool, monitor: string, time_period: int, interval: int,
 *         loss_interval: int, losshigh: int}>,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     route: array{present: bool, gateway: string, interface: string, reject: bool, ours: bool},
 *     fib_sync_ms: ?int, contract_input: array{cacheflush: bool}} $s
 * @param callable(string, int): void $log
 */
function uu_apply_preview(array $p, array $s, callable $log): void
{
    (new UuApplyRun($p, $s, uu_dry_io($log, $s['unbound']['live_root'])))->run();
}

/**
 * An Io that only logs, each line marked [dry]. It plays Unbound's live root along (forward_add and forward_remove
 * set what `forward` prints), so the logged steps are the ones a passing run would take.
 *
 * @param callable(string, int): void $log
 * @param ?list<string> $live the snapshot's live root
 * @return array{route: callable(string, list<string>): bool, sleep_ms: callable(int): void,
 *     probe_direct: callable(string, string): bool, probe_unbound: callable(string): bool,
 *     uc: callable(list<string>): ?string, restart_unbound: callable(): bool, log: callable(string, int): void,
 *     save: callable(array): void}
 */
function uu_dry_io(callable $log, ?array $live): array
{
    $say = function (string $msg) use ($log): void {
        $log('[dry] ' . $msg, LOG_NOTICE);
    };
    return [
        'route' => function (string $verb, array $args) use ($say): bool {
            $say('would run: route -n ' . $verb . ' ' . implode(' ', $args));
            return true;
        },
        'sleep_ms' => function (int $ms) use ($say): void {
            $say("would wait $ms ms for the route change to reach the data path");
        },
        'probe_direct' => function (string $resolver, string $name) use ($say): bool {
            $say("would probe $resolver for $name SOA through the route (taken as passing)");
            return true;
        },
        'probe_unbound' => function (string $name) use ($say): bool {
            $say("would ask Unbound for $name SOA (taken as passing)");
            return true;
        },
        'uc' => function (array $args) use ($say, &$live): ?string {
            $say('would run: unbound-control ' . implode(' ', $args));
            $cmd = $args[0] ?? '';
            if ($cmd === 'forward') {
                return $live === null ? null : ($live === [] ? 'off (using root hints)' : implode(' ', $live));
            }
            if ($cmd === 'forward_add') {
                $dot = array_search('.', $args, true);
                $live = uu_apply_bare(array_values(array_slice($args, $dot === false ? count($args) : $dot + 1)));
            } elseif ($cmd === 'forward_remove') {
                $live = [];
            }
            return 'ok';
        },
        'restart_unbound' => function () use ($say): bool {
            $say('would run: configctl unbound restart');
            return true;
        },
        'log' => function (string $msg, int $prio) use ($log): void {
            $log('[dry] ' . $msg, $prio);
        },
        'save' => function (array $state): void {
            /* a simulated run is never saved */
        },
    ];
}

/** One resolver probe: `drill -D <name> @<server> SOA`, each try under UU_PROBE_TIMEOUT_SECONDS. */
function uu_drill(string $server, string $name): bool
{
    for ($try = 0; $try < UU_PROBE_TRIES; $try++) {
        $out = [];
        $rc = 0;
        exec('/usr/bin/timeout ' . UU_PROBE_TIMEOUT_SECONDS . ' /usr/bin/drill -D ' . escapeshellarg($name) . ' '
            . escapeshellarg('@' . $server) . ' SOA 2>&1', $out, $rc);
        if (uu_drill_passed(implode("\n", $out))) {
            return true;
        }
    }
    return false;
}

/**
 * The real I/O. Every unbound-control call runs under UU_CONTROL_CALL_TIMEOUT_SECONDS (section 3.1); a failing
 * route or unbound-control call logs its output here, where the output is known.
 *
 * @param string $statePath where save writes the state (evaluate.php's UU_STATE_PATH)
 * @return array{route: callable(string, list<string>): bool, sleep_ms: callable(int): void,
 *     probe_direct: callable(string, string): bool, probe_unbound: callable(string): bool,
 *     uc: callable(list<string>): ?string, restart_unbound: callable(): bool, log: callable(string, int): void,
 *     save: callable(array): void}
 */
function uu_live_io(string $statePath): array
{
    return [
        'route' => function (string $verb, array $args): bool {
            if (!in_array($verb, ['add', 'change', 'delete'], true)) {
                return false;
            }
            $out = [];
            $rc = 0;
            exec('/sbin/route -n ' . $verb . ' ' . implode(' ', array_map('escapeshellarg', $args)) . ' 2>&1', $out,
                $rc);
            if ($rc !== 0) {
                uu_log("route -n $verb " . implode(' ', $args) . ': ' . implode('; ', $out), LOG_WARNING);
            }
            return $rc === 0;
        },
        'sleep_ms' => function (int $ms): void {
            usleep(max(0, $ms) * 1000);
        },
        'probe_direct' => fn (string $resolver, string $name): bool => uu_drill($resolver, $name),
        'probe_unbound' => fn (string $name): bool => uu_drill('127.0.0.1', $name),
        'uc' => function (array $args): ?string {
            $out = [];
            $rc = 0;
            exec('/usr/bin/timeout ' . UU_CONTROL_CALL_TIMEOUT_SECONDS
                . ' /usr/local/sbin/unbound-control -c /var/unbound/unbound.conf '
                . implode(' ', array_map('escapeshellarg', $args)) . ' 2>&1', $out, $rc);
            if ($rc !== 0) {
                uu_log('unbound-control ' . implode(' ', $args) . ' (exit ' . $rc . '): ' . implode('; ', $out),
                    LOG_WARNING);
                return null;
            }
            return implode("\n", $out) . "\n";
        },
        'restart_unbound' => function (): bool {
            $out = [];
            $rc = 0;
            exec('/usr/local/sbin/configctl unbound restart 2>&1', $out, $rc);
            if ($rc !== 0) {
                uu_log('configctl unbound restart (exit ' . $rc . '): ' . implode('; ', $out), LOG_ERR);
            }
            return $rc === 0;
        },
        'log' => function (string $msg, int $prio): void {
            uu_log($msg, $prio);
        },
        'save' => function (array $state) use ($statePath): void {
            uu_state_save($statePath, $state);
        },
    ];
}
