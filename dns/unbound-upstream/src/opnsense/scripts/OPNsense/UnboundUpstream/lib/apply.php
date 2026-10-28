<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Apply a plan through injected I/O, so order and failure
 * handling are testable. uu_live_io() binds the real commands.
 *
 * Io = array{route: callable(string $verb, list<string> $args): bool, sleep_ms: callable(int $ms): void,
 *            probe_direct: callable(string $resolver, string $name): bool, probe_unbound: callable(string $name): bool,
 *            uc: callable(list<string> $args): ?string, restart_unbound: callable(): bool,
 *            log: callable(string $msg, int $prio): void, save: callable(array $state): void}
 *   route runs route(8) with the verb (add, change or delete); uc runs unbound-control and returns its reply, an
 *   `error ...` reply from the daemon included, and null only when nothing answered (uu_uc_result()); each probe is
 *   one `drill -D <name> @<server> SOA` tried UU_PROBE_TRIES times and passes on NOERROR with the ad flag; log takes a syslog priority; save writes the State (state.php) the run has
 *   reached, after every successful route or forwarder change and when an exception escapes, so the route record
 *   (the route record in state.php's addresses) survives a failure partway through.
 *
 * Every path keeps these, per address (each member's own resolver, every address the state's map holds):
 *   - a route is changed in place (change, or add when absent), never deleted and added: in the gap the address
 *     would follow the default route; an address used again (an orphan in its hold) gets its member route by change
 *     from its reject route;
 *   - nothing probes an address before its route change reached the data path (fib_sync_ms + UU_FIB_SYNC_MARGIN_MS);
 *   - forward_add is decided by Unbound's live root, never by the state's mode, and the restore by whether the live
 *     root names an address of the plugin's and is not Unbound's configured root zone (uu_plan_restore_due());
 *   - a reject route never replaces a route the plugin did not make, and is installed on an address only while its
 *     forwarded is false, which only a live root read in this run that names something else makes it (else it would
 *     black-hole every query), except as a removal's last resort, when no plugin is left to undo the routes; no route
 *     is deleted then either (the queries would follow the default route out a WAN);
 *   - a switch to a member with another resolver changes every other address the map holds to its reject route once
 *     the live root is confirmed as the new one; an address that is no member's resolver any more (an orphan) is
 *     released then, and deleted only by a drain at least UU_OLD_ADDRESS_HOLD later: one flush_requestlist, one drain,
 *     then each delete, nothing deleted when the flush failed. An orphan that Unbound's own configured root zone names
 *     is drained and deleted at once, behind its reject route (uu_plan_configured_orphan()): the owner's forwarder wins
 *     over the hold. An address that is still a member's resolver keeps its reject route while it is not in use,
 *     whatever the configured zone names;
 *   - a stop undoes every address, ignoring the hold: one restore, every reject route, one flush_requestlist, one
 *     drain, every delete; an address Unbound's restored root still names keeps its route, but for an orphan on its
 *     reject route, which is drained and deleted with the others;
 *   - an address the run had to leave and could not (its reject route, its delete, the flush_requestlist before it or
 *     the restore that had to take Unbound off it failed) has an error line naming it (the one-address lines read as
 *     they always did) and keeps its entry, its route record and its hold, so the next evaluation tries again;
 *   - the state's mode and member change only when the step that makes them true succeeded, and a switch in place on
 *     the same member (its resolver changed) records none;
 *   - Unbound's caches are never flushed: flush_infra <resolver> and flush_type <probe_name> SOA only; the
 *     flush_requestlist of a stop or a drain drops the queries in progress (their clients ask again), never a cache
 *     entry, and runs only behind reject routes.
 *
 * The fail-closed view keeps these on every path:
 *   - the refuse of "." is armed before a fallback's restore, and before the restore of a stop that keeps the view
 *     (an upgrade from tunnel mode), which runs whatever the arm's outcome;
 *   - it is lifted only once the live root is the resolver (an entry's or a reassert's confirm, or the snapshot's
 *     read when staying needs no reassert) or the configured root zone (a stop's restore, its restart, or nothing to
 *     restore; the fallback of an emptied set), never by a stop that kept the view (an upgrade, a tick of the
 *     removal) or that could not restore;
 *   - no view command runs unless the set is read as loaded or the read shows the refuse of ".", so an owner with
 *     nothing selected gets 1.4's calls exactly;
 *   - after apply, the file step (uu_view_file_apply(), uu_view_file_io() binds it) installs a view file only once
 *     unbound-checkconf passes it, deletes it only once the set is no longer refused, never touches the copy in
 *     /var/unbound/etc (core's start empties and refills it), and restarts Unbound through core's restart only when
 *     the copy's node lines differ from the file's (a deleted file has none).
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/address.php';
require_once __DIR__ . '/choose.php';
require_once __DIR__ . '/state.php';
require_once __DIR__ . '/planner.php';
require_once __DIR__ . '/views.php';
require_once __DIR__ . '/snapshot.php';
require_once __DIR__ . '/control.php';
require_once __DIR__ . '/log.php';
require_once __DIR__ . '/corecmd.php';

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
 * Whether a stop has anything to undo, as the snapshot and the state show it: tunnel mode (or a member), a restore due
 * (the live root names an address of the plugin's and is not Unbound's configured root zone, uu_plan_restore_due(), or
 * with the live root unknown, one of them is recorded forwarded), or a route of the plugin's on an address Unbound no
 * longer forwards to, as the snapshot's read says (uu_state_forwarded()), or an orphan's reject route that Unbound's
 * own configured root zone names (uu_plan_configured_orphan()): the stop releases it, and dry run, which otherwise
 * only previews, must undo it for real or it would leave every lookup rejected. A route the stop keeps by design, on
 * any other address Unbound's configured root zone names, is nothing to undo, and a stopped Unbound needs no
 * restore.
 * The one test of stop()'s quiet return and of dry run's undo first, so neither repeats a line every minute over such a
 * route.
 * The plan's view adds the view work of a stop: the refuse armed, or the file or its copy on disk, even with nothing
 * left of 1.4's to undo (a disable while in fallback). A plan whose view is kept (an upgrade, a tick of the removal)
 * has only the arm: a loaded set read without the refuse while the file is on disk (the upgrade window's mark; a
 * removal deletes the file), which stop() arms before its restore, also in fallback mode after an arm that failed. An
 * unknown read is no work, and null is 1.4's answer.
 *
 * @param array{mode: string, member: ?string, addresses: array<string, array{route: ?array{kind: string,
 *     next_hop: string, if: string}, forwarded: bool, released_at: ?int}>} $st
 * @param array{settings: array{default: string}, members: array<string, array{resolver: string}>,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     routes: array<string, array{present: bool, gateway: string, interface: string, reject: bool,
 *         ours: bool}>,
 *     view: array{copy: ?string, file_present: bool}} $s
 * @param ?array{active: bool, armed: ?bool, keep: bool} $view the plan's view
 */
function uu_apply_undo_due(array $st, array $s, ?array $view = null): bool
{
    if ($st['mode'] === 'tunnel' || $st['member'] !== null) {
        return true;
    }
    if ($view !== null && $view['keep'] && $view['active'] && $view['armed'] === false && $s['view']['file_present']) {
        return true;
    }
    if ($view !== null && !$view['keep']
        && ($view['armed'] === true || $s['view']['file_present'] || $s['view']['copy'] !== null)) {
        return true;
    }
    $pid = $s['unbound']['pid_alive'];
    $read = uu_state_snapshot_read($s['unbound']);
    $kept = uu_plan_addresses($s);
    $addresses = array_values(array_unique(array_merge($kept, array_map('strval', array_keys($s['routes'])),
        array_map('strval', array_keys($st['addresses'])))));
    foreach ($addresses as $address) {
        $forwarded = uu_state_forwarded($read, $address, $st['addresses'][$address]['forwarded'] ?? false);
        $route = uu_plan_route($s, $address);
        if (($pid && $read === null && $forwarded) || ($route['present'] && $route['ours'] && !$forwarded)
            || ($route['present'] && $route['ours'] && $route['reject']
                && uu_plan_configured_orphan($read, $s['zone'], $address, $kept))) {
            return true;
        }
    }
    return $pid && uu_plan_restore_due($read, $addresses, $s['zone']) !== null;
}

/**
 * One apply: the plan's steps in order against the injected I/O, tracking per address what this run itself changed
 * (each route, the live root) so each later step decides on the current facts rather than the snapshot's. The run's
 * addresses are the planner's (uu_plan_addresses()), every address the state's map holds and every address the
 * snapshot read a route for; each member's own resolver is the one its entry routes, probes and forwards to.
 */
final class UuApplyRun
{
    /**
     * @var array{action: string, candidates: list<string>, reassert: bool, route_repair: bool,
     *     escalate_restart: bool,
     *     state: array{version: int, mode: string, member: ?string,
     *         timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int,
     *         resolver_failed_until: ?int, probe_failures: int,
     *             last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
     *         control_silent_since: ?int, last_switch: ?array{at: int, from: string, to: string, reason: string},
     *         checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
     *         member: string}}, tls_applied: ?bool, blocked: ?int,
     *         addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
     *             forwarded: bool, released_at: ?int}>,
     *         view: array{refuse: string, scope: string, nets: list<string>, problem: ?string,
     *             restarted: ?string, unwritable: int}},
     *     reasons: list<string>, drain: list<string>,
     *     view: array{active: bool, armed: ?bool, keep: bool, zones: array<string, string>,
     *         mirror: array<string, list<string>>, problem: ?string}}
     */
    private array $p;
    /**
     * @var array{now: int, wall: int,
     *     settings: array{enabled: bool, dry_run: bool, group: string, default: string,
     *         rows: array<string, string>, failback_delay: int, probe_name: string},
     *     members: array<string, array{name: string, interface: string, if: string, ipprotocol: string,
     *         resolver: string, next_hop: string, disabled: bool, force_down: bool, monitor_disable: bool,
     *         monitor: string, time_period: int, interval: int, loss_interval: int, losshigh: int}>, stop: ?string,
     *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
     *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
     *     routes: array<string, array{present: bool, gateway: string, interface: string, reject: bool,
     *         ours: bool}>,
     *     route_flags: array<string, list<string>>,
     *     fib_sync_ms: ?int, contract_input: array{cacheflush: bool}, upgrade: bool,
     *     view: array{scope: string, nets: list<string>, notes: list<string>, acl: ?array{nodes: list<array{net:
     *         string, action: string}>, foreign: list<string>}, zones: ?array<string, string>, data: ?list<string>,
     *         loaded: string, view_zones: array<string, string>, view_data: list<string>, file: ?string,
     *         copy: ?string, file_present: bool}}
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
     *     probe_failures: int,
     *         last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
     *     control_silent_since: ?int,
     *     last_switch: ?array{at: int, from: string, to: string, reason: string},
     *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
     *     member: string}}, tls_applied: ?bool, blocked: ?int,
     *     addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
     *         forwarded: bool, released_at: ?int}>,
     *     view: array{refuse: string, scope: string, nets: list<string>, problem: ?string,
     *         restarted: ?string, unwritable: int}}
     */
    private array $st;
    /** @var ?list<string> Unbound's live root as last read or set; null while unknown */
    private ?array $live;
    /**
     * @var array<string, bool> per address (its canonical form): Unbound is, or may be, forwarding to it. True once
     *     this run sent forward_add for it, although the reply was lost, or a live root read names it; false only
     *     after a read in this run that succeeded and names something else. A failed or unparseable read changes
     *     nothing.
     */
    private array $forwarded = [];
    /** @var array<string, bool> forwarded as the snapshot's read left it, before any call of this run */
    private array $forwardedAtStart = [];
    /** @var array<string, array{present: bool, gateway: string, interface: string, reject: bool, ours: bool}> */
    private array $routes = [];
    /** @var array<string, ?array{kind: string, next_hop: string, if: string}> the route the plugin last installed */
    private array $records = [];
    /** @var array<string, bool> per address: a route call failed after an absent read, so the route is not known */
    private array $unknown = [];
    /** @var array<string, bool> per address: its route changed and the change may not have reached the data path */
    private array $fibPending = [];
    /** @var list<string> the planner's addresses (uu_plan_addresses()): every member's resolver, or the Default */
    private array $kept;
    /**
     * @var list<string> the addresses the state's map held when the run started: a checkpoint between two reject routes
     *     must not drop a later one from step 5 (footprint() prunes a route-less entry Unbound no longer forwards to)
     */
    private array $recorded;
    /** @var array<string, ?int> each recorded address's released_at as the run started: its hold if pruned and back */
    private array $releasedAtStart = [];
    /** an unbound-control call of this run got no answer (timeout or no channel) */
    private bool $silent = false;
    private bool $reasonsLogged = false;
    /** @var list<string> what this run found on the way, for the switch reason */
    private array $notes = [];
    private string $probe;
    /**
     * whether the view holds the refuse of ".", as the snapshot read it or this run's last arm or lift read it back;
     * null while unknown (not loaded, or a read back that failed)
     */
    private ?bool $viewArmed;
    /** @var array<string, string> the view's zones as last read: the snapshot's, then each arm's or lift's read back */
    private array $viewZones;
    /**
     * this run wanted the set refused: it ran fallback(), stayed in fallback, or armed the set for a stop that keeps
     * the view; else it wanted the refuse lifted, whatever the mode a failed restore left
     */
    private bool $wantArmed = false;

    /**
     * @param array{action: string, candidates: list<string>, reassert: bool, route_repair: bool,
     *     escalate_restart: bool,
     *     state: array{version: int, mode: string, member: ?string,
     *         timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int,
     *         resolver_failed_until: ?int, probe_failures: int,
     *             last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
     *         control_silent_since: ?int, last_switch: ?array{at: int, from: string, to: string, reason: string},
     *         checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
     *         member: string}}, tls_applied: ?bool, blocked: ?int,
     *         addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
     *             forwarded: bool, released_at: ?int}>,
     *         view: array{refuse: string, scope: string, nets: list<string>, problem: ?string,
     *             restarted: ?string, unwritable: int}},
     *     reasons: list<string>, drain: list<string>,
     *     view: array{active: bool, armed: ?bool, keep: bool, zones: array<string, string>,
     *         mirror: array<string, list<string>>, problem: ?string}} $p
     * @param array{now: int, wall: int,
     *     settings: array{enabled: bool, dry_run: bool, group: string, default: string,
     *         rows: array<string, string>, failback_delay: int, probe_name: string},
     *     members: array<string, array{name: string, interface: string, if: string, ipprotocol: string,
     *         resolver: string, next_hop: string, disabled: bool, force_down: bool, monitor_disable: bool,
     *         monitor: string, time_period: int, interval: int, loss_interval: int, losshigh: int}>, stop: ?string,
     *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
     *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
     *     routes: array<string, array{present: bool, gateway: string, interface: string, reject: bool,
     *         ours: bool}>,
     *     route_flags: array<string, list<string>>,
     *     fib_sync_ms: ?int, contract_input: array{cacheflush: bool}, upgrade: bool,
     *     view: array{scope: string, nets: list<string>, notes: list<string>, acl: ?array{nodes: list<array{net:
     *         string, action: string}>, foreign: list<string>}, zones: ?array<string, string>, data: ?list<string>,
     *         loaded: string, view_zones: array<string, string>, view_data: list<string>, file: ?string,
     *         copy: ?string, file_present: bool}} $s
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
        $this->probe = $s['settings']['probe_name'];
        $this->viewArmed = $p['view']['armed'];
        $this->viewZones = $s['view']['view_zones'];
        $this->kept = uu_plan_addresses($s);
        $this->recorded = array_map('strval', array_keys($this->st['addresses']));
        foreach ($this->st['addresses'] as $address => $entry) {
            $this->releasedAtStart[(string)$address] = $entry['released_at'];
        }
        /* each address is forwarded again as the live root read for this snapshot says, before any route call; a root
         * that could not be read leaves the record as it was, but Unbound that is not running forwards to nothing (it
         * restarts on its configured root), which counts as a read of the empty root */
        $read = uu_state_snapshot_read($s['unbound']);
        $addresses = array_merge($this->kept, array_map('strval', array_keys($s['routes'])),
            array_map('strval', array_keys($this->st['addresses'])));
        foreach (array_unique($addresses) as $address) {
            $this->routes[$address] = uu_plan_route($s, $address);
            $this->records[$address] = uu_state_route_record($this->st, $address);
            $this->forwarded[$address] = $this->st['addresses'][$address]['forwarded'] ?? false;
        }
        $this->setLive($read);
        foreach (array_keys($this->st['addresses']) as $address) {
            $this->st['addresses'][$address]['forwarded'] = $this->forwarded[(string)$address];
        }
        $this->forwardedAtStart = $this->forwarded;
        /* the forwarded flags took the snapshot's read (the empty root for an Unbound that is not running), but the
         * live root stays what the snapshot read: unknown (null) for an Unbound that is not running, which
         * needsRestore() reads with the pid first */
        $this->live = $s['unbound']['live_root'];
    }

    /**
     * "the resolver" in an error line, with the addresses it is about when the run has more than one, so a line about
     * one address reads as it always did.
     *
     * @param list<string> $addresses
     */
    private function theResolver(array $addresses): string
    {
        return count($this->routes) > 1 && $addresses !== []
            ? 'the resolver (' . implode(', ', $addresses) . ')' : 'the resolver';
    }

    /**
     * The run's addresses, sorted.
     *
     * @return list<string>
     */
    private function addresses(): array
    {
        $addresses = array_map('strval', array_keys($this->routes));
        sort($addresses, SORT_STRING);
        return $addresses;
    }

    /** A member's effective resolver, canonical; '' for none (such a member is no candidate). */
    private function resolverOf(string $name): string
    {
        return uu_member_resolver($this->s, $name);
    }

    /**
     * An address's route as this run last saw or made it.
     *
     * @return array{present: bool, gateway: string, interface: string, reject: bool, ours: bool}
     */
    private function route(string $address): array
    {
        return $this->routes[$address]
            ?? ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false, 'ours' => false];
    }

    /** Whether the address's route is there and the plugin's. */
    private function ours(string $address): bool
    {
        return $this->route($address)['present'] && $this->route($address)['ours'];
    }

    /**
     * Whether the address is an orphan Unbound's own configured root zone names, as this run last read or set the live
     * root (uu_plan_configured_orphan()): released at once, never held on its reject route.
     */
    private function configuredOrphan(string $address): bool
    {
        return uu_plan_configured_orphan($this->live, $this->s['zone'], $address, $this->kept);
    }

    /**
     * Take a live root read: it settles, for every address, whether Unbound forwards to it, unless it failed (null),
     * which leaves what was known.
     *
     * @param ?list<string> $live
     */
    private function setLive(?array $live): void
    {
        $this->live = $live;
        foreach ($this->forwarded as $address => $forwarded) {
            $this->forwarded[$address] = uu_state_forwarded($live, (string)$address, $forwarded);
        }
    }

    /**
     * Run the plan; the action decides, never the candidates alone (they are filled under every action). The orphans
     * the plan says are due are drained last.
     *
     * @return array{version: int, mode: string, member: ?string,
     *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
     *     probe_failures: int,
     *         last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
     *     control_silent_since: ?int,
     *     last_switch: ?array{at: int, from: string, to: string, reason: string},
     *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
     *     member: string}}, tls_applied: ?bool, blocked: ?int,
     *     addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
     *         forwarded: bool, released_at: ?int}>,
     *     view: array{refuse: string, scope: string, nets: list<string>, problem: ?string,
     *         restarted: ?string, unwritable: int}}
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
            if (!in_array($this->p['action'], ['stop', 'skip'], true)) {
                $this->reconcile();
            }
            if ($this->p['action'] !== 'stop') {
                $this->viewRecord();
            }
            $this->drainOrphans($this->p['drain']);
        } catch (\Throwable $e) {
            /* what this run changed (the route records above all) is saved before the failure escapes */
            try {
                $this->checkpoint();
            } catch (\Throwable $saveError) {
                $this->log('saving the state after a failure failed too: ' . $saveError->getMessage(), LOG_ERR);
            }
            throw $e;
        }
        $this->footprint();
        return $this->st;
    }

    /**
     * The configured forwarders back if Unbound may be on one of the plugin's addresses, then the view's refuse
     * lifted (unless the stop keeps the view: an upgrade, a tick of the removal; after a restart over the plugin's
     * file the view is read back first, since the restart armed it), then every route the plugin made
     * drained and deleted, ignoring any orphan's hold. A stop that keeps the view arms a loaded set first while the
     * file is kept (the upgrade window; a removal deleted it), as fallback() does, so the set stays refused through
     * the window also when it starts in tunnel mode or after an arm that failed: the restore runs whatever the arm's
     * outcome. A restore that failed ends in a restart (restartForStop()), and
     * when that fails too, in stopIncomplete(), which keeps the refuse. Nothing is logged while there is nothing to
     * undo (uu_apply_undo_due()), which the minute job's ticks would otherwise repeat.
     */
    private function stop(): void
    {
        if (!uu_apply_undo_due($this->st, $this->s, $this->p['view'])) {
            return;
        }
        $this->reasons();
        /* the addresses Unbound was, or may have been, on when the run started; in tunnel mode its member's too */
        $was = $this->forwardedAtStart;
        if ($this->st['mode'] === 'tunnel' && $this->st['member'] !== null) {
            $was[$this->resolverOf($this->st['member'])] = true;
        }
        if ($this->p['view']['keep'] && $this->p['view']['active'] && $this->viewArmed !== true
            && $this->s['view']['file_present']) {
            $this->wantArmed = true;
            $this->arm($this->s['upgrade'] ? 'the package is being upgraded'
                : (uu_plan_stop_reason($this->s) ?? 'stop'));
        }
        $restored = $this->restore();
        if (!$restored && !$this->restartForStop()) {
            $this->stopIncomplete($was);
            return;
        }
        if (!$restored && ($this->s['view']['file_present'] || $this->s['view']['copy'] !== null)) {
            /* the restart loaded the plugin's file, refuse included, whatever the read before it gave */
            $this->viewRead();
        }
        if (!$this->p['view']['keep']) {
            $this->lift(uu_plan_stop_reason($this->s) ?? ($this->s['settings']['dry_run'] ? 'dry run' : 'stop'));
        }
        $this->drainAndDelete($was);
        $this->switchTo('fallback', null);
    }

    /**
     * Restart Unbound after this run's restore failed, so that Unbound's own start applies the root zone the user
     * configured. A requested stop and a removal restart at once, on any restore failure: a silent channel, a refused
     * forward_add, a `forward` that does not confirm, an unrestorable zone. Any other stop (a disabled plugin's tick,
     * a tick while the removal marker exists, dry run's undo) restarts only on a silent channel, which nothing else
     * can undo, and only once the planner's escalate_restart says the silence has lasted the bound: the minute job
     * repeats those stops, while a footprint remains even disabled. Never while Unbound is disabled in its settings,
     * even with its pid still alive; with cacheflush on only for remove itself (the restart wipes the cache the user
     * keeps, and a removal has nothing after it but the reject route). Confirmed through `forward`, polled for up to
     * UU_CONTROL_WAIT_SECONDS: true only when the live root no longer needs restoring (needsRestore()).
     */
    private function restartForStop(): bool
    {
        $cause = $this->s['stop'];
        $atOnce = uu_plan_restarts_at_once($cause);
        if ((!$this->silent && !$atOnce) || !$this->s['unbound']['pid_alive']) {
            return false;
        }
        $why = $this->silent ? "Unbound's control channel is silent"
            : "Unbound's configured root zone could not be restored through its control channel";
        if (!$this->s['unbound']['enabled']) {
            $this->log("stop: $why, but Unbound is disabled in its settings: no restart", LOG_ERR);
            return false;
        }
        if (!$atOnce && !$this->p['escalate_restart']) {
            return false;
        }
        $flush = $this->s['contract_input']['cacheflush'];
        if ($flush && $cause !== UU_STOP_REMOVE) {
            $this->log("stop: $why, and with cacheflush on a restart would wipe its cache: no restart", LOG_ERR);
            return false;
        }
        $this->log("stop: $why, so only a restart brings back its configured root zone: restarting "
            . 'Unbound' . ($flush ? ', although with cacheflush on it wipes the cache: the package is being removed'
            : ''), LOG_WARNING);
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
            $this->setLive($live);
            if (uu_plan_restore_due($live, $this->addresses(), $this->s['zone']) !== null) {
                $this->log('stop: Unbound restarted but still forwards to the resolver', LOG_ERR);
                return false;
            }
            /* Unbound's own start applied the configured TLS flag, not the plugin */
            $this->st['tls_applied'] = null;
            $this->checkpoint();
            $this->log('stop: Unbound restarted and no longer forwards to the resolver (live root '
                . $this->liveText() . ')', LOG_WARNING);
            return true;
        }
        $this->log('stop: Unbound\'s control channel is still silent ' . UU_CONTROL_WAIT_SECONDS
            . ' s after the restart', LOG_ERR);
        return false;
    }

    /**
     * Neither the restore nor a restart took Unbound off the plugin's addresses. A removal's last resort, in remove
     * itself only (a tick while the removal marker exists keeps the routes: the package is still installed), is the
     * reject route over every address Unbound may still forward to or the plugin routed, never a delete: with the
     * plugin gone, no block rule and no route repair are left for when a member route goes (a wireguard restart
     * deletes it) and the queries follow the default route out a WAN, while the reject route keeps them local through
     * any device change. The state keeps the addresses recorded. A reject route that cannot be made (a route not ours,
     * a failed route call) leaves that route as it is, and the error says what to run. Any other stop keeps the routes
     * for the next try; a requested stop that leaves a footprint with the plugin disabled says once that the
     * footprint's block stays (once per change, never by the ticks that retry the stop).
     *
     * @param array<string, bool> $was the addresses Unbound was, or may have been, on when the run started
     */
    private function stopIncomplete(array $was): void
    {
        if ($this->s['stop'] === UU_STOP_REMOVE) {
            $rejected = [];
            $kept = [];
            foreach ($this->addresses() as $address) {
                if (!isset($this->st['addresses'][$address]) && !($was[$address] ?? false) && !$this->ours($address)) {
                    continue;
                }
                $this->routeReject($address, '', true);
                if ($this->ours($address) && $this->route($address)['reject']) {
                    $rejected[] = $address;
                } else {
                    $kept[] = $address;
                }
            }
            if ($rejected !== []) {
                $named = implode(', ', $rejected);
                $this->log("stop: the package is being removed while Unbound may still forward to $named, so its "
                    . "queries to $named are rejected locally until Unbound restarts: run configctl unbound restart, "
                    . 'then ' . implode('; ', array_map('uu_route_delete_text', $rejected)), LOG_ERR);
            }
            if ($kept !== []) {
                $this->log('stop: the package is being removed while Unbound may still forward to '
                    . implode(', ', $kept) . ', and its route could not be made a reject route: run configctl '
                    . 'unbound restart', LOG_ERR);
            }
            return;
        }
        $this->footprint();
        $this->log('stop: Unbound may still forward to ' . $this->theResolver(uu_state_footprint($this->st))
            . ', so its route stays (without it the queries would follow the default route)', LOG_ERR);
        $disabled = !$this->s['settings']['enabled'];
        if ($this->s['stop'] === UU_STOP_REQUEST && $disabled && $this->st['addresses'] !== []) {
            $this->log('the plugin is disabled but Unbound may still forward to '
                . uu_footprint_text(uu_state_footprint($this->st)) . ': its block stays until a stop restores the '
                . 'forwarders', LOG_WARNING);
        }
    }

    /**
     * Why stop drains: once a route is gone and the filter reload has removed its block rule, a retry Unbound still
     * sends to that address follows the default route out a WAN, and those retries ran up to 14.5 s after the restore
     * on the VM. So each address goes to the reject route first: from our member route, already there after a recent
     * fallback, or added when the route is missing while Unbound was on the address (a stop in a route-loss window,
     * such as right after a wireguard restart, when the block rule has been dropping those very retries). Then one
     * flush_requestlist drops the queries Unbound was working on (they start again on the restored forwarders; the
     * cache is untouched), and the reject routes are held for one drain before the deletes. A reject route that failed
     * keeps that address's route, and a flush that failed keeps every route: Unbound may still retry them. An address
     * the restored root still names (Unbound's configured root zone names it) keeps its route, never rejected or
     * deleted, and a warning says which route stays and what that means, with the delete to run once the package is
     * removed in a removal; except an orphan on its reject route, which is released with the others
     * (uu_plan_configured_orphan()). A stopped Unbound has nothing in flight; a route that is not ours is never
     * touched.
     *
     * @param array<string, bool> $was the addresses Unbound was, or may have been, on when the run started
     */
    private function drainAndDelete(array $was): void
    {
        $pid = $this->s['unbound']['pid_alive'];
        $rejected = [];
        /* the routes kept because the restored root names their address: member routes, and reject routes of one of
         * the plugin's resolvers (a planner address: it stays closed) */
        $named = ['member' => [], 'reject' => []];
        foreach ($this->addresses() as $address) {
            $gap = !$this->route($address)['present'] && ($was[$address] ?? false);
            if (!$pid || !($this->ours($address) || $gap)) {
                continue;
            }
            if ($this->forwarded[$address]) {
                $reject = $this->route($address)['reject'];
                if ($this->ours($address) && $reject && $this->configuredOrphan($address)) {
                    /* an orphan Unbound's configured zone names: released behind its reject route */
                    $rejected[] = $address;
                } elseif ($this->ours($address)) {
                    $named[$reject ? 'reject' : 'member'][] = $address;
                }
                continue;
            }
            $this->routeReject($address);
            if (!$this->route($address)['reject']) {
                $this->log("stop: no reject route, so the resolver's route stays: Unbound may still retry the "
                    . 'resolver', LOG_ERR);
                continue;
            }
            $rejected[] = $address;
        }
        /* after a removal nothing deletes a kept route: the remedy is named */
        $remedy = fn (array $kept): string => $this->s['stop'] !== UU_STOP_REMOVE ? ''
            : '; once the package is removed, run ' . implode('; ', array_map('uu_route_delete_text', $kept))
                . " when Unbound's configured root zone no longer names " . (count($kept) === 1 ? 'it' : 'them');
        if ($named['member'] !== []) {
            $this->log("stop: Unbound's configured root zone names " . implode(', ', $named['member']) . ', so its '
                . 'route stays (without it the queries would follow the default route)' . $remedy($named['member']),
                LOG_WARNING);
        }
        if ($named['reject'] !== []) {
            $this->log("stop: Unbound's configured root zone names " . implode(', ', $named['reject']) . ', which '
                . "stays closed as one of the plugin's resolvers: its reject route stays, and Unbound's queries to it "
                . 'are rejected locally' . $remedy($named['reject']), LOG_WARNING);
        }
        if ($rejected !== []) {
            if (!$this->ucOk(['flush_requestlist'])) {
                $this->log('stop: unbound-control flush_requestlist failed, so the reject route stays: Unbound may '
                    . 'still retry ' . $this->theResolver($rejected), LOG_ERR);
                return;
            }
            $this->log('stop: flush_requestlist: the queries Unbound was working on start again on its configured '
                . 'forwarders (the cache is untouched)');
            $this->drainWait();
        }
        foreach ($this->addresses() as $address) {
            if (!$pid || in_array($address, $rejected, true)) {
                $this->routeDelete($address);
            }
        }
    }

    /**
     * The orphans the planner found due (uu_plan_drain()), and every orphan of the run (in the map, or on a route of
     * the plugin's after a lost state) that Unbound's own configured root zone names as this run last read the live
     * root (configuredOrphan(): the restore may have just put it there): each that is still on its reject route, and
     * that Unbound does not forward to or forwards to only through its configured zone, is drained as a stop drains,
     * then deleted. One flush_requestlist for them all, then one drain; a flush that failed keeps every reject route
     * and hold, with one error naming them, and the next evaluation drains them again. An orphan still on a member
     * route (its reject route failed) waits for the route repair that puts the reject route on first; one Unbound
     * forwards to through its configured zone keeps it, its queries in the tunnel.
     *
     * @param list<string> $due the plan's drain
     */
    private function drainOrphans(array $due): void
    {
        foreach ($this->addresses() as $address) {
            if ($this->configuredOrphan($address)) {
                $due[] = $address;
            }
        }
        $due = array_values(array_unique($due));
        sort($due, SORT_STRING);
        $held = array_values(array_filter($due, fn (string $a): bool
            => (!($this->forwarded[$a] ?? true) || $this->configuredOrphan($a)) && $this->ours($a)
            && $this->route($a)['reject']));
        if ($held === []) {
            return;
        }
        $named = implode(', ', $held);
        if (!$this->ucOk(['flush_requestlist'])) {
            $this->log("route: draining $named failed (unbound-control flush_requestlist), so its reject route stays",
                LOG_ERR);
            return;
        }
        $this->log("flush_requestlist: draining $named, no member's resolver any more, before its reject route is "
            . 'deleted (the cache is untouched)');
        $this->drainWait();
        foreach ($held as $address) {
            $this->routeDelete($address);
        }
    }

    /** The drain: every reject route reached the data path, then UU_STOP_DRAIN_SECONDS for the last retries. */
    private function drainWait(): void
    {
        ($this->io['sleep_ms'])(($this->s['fib_sync_ms'] ?? 1000) + UU_FIB_SYNC_MARGIN_MS
            + UU_STOP_DRAIN_SECONDS * 1000);
        $this->fibPending = [];
    }

    /** Control channel silent: nothing can be read or set; only the escalation acts. */
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

    /**
     * Staying: the reconcile (the member's route, every other address's reject route, then reassert), the lift of a
     * view Unbound's start or reload armed, and the per-evaluation checks on M; outside tunnel mode the route repair
     * is every address's reject route, then the arm of a set whose view lost its refuse, or the lift of one emptied.
     */
    private function none(): void
    {
        $member = $this->st['member'];
        if ($this->st['mode'] !== 'tunnel' || $member === null) {
            if ($this->p['route_repair']) {
                $this->reasons();
                $this->rejectAll();
            }
            $this->wantArmed = true;
            if ($this->p['view']['active'] && $this->viewArmed === false) {
                $this->arm('no usable member');
            }
            $this->liftEmptied();
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
        if ($this->p['reassert'] && !$this->toResolver($this->resolverOf($member))) {
            return;
        }
        if ($this->p['route_repair'] && !$this->p['reassert']) {
            $this->rejectOthers($this->resolverOf($member));
        }
        if ($this->viewArmed === true) {
            $this->lift($member);
        }
        if (!$this->check($member)) {
            $this->tryCandidates($rest);
        }
    }

    /**
     * "Entering tunnel mode" for each candidate in order; the first that passes is the member. None
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
        $resolver = $this->resolverOf($name);
        if (!$this->routeVia($name)) {
            $this->note("route via $name failed");
            return 'member';
        }
        if (!$this->probeDirect($name)) {
            $this->markFailed($name, 'direct probe of ' . $resolver . ' failed');
            return 'member';
        }
        if (!$this->toResolver($resolver)) {
            $this->note('Unbound did not take ' . $resolver);
            return 'unbound';
        }
        $this->lift($name);
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

    /** The probe-outcome table for the current member; false when it reached UU_PROBE_FAILURES and was marked. */
    private function check(string $name): bool
    {
        $direct = $this->probeDirect($name);
        $outcome = uu_probe_outcome(false, null, false);
        if ($direct) {
            $outcome = uu_probe_outcome(true, $this->probeUnbound($name), false);
            if ($outcome === 'flush_infra') {
                $this->flushInfra($this->resolverOf($name));
                $outcome = uu_probe_outcome(true, $this->probeUnbound($name), true);
            }
        }
        if ($outcome === 'ok') {
            $this->setFailures($name, 0);
            return true;
        }
        $failures = ($this->st['timers'][$name]['probe_failures'] ?? 0) + 1;
        $what = $direct ? 'the check through Unbound failed, also after flush_infra'
            : 'direct probe of ' . $this->resolverOf($name) . ' failed';
        if ($failures < UU_PROBE_FAILURES) {
            $this->setFailures($name, $failures);
            $this->log(sprintf('%s: %s (%d of %d)', $name, $what, $failures, UU_PROBE_FAILURES), LOG_WARNING);
            return true;
        }
        $this->markFailed($name, sprintf('%s (%d of %d)', $what, $failures, UU_PROBE_FAILURES));
        return false;
    }

    /**
     * Fallback steps 1 to 3; the reject routes only once Unbound is off the plugin's addresses. The set is refused
     * first, and the restore runs whatever the arm's outcome: the other clients and the firewall need DNS.
     */
    private function fallback(): void
    {
        $this->wantArmed = true;
        if ($this->p['view']['active'] && $this->viewArmed !== true) {
            $this->arm('no usable member');
        }
        if (!$this->restore()) {
            $named = array_values(array_filter($this->addresses(), fn (string $a): bool => $this->forwarded[$a]));
            $this->log('fallback incomplete: Unbound may still forward to ' . $this->theResolver($named)
                . ', so no reject route; the next evaluation tries again', LOG_ERR);
            return;
        }
        $this->rejectAll();
        $this->liftEmptied();
        $this->switchTo('fallback', null);
    }

    /**
     * Whether Unbound is, or may be, on one of the plugin's addresses: its live root names one and is not its
     * configured root zone (uu_plan_restore_due()); with the live root unknown, tunnel mode or any address recorded
     * forwarded. A stopped Unbound restarts on its configured root anyway.
     */
    private function needsRestore(): bool
    {
        if (!$this->s['unbound']['pid_alive']) {
            return false;
        }
        if ($this->live === null) {
            return $this->st['mode'] === 'tunnel' || in_array(true, $this->forwarded, true);
        }
        return uu_plan_restore_due($this->live, $this->addresses(), $this->s['zone']) !== null;
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

    /**
     * Steps 3 to 5 of entering: forward_add only when the live root is not the resolver, flush_infra, confirm, then
     * every other address's reject route (rejectOthers()).
     */
    private function toResolver(string $resolver): bool
    {
        $this->fibWait($resolver);
        if (!uu_apply_same($this->live, [$resolver])) {
            $this->forwarded[$resolver] = true;
            $this->live = null;
            if (!$this->ucOk(['forward_add', '.', $resolver])) {
                $this->log('unbound-control forward_add . ' . $resolver . ' failed', LOG_ERR);
                return false;
            }
            $this->st['tls_applied'] = false;
            $this->checkpoint();
            $this->log('forwarders: . -> ' . $resolver . ', plain DNS inside the tunnel (no +t)');
        }
        $this->flushInfra($resolver);
        if (!$this->confirm([$resolver])) {
            $this->log("Unbound's live root is " . $this->liveText() . ', not ' . $resolver, LOG_ERR);
            return false;
        }
        $this->rejectOthers($resolver);
        return true;
    }

    /**
     * Step 5: every other address the map holds or held when the run started, or that has a route of the plugin's,
     * gets its reject route, changed in place, or added when its route is gone, once this run's read says Unbound no
     * longer forwards to it (routeReject()); an entry whose route is gone keeps its entry and hold that way until the
     * drain. One Unbound was on when the run started is the previous member's resolver, and its line says so. An orphan
     * among them is released at the next checkpoint (footprint()).
     */
    private function rejectOthers(string $active): void
    {
        foreach ($this->addresses() as $address) {
            if ($address !== $active && (in_array($address, $this->recorded, true)
                || isset($this->st['addresses'][$address]) || $this->ours($address))) {
                $this->routeReject($address, $this->forwardedAtStart[$address] ? "previous member's resolver" : '');
            }
        }
    }

    /** Outside tunnel mode: every address of the run gets its reject route (routeReject()). */
    private function rejectAll(): void
    {
        foreach ($this->addresses() as $address) {
            $this->routeReject($address);
        }
    }

    /** Route a member's own resolver through the member's next hop: change from any route of ours, never delete. */
    private function routeVia(string $name): bool
    {
        $m = $this->s['members'][$name] ?? null;
        if ($m === null) {
            $this->log("$name has no gateway record: no route through it", LOG_ERR);
            return false;
        }
        $resolver = $this->resolverOf($name);
        if ($resolver === '') {
            $this->log("$name has no resolver: no route through it", LOG_ERR);
            return false;
        }
        $route = $this->route($resolver);
        if (uu_plan_route_via($route, $m)) {
            return true;
        }
        if ($route['present'] && !$route['ours']) {
            $this->log("the resolver's route is not ours: it is not replaced by one via $name", LOG_ERR);
            return false;
        }
        /* -ifp pins the device: members may share a next hop */
        if (!$this->routeSet($resolver, [$this->familyArg($resolver), '-host', $resolver,
                                         uu_route_hop($m['next_hop'], $m['if']), '-ifp', $m['if']])) {
            $this->log("route: $resolver via $name ({$m['next_hop']} on {$m['if']}) failed", LOG_ERR);
            return false;
        }
        $this->routes[$resolver] = ['present' => true, 'gateway' => $m['next_hop'], 'interface' => $m['if'],
                                    'reject' => false, 'ours' => true];
        $this->records[$resolver] = ['kind' => 'member', 'next_hop' => $m['next_hop'], 'if' => $m['if']];
        $this->checkpoint();
        $this->log("route: $resolver via $name ({$m['next_hop']} on {$m['if']})");
        return true;
    }

    /**
     * The reject route for an address, only while Unbound no longer forwards to it (it would black-hole every query),
     * except as a removal's last resort; never over a route the plugin did not make.
     *
     * @param string $why what the address was, for the log line; '' for none
     */
    private function routeReject(string $address, string $why = '', bool $lastResort = false): void
    {
        $route = $this->route($address);
        if ($route['present'] && !$route['ours']) {
            $this->log("the resolver's route is not ours: no reject route over it", LOG_WARNING);
            return;
        }
        if ($route['present'] && $route['reject']) {
            return;
        }
        if (($this->forwarded[$address] ?? false) && !$lastResort) {
            return;
        }
        if (!$this->routeSet($address, [$this->familyArg($address), '-host', $address,
                                        uu_ip_family($address) === 'inet6' ? '::1' : '127.0.0.1', '-reject'])) {
            $this->log("route: the reject route for $address failed", LOG_ERR);
            return;
        }
        $this->routes[$address] = ['present' => true, 'gateway' => '', 'interface' => 'lo0', 'reject' => true,
                                   'ours' => true];
        $this->records[$address] = ['kind' => 'reject', 'next_hop' => '', 'if' => 'lo0'];
        $this->checkpoint();
        $this->log("route: $address rejected locally" . ($why === '' ? '' : " ($why)"));
    }

    private function routeDelete(string $address): void
    {
        if (!$this->ours($address)) {
            return;
        }
        if (!($this->io['route'])('delete', [$this->familyArg($address), '-host', $address])) {
            $this->log("route: deleting the route of $address failed", LOG_ERR);
            return;
        }
        $this->routes[$address] = ['present' => false, 'gateway' => '', 'interface' => '', 'reject' => false,
                                   'ours' => false];
        $this->records[$address] = null;
        $this->checkpoint();
        $this->log("route: $address deleted");
    }

    /** route(8)'s address-family argument for an address. */
    private function familyArg(string $address): string
    {
        return uu_family_arg(uu_ip_family($address) ?? 'inet');
    }

    /**
     * change when the address's route is present, add when absent, never delete and add.
     *
     * @param list<string> $args
     */
    private function routeSet(string $address, array $args): bool
    {
        $verb = $this->route($address)['present'] ? 'change' : 'add';
        $ok = ($this->io['route'])($verb, $args);
        if (!$ok && $verb === 'change') {
            /* the route went after the snapshot (its device was recreated): add it */
            $ok = ($this->io['route'])('add', $args);
        }
        if ($ok) {
            $this->fibPending[$address] = true;
        }
        /* a failed call proves no more than a failed read: an add refused because the route exists after all must
         * not lose the record that lets the next run adopt it, and is never retried as a change (the route may be
         * foreign) */
        $this->unknown[$address] = !$ok;
        return $ok;
    }

    /** A changed route reaches the data path up to fib_max_sync_delay_ms later: wait before using the address. */
    private function fibWait(string $address): void
    {
        if (!($this->fibPending[$address] ?? false)) {
            return;
        }
        /* 1000 is FreeBSD's default; the contract refuses tunnel mode when the sysctl is unreadable */
        ($this->io['sleep_ms'])(($this->s['fib_sync_ms'] ?? 1000) + UU_FIB_SYNC_MARGIN_MS);
        $this->fibPending = [];
    }

    private function probeDirect(string $name): bool
    {
        $resolver = $this->resolverOf($name);
        $this->fibWait($resolver);
        $ok = ($this->io['probe_direct'])($resolver, $this->probe);
        $this->st['checks']['direct'] = ['ok' => $ok, 'at' => time(), 'member' => $name];
        return $ok;
    }

    /** flush_type first: with serve-expired and aggressive-nsec a cached answer would pass without the upstream. */
    private function probeUnbound(string $name): bool
    {
        $this->fibWait($this->resolverOf($name));
        $flushed = $this->ucOk(['flush_type', $this->probe, 'SOA']);
        if (!$flushed) {
            $this->log("unbound-control flush_type {$this->probe} SOA failed: the check through Unbound counts as "
                . 'failed (a cached answer proves nothing)', LOG_WARNING);
        }
        $ok = $flushed && ($this->io['probe_unbound'])($this->probe);
        $this->st['checks']['unbound'] = ['ok' => $ok, 'at' => time(), 'member' => $name];
        return $ok;
    }

    private function flushInfra(string $resolver): void
    {
        if (!$this->ucOk(['flush_infra', $resolver])) {
            $this->log('unbound-control flush_infra ' . $resolver . ' failed', LOG_WARNING);
        }
    }

    /**
     * The set refused: the refuse of "." in the view, then each zone that passes names on (the mirror's) at its class,
     * static or refuse, once "." answered ok, every one tried past a refused one (a zone left noview passes its names
     * on, the open side); confirmed only by the view's zones read back holding "." refused and each of those zones at
     * its armed class (viewMissing()). A
     * failure is the run's view problem, with the first failed reply, else the read's, and the state's refuse as the
     * read shows it.
     *
     * @param string $why what the arm follows, for its event line: no usable member, or the stop's cause
     */
    private function arm(string $why): void
    {
        $calls = [];
        foreach (array_keys($this->p['view']['mirror']) as $zone) {
            $calls[] = ['view_local_zone', UU_VIEW_NAME, (string)$zone,
                        uu_view_zone_class($this->p['view']['zones'][$zone] ?? '')];
        }
        $failed = $this->viewCalls([['view_local_zone', UU_VIEW_NAME, '.', 'refuse']], false)
            ?? $this->viewCalls($calls, true);
        $read = $this->viewConfirm(true);
        $missing = $read === null ? $this->viewMissing() : null;
        if ($read !== null || $missing !== null) {
            if ($this->viewArmed !== null) {
                $this->st['view']['refuse'] = $this->viewArmed ? 'armed' : 'lifted';
            }
            $this->viewFault('Fail closed not armed: ' . ($failed ?? $read ?? "the view does not list $missing"));
            return;
        }
        $this->st['view']['refuse'] = 'armed';
        $this->st['view']['problem'] = null;
        $this->log('fail closed: ' . $this->viewSet() . " refused ($why)", LOG_ERR);
    }

    /**
     * The refuse lifted: "." removed from the view, then each zone that passes names on (the mirror's, and any other
     * the view as last read holds at an armed class) set to noview, every one tried past a refused one, as the arm
     * does (a zone left at its armed class would answer its misses locally until the next reconcile); confirmed only
     * by the view's zones read back without the refuse of "." (a view no longer loaded refuses nothing). Only while
     * the set is read as loaded or the view holds the refuse of ".", never on an unknown read, so an owner with
     * nothing selected gets no view command. A failure leaves the set refused, which fails closed but is a fault: the
     * run's view problem, tried again by the next evaluation.
     *
     * The event line is logged only for a refuse that was there: an active view already lifted gets the commands (its
     * zones back to noview) without it.
     *
     * @param string $why what the lift follows: the member entered or kept, or the stop's cause
     */
    private function lift(string $why): void
    {
        if (!$this->p['view']['active'] && $this->viewArmed !== true) {
            return;
        }
        $was = $this->viewArmed === true;
        /* the mirror's zones, and any other the view as last read holds at an armed class (a restart's file, read
         * back after a silent channel left the mirror unknown) */
        $zones = array_map('strval', array_keys($this->p['view']['mirror']));
        foreach ($this->viewZones as $zone => $type) {
            if ($zone !== '.' && $type !== 'noview' && !in_array((string)$zone, $zones, true)) {
                $zones[] = (string)$zone;
            }
        }
        $calls = [['view_local_zone_remove', UU_VIEW_NAME, '.']];
        foreach ($zones as $zone) {
            $calls[] = ['view_local_zone', UU_VIEW_NAME, $zone, 'noview'];
        }
        $failed = $this->viewCalls($calls, true);
        $read = $this->viewConfirm(false);
        if ($read !== null) {
            /* the set may still be refused (the read back says so, or it is unknown after a refuse that was there):
             * recorded armed, so the file step keeps the file and the next tick reads the view and lifts again */
            if ($this->viewArmed === true || ($this->viewArmed === null && $was)) {
                $this->st['view']['refuse'] = 'armed';
            }
            $this->viewFault('Fail closed stuck: ' . ($failed ?? $read));
            return;
        }
        /* a view no longer loaded is none */
        $this->st['view']['refuse'] = $this->viewArmed === null ? 'none' : 'lifted';
        $this->st['view']['problem'] = null;
        if ($was) {
            $this->log("fail closed: lifted ($why)", LOG_ERR);
        }
    }

    /** A view still holding the refuse of "." with nothing selected any more (an empty set at Apply): lifted. */
    private function liftEmptied(): void
    {
        if (!$this->p['view']['active'] && $this->viewArmed === true) {
            $this->lift('empty set');
        }
    }

    /**
     * The loaded view brought to the wanted one while the set is read as loaded (uu_view_reconcile()), after every run
     * but a stop's or a silent channel's, from the view as the run last read it (its arm's or lift's read back
     * included): zones added or retyped, stale ones removed, a stale record's name removed and its wanted records
     * added back, each change logged. Nothing while the refuse is unknown, nor while the daemon's zones or records
     * could not be read (every zone of the view would look stale); a call that gets no answer ends it.
     */
    private function reconcile(): void
    {
        if (!$this->p['view']['active'] || $this->viewArmed === null || $this->s['view']['zones'] === null
            || $this->s['view']['data'] === null) {
            return;
        }
        $diff = uu_view_reconcile($this->viewZones, $this->s['view']['view_data'],
            uu_view_wanted($this->p['view']['zones'], $this->p['view']['mirror'], $this->viewArmed));
        $steps = [];
        foreach ($diff['set'] as $zone => $type) {
            $steps[] = [['view_local_zone', UU_VIEW_NAME, (string)$zone, $type], "zone +$zone $type"];
        }
        foreach ($diff['remove'] as $zone) {
            $steps[] = [['view_local_zone_remove', UU_VIEW_NAME, $zone], "zone -$zone"];
        }
        foreach ($diff['data_remove'] as $name) {
            $steps[] = [['view_local_data_remove', UU_VIEW_NAME, $name], "data -$name"];
        }
        foreach ($diff['data_add'] as $record) {
            $fields = explode(' ', $record);
            $steps[] = [['view_local_data', UU_VIEW_NAME, $record], 'data +' . $fields[0] . ' ' . ($fields[3] ?? '')];
        }
        foreach ($steps as [$args, $what]) {
            $out = $this->viewCall($args);
            $failed = $this->viewWhy($out);
            $this->log("fail closed: $what" . ($failed === null ? '' : " failed: $failed"),
                $failed === null ? LOG_NOTICE : LOG_WARNING);
            if ($out === null) {
                return;
            }
            if ($failed === null && $args[0] === 'view_local_zone') {
                $this->viewZones[$args[2]] = $args[3];
            } elseif ($failed === null && $args[0] === 'view_local_zone_remove') {
                unset($this->viewZones[$args[2]]);
            }
        }
    }

    /**
     * The state's refuse as the loaded set's view holds it at the end of a run that is no stop, so a refuse that
     * Unbound's start or reload put back, or one already there at a fallback, is recorded too; and an arm's or a
     * lift's own fault cleared once the view holds what this run wanted (wantArmed: armed with the arm's zones; else
     * lifted), however it got there (a lost reply that took effect, a reload, the reconcile). What the run wanted,
     * not the mode: a fallback whose restore failed stays in tunnel mode yet wanted the set refused. A stop leaves it
     * to the stop's own lift and the file step: its view stays loaded, without the refuse, until Unbound next starts.
     */
    private function viewRecord(): void
    {
        if (!$this->p['view']['active'] || $this->viewArmed === null) {
            return;
        }
        $this->st['view']['refuse'] = $this->viewArmed ? 'armed' : 'lifted';
        $problem = $this->st['view']['problem'] ?? '';
        $ours = str_starts_with($problem, 'Fail closed not armed: ')
            || str_starts_with($problem, 'Fail closed stuck: ');
        $holds = $this->wantArmed ? $this->viewArmed && $this->viewMissing() === null : !$this->viewArmed;
        if ($ours && $holds) {
            $this->st['view']['problem'] = null;
        }
    }

    /**
     * The first of the arm's own zones (the mirror's, which pass names on unless held at their armed class) that the
     * view as last read does not hold at that class, as "<zone> <class>"; null when it holds every one. A noview zone
     * missing from an armed view is the closed side: its names match the refuse of ".".
     */
    private function viewMissing(): ?string
    {
        foreach (array_keys($this->p['view']['mirror']) as $zone) {
            $class = uu_view_zone_class($this->p['view']['zones'][$zone] ?? '');
            if (($this->viewZones[$zone] ?? null) !== $class) {
                return "$zone $class";
            }
        }
        return null;
    }

    /**
     * Read the view's zones back after an arm or a lift: null when the refuse of "." is as wanted, else why not. A
     * reply that is not the view's zones leaves the refuse unknown.
     */
    private function viewConfirm(bool $refused): ?string
    {
        $out = $this->viewRead();
        if ($this->viewArmed === null) {
            $absent = $out !== null && str_starts_with(ltrim($out), 'no view with name');
            return $absent && !$refused ? null : $this->viewText($out);
        }
        if ($this->viewArmed === $refused) {
            return null;
        }
        return $refused ? 'the view does not refuse .' : 'the view still refuses .';
    }

    /**
     * Read the view's zones: the run's view as Unbound now holds it, the refuse unknown for a reply that is not the
     * view's zones. The reply, null when nothing answered.
     */
    private function viewRead(): ?string
    {
        $out = $this->viewCall(['view_list_local_zones', UU_VIEW_NAME]);
        $zones = $out === null ? null : uu_view_parse_list($out);
        if ($zones === null) {
            $this->viewArmed = null;
            return $out;
        }
        $this->viewZones = $zones;
        $this->viewArmed = ($zones['.'] ?? null) === 'refuse';
        return $out;
    }

    /**
     * The view commands in order: null when each answered ok, else why the first did not. They stop at the first that
     * did not, or with $onPast only at one that got no answer (each silent call costs the timeout).
     *
     * @param list<list<string>> $calls
     */
    private function viewCalls(array $calls, bool $onPast): ?string
    {
        $first = null;
        foreach ($calls as $args) {
            $out = $this->viewCall($args);
            $first ??= $this->viewWhy($out);
            if ($first !== null && (!$onPast || $out === null)) {
                break;
            }
        }
        return $first;
    }

    /**
     * One view command: its reply, null when nothing answered.
     *
     * @param list<string> $args
     */
    private function viewCall(array $args): ?string
    {
        $out = ($this->io['uc'])($args);
        $this->silent = $this->silent || $out === null;
        return $out;
    }

    /** Why a view command's reply is not `ok`; null when it is. */
    private function viewWhy(?string $out): ?string
    {
        return $out !== null && trim($out) === 'ok' ? null : $this->viewText($out);
    }

    /** A reply as one line for the log and the status: "no answer" for none. */
    private function viewText(?string $out): string
    {
        if ($out === null) {
            return 'no answer';
        }
        $text = (string)preg_replace('/\s*\n\s*/', '; ', trim($out));
        return $text === '' ? 'an empty reply' : $text;
    }

    /** A failed arm or lift: the run's view problem, logged at error level. */
    private function viewFault(string $problem): void
    {
        $this->st['view']['problem'] = $problem;
        $this->log($problem, LOG_ERR);
    }

    /**
     * The set for the log: its nets, "every client" for the whole address space; for a selection without a net yet
     * (its interfaces have no address) the nets the file on disk refuses, which the loaded view still holds.
     */
    private function viewSet(): string
    {
        if ($this->s['view']['scope'] === 'all') {
            return 'every client';
        }
        if ($this->s['view']['nets'] !== []) {
            return implode(', ', $this->s['view']['nets']);
        }
        $file = uu_view_refused_nets($this->s['view']['file']);
        return $file === [] ? 'the selected interfaces (no net yet)' : implode(', ', $file);
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
        $this->setLive($out === null ? null : uu_parse_forward($out));
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

    /**
     * Record a mode or member change with wall time (display only) and its reasons. A switch in place on the same
     * member (its resolver changed) is no change: nothing is recorded.
     */
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

    /** Save what the run has reached, so a failure later in the run keeps it. */
    private function checkpoint(): void
    {
        $this->footprint();
        ($this->io['save'])($this->st);
    }

    /**
     * Record each address while the plugin's route refers to it or Unbound may forward to it, and drop it once neither
     * holds, so the rules and a later stop know every address to undo. The route is this run's live view of it, not
     * the record: a record can outlive a route the kernel deleted (device recreation), and it must not pin an address
     * nothing refers to. Tunnel mode is on its member's resolver by definition. An address that is no planner address
     * (no member's resolver) and that Unbound no longer forwards to is released: released_at is the first such
     * checkpoint's time (or the one the run started with, for an entry an earlier checkpoint pruned and a reject route
     * brought back), kept until the drain deletes it, and cleared once it is a member's resolver again. An orphan
     * Unbound forwards to only through its own configured root zone (configuredOrphan()) keeps its entry only while
     * its route is the plugin's. The map is kept sorted by address.
     */
    private function footprint(): void
    {
        $tunnel = $this->st['mode'] === 'tunnel';
        $active = $tunnel && $this->st['member'] !== null ? $this->resolverOf($this->st['member']) : null;
        $map = [];
        foreach ($this->addresses() as $address) {
            if (uu_ip_canonical($address) !== $address) {
                continue;
            }
            $entry = $this->st['addresses'][$address] ?? null;
            $forwarded = $address === $active || $this->forwarded[$address];
            $keep = ($this->unknown[$address] ?? false) && $entry !== null;
            /* an orphan forwarded to only through Unbound's own configured zone is the owner's: no claim on the map */
            $claim = $forwarded && !($address !== $active && $this->configuredOrphan($address));
            if (!$this->ours($address) && !$claim && !$keep) {
                continue;
            }
            $released = $entry['released_at'] ?? $this->releasedAtStart[$address] ?? null;
            if (in_array($address, $this->kept, true)) {
                $released = null;
            } elseif ($released === null && !$forwarded) {
                $released = $this->s['now'];
            }
            $map[$address] = ['route' => $this->records[$address], 'forwarded' => $forwarded,
                              'released_at' => $released];
        }
        $this->st['addresses'] = $map;
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
 * plugin's changes live (uu_apply_undo_due(): dry run turned on in tunnel mode, a restore due, a route of the
 * plugin's that a stop would undo, or the view's refuse armed) first undoes them for real, as stop does, so dry run
 * never leaves Unbound on the resolver nor the set refused.
 *
 * @param array{action: string, candidates: list<string>, reassert: bool, route_repair: bool,
 *     escalate_restart: bool,
 *     state: array{version: int, mode: string, member: ?string,
 *         timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int,
 *         resolver_failed_until: ?int, probe_failures: int,
 *             last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
 *         control_silent_since: ?int, last_switch: ?array{at: int, from: string, to: string, reason: string},
 *         checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *         member: string}}, tls_applied: ?bool, blocked: ?int,
 *         addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *             forwarded: bool, released_at: ?int}>,
 *         view: array{refuse: string, scope: string, nets: list<string>, problem: ?string,
 *             restarted: ?string, unwritable: int}},
 *     reasons: list<string>, drain: list<string>,
 *     view: array{active: bool, armed: ?bool, keep: bool, zones: array<string, string>,
 *         mirror: array<string, list<string>>, problem: ?string}} $p uu_plan()
 * @param array{now: int, wall: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, default: string,
 *         rows: array<string, string>, failback_delay: int, probe_name: string},
 *     members: array<string, array{name: string, interface: string, if: string, ipprotocol: string,
 *         resolver: string, next_hop: string, disabled: bool, force_down: bool, monitor_disable: bool,
 *         monitor: string, time_period: int, interval: int, loss_interval: int, losshigh: int}>, stop: ?string,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     routes: array<string, array{present: bool, gateway: string, interface: string, reject: bool,
 *         ours: bool}>,
 *     route_flags: array<string, list<string>>,
 *     fib_sync_ms: ?int, contract_input: array{cacheflush: bool}, upgrade: bool,
 *     view: array{scope: string, nets: list<string>, notes: list<string>, acl: ?array{nodes: list<array{net: string,
 *         action: string}>, foreign: list<string>}, zones: ?array<string, string>, data: ?list<string>,
 *         loaded: string, view_zones: array<string, string>, view_data: list<string>, file: ?string,
 *         copy: ?string, file_present: bool}} $s the snapshot the plan was made from
 * @param array{route: callable(string, list<string>): bool, sleep_ms: callable(int): void,
 *     probe_direct: callable(string, string): bool, probe_unbound: callable(string): bool,
 *     uc: callable(list<string>): ?string, restart_unbound: callable(): bool, log: callable(string, int): void,
 *     save: callable(array): void} $io
 * @return array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int,
 *         last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
 *     control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *         forwarded: bool, released_at: ?int}>,
 *     view: array{refuse: string, scope: string, nets: list<string>, problem: ?string,
 *         restarted: ?string, unwritable: int}}
 */
function uu_apply(array $p, array $s, array $io): array
{
    if (!$s['settings']['dry_run']) {
        return (new UuApplyRun($p, $s, $io))->run();
    }
    /* dry run neither writes nor deletes the view's file, so of the view only a refuse a real run left armed is a
     * live change to undo: the file alone would make every tick a stop */
    $undo = $s;
    $undo['view']['file'] = null;
    $undo['view']['file_present'] = false;
    $undo['view']['copy'] = null;
    $changed = uu_apply_undo_due($p['state'], $undo, $p['view']);
    if ($changed && $p['action'] === 'skip') {
        /* through a silent channel nothing can be undone; the skip runs as planned, its escalation
         * included, and the undo waits for the channel to answer */
        return (new UuApplyRun($p, $s, $io))->run();
    }
    if ($p['action'] === 'stop' || $changed) {
        if ($changed) {
            ($io['log'])('dry run: undoing the plugin\'s live changes first (forwarders and route), as stop does',
                LOG_NOTICE);
        }
        $p['action'] = 'stop';
        return (new UuApplyRun($p, $undo, $io))->run();
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
 *         resolver_failed_until: ?int, probe_failures: int,
 *             last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
 *         control_silent_since: ?int, last_switch: ?array{at: int, from: string, to: string, reason: string},
 *         checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *         member: string}}, tls_applied: ?bool, blocked: ?int,
 *         addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *             forwarded: bool, released_at: ?int}>,
 *         view: array{refuse: string, scope: string, nets: list<string>, problem: ?string,
 *             restarted: ?string, unwritable: int}},
 *     reasons: list<string>, drain: list<string>,
 *     view: array{active: bool, armed: ?bool, keep: bool, zones: array<string, string>,
 *         mirror: array<string, list<string>>, problem: ?string}} $p
 * @param array{now: int, wall: int,
 *     settings: array{enabled: bool, dry_run: bool, group: string, default: string,
 *         rows: array<string, string>, failback_delay: int, probe_name: string},
 *     members: array<string, array{name: string, interface: string, if: string, ipprotocol: string,
 *         resolver: string, next_hop: string, disabled: bool, force_down: bool, monitor_disable: bool,
 *         monitor: string, time_period: int, interval: int, loss_interval: int, losshigh: int}>, stop: ?string,
 *     unbound: array{enabled: bool, pid_alive: bool, control_ok: bool, live_root: ?list<string>},
 *     zone: array{shape: string, addrs: list<string>, tls: bool, problems: list<string>},
 *     routes: array<string, array{present: bool, gateway: string, interface: string, reject: bool,
 *         ours: bool}>,
 *     route_flags: array<string, list<string>>,
 *     fib_sync_ms: ?int, contract_input: array{cacheflush: bool}, upgrade: bool,
 *     view: array{scope: string, nets: list<string>, notes: list<string>, acl: ?array{nodes: list<array{net: string,
 *         action: string}>, foreign: list<string>}, zones: ?array<string, string>, data: ?list<string>,
 *         loaded: string, view_zones: array<string, string>, view_data: list<string>, file: ?string,
 *         copy: ?string, file_present: bool}} $s
 * @param callable(string, int): void $log
 */
function uu_apply_preview(array $p, array $s, callable $log): void
{
    (new UuApplyRun($p, $s, uu_dry_io($log, $s['unbound']['live_root'], $s['view']['view_zones'])))->run();
}

/**
 * The file step after apply, as uu_view_file_step() decided it, carried out: the install, the delete, the restart line
 * and the restart, and the state's view record the step gives. Only a failure changes what the step decided:
 * - a write that is not installed (uu_view_install()) or a delete that fails keeps the record's refuse, restarted
 *   and unwritable as apply left them (the next tick tries again), keeps the old file's nets, names the fault, and
 *   cancels the restart, which would otherwise start Unbound on the file the step meant to replace or remove;
 * - a restart that fails keeps the refuse and names the fault, but its restarted stands: one reported failed may still
 *   have happened, so it is never tried again for the same node lines (no outage a minute).
 * A restart that ran puts Unbound on its configured root zone (tls_applied null; the evaluation
 * its start queues re-enters). Dry run calls nothing, and logs what it would do.
 *
 * @param array{view: array{active: bool, armed: ?bool, keep: bool, zones: array<string, string>,
 *     mirror: array<string, list<string>>, problem: ?string}} $p
 * @param array{stop: ?string, settings: array{enabled: bool, dry_run: bool},
 *     unbound: array{enabled: bool, pid_alive: bool}, contract_input: array{cacheflush: bool},
 *     view: array{scope: string, nets: list<string>, notes: list<string>, acl: ?array{nodes: list<array{net: string,
 *         action: string}>, foreign: list<string>}, zones: ?array<string, string>, data: ?list<string>,
 *         loaded: string, view_zones: array<string, string>, view_data: list<string>, file: ?string,
 *         copy: ?string, file_present: bool}} $s
 * @param array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int,
 *         last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
 *     control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *         forwarded: bool, released_at: ?int}>,
 *     view: array{refuse: string, scope: string, nets: list<string>, problem: ?string,
 *         restarted: ?string, unwritable: int}} $st
 *     the state apply returned
 * @param array{install: callable(string): bool, delete: callable(): bool, restart: callable(): bool,
 *     log: callable(string, int): void} $io
 * @return array{version: int, mode: string, member: ?string,
 *     timers: array<string, array{usable_since: ?int, counted: int, last_at: ?int, resolver_failed_until: ?int,
 *     probe_failures: int,
 *         last_down: ?array{at: int, reason: string}, resolver: string}>, control_failures: int,
 *     control_silent_since: ?int,
 *     last_switch: ?array{at: int, from: string, to: string, reason: string},
 *     checks: array{direct: ?array{ok: bool, at: int, member: string}, unbound: ?array{ok: bool, at: int,
 *     member: string}}, tls_applied: ?bool, blocked: ?int,
 *     addresses: array<string, array{route: ?array{kind: string, next_hop: string, if: string},
 *         forwarded: bool, released_at: ?int}>,
 *     view: array{refuse: string, scope: string, nets: list<string>, problem: ?string,
 *         restarted: ?string, unwritable: int}}
 */
function uu_view_file_apply(array $p, array $s, array $st, array $io): array
{
    $dry = $s['settings']['dry_run'];
    $step = uu_view_file_step($s['view'], $p['view'], $st['view'], $st['mode'], $s['unbound']['pid_alive'],
        $s['unbound']['enabled'], $dry, uu_plan_stop_reason($s) !== null, $s['stop'] === UU_STOP_REMOVE,
        $s['contract_input']['cacheflush']);
    $record = $step['record'];
    $restart = $step['restart'];
    $kept = ['refuse' => $st['view']['refuse'], 'nets' => uu_view_refused_nets($s['view']['file']),
             'restarted' => $st['view']['restarted'], 'unwritable' => $st['view']['unwritable']];
    if ($step['write'] !== null && !($io['install'])($step['write'])) {
        $record = array_merge($record, $kept,
            ['problem' => 'Fail closed: the view file was kept (the new file was not installed)']);
        $restart = false;
    } elseif ($step['delete'] && !($io['delete'])()) {
        $record = array_merge($record, $kept,
            ['problem' => 'Fail closed: the view file could not be deleted']);
        $restart = false;
    }
    if ($step['line'] !== null && ($restart || $dry)) {
        ($io['log'])($step['line'], $restart ? LOG_WARNING : LOG_NOTICE);
    }
    if ($restart) {
        if (($io['restart'])()) {
            /* Unbound's own start applied the configured TLS flag, not the plugin */
            $st['tls_applied'] = null;
        } else {
            /* restarted stays the step's: a restart reported failed may still have happened, and is not tried
             * again for the same node lines until the copy changes */
            $record = array_merge($record, ['refuse' => $kept['refuse'], 'problem' => UU_VIEW_RESTART_FAILED]);
        }
    }
    $st['view'] = $record;
    return $st;
}

/**
 * An Io that only logs, each line marked [dry]. It plays Unbound's live root along (forward_add and forward_remove
 * set what `forward` prints) and the view's zones (view_local_zone and view_local_zone_remove set what
 * view_list_local_zones prints), so the logged steps are the ones a passing run would take.
 *
 * @param callable(string, int): void $log
 * @param ?list<string> $live the snapshot's live root
 * @param array<string, string> $zones the view's zones as the snapshot read them
 * @return array{route: callable(string, list<string>): bool, sleep_ms: callable(int): void,
 *     probe_direct: callable(string, string): bool, probe_unbound: callable(string): bool,
 *     uc: callable(list<string>): ?string, restart_unbound: callable(): bool, log: callable(string, int): void,
 *     save: callable(array): void}
 */
function uu_dry_io(callable $log, ?array $live, array $zones): array
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
        'uc' => function (array $args) use ($say, &$live, &$zones): ?string {
            $say('would run: unbound-control ' . implode(' ', $args));
            $cmd = $args[0] ?? '';
            if ($cmd === 'view_list_local_zones') {
                $lines = [];
                foreach ($zones as $name => $type) {
                    $lines[] = "$name $type";
                }
                return implode("\n", $lines) . "\n";
            }
            if ($cmd === 'view_local_zone') {
                $zones[(string)($args[2] ?? '')] = (string)($args[3] ?? '');
            } elseif ($cmd === 'view_local_zone_remove') {
                unset($zones[(string)($args[2] ?? '')]);
            }
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
 * The real I/O. Every unbound-control call runs under UU_CONTROL_CALL_TIMEOUT_SECONDS (uu_uc_run()); a failing
 * route call logs its output here, where the output is known. Every restart, whatever its cause,
 * is uu_unbound_restart(): core's restart through configd, else core's own command.
 *
 * @param string $statePath where save writes the state (UU_STATE_PATH)
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
        'uc' => fn (array $args): ?string => uu_uc_run($args),
        'restart_unbound' => fn (): bool => uu_unbound_restart('uu_core_shell', 'uu_log'),
        'log' => function (string $msg, int $prio): void {
            uu_log($msg, $prio);
        },
        'save' => function (array $state) use ($statePath): void {
            uu_state_save($statePath, $state);
        },
    ];
}

/**
 * The file step's real I/O (uu_view_file_apply()): the install through unbound-checkconf (uu_view_install()), the
 * delete of the plugin's own file (uu_view_delete()), and Unbound's restart through core's
 * (uu_unbound_restart()).
 *
 * @return array{install: callable(string): bool, delete: callable(): bool, restart: callable(): bool,
 *     log: callable(string, int): void}
 */
function uu_view_file_io(): array
{
    return [
        'install' => fn (string $text): bool => uu_view_install($text, 'uu_core_shell', 'uu_log'),
        'delete' => fn (): bool => uu_view_delete('uu_log'),
        'restart' => fn (): bool => uu_unbound_restart('uu_core_shell', 'uu_log'),
        'log' => function (string $msg, int $prio): void {
            uu_log($msg, $prio);
        },
    ];
}
