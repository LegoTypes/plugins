#!/bin/sh

# Copyright (C) 2026 cayossarian
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# WireGuard upstream tunnels: the managed tunnels' IPv6 addresses, their
# next-hop and monitor routes, and the reconcile.
#
#   start | restart | configure_routes
#       add each managed tunnel's IPv6 address to its device, the host route
#       to its IPv6 next hop and the host route to its IPv6 monitor
#       (configure_routes is the service's soft reload, configd's [reload])
#   tick
#       cron's mirror tick: health_mirror.php, then prime.php whatever the
#       mirror's exit; exits with the prime's status
#   tunnel <arguments>
#       configd's tunnel actions: tunnel.php with the arguments that follow
#   reconcile [--cron]
#       the same as start, silent unless it repairs something; then
#       default_guard.php, freshness.php and core_contract.php; --cron (the
#       minute cron only) says each minute when a removal marker stops it
#   hook
#       core's monitor, newwanip and bootup hooks: the route set (as reconcile runs it), then queue a reconcile
#       for the rest and return
#   request_reconcile
#       the config syshook's entry: queue a reconcile and return at once
#   stop     remove what start added, and the footprint the filter hook falls back to; the route set then adds
#            nothing until the next start, restart or configure_routes (core's Start, Restart or Apply) or the boot
#            that empties /var/run
#   status   the service line core's service framework reads: running once a route set has run on the enabled
#            plugin, until stop
#   routes_status
#       per-tunnel IPv6 route and monitor state as JSON
#   _routes [quiet] | _cleanup
#       the route set and its removal; run only under routes.lock (below)
#
# The route set comes from gateway_config.php (its line protocol). Every run holds ${STATE_DIR}/routes.lock through
# "flock -o": only the waiting flock process holds the lock, and nothing the
# section starts inherits it.

# Every file this script writes is root's alone; the state directories are 0700 (see ensure_state_dir). The PHP that
# tick and tunnel start runs under the caller's umask instead, as cron and configd ran it before they entered through
# this script, so Config::save()'s backups and whatever core creates from those runs keep their modes.
CALLER_UMASK=$(umask)
umask 077

SCRIPTS="/usr/local/opnsense/scripts/OPNsense/WGClientTunnels"
STATE_DIR="/var/run/wgclienttunnels"
DB_DIR="/var/db/wgclienttunnels"
RECORD="${STATE_DIR}/active_gateways"
GUARD="${SCRIPTS}/default_guard.php"
FRESHNESS="${SCRIPTS}/freshness.php"
PHP="/usr/local/bin/php"
FLOCK="/usr/local/bin/flock"
# core's WireGuard log takes the program name "wireguard"; the prefix tells these lines from core's
LOGGER_TAG="wireguard"

# A state directory is root 0700: -m applies only to a directory that mkdir creates, so chmod follows.
ensure_state_dir() {
    mkdir -p -m 700 "$1" && chmod 700 "$1"
}

log_msg() {
    logger -t "${LOGGER_TAG}" "[wgct-routes] $1"
}

# The route protocol on stdout. PHP diagnostics go to stderr, so a notice can
# never land ahead of the state line.
parse_config() {
    "${PHP}" -d display_errors=stderr "${SCRIPTS}/gateway_config.php"
}

# The device a host route to exactly $1 leaves by; nothing when the address
# is reached by a network or default route, or not at all.
host_route_dev() {
    /sbin/route -n get -inet6 "$1" 2>/dev/null | awk -v ip="$1" '
        $1 == "destination:" { dst = $2 }
        $1 == "interface:" { dev = $2 }
        END { if (dst == ip) print dev }'
}

# Exit 0 when device $1 holds exactly the IPv6 address $2: field 2 of an inet6 line, without its %zone. Both are
# canonical (gateway_config.php writes them so), and the prefix length is not compared.
inet6_addr_on() {
    /sbin/ifconfig "$1" inet6 | awk -v w="$2" '$1 == "inet6" { split($2, a, "%"); if (a[1] == w) f = 1 } END { exit !f }'
}

# A tunnel's IPv6 address and the interface route to its IPv6 next hop.
configure_gateway() {
    local iface="$1" ipv6_addr="$2" ipv6_gw="$3"

    if ! /sbin/ifconfig "${iface}" > /dev/null 2>&1; then
        log_msg "interface ${iface} does not exist, skipping"
        return 1
    fi

    /sbin/ifconfig "${iface}" inet6 -ifdisabled 2>/dev/null

    if ! inet6_addr_on "${iface}" "${ipv6_addr%/*}"; then
        /sbin/ifconfig "${iface}" inet6 "${ipv6_addr}" alias
        log_msg "added ${ipv6_addr} to ${iface}"
    fi

    if [ "$(host_route_dev "${ipv6_gw}")" != "${iface}" ]; then
        if host_route 'next hop' add "${ipv6_gw}" "${iface}" -iface "${iface}"; then
            log_msg "added route ${ipv6_gw} via ${iface}"
        fi
    fi
}

# Run "route add|delete" for a host route of KIND ("monitor" or "next hop"). Success returns 0 and forgets an earlier
# failure of that (IP, device). A failure is logged once per (IP, device) in route_failures, so a persistent one does
# not repeat every minute. No -q: route(8) prints nothing under it, and the log line carries route's reason.
host_route() {
    local kind="$1" verb="$2" ip="$3" dev="$4" out reason file="${STATE_DIR}/route_failures"
    shift 4
    if out=$(/sbin/route -n "${verb}" -6 -host "${ip}" "$@" 2>&1); then
        if grep -qxF "${ip}|${dev}" "${file}" 2>/dev/null; then
            grep -vxF "${ip}|${dev}" "${file}" > "${file}.tmp"
            mv -f "${file}.tmp" "${file}"
        fi
        return 0
    fi
    if ! grep -qxF "${ip}|${dev}" "${file}" 2>/dev/null; then
        printf '%s|%s\n' "${ip}" "${dev}" >> "${file}"
        reason=$(printf '%s' "${out}" | tr '\n' ' ')
        log_msg "route ${verb} for ${kind} ${ip} on ${dev} failed${reason:+: ${reason}}"
    fi
    return 1
}

# The host route to a tunnel's IPv6 monitor, as an interface route that needs no next hop. A host route to the
# monitor that the plugin did not record (a static route, an operator's) is left alone and noted once in
# foreign_routes.
configure_monitor_route() {
    local iface="$1" monitor="$2" current
    current=$(host_route_dev "${monitor}")
    if [ "${current}" = "${iface}" ]; then
        return 0
    fi
    if [ -n "${current}" ]; then
        if ! grep -qxF "${monitor}|${current}" "${STATE_DIR}/foreign_routes" 2>/dev/null; then
            printf '%s|%s\n' "${monitor}" "${current}" >> "${STATE_DIR}/foreign_routes"
            log_msg "monitor ${monitor} of ${iface} already has a host route via ${current}; left alone"
        fi
        return 0
    fi
    if host_route monitor add "${monitor}" "${iface}" -iface "${iface}"; then
        log_msg "added monitor route ${monitor} via ${iface}"
    fi
}

# Forget foreign routes that are gone, so a new one is noted again.
prune_foreign() {
    local file="${STATE_DIR}/foreign_routes" tmp monitor current
    [ -f "${file}" ] || return 0
    tmp=$(mktemp "${file}.XXXXXX") || return 0
    while IFS='|' read -r monitor current; do
        if [ "$(host_route_dev "${monitor}")" = "${current}" ]; then
            printf '%s|%s\n' "${monitor}" "${current}" >> "${tmp}"
        fi
    done < "${file}"
    mv -f "${tmp}" "${file}"
}

# A helper failure, logged once per distinct failure.
parse_failure() {
    local key="exit $1: $2"
    if [ "$(cat "${STATE_DIR}/parse_error" 2>/dev/null)" != "${key}" ]; then
        printf '%s\n' "${key}" > "${STATE_DIR}/parse_error"
        log_msg "gateway_config.php failed (${key}); routes left as they are"
    fi
}

# Clear stop's mark (start, restart and configure_routes: core's Start, Restart and Apply), so the route set runs again.
clear_stop() {
    rm -f "${STATE_DIR}/stopped" "${STATE_DIR}/stopped.logged"
}

# The route set. Run only under routes.lock (with_routes_lock).
routes_section() {
    local quiet="$1" out rc first keeps new kind dev addr nexthop gw4 gw6 monitor

    # stopped from the service controls: what stop removed stays removed, said once per stop. Checked under the lock,
    # so a route set that waited on stop's removal adds nothing back.
    if [ -f "${STATE_DIR}/stopped" ]; then
        if [ ! -f "${STATE_DIR}/stopped.logged" ]; then
            : > "${STATE_DIR}/stopped.logged"
            log_msg "route set skipped: the service is stopped; the IPv6 addresses and routes stay removed until the next start, Apply or boot"
        fi
        return 0
    fi
    out=$(parse_config)
    rc=$?
    first=$(printf '%s\n' "${out}" | head -n 1)
    if [ "${rc}" -ne 0 ] || { [ "${first}" != "state|on" ] && [ "${first}" != "state|off" ] \
        && [ "${first}" != "state|disabled" ] && [ "${first}" != "state|pending" ]; }; then
        parse_failure "${rc}" "${first}"
        return 0
    fi
    rm -f "${STATE_DIR}/parse_error"
    # the plugin's stored data waits for its migration: nothing is added or removed, said once per state
    if [ "${first}" = "state|pending" ]; then
        if [ ! -f "${STATE_DIR}/routes.awaiting-migration" ]; then
            : > "${STATE_DIR}/routes.awaiting-migration"
            log_msg "route set refused: the plugin's stored data is not migrated to this version yet (the package install runs run_migrations.php); routes left as they are"
        fi
        return 0
    fi
    if [ -f "${STATE_DIR}/routes.awaiting-migration" ]; then
        rm -f "${STATE_DIR}/routes.awaiting-migration"
        log_msg "route set runs again: the plugin's stored data is migrated"
    fi
    # the plugin disabled: nothing is maintained and nothing removed (only stop removes), and the running flag is left
    # as it is: a saved Enable off leaves the service running until its Apply stops it
    if [ "${first}" = "state|disabled" ]; then
        return 0
    fi
    # IPv6 routes off on the enabled plugin: nothing is maintained and nothing removed, and the service runs with no
    # route set, so core's Apply reloads it rather than starting it
    if [ "${first}" = "state|off" ]; then
        [ "${quiet}" = "quiet" ] || log_msg "IPv6 routes are off; routes left as they are"
        touch "${STATE_DIR}/enabled"
        return 0
    fi

    prune_foreign
    keeps=$(printf '%s\n' "${out}" | awk -F'|' '$1 == "keep" { print $2 }')
    new=$(mktemp "${RECORD}.XXXXXX") || return 1

    # stale monitor routes first, so a monitor moved between tunnels is added again below
    if [ -f "${RECORD}" ]; then
        while IFS='|' read -r dev addr nexthop gw4 monitor; do
            [ -n "${dev}" ] || continue
            if printf '%s\n' "${keeps}" | grep -qxF "${dev}"; then
                printf '%s|%s|%s|%s|%s\n' "${dev}" "${addr}" "${nexthop}" "${gw4}" "${monitor}" >> "${new}"
                continue
            fi
            [ -n "${monitor}" ] || continue
            if printf '%s\n' "${out}" | awk -F'|' -v d="${dev}" -v m="${monitor}" \
                '$1 == "route" && $2 == d && $7 == m { found = 1 } END { exit !found }'; then
                continue
            fi
            if [ "$(host_route_dev "${monitor}")" = "${dev}" ]; then
                if host_route monitor delete "${monitor}" "${dev}"; then
                    log_msg "removed monitor route ${monitor} via ${dev}"
                fi
            fi
        done < "${RECORD}"
    fi

    printf '%s\n' "${out}" | awk -F'|' '$1 == "route"' > "${new}.routes"
    while IFS='|' read -r kind dev addr nexthop gw4 gw6 monitor; do
        configure_gateway "${dev}" "${addr}" "${nexthop}" || continue
        [ -z "${monitor}" ] || configure_monitor_route "${dev}" "${monitor}"
        printf '%s|%s|%s|%s|%s\n' "${dev}" "${addr}" "${nexthop}" "${gw4}" "${monitor}" >> "${new}"
    done < "${new}.routes"
    rm -f "${new}.routes"

    mv -f "${new}" "${RECORD}"
    touch "${STATE_DIR}/enabled"
    [ "${quiet}" = "quiet" ] || log_msg "IPv6 gateway routes configured"
}

# Remove every recorded route and address (stop). Reads the previous
# version's four-field record too. Run only under routes.lock.
cleanup_section() {
    local dev addr nexthop gw4 monitor removed
    if [ -f "${RECORD}" ]; then
        while IFS='|' read -r dev addr nexthop gw4 monitor; do
            [ -n "${dev}" ] || continue
            removed=""
            if [ -n "${monitor}" ] && [ "$(host_route_dev "${monitor}")" = "${dev}" ]; then
                host_route monitor delete "${monitor}" "${dev}" && removed=" and monitor route ${monitor}"
            fi
            if [ "$(host_route_dev "${nexthop}")" = "${dev}" ]; then
                host_route 'next hop' delete "${nexthop}" "${dev}" && removed=" and route ${nexthop}${removed}"
            fi
            /sbin/ifconfig "${dev}" inet6 "${addr%/*}" -alias 2>/dev/null
            log_msg "removed ${addr}${removed} from ${dev}"
        done < "${RECORD}"
        rm -f "${RECORD}"
    fi
    rm -f "${STATE_DIR}/enabled"
}

# Run a route-set section under routes.lock. Only the flock process holds the
# lock (-o closes it for the section), every caller waits at most 10 s, and
# exit 75 means that wait ran out.
with_routes_lock() {
    local rc
    ensure_state_dir "${STATE_DIR}"
    "${FLOCK}" -E 75 -w 10 -o "${STATE_DIR}/routes.lock" "$0" "$@"
    rc=$?
    if [ "${rc}" -eq 75 ]; then
        log_msg "$1 skipped: another run held ${STATE_DIR}/routes.lock for 10 s"
    fi
    return "${rc}"
}

# Mark a reconcile wanted and start a detached waiter for it on reconcile.lock; the status is the first failing
# step's, so a mark that cannot be written fails the queue as daemon does. Each request queues a waiter, and a
# waiter that finds the mark cleared by an earlier run exits, so a burst costs one or two reconciles and a request
# made during a run still gets a run that sees it.
queue_reconcile() {
    ensure_state_dir "${STATE_DIR}" && : > "${STATE_DIR}/reconcile.pending" && /usr/sbin/daemon -f "$0" _reconcile_wait
}

# up, down or unknown from a gateway's dpinger socket (loss below 100%)
dpinger_state() {
    local sock="/var/run/dpinger_$1.sock" out loss
    if [ ! -S "${sock}" ]; then
        echo unknown
        return
    fi
    out=$(echo "" | /usr/bin/nc -U "${sock}" 2>/dev/null)
    if [ -z "${out}" ]; then
        echo unknown
        return
    fi
    loss=$(echo "${out}" | awk '{print $NF}')
    if [ "${loss}" -lt 100 ] 2>/dev/null; then
        echo up
    else
        echo down
    fi
}

# The service line core's service framework reads (ApiMutableServiceControllerBase::statusAction looks
# for "is running" / "not running"), and nothing else. The running flag is the route set's (state|on or state|off),
# and stop removes it.
do_status() {
    if [ -f "${STATE_DIR}/enabled" ]; then
        echo "wgclienttunnels is running"
    else
        echo "wgclienttunnels is not running"
    fi
}

# Per-tunnel IPv6 route and monitor state as one JSON object, for the operator
# (configctl wgclienttunnels routes_status).
do_routes_status() {
    local out first=1 kind dev addr nexthop gw4 gw6 monitor route_ok ipv4_status v6 m_route m_running status
    out=$(parse_config)
    printf '{"gateways":['
    while IFS='|' read -r kind dev addr nexthop gw4 gw6 monitor; do
        case "${kind}" in
            route|keep) ;;
            *) continue ;;
        esac
        [ "${first}" = 1 ] || printf ','
        first=0
        if [ "${kind}" = "keep" ]; then
            printf '{"interface":"%s","status":"blocked"}' "${dev}"
            continue
        fi
        route_ok=false
        [ "$(host_route_dev "${nexthop}")" = "${dev}" ] && route_ok=true
        ipv4_status=$(dpinger_state "${gw4}")
        m_route=false
        m_running=false
        v6="${ipv4_status}"
        if [ -n "${monitor}" ]; then
            [ "$(host_route_dev "${monitor}")" = "${dev}" ] && m_route=true
            pgrep -qF "/var/run/dpinger_${gw6}.pid" 2>/dev/null && m_running=true
            v6=$(dpinger_state "${gw6}")
        fi
        status=down
        if [ "${route_ok}" = true ] && [ "${v6}" = up ]; then
            status=up
        fi
        printf '{"interface":"%s","ipv6_address":"%s","ipv6_gateway":"%s","ipv4_gateway":"%s","route_exists":%s,"ipv4_status":"%s","monitor6":"%s","monitor6_route_ok":%s,"monitor6_running":%s,"status":"%s","description":"%s"}' \
            "${dev}" "${addr}" "${nexthop}" "${gw4}" "${route_ok}" "${ipv4_status}" "${monitor}" "${m_route}" "${m_running}" "${status}" "${gw6}"
    done <<EOF
${out}
EOF
    printf ']}\n'
}

# The package removal's marker (+PRE_DEINSTALL.pre writes it, +POST_INSTALL.pre deletes it): while it exists nothing
# here adds, repairs or queues anything, so nothing rebuilds what the removal takes away. stop (the removal's own), its
# section and the status lines still run. The minute cron's reconcile says so each minute, which a removal that stopped
# partway is worth. tick and tunnel are not listed: their PHP scripts check the marker themselves (entry.php).
case "$1" in
    start|restart|configure_routes|reconcile|hook|request_reconcile|_reconcile_wait|_reconcile_queued|_routes)
        if [ -f "${STATE_DIR}/removing" ]; then
            if [ "$1" = "reconcile" ] && [ "$2" = "--cron" ]; then
                log_msg "the package is being removed (${STATE_DIR}/removing exists): the plugin does nothing; delete it if the package is still installed"
            fi
            exit 0
        fi
        ;;
esac

case "$1" in
    start|configure_routes)
        clear_stop
        with_routes_lock _routes
        ;;
    stop)
        # A clean stop also ends the footprint a failed render would enforce, and the hook's note about it. Its mark,
        # written before the removal, keeps the hooks' and the reconcile's route set from adding back what it removes;
        # the WAN pins, the default-route guard, freshness and the health mirror are policy for the tunnels that still
        # exist and run on, and the prime finds no address to use.
        rm -f "${DB_DIR}/footprint.json" "${STATE_DIR}/fallback.json" "${STATE_DIR}/fallback.logged"
        ensure_state_dir "${STATE_DIR}" && : > "${STATE_DIR}/stopped"
        rm -f "${STATE_DIR}/stopped.logged"
        with_routes_lock _cleanup && log_msg "stopped"
        ;;
    restart)
        clear_stop
        # While the stored data waits for its migration the route set adds nothing, so a restart must not remove first.
        if [ "$(parse_config 2>/dev/null | head -n 1)" = "state|pending" ]; then
            with_routes_lock _routes
        else
            with_routes_lock _cleanup && with_routes_lock _routes
        fi
        ;;
    reconcile)
        # Idempotent: adds only what is missing and is silent unless it fixed something.
        ensure_state_dir "${DB_DIR}"
        with_routes_lock _routes quiet
        "${PHP}" "${GUARD}"
        "${PHP}" "${FRESHNESS}"
        "${PHP}" "${SCRIPTS}/core_contract.php"
        ;;
    hook)
        # core's monitor, newwanip and bootup hooks (wgclienttunnels_configure_do()). Only the route set runs before
        # core continues, since its routing configure needs the routes in place; the rest follows in a queued
        # reconcile. A queue that cannot start is logged, and the minute reconcile runs the rest; a mark it did write
        # stays for that run or the next request.
        ensure_state_dir "${DB_DIR}"
        with_routes_lock _routes quiet
        rc=$?
        queue_reconcile || log_msg "queued reconcile could not be started (exit $?); the minute reconcile runs it"
        exit "${rc}"
        ;;
    request_reconcile)
        # The config syshook: mark a reconcile wanted and return at once, so core's config-event
        # handler is never held up.
        queue_reconcile
        ;;
    _reconcile_wait)
        # A reconcile running past the wait leaves the mark for the next request or the minute cron.
        wait=120
        "${FLOCK}" -E 75 -w "${wait}" -o "${STATE_DIR}/reconcile.lock" "$0" _reconcile_queued
        if [ $? -eq 75 ]; then
            log_msg "queued reconcile skipped: another reconcile held reconcile.lock for ${wait} s; the minute reconcile will run it"
        fi
        ;;
    _reconcile_queued)
        [ -f "${STATE_DIR}/reconcile.pending" ] || exit 0
        rm -f "${STATE_DIR}/reconcile.pending"
        "$0" reconcile
        ;;
    _routes)
        routes_section "$2"
        ;;
    _cleanup)
        cleanup_section
        ;;
    tick)
        # The mirror's exit does not stop the prime: the prime runs after every tick, whatever the mirror decided.
        ( umask "${CALLER_UMASK}"; "${PHP}" "${SCRIPTS}/health_mirror.php" )
        ( umask "${CALLER_UMASK}"; "${PHP}" "${SCRIPTS}/prime.php" )
        ;;
    tunnel)
        shift
        umask "${CALLER_UMASK}"
        exec "${PHP}" "${SCRIPTS}/tunnel.php" "$@"
        ;;
    status)
        do_status
        ;;
    routes_status)
        do_routes_status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|configure_routes|reconcile|hook|request_reconcile|tick|tunnel <arguments>|status|routes_status}"
        exit 1
        ;;
esac
