#!/bin/sh

# Copyright (C) 2026 cayossarian (Bill Flood)
# All rights reserved.
#
# WireGuard upstream tunnels: the managed tunnels' IPv6 addresses, their
# next-hop and monitor routes, and the reconcile.
#
#   start | restart | configure_routes
#       add each managed tunnel's IPv6 address to its device, the host route
#       to its IPv6 next hop and the host route to its IPv6 monitor
#   reconcile
#       the same as start, silent unless it repairs something; then
#       default_guard.php and freshness.php
#   stop     remove what start added
#   status   the service line the dashboard reads, then per-tunnel JSON
#   _routes [quiet] | _cleanup
#       the route set and its removal; run only under routes.lock (below)
#
# The route set comes from gateway_config.php (its line protocol: spec
# 2026-09-28 section 3.4.1). Every run holds ${STATE_DIR}/routes.lock through
# "flock -o": only the waiting flock process holds the lock, and nothing the
# section starts inherits it. WGCT_CONFIG_HELPER (a command printing the
# protocol) and WGCT_STATE_DIR override the helper and the state directory;
# the shell tests use both.

SCRIPTS="/usr/local/opnsense/scripts/OPNsense/WGClientTunnels"
STATE_DIR="${WGCT_STATE_DIR:-/var/run/wgclienttunnels}"
RECORD="${STATE_DIR}/active_gateways"
GUARD="${SCRIPTS}/default_guard.php"
FRESHNESS="${SCRIPTS}/freshness.php"
PHP="/usr/local/bin/php"
FLOCK="/usr/local/bin/flock"
LOGGER_TAG="wgct"

log_msg() {
    logger -t "${LOGGER_TAG}" "$1"
}

# The route protocol on stdout. PHP diagnostics go to stderr, so a notice can
# never land ahead of the state line.
parse_config() {
    if [ -n "${WGCT_CONFIG_HELPER:-}" ]; then
        "${WGCT_CONFIG_HELPER}"
    else
        "${PHP}" -d display_errors=stderr "${SCRIPTS}/gateway_config.php"
    fi
}

# The device a host route to exactly $1 leaves by; nothing when the address
# is reached by a network or default route, or not at all.
host_route_dev() {
    /sbin/route -n get -inet6 "$1" 2>/dev/null | awk -v ip="$1" '
        $1 == "destination:" { dst = $2 }
        $1 == "interface:" { dev = $2 }
        END { if (dst == ip) print dev }'
}

# A tunnel's IPv6 address and the interface route to its IPv6 next hop.
configure_gateway() {
    local iface="$1" ipv6_addr="$2" ipv6_gw="$3" addr_only

    if ! /sbin/ifconfig "${iface}" > /dev/null 2>&1; then
        log_msg "interface ${iface} does not exist, skipping"
        return 1
    fi

    /sbin/ifconfig "${iface}" inet6 -ifdisabled 2>/dev/null

    addr_only=$(echo "${ipv6_addr}" | cut -d/ -f1)
    if ! /sbin/ifconfig "${iface}" | grep -q "${addr_only}"; then
        /sbin/ifconfig "${iface}" inet6 "${ipv6_addr}" alias
        log_msg "added ${ipv6_addr} to ${iface}"
    fi

    if ! /usr/bin/netstat -rn -f inet6 | grep -q "${ipv6_gw}.*${iface}"; then
        /sbin/route -q -n add -6 "${ipv6_gw}" -iface "${iface}"
        log_msg "added route ${ipv6_gw} via ${iface}"
    fi
}

# The host route to a tunnel's IPv6 monitor, as an interface route: it needs
# no next hop, so it works as soon as the device exists. A host route to the
# monitor that the plugin did not record (a static route, an operator's
# route) is left alone and noted once in foreign_routes.
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
    /sbin/route -q -n add -6 -host "${monitor}" -iface "${iface}"
    log_msg "added monitor route ${monitor} via ${iface}"
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

# The route set (spec 3.4.2). Run only under routes.lock (with_routes_lock).
routes_section() {
    local quiet="$1" out rc first keeps new kind dev addr nexthop gw4 gw6 monitor

    out=$(parse_config)
    rc=$?
    first=$(printf '%s\n' "${out}" | head -n 1)
    if [ "${rc}" -ne 0 ] || { [ "${first}" != "state|on" ] && [ "${first}" != "state|off" ]; }; then
        parse_failure "${rc}" "${first}"
        return 0
    fi
    rm -f "${STATE_DIR}/parse_error"
    # plugin or IPv6 routes off: nothing is maintained and nothing removed; only stop removes
    if [ "${first}" = "state|off" ]; then
        [ "${quiet}" = "quiet" ] || log_msg "IPv6 routes are off; routes left as they are"
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
                /sbin/route -q -n delete -6 -host "${monitor}"
                log_msg "removed monitor route ${monitor} via ${dev}"
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
    local dev addr nexthop gw4 monitor
    if [ -f "${RECORD}" ]; then
        while IFS='|' read -r dev addr nexthop gw4 monitor; do
            [ -n "${dev}" ] || continue
            if [ -n "${monitor}" ] && [ "$(host_route_dev "${monitor}")" = "${dev}" ]; then
                /sbin/route -q -n delete -6 -host "${monitor}"
            fi
            /sbin/route -q -n delete -6 "${nexthop}" 2>/dev/null
            /sbin/ifconfig "${dev}" inet6 "${addr%/*}" -alias 2>/dev/null
            log_msg "removed ${addr} and route ${nexthop}${monitor:+ and monitor route ${monitor}} from ${dev}"
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
    mkdir -p "${STATE_DIR}"
    "${FLOCK}" -E 75 -w 10 -o "${STATE_DIR}/routes.lock" "$0" "$@"
    rc=$?
    if [ "${rc}" -eq 75 ]; then
        log_msg "$1 skipped: another run held ${STATE_DIR}/routes.lock for 10 s"
    fi
    return "${rc}"
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

# The first line must contain "is running" or "not running" for the OPNsense
# service framework (ApiMutableServiceControllerBase) to detect the service
# state on the dashboard widget.
do_status() {
    local out first=1 kind dev addr nexthop gw4 gw6 monitor route_ok ipv4_status v6 m_route m_running status
    out=$(parse_config)
    if [ -f "${STATE_DIR}/enabled" ]; then
        echo "wgclienttunnels is running"
    else
        echo "wgclienttunnels is not running"
    fi
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
        /usr/bin/netstat -rn -f inet6 | grep -q "${nexthop}.*${dev}" && route_ok=true
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

case "$1" in
    start|configure_routes)
        with_routes_lock _routes
        ;;
    stop)
        with_routes_lock _cleanup && log_msg "stopped"
        ;;
    restart)
        with_routes_lock _cleanup && with_routes_lock _routes
        ;;
    reconcile)
        # Idempotent repair pass for event hooks and cron: adds only what is
        # missing and stays silent unless it actually had to fix something.
        with_routes_lock _routes quiet
        # Then make sure no tunnel carries a default route (see default_guard.php).
        "${PHP}" "${GUARD}"
        # Then keep the rendered pins and MSS anchor current (freshness.php).
        "${PHP}" "${FRESHNESS}"
        ;;
    _routes)
        routes_section "$2"
        ;;
    _cleanup)
        cleanup_section
        ;;
    status)
        do_status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|configure_routes|reconcile|status}"
        exit 1
        ;;
esac
