#!/bin/sh

# Copyright (C) 2026 cayossarian (Bill Flood)
# All rights reserved.
#
# WireGuard upstream tunnels: the managed tunnels' IPv6 addresses and next-hop
# routes, and the reconcile.
#
#   start | restart | configure_routes
#       add each managed tunnel's IPv6 address to its device and the host
#       route to its IPv6 next hop
#   reconcile
#       first migrates a pre-3.0 section that config holds without one of
#       this plugin's own (heal_legacy_section); then the same as start,
#       silent unless it repairs something; then default_guard.php and
#       freshness.php
#   stop     remove what start added
#   status   the service line the dashboard reads, then per-tunnel JSON
#
# The route set comes from gateway_config.php, derived from core config.

CONFIG_HELPER="/usr/local/opnsense/scripts/OPNsense/WGClientTunnels/gateway_config.php"
GUARD="/usr/local/opnsense/scripts/OPNsense/WGClientTunnels/default_guard.php"
FRESHNESS="/usr/local/opnsense/scripts/OPNsense/WGClientTunnels/freshness.php"
MIGRATE="/usr/local/opnsense/scripts/OPNsense/WGClientTunnels/migrate.php"
PHP="/usr/local/bin/php"
CONFIG_XML="/conf/config.xml"
LOGGER_TAG="wgct"
STATE_DIR="/var/run/wgclienttunnels"

log_msg() {
    logger -t "${LOGGER_TAG}" "$1"
}

# Log each non-empty line of $2 under the prefix $1.
log_lines() {
    printf '%s\n' "$2" | while IFS= read -r line; do
        [ -z "${line}" ] || log_msg "$1${line}"
    done
}

# Whether config holds os-wg-ipv6-gateway's pre-3.0 section (WGIPv6Gateway)
# and no WGClientTunnels section. Reads config.xml only; an unreadable file
# (grep status 2) never counts.
legacy_section_only() {
    grep -qs '<WGIPv6Gateway[[:space:]/>]' "${CONFIG_XML}" || return 1
    grep -qs '<WGClientTunnels[[:space:]/>]' "${CONFIG_XML}"
    [ $? -eq 1 ]
}

# Migrate a pre-3.0 section that config holds without one of this plugin's
# own. A restore from System > Configuration > Backups runs the model
# migrations, but a Config History revert only restores and saves, so a
# revert to a pre-3.0 revision would leave this plugin on its defaults
# (everything off: no pins, no MSS clamp, no mirror, no guard). migrate.php
# --dry decides, reading config only; migrate.php then takes the config lock,
# migrates and saves once. That save runs the config hook, and so this
# reconcile, again, which then finds the WGClientTunnels section and does
# nothing; a reconcile racing this one finds it under the config lock and
# reports "already at". A refusal (a pre-2.0 section) or a failed migration
# is logged once per distinct state in $STATE_DIR/legacy_section.logged, not
# every minute; a failed state is not retried until the section, and with it
# the dry run's report, changes, or a reboot or a redeploy retries it. The
# reconcile goes on either way.
heal_legacy_section() {
    local mark="${STATE_DIR}/legacy_section.logged"
    local dry dry_rc=0 out rc=0
    if ! legacy_section_only; then
        rm -f "${mark}"
        return 0
    fi
    dry=$("${PHP}" "${MIGRATE}" --dry 2>&1) || dry_rc=$?
    if [ "${dry_rc}" -ne 0 ]; then
        if [ "$(cat "${mark}" 2>/dev/null)" != "refused ${dry}" ]; then
            log_msg "[wgct-migrate] config holds the os-wg-ipv6-gateway section and no WGClientTunnels section, and migrate.php --dry refuses it (exit ${dry_rc}); the plugin stays on its defaults, everything off, until it is migrated:"
            log_lines "[wgct-migrate]   " "${dry}"
            mkdir -p "${STATE_DIR}"
            printf '%s\n' "refused ${dry}" > "${mark}"
        fi
        return 0
    fi
    if [ "$(cat "${mark}" 2>/dev/null)" = "failed ${dry}" ]; then
        return 0
    fi
    log_msg "[wgct-migrate] config holds the os-wg-ipv6-gateway section and no WGClientTunnels section (a Config History revert to a pre-3.0 revision?); migrating:"
    log_lines "[wgct-migrate]   " "${dry}"
    out=$("${PHP}" "${MIGRATE}" 2>&1) || rc=$?
    log_lines "[wgct-migrate]   " "${out}"
    if [ "${rc}" -eq 0 ] && ! legacy_section_only; then
        rm -f "${mark}"
        return 0
    fi
    log_msg "[wgct-migrate] the migration did not complete (migrate.php exit ${rc}); the plugin stays on its defaults, everything off; not retried until the section changes, a reboot or a redeploy"
    mkdir -p "${STATE_DIR}"
    printf '%s\n' "failed ${dry}" > "${mark}"
    return 0
}

# Parse gateway entries from the MVC model helper.
# Output: enabled|wg_device|ipv6_address|ipv6_gw_addr|ipv4_gw_name|ipv6_gw_name
parse_config() {
    /usr/local/bin/php "${CONFIG_HELPER}"
}

# Add IPv6 address and interface route for a single gateway
configure_gateway() {
    local iface="$1" ipv6_addr="$2" ipv6_gw="$3" ipv4_gw="$4"

    if ! /sbin/ifconfig "${iface}" > /dev/null 2>&1; then
        log_msg "interface ${iface} does not exist, skipping"
        return 1
    fi

    /sbin/ifconfig "${iface}" inet6 -ifdisabled 2>/dev/null

    local addr_only
    addr_only=$(echo "${ipv6_addr}" | cut -d/ -f1)
    if ! /sbin/ifconfig "${iface}" | grep -q "${addr_only}"; then
        /sbin/ifconfig "${iface}" inet6 "${ipv6_addr}" alias
        log_msg "added ${ipv6_addr} to ${iface}"
    fi

    if ! /usr/bin/netstat -rn -f inet6 | grep -q "${ipv6_gw}.*${iface}"; then
        /sbin/route -q -n add -6 "${ipv6_gw}" -iface "${iface}"
        log_msg "added route ${ipv6_gw} via ${iface}"
    fi

    echo "${iface}|${ipv6_addr}|${ipv6_gw}|${ipv4_gw}" >> "${STATE_DIR}/active_gateways"
}

# Remove all managed routes and addresses
cleanup_gateways() {
    if [ ! -f "${STATE_DIR}/active_gateways" ]; then
        return
    fi

    while IFS='|' read -r iface ipv6_addr ipv6_gw ipv4_gw; do
        local addr_only
        addr_only=$(echo "${ipv6_addr}" | cut -d/ -f1)
        /sbin/route -q -n delete -6 "${ipv6_gw}" 2>/dev/null
        /sbin/ifconfig "${iface}" inet6 "${addr_only}" -alias 2>/dev/null
        log_msg "removed ${ipv6_addr} and route ${ipv6_gw} from ${iface}"
    done < "${STATE_DIR}/active_gateways"

    rm -f "${STATE_DIR}/active_gateways"
}

# Configure all gateway routes
do_configure_routes() {
    mkdir -p "${STATE_DIR}"
    rm -f "${STATE_DIR}/active_gateways"

    local gateways
    gateways=$(parse_config)
    if [ $? -ne 0 ] || [ -z "${gateways}" ]; then
        [ "$1" = "quiet" ] || log_msg "no enabled gateways configured"
        return
    fi

    echo "${gateways}" | while IFS='|' read -r enabled iface addr gw ipv4 desc; do
        configure_gateway "${iface}" "${addr}" "${gw}" "${ipv4}"
    done

    touch "${STATE_DIR}/enabled"
    [ "$1" = "quiet" ] || log_msg "IPv6 gateway routes configured"
}

# Output status of all gateways.
# The first line must contain "is running" or "not running" for the
# OPNsense service framework (ApiMutableServiceControllerBase) to
# detect the service state on the dashboard widget.
do_status() {
    local gateways
    gateways=$(parse_config)

    if [ -f "${STATE_DIR}/enabled" ]; then
        echo "wgclienttunnels is running"
    else
        echo "wgclienttunnels is not running"
    fi

    printf '{"gateways":['
    local first=1

    if [ -n "${gateways}" ]; then
        echo "${gateways}" | while IFS='|' read -r enabled iface addr gw ipv4 desc; do
            local route_ok="false"
            if /usr/bin/netstat -rn -f inet6 | grep -q "${gw}.*${iface}"; then
                route_ok="true"
            fi

            local ipv4_status="unknown"
            local sock="/var/run/dpinger_${ipv4}.sock"
            if [ -S "${sock}" ]; then
                local dpinger_out
                dpinger_out=$(echo "" | /usr/bin/nc -U "${sock}" 2>/dev/null)
                if [ -n "${dpinger_out}" ]; then
                    local loss
                    loss=$(echo "${dpinger_out}" | awk '{print $NF}')
                    if [ "${loss}" -lt 100 ] 2>/dev/null; then
                        ipv4_status="up"
                    else
                        ipv4_status="down"
                    fi
                fi
            fi

            local status="down"
            if [ "${route_ok}" = "true" ] && [ "${ipv4_status}" = "up" ]; then
                status="up"
            fi

            if [ "${first}" != "1" ]; then
                printf ','
            fi
            first=0

            printf '{"interface":"%s","ipv6_address":"%s","ipv6_gateway":"%s","ipv4_gateway":"%s","route_exists":%s,"ipv4_status":"%s","status":"%s","description":"%s"}' \
                "${iface}" "${addr}" "${gw}" "${ipv4}" "${route_ok}" "${ipv4_status}" "${status}" "${desc}"
        done
    fi

    printf ']}\n'
}

case "$1" in
    start)
        do_configure_routes
        ;;
    stop)
        cleanup_gateways
        rm -f "${STATE_DIR}/enabled"
        log_msg "stopped"
        ;;
    restart)
        cleanup_gateways
        do_configure_routes
        ;;
    configure_routes)
        do_configure_routes
        ;;
    reconcile)
        # Idempotent repair pass for event hooks and cron: adds only what is
        # missing and stays silent unless it actually had to fix something.
        # First, a pre-3.0 section a Config History revert brought back is
        # migrated, so everything below reads the migrated settings.
        heal_legacy_section
        do_configure_routes quiet
        # Then make sure no tunnel carries a default route (see default_guard.php).
        /usr/local/bin/php "${GUARD}"
        # Then keep the rendered pins and MSS anchor current (freshness.php).
        /usr/local/bin/php "${FRESHNESS}"
        ;;
    status)
        do_status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|configure_routes|reconcile|status}"
        exit 1
        ;;
esac
