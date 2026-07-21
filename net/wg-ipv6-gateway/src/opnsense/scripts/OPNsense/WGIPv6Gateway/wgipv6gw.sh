#!/bin/sh

# Copyright (C) 2026 cayossarian (Bill Flood)
# All rights reserved.
#
# WireGuard IPv6 Gateway - route management and health mirroring
#
# This script manages IPv6 routing through WireGuard tunnels:
# 1. Adds IPv6 addresses to WG interfaces
# 2. Creates interface host routes for IPv6 gateways
# 3. Mirrors IPv6 gateway health from corresponding IPv4 gateways
#
# Configuration is read from the OPNsense MVC models via gateway_config.php.

CONFIG_HELPER="/usr/local/opnsense/scripts/OPNsense/WGIPv6Gateway/gateway_config.php"
LOGGER_TAG="wgipv6gw"
STATE_DIR="/var/run/wgipv6gateway"

log_msg() {
    logger -t "${LOGGER_TAG}" "$1"
}

# Parse gateway entries from the MVC model helper.
# Output: enabled|wg_device|ipv6_address|ipv6_gw_addr|ipv4_gw_name|description
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
        echo "wgipv6gateway is running"
    else
        echo "wgipv6gateway is not running"
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
        do_configure_routes quiet
        ;;
    status)
        do_status
        ;;
    *)
        echo "Usage: $0 {start|stop|restart|configure_routes|reconcile|status}"
        exit 1
        ;;
esac
