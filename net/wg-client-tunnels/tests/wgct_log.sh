#!/bin/sh

# Copyright (C) 2026 cayossarian
# All rights reserved.
# BSD 2-Clause License
#
# Log routing test: the plugin logs to core's WireGuard log. Root on the disposable test VM, with the branch
# build of os-wg-client-tunnels installed; never on a firewall. It logs marked lines the plugin's ways and
# looks for them in the WireGuard log and the system log. The wgct.sh line comes from a substituted copy of
# wgct.sh (wgct_stub.sh; production honours no environment override): the file named by the optional argument,
# else the installed one.
#
# Usage: wgct_log.sh [/path/to/wgct.sh]

set -u
pass=0
fail=0
check() {
    if eval "$2"; then
        pass=$((pass + 1)); echo "[PASS] log: $1"
    else
        fail=$((fail + 1)); echo "[FAIL] log: $1"
    fi
}
tag="wgct-logtest-$$"
S=/usr/local/opnsense/scripts/OPNsense/WGClientTunnels
L=/var/log/wireguard
T=$(mktemp -d /tmp/wgct-log.XXXXXX)
sh "$(dirname "$0")/wgct_stub.sh" "${1:-$S/wgct.sh}" "$T/wgct.sh" "$T/state" "$T/helper" "$T/recon" 120 || exit 1
# a plugin line from a process whose ident is core's (as in the filter hook or a controller), and an info line
/usr/local/bin/php -d log_errors=0 -r 'require "'$S'/lib/tunnels.php"; openlog("config", 0, LOG_USER);
    wgct_log(LOG_NOTICE, "[wgct-logtest] '$tag' core-ident"); wgct_log(LOG_INFO, "[wgct-logtest] '$tag' info");'
# a wgct.sh line: a stub helper reports the routes off, which the non-quiet route set logs
printf '#!/bin/sh\necho "state|off"\n' > "$T/helper"
chmod +x "$T/helper"
"$T/wgct.sh" configure_routes
# core's own line
logger -t config "coretest-$tag"
# every line above is written once a marker logged after them is (syslog writes in order): one to the WireGuard log,
# and core's own line to the system log (at most 10 s each)
. "$(dirname "$0")/wgct_marks.sh"
lmark wireguard > /dev/null
n=0
while [ "$n" -lt 100 ] && ! grep -qs "coretest-$tag" /var/log/system/*.log; do
    sleep 0.1
    n=$((n + 1))
done
check "1 a plugin line from a process with a core ident lands in the WireGuard log" 'grep -qs "$tag core-ident" $L/*.log'
check "2 info-level lines are kept" 'grep -qs "$tag info" $L/*.log'
check "3 a wgct.sh line lands in the WireGuard log with its [wgct-routes] prefix" 'grep -hs "IPv6 routes are off" $L/*.log | tail -1 | grep -q "wireguard.*\[wgct-routes\] IPv6 routes are off"'
check "4 none of them is in the system log" '! grep -qs -e "$tag core-ident" -e "$tag info" /var/log/system/*.log'
check "5 core's own lines stay in the system log" 'grep -qs "coretest-$tag" /var/log/system/*.log && ! grep -qs "coretest-$tag" $L/*.log'
check "6 nothing lands in a log of the plugin's own" '! grep -qs "$tag" /var/log/wgclienttunnels/*.log'
rm -rf "$T"
echo "log: $pass/$((pass + fail)) passed"
[ "$fail" = 0 ]
