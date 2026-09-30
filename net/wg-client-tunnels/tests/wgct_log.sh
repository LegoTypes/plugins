#!/bin/sh

# Copyright (C) 2026 cayossarian (Bill Flood)
# All rights reserved.
# BSD 2-Clause License
#
# Log routing test for the plugin's syslog destination. Root on the disposable test VM, with the
# branch build of os-wg-client-tunnels installed; never on a firewall. It writes marked lines with
# logger(1) and looks for them in the plugin log and the system log.

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
L=/var/log/wgclienttunnels
logger -t wgct "$tag shell"
logger -t config "[wgct-logtest] $tag core-ident"
logger -p user.info -t wgct "$tag info"
logger -t config "coretest-$tag"
sleep 3
check "1 a line from the wgct program lands in the plugin log" 'grep -qs "$tag shell" $L/*.log'
check "2 a [wgct-] line under a core program name lands in the plugin log" 'grep -qs "$tag core-ident" $L/*.log'
check "3 neither is in the system log" '! grep -qs -e "$tag shell" -e "$tag core-ident" /var/log/system/*.log'
check "4 info-level lines are kept" 'grep -qs "$tag info" $L/*.log'
check "5 core's own lines stay in the system log" 'grep -qs "coretest-$tag" /var/log/system/*.log && ! grep -qs "coretest-$tag" $L/*.log'
echo "log: $pass/$((pass + fail)) passed"
[ "$fail" = 0 ]
