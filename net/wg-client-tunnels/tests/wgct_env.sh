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
# Production wgct.sh and the PHP scripts honour no WGCT_* environment override: a variable in the environment of a root
# process must not choose which helper runs or where the state lives. Root on the disposable test VM only
# (vm_selftest.sh), never on a firewall. It runs the production file itself, not a substituted copy: the one named by
# the argument (vm_selftest.sh passes /tmp/wgct/wgct.sh, the tree's copy), else the installed one.
#
# Usage: wgct_env.sh [/path/to/wgct.sh]

set -u
W="${1:-/usr/local/opnsense/scripts/OPNsense/WGClientTunnels/wgct.sh}"
D=$(dirname "$W")
T=$(mktemp -d /tmp/wgct-env.XXXXXX)
trap 'rm -rf "$T" /tmp/y' EXIT
pass=0
fail=0
check() {
    if eval "$2"; then
        pass=$((pass + 1)); echo "[PASS] env: $1"
    else
        fail=$((fail + 1)); echo "[FAIL] env: $1"
    fi
}
rm -rf /tmp/y
printf '#!/bin/sh\ntouch "%s/marker"\necho "state|off"\n' "$T" > "$T/x"
chmod +x "$T/x"
WGCT_CONFIG_HELPER="$T/x" WGCT_STATE_DIR=/tmp/y WGCT_RECONCILE_CMD="$T/x" WGCT_RECONCILE_WAIT=1 "$W" configure_routes > /dev/null
check "1 WGCT_CONFIG_HELPER is ignored: the helper it names does not run" '[ ! -e "$T/marker" ]'
check "2 WGCT_STATE_DIR is ignored: the directory it names is not created" '[ ! -e /tmp/y ]'
check "3 no production shell or PHP script reads a WGCT_ environment variable" '! grep -rnE "getenv\(.WGCT_|[$][{]WGCT_[A-Z_]+[:}-]" "$D" --include=*.sh --include=*.php'
echo "env: $pass/$((pass + fail)) passed"
[ "$fail" = 0 ]
