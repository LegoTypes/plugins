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
# Writes a copy of the production wgct.sh with the four values the shell tests need to control substituted:
# the state directory, the command that prints the route protocol, the command a queued reconcile runs, and
# the seconds a queued reconcile waits for reconcile.lock. The persistent state directory becomes <state dir>/db,
# so a copy never touches the footprint in /var/db. Production wgct.sh honours no environment override,
# so the tests run this copy instead. Each substitution must match exactly one line of wgct.sh; when one
# matches none (or several), this fails, so a later edit of wgct.sh cannot leave the copy on production paths.
# With the optional seventh value, every PHP run of the copy goes to that command instead (a recorder): only the
# route protocol stays the helper, which is substituted separately.
#
# Usage: wgct_stub.sh <wgct.sh> <out> <state dir> <helper> <reconcile cmd> <wait> [<php>]
# The values must not contain '#', '&', '\' or a newline.

set -u
if [ $# -ne 6 ] && [ $# -ne 7 ]; then
    echo "usage: wgct_stub.sh <wgct.sh> <out> <state dir> <helper> <reconcile cmd> <wait> [<php>]" >&2
    exit 2
fi
src="$1"; out="$2"; state="$3"; helper="$4"; recon="$5"; wait="$6"; php="${7:-}"
cur=$(mktemp "${out}.XXXXXX") || exit 1
next=$(mktemp "${out}.XXXXXX") || exit 1
trap 'rm -f "$cur" "$next"' EXIT
cat "$src" > "$cur"

# substitute <what> <BRE matching the whole line> <replacement>
substitute() {
    n=$(grep -c -e "$2" "$cur")
    if [ "$n" != 1 ]; then
        echo "wgct_stub.sh: $1: $n lines of $src match, expected 1" >&2
        exit 1
    fi
    sed -e "s#$2#$3#" "$cur" > "$next"
    cat "$next" > "$cur"
}

substitute "state directory" '^STATE_DIR="/var/run/wgclienttunnels"$' "STATE_DIR=\"$state\""
substitute "db directory" '^DB_DIR="/var/db/wgclienttunnels"$' "DB_DIR=\"$state/db\""
substitute "route protocol helper" '^\( *\)"${PHP}" -d display_errors=stderr "${SCRIPTS}/gateway_config.php"$' "\\1\"$helper\""
substitute "reconcile command" '^\( *\)"$0" reconcile$' "\\1\"$recon\""
substitute "reconcile wait" '^\( *\)wait=120$' "\\1wait=$wait"
if [ -n "$php" ]; then
    substitute "php" '^PHP="/usr/local/bin/php"$' "PHP=\"$php\""
fi
cat "$cur" > "$out"
chmod +x "$out"
