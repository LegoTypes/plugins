#!/bin/sh

# Copyright (C) 2026 cayossarian
# All rights reserved.
# BSD 2-Clause License
#
# Writes a copy of the production wgct.sh with the four values the shell tests need to control substituted:
# the state directory, the command that prints the route protocol, the command a queued reconcile runs, and
# the seconds a queued reconcile waits for reconcile.lock. The persistent state directory becomes <state dir>/db,
# so a copy never touches the footprint in /var/db. Production wgct.sh honours no environment override,
# so the tests run this copy instead. Each substitution must match exactly one line of wgct.sh; when one
# matches none (or several), this fails, so a later edit of wgct.sh cannot leave the copy on production paths.
#
# Usage: wgct_stub.sh <wgct.sh> <out> <state dir> <helper> <reconcile cmd> <wait>
# The values must not contain '#', '&', '\' or a newline.

set -u
if [ $# -ne 6 ]; then
    echo "usage: wgct_stub.sh <wgct.sh> <out> <state dir> <helper> <reconcile cmd> <wait>" >&2
    exit 2
fi
src="$1"; out="$2"; state="$3"; helper="$4"; recon="$5"; wait="$6"
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
cat "$cur" > "$out"
chmod +x "$out"
