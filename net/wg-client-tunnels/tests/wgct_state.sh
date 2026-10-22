#!/bin/sh

# Copyright (C) 2026 cayossarian
# All rights reserved.
# BSD 2-Clause License
#
# VM tests for the plugin's state directories and the one reader every trusted state file goes through
# (spec 2026-10-20 section 3.2, convention C3). Root on the disposable test VM only (vm_selftest.sh), never
# on a firewall: it moves /var/run/wgclienttunnels and /var/db/wgclienttunnels aside, runs a real reconcile
# and plants files in the new run directory. At exit it removes what the test made and moves the originals
# back. It runs the copy of the scripts vm_selftest.sh puts in /tmp/wgct, so the code under test is the
# working tree, not the installed package; the installed package supplies only what wgct.sh calls through
# its own fixed paths. The VM's minute cron also reconciles, so the windows are kept to one php process.
#
# Usage: wgct_state.sh /path/to/wgct.sh   (its lib/ directory beside it)

set -u
SRC="$1"
LIB="$(dirname "$SRC")/lib"
RUN=/var/run/wgclienttunnels
DB=/var/db/wgclienttunnels
PHP=/usr/local/bin/php
T=$(mktemp -d /tmp/wgct-state.XXXXXX)
PASS=0
FAIL=0

check() {
    if [ "$2" = "$3" ]; then
        PASS=$((PASS + 1))
        echo "[PASS] $1"
    else
        FAIL=$((FAIL + 1))
        echo "[FAIL] $1 (expected '$3', got '$2')"
    fi
}

restore() {
    rm -rf "$RUN" "$DB"
    [ -d "$T/run" ] && mv "$T/run" "$RUN"
    [ -d "$T/db" ] && mv "$T/db" "$DB"
    rm -rf "$T"
}
trap restore EXIT

[ -d "$RUN" ] && mv "$RUN" "$T/run"
[ -d "$DB" ] && mv "$DB" "$T/db"

# (c) both directories are 0700 after a reconcile from a clean state, whatever the caller's umask
(umask 022; /bin/sh "$SRC" reconcile > /dev/null 2>&1)
check "run directory is 700 after reconcile from a removed state" "$(stat -f %Lp "$RUN" 2>/dev/null)" 700
check "db directory is 700 after reconcile from a removed state" "$(stat -f %Lp "$DB" 2>/dev/null)" 700
check "run directory is owned by root" "$(stat -f %Su "$RUN" 2>/dev/null)" root

# an existing 0755 directory (the previous version's mode) is tightened by the next reconcile
chmod 755 "$RUN" "$DB"
(umask 022; /bin/sh "$SRC" reconcile > /dev/null 2>&1)
check "run directory 755 from an older version is 700 after reconcile" "$(stat -f %Lp "$RUN" 2>/dev/null)" 700
check "db directory 755 from an older version is 700 after reconcile" "$(stat -f %Lp "$DB" 2>/dev/null)" 700

# (d) a planted symlink and (e) a non-root owner read as absent; a root-owned regular file reads as its record
cat > "$T/probe.php" <<PHPEOF
<?php
require_once '$LIB/render.php';
\$file = WGCT_OBSERVED_FILE;
\$record = ['checksum' => '0xaa', 'labels_hash' => 'h1', 'missing_labels' => 0];
\$real = '$T/real.json';
file_put_contents(\$real, json_encode(\$record));
\$show = fn (?array \$r): string => \$r === null ? 'absent' : (\$r === \$record ? 'record' : 'other');
@unlink(\$file);
copy(\$real, \$file);
echo 'regular=', \$show(wgct_read_observed()), "\n";
chown(\$file, 'nobody');
echo 'nobody=', \$show(wgct_read_observed()), "\n";
unlink(\$file);
symlink(\$real, \$file);
echo 'symlink=', \$show(wgct_read_observed()), "\n";
unlink(\$file);
echo 'missing=', \$show(wgct_read_observed()), "\n";
PHPEOF
$PHP -d log_errors=0 "$T/probe.php" > "$T/probe.out" 2>&1
check "a root-owned regular observed.json reads as its record" "$(grep '^regular=' "$T/probe.out")" "regular=record"
check "an observed.json owned by nobody reads as absent" "$(grep '^nobody=' "$T/probe.out")" "nobody=absent"
check "a symlink at observed.json reads as absent" "$(grep '^symlink=' "$T/probe.out")" "symlink=absent"
check "no observed.json reads as absent" "$(grep '^missing=' "$T/probe.out")" "missing=absent"

echo "state: $PASS/$((PASS + FAIL)) passed"
[ "$FAIL" -eq 0 ]
