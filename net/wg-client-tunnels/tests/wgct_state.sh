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
# The mirror cases (spec section 3.2, lock bullets) run the copy's health_mirror.php with --dry, which still
# takes health.lock and writes the skip markers but changes no gateway. The VM's own cron may run the mirror
# inside a window; a holder keeps health.lock for the whole case, so a cron tick skips too, and the dedup marker
# makes the log carry one skip line whichever process wrote it. Counts are of lines after a recorded marker.
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

stop_holder() {
    [ -n "$HOLDER" ] && kill "$HOLDER" > /dev/null 2>&1
    HOLDER=""
}

restore() {
    rm -rf "$RUN" "$DB"
    [ -d "$T/run" ] && mv "$T/run" "$RUN"
    [ -d "$T/db" ] && mv "$T/db" "$DB"
    rm -rf "$T"
}
HOLDER=""
trap 'stop_holder; restore' EXIT

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

# (a) and (b) the health mirror's tick lock: three skipped runs log one skip, the first run after the holder
# ends logs one resume
MIRROR="$(dirname "$SRC")/health_mirror.php"
WGLOG=/var/log/wireguard/latest.log
mkdir -p -m 700 "$RUN"
rm -f "$RUN/health.skipped"
$PHP -d log_errors=0 -r '$f = fopen("'"$RUN"'/health.lock", "c"); flock($f, LOCK_EX); sleep(20);' &
HOLDER=$!
sleep 1
mark=$(wc -l < "$WGLOG")
slow=0
for i in 1 2 3; do
    t0=$(date +%s)
    $PHP -d log_errors=0 "$MIRROR" --dry > /dev/null 2>&1
    rc=$?
    [ "$rc" -eq 0 ] || slow=1
    [ $(($(date +%s) - t0)) -le 1 ] || slow=1
done
sleep 1
check "three runs against a held health.lock each exit 0 within a second" "$slow" 0
check "three skipped runs log one skip line" "$(tail -n +$((mark + 1)) "$WGLOG" | grep -c 'wgct-health.*tick skipped: another run holds health.lock')" 1
check "the skip leaves its marker" "$([ -f "$RUN/health.skipped" ] && echo yes || echo no)" yes
stop_holder
sleep 1
mark=$(wc -l < "$WGLOG")
$PHP -d log_errors=0 "$MIRROR" --dry > /dev/null 2>&1
$PHP -d log_errors=0 "$MIRROR" --dry > /dev/null 2>&1
sleep 1
check "the first run after the holder ends logs one resume line, the next none" "$(tail -n +$((mark + 1)) "$WGLOG" | grep -c 'wgct-health.*health resumed')" 1
check "the resume removes the marker" "$([ -f "$RUN/health.skipped" ] && echo yes || echo no)" no
check "no /tmp/wgct_health.lock is created by a run" "$(rm -f /tmp/wgct_health.lock; $PHP -d log_errors=0 "$MIRROR" --dry > /dev/null 2>&1; [ -e /tmp/wgct_health.lock ] && echo yes || echo no)" no

# (f) a health.lock that cannot be opened (a directory stands where the file belongs) ends the tick quietly:
# exit 0, one log line across two runs, no output (a PHP fatal would print and, outside this test's log_errors=0, reach the crash reporter); the lock is a file again afterwards
rm -f "$RUN/health.lock" "$RUN/health.skipped" "$RUN/health.unopenable"
mkdir "$RUN/health.lock"
mark=$(wc -l < "$WGLOG")
$PHP -d log_errors=0 "$MIRROR" --dry > "$T/open1.out" 2>&1
rc1=$?
$PHP -d log_errors=0 "$MIRROR" --dry > "$T/open2.out" 2>&1
rc2=$?
sleep 1
check "two runs against an unopenable health.lock exit 0" "$rc1$rc2" 00
check "they print nothing (no PHP fatal)" "$(cat "$T/open1.out" "$T/open2.out")" ""
check "they log one line naming the unopenable lock" "$(tail -n +$((mark + 1)) "$WGLOG" | grep -c 'wgct-health.*tick skipped: health.lock cannot be opened')" 1
rmdir "$RUN/health.lock"
mark=$(wc -l < "$WGLOG")
$PHP -d log_errors=0 "$MIRROR" --dry > /dev/null 2>&1
sleep 1
check "the first run with an openable lock logs one resume line" "$(tail -n +$((mark + 1)) "$WGLOG" | grep -c 'wgct-health.*health.lock opens again')" 1

# F4 (spec section 3.4): core's /tmp files are read for the devices core has and in the shape core writes.
TUNNEL="$(dirname "$SRC")/tunnel.php"
PLANTED=""
cleanup_planted() {
    for f in $PLANTED; do /bin/rm -f "$f"; done
    PLANTED=""
}
trap 'stop_holder; cleanup_planted; restore' EXIT

# (a) a prefix file for a name that is not one of core's devices does not refuse an IPv6 monitor: the old glob read it
priv=$(wg genkey)
peer=$(wg genkey | wg pubkey)
CFG="[Interface]
PrivateKey = $priv
Address = 198.51.100.50/32, fd00:db8:50::2/128

[Peer]
PublicKey = $peer
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 192.0.2.50:51820
" $PHP -d log_errors=0 -r 'echo json_encode(["name" => "f4probe", "wan" => "WAN_B", "monitor" => "198.51.100.51", "monitor6" => "2001:db8:ffff::51", "mtu" => 1380, "config" => getenv("CFG")]);' > "$T/f4.json"
PLANTED="/tmp/zz_prefixv6"
echo "2000::/3" > /tmp/zz_prefixv6
$PHP -d log_errors=0 "$TUNNEL" --json --dry create < "$T/f4.json" > "$T/f4a.out" 2>&1
cleanup_planted
check "a dry Create with an IPv6 monitor is not refused by /tmp/zz_prefixv6 (not a device of core)" "$(grep -c '"monitor6"' "$T/f4a.out")" 0
check "that dry Create reports no error" "$(grep -c '"ok":true.*"errors":\[\]' "$T/f4a.out")" 1

# (b) a rules.debug.error not owned by root, with a future mtime, leaves freshness at 'current'
FRESH="$(dirname "$SRC")/freshness.php"
[ -f /tmp/rules.debug.error ] && mv /tmp/rules.debug.error "$T/rules.debug.error.orig"
$PHP -d log_errors=0 "$FRESH" --dry > "$T/f4b0.out" 2>&1
printf 'pfctl: planted\n' > /tmp/rules.debug.error
chown nobody /tmp/rules.debug.error
touch -t 203012312359 /tmp/rules.debug.error
$PHP -d log_errors=0 "$FRESH" --dry > "$T/f4b.out" 2>&1
/bin/rm -f /tmp/rules.debug.error
[ -f "$T/rules.debug.error.orig" ] && mv "$T/rules.debug.error.orig" /tmp/rules.debug.error
check "freshness --dry is at 'current' before the planted error file" "$(grep -c 'reason: current' "$T/f4b0.out")" 1
check "a nobody-owned rules.debug.error with a future mtime leaves freshness at 'current'" "$(grep -c 'reason: current' "$T/f4b.out")" 1

# F8 (spec section 3.8): a symlink at the hand-off path is never written through. A monitor change on the
# dummy tunnel hands off the old monitor's kernel host route; the save happens before the hand-off, so the
# error is reported with the new monitor already stored, and a second edit puts the old one back. The symlink
# itself may be gone by then (the failed edit still runs the routes step, which consumes hand-off files), so
# only its target is checked.
UUID=$($PHP -d log_errors=0 "$TUNNEL" --json list | $PHP -r '$d = json_decode(stream_get_contents(STDIN), true); foreach ($d["tunnels"] as $t) { if ($t["name"] === "rehearse") { echo $t["uuid"]; } }')
OLDMON=$($PHP -d log_errors=0 "$TUNNEL" --json list | $PHP -r '$d = json_decode(stream_get_contents(STDIN), true); foreach ($d["tunnels"] as $t) { if ($t["name"] === "rehearse") { echo $t["monitor"]; } }')
GWUUID=$($PHP -d log_errors=0 -r '$x = simplexml_load_file("/conf/config.xml"); foreach ($x->OPNsense->Gateways->gateway_item as $g) { if ((string)$g->name === "rehearse") { echo $g["uuid"]; } }')
if [ -n "$UUID" ] && [ -n "$OLDMON" ] && [ -n "$GWUUID" ]; then
    TODO=$($PHP -d log_errors=0 -r 'require_once "'"$LIB"'/apply.php"; echo "/tmp/delete_route_" . wgct_route_todo_key($argv[1], $argv[2]) . ".todo";' "$GWUUID" "$OLDMON")
    echo "harmless" > "$T/f8.target"
    ln -s "$T/f8.target" "$TODO"
    PLANTED="$TODO"
    NEWMON=198.51.100.3
    [ "$OLDMON" = "$NEWMON" ] && NEWMON=198.51.100.4
    echo "{\"uuid\":\"$UUID\",\"monitor\":\"$NEWMON\"}" | $PHP -d log_errors=0 "$TUNNEL" --json edit > "$T/f8.out" 2>&1
    check "the edit reports the route hand-off file that already exists" "$(grep -c 'route hand-off file already exists' "$T/f8.out")" 1
    check "the symlink's target is unchanged" "$(cat "$T/f8.target")" harmless
    cleanup_planted
    echo "{\"uuid\":\"$UUID\",\"monitor\":\"$OLDMON\"}" | $PHP -d log_errors=0 "$TUNNEL" --json edit > "$T/f8r.out" 2>&1
    check "the second edit restores the dummy tunnel's monitor" "$($PHP -d log_errors=0 "$TUNNEL" --json list | $PHP -r '$d = json_decode(stream_get_contents(STDIN), true); foreach ($d["tunnels"] as $t) { if ($t["name"] === "rehearse") { echo $t["monitor"]; } }')" "$OLDMON"
else
    check "the dummy tunnel rehearse and its gateway are found for the F8 case" "uuid=$UUID monitor=$OLDMON gateway=$GWUUID" "found"
fi

# R28: an entry script whose plugin library cannot be loaded ends quietly: exit 0, no output, one line per state in
# the WireGuard log, nothing in PHP's error log (core's GUI crash reporter reads it). They run from a copy of the
# script directory without lib/, never the installed one; the copy's entry.php keeps its markers in a directory
# of this test's own, so the VM's cron runs never see them. php runs with the production ini here (log_errors on).
PHPLOG=$($PHP -r 'echo ini_get("error_log");')
E="$T/entry"
mkdir -p "$E/run"
cp -Rp "$(dirname "$SRC")" "$E/scripts"
rm -rf "$E/scripts/lib"
check "the copy's entry.php names the run directory once" "$(grep -c "'/var/run/wgclienttunnels'" "$E/scripts/entry.php" 2>/dev/null)" 1
sed -i '' -e "s#'/var/run/wgclienttunnels'#'$E/run'#" "$E/scripts/entry.php" 2>/dev/null
phplog_size() { stat -f %z "$PHPLOG" 2>/dev/null || echo 0; }
entry_runs() {
    # entry_runs <label> <script> [args]: two runs, their exit codes, output and log lines after a mark
    label=$1; script=$2; shift 2
    emark=$(wc -l < "$WGLOG")
    $PHP "$E/scripts/$script" "$@" > "$E/$label.1.out" 2> "$E/$label.1.err"; erc1=$?
    $PHP "$E/scripts/$script" "$@" > "$E/$label.2.out" 2> "$E/$label.2.err"; erc2=$?
    sleep 1
    elines=$(tail -n +$((emark + 1)) "$WGLOG" | grep -c "\[wgct-[a-z]*\] $script cannot load the plugin library")
}
before=$(phplog_size)
for script in health_mirror.php prime.php gateway_config.php default_guard.php core_contract.php monitor_repair.php freshness.php; do
    entry_runs "${script%.php}" "$script"
    check "$script without lib/: two runs exit 0" "$erc1$erc2" 00
    check "$script without lib/: nothing on stdout or stderr" "$(cat "$E/${script%.php}".*.out "$E/${script%.php}".*.err)" ""
    check "$script without lib/: one log line across two runs" "$elines" 1
done
entry_runs tunnel tunnel.php --json list
check "tunnel.php --json list without lib/: two runs exit 1 (the command failed), nothing on stderr" "$erc1$erc2$(cat "$E"/tunnel.*.err)" 11
check "tunnel.php --json list without lib/: a JSON failure naming the missing file" "$(cat "$E/tunnel.1.out")" '{"ok":false,"errors":["plugin library file cli.php missing"]}'
check "tunnel.php without lib/: one log line across two runs" "$elines" 1
entry_runs release tunnel.php --json release-holds
check "tunnel.php --json release-holds without lib/: two runs exit 0 (the package removal must complete), nothing on stderr" "$erc1$erc2$(cat "$E"/release.*.err)" 00
check "tunnel.php --json release-holds without lib/: the same JSON failure" "$(cat "$E/release.1.out")" '{"ok":false,"errors":["plugin library file cli.php missing"]}'
mkdir "$E/scripts/lib"
for f in tunnels.php selftest.php; do cp -p "$LIB/$f" "$E/scripts/lib/"; done
entry_runs guard default_guard.php
check "default_guard.php with lib/addr.php missing: exit 0, no output, one new line naming addr.php" "$erc1$erc2$(cat "$E"/guard.*.out "$E"/guard.*.err)$(tail -n +$((emark + 1)) "$WGLOG" | grep -c 'default_guard.php cannot load the plugin library (plugin library file addr.php missing)')" 001
check "PHP's error log ($PHPLOG) did not grow" "$(phplog_size)" "$before"
rm -rf "$E/scripts/lib"
cp -Rp "$LIB" "$E/scripts/lib"
emark=$(wc -l < "$WGLOG")
$PHP "$E/scripts/core_contract.php" > /dev/null 2>&1
$PHP "$E/scripts/core_contract.php" > /dev/null 2>&1
sleep 1
check "the first run with the library back logs one recovery line and drops its marker" "$(tail -n +$((emark + 1)) "$WGLOG" | grep -c 'core_contract.php loads the plugin library again')$(ls "$E/run" | grep -c '^core_contract')" 10
rm -rf "$E"

echo "state: $PASS/$((PASS + FAIL)) passed"
[ "$FAIL" -eq 0 ]
