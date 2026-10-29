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
# Shell tests for wgct.sh's route set. Root on the disposable test VM
# only (vm_selftest.sh), never on a firewall: it creates lo9, lo91 and lo92 and routes documentation-range monitors.
# Production wgct.sh honours no environment override, so the tests run a substituted copy that wgct_stub.sh
# writes: a stub helper stands in for gateway_config.php, a temp directory for the state directory and a stub
# command for the queued reconcile. A second copy sends every PHP run to a recorder, so a test can read which
# scripts ran. The VM's own reconcile never touches routes it did not record.
#
# Usage: wgct_routes.sh /path/to/wgct.sh

set -u
. "$(dirname "$0")/wgct_exact.sh"
SRC="$1"
T=$(mktemp -d /tmp/wgct-routes.XXXXXX)
export WGCT_TEST_DIR="$T"
STATE="$T/state"
mkdir -p "$STATE"
W="$T/wgct.sh"
sh "$(dirname "$0")/wgct_stub.sh" "$SRC" "$W" "$STATE" "$T/helper" "$T/recon" 120 || exit 1
cat > "$T/helper" <<'EOF'
#!/bin/sh
D="$WGCT_TEST_DIR"
[ -e "$D/inside" ] && touch "$D/overlap"
touch "$D/inside"
[ -f "$D/sleep" ] && sleep "$(cat "$D/sleep")"
[ -f "$D/daemon.on" ] && { sleep 30 </dev/null >/dev/null 2>&1 & echo $! > "$D/daemon"; }
cat "$D/out"
rm -f "$D/inside"
exit "$(cat "$D/rc" 2>/dev/null || echo 0)"
EOF
chmod +x "$T/helper"

M1=2001:db8:ffff::a1
M3=2001:db8:ffff::a3
M4=2001:db8:ffff::a4
REC="$STATE/active_gateways"
for i in 9 91 92; do
    ifconfig lo$i create 2>/dev/null
    ifconfig lo$i inet6 -ifdisabled up
done
# the gateway of the kernel cases' IPv4 route
ifconfig lo91 inet 192.0.2.91/32 alias
cleanup() {
    route -q -n delete -inet 198.51.100.77/32 2>/dev/null
    route -q -n delete -inet6 2001:db8:77::77/128 2>/dev/null
    ifconfig lo91 inet6 fd00::91:77 -alias 2>/dev/null
    ifconfig lo91 inet 192.0.2.91 -alias 2>/dev/null
    for m in $M1 $M3 $M4; do route -q -n delete -6 -host $m 2>/dev/null; done
    for r in fd00::9:23 fd00::92:20; do route -q -n delete -6 -host $r 2>/dev/null; done
    for i in 9 91 92; do ifconfig lo$i destroy 2>/dev/null; done
    rm -rf "$T"
}
trap cleanup EXIT

pass=0
fail=0
check() {
    if eval "$2"; then
        pass=$((pass + 1)); echo "[PASS] routes: $1"
    else
        fail=$((fail + 1)); echo "[FAIL] routes: $1"
        return 1
    fi
}
say() { printf '%s\n' "$@" > "$T/out"; }
# until COND: wait (at most 30 s) until the shell condition COND holds
until_true() {
    n=0
    while [ "$n" -lt 300 ] && ! eval "$1"; do
        sleep 0.1
        n=$((n + 1))
    done
}
# drained: no queued reconcile of this test's copies waits or runs (at most 30 s)
drained() { until_true '! pgrep -f "$T/.*_reconcile_(wait|queued)" > /dev/null'; }
line() { printf 'route|%s|fd00::%s:1/128|fd00::%s:2|t%s|t%s-ipv6|%s' "$1" "$2" "$2" "$2" "$2" "$3"; }
run() { "$W" configure_routes; }
# the logger stand-in: a copy of wgct.sh that uses it writes its log lines to $T/log
cat > "$T/logger" <<'EOF'
#!/bin/sh
shift 2
echo "$*" >> "$WGCT_TEST_DIR/log"
EOF
chmod +x "$T/logger"

# exact matches: a decoy that merely extends the wanted address or device does not count
route -q -n add -6 -host fd00::92:20 -iface lo92
say 'state|on' "$(line lo92 92 '')"
check "a decoy route: routes_status reads route_exists false for a next hop it only extends" '"$W" routes_status | grep -qF "\"interface\":\"lo92\",\"ipv6_address\":\"fd00::92:1/128\",\"ipv6_gateway\":\"fd00::92:2\",\"ipv4_gateway\":\"t92\",\"route_exists\":false"'
run
check "a route to a next hop that extends the wanted one does not count" '[ "$(dev_of fd00::92:2)" = lo92 ]'
ifconfig lo91 inet6 fd00::91:10/128 alias
say 'state|on' "$(line lo91 91 '')"; run
check "an address that extends the wanted one does not count as present" 'inet6_on lo91 fd00::91:1'
route -q -n add -6 -host fd00::9:23 -iface lo91
say 'state|on' "$(line lo9 9 '')"; run
check "a route on a device whose name extends the wanted one does not count" '[ "$(dev_of fd00::9:2)" = lo9 ]'
printf 'lo91|fd00::91:1/128|fd00::9:2|t91|\n' > "$REC"
sed -e "s#logger -t#$T/logger -t#g" "$W" > "$T/wgct_fakes.sh"
chmod +x "$T/wgct_fakes.sh"
: > "$T/log"
"$T/wgct_fakes.sh" stop
check "stop leaves a next-hop route on another device alone, and does not say it removed it" '[ "$(dev_of fd00::9:2)" = lo9 ] && grep -qF "] removed fd00::91:1/128 from lo91" "$T/log" && ! grep -q "route fd00::9:2" "$T/log"'
ifconfig lo91 inet6 fd00::91:1/128 alias
sed -e "s#logger -t#$T/logger -t#g" "$W" > "$T/wgct_fakes.sh"
chmod +x "$T/wgct_fakes.sh"
: > "$T/log"
say 'state|on' "$(line lo91 91 '')"; "$T/wgct_fakes.sh" configure_routes; "$T/wgct_fakes.sh" configure_routes
check "a canonical address already present is not added again" '! grep -q "added fd00::91:1/128" "$T/log"'
"$W" stop
say 'state|on' 'route|lo9|fd00::9:1/128|fe80::9:2%lo9|t9|t9-ipv6|'; run
check "a zoned next hop is added, found by its zone, and reads route_exists true" '[ "$(dev_of fe80::9:2%lo9)" = lo9 ] && "$W" routes_status | grep -qF "\"ipv6_gateway\":\"fe80::9:2%lo9\",\"ipv4_gateway\":\"t9\",\"route_exists\":true"'
"$W" stop
check "stop removes a zoned next hop" '[ -z "$(dev_of fe80::9:2%lo9)" ]'
for r in fd00::92:2 fd00::92:20 fd00::9:2 fd00::9:23 fd00::91:2; do route -q -n delete -6 -host $r 2>/dev/null; done
ifconfig lo91 inet6 fd00::91:10 -alias
ifconfig lo92 inet6 fd00::92:1 -alias
ifconfig lo9 inet6 fd00::9:1 -alias
rm -f "$T/log"


say 'state|on' "$(line lo91 91 $M1)"; run
check "1 a wanted monitor route is added via its device" '[ "$(dev_of $M1)" = lo91 ]'
check "2 it is recorded with the next hop" 'grep -qxF "lo91|fd00::91:1/128|fd00::91:2|t91|$M1" "$REC"'
run
check "3 an unchanged run keeps the route and one record line" '[ "$(dev_of $M1)" = lo91 ] && [ "$(grep -c . "$REC")" = 1 ]'
say 'state|on' 'keep|lo91'; run
check "4 a blocked (keep) tunnel keeps its monitor route and record line" '[ "$(dev_of $M1)" = lo91 ] && grep -q "^lo91|" "$REC"'
say 'state|on' "$(line lo91 91 $M3)"; run
check "5 a changed monitor: the old route deleted, the new one added" '[ -z "$(dev_of $M1)" ] && [ "$(dev_of $M3)" = lo91 ]'
say 'state|on' "$(line lo92 92 $M3)"; run
check "6 a monitor moved to another tunnel in one run: deleted, then added" '[ "$(dev_of $M3)" = lo92 ]'
say 'state|on' "$(line lo92 92 '')"; run
check "7 a removed monitor: its route deleted" '[ -z "$(dev_of $M3)" ]'
say 'state|on' "$(line lo91 91 $M1)"; run; say 'state|on'; run
check "8 a tunnel that left the managed list: its monitor route deleted" '[ -z "$(dev_of $M1)" ]'
say 'state|on' "$(line lo91 91 $M1)"; run
route -q -n change -6 -host $M1 -iface lo92
say 'state|on'; run
check "9 a recorded route that no longer leaves by its device is left alone" '[ "$(dev_of $M1)" = lo92 ]'
route -q -n delete -6 -host $M1
route -q -n add -6 -host $M4 -iface lo92
say 'state|on' "$(line lo91 91 $M4)"; run; run
check "10 a foreign host route to the monitor is left alone, noted once" '[ "$(dev_of $M4)" = lo92 ] && [ "$(grep -c "^$M4|lo92\$" "$STATE/foreign_routes")" = 1 ]'
route -q -n delete -6 -host $M4
say 'state|on' "$(line lo91 91 $M1)"; run
cp "$REC" "$T/rec.before"
echo 1 > "$T/rc"; say 'state|on'; run
check "11 a failed helper (exit 1) changes nothing" '[ "$(dev_of $M1)" = lo91 ] && cmp -s "$REC" "$T/rec.before"'
rm -f "$T/rc"; say 'PHP Notice: junk' 'state|on'; run
check "12 output not starting with a state line changes nothing and is noted" '[ "$(dev_of $M1)" = lo91 ] && cmp -s "$REC" "$T/rec.before" && [ -s "$STATE/parse_error" ]'
say 'state|off'; run
check "13 state|off (plugin or IPv6 routes off) changes no route and keeps the record" '[ "$(dev_of $M1)" = lo91 ] && cmp -s "$REC" "$T/rec.before"'
"$W" stop
check "14 stop deletes the monitor route, the record and the running flag" '[ -z "$(dev_of $M1)" ] && [ ! -f "$REC" ] && [ ! -f "$STATE/enabled" ]'
ifconfig lo91 inet6 fd00::91:1/128 alias 2>/dev/null
route -q -n add -6 fd00::91:2 -iface lo91
printf 'lo91|fd00::91:1/128|fd00::91:2|t91\n' > "$REC"
"$W" stop
check "15 stop reads a four-field record written by the previous version" '[ -z "$(dev_of fd00::91:2)" ] && [ ! -f "$REC" ]'
say 'state|on' "$(line lo91 91 $M1)"; echo 2 > "$T/sleep"
"$W" configure_routes & a=$!
until_true '[ -e "$T/inside" ]'
"$W" configure_routes & b=$!
wait $a; ra=$?
wait $b; rb=$?
rm -f "$T/sleep"
check "16 two concurrent route sets both complete, never overlap (the second waits), and leave one record line" '[ $ra = 0 ] && [ $rb = 0 ] && [ ! -e "$T/overlap" ] && [ "$(grep -c . "$REC")" = 1 ]'
touch "$T/daemon.on"
run
rm -f "$T/daemon.on"
check "17 a daemon the section started does not inherit routes.lock" '[ "$(fstat "$STATE/routes.lock" | grep -c .)" -le 1 ]'
kill "$(cat "$T/daemon")" 2>/dev/null
/usr/local/bin/flock "$STATE/routes.lock" sleep 15 & h=$!
until_true '! /usr/local/bin/flock -n "$STATE/routes.lock" true'
"$W" configure_routes; rt=$?
kill $h 2>/dev/null
check "18 a wait past 10 s gives up with exit 75" '[ $rt = 75 ]'

# a failing route command: a copy of wgct.sh whose route and logger are stand-ins (route fails for a host route
# while $T/route.fail exists, and, like route(8), prints nothing under -q), so the log can be read back
"$W" stop
sed -e "s#/sbin/route #$T/route #g" -e "s#logger -t#$T/logger -t#g" "$W" > "$T/wgct_fakes.sh"
chmod +x "$T/wgct_fakes.sh"
cat > "$T/route" <<'EOF'
#!/bin/sh
case " $* " in
*" add "* | *" delete "*)
    if [ -f "$WGCT_TEST_DIR/route.fail" ]; then
        case " $* " in *" -q "*) ;; *) echo "route: writing to routing socket: Network is unreachable" ;; esac
        exit 1
    fi
    ;;
esac
exec /sbin/route "$@"
EOF
chmod +x "$T/route"
: > "$T/log"
touch "$T/route.fail"
say 'state|on' "$(line lo91 91 $M4)"; "$T/wgct_fakes.sh" configure_routes; "$T/wgct_fakes.sh" configure_routes
check "19 a failing route add is logged once, never as an added route, and noted" '[ -z "$(dev_of $M4)" ] && [ "$(grep -c "route add for monitor $M4 on lo91 failed: .*Network is unreachable" "$T/log")" = 1 ] && ! grep -q "added monitor route" "$T/log" && grep -qxF "$M4|lo91" "$STATE/route_failures"'
rm -f "$T/route.fail"; "$T/wgct_fakes.sh" configure_routes
check "20 once it succeeds the route is added, logged, and the failure note cleared" '[ "$(dev_of $M4)" = lo91 ] && grep -q "added monitor route $M4 via lo91" "$T/log" && ! grep -qxF "$M4|lo91" "$STATE/route_failures"'
: > "$T/log"; touch "$T/route.fail"
"$T/wgct_fakes.sh" stop
check "21 a failing route delete in stop is logged as a failure, not as a removed monitor route" '[ "$(dev_of $M4)" = lo91 ] && grep -q "route delete for monitor $M4 on lo91 failed: .*Network is unreachable" "$T/log" && ! grep -q "monitor route $M4" "$T/log"'
rm -f "$T/route.fail"

cat > "$T/json_iface" <<'EOF'
#!/usr/local/bin/php
<?php
$j = json_decode(stream_get_contents(STDIN), true);
echo is_array($j) ? ($j['gateways'][0]['interface'] ?? 'no-gateway') : 'not-json';
EOF
chmod +x "$T/json_iface"
say 'state|on' "$(line lo91 91 $M1)"; run
check "22 status prints only core's running line" '[ "$("$W" status | grep -c .)" = 1 ] && [ "$("$W" status)" = "wgclienttunnels is running" ]'
check "23 routes_status prints one JSON object naming the tunnel" '[ "$("$W" routes_status | "$T/json_iface")" = lo91 ]'

cat > "$T/recon" <<'EOF'
#!/bin/sh
echo run >> "$WGCT_TEST_DIR/runs"
sleep 2
EOF
chmod +x "$T/recon"
: > "$T/runs"
t0=$(date +%s)
"$W" request_reconcile; "$W" request_reconcile; "$W" request_reconcile
t1=$(date +%s)
check "24 request_reconcile returns without waiting for the reconcile" '[ $((t1 - t0)) -le 1 ]'
drained
check "25 a burst of requests runs the reconcile once or twice, never once per request" '[ "$(grep -c . "$T/runs")" -ge 1 ] && [ "$(grep -c . "$T/runs")" -le 2 ]'
: > "$T/runs"
"$W" request_reconcile; until_true '[ -s "$T/runs" ]'; "$W" request_reconcile
drained
check "26 a request made while a reconcile runs gets its own run after it" '[ "$(grep -c . "$T/runs")" = 2 ]'
check "27 no waiter is left running" '! pgrep -f "_reconcile_queued" > /dev/null'
: > "$T/log"; : > "$T/runs"
sh "$(dirname "$0")/wgct_stub.sh" "$SRC" "$T/wgct_wait1.sh" "$STATE" "$T/helper" "$T/recon" 1 || exit 1
sed -e "s#logger -t#$T/logger -t#g" "$T/wgct_wait1.sh" > "$T/wgct_fakes.sh"
/usr/local/bin/flock "$STATE/reconcile.lock" sleep 4 & h=$!
until_true '! /usr/local/bin/flock -n "$STATE/reconcile.lock" true'
"$T/wgct_fakes.sh" request_reconcile
drained
kill $h 2>/dev/null
check "28 a queued reconcile that waits out its time logs that it gave up, and does not run" 'grep -q "queued reconcile skipped" "$T/log" && [ ! -s "$T/runs" ]'
mkdir -p "$STATE/db"
touch "$STATE/db/footprint.json" "$STATE/fallback.json" "$STATE/fallback.logged"
"$W" stop
check "29 stop removes the footprint, the fallback record and its log marker" '[ ! -e "$STATE/db/footprint.json" ] && [ ! -e "$STATE/fallback.json" ] && [ ! -e "$STATE/fallback.logged" ]'

# the plugin's stored data waiting for its migration: the route set changes nothing, said once per state
sed -e "s#logger -t#$T/logger -t#g" "$W" > "$T/wgct_fakes.sh"
chmod +x "$T/wgct_fakes.sh"
: > "$T/log"
say 'state|on' "$(line lo91 91 $M1)"; "$T/wgct_fakes.sh" configure_routes
cp "$REC" "$T/rec.before"
say 'state|pending' "$(line lo91 91 $M1)"; "$T/wgct_fakes.sh" configure_routes; "$T/wgct_fakes.sh" configure_routes
check "30 state|pending (a migration pending) removes no route, keeps the record and logs one refusal" '[ "$(dev_of $M1)" = lo91 ] && cmp -s "$REC" "$T/rec.before" && [ "$(grep -c "route set refused: the plugin'\''s stored data is not migrated to this version yet" "$T/log")" = 1 ]'
say 'state|pending' "$(line lo91 91 $M3)"; "$T/wgct_fakes.sh" configure_routes
check "31 state|pending adds and deletes nothing either" '[ -z "$(dev_of $M3)" ] && [ "$(dev_of $M1)" = lo91 ] && cmp -s "$REC" "$T/rec.before"'
say 'state|on' "$(line lo91 91 $M1)"; "$T/wgct_fakes.sh" configure_routes; "$T/wgct_fakes.sh" configure_routes
check "32 once migrated the route set runs again, said once" '[ "$(dev_of $M1)" = lo91 ] && [ "$(grep -c "route set runs again" "$T/log")" = 1 ] && [ ! -e "$STATE/routes.awaiting-migration" ]'
"$W" stop

# the default-route guard deletes by the gateway it judged: the kernel must refuse a delete that names another
# gateway, so a default route core replaced after the guard read it stays. A host route with an IP gateway, the
# shape the default route has, stands in for it.
host4_gw() { route -n get -inet "$1" 2>/dev/null | awk -v ip="$1" '$1 == "destination:" { d = $2 } $1 == "gateway:" { g = $2 } END { if (d == ip) print g }'; }
kernel_evidence() { echo "      | $1; route get 198.51.100.77: $(route -n get -inet 198.51.100.77 2>&1 | tr '\n' ' ')"; }
out=$(route -n add -inet 198.51.100.77/32 192.0.2.91 2>&1)
# a failed setup is its own FAIL, and the delete cases do not run on it
if check "kernel: setup" '[ "$(host4_gw 198.51.100.77)" = 192.0.2.91 ]'; then
    out=$(route -n delete -inet 198.51.100.77/32 192.0.2.254 2>&1); rd=$?
    check "kernel: a delete that names another gateway leaves the route" '[ "$rd" -ne 0 ] && [ "$(host4_gw 198.51.100.77)" = 192.0.2.91 ]' \
        || kernel_evidence "delete exit $rd: $out"
    out=$(route -n delete -inet 198.51.100.77/32 192.0.2.91 2>&1); rd=$?
    check "kernel: a delete that names the route's own gateway removes it" '[ "$rd" = 0 ] && [ -z "$(host4_gw 198.51.100.77)" ]' \
        || kernel_evidence "delete exit $rd: $out"
else
    kernel_evidence "add: $out"
    echo "[SKIP] routes: kernel: the two delete cases, on a failed setup"
fi
# the same for IPv6, which the guard deletes too: a route via a ULA gateway on lo91
host6_gw() { route -n get -inet6 "$1" 2>/dev/null | awk -v ip="$1" '$1 == "destination:" { d = $2 } $1 == "gateway:" { g = $2 } END { if (d == ip) print g }'; }
kernel6_evidence() { echo "      | $1; route get 2001:db8:77::77: $(route -n get -inet6 2001:db8:77::77 2>&1 | tr '\n' ' ')"; }
ifconfig lo91 inet6 fd00::91:77/128 alias
out=$(route -n add -inet6 2001:db8:77::77/128 fd00::91:77 2>&1)
if check "kernel: IPv6 setup" '[ "$(host6_gw 2001:db8:77::77)" = fd00::91:77 ]'; then
    out=$(route -n delete -inet6 2001:db8:77::77/128 fd00::91:78 2>&1); rd=$?
    check "kernel: an IPv6 delete that names another gateway leaves the route" '[ "$rd" -ne 0 ] && [ "$(host6_gw 2001:db8:77::77)" = fd00::91:77 ]' \
        || kernel6_evidence "delete exit $rd: $out"
    out=$(route -n delete -inet6 2001:db8:77::77/128 fd00::91:77 2>&1); rd=$?
    check "kernel: an IPv6 delete that names the route's own gateway removes it" '[ "$rd" = 0 ] && [ -z "$(host6_gw 2001:db8:77::77)" ]' \
        || kernel6_evidence "delete exit $rd: $out"
else
    kernel6_evidence "add: $out"
    echo "[SKIP] routes: kernel: the two IPv6 delete cases, on a failed setup"
fi
ifconfig lo91 inet6 fd00::91:77 -alias

# the PHP recorder: logs each PHP run's arguments to php.log and its umask to php.umask, and exits with the number
# in php.rc.<script> (the last argument ending in .php) when that file exists, else 0
cat > "$T/php" <<'EOF'
#!/bin/sh
echo "$*" >> "$WGCT_TEST_DIR/php.log"
umask >> "$WGCT_TEST_DIR/php.umask"
s=""
for a in "$@"; do
    case "$a" in *.php) s="${a##*/}" ;; esac
done
[ -n "$s" ] && [ -f "$WGCT_TEST_DIR/php.rc.$s" ] && exit "$(cat "$WGCT_TEST_DIR/php.rc.$s")"
exit 0
EOF
chmod +x "$T/php"
W2="$T/wgct_php.sh"
sh "$(dirname "$0")/wgct_stub.sh" "$SRC" "$W2" "$STATE" "$T/helper" "$T/recon" 120 "$T/php" || exit 1
# the scripts the recorder saw, in order, by file name
php_runs() { awk '{ n = split($NF, a, "/"); printf "%s ", a[n] }' "$T/php.log"; }
# stop's mark cleared, as the boot that empties /var/run clears it, so core's hooks run the route set again
unstop() { rm -f "$STATE/stopped" "$STATE/stopped.logged"; }
say 'state|on' "$(line lo91 91 $M1)"
: > "$T/php.log"
"$W2" reconcile
check "reconcile: the recorder sees the guard, freshness and the contract" '[ "$(php_runs)" = "default_guard.php freshness.php core_contract.php " ]' \
    || echo "      | php.log: $(tr '\n' ';' < "$T/php.log")"

# core's hooks: only the route set runs before the hook returns; the rest is queued. The mark left above by the
# waiter that gave up is cleared first, so only the hook's own can satisfy the check.
"$W2" stop
unstop
rm -f "$STATE/reconcile.pending"
: > "$T/php.log"; : > "$T/runs"
say 'state|on' "$(line lo91 91 $M1)"
"$W2" hook
check "hook: only the route set runs before it returns" '[ "$(dev_of $M1)" = lo91 ] && [ ! -s "$T/php.log" ] && { [ -e "$STATE/reconcile.pending" ] || pgrep -f "$T/.*_reconcile_wait" > /dev/null; }' \
    || echo "      | monitor route via '$(dev_of $M1)'; php.log: $(tr '\n' ';' < "$T/php.log"); pending: $(ls "$STATE/reconcile.pending" 2>&1)"
drained
check "hook: the rest runs from the queue" '[ "$(grep -c . "$T/runs")" = 1 ]' || echo "      | queued runs: $(grep -c . "$T/runs")"
# a queue that cannot start (daemon fails): the hook says so, keeps the mark for the minute reconcile, runs nothing
# else inline and returns the route set's status
"$W2" stop
unstop
rm -f "$STATE/reconcile.pending"
sed -e "s#/usr/sbin/daemon #/usr/bin/false #" -e "s#logger -t#$T/logger -t#g" "$W2" > "$T/wgct_nodaemon.sh"
chmod +x "$T/wgct_nodaemon.sh"
: > "$T/php.log"; : > "$T/log"
say 'state|on' "$(line lo91 91 $M1)"
"$T/wgct_nodaemon.sh" hook; rh=$?
check "hook: a queue that cannot start is logged, its mark kept, and the route set's status returned" '[ "$rh" = 0 ] && [ "$(dev_of $M1)" = lo91 ] && grep -qxF "[wgct-routes] queued reconcile could not be started (exit 1); the minute reconcile runs it" "$T/log" && [ -e "$STATE/reconcile.pending" ] && [ ! -s "$T/php.log" ]' \
    || echo "      | exit $rh; monitor route via '$(dev_of $M1)'; log: $(tr '\n' ';' < "$T/log"); php.log: $(tr '\n' ';' < "$T/php.log"); pending: $(ls "$STATE/reconcile.pending" 2>&1)"
drained
rm -f "$STATE/reconcile.pending"
"$W2" stop
unstop

# the service: running once a route set has run on the enabled plugin, IPv6 routes off included, so core's Apply
# reloads it; a Stop holds against core's hooks and the reconcile until the next start, Apply or restart (or the boot
# that empties /var/run), said once per stop, while the reconcile's policy steps run on
sed -e "s#logger -t#$T/logger -t#g" "$W2" > "$T/wgct_rec.sh"
chmod +x "$T/wgct_rec.sh"
"$W2" stop
say 'state|off'; "$W2" start
check "service: with IPv6 routes off, start leaves the plugin running" '[ "$("$W2" status)" = "wgclienttunnels is running" ]' \
    || echo "      | status '$("$W2" status)'; state: $(ls "$STATE" | tr '\n' ' ')"
say 'state|disabled'; "$W2" configure_routes
r_disabled=$("$W2" status)
"$W2" stop; "$W2" start
check "service: the plugin disabled leaves the running flag as it is, and does not set it" \
    '[ "$r_disabled" = "wgclienttunnels is running" ] && [ "$("$W2" status)" = "wgclienttunnels is not running" ]' \
    || echo "      | after a reload while disabled '$r_disabled'; after stop and start while disabled '$("$W2" status)'"
say 'state|on' "$(line lo91 91 $M1)"; "$W2" start
: > "$T/log"; : > "$T/php.log"; : > "$T/runs"
"$T/wgct_rec.sh" stop
"$T/wgct_rec.sh" hook; drained
"$T/wgct_rec.sh" reconcile; "$T/wgct_rec.sh" reconcile --repair
check "service: after a stop, a hook and a reconcile add nothing back, the plugin stays stopped, and that is logged once" \
    '[ -z "$(dev_of $M1)" ] && ! inet6_on lo91 fd00::91:1 && [ ! -f "$REC" ] && [ "$("$W2" status)" = "wgclienttunnels is not running" ] && [ "$(grep -c "route set skipped: the service is stopped" "$T/log")" = 1 ]' \
    || echo "      | monitor route via '$(dev_of $M1)'; record: $(cat "$REC" 2>&1); status '$("$W2" status)'; log: $(tr '\n' ';' < "$T/log")"
check "service: while stopped, the hook still queues the reconcile, and the reconcile's guard, freshness and contract run" \
    '[ "$(grep -c . "$T/runs")" = 1 ] && [ "$(php_runs)" = "default_guard.php freshness.php core_contract.php default_guard.php freshness.php core_contract.php monitor_repair.php " ]' \
    || echo "      | queued runs: $(grep -c . "$T/runs"); php.log: $(tr '\n' ';' < "$T/php.log")"
"$T/wgct_rec.sh" start
check "service: start clears the stop: the route set runs and the plugin is running" \
    '[ "$(dev_of $M1)" = lo91 ] && [ "$("$W2" status)" = "wgclienttunnels is running" ] && [ ! -e "$STATE/stopped" ]' \
    || echo "      | monitor route via '$(dev_of $M1)'; status '$("$W2" status)'; state: $(ls "$STATE" | tr '\n' ' ')"
"$T/wgct_rec.sh" stop; "$T/wgct_rec.sh" configure_routes; r_reload=$(dev_of $M1)
"$T/wgct_rec.sh" stop; "$T/wgct_rec.sh" restart; r_restart=$(dev_of $M1)
check "service: configure_routes (core's Apply) and restart clear the stop too" '[ "$r_reload" = lo91 ] && [ "$r_restart" = lo91 ]' \
    || echo "      | monitor route after configure_routes via '$r_reload', after restart via '$r_restart'"
"$T/wgct_rec.sh" stop; "$T/wgct_rec.sh" hook; drained
check "service: a later stop is logged again, once" '[ "$(grep -c "route set skipped: the service is stopped" "$T/log")" = 2 ] && [ -z "$(dev_of $M1)" ]' \
    || echo "      | log: $(tr '\n' ';' < "$T/log"); monitor route via '$(dev_of $M1)'"
rm -f "$STATE/reconcile.pending"
unstop

# cron's tick: the mirror, then the prime whatever the mirror's exit, and the tick exits with the prime's status
: > "$T/php.log"
echo 1 > "$T/php.rc.health_mirror.php"
"$W2" tick; rt=$?
check "tick: the mirror runs, then the prime" '[ "$(php_runs)" = "health_mirror.php prime.php " ] && [ "$rt" = 0 ]' \
    || echo "      | exit $rt; php.log: $(tr '\n' ';' < "$T/php.log")"
rm -f "$T/php.rc.health_mirror.php"
: > "$T/php.log"
echo 3 > "$T/php.rc.prime.php"
"$W2" tick; rt=$?
check "tick: it exits with the prime's status" '[ "$rt" = 3 ] && [ "$(php_runs)" = "health_mirror.php prime.php " ]' \
    || echo "      | exit $rt; php.log: $(tr '\n' ';' < "$T/php.log")"
rm -f "$T/php.rc.prime.php"
# configd's tunnel actions: tunnel.php sees only its own arguments
: > "$T/php.log"
"$W2" tunnel --json list
check "tunnel: tunnel.php gets only its own arguments" '[ "$(grep -c . "$T/php.log")" = 1 ] && grep -qxF "/usr/local/opnsense/scripts/OPNsense/WGClientTunnels/tunnel.php --json list" "$T/php.log"' \
    || echo "      | php.log: $(tr '\n' ';' < "$T/php.log")"
# the PHP that cron and configd start runs under their umask (Config::save()'s backups keep their modes), while
# wgct.sh's own files stay root's alone
: > "$T/php.umask"
(umask 022; "$W2" tick)
u_tick=$(sort -u "$T/php.umask" | tr '\n' ' ')
: > "$T/php.umask"
(umask 027; "$W2" tunnel --json list)
u_tunnel=$(sort -u "$T/php.umask" | tr '\n' ' ')
check "umask: tick and tunnel run PHP under the caller's umask" '[ "$u_tick" = "0022 " ] && [ "$u_tunnel" = "0027 " ]' \
    || echo "      | tick under 022: '$u_tick'; tunnel under 027: '$u_tunnel'"

echo "routes: $pass/$((pass + fail)) passed"
[ "$fail" = 0 ]
