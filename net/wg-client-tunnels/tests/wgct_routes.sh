#!/bin/sh

# Copyright (C) 2026 cayossarian (Bill Flood)
# All rights reserved.
# BSD 2-Clause License
#
# Shell tests for wgct.sh's route set (spec 2026-09-28 sections 3.4.1-3.4.2). Root on the disposable test VM
# only (vm_selftest.sh), never on a firewall: it creates lo91 and lo92 and routes documentation-range monitors.
# A stub helper stands in for gateway_config.php and a temp directory for the state directory, so the copy
# under test runs without the installed plugin; the VM's own reconcile never touches routes it did not record.
#
# Usage: wgct_routes.sh /path/to/wgct.sh

set -u
W="$1"
T=$(mktemp -d /tmp/wgct-routes.XXXXXX)
export WGCT_STATE_DIR="$T/state" WGCT_CONFIG_HELPER="$T/helper" WGCT_TEST_DIR="$T"
mkdir -p "$WGCT_STATE_DIR"
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
REC="$WGCT_STATE_DIR/active_gateways"
for i in 91 92; do
    ifconfig lo$i create 2>/dev/null
    ifconfig lo$i inet6 -ifdisabled up
done
cleanup() {
    for m in $M1 $M3 $M4; do route -q -n delete -6 -host $m 2>/dev/null; done
    for i in 91 92; do ifconfig lo$i destroy 2>/dev/null; done
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
    fi
}
dev_of() {
    route -n get -inet6 "$1" 2>/dev/null | awk -v ip="$1" '$1 == "destination:" { d = $2 } $1 == "interface:" { i = $2 } END { if (d == ip) print i }'
}
say() { printf '%s\n' "$@" > "$T/out"; }
line() { printf 'route|%s|fd00::%s:1/128|fd00::%s:2|t%s|t%s-ipv6|%s' "$1" "$2" "$2" "$2" "$2" "$3"; }
run() { "$W" configure_routes; }

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
check "10 a foreign host route to the monitor is left alone, noted once" '[ "$(dev_of $M4)" = lo92 ] && [ "$(grep -c "^$M4|lo92\$" "$WGCT_STATE_DIR/foreign_routes")" = 1 ]'
route -q -n delete -6 -host $M4
say 'state|on' "$(line lo91 91 $M1)"; run
cp "$REC" "$T/rec.before"
echo 1 > "$T/rc"; say 'state|on'; run
check "11 a failed helper (exit 1) changes nothing" '[ "$(dev_of $M1)" = lo91 ] && cmp -s "$REC" "$T/rec.before"'
rm -f "$T/rc"; say 'PHP Notice: junk' 'state|on'; run
check "12 output not starting with a state line changes nothing and is noted" '[ "$(dev_of $M1)" = lo91 ] && cmp -s "$REC" "$T/rec.before" && [ -s "$WGCT_STATE_DIR/parse_error" ]'
say 'state|off'; run
check "13 state|off (plugin or IPv6 routes off) changes no route and keeps the record" '[ "$(dev_of $M1)" = lo91 ] && cmp -s "$REC" "$T/rec.before"'
"$W" stop
check "14 stop deletes the monitor route, the record and the running flag" '[ -z "$(dev_of $M1)" ] && [ ! -f "$REC" ] && [ ! -f "$WGCT_STATE_DIR/enabled" ]'
ifconfig lo91 inet6 fd00::91:1/128 alias 2>/dev/null
route -q -n add -6 fd00::91:2 -iface lo91
printf 'lo91|fd00::91:1/128|fd00::91:2|t91\n' > "$REC"
"$W" stop
check "15 stop reads a four-field record written by the previous version" '! netstat -rn -f inet6 | grep -q "fd00::91:2.*lo91" && [ ! -f "$REC" ]'
say 'state|on' "$(line lo91 91 $M1)"; echo 2 > "$T/sleep"
"$W" configure_routes & a=$!
sleep 1
"$W" configure_routes & b=$!
wait $a; ra=$?
wait $b; rb=$?
rm -f "$T/sleep"
check "16 two concurrent route sets both complete, never overlap (the second waits), and leave one record line" '[ $ra = 0 ] && [ $rb = 0 ] && [ ! -e "$T/overlap" ] && [ "$(grep -c . "$REC")" = 1 ]'
touch "$T/daemon.on"
run
rm -f "$T/daemon.on"
check "17 a daemon the section started does not inherit routes.lock" '[ "$(fstat "$WGCT_STATE_DIR/routes.lock" | grep -c .)" -le 1 ]'
kill "$(cat "$T/daemon")" 2>/dev/null
/usr/local/bin/flock "$WGCT_STATE_DIR/routes.lock" sleep 15 & h=$!
sleep 1
"$W" configure_routes; rt=$?
kill $h 2>/dev/null
check "18 a wait past 10 s gives up with exit 75" '[ $rt = 75 ]'

# a failing route command: a copy of wgct.sh whose route and logger are stand-ins (route fails for a host route
# while $T/route.fail exists, and, like route(8), prints nothing under -q), so the log can be read back
"$W" stop
sed -e "s#/sbin/route #$T/route #g" -e "s#logger -t#$T/logger -t#g" "$W" > "$T/wgct_stub.sh"
chmod +x "$T/wgct_stub.sh"
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
cat > "$T/logger" <<'EOF'
#!/bin/sh
shift 2
echo "$*" >> "$WGCT_TEST_DIR/log"
EOF
chmod +x "$T/route" "$T/logger"
: > "$T/log"
touch "$T/route.fail"
say 'state|on' "$(line lo91 91 $M4)"; "$T/wgct_stub.sh" configure_routes; "$T/wgct_stub.sh" configure_routes
check "19 a failing route add is logged once, never as an added route, and noted" '[ -z "$(dev_of $M4)" ] && [ "$(grep -c "route add for monitor $M4 on lo91 failed: .*Network is unreachable" "$T/log")" = 1 ] && ! grep -q "added monitor route" "$T/log" && grep -qxF "$M4|lo91" "$WGCT_STATE_DIR/route_failures"'
rm -f "$T/route.fail"; "$T/wgct_stub.sh" configure_routes
check "20 once it succeeds the route is added, logged, and the failure note cleared" '[ "$(dev_of $M4)" = lo91 ] && grep -q "added monitor route $M4 via lo91" "$T/log" && ! grep -qxF "$M4|lo91" "$WGCT_STATE_DIR/route_failures"'
: > "$T/log"; touch "$T/route.fail"
"$T/wgct_stub.sh" stop
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
export WGCT_RECONCILE_CMD="$T/recon"
: > "$T/runs"
t0=$(date +%s)
"$W" request_reconcile; "$W" request_reconcile; "$W" request_reconcile
t1=$(date +%s)
check "24 request_reconcile returns without waiting for the reconcile" '[ $((t1 - t0)) -le 1 ]'
sleep 6
check "25 a burst of requests runs the reconcile once or twice, never once per request" '[ "$(grep -c . "$T/runs")" -ge 1 ] && [ "$(grep -c . "$T/runs")" -le 2 ]'
: > "$T/runs"
"$W" request_reconcile; sleep 1; "$W" request_reconcile
sleep 6
check "26 a request made while a reconcile runs gets its own run after it" '[ "$(grep -c . "$T/runs")" = 2 ]'
check "27 no waiter is left running" '! pgrep -f "_reconcile_queued" > /dev/null'
: > "$T/log"; : > "$T/runs"
/usr/local/bin/flock "$WGCT_STATE_DIR/reconcile.lock" sleep 4 & h=$!
sleep 1
WGCT_RECONCILE_WAIT=1 "$T/wgct_stub.sh" request_reconcile
sleep 5
kill $h 2>/dev/null
check "28 a queued reconcile that waits out its time logs that it gave up, and does not run" 'grep -q "queued reconcile skipped" "$T/log" && [ ! -s "$T/runs" ]'
unset WGCT_RECONCILE_CMD

echo "routes: $pass/$((pass + fail)) passed"
[ "$fail" = 0 ]
