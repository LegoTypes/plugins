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
[ -f "$WGCT_TEST_DIR/sleep" ] && sleep "$(cat "$WGCT_TEST_DIR/sleep")"
cat "$WGCT_TEST_DIR/out"
exit "$(cat "$WGCT_TEST_DIR/rc" 2>/dev/null || echo 0)"
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
"$W" configure_routes & b=$!
wait $a; ra=$?
wait $b; rb=$?
rm -f "$T/sleep"
check "16 two concurrent route sets both complete (the second waits) and leave one record line" '[ $ra = 0 ] && [ $rb = 0 ] && [ "$(grep -c . "$REC")" = 1 ]'
check "17 nothing holds routes.lock once the section returned" '[ "$(fstat "$WGCT_STATE_DIR/routes.lock" | grep -c .)" -le 1 ]'
/usr/local/bin/flock "$WGCT_STATE_DIR/routes.lock" sleep 15 & h=$!
sleep 1
"$W" configure_routes; rt=$?
kill $h 2>/dev/null
check "18 a wait past 10 s gives up with exit 75" '[ $rt = 75 ]'

echo "routes: $pass/$((pass + fail)) passed"
[ "$fail" = 0 ]
