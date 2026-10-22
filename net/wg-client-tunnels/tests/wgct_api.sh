#!/bin/sh

# Copyright (C) 2026 cayossarian
# All rights reserved.
# BSD 2-Clause License
#
# VM tests for the plugin's API guards and the one-at-a-time MTU measurement (spec 2026-10-20 section 3.3,
# convention C4). Root on the disposable test VM only (vm_selftest.sh), never on a firewall.
#
# It creates two throw-away users through core's own User model and gives each an API key: one with access
# to the plugin page plus core's user-config-readonly privilege (what throwReadOnly() checks), and a control
# with the page privilege only. It calls the installed plugin's API with curl against the GUI on this
# machine, so the controllers under test are the ones the GUI serves (vm_overlay.sh puts the working tree
# there); the CLI case runs the copy of the scripts vm_selftest.sh puts in /tmp/wgct. At exit, even on
# failure, it removes both users, and with them their keys.
#
# Case 1: the read-only user's measure_mtu POST is refused. core's throwReadOnly() raises a UserException, which
#         core's API front controller answers as HTTP 500 with the message "User NAME denied for write access
#         (user-config-readonly set)" (UserBaseException::getHttpCode() is 500), so "refused" means that pair.
# Case 2: its dry=1 POSTs to edit, remove, adopt and the sentinel are refused, a reconfigure POST too, and
#         configd's log shows no plugin action in that window. The control user's dry sentinel preview answers
#         200 and does appear in the log, so the check can see what it looks for.
# Case 3: two concurrent measure-mtu runs give one measurement and one refusal.
# Case 4: the control user's settings/set POST naming `managed` and `held` (spec section 3.5, convention C1) is
#         saved with no validation message and changes neither the settings node (its persisted_at stamp aside,
#         which every save rewrites) nor the engine node: the settings model has no such fields. Should a change
#         get through, the old values are posted back so the VM keeps its managed list.
#
# The dummy tunnel `rehearse` (bound to the second VM WAN, endpoint 192.0.2.10) provides the uuid; the first
# VM WAN is never touched.
#
# Usage: wgct_api.sh /path/to/wgct.sh   (tunnel.php beside it)

set -u
SRC="$1"
TUNNEL="$(dirname "$SRC")/tunnel.php"
PHP="/usr/local/bin/php -d log_errors=0"
API=https://127.0.0.1/api/wgclienttunnels
LOG=/var/log/configd/latest.log
PAGE_PRIV=page-vpn-wgclienttunnels
RO_USER=wgct-api-readonly
CTL_USER=wgct-api-control
WAN=WAN_B
ENDPOINT=192.0.2.10
T=$(mktemp -d /tmp/wgct-api.XXXXXX)
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

cat > "$T/user.php" <<'PHPEOF'
<?php
require_once 'config.inc';
require_once '/usr/local/opnsense/mvc/script/load_phalcon.php';

use OPNsense\Auth\User;
use OPNsense\Core\Config;

/* user.php create NAME PRIVS => "key:secret"; user.php delete NAME */
[, $mode, $name] = $argv;
Config::getInstance()->lock();
$model = new User();
if ($mode === 'create') {
    $user = $model->user->Add();
    $user->name = $name;
    $user->scope = 'user';
    $user->password = $model->generatePasswordHash(bin2hex(random_bytes(24)));
    $user->priv = $argv[3];
    $key = $user->apikeys->add();
    foreach ($model->performValidation() as $msg) {
        fwrite(STDERR, $msg->getMessage() . "\n");
        Config::getInstance()->unlock();
        exit(1);
    }
    $model->serializeToConfig(false, true);
    Config::getInstance()->save();
    echo $key['key'], ':', $key['secret'], "\n";
    exit(0);
}
foreach ($model->user->iterateItems() as $uuid => $node) {
    if ((string)$node->name === $name) {
        $model->user->del($uuid);
    }
}
$model->serializeToConfig(false, true);
Config::getInstance()->save();
PHPEOF

remove_users() {
    for u in "$RO_USER" "$CTL_USER"; do
        $PHP "$T/user.php" delete "$u" > /dev/null 2>&1
        configctl auth sync user "$u" > /dev/null 2>&1
    done
}

cleanup() {
    remove_users
    rm -rf "$T"
}
trap cleanup EXIT

# a leftover from an interrupted run goes first
remove_users

make_user() {
    $PHP "$T/user.php" create "$1" "$2" || return 1
    configctl auth sync user "$1" > /dev/null 2>&1
}

RO_CRED=$(make_user "$RO_USER" "$PAGE_PRIV,user-config-readonly")
CTL_CRED=$(make_user "$CTL_USER" "$PAGE_PRIV")
[ -n "$RO_CRED" ] && [ -n "$CTL_CRED" ] || { echo "[FAIL] the test users could not be created"; exit 1; }

UUID=$($PHP "$TUNNEL" --json list | $PHP -r '
    $j = json_decode(stream_get_contents(STDIN), true);
    foreach ($j["tunnels"] as $t) { if ($t["name"] === "rehearse") { echo $t["uuid"]; } }')
[ -n "$UUID" ] || { echo "[FAIL] the rehearse tunnel is missing (vm_base.sh)"; exit 1; }

# call CREDENTIALS PATH [CURL ARGS]: prints the HTTP status, the body goes to $T/body
call() {
    cred="$1"; path="$2"; shift 2
    curl -sk -m 150 -o "$T/body" -w '%{http_code}' -u "$cred" -X POST "$@" "$API/$path"
}

# refused CREDENTIALS PATH [CURL ARGS]: "refused" when core's throwReadOnly() answered (core's UserException is
# HTTP 500 with the message "User NAME denied for write access (user-config-readonly set)"), else "answered HTTP n"
refused() {
    code=$(call "$@")
    if [ "$code" = 500 ] && grep -q 'denied for write access (user-config-readonly set)' "$T/body"; then
        echo refused
    else
        echo "answered HTTP $code"
    fi
}

# plugin actions configd logged: the log lines that name one of the actions with a side effect or a preview
actions() {
    grep -c -E 'previewing the (removal|adoption|no-default)|ensuring the no-default|removing WireGuard upstream|adopting WireGuard instance|measuring the tunnel MTU|applying WireGuard upstream tunnel [0-9a-f]|rebinding WireGuard|reconfiguring WireGuard upstream tunnel IPv6 routes' "$LOG"
}

# the control user may preview, and the preview shows in configd's log
before=$(actions)
check "control user (page privilege only): dry sentinel preview answers 200" \
    "$(call "$CTL_CRED" service/sentinel -d dry=1)" 200
check "control user: that preview is in configd's log" "$(( $(actions) - before ))" 1

# case 1
check "read-only user: measure_mtu POST is refused" \
    "$(refused "$RO_CRED" tunnels/measure_mtu -d "wan=$WAN" -d "endpoint=$ENDPOINT")" refused

# case 2
before=$(actions)
for what in "tunnels/edit/$UUID" "tunnels/remove/$UUID" "tunnels/adopt/$UUID" service/sentinel; do
    check "read-only user: dry=1 POST to $(echo "$what" | sed "s/$UUID/<uuid>/") is refused" \
        "$(refused "$RO_CRED" "$what" -d dry=1)" refused
done
check "read-only user: a reconfigure POST is refused" "$(refused "$RO_CRED" service/reconfigure)" refused
check "read-only user: no plugin action in configd's log" "$(( $(actions) - before ))" 0

# case 3: two measurements at once; the loser is refused while the winner pings (about 3 s)
$PHP "$TUNNEL" --json measure-mtu "$WAN" "$ENDPOINT" > "$T/m1" &
P1=$!
$PHP "$TUNNEL" --json measure-mtu "$WAN" "$ENDPOINT" > "$T/m2" &
P2=$!
wait "$P1" "$P2"
oks=0
refusals=0
for f in "$T/m1" "$T/m2"; do
    case "$(cat "$f")" in
        *'"ok":true'*) oks=$((oks + 1)) ;;
        *'another MTU measurement is running'*) refusals=$((refusals + 1)) ;;
    esac
done
check "two concurrent measure-mtu: one measurement" "$oks" 1
check "two concurrent measure-mtu: one refusal" "$refusals" 1
# the lock is free again afterwards
$PHP "$TUNNEL" --json measure-mtu "$WAN" "$ENDPOINT" > "$T/m3"
check "a measurement after both: runs" "$(grep -c '"ok":true' "$T/m3")" 1

# case 4: the plugin's two config nodes, the settings node without its persisted_at stamp
nodes() {
    $PHP -r '
        $x = simplexml_load_file("/conf/config.xml");
        $s = $x->OPNsense->WGClientTunnels;
        unset($s["persisted_at"]);
        echo $s->asXML(), "\n", (string)$x->OPNsense->WGClientTunnelsEngine->asXML(), "\n";'
}
# the settings node's raw value of FIELD, as a 3.7_1 config holds it
raw_field() {
    $PHP -r 'echo (string)simplexml_load_file("/conf/config.xml")->OPNsense->WGClientTunnels->{$argv[1]};' "$1"
}
FOREIGN=00000000-0000-4000-8000-0000000000f5
OLD_MANAGED=$(raw_field managed)
OLD_HELD=$(raw_field held)
nodes > "$T/nodes.before"
check "control user: a settings/set POST naming managed and held answers 200" \
    "$(call "$CTL_CRED" settings/set -d "wgclienttunnels[managed]=$FOREIGN" -d "wgclienttunnels[held]=$FOREIGN")" 200
check "control user: that POST is saved with no validation message" "$(cat "$T/body")" '{"result":"saved"}'
nodes > "$T/nodes.after"
if cmp -s "$T/nodes.before" "$T/nodes.after"; then
    same=unchanged
else
    same=changed
    call "$CTL_CRED" settings/set -d "wgclienttunnels[managed]=$OLD_MANAGED" -d "wgclienttunnels[held]=$OLD_HELD" > /dev/null
fi
check "control user: that POST leaves the settings node and the engine node as they were" "$same" unchanged

echo "api: $PASS/$((PASS + FAIL)) passed"
[ "$FAIL" -eq 0 ]
