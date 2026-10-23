#!/bin/sh

# Copyright (C) 2026 cayossarian
# All rights reserved.
# BSD 2-Clause License
#
# Quiet points for the VM tests (sourced: . wgct_settle.sh). Root on the disposable test VM only, never on a
# firewall. They poll the condition a test needs and never sleep a fixed time.
#
#   in_flight             exit 0 while a mirror tick, prime, reconcile or routing configure runs (their processes;
#                         an offset round still asleep is not one)
#   settle [MAX]          wait (at most MAX s, default 90) until nothing above runs
#   cron_quiesce          stop cron and wait (at most 90 s) until no round of the plugin's cron is left and nothing
#                         runs. An offset mirror round is `sh -c "sleep N && php health_mirror.php; php prime.php"`:
#                         while its sleep runs it has run nothing, so the sleep is ended rather than waited out (up to
#                         45 s); the round then skips its tick (`&&`) and runs only its prime, which is waited out.
#                         Prints the seconds waited.
#   reconcile_drained [MAX] wait (at most MAX s, default 150) until no reconcile is queued (wgct.sh's
#                         reconcile.pending, a `_reconcile_wait` waiter) and nothing runs: what a config save's syshook
#                         set off has ended
#   gw_window NAME        NAME's settle window in seconds: its time_period, or 60 (core's dpinger default) when unset;
#                         the plugin's settle guard uses the same window
#   gw_settled NAME [MAX] wait (at most MAX s, default the window plus 90) until NAME's dpinger socket is older than its
#                         settle window plus 2 s and its reading has data: the plugin's settle guard has passed and
#                         dpinger's average holds only probes sent since its start
#   gw_quiet [MAX]        wait (at most MAX s, default 120) until WAN_B reads up and is not forced down in config.xml,
#                         every monitored gateway's status is the one core's gateway watcher last acted on (no alarm
#                         pending), core has run the config hooks of every config save, no reconcile is queued and
#                         nothing above runs. A save reaches the plugin's hook through core's own path (syslog,
#                         configctl, configd, trigger_config_changed_events.py, rc.syshook config); core records the
#                         newest save it ran hooks for in /conf/event_config_changed.json. Core never raises the
#                         event of a save made while configd was stopped, and its trigger skips one while it runs,
#                         so when a save's hooks have not run and nothing runs, gw_quiet drives core's trigger itself
#                         (configctl system event config_changed), as the next save would: it runs the hooks of every
#                         save not yet run, so a delivery still on its way finds nothing left to run.
#   ws_hooks              "done" or "due", the newest /conf/backup save's stamp and the one core last ran hooks for
# Each wait returns 1 when it times out, after printing "      | " lines with what it waited on (what still runs, the
# gateway state); the caller's check turns that into a FAIL.
# Their own variables are named ws_*, so a test's are left alone.

WS_PHP="/usr/local/bin/php -d log_errors=0"
WS_PENDING='^/usr/local/bin/php .*(health_mirror|prime)[.]php|wgct[.]sh (reconcile|_reconcile)|rc[.]routing_configure|trigger_config_changed_events|rc[.]syshook'
# the plugin's cron rounds, as cron runs them (cron.d/wgclienttunnels)
WS_CRON='^/bin/sh -c (sleep [0-9]+ && )?/usr/local/(bin/php /usr/local/)?opnsense/scripts/OPNsense/WGClientTunnels/'

in_flight() {
    pgrep -f "$WS_PENDING" > /dev/null
}

# ws_running: what still runs, as evidence
ws_running() {
    pgrep -lf "$WS_PENDING|$WS_CRON|_reconcile_wait" | sed 's/^/      |   running: /'
}

settle() {
    ws_end=$(($(date +%s) + ${1:-90}))
    while in_flight; do
        if [ "$(date +%s)" -ge "$ws_end" ]; then
            echo "      | settle: still running after ${1:-90} s"
            ws_running
            return 1
        fi
        sleep 0.1
    done
}

cron_quiesce() {
    service cron stop > /dev/null 2>&1
    ws_t0=$(date +%s)
    while :; do
        ws_rounds=$(pgrep -f "$WS_CRON")
        for ws_p in $ws_rounds; do
            for ws_c in $(pgrep -P "$ws_p" -x sleep); do
                kill "$ws_c" 2> /dev/null
            done
        done
        [ -z "$ws_rounds" ] && ! in_flight && break
        if [ $(($(date +%s) - ws_t0)) -ge 90 ]; then
            echo "90; cron's runs still under way:"
            ws_running
            return 1
        fi
        sleep 0.1
    done
    echo $(($(date +%s) - ws_t0))
}

reconcile_drained() {
    ws_end=$(($(date +%s) + ${1:-150}))
    while [ -e /var/run/wgclienttunnels/reconcile.pending ] || pgrep -f 'wgct[.]sh _reconcile_(wait|queued)' > /dev/null \
        || in_flight; do
        if [ "$(date +%s)" -ge "$ws_end" ]; then
            echo "      | reconcile_drained: a reconcile is still queued or running after ${1:-150} s" \
                "(reconcile.pending $([ -e /var/run/wgclienttunnels/reconcile.pending ] && echo present || echo absent))"
            ws_running
            return 1
        fi
        sleep 0.1
    done
}

gw_window() {
    $WS_PHP -r '$t = 0; foreach (simplexml_load_file("/conf/config.xml")->OPNsense->Gateways->gateway_item as $g) {
        if ((string)$g->name === $argv[1]) { $t = (int)(string)$g->time_period; } } echo $t > 0 ? $t : 60, "\n";' "$1"
}

gw_settled() {
    ws_w=$(gw_window "$1")
    ws_end=$(($(date +%s) + ${2:-$((ws_w + 90))}))
    while [ "$(date +%s)" -lt "$ws_end" ]; do
        $WS_PHP -r 'require_once "config.inc"; require_once "util.inc"; require_once "interfaces.inc";
            require_once "plugins.inc.d/dpinger.inc";
            $m = @filemtime("/var/run/dpinger_" . $argv[1] . ".sock");
            $loss = dpinger_status()[$argv[1]]["loss"] ?? "~";
            exit($m !== false && time() - $m >= (int)$argv[2] + 2 && $loss !== "~" ? 0 : 1);' "$1" "$ws_w" && return 0
        sleep 0.5
    done
    echo "      | gw_settled: $1's dpinger has not settled past its ${ws_w} s window"
    ls -l "/var/run/dpinger_$1.sock" 2>&1 | sed 's/^/      |   /'
    return 1
}

ws_hooks() {
    $WS_PHP -r '
        /* the stamps as core reads them: a backup file name config-<stamp>.xml, last_processed_stamp rounded to 4 places */
        $done = json_decode((string)@file_get_contents("/conf/event_config_changed.json"), true);
        $last = round((float)($done["last_processed_stamp"] ?? 0), 4);
        $newest = 0.0;
        foreach (glob("/conf/backup/config-*.xml") ?: [] as $f) {
            if (preg_match("/config-([0-9]+(\\.[0-9]+)?)\\.xml$/", $f, $m)) {
                $newest = max($newest, round((float)str_replace("_", "", $m[1]), 4));
            }
        }
        printf("%s %.4f %.4f\n", $newest > $last ? "due" : "done", $newest, $last);'
}

# ws_gateways: "quiet" when WAN_B reads up and is not forced down in config.xml, and the gateway watcher's last state
# of every monitored gateway is its status now; else one line naming what is not
ws_gateways() {
    $WS_PHP -r 'require_once "config.inc"; require_once "util.inc"; require_once "interfaces.inc";
        require_once "plugins.inc.d/dpinger.inc";
        $now = dpinger_status();
        $seen = @unserialize((string)@file_get_contents("/tmp/gateways.status"));
        $seen = is_array($seen) ? $seen : [];
        $why = [];
        if (($now["WAN_B"]["status"] ?? "absent") !== "none") {
            $why[] = "WAN_B reads " . ($now["WAN_B"]["status"] ?? "absent");
        }
        $forced = "absent";
        foreach (simplexml_load_file("/conf/config.xml")->OPNsense->Gateways->gateway_item as $g) {
            if ((string)$g->name === "WAN_B") {
                $forced = (string)$g->force_down;
            }
        }
        if ($forced !== "0" && $forced !== "") {
            $why[] = $forced === "absent" ? "no WAN_B gateway in config.xml" : "WAN_B is forced down in config.xml";
        }
        if (file_exists("/var/run/wgclienttunnels/reconcile.pending")) {
            $why[] = "a reconcile is queued (reconcile.pending)";
        }
        foreach ($now as $name => $r) {
            if ($r["loss"] !== "~" && ($seen[$name] ?? "") !== $r["status"]) {
                $why[] = "$name reads {$r["status"]}, the watcher last acted on " . ($seen[$name] ?? "nothing");
            }
        }
        echo $why === [] ? "quiet" : implode("; ", $why), "\n";'
}

gw_quiet() {
    ws_max=${1:-120}
    ws_end=$(($(date +%s) + ws_max))
    while [ "$(date +%s)" -lt "$ws_end" ]; do
        if ! in_flight; then
            ws_h=$(ws_hooks)
            if [ "${ws_h%% *}" = due ]; then
                /usr/local/sbin/configctl system event config_changed > /dev/null 2>&1
            elif [ "$(ws_gateways)" = quiet ] && ! in_flight && [ "$(ws_hooks | cut -d' ' -f1)" = done ]; then
                return 0
            fi
        fi
        sleep 0.25
    done
    echo "      | gw_quiet: not quiet within ${ws_max} s: $(ws_gateways); config hooks $(ws_hooks)"
    $WS_PHP /usr/local/opnsense/scripts/routes/gateway_status.php | $WS_PHP -r '
        foreach (json_decode(stream_get_contents(STDIN), true) as $n => $g) {
            echo "      |   $n: {$g["status"]} loss {$g["loss"]} delay {$g["delay"]} monitor {$g["monitor"]}\n";
        }'
    ws_running
    return 1
}
