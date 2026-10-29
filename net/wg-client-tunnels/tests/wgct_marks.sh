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
# Marker-bounded windows of core's WireGuard and configd logs, for the VM tests (sourced: . wgct_marks.sh). Root on
# the disposable test VM only, never on a firewall. A test logs a marker line before a case; a count is of the lines
# between that marker and a closing one logged after the case and waited for. The plugin, configd and the markers
# all log through syslog's socket in order, so every line logged before the closing marker is written before it,
# whatever syslog's latency.
#
#   wgct_log_files LOG        LOG's newest two daily files (LOG: wireguard or configd), oldest first: syslog starts
#                             a new file at midnight, and latest.log can name the old one for hours after that.
#                             With no daily file yet, nothing.
#   lmark LOG                 log a unique marker line to LOG and wait (at most 10 s) until it is written; prints
#                             the marker's name
#   lwindow LOG MARK          the lines between MARK and a closing marker; when either marker is not in the files,
#                             the line "wgct-marks: marker missing", so an expectation of "nothing" cannot pass
#   lcount LOG MARK GREP...   grep -c GREP... over that window; -1 when a marker is missing
# Their own variables are named wm_*, so a test's are left alone.

# wgct_log_tag LOG: the program name syslog files LOG's lines under
wgct_log_tag() {
    case "$1" in
    configd) echo configd.py ;;
    *) echo wireguard ;;
    esac
}

wgct_log_files() {
    set -- /var/log/"$1"/"$1"_*.log
    [ -e "$1" ] || return 0
    while [ "$#" -gt 2 ]; do
        shift
    done
    cat -- "$@"
}

lmark() {
    wm_m="wgct-mark-$$-$(od -An -N6 -tx1 /dev/urandom | tr -d ' \n')."
    /usr/bin/logger -t "$(wgct_log_tag "$1")" -- "[wgct-marks] marker $wm_m"
    wm_n=0
    while [ "$wm_n" -lt 100 ] && ! wgct_log_files "$1" | grep -qF -- "marker $wm_m"; do
        sleep 0.1
        wm_n=$((wm_n + 1))
    done
    echo "$wm_m"
}

lwindow() {
    wm_end=$(lmark "$1")
    wgct_log_files "$1" | awk -v a="marker $2" -v b="marker $wm_end" '
        index($0, b) && f { closed = 1; exit }
        f { print }
        index($0, a) { f = 1 }
        END { if (!closed) print "wgct-marks: marker missing" }'
}

lcount() {
    wm_log=$1
    wm_mark=$2
    shift 2
    wm_window=$(lwindow "$wm_log" "$wm_mark")
    case "$wm_window" in
    *"wgct-marks: marker missing"*) echo -1 ;;
    *) printf '%s\n' "$wm_window" | grep -c "$@" ;;
    esac
}
