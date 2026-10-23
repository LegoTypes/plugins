<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Timings and limits (spec 2026-10-17 sections 3.1 to 3.10). Constants, not settings: none has a
 * demonstrated need to vary.
 */

const UU_DEAD_MIN_SECONDS = 10;           /* all packets lost this long, on a young window, is down */
const UU_FIB_SYNC_MARGIN_MS = 500;        /* added to net.route.algo.fib_max_sync_delay_ms before probing */
const UU_PROBE_TIMEOUT_SECONDS = 3;       /* one resolver probe */
const UU_PROBE_TRIES = 2;                 /* a probe is tried once more before it counts as failed */
const UU_PROBE_FAILURES = 2;              /* consecutive failed probes before leaving tunnel mode */
const UU_CONTROL_WAIT_SECONDS = 15;       /* wait for Unbound's control channel after a start */
const UU_CONTROL_CALL_TIMEOUT_SECONDS = 5; /* every unbound-control call has a timeout */
const UU_ESCALATE_EVALUATIONS = 3;        /* silent control channel this many evaluations before a restart */
const UU_ESCALATE_MIN_SECONDS = 120;      /* and silent at least this long, so a fresh start is never restarted */
const UU_LOCK_WAIT_SECONDS = 60;          /* wait for the evaluate lock */
const UU_STOP_DRAIN_SECONDS = 1;          /* stop holds the reject route this long after flush_requestlist, before
                                           * the delete: the VM measured the last send to the resolver within 13 ms
                                           * of the flush (without it, retries ran up to 14.5 s) */
const UU_RULE_PRIORITY = 99998;           /* firewall rule priority, beside the tunnels plugin's 99999 */
const UU_FAILBACK_DELAY_MAX = 3600;       /* the largest failback_delay Save accepts */
const UU_BLOCK_TABLE = '__unboundupstream_block'; /* the counting block's table, in core's __ namespace, which no
                                                     * alias can take (spec section 3.6c, P7) */
const UU_RUN_DIR = '/var/run/unboundupstream'; /* root's, mode 0700, made at use (uu_run_dir()): never /tmp (C3) */
const UU_STATE_PATH = UU_RUN_DIR . '/state.json'; /* the runtime state (state.php) */
const UU_RULES_PATH = UU_RUN_DIR . '/rules.json'; /* the rules verification record (section 3.6c) */
const UU_FILE_MAX_BYTES = 1048576;        /* the most read of a state, record or zone file (uu_read_regular_file(),
                                           * zone_read.py) */
const UU_PYTHON = '/usr/local/bin/python3'; /* core's interpreter, the one configd runs on (rc.d/configd) */
const UU_ZONE_READ_SECONDS = 5;           /* zone_read.py is killed after this long; it takes tens of ms */
const UU_RULES_LIST_PAIRS = 2;            /* checksum-listing-checksum tries before a straddled listing is given up
                                           * (section 3.6c, P12) */
const UU_STOP_REQUEST = 'request';        /* Snapshot.stop: evaluate.php stop (the service's stop, or a Save) */
const UU_STOP_REMOVE = 'remove';          /* Snapshot.stop: the package is being removed */
const UU_STOP_RESOLVER = 'resolver';      /* Snapshot.stop: undoing the resolver address a Save replaced */
const UU_NOTIFY_CONNECT_SECONDS = 3;     /* the switch notification's connect timeout */
const UU_NOTIFY_TIMEOUT_SECONDS = 5;     /* and its whole POST, under the evaluate lock */
const UU_NOTIFY_URL_MASK = '/^https?:\/\/[^\s\/?#]+(\/\S*)?$/'; /* the model's notify_url <Mask>, byte for byte:
                                          * what the stored value must match to be used */
const UU_SYSLOG_IDENT = 'dnsupstream';   /* the program name every log line carries; syslog-ng's program() is an
                                           * unanchored regex, so it must contain no other log's pattern (core's
                                           * resolver log is program("unbound")); unboundupstream.inc's syslog and
                                           * firewall hooks and the Syslog template repeat it */
