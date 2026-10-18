<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
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
const UU_STOP_DRAIN_SECONDS = 5;          /* stop holds the reject route this long before the delete, so Unbound's
                                           * in-flight retries to the resolver fail locally; Task 12 measures the
                                           * bound on the VM */
const UU_RULE_PRIORITY = 99998;           /* firewall rule priority, beside the tunnels plugin's 99999 */
const UU_FAILBACK_DELAY_MAX = 3600;       /* the largest failback_delay Save accepts */
