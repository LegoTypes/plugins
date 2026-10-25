<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Paths, and the timings of spec 2026-10-05 section 3.10. Constants, not settings: none has a demonstrated need
 * to vary. Every file the plugin keeps is root's alone, in a 0700 directory and 0600 itself, and what the plugin
 * reads back it reads as a regular file only, at most WF_FILE_MAX_BYTES.
 */

const WF_RUN_DIR = '/var/run/wanfailover';           /* the evaluate lock, the Monit event and the crash-test flag */
const WF_STATE = '/var/db/wanfailover/state.json';
const WF_EVENT = WF_RUN_DIR . '/event';
const WF_NOTIFIED = WF_RUN_DIR . '/notified';        /* the fingerprint of the event Monit last reported */
const WF_TRACE = '/var/log/wanfailover/trace';
const WF_CRASH_FLAG = WF_RUN_DIR . '/crash_at';      /* a test names a crash point here; the point consumes it */
const WF_FILE_MAX_BYTES = 1048576;

const WF_FRESH_SECONDS = 120;        /* an alternative must have read settled-up this recently to back a hold */
const WF_UNKNOWN_MAX_SECONDS = 180;  /* unreadable this long counts as bad (three dpinger time_periods) */
const WF_DEAD_MIN_SECONDS = 10;      /* 100% loss for this long is hard down, settled or not */
const WF_FAILBACK_MAX_SECONDS = 600; /* a failback that cannot complete is dropped after this */
const WF_TS_STABLE_SECONDS = 90;     /* a core-driven default change must hold this long before a Tailscale restart */
const WF_TS_COOLDOWN_SECONDS = 300;  /* minimum time between Tailscale restarts */
const WF_TRACE_DAYS = 30;            /* trace for this long after install */
const WF_TRACE_KEEP_DAYS = 7;        /* keep trace files this long */
