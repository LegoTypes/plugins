<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Timings (spec 2026-10-05 section 3.10). Constants, not settings: none has a demonstrated need to vary.
 */

const WF_FRESH_SECONDS = 120;        /* an alternative must have read settled-up this recently to back a hold */
const WF_UNKNOWN_MAX_SECONDS = 180;  /* unreadable this long counts as bad (three dpinger time_periods) */
const WF_DEAD_MIN_SECONDS = 10;      /* 100% loss for this long is hard down, settled or not */
const WF_FAILBACK_MAX_SECONDS = 600; /* a failback that cannot complete is dropped after this */
const WF_TS_STABLE_SECONDS = 90;     /* a core-driven default change must hold this long before a Tailscale restart */
const WF_TS_COOLDOWN_SECONDS = 300;  /* minimum time between Tailscale restarts */
const WF_TRACE_DAYS = 30;            /* trace for this long after install */
const WF_TRACE_KEEP_DAYS = 7;        /* keep trace files this long */
