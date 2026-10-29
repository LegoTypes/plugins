<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Paths and timings. Constants, not settings: none has a demonstrated need
 * to vary. Every file the plugin keeps is root's alone, in a 0700 directory and 0600 itself, and what the plugin
 * reads back it reads as a regular file only, at most WF_FILE_MAX_BYTES.
 */

const WF_RUN_DIR = '/var/run/wanfailover';           /* the evaluate lock, Monit event, crash-test flag and removal marker */
const WF_STATE = '/var/db/wanfailover/state.json';
const WF_EVENT = WF_RUN_DIR . '/event';
const WF_NOTIFIED = WF_RUN_DIR . '/notified';        /* the fingerprint of the event Monit last reported */
const WF_TRACE = '/var/log/wanfailover/trace';
const WF_CRASH_FLAG = WF_RUN_DIR . '/crash_at';      /* a test names a crash point here; the point consumes it */
const WF_REMOVING = WF_RUN_DIR . '/removing';        /* the package removal's marker: +PRE_DEINSTALL.pre writes it */
const WF_FILE_MAX_BYTES = 1048576;

/* core's own commands, for the package removal, which cannot use the plugin's configd actions (they go with the
 * package): core's [routes.configure] command, and the command the plugin's [replay_alarm] action wraps; and core's
 * [restart] command of actions_cron.conf, which +POST_DEINSTALL.post runs when configd does not answer */
const WF_CORE_ROUTES_CONFIGURE = '/usr/local/etc/rc.routing_configure';
const WF_CORE_CRON_RESTART = '/usr/local/sbin/pluginctl -s cron restart';
const WF_REPLAY_ALARM_CMD = '/usr/local/bin/flock -o -w 120 /tmp/filter_reload_gateway.lock /usr/local/etc/rc.routing_configure alarm';
const WF_CONFIGD_TIMEOUT_SECONDS = 30; /* the removal's configctl call is bounded; core's own command, its fallback, is not */
const WF_DEINSTALL_WAIT_SECONDS = 180; /* the removal's release, its wait for an evaluation's lock included: that evaluation's
                                         worst case is the gateway lock's 30 s, the replay's 120 s, the reconfigure */
const WF_DEINSTALL_RETRY_SECONDS = 5;  /* between the removal's tries at a release that did not land */

/* core's own mask for a gateway name (Gateways.xml), with the D flag so a trailing newline fails; names and
 * interfaces from a restored configuration are checked against these where they build paths and arguments; the
 * names contract compares the mask with core's at run time (wf_contract_name_mask()) */
const WF_GATEWAY_NAME_MASK = '/^[a-zA-Z0-9_\-]{1,32}$/D';
const WF_IF_MASK = '/^[a-z][a-z0-9_.]*\z/';

/* core 26.7.7's files the snapshot reads, verbatim (%s is the gateway's name); the contract notes any that core no
 * longer keeps there */
const WF_DPINGER_PID = '/var/run/dpinger_%s.pid';   /* dpinger.inc */
const WF_DPINGER_SOCK = '/var/run/dpinger_%s.sock'; /* dpinger.inc */
const WF_CORE_GATEWAYS_XML = '/usr/local/opnsense/mvc/app/models/OPNsense/Routing/Gateways.xml';
/* core 26.7.7's class and method the snapshot reads the gateway groups through (wf_contract_groups_read()) */
const WF_CORE_GROUPS_CLASS = 'OPNsense\\Routing\\GatewayGroups';
const WF_CORE_GROUPS_METHOD = 'getGroupsConfig';

const WF_FRESH_SECONDS = 120;        /* an alternative must have read settled-up this recently to back a hold */
const WF_UNKNOWN_MAX_SECONDS = 180;  /* unreadable this long counts as bad (three dpinger time_periods) */
const WF_DEAD_MIN_SECONDS = 10;      /* 100% loss for this long is hard down, settled or not */
const WF_FAILBACK_MAX_SECONDS = 600; /* a failback that cannot complete is dropped after this */
const WF_TS_STABLE_SECONDS = 90;     /* a core-driven default change must hold this long before a Tailscale restart */
const WF_TS_COOLDOWN_SECONDS = 300;  /* minimum time between Tailscale restarts */
const WF_TRACE_DAYS = 30;            /* trace for this long after install */
const WF_TRACE_KEEP_DAYS = 7;        /* keep trace files this long */
