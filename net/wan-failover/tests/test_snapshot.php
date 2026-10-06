<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The snapshot's pure parsers (the live collectors need a box and are checked on the VM).
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/WanFailover/lib/parsers.php';

wf_register_suite('snapshot', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $up = "igc2: flags=1008843<UP,BROADCAST,RUNNING> metric 0 mtu 1500\n\tinet 192.168.12.148 netmask 0xffffff00 broadcast 192.168.12.255\n\tmedia: Ethernet autoselect (1000baseT <full-duplex>)\n\tstatus: active\n";
    $nc = "igc1: flags=8843<UP,BROADCAST> metric 0 mtu 1500\n\tmedia: Ethernet autoselect\n\tstatus: no carrier\n";
    wf_check($t, 'ifconfig: active with an address', wf_parse_ifconfig($up) === ['carrier' => true, 'has_ipv4' => true]);
    wf_check($t, 'ifconfig: no carrier, no address', wf_parse_ifconfig($nc) === ['carrier' => false, 'has_ipv4' => false]);
    $wg = "wg1: flags=10080c1<UP,RUNNING,NOARP,MULTICAST,LOWER_UP> metric 0 mtu 1420\n\tinet 10.2.0.2 netmask 0xffffffff\n\tgroups: wg wireguard\n";
    wf_check($t, 'ifconfig: an interface that prints no status line (wg, pppoe) is not taken for carrier loss', wf_parse_ifconfig($wg) === ['carrier' => true, 'has_ipv4' => true]);
    wf_check($t, 'route get default', wf_parse_route_get("   route to: default\ndestination: default\n    gateway: 203.0.113.1\n  interface: igc1\n")
        === ['destination' => 'default', 'gateway' => '203.0.113.1']);
    wf_check($t, 'route get with no route', wf_parse_route_get("route: route has not been found\n") === ['destination' => null, 'gateway' => null]);
    wf_check($t, 'kern.boottime', wf_parse_boottime('{ sec = 1791072586, usec = 85313 } Sat Oct  3 17:09:46 2026') === 1791072586);
    wf_check($t, 'kern.boottime unparseable is 0', wf_parse_boottime('') === 0);
    $r = wf_resolve_uuids(['u1', 'u9', ''], ['u1' => 'PRIMARY_WAN', 'u2' => 'WAN2']);
    wf_check($t, 'UUIDs resolve to names; unknown ones are reported; empty ignored', $r['names'] === ['PRIMARY_WAN'] && $r['unresolved'] === ['u9']);
    return wf_tally_report('snapshot', $t);
});
