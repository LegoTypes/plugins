<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Remove's refusal set (spec 2026-09-24 section 6.3): everything in config
 * that can name a tunnel's gateways or its interface, flattened into one list
 * of references -- the union of core's delGatewayAction and
 * AssignmentController::delItemAction checks, the rule fields those checks do
 * not cover (MVC replyto and received-on, source/destination nets naming optN
 * or optNip, NAT targets), VIPs on the interface and the system DNS-server
 * gateways. wgipv6_refs_from_tree() is pure over a SimpleXML tree, so the
 * self-test runs it on a synthetic config; wgipv6_refs_snapshot() applies it
 * to the live one.
 */

require_once __DIR__ . '/tunnels.php';
require_once __DIR__ . '/selftest.php';

/**
 * @param string $members comma- or space-separated interface names
 * @return list<string> names with any _vipN suffix removed (core's delItemAction rule)
 */
function wgipv6_member_tokens(string $members): array {
    $out = [];
    foreach (preg_split('/[\s,]+/', $members) ?: [] as $member) {
        if ($member !== '') {
            $out[] = explode('_vip', $member)[0];
        }
    }
    return $out;
}

/**
 * @param \SimpleXMLElement            $root   a config tree (the live one, or a fixture)
 * @param array<string, list<string>>  $groups gateway group name => member gateway names
 * @return list<array{id: string, what: string, gateways: list<string>, interfaces: list<string>}>
 */
function wgipv6_refs_from_tree(\SimpleXMLElement $root, array $groups): array {
    $refs = [];
    $add = function (string $id, string $what, array $gateways, array $interfaces) use (&$refs): void {
        $refs[] = [
            'id' => $id,
            'what' => $what,
            'gateways' => array_values(array_filter($gateways, fn (string $g): bool => $g !== '')),
            'interfaces' => array_values(array_filter($interfaces, fn (string $i): bool => $i !== '')),
        ];
    };
    $id = fn (string $kind, \SimpleXMLElement $n, int $i): string
        => $kind . ':' . ((string)$n['uuid'] !== '' ? (string)$n['uuid'] : (string)$i);
    $label = fn (string $kind, \SimpleXMLElement $n, string $field, int $i): string
        => $kind . ' ' . ((string)$n->{$field} !== '' ? '"' . (string)$n->{$field} . '"' : '#' . ($i + 1));
    $csv = fn (\SimpleXMLElement $n, string $field): array => wgipv6_split_csv((string)$n->{$field});

    foreach ($groups as $name => $members) {
        $add('group:' . $name, 'gateway group ' . $name, $members, []);
    }
    foreach (wgipv6_xml_list($root, 'interfaces') as $interfaces) {
        foreach ($interfaces->children() as $key => $if) {
            $add('if:' . $key, 'interface ' . $key, [(string)$if->gateway, (string)$if->gatewayv6], []);
        }
    }
    foreach (range(1, 8) as $n) {
        $gw = (string)$root->system->{"dns{$n}gw"};
        if ($gw !== '' && $gw !== 'none') {
            $add('dnsgw:' . $n, "system DNS server {$n}", [$gw], []);
        }
    }
    foreach (wgipv6_xml_list($root, 'filter', 'rule') as $i => $r) {
        $add($id('filter', $r, $i), $label('firewall rule', $r, 'descr', $i),
            [(string)$r->gateway, (string)$r->{'reply-to'}],
            array_merge($csv($r, 'interface'), [(string)$r->source->network, (string)$r->destination->network]));
    }
    foreach (wgipv6_xml_list($root, 'nat', 'rule') as $i => $r) {
        $add($id('dnat', $r, $i), $label('port forward', $r, 'descr', $i), [],
            array_merge($csv($r, 'interface'), [(string)$r->source->network, (string)$r->destination->network, (string)$r->target]));
    }
    foreach (wgipv6_xml_list($root, 'nat', 'outbound', 'rule') as $i => $r) {
        $add($id('outbound', $r, $i), $label('legacy outbound NAT rule', $r, 'descr', $i), [],
            array_merge($csv($r, 'interface'), [(string)$r->source->network, (string)$r->destination->network]));
    }
    foreach (wgipv6_xml_list($root, 'OPNsense', 'Firewall', 'Filter', 'rules', 'rule') as $i => $r) {
        $add($id('rule', $r, $i), $label('firewall rule', $r, 'description', $i),
            [(string)$r->gateway, (string)$r->replyto],
            array_merge($csv($r, 'interface'), $csv($r, 'received-on'), $csv($r, 'source_net'), $csv($r, 'destination_net')));
    }
    foreach (wgipv6_xml_list($root, 'OPNsense', 'Firewall', 'Filter', 'snatrules', 'rule') as $i => $r) {
        $add($id('snat', $r, $i), $label('outbound NAT rule', $r, 'description', $i), [],
            array_merge($csv($r, 'interface'), $csv($r, 'source_net'), $csv($r, 'destination_net'), $csv($r, 'target')));
    }
    foreach (wgipv6_xml_list($root, 'OPNsense', 'Firewall', 'Filter', 'npt', 'rule') as $i => $r) {
        $add($id('npt', $r, $i), $label('NPTv6 rule', $r, 'description', $i), [],
            array_merge($csv($r, 'interface'), $csv($r, 'trackif')));
    }
    foreach (wgipv6_xml_list($root, 'OPNsense', 'Firewall', 'Filter', 'onetoone', 'rule') as $i => $r) {
        $add($id('onetoone', $r, $i), $label('1:1 NAT rule', $r, 'description', $i), [],
            array_merge($csv($r, 'interface'), $csv($r, 'source_net'), $csv($r, 'destination_net')));
    }
    foreach (wgipv6_xml_list($root, 'staticroutes', 'route') as $i => $r) {
        $add($id('route', $r, $i), 'static route ' . (string)$r->network, [(string)$r->gateway], []);
    }
    foreach (wgipv6_xml_list($root, 'ifgroups', 'ifgroupentry') as $g) {
        $add('ifgroup:' . (string)$g->ifname, 'interface group ' . (string)$g->ifname, [], wgipv6_member_tokens((string)$g->members));
    }
    foreach (wgipv6_xml_list($root, 'bridges', 'bridged') as $i => $b) {
        $add($id('bridge', $b, $i), $label('bridge', $b, 'bridgeif', $i), [], wgipv6_member_tokens((string)$b->members));
    }
    foreach (wgipv6_xml_list($root, 'gres', 'gre') as $i => $g) {
        $add($id('gre', $g, $i), $label('GRE tunnel', $g, 'greif', $i), [], wgipv6_member_tokens((string)$g->if));
    }
    foreach (wgipv6_xml_list($root, 'gifs', 'gif') as $i => $g) {
        $add($id('gif', $g, $i), $label('GIF tunnel', $g, 'gifif', $i), [], wgipv6_member_tokens((string)$g->if));
    }
    foreach (wgipv6_xml_list($root, 'virtualip', 'vip') as $i => $v) {
        $add($id('vip', $v, $i), $label('virtual IP', $v, 'subnet', $i), [], [(string)$v->interface]);
    }
    return $refs;
}

/**
 * The live references. Reads the config tree as it stands (call it under
 * Config::lock() in a writer); writes nothing.
 *
 * @param array<string, list<string>> $groups wgipv6_core_snapshot()['groups']
 * @return list<array{id: string, what: string, gateways: list<string>, interfaces: list<string>}>
 */
function wgipv6_refs_snapshot(array $groups): array {
    return wgipv6_refs_from_tree(\OPNsense\Core\Config::getInstance()->object(), $groups);
}

/**
 * Why Remove must refuse (spec 6.3), changing nothing. Pure. Interface tokens
 * match exactly -- optN itself or its address optNip -- so opt1 never matches
 * opt13.
 *
 * @param array        $refs         wgipv6_refs_from_tree()
 * @param list<string> $gatewayNames every gateway on the tunnel interface
 * @param string       $opt          the tunnel interface key, '' when unassigned
 * @param list<string> $ownIds       reference ids Remove deletes itself
 * @return list<string> one line per referencing object; empty = Remove may proceed
 */
function wgipv6_remove_refusals(array $refs, array $gatewayNames, string $opt, array $ownIds): array {
    $gatewayNames = array_values(array_filter($gatewayNames, fn (string $g): bool => $g !== ''));
    $out = [];
    foreach ($refs as $ref) {
        if (in_array($ref['id'], $ownIds, true)) {
            continue;
        }
        $gateways = array_values(array_intersect($gatewayNames, $ref['gateways']));
        $onInterface = $opt !== ''
            && (in_array($opt, $ref['interfaces'], true) || in_array($opt . 'ip', $ref['interfaces'], true));
        if ($gateways === [] && !$onInterface) {
            continue;
        }
        $uses = [];
        if ($gateways !== []) {
            $uses[] = 'gateway ' . implode(', ', $gateways);
        }
        if ($onInterface) {
            $uses[] = 'interface ' . $opt;
        }
        $out[] = $ref['what'] . ' uses ' . implode(' and ', $uses);
    }
    return $out;
}

/**
 * Self-tests for the reference collector and the refusals. Pure.
 *
 * @return int exit code, 0 when every case passes
 */
function wgipv6_refs_selftest(): int {
    $t = ['fail' => 0, 'total' => 0];
    $gws = ['tun_c', 'tun_c-ipv6'];
    $own = ['route:own', 'snat:own'];
    $ref = fn (string $id, array $gateways, array $interfaces): array
        => ['id' => $id, 'what' => $id, 'gateways' => $gateways, 'interfaces' => $interfaces];
    $cases = [
        ['a gateway group lists the IPv4 gateway', [$ref('group:g', ['WAN_A', 'tun_c'], [])], 1],
        ['a gateway group lists the IPv6 gateway', [$ref('group:g', ['tun_c-ipv6'], [])], 1],
        ['an MVC rule routes via the gateway', [$ref('rule:1', ['tun_c', ''], ['lan'])], 1],
        ['an MVC rule replies via the IPv6 gateway', [$ref('rule:2', ['', 'tun_c-ipv6'], ['lan'])], 1],
        ['a rule on the interface (interface list)', [$ref('rule:3', [], ['lan', 'opt13'])], 1],
        ['a rule whose source is the interface address (optNip)', [$ref('rule:4', [], ['opt13ip'])], 1],
        ['a static route via the tunnel gateway', [$ref('route:r1', ['tun_c'], [])], 1],
        ['its own endpoint route and NAT rule', [$ref('route:own', ['tun_c'], []), $ref('snat:own', [], ['opt13'])], 0],
        ['an interface names the tunnel gateway', [$ref('if:opt3', ['tun_c'], [])], 1],
        ['an interface group member with a _vip suffix', [$ref('ifgroup:x', [], wgipv6_member_tokens('opt3 opt13_vip2'))], 1],
        ['a bridge member', [$ref('bridge:0', [], wgipv6_member_tokens('opt13,opt3'))], 1],
        ['a GRE parent', [$ref('gre:0', [], ['opt13'])], 1],
        ['opt1, opt1ip and opt130 are not opt13', [$ref('rule:5', [], ['opt1', 'opt1ip', 'opt130'])], 0],
        ['nothing references the tunnel', [$ref('group:h', ['WAN_A'], []), $ref('rule:6', ['WAN_A'], ['lan'])], 0],
    ];
    foreach ($cases as [$desc, $refs, $expect]) {
        wgipv6_check($t, "refs: {$desc} => " . ($expect === 1 ? 'refused' : 'allowed'),
            count(wgipv6_remove_refusals($refs, $gws, 'opt13', $own)) === $expect);
    }
    wgipv6_check($t, 'refs: a refusal names the object and what it uses',
        wgipv6_remove_refusals([$ref('rule:7', ['tun_c'], ['opt13'])], $gws, 'opt13', []) === ['rule:7 uses gateway tun_c and interface opt13']);
    wgipv6_check($t, 'refs: an unassigned tunnel (no interface) matches no empty token',
        wgipv6_remove_refusals([$ref('rule:8', [], [''])], $gws, '', []) === []);
    wgipv6_check($t, 'refs: member tokens split on commas and spaces, _vip stripped',
        wgipv6_member_tokens('opt3, opt13_vip2  lan') === ['opt3', 'opt13', 'lan']);

    $x = simplexml_load_string('<opnsense><filter><rule><a>1</a></rule><rule/></filter></opnsense>');
    wgipv6_check($t, 'xml_list: every element on the path, none for a missing path',
        $x !== false && count(wgipv6_xml_list($x, 'filter', 'rule')) === 2 && wgipv6_xml_list($x, 'nat', 'outbound', 'rule') === []);

    $tree = <<<'XML'
<opnsense>
  <interfaces>
    <lan><if>igc1</if><gateway>tun_c</gateway></lan>
    <opt13><if>wg3</if><descr>tunc</descr></opt13>
  </interfaces>
  <system><dns1gw>tun_c</dns1gw><dns2gw>none</dns2gw></system>
  <filter>
    <rule><interface>lan,opt13</interface><gateway>tun_c</gateway><reply-to>tun_c-ipv6</reply-to>
      <source><network>opt13ip</network></source><destination><network>lan</network></destination><descr>legacy</descr></rule>
  </filter>
  <nat>
    <rule><interface>wan</interface><source><network>any</network></source><destination><network>opt13ip</network></destination>
      <target>192.0.2.5</target><descr>fwd</descr></rule>
    <outbound><rule><interface>opt13</interface><source><network>lan</network></source></rule></outbound>
  </nat>
  <staticroutes><route uuid="r-1"><network>198.51.100.0/24</network><gateway>tun_c</gateway></route></staticroutes>
  <ifgroups><ifgroupentry><ifname>GRP</ifname><members>opt3 opt13</members></ifgroupentry></ifgroups>
  <bridges><bridged><members>opt13,opt3</members></bridged></bridges>
  <gres><gre><if>opt13</if></gre></gres>
  <gifs><gif><if>opt13_vip1</if></gif></gifs>
  <virtualip><vip><interface>opt13</interface><subnet>192.0.2.9</subnet></vip></virtualip>
  <OPNsense><Firewall><Filter>
    <rules><rule uuid="f-1"><interface>lan</interface><received-on>opt13</received-on><gateway/><replyto>tun_c</replyto>
      <source_net>any</source_net><destination_net>opt13</destination_net><description>mvc</description></rule></rules>
    <snatrules>
      <rule uuid="s-1"><interface>opt13</interface><source_net>lan</source_net><destination_net>any</destination_net><target/></rule>
      <rule uuid="s-2"><interface>wan</interface><source_net>opt13</source_net><destination_net>any</destination_net><target/></rule>
    </snatrules>
    <npt><rule uuid="n-1"><interface>wan</interface><trackif>opt13</trackif></rule></npt>
    <onetoone><rule uuid="o-1"><interface>opt13</interface><source_net>192.0.2.7</source_net><destination_net>any</destination_net></rule></onetoone>
  </Filter></Firewall></OPNsense>
</opnsense>
XML;
    $root = simplexml_load_string($tree);
    $refs = $root !== false ? wgipv6_refs_from_tree($root, ['grp' => ['tun_c', 'WAN_A']]) : [];
    $out = wgipv6_remove_refusals($refs, $gws, 'opt13', ['snat:s-1', 'if:opt13']);
    /* group, interface lan, DNS server 1, legacy rule, port forward, legacy outbound NAT, MVC rule, snat s-2,
     * NPT, 1:1, route, interface group, bridge, GRE, GIF, VIP -- and not its own snat s-1 or interface opt13 */
    wgipv6_check($t, 'refs: every section of a config tree is found, legacy spellings included (16 refusals)',
        count($out) === 16
        && in_array('firewall rule "legacy" uses gateway tun_c, tun_c-ipv6 and interface opt13', $out, true)
        && in_array('port forward "fwd" uses interface opt13', $out, true)
        && in_array('outbound NAT rule #2 uses interface opt13', $out, true));
    wgipv6_check($t, 'refs: the same tree does not refuse an unrelated tunnel',
        wgipv6_remove_refusals($refs, ['tun_x', 'tun_x-ipv6'], 'opt14', []) === []);

    return wgipv6_tally_report('refs', $t);
}
