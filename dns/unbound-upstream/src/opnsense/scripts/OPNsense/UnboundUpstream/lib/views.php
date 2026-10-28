<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The fail-closed view as plain arrays. Pure.
 *
 * The set of source networks the view refuses internet names to, the ACL nodes Unbound needs for those networks to
 * reach the view, the zones the view must still answer from (every zone the daemon reports, as noview or as an
 * armed copy), the file between the plugin's two markers, and the diff that brings a loaded view to the wanted one.
 * The I/O (the control channel, the file, the restart) is elsewhere.
 *
 * Net  = array{net: string, action: string}   an ACL node: canonical CIDR and the access-control action
 * Nodes = array{view: list<string>, access: list<Net>}
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/address.php';

const UU_VIEW_BEGIN = '# Rendered by os-unbound-upstream. Do not edit.';
const UU_VIEW_END = '# End of os-unbound-upstream.';

/** The access-control actions that answer queries from their source. */
const UU_VIEW_ALLOW_TYPES = ['allow', 'allow_setrd', 'allow_snoop', 'allow_cookie'];

/** The networks Unbound's own loopback nodes cover; a view on a node within them would refuse the firewall's lookups. */
const UU_VIEW_LOOPBACK = ['127.0.0.0/8', '::1/128', '::ffff:127.0.0.1/128'];

/* the planner's reasons the set cannot be armed (uu_plan_view()); the file step keeps them in the state only while
 * the plan gives them */
const UU_VIEW_UNSUPPORTED = 'Fail closed not armed: Unbound has no view support';
const UU_VIEW_FOREIGN = 'Fail closed not armed: a view the plugin does not own covers ';
const UU_VIEW_UNLOADED = 'Fail closed not armed: restart Unbound to load the view';
/* the file step's reason when the start it restarted Unbound for did not load the file's node lines */
const UU_VIEW_NOT_LOADED = "Fail closed not armed: Unbound's start did not load the view file "
    . '(restart Unbound to load it)';
/* the file step's reason when the start it restarted Unbound for kept the copy of a file it deleted */
const UU_VIEW_NOT_DROPPED = "Fail closed: Unbound's start kept the copy of the deleted view file "
    . '(restart Unbound to drop it)';

/** Zone types whose names are answered from the zone itself or from the owner's chosen target: the view skips them. */
const UU_VIEW_NOVIEW_TYPES = ['static', 'redirect', 'deny', 'refuse', 'always_refuse', 'always_nxdomain',
    'always_nodata', 'always_deny', 'always_null', 'forward', 'stub'];

/**
 * Order of two canonical networks: IPv4 before IPv6, then by address, then by prefix length.
 */
function uu_view_net_cmp(string $a, string $b): int
{
    $pa = uu_net_parse($a);
    $pb = uu_net_parse($b);
    if ($pa === null || $pb === null) {
        return strcmp($a, $b);
    }
    return strlen($pa['packed']) <=> strlen($pb['packed']) ?: strcmp($pa['packed'], $pb['packed'])
        ?: $pa['prefix'] <=> $pb['prefix'];
}

/**
 * The canonical networks sorted as uu_view_net_cmp() orders them, without duplicates.
 *
 * @param list<string> $nets
 * @return list<string>
 */
function uu_view_net_sort(array $nets): array
{
    $nets = array_values(array_unique($nets));
    usort($nets, 'uu_view_net_cmp');
    return $nets;
}

/** Whether a canonical network lies within Unbound's loopback nodes. */
function uu_view_loopback(string $net): bool
{
    foreach (UU_VIEW_LOOPBACK as $loopback) {
        if (uu_net_contains($loopback, $net)) {
            return true;
        }
    }
    return false;
}

/**
 * The network of every live address of each selected interface, GUA and ULA, never fe80::/10; a selected interface
 * with no IPv6 address adds a note.
 *
 * @param array<string, array{ipv4: list<array{ipaddr: string, subnetbits: int}>, ipv6: list<array{ipaddr: string,
 *     subnetbits: int, link-local: bool}>}> $details legacy_interfaces_details(), by device
 * @param list<string> $selected interface ids
 * @param array<string, string> $devices interface id => device
 * @return array{nets: list<string>, notes: list<string>}
 */
function uu_view_iface_nets(array $details, array $selected, array $devices): array
{
    $nets = [];
    $notes = [];
    foreach ($selected as $id) {
        $entry = $details[$devices[$id] ?? ''] ?? ['ipv4' => [], 'ipv6' => []];
        foreach ($entry['ipv4'] as $addr) {
            $net = uu_net_canonical($addr['ipaddr'] . '/' . $addr['subnetbits']);
            if ($net !== null) {
                $nets[] = $net;
            }
        }
        $v6 = 0;
        foreach ($entry['ipv6'] as $addr) {
            $net = uu_net_canonical($addr['ipaddr'] . '/' . $addr['subnetbits']);
            if ($net === null || $addr['link-local'] || uu_net_contains('fe80::/10', $net)) {
                continue;
            }
            $nets[] = $net;
            $v6++;
        }
        if ($v6 === 0) {
            $notes[] = 'no IPv6 net yet for ' . $id;
        }
    }
    return ['nets' => array_values(array_unique($nets)), 'notes' => $notes];
}

/**
 * The set the view refuses: every address when the fallback is off, else the selected interfaces' networks and the
 * listed ones. A selected interface keeps the scope "selected" with no net (its VLAN is down, the file stays); a
 * listed 0.0.0.0/0 or ::/0 is dropped (the checkbox off is that choice).
 *
 * @param list<string> $selected
 * @param list<string> $ifaceNets
 * @param list<string> $networks
 * @return array{scope: string, nets: list<string>}
 */
function uu_view_set(bool $fallback, array $selected, array $ifaceNets, array $networks): array
{
    if (!$fallback) {
        return ['scope' => 'all', 'nets' => ['0.0.0.0/0', '::/0']];
    }
    $listed = [];
    foreach ($networks as $network) {
        $net = uu_net_canonical($network);
        if ($net !== null && $net !== '0.0.0.0/0' && $net !== '::/0') {
            $listed[] = $net;
        }
    }
    $all = [];
    foreach ([...$ifaceNets, ...$listed] as $net) {
        $net = uu_net_canonical($net);
        if ($net !== null) {
            $all[] = $net;
        }
    }
    $all = uu_view_net_sort($all);
    $nets = array_values(array_filter($all, function (string $net) use ($all): bool {
        foreach ($all as $other) {
            if ($other !== $net && uu_net_contains($other, $net)) {
                return false;
            }
        }
        return true;
    }));
    return ['scope' => $selected !== [] || $listed !== [] ? 'selected' : 'none', 'nets' => $nets];
}

/** The token without one pair of matching quotes around it. */
function uu_view_unquote(string $token): string
{
    return strlen($token) >= 2 && ($token[0] === '"' || $token[0] === "'") && $token[-1] === $token[0]
        ? substr($token, 1, -1) : $token;
}

/**
 * Unbound's ACL nodes and the view lines outside the plugin's block, from the configuration as
 * uu_conf_expanded_text() splices it. Each netblock is masked as Unbound masks it, and one listed twice takes its
 * last line's action; a value in one pair of quotes is read as Unbound reads it. Null when the text lacks a node for
 * 0.0.0.0/0 or ::/0, which core always renders (a read taken while Unbound starts, or a cut file), when an
 * access-control line does not parse, and when the plugin's block never ends.
 *
 * @return ?array{nodes: list<Net>, foreign: list<string>}
 */
function uu_view_acl_parse(string $expanded): ?array
{
    $nodes = [];
    $foreign = [];
    $inside = false;
    foreach (explode("\n", $expanded) as $line) {
        $line = trim($line);
        if ($line === UU_VIEW_BEGIN) {
            $inside = true;
            continue;
        }
        if ($inside) {
            $inside = $line !== UU_VIEW_END;
            continue;
        }
        $bare = trim((string)preg_replace('/#.*$/', '', $line));
        if (preg_match('/^(?:view|access-control-view)\s*:/', $bare) === 1) {
            $foreign[] = $bare;
        } elseif (preg_match('/^access-control\s*:/', $bare) === 1) {
            $token = '("[^"]*"|\'[^\']*\'|\S+)';
            if (preg_match('/^access-control\s*:\s*' . $token . '\s+' . $token . '$/D', $bare, $m) !== 1) {
                return null;
            }
            $net = uu_net_canonical(uu_view_unquote($m[1]));
            if ($net === null) {
                return null;
            }
            $nodes[$net] = uu_view_unquote($m[2]);
        }
    }
    if ($inside) {
        return null;
    }
    if (!isset($nodes['0.0.0.0/0'], $nodes['::/0'])) {
        return null;
    }
    $list = [];
    foreach ($nodes as $net => $action) {
        $list[] = ['net' => (string)$net, 'action' => $action];
    }
    return ['nodes' => $list, 'foreign' => $foreign];
}

/**
 * The lines the file needs for the set to reach the view: a view line on every allow-type node of Unbound's that
 * lies within a set net and, where Unbound has no node at the set net itself, on the net, with an access-control
 * line first when the node covering it is an allow-type other than allow. Never a node within loopback.
 *
 * @param list<string> $nets the set, canonical
 * @param list<Net> $acl uu_view_acl_parse()'s nodes
 * @return Nodes
 */
function uu_view_nodes(array $nets, array $acl): array
{
    $view = [];
    $access = [];
    foreach ($nets as $net) {
        if (uu_view_loopback($net)) {
            continue;
        }
        $own = false;
        $cover = null;
        foreach ($acl as $node) {
            if ($node['net'] === $net) {
                $own = true;
            }
            if (in_array($node['action'], UU_VIEW_ALLOW_TYPES, true) && uu_net_contains($net, $node['net'])
                && !uu_view_loopback($node['net'])) {
                $view[] = $node['net'];
            }
            if (uu_net_contains($node['net'], $net)
                && ($cover === null || uu_net_contains($cover['net'], $node['net']))) {
                $cover = $node;
            }
        }
        if ($own || $cover === null || !in_array($cover['action'], UU_VIEW_ALLOW_TYPES, true)) {
            continue;
        }
        $view[] = $net;
        if ($cover['action'] !== 'allow') {
            $access[$net] = $cover['action'];
        }
    }
    $lines = [];
    foreach (uu_view_net_sort(array_map('strval', array_keys($access))) as $net) {
        $lines[] = ['net' => $net, 'action' => $access[$net]];
    }
    return ['view' => uu_view_net_sort($view), 'access' => $lines];
}

/** Whether a zone or record name is one the file may carry: printable ASCII, no white space or quote, ending in a dot. */
function uu_view_zone_ok(string $name): bool
{
    return $name !== '.' && strlen($name) <= 255 && str_ends_with($name, '.')
        && preg_match('/^[\x21\x23-\x7e]+$/D', $name) === 1;
}

/**
 * The lines of a control reply, blank ones dropped.
 *
 * @return list<string>
 */
function uu_view_lines(string $out): array
{
    $lines = [];
    foreach (explode("\n", $out) as $line) {
        $line = trim($line);
        if ($line !== '') {
            $lines[] = $line;
        }
    }
    return $lines;
}

/**
 * Every zone the running daemon reports, minus ".", with its type: list_local_zones' second word, "forward" for
 * list_forwards and "stub" for list_stubs (a forward or stub of a name wins over a local zone of it, as the owner's
 * chosen target does). Null when an input is null, a line has another shape, a name is not one the file may carry, or
 * the result lacks the zones Unbound always has.
 *
 * @return ?array<string, string>
 */
function uu_view_zone_list(?string $localZones, ?string $forwards, ?string $stubs): ?array
{
    if ($localZones === null || $forwards === null || $stubs === null) {
        return null;
    }
    $zones = [];
    foreach (['' => $localZones, 'forward' => $forwards, 'stub' => $stubs] as $type => $out) {
        foreach (uu_view_lines($out) as $line) {
            $pattern = $type === '' ? '/^(\S+) ([A-Za-z_]+)$/D' : '/^(\S+) IN ' . $type . '(?: .*)?$/D';
            if (preg_match($pattern, $line, $m) !== 1) {
                return null;
            }
            if ($m[1] === '.') {
                continue;
            }
            if (!uu_view_zone_ok($m[1])) {
                return null;
            }
            $zones[$m[1]] = $type === '' ? $m[2] : $type;
        }
    }
    if (!isset($zones['localhost.'], $zones['127.in-addr.arpa.'])) {
        return null;
    }
    ksort($zones, SORT_STRING);
    return $zones;
}

/**
 * What the view does with a zone of a type: noview (the zone answers itself, or the owner chose its target), static
 * (a local domain: data answered, the rest locally NXDOMAIN or NODATA) or refuse (a zone that passes names on, and
 * any type unknown here).
 */
function uu_view_zone_class(string $type): string
{
    if (in_array($type, UU_VIEW_NOVIEW_TYPES, true)) {
        return 'noview';
    }
    return $type === 'transparent' || $type === 'inform' ? 'static' : 'refuse';
}

/**
 * One record as list_local_data prints it, its white space outside quoted strings collapsed to one space; a quoted
 * string (a TXT record's text) is kept byte for byte, a backslash escape included. Null for a quote that never ends and
 * for a record that is not "<name> <ttl> <class> <type> <rdata>" with a name the file may carry.
 */
function uu_view_record(string $line): ?string
{
    $out = '';
    $quoted = false;
    $space = false;
    for ($i = 0, $n = strlen($line); $i < $n; $i++) {
        $c = $line[$i];
        if ($quoted) {
            $out .= $c;
            if ($c === '\\' && $i + 1 < $n) {
                $out .= $line[++$i];
            } elseif ($c === '"') {
                $quoted = false;
            }
        } elseif (ctype_space($c)) {
            $space = $out !== '';
        } else {
            $out .= ($space ? ' ' : '') . $c;
            $space = false;
            $quoted = $c === '"';
        }
    }
    return !$quoted && preg_match('/^(\S+) \d+ [A-Za-z]+ [A-Za-z0-9]+ \S/D', $out, $m) === 1 && uu_view_zone_ok($m[1])
        ? $out : null;
}

/**
 * list_local_data's records, each as uu_view_record() gives it, sorted and unique. Null for a null input and for a
 * line uu_view_record() refuses (a cut reply).
 *
 * @return ?list<string>
 */
function uu_view_data_list(?string $out): ?array
{
    if ($out === null) {
        return null;
    }
    $records = [];
    foreach (uu_view_lines($out) as $line) {
        $record = uu_view_record($line);
        if ($record === null) {
            return null;
        }
        $records[] = $record;
    }
    $records = array_values(array_unique($records));
    sort($records, SORT_STRING);
    return $records;
}

/**
 * The records each zone that passes names on keeps in the view: the records whose closest enclosing zone, over all
 * the zones, it is.
 *
 * @param array<string, string> $zones name => type
 * @param list<string> $records
 * @return array<string, list<string>>
 */
function uu_view_mirror(array $zones, array $records): array
{
    $mirror = [];
    foreach ($zones as $name => $type) {
        if (uu_view_zone_class($type) !== 'noview') {
            $mirror[$name] = [];
        }
    }
    foreach ($records as $record) {
        $owner = strtolower((string)strstr($record . ' ', ' ', true));
        $closest = null;
        foreach (array_keys($zones) as $name) {
            $zone = strtolower((string)$name);
            if (($owner === $zone || str_ends_with($owner, '.' . $zone))
                && ($closest === null || strlen($zone) > strlen($closest))) {
                $closest = $zone;
                $closestName = (string)$name;
            }
        }
        if ($closest !== null && isset($closestName, $mirror[$closestName])) {
            $mirror[$closestName][] = $record;
        }
    }
    return $mirror;
}

/**
 * view_list_local_zones' reply: "<name> <type>" per line. Null for a line of another shape.
 *
 * @return ?array<string, string>
 */
function uu_view_parse_list(string $out): ?array
{
    $zones = [];
    foreach (uu_view_lines($out) as $line) {
        if (preg_match('/^(\S+) (\S+)$/D', $line, $m) !== 1) {
            return null;
        }
        $zones[$m[1]] = $m[2];
    }
    return $zones;
}

/**
 * A record's local-data line: in double quotes, or in single quotes when it holds a double quote (a TXT record's text);
 * null for a record the file cannot carry: one that holds both quotes (Unbound's configuration has no escape for the
 * quote around it) or a byte that is not printable ASCII.
 */
function uu_view_record_line(string $record): ?string
{
    if (preg_match('/^[\x20-\x7e]+$/D', $record) !== 1) {
        return null;
    }
    if (!str_contains($record, '"')) {
        return '    local-data: "' . $record . '"';
    }
    return str_contains($record, "'") ? null : "    local-data: '" . $record . "'";
}

/**
 * The mirrored records the file cannot carry (uu_view_record_line()): the view gets them at run time only, from the
 * reconcile.
 *
 * @param array<string, list<string>> $mirror
 * @return list<string>
 */
function uu_view_unwritable(array $mirror): array
{
    $left = [];
    foreach ($mirror as $records) {
        foreach ($records as $record) {
            if (uu_view_record_line($record) === null) {
                $left[] = $record;
            }
        }
    }
    return $left;
}

/**
 * The file between the plugin's markers: the access-control lines, the view lines of the set, the view with its
 * root refuse and each zone as its class (the armed type) followed by its mirrored records, but those the file cannot
 * carry (uu_view_unwritable()).
 *
 * @param Nodes $nodes
 * @param array<string, string> $zones name => type
 * @param array<string, list<string>> $mirror
 */
function uu_view_render(array $nodes, array $zones, array $mirror): string
{
    $lines = [UU_VIEW_BEGIN, 'server:'];
    foreach ($nodes['access'] as $node) {
        $lines[] = '    access-control: ' . $node['net'] . ' ' . $node['action'];
    }
    foreach ($nodes['view'] as $net) {
        $lines[] = '    access-control-view: ' . $net . ' ' . UU_VIEW_NAME;
    }
    array_push($lines, 'view:', '    name: "' . UU_VIEW_NAME . '"', '    view-first: yes', '    local-zone: "." refuse');
    ksort($zones, SORT_STRING);
    foreach ($zones as $name => $type) {
        if ($name === '.') {
            continue;
        }
        $lines[] = '    local-zone: "' . $name . '" ' . uu_view_zone_class($type);
        foreach ($mirror[$name] ?? [] as $record) {
            $line = uu_view_record_line($record);
            if ($line !== null) {
                $lines[] = $line;
            }
        }
    }
    $lines[] = UU_VIEW_END;
    return implode("\n", $lines) . "\n";
}

/**
 * The access-control and access-control-view lines of a rendered file, as written; none for no file.
 *
 * @return list<string>
 */
function uu_view_node_lines(?string $file): array
{
    $lines = [];
    foreach (explode("\n", $file ?? '') as $line) {
        if (preg_match('/^\s*access-control(?:-view)?:/', $line) === 1) {
            $lines[] = $line;
        }
    }
    return $lines;
}

/**
 * The netblocks a rendered file's access-control-view lines name, in the file's order; none for no file.
 *
 * @return list<string>
 */
function uu_view_refused_nets(?string $file): array
{
    $nets = [];
    foreach (uu_view_node_lines($file) as $line) {
        if (preg_match('/^\s*access-control-view:\s*(\S+)/', $line, $m) === 1) {
            $nets[] = $m[1];
        }
    }
    return $nets;
}

/**
 * Whether a file holds only what uu_view_render() writes, each line checked against its shape: the markers first and
 * last, then the server clause (an access-control line of an allow-type, then the view lines, each on a canonical
 * netblock outside loopback), then the view clause (its name, view-first, the root refuse, then each zone a name the
 * file may carry at a class, each record of the shape list_local_data gives, quoted as uu_view_record_line() quotes
 * it). The last guard before unbound-checkconf, which parses neither an access-control netblock nor a view's records.
 */
function uu_view_text_ok(string $text): bool
{
    if (!str_ends_with($text, "\n") || preg_match('/^[\x20-\x7e\n]*$/D', $text) !== 1) {
        return false;
    }
    $lines = explode("\n", substr($text, 0, -1));
    $head = [UU_VIEW_BEGIN, 'server:'];
    $view = ['view:', '    name: "' . UU_VIEW_NAME . '"', '    view-first: yes', '    local-zone: "." refuse'];
    if (count($lines) < count($head) + count($view) + 1 || array_slice($lines, 0, 2) !== $head
        || end($lines) !== UU_VIEW_END) {
        return false;
    }
    $net = fn (string $n): bool => uu_net_canonical($n) === $n && !uu_view_loopback($n);
    $i = 2;
    while (preg_match('/^    access-control: (\S+) (\S+)$/D', $lines[$i], $m) === 1) {
        if (!$net($m[1]) || !in_array($m[2], UU_VIEW_ALLOW_TYPES, true)) {
            return false;
        }
        $i++;
    }
    while (preg_match('/^    access-control-view: (\S+) ' . UU_VIEW_NAME . '$/D', $lines[$i], $m) === 1) {
        if (!$net($m[1])) {
            return false;
        }
        $i++;
    }
    if (array_slice($lines, $i, count($view)) !== $view) {
        return false;
    }
    $zone = false;
    for ($i += count($view); $i < count($lines) - 1; $i++) {
        if (preg_match('/^    local-zone: "([^"]*)" (noview|static|refuse)$/D', $lines[$i], $m) === 1) {
            if (!uu_view_zone_ok($m[1])) {
                return false;
            }
            $zone = true;
        } elseif (!$zone || preg_match('/^    local-data: ([\'"])(.*)\1$/D', $lines[$i], $m) !== 1
            || uu_view_record($m[2]) !== $m[2] || uu_view_record_line($m[2]) !== $lines[$i]) {
            return false;
        }
    }
    return true;
}

/** Whether the run wants no view file: nothing selected, or a stop the view is not kept through. */
function uu_view_file_unwanted(string $scope, bool $stopping, bool $keep): bool
{
    return $scope === 'none' || ($stopping && !$keep);
}

/**
 * Whether a view problem is the file step's to keep or clear: its own faults ("Fail closed: ..."), its reason that
 * Unbound's start did not load the file, and the planner's reasons, which it carries into the state while the plan
 * gives them. Apply's own faults (an arm's or a lift's) are not.
 */
function uu_view_step_problem(?string $problem): bool
{
    return $problem !== null && (str_starts_with($problem, 'Fail closed: ') || $problem === UU_VIEW_UNSUPPORTED
        || str_starts_with($problem, UU_VIEW_FOREIGN) || $problem === UU_VIEW_UNLOADED
        || $problem === UU_VIEW_NOT_LOADED);
}

/**
 * The file step (spec 3.2, 3.4, 3.6, 3.8), decided from the view as the snapshot read it, the planner's view share
 * (uu_plan_view()) and the state's view record as apply left it: the text to write, whether the plugin's file goes,
 * whether Unbound restarts, the line the restart (or dry run) logs, and the view record once all of it has run. The
 * plugin writes and deletes only its own file in /usr/local/etc/unbound.opnsense.d, never the copy in
 * /var/unbound/etc, which core's start empties and refills: the copy goes with core's restart.
 * - A stop the view is kept through (an upgrade's, a tick of the removal): nothing, the record as it is.
 * - No file wanted (nothing selected, or any other stop): the file deleted and, while a copy with node lines is
 *   loaded, Unbound restarted so the copy goes too; refuse none, and no problem but this run's. File and copy are
 *   held, so the next tick reads the view and lifts it, while the view may still refuse: the record
 *   says armed after apply (a lift that failed records it) and this run's read did not show the view without the
 *   refuse of "." (it showed the refuse, or got no answer: silent, or Unbound down); or a stop could not restore (it
 *   stays in tunnel mode). The record, not the read before apply: a lift that took (a removal's) deletes at once.
 * - A view the plugin does not own in Unbound's configuration, or an Unbound without view commands: nothing written,
 *   the file deleted, and the planner's reason.
 * - Unbound not running (the planner's stop action without a stop reason is no stop of the plugin), or a selected set
 *   with no net (its interfaces have no address): the file kept, for Unbound's next start.
 * - Else the file rendered from core's ACL nodes and Unbound's zones and records, only from reads that all answered,
 *   only when the text passes its shape check and fits what the plugin reads back (UU_FILE_MAX_BYTES; else the file
 *   kept, and why), and written when its bytes differ. A record the file cannot carry (uu_view_unwritable()) is left
 *   to the reconcile, and counted in the problem.
 * Unbound restarts only when the file on disk after the step (no file: no node lines) names other ACL nodes than the
 * copy Unbound loaded, while it runs and is enabled, and never twice for the same node lines (restarted holds their
 * hash until the copy holds them): a start that did not load them, or did not drop a deleted file's copy, is reported,
 * not repeated. The restart is the remedy for the planner's
 * "restart Unbound to load the view", and refuse is then armed (the file's refuse of "."), or none without a file. The
 * problem is this run's reason, else apply's fault (uu_view_step_problem() says which are not the step's). Dry run
 * writes, deletes and restarts nothing: its line says what would be done. Pure.
 *
 * @param array{scope: string, nets: list<string>, notes: list<string>, acl: ?array{nodes: list<array{net: string,
 *     action: string}>, foreign: list<string>}, zones: ?array<string, string>, data: ?list<string>, loaded: string,
 *     view_zones: array<string, string>, view_data: list<string>, file: ?string, copy: ?string,
 *     file_present: bool} $view
 * @param array{active: bool, armed: ?bool, keep: bool, zones: array<string, string>,
 *     mirror: array<string, list<string>>, problem: ?string} $planView
 * @param array{refuse: string, scope: string, nets: list<string>, problem: ?string, restarted: ?string} $record
 *     the state's view record as apply left it
 * @param string $mode the state's mode as apply left it
 * @param bool $stopping uu_plan_stop_reason() is not null
 * @return array{write: ?string, delete: bool, restart: bool, line: ?string,
 *     record: array{refuse: string, scope: string, nets: list<string>, problem: ?string, restarted: ?string}}
 */
function uu_view_file_step(array $view, array $planView, array $record, string $mode, bool $unboundRunning,
    bool $unboundEnabled, bool $dry, bool $stopping, bool $cacheflush): array
{
    $step = ['write' => null, 'delete' => false, 'restart' => false, 'line' => null, 'record' => $record];
    if ($stopping && $planView['keep']) {
        return $step;
    }
    $problem = fn (?string $reason): ?string => $reason
        ?? (uu_view_step_problem($record['problem']) ? null : $record['problem']);
    $step['record']['scope'] = $view['scope'];
    $step['record']['nets'] = uu_view_refused_nets($view['file']);
    $step['record']['problem'] = $problem(null);
    $exists = $view['file_present'] || $view['copy'] !== null;
    $unwanted = uu_view_file_unwanted($view['scope'], $stopping, $planView['keep']);
    $foreign = $view['acl']['foreign'] ?? [];
    $write = null;
    $skipped = 0;
    if ($unwanted) {
        /* the record says armed after apply (a lift that failed, or none tried), unless this run's read showed the
         * view without the refuse of "."; a read that got no answer (silent, Unbound down) does not show it */
        $refused = $record['refuse'] === 'armed'
            && ($planView['armed'] === true || in_array($view['loaded'], ['silent', 'skipped'], true));
        if ($exists && ($refused || ($stopping && $mode === 'tunnel'))) {
            return $step;
        }
        $after = null;
        $delete = $view['file_present'];
        $reason = null;
    } elseif ($view['loaded'] === 'unsupported' || $foreign !== []) {
        $after = null;
        $delete = $view['file_present'];
        $reason = $planView['problem'];
    } elseif (!$unboundRunning || ($view['scope'] === 'selected' && $view['nets'] === [])) {
        return $step;
    } else {
        if ($view['acl'] === null || $view['zones'] === null || $view['data'] === null) {
            $unread = array_keys(array_filter(['access-control lines' => $view['acl'], 'local zones' => $view['zones'],
                'local data' => $view['data']], fn (?array $read): bool => $read === null));
            $last = array_pop($unread);
            $what = ($unread === [] ? '' : implode(', ', $unread) . ' and ') . $last;
            $step['record']['problem'] = $problem($planView['problem']
                ?? "Fail closed: the view file was kept (Unbound's $what could not be read)");
            return $step;
        }
        $mirror = uu_view_mirror($view['zones'], $view['data']);
        $after = uu_view_render(uu_view_nodes($view['nets'], $view['acl']['nodes']), $view['zones'], $mirror);
        $kept = match (true) {
            strlen($after) > UU_FILE_MAX_BYTES => 'the rendered file is larger than 1 MiB',
            !uu_view_text_ok($after) => 'the rendered file failed its shape check',
            default => null,
        };
        if ($kept !== null) {
            $step['record']['problem'] = $problem($planView['problem']
                ?? "Fail closed: the view file was kept ($kept)");
            return $step;
        }
        $write = $after === $view['file'] ? null : $after;
        $delete = false;
        $reason = $planView['problem'];
        $skipped = count(uu_view_unwritable($mirror));
    }
    /* one rule for every restart: the node lines of the file on disk after the step (none without a file) against
     * the copy's, which Unbound loaded; core's start empties and refills /var/unbound/etc, so a restart is also what
     * takes a deleted file's copy away */
    $nodes = uu_view_node_lines($after);
    $hash = hash('sha256', implode("\n", $nodes));
    $differs = $nodes !== uu_view_node_lines($view['copy']);
    $restart = $unboundRunning && $unboundEnabled && $differs;
    $restarted = $differs ? $record['restarted'] : null;
    $render = !$unwanted && $view['loaded'] !== 'unsupported' && $foreign === [];
    if ($restart && $record['restarted'] === $hash) {
        /* this run would restart for the node lines the last restart was for, and the copy still differs */
        $restart = false;
        $reason = $render ? UU_VIEW_NOT_LOADED : ($unwanted ? UU_VIEW_NOT_DROPPED : $reason);
    } elseif ($restart && !$dry) {
        $restarted = $hash;
        $reason = $render ? null : $reason;
    }
    if ($reason === null && $skipped > 0) {
        $reason = "Fail closed: $skipped local record(s) could not be copied into the view";
    }
    $list = function (?string $file): string {
        $nets = uu_view_refused_nets($file);
        return $nets === [] ? 'none' : implode(', ', $nets);
    };
    $change = 'the refused nets changed (' . $list($view['copy']) . ' -> ' . $list($after) . ')';
    /* with no file wanted the view no longer refuses (else it was held above): nothing is armed, and only this run's
     * reason is left to report */
    $final = $unwanted ? ['refuse' => 'none', 'scope' => $view['scope'], 'nets' => [], 'problem' => $reason,
        'restarted' => $restarted] : null;
    if ($dry) {
        $would = [];
        if ($write !== null) {
            $would[] = 'would write the view file';
        }
        if ($delete) {
            $would[] = 'would delete the view file';
        }
        if ($restart) {
            $would[] = "$change: would restart Unbound"
                . ($cacheflush ? '; the cache would be flushed (cacheflush is on)' : '');
        }
        $step['line'] = $would === [] ? null : '[dry] fail closed: ' . implode('; ', $would);
        $step['record']['problem'] = $problem($reason);
        if ($final !== null && $would === []) {
            $step['record'] = $final;
        }
        return $step;
    }
    return [
        'write' => $write,
        'delete' => $delete,
        'restart' => $restart,
        'line' => $restart ? "fail closed: $change: restarting Unbound"
            . ($cacheflush ? '; the cache is flushed (cacheflush is on)' : '') : null,
        'record' => $final ?? [
            'refuse' => $restart ? ($after === null ? 'none' : 'armed') : $record['refuse'],
            'scope' => $view['scope'],
            'nets' => uu_view_refused_nets($after),
            'problem' => $problem($reason),
            'restarted' => $restarted,
        ],
    ];
}

/**
 * The plugin's block, markers included, as uu_conf_expanded_text() spliced the loaded copy in; null when the text
 * holds no complete block.
 */
function uu_view_block(string $expanded): ?string
{
    $block = [];
    $inside = false;
    foreach (explode("\n", $expanded) as $line) {
        if (!$inside && trim($line) === UU_VIEW_BEGIN) {
            $inside = true;
        }
        if ($inside) {
            $block[] = $line;
            if (trim($line) === UU_VIEW_END) {
                return implode("\n", $block) . "\n";
            }
        }
    }
    return null;
}

/**
 * The view as it should be: the root refuse when armed, each zone its class, a mirrored zone noview while lifted, and
 * the mirrored records.
 *
 * @param array<string, string> $zones
 * @param array<string, list<string>> $mirror
 * @return array{zones: array<string, string>, data: list<string>}
 */
function uu_view_wanted(array $zones, array $mirror, bool $armed): array
{
    $wanted = $armed ? ['.' => 'refuse'] : [];
    $data = [];
    foreach ($zones as $name => $type) {
        $class = uu_view_zone_class($type);
        $wanted[$name] = $armed ? $class : 'noview';
        foreach ($mirror[$name] ?? [] as $record) {
            $data[] = $record;
        }
    }
    ksort($wanted, SORT_STRING);
    $data = array_values(array_unique($data));
    sort($data, SORT_STRING);
    return ['zones' => $wanted, 'data' => $data];
}

/**
 * What brings the loaded view to the wanted one: the zones to add or retype, the zones to remove (never "."), the
 * records to add and the names whose records must go. A name's records go together (view_local_data_remove), so a
 * name in data_remove gets its wanted records back in data_add.
 *
 * @param array<string, string> $loadedZones
 * @param list<string> $loadedData
 * @param array{zones: array<string, string>, data: list<string>} $wanted
 * @return array{set: array<string, string>, remove: list<string>, data_add: list<string>, data_remove: list<string>}
 */
function uu_view_reconcile(array $loadedZones, array $loadedData, array $wanted): array
{
    $set = [];
    foreach ($wanted['zones'] as $name => $type) {
        if ($name !== '.' && ($loadedZones[$name] ?? null) !== $type) {
            $set[$name] = $type;
        }
    }
    $remove = [];
    foreach (array_keys($loadedZones) as $name) {
        if ($name !== '.' && !isset($wanted['zones'][$name])) {
            $remove[] = (string)$name;
        }
    }
    $owner = fn (string $record): string => strtolower((string)strstr($record . ' ', ' ', true));
    $gone = [];
    foreach (array_diff($loadedData, $wanted['data']) as $record) {
        $gone[$owner($record)] = true;
    }
    $dataAdd = [];
    foreach ($wanted['data'] as $record) {
        if (!in_array($record, $loadedData, true) || isset($gone[$owner($record)])) {
            $dataAdd[] = $record;
        }
    }
    $dataRemove = array_map('strval', array_keys($gone));
    sort($dataRemove, SORT_STRING);
    return ['set' => $set, 'remove' => $remove, 'data_add' => $dataAdd, 'data_remove' => $dataRemove];
}
