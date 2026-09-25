<?php

/*
 * Copyright (C) 2026 cayossarian (Bill Flood)
 * All rights reserved.
 * BSD 2-Clause License
 *
 * Create's inputs (spec 2026-09-24 section 6.1): the wg-quick parser, the
 * request check and the public-key derivation. Everything here except
 * wgipv6_derive_pubkey() is pure. The private and preshared keys travel only
 * in parameters marked #[\SensitiveParameter] -- PHP then leaves them out of
 * stack traces, which this box would otherwise include
 * (zend.exception_ignore_args = 0) -- and no message quotes a config line,
 * so a key cannot reach a log, the crash reporter or an API response.
 */

require_once __DIR__ . '/tunnels.php';
require_once __DIR__ . '/selftest.php';

/* core's gateway names stop at 32 characters and the IPv6 gateway adds "-ipv6" */
const WGIPV6_NAME_PATTERN = '/^[a-zA-Z0-9_-]{1,27}$/';
const WGIPV6_TUNNEL_MTU_MIN = 1280;
const WGIPV6_TUNNEL_MTU_MAX = 1420;
const WGIPV6_KEEPALIVE = '25';
/* the Create request's keys: the API form's create.<key> and the CLI's JSON */
const WGIPV6_CREATE_FIELDS = ['config', 'name', 'wan', 'monitor', 'ipv6', 'unique', 'mtu', 'template', 'nat4', 'nat6'];

/**
 * @param string $key candidate WireGuard key
 * @return bool 44 characters of strict base64 that decode to 32 bytes
 */
function wgipv6_is_wg_key(#[\SensitiveParameter] string $key): bool {
    if (strlen($key) !== 44) {
        return false;
    }
    $raw = base64_decode($key, true);
    return $raw !== false && strlen($raw) === 32;
}

/**
 * @param string $address an address with or without a prefix length
 * @return array{family: string, ip: string, cidr: string}|null null when not an IP address
 */
function wgipv6_normalize_address(string $address): ?array {
    $parts = explode('/', trim($address), 2);
    $ip = $parts[0];
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
        $family = 'inet';
        $max = 32;
    } elseif (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
        $family = 'inet6';
        $max = 128;
    } else {
        return null;
    }
    $prefix = $max;
    if (count($parts) === 2) {
        if (!ctype_digit($parts[1]) || (int)$parts[1] > $max) {
            return null;
        }
        $prefix = (int)$parts[1];
    }
    return ['family' => $family, 'ip' => $ip, 'cidr' => $ip . '/' . $prefix];
}

/**
 * Parse a wg-quick client config. Pure. Reads PrivateKey and Address from the
 * [Interface], and PublicKey, PresharedKey and Endpoint from the one [Peer].
 * DNS, MTU, AllowedIPs, PersistentKeepalive and hook lines are ignored: the
 * plugin sets those itself (spec 6.1). Messages never quote a line.
 *
 * @param string $text the config as pasted or read from a file
 * @return array{errors: list<string>, public: array{addresses: array{inet: list<string>, inet6: list<string>}, peer_pubkey: string, endpoint_ip: string, endpoint_port: string, has_psk: bool}, secret: array{privkey: string, psk: string}}
 */
function wgipv6_parse_wgquick(#[\SensitiveParameter] string $text): array {
    $errors = [];
    $public = [
        'addresses' => ['inet' => [], 'inet6' => []],
        'peer_pubkey' => '', 'endpoint_ip' => '', 'endpoint_port' => '', 'has_psk' => false,
    ];
    $secret = ['privkey' => '', 'psk' => ''];
    $section = '';
    $interfaces = 0;
    $peers = 0;
    $endpoint = '';
    $lines = preg_split('/\r\n|\r|\n/', (string)preg_replace('/^\xEF\xBB\xBF/', '', $text));
    foreach ($lines === false ? [] : $lines as $i => $raw) {
        $line = trim(explode('#', $raw, 2)[0]);
        $where = 'line ' . ($i + 1);
        if ($line === '') {
            continue;
        }
        if ($line[0] === '[') {
            $section = strtolower($line);
            if ($section === '[interface]') {
                $interfaces++;
            } elseif ($section === '[peer]') {
                $peers++;
            } else {
                $errors[] = "{$where}: unknown section";
            }
            continue;
        }
        $eq = strpos($line, '=');
        if ($eq === false) {
            $errors[] = "{$where}: not a \"Key = value\" line";
            continue;
        }
        $key = strtolower(trim(substr($line, 0, $eq)));
        $value = trim(substr($line, $eq + 1));
        if ($section === '[interface]' && $interfaces === 1) {
            if ($key === 'privatekey') {
                $secret['privkey'] = $value;
            } elseif ($key === 'address') {
                foreach (explode(',', $value) as $address) {
                    if (trim($address) === '') {
                        continue;
                    }
                    $norm = wgipv6_normalize_address($address);
                    if ($norm === null) {
                        $errors[] = "{$where}: Address is not an IP address or network";
                    } else {
                        $public['addresses'][$norm['family']][] = $norm['cidr'];
                    }
                }
            }
        } elseif ($section === '[peer]' && $peers === 1) {
            if ($key === 'publickey') {
                $public['peer_pubkey'] = $value;
            } elseif ($key === 'presharedkey') {
                $secret['psk'] = $value;
            } elseif ($key === 'endpoint') {
                $endpoint = $value;
            }
        } elseif ($section === '') {
            $errors[] = "{$where}: setting outside any section";
        }
    }
    if ($interfaces !== 1) {
        $errors[] = "exactly one [Interface] section is required, found {$interfaces}";
    }
    if ($peers !== 1) {
        $errors[] = "exactly one [Peer] section is required, found {$peers}";
    }
    if (!wgipv6_is_wg_key($secret['privkey'])) {
        $errors[] = $secret['privkey'] === '' ? 'PrivateKey is missing' : 'PrivateKey is not a WireGuard key';
    }
    if (!wgipv6_is_wg_key($public['peer_pubkey'])) {
        $errors[] = $public['peer_pubkey'] === '' ? 'the peer PublicKey is missing' : 'the peer PublicKey is not a WireGuard key';
    }
    if ($secret['psk'] !== '' && !wgipv6_is_wg_key($secret['psk'])) {
        $errors[] = 'PresharedKey is not a WireGuard key';
    }
    $public['has_psk'] = $secret['psk'] !== '';
    if (preg_match('/^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/', $endpoint, $m) === 1
        && filter_var($m[1], FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false
        && (int)$m[2] >= 1 && (int)$m[2] <= 65535) {
        $public['endpoint_ip'] = $m[1];
        $public['endpoint_port'] = (string)(int)$m[2];
    } else {
        $errors[] = $endpoint === ''
            ? 'Endpoint is missing'
            : 'Endpoint must be an IPv4 address and port; hostnames and IPv6 endpoints are not supported';
    }
    $v4 = count($public['addresses']['inet']);
    if ($v4 !== 1) {
        $errors[] = $v4 === 0 ? 'Address has no IPv4 address' : 'Address has several IPv4 addresses; exactly one is supported';
    }
    return ['errors' => $errors, 'public' => $public, 'secret' => $secret];
}

/**
 * The typed Create request, from the API form (strings) or the CLI's JSON
 * (strings, bools, ints, lists). $raw is a form/JSON boundary: its values are
 * whatever the POST or json_decode produced, so each one is type-checked here
 * rather than trusted. Pure.
 *
 * @param array $raw         keys of WGIPV6_CREATE_FIELDS. ipv6/unique: bool or '0'/'1'
 *                           (absent = the planner's default: ipv6 on exactly when the
 *                           config has an IPv6 address, unique per ruling 3);
 *                           mtu: int or digits ('' or absent = measure);
 *                           nat4/nat6: list of strings or a comma-separated string
 * @param bool  $mtuRequired the API requires an MTU; the CLI measures one when absent
 * @return array{errors: array<string, string>, req: array{name: string, wan: string, monitor: string, ipv6: ?bool, unique: ?bool, mtu: ?int, template: string, nat: array{inet: list<string>, inet6: list<string>}}, text: string}
 */
function wgipv6_create_request(#[\SensitiveParameter] array $raw, bool $mtuRequired): array {
    $errors = [];
    $str = function (string $key) use ($raw): string {
        $v = $raw[$key] ?? '';
        return is_string($v) ? trim($v) : '';
    };
    $flag = function (string $key) use ($raw): ?bool {
        $v = $raw[$key] ?? null;
        if ($v === true || $v === '1' || $v === 1) {
            return true;
        }
        if ($v === false || $v === '0' || $v === 0 || $v === '') {
            return false;
        }
        return null;
    };
    $list = function (string $key) use ($raw): array {
        $v = $raw[$key] ?? [];
        if (is_string($v)) {
            return wgipv6_split_csv($v);
        }
        $out = [];
        foreach (is_array($v) ? $v : [] as $item) {
            if (is_string($item) && trim($item) !== '') {
                $out[] = trim($item);
            }
        }
        return $out;
    };

    $text = is_string($raw['config'] ?? null) ? $raw['config'] : '';
    if (trim($text) === '') {
        $errors['config'] = 'paste the WireGuard config';
    }
    $name = $str('name');
    if (preg_match(WGIPV6_NAME_PATTERN, $name) !== 1) {
        $errors['name'] = '1 to 27 letters, digits, "_" or "-" (the IPv6 gateway adds "-ipv6" and gateway names stop at 32)';
    }
    $wan = $str('wan');
    if ($wan === '') {
        $errors['wan'] = 'choose the WAN the tunnel is bound to';
    }
    $monitor = $str('monitor');
    if (filter_var($monitor, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) === false) {
        $errors['monitor'] = 'an IPv4 address';
    }
    $mtuRaw = $raw['mtu'] ?? null;
    $mtu = null;
    if (is_int($mtuRaw)) {
        $mtu = $mtuRaw;
    } elseif (is_string($mtuRaw) && ctype_digit(trim($mtuRaw))) {
        $mtu = (int)trim($mtuRaw);
    } elseif (!($mtuRaw === null || (is_string($mtuRaw) && trim($mtuRaw) === ''))) {
        $errors['mtu'] = 'a whole number';
    }
    if ($mtu !== null && ($mtu < WGIPV6_TUNNEL_MTU_MIN || $mtu > WGIPV6_TUNNEL_MTU_MAX)) {
        $errors['mtu'] = sprintf('%d to %d', WGIPV6_TUNNEL_MTU_MIN, WGIPV6_TUNNEL_MTU_MAX);
    } elseif ($mtu === null && $mtuRequired && !isset($errors['mtu'])) {
        $errors['mtu'] = 'measure or enter the MTU';
    }
    return [
        'errors' => $errors,
        'req' => [
            'name' => $name, 'wan' => $wan, 'monitor' => $monitor,
            'ipv6' => $flag('ipv6'), 'unique' => $flag('unique'),
            'mtu' => $mtu, 'template' => $str('template'),
            'nat' => ['inet' => $list('nat4'), 'inet6' => $list('nat6')],
        ],
        'text' => $text,
    ];
}

/**
 * Our public key from the config's private key. core's gen_keypair cannot
 * derive from a supplied key, so this runs `wg pubkey` itself, with the key
 * on stdin -- never on argv, where ps would show it. Runs before any lock.
 *
 * @param string $privkey a key wgipv6_is_wg_key() accepted
 * @return string|null the public key, or null when wg rejected the key
 */
function wgipv6_derive_pubkey(#[\SensitiveParameter] string $privkey): ?string {
    $proc = proc_open(
        ['/usr/bin/wg', 'pubkey'],
        [0 => ['pipe', 'r'], 1 => ['pipe', 'w'], 2 => ['file', '/dev/null', 'w']],
        $pipes
    );
    if (!is_resource($proc)) {
        return null;
    }
    fwrite($pipes[0], $privkey . "\n");
    fclose($pipes[0]);
    $out = trim((string)stream_get_contents($pipes[1]));
    fclose($pipes[1]);
    return proc_close($proc) === 0 && wgipv6_is_wg_key($out) ? $out : null;
}

/**
 * Last line of defence for anything logged after a failure: every secret of
 * eight characters or more that occurs in $message is replaced.
 *
 * @param string       $message text about to be logged or returned
 * @param list<string> $secrets the keys in play
 * @return string
 */
function wgipv6_redact(string $message, #[\SensitiveParameter] array $secrets): string {
    foreach ($secrets as $secret) {
        if (is_string($secret) && strlen($secret) >= 8) {
            $message = str_replace($secret, '[redacted]', $message);
        }
    }
    return $message;
}

/**
 * Self-tests for the parser and the request check. Pure.
 *
 * @return int exit code, 0 when every case passes
 */
function wgipv6_wgconf_selftest(): int {
    $t = ['fail' => 0, 'total' => 0];
    $priv = base64_encode(str_repeat('A', 32));
    $peer = base64_encode(str_repeat('B', 32));
    $psk = base64_encode(str_repeat('C', 32));
    $base = "[Interface]\n# provider comment\nPrivateKey = {$priv}\nAddress = 10.2.0.2/32, 2001:db8::2:2/128\nDNS = 192.0.2.53\n\n"
        . "[Peer]\nPublicKey = {$peer}\nAllowedIPs = 0.0.0.0/0, ::/0\nEndpoint = 198.51.100.10:51820\n";
    $noKey = function (array $messages) use ($priv, $psk): bool {
        $all = implode("\n", $messages);
        return strpos($all, substr($priv, 0, 16)) === false && strpos($all, substr($psk, 0, 16)) === false;
    };

    $p = wgipv6_parse_wgquick($base);
    wgipv6_check($t, 'wgconf: provider config => both addresses, peer key, endpoint; DNS ignored',
        $p['errors'] === []
        && $p['public']['addresses'] === ['inet' => ['10.2.0.2/32'], 'inet6' => ['2001:db8::2:2/128']]
        && $p['public']['peer_pubkey'] === $peer && $p['public']['endpoint_ip'] === '198.51.100.10'
        && $p['public']['endpoint_port'] === '51820' && $p['public']['has_psk'] === false
        && $p['secret'] === ['privkey' => $priv, 'psk' => '']);

    $p = wgipv6_parse_wgquick(str_replace(', 2001:db8::2:2/128', '', $base));
    wgipv6_check($t, 'wgconf: no IPv6 address => inet6 empty, no error',
        $p['errors'] === [] && $p['public']['addresses']['inet6'] === []);

    $p = wgipv6_parse_wgquick(str_replace("Address = 10.2.0.2/32, 2001:db8::2:2/128\n", "Address = 10.2.0.2\nAddress = 2001:db8::2:2\n", $base));
    wgipv6_check($t, 'wgconf: several Address lines without prefixes => collected, /32 and /128 added',
        $p['errors'] === [] && $p['public']['addresses'] === ['inet' => ['10.2.0.2/32'], 'inet6' => ['2001:db8::2:2/128']]);

    $p = wgipv6_parse_wgquick(str_replace('Endpoint', "PresharedKey = {$psk}\nEndpoint", $base));
    wgipv6_check($t, 'wgconf: PresharedKey => kept as a secret, has_psk',
        $p['errors'] === [] && $p['secret']['psk'] === $psk && $p['public']['has_psk'] === true);

    $p = wgipv6_parse_wgquick(str_replace('198.51.100.10:51820', 'vpn.example.net:51820', $base));
    wgipv6_check($t, 'wgconf: hostname endpoint => one error',
        count($p['errors']) === 1 && strpos($p['errors'][0], 'hostnames and IPv6 endpoints are not supported') !== false);

    $p = wgipv6_parse_wgquick(str_replace('198.51.100.10:51820', '[2001:db8::10]:51820', $base));
    wgipv6_check($t, 'wgconf: IPv6 endpoint => one error', count($p['errors']) === 1);

    $p = wgipv6_parse_wgquick($base . "\n[Peer]\nPublicKey = {$peer}\nEndpoint = 198.51.100.11:51820\n");
    wgipv6_check($t, 'wgconf: two peers => refused', in_array('exactly one [Peer] section is required, found 2', $p['errors'], true));

    $p = wgipv6_parse_wgquick(str_replace("PrivateKey = {$priv}\n", '', $base));
    wgipv6_check($t, 'wgconf: no PrivateKey => refused', $p['errors'] === ['PrivateKey is missing']);

    $p = wgipv6_parse_wgquick(str_replace('10.2.0.2/32, 2001:db8::2:2/128', '10.2.0.2/32, 10.2.0.3/32', $base));
    wgipv6_check($t, 'wgconf: two IPv4 addresses => refused',
        $p['errors'] === ['Address has several IPv4 addresses; exactly one is supported']);

    $p = wgipv6_parse_wgquick(str_replace("\n", "\r\n", $base));
    wgipv6_check($t, 'wgconf: CRLF line ends => same result', $p['errors'] === [] && $p['public']['endpoint_ip'] === '198.51.100.10');

    $p = wgipv6_parse_wgquick(str_replace("PrivateKey = {$priv}", 'PrivateKey = ' . substr($priv, 0, 43), $base));
    wgipv6_check($t, 'wgconf: a key one character short => refused, and the message does not quote it',
        $p['errors'] === ['PrivateKey is not a WireGuard key'] && $noKey($p['errors']));

    /* the stray line has no "=" (padding stripped), so it is reported as a bad line -- without quoting it */
    $bad = str_replace('198.51.100.10:51820', 'nonsense', $base) . 'stray ' . rtrim($priv, '=') . "\n[Extra]\nPresharedKey = {$psk}\n";
    $p = wgipv6_parse_wgquick($bad);
    wgipv6_check($t, 'wgconf: every message for a broken config is key-free', count($p['errors']) >= 3 && $noKey($p['errors']));

    $raw = ['config' => $base, 'name' => 'tun_c', 'wan' => 'WAN_A', 'monitor' => '203.0.113.12', 'ipv6' => '1', 'unique' => '0',
            'mtu' => '1376', 'template' => '', 'nat4' => 'opt3,TailscaleNetworks', 'nat6' => ''];
    $r = wgipv6_create_request($raw, true);
    wgipv6_check($t, 'request: API form strings => typed request',
        $r['errors'] === [] && $r['text'] === $base
        && $r['req'] === ['name' => 'tun_c', 'wan' => 'WAN_A', 'monitor' => '203.0.113.12', 'ipv6' => true, 'unique' => false,
                          'mtu' => 1376, 'template' => '', 'nat' => ['inet' => ['opt3', 'TailscaleNetworks'], 'inet6' => []]]);

    $json = ['config' => $base, 'name' => 'tun_c', 'wan' => 'WAN_A', 'monitor' => '203.0.113.12', 'nat4' => ['opt3', ' ', 7]];
    $r = wgipv6_create_request($json, false);
    wgipv6_check($t, 'request: CLI JSON with ipv6/unique/mtu absent => all three null (defaults decided by the planner); non-strings dropped from lists',
        $r['errors'] === [] && $r['req']['ipv6'] === null && $r['req']['unique'] === null && $r['req']['mtu'] === null
        && $r['req']['nat']['inet'] === ['opt3']);

    $r = wgipv6_create_request($json, true);
    wgipv6_check($t, 'request: API requires the MTU', ($r['errors']['mtu'] ?? '') === 'measure or enter the MTU');

    $cases = [
        ['name of 28 characters', ['name' => str_repeat('a', 28)], 'name'],
        ['name with a dot', ['name' => 'tun.c'], 'name'],
        ['IPv6 monitor', ['monitor' => '2001:db8::1'], 'monitor'],
        ['MTU below 1280', ['mtu' => 1279], 'mtu'],
        ['MTU above 1420', ['mtu' => '1421'], 'mtu'],
        ['MTU not a number', ['mtu' => '13x6'], 'mtu'],
        ['empty config', ['config' => "  \n"], 'config'],
        ['no WAN', ['wan' => ''], 'wan'],
    ];
    foreach ($cases as [$desc, $over, $field]) {
        $r = wgipv6_create_request(array_merge($json, $over), false);
        wgipv6_check($t, "request: {$desc} => {$field} error", array_keys($r['errors']) === [$field]);
    }

    wgipv6_check($t, 'redact: a secret in a message is replaced, short and empty secrets are ignored',
        wgipv6_redact("x {$priv} y ab", [$priv, 'ab', '']) === 'x [redacted] y ab');
    wgipv6_check($t, 'is_wg_key: base64 of 32 bytes only',
        wgipv6_is_wg_key($priv) && !wgipv6_is_wg_key('abc') && !wgipv6_is_wg_key(str_repeat('!', 44))
        && !wgipv6_is_wg_key(base64_encode(str_repeat('A', 31)) . 'AAAA'));

    return wgipv6_tally_report('wgconf', $t);
}
