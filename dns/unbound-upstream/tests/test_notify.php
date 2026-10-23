<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The switch notification (spec section 3.11): when one is due, and its body.
 */

require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/selftest.php';
require_once __DIR__ . '/../src/opnsense/scripts/OPNsense/UnboundUpstream/lib/notify.php';

uu_register_suite('notify', function (): int {
    $t = ['fail' => 0, 'total' => 0];
    $a = ['at' => 1000, 'from' => 'fallback', 'to' => 'wg-a', 'reason' => 'wg-a usable for 120 s'];
    $b = ['at' => 1060, 'from' => 'wg-a', 'to' => 'fallback', 'reason' => 'wg-a: settled down'];

    uu_check($t, 'due: a first switch, and a switch that replaced another',
        uu_notify_due(null, $a) && uu_notify_due($a, $b));
    uu_check($t, 'due: not when the run kept the saved switch, nor with none at all',
        !uu_notify_due($a, $a) && !uu_notify_due(null, null));
    uu_check($t, 'due: a switch back to the same place at a later time is a new switch',
        uu_notify_due($a, ['at' => 1200] + $a));

    $body = json_decode(uu_notify_body(['mode' => 'fallback', 'member' => null, 'last_switch' => $b]), true);
    uu_check($t, 'body: the last switch, then the saved mode and member, as JSON',
        $body === ['at' => 1060, 'from' => 'wg-a', 'to' => 'fallback', 'reason' => 'wg-a: settled down',
            'mode' => 'fallback', 'member' => null]);
    uu_check($t, 'body: a tunnel switch carries its member',
        json_decode(uu_notify_body(['mode' => 'tunnel', 'member' => 'wg-a', 'last_switch' => $a]), true)['member']
            === 'wg-a');

    $opts = uu_notify_curl_options('{}');
    uu_check($t, 'curl: only http and https, on the first request and on a redirect; no redirect is followed',
        array_intersect_key($opts, uu_notify_protocol_options(defined('CURLOPT_PROTOCOLS_STR')))
            === uu_notify_protocol_options(defined('CURLOPT_PROTOCOLS_STR')) && $opts[CURLOPT_FOLLOWLOCATION] === false);
    uu_check($t, 'curl: the string arm sets both keys to http,https',
        !defined('CURLOPT_PROTOCOLS_STR') || uu_notify_protocol_options(true)
            === [CURLOPT_PROTOCOLS_STR => 'http,https', CURLOPT_REDIR_PROTOCOLS_STR => 'http,https']);
    uu_check($t, 'curl: the bitmask arm sets both keys to http and https only',
        uu_notify_protocol_options(false) === [CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS]);
    uu_check($t, 'curl: the body is posted and the two timeouts are the constants',
        $opts[CURLOPT_POSTFIELDS] === '{}' && $opts[CURLOPT_CONNECTTIMEOUT] === UU_NOTIFY_CONNECT_SECONDS
            && $opts[CURLOPT_TIMEOUT] === UU_NOTIFY_TIMEOUT_SECONDS);
    uu_check($t, 'url_ok: refuses file, gopher and a URL with a space',
        !uu_notify_url_ok('file:///etc/passwd') && !uu_notify_url_ok('gopher://198.51.100.20/')
            && !uu_notify_url_ok('http://198.51.100.20/a b'));
    uu_check($t, 'url_ok: accepts http with a port and path, and https with userinfo',
        uu_notify_url_ok('http://198.51.100.20:8123/api/webhook/example')
            && uu_notify_url_ok('https://user:pw@198.51.100.20/x'));

    $bad = 'file:///etc/passwd';
    uu_check($t, 'checked: a stored value that fails the mask gives no URL and the warning text',
        uu_notify_url_checked($bad) === ['url' => null,
            'problem' => 'notify: the stored URL is not an http or https URL; no notification is sent']);
    uu_check($t, 'checked: a good value is the URL with no problem; an empty one is neither',
        uu_notify_url_checked('https://198.51.100.20/x') === ['url' => 'https://198.51.100.20/x', 'problem' => null]
            && uu_notify_url_checked('') === ['url' => null, 'problem' => null]);

    uu_check($t, 'failure line: a 4xx answer names scheme, host and port, and points at the Notify URL',
        uu_notify_failure_line('http://198.51.100.20:8123/api/webhook/example', 'HTTP 404')
            === 'http://198.51.100.20:8123: HTTP 404 (see the Notify URL on the page)');
    uu_check($t, 'failure line: HTTP 500 and a curl error get no hint; an IPv6 host keeps brackets and port',
        uu_notify_failure_line('http://198.51.100.20/x', 'HTTP 500') === 'http://198.51.100.20: HTTP 500'
            && uu_notify_failure_line('https://198.51.100.20/x', 'Connection refused')
                === 'https://198.51.100.20: Connection refused'
            && uu_notify_failure_line('https://[2001:db8::20]:8123/x', 'Connection refused')
                === 'https://[2001:db8::20]:8123: Connection refused');
    $line = uu_notify_failure_line('https://user:secret@198.51.100.20:8123/api/webhook/x?t=secret', 'HTTP 403');
    uu_check($t, 'failure line: userinfo, path and query never appear',
        $line === 'https://198.51.100.20:8123: HTTP 403 (see the Notify URL on the page)'
            && !str_contains($line, 'user') && !str_contains($line, 'secret') && !str_contains($line, 'webhook'));
    uu_check($t, 'failure line: a URL parse_url cannot split is named as the notify URL',
        uu_notify_failure_line('http:///x', 'HTTP 404') === 'the notify URL: HTTP 404 (see the Notify URL on the page)');

    return uu_tally_report('notify', $t);
});
