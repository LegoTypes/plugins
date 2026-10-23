<?php

declare(strict_types=1);

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 * BSD 2-Clause License
 *
 * The switch notification (spec 2026-10-17 section 3.11): after an evaluation saved a new last_switch, one JSON POST
 * to the notify URL. A prompt for the receiver to read the state, so only the last switch is sent and a failure is
 * logged, never retried.
 */

require_once __DIR__ . '/constants.php';
require_once __DIR__ . '/log.php';
require_once __DIR__ . '/snapshot.php';

/**
 * Whether a run changed the last switch; a run that switched nothing keeps the saved one unchanged.
 *
 * @param ?array{at: int, from: string, to: string, reason: string} $before
 * @param ?array{at: int, from: string, to: string, reason: string} $after
 */
function uu_notify_due(?array $before, ?array $after): bool
{
    return $after !== null && $after !== $before;
}

/**
 * @param array{mode: string, member: ?string, last_switch: array{at: int, from: string, to: string, reason: string}} $st
 */
function uu_notify_body(array $st): string
{
    return json_encode($st['last_switch'] + ['mode' => $st['mode'], 'member' => $st['member']],
        JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
}

/** Whether the URL is an http or https URL, as the settings model's Mask admits it. */
function uu_notify_url_ok(string $url): bool
{
    return preg_match(UU_NOTIFY_URL_MASK, $url) === 1;
}

/**
 * What a stored notify URL means: the URL to use, or no URL and, for a value that fails the mask (a restored config,
 * a hand edit), the warning to log. An empty value is no URL and no problem.
 *
 * @return array{url: ?string, problem: ?string}
 */
function uu_notify_url_checked(string $stored): array
{
    if ($stored === '') {
        return ['url' => null, 'problem' => null];
    }
    if (!uu_notify_url_ok($stored)) {
        return ['url' => null,
            'problem' => 'notify: the stored URL is not an http or https URL; no notification is sent'];
    }
    return ['url' => $stored, 'problem' => null];
}

/** The notify URL while notify is on, else null; a stored value that fails the mask is logged once and not used. */
function uu_notify_url(): ?string
{
    uu_load_core();
    $mdl = new \OPNsense\UnboundUpstream\UnboundUpstream();
    if (!$mdl->notify->isEqual('1')) {
        return null;
    }
    $checked = uu_notify_url_checked($mdl->notify_url->getValue());
    if ($checked['problem'] !== null) {
        uu_log($checked['problem'], LOG_WARNING);
    }
    return $checked['url'];
}

/**
 * curl's protocol options: only http and https, on the request and on any redirect. The _STR keys exist from PHP 8.3
 * with curl 7.85, the bitmask keys before them.
 *
 * @return array<int, mixed>
 */
function uu_notify_protocol_options(bool $strKeys): array
{
    return $strKeys
        ? [CURLOPT_PROTOCOLS_STR => 'http,https', CURLOPT_REDIR_PROTOCOLS_STR => 'http,https']
        : [CURLOPT_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS,
            CURLOPT_REDIR_PROTOCOLS => CURLPROTO_HTTP | CURLPROTO_HTTPS];
}

/**
 * curl's options for the POST; no redirect is followed.
 *
 * @return array<int, mixed>
 */
function uu_notify_curl_options(string $body): array
{
    return uu_notify_protocol_options(defined('CURLOPT_PROTOCOLS_STR')) + [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $body,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CONNECTTIMEOUT => UU_NOTIFY_CONNECT_SECONDS,
        CURLOPT_TIMEOUT => UU_NOTIFY_TIMEOUT_SECONDS,
    ];
}

/** POST body as JSON; null on a 2xx answer, else what went wrong. */
function uu_notify_post(string $url, string $body): ?string
{
    $ch = curl_init($url);
    if ($ch === false) {
        return 'curl_init failed';
    }
    curl_setopt_array($ch, uu_notify_curl_options($body));
    if (curl_exec($ch) === false) {
        return curl_error($ch);
    }
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    return $code >= 200 && $code < 300 ? null : "HTTP $code";
}

/**
 * What a failed notification says about the receiver, after "did not reach ": its scheme, host and port and the
 * error, never the userinfo, path or query, which carry the receiver's secret. A 4xx answer points at the URL.
 */
function uu_notify_failure_line(string $url, string $error): string
{
    $parts = parse_url($url);
    if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
        $target = 'the notify URL';
    } else {
        $target = $parts['scheme'] . '://' . $parts['host'] . (isset($parts['port']) ? ':' . $parts['port'] : '');
    }
    $hint = preg_match('/^HTTP 4\d\d$/', $error) === 1 ? ' (see the Notify URL on the page)' : '';
    return "$target: $error$hint";
}

/**
 * Send the saved state's last switch to the notify URL, when notify is on. The switch is already saved, so nothing
 * here may fail the evaluation: every failure is one warning.
 *
 * @param array{mode: string, member: ?string, last_switch: array{at: int, from: string, to: string, reason: string}} $st
 */
function uu_notify_switch(array $st): void
{
    $switch = "{$st['last_switch']['from']} -> {$st['last_switch']['to']}";
    try {
        $url = uu_notify_url();
        if ($url === null) {
            return;
        }
        $error = uu_notify_post($url, uu_notify_body($st));
        if ($error !== null) {
            uu_log("notify: the switch $switch did not reach " . uu_notify_failure_line($url, $error), LOG_WARNING);
        }
    } catch (\Throwable $e) {
        uu_log("notify: the switch $switch was not sent: " . $e->getMessage(), LOG_WARNING);
    }
}
