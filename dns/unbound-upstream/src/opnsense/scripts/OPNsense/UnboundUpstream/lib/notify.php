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

/** The notify URL while notify is on, else null. */
function uu_notify_url(): ?string
{
    uu_load_core();
    $mdl = new \OPNsense\UnboundUpstream\UnboundUpstream();
    return $mdl->notify->isEqual('1') && !$mdl->notify_url->isEmpty() ? $mdl->notify_url->getValue() : null;
}

/** POST body as JSON; null on a 2xx answer, else what went wrong. */
function uu_notify_post(string $url, string $body): ?string
{
    $ch = curl_init($url);
    if ($ch === false) {
        return 'curl_init failed';
    }
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $body,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => false,
        CURLOPT_CONNECTTIMEOUT => UU_NOTIFY_CONNECT_SECONDS,
        CURLOPT_TIMEOUT => UU_NOTIFY_TIMEOUT_SECONDS,
    ]);
    if (curl_exec($ch) === false) {
        return curl_error($ch);
    }
    $code = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    return $code >= 200 && $code < 300 ? null : "HTTP $code";
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
            uu_log("notify: the switch $switch did not reach $url: $error", LOG_WARNING);
        }
    } catch (\Throwable $e) {
        uu_log("notify: the switch $switch was not sent: " . $e->getMessage(), LOG_WARNING);
    }
}
