<?php

/*
 * Copyright (C) 2026 cayossarian
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Test VM only, never a firewall: the plugin's Edit request (tunnel.php --json edit reads it on stdin) that turns a
 * tunnel's IPv6 on or off. It carries the instance's own key and endpoint, with its IPv4 tunnel addresses and ADDR6
 * added (on) or not (off), as a replacement config. wgct_api.sh runs it; the VM harness's vmh.php `edit` loads it
 * for wgct_edit_request().
 *
 * Usage: wgct_edit_request.php NAME on|off ADDR6 [MONITOR6]   prints the request's JSON
 */

/**
 * @param \SimpleXMLElement $config   config.xml
 * @param string            $name     the WireGuard instance's name
 * @param bool              $on       IPv6 on (ADDR6 added, ::/0 allowed, MONITOR6 the IPv6 monitor) or off
 * @param string            $addr6    the IPv6 tunnel address, with its prefix length
 * @param string            $monitor6 the IPv6 monitor address (on only)
 * @return string the request's JSON
 * @throws \RuntimeException when no instance of that name has a peer
 */
function wgct_edit_request(\SimpleXMLElement $config, string $name, bool $on, string $addr6, string $monitor6): string
{
    foreach ($config->OPNsense->wireguard->server->servers->server as $s) {
        if ((string)$s->name !== $name) {
            continue;
        }
        $v4 = array_values(array_filter(array_map('trim', explode(',', (string)$s->tunneladdress)),
            fn (string $t): bool => $t !== '' && !str_contains($t, ':')));
        $peer = explode(',', (string)$s->peers)[0];
        foreach ($config->OPNsense->wireguard->client->clients->client as $c) {
            if ((string)$c['uuid'] !== $peer) {
                continue;
            }
            $text = "[Interface]\nPrivateKey = {$s->privkey}\nAddress = " . implode(', ', $on ? [...$v4, $addr6] : $v4)
                . "\n\n[Peer]\nPublicKey = {$c->pubkey}\nAllowedIPs = 0.0.0.0/0" . ($on ? ', ::/0' : '')
                . "\nEndpoint = {$c->serveraddress}:{$c->serverport}\n";
            $req = ['uuid' => (string)$s['uuid'], 'config' => $text, 'ipv6' => $on];
            if ($on) {
                $req['monitor6'] = $monitor6;
            }
            return (string)json_encode($req);
        }
    }
    throw new \RuntimeException("no instance {$name} with a peer");
}

/* run as a script (not loaded by another one) */
if (realpath((string)($_SERVER['SCRIPT_FILENAME'] ?? '')) === __FILE__) {
    try {
        $x = simplexml_load_file('/conf/config.xml');
        if ($x === false) {
            throw new \RuntimeException('config.xml cannot be read');
        }
        echo wgct_edit_request($x, $argv[1] ?? '', ($argv[2] ?? '') === 'on', $argv[3] ?? '', $argv[4] ?? ''), "\n";
    } catch (\RuntimeException $e) {
        fwrite(STDERR, 'wgct_edit_request.php: ' . $e->getMessage() . "\n");
        exit(1);
    }
}
