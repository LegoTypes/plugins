#!/bin/sh

# Copyright (C) 2026 cayossarian
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
# INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# Exact reads of the route set for the shell tests, sourced from the test's own directory. A test that judges an
# address or a device with a substring match is satisfied by a decoy (fd00::91:10 for fd00::91:1, lo91 for lo9), so
# every read here compares whole fields.

# The device a host route to exactly $1 leaves by; nothing when $1 is reached by a network or default route,
# or not at all.
dev_of() {
    route -n get -inet6 "$1" 2>/dev/null | awk -v ip="$1" '$1 == "destination:" { d = $2 } $1 == "interface:" { i = $2 } END { if (d == ip) print i }'
}

# Exit 0 when device $1 holds exactly the IPv6 address $2 (any %zone and the prefix length are not compared).
inet6_on() {
    ifconfig "$1" inet6 | awk -v w="$2" '$1 == "inet6" { split($2, a, "%"); if (a[1] == w) f = 1 } END { exit !f }'
}
