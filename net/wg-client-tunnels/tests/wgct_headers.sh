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
# Header test, three parts. Every file of the plugin that carries a copyright line names the handle only. Every *.php,
# *.inc, *.sh and *.volt file under src and tests, and the config syshook, holds the copyright line followed by the
# full BSD 2-Clause text, compared with the comment leader stripped. The three package scripts hold printable ASCII
# only. POSIX sh, find, grep and sed, so it runs on the Mac and on the test VM.
#
# Usage: wgct_headers.sh /path/to/net/wg-client-tunnels

set -u
D="$1"
key='Copyright [(]C[)]'
want='^ ?[#*]? ?Copyright \(C\) 2026 cayossarian$'
tmp=$(mktemp -d "${TMPDIR:-/tmp}/wgct_headers.XXXXXX")
trap 'rm -rf "$tmp"' EXIT
pass=0
fail=0

files=$(find "$D" -type f -exec grep -l "$key" {} + | sort)
for f in $files; do
    if grep "$key" "$f" | grep -v -E "$want" | grep -q .; then
        fail=$((fail + 1)); echo "[FAIL] headers: $f"
    else
        pass=$((pass + 1)); echo "[PASS] headers: $f"
    fi
done
if [ "$((pass + fail))" = 0 ]; then
    echo "[FAIL] headers: no file under $D holds a copyright line"
    fail=1
fi

cat > "$tmp/want" <<'EOF'
Copyright (C) 2026 cayossarian
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,
INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
EOF
n=$(wc -l < "$tmp/want")

# The full text, one file at a time: the copyright line and the lines after it, comment leader stripped, must equal
# the text. A failure names the first line of the text that the file lacks.
set_files=$(find "$D/src" "$D/tests" -type f \( -name '*.php' -o -name '*.inc' -o -name '*.sh' -o -name '*.volt' \) | sort)
syshook=$(find "$D/src/etc/rc.syshook.d" -type f | sort)
for f in $set_files $syshook; do
    sed -n '/Copyright [(]C[)] 2026 cayossarian$/,$p' "$f" | head -n "$n" | sed -E 's/^ ?[#*]? ?//' > "$tmp/got"
    if [ ! -s "$tmp/got" ]; then
        fail=$((fail + 1)); echo "[FAIL] headers: $f (no copyright line)"
    elif cmp -s "$tmp/want" "$tmp/got"; then
        pass=$((pass + 1)); echo "[PASS] headers: $f"
    else
        miss=$(grep -v -x -F -f "$tmp/got" "$tmp/want" | grep . | head -n 1)
        [ -n "$miss" ] || miss='lines out of order'
        fail=$((fail + 1)); echo "[FAIL] headers: $f ($miss)"
    fi
done

# Package scripts: printable ASCII, space, tab and newline only.
for s in +PRE_DEINSTALL.pre +POST_DEINSTALL.post +POST_INSTALL.pre; do
    f="$D/$s"
    if [ ! -f "$f" ]; then
        fail=$((fail + 1)); echo "[FAIL] headers: $f is missing"
        continue
    fi
    hits=$(LC_ALL=C grep -n '[^[:print:][:blank:]]' "$f" | cut -d: -f1)
    if [ -z "$hits" ]; then
        pass=$((pass + 1)); echo "[PASS] headers: package scripts are printable ASCII: $s"
    else
        for l in $hits; do
            fail=$((fail + 1)); echo "[FAIL] headers: $f:$l is not printable ASCII"
        done
    fi
done

echo "headers: $pass/$((pass + fail)) passed"
[ "$fail" = 0 ]
