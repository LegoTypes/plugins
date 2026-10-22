#!/bin/sh

# Copyright (C) 2026 cayossarian
# All rights reserved.
# BSD 2-Clause License
#
# Header test: every file of the plugin that carries a copyright line names the handle only. POSIX sh, find and
# grep, so it runs on the Mac and on the test VM.
#
# Usage: wgct_headers.sh /path/to/net/wg-client-tunnels

set -u
D="$1"
key='Copyright [(]C[)]'
want='^ ?[#*]? ?Copyright \(C\) 2026 cayossarian$'
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
echo "headers: $pass/$((pass + fail)) passed"
[ "$fail" = 0 ]
