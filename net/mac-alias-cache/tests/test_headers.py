import os
import re
import subprocess

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
PLUGIN = "net/mac-alias-cache"
MVC = PLUGIN + "/src/opnsense/mvc/app/controllers/OPNsense/MacAliasCache/"
SCRIPTS = PLUGIN + "/src/opnsense/scripts/OPNsense/MacAliasCache/"
# Built from parts so that this file never holds the fixed marker the release grep looks for.
MARKER = "Copyright" + " (C)"
HANDLE = MARKER + " 2026 cayossarian"

# Path -> the comment prefix in front of the header line.
EXPECTED = {
    MVC + "Api/ServiceController.php": " * ",
    MVC + "IndexController.php": " * ",
    SCRIPTS + "macalias.py": "",
    SCRIPTS + "macaliascache_lib.py": "",
}

# The 22 lines of the BSD 2-Clause text that follow the handle line.
BSD_TEXT = (
    "All rights reserved.",
    "",
    "Redistribution and use in source and binary forms, with or without",
    "modification, are permitted provided that the following conditions are met:",
    "",
    "1. Redistributions of source code must retain the above copyright notice,",
    "   this list of conditions and the following disclaimer.",
    "",
    "2. Redistributions in binary form must reproduce the above copyright",
    "   notice, this list of conditions and the following disclaimer in the",
    "   documentation and/or other materials provided with the distribution.",
    "",
    "THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES,",
    "INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY",
    "AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE",
    "AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,",
    "OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF",
    "SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS",
    "INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN",
    "CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)",
    "ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE",
    "POSSIBILITY OF SUCH DAMAGE.",
)


def tracked():
    out = subprocess.run(
        ["git", "-C", ROOT, "ls-files", PLUGIN],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return out.splitlines()


def lines_of(path):
    with open(os.path.join(ROOT, path), encoding="utf-8", errors="replace") as f:
        return f.read().splitlines()


def test_only_four_files_carry_a_header_and_each_is_the_handle_only():
    found = {}
    for path in tracked():
        hits = [line for line in lines_of(path) if re.search(re.escape(MARKER), line)]
        if hits:
            found[path] = hits
    assert set(found) == set(EXPECTED)
    for path, prefix in EXPECTED.items():
        assert found[path] == [prefix + HANDLE], path


def test_no_header_line_continues_after_the_handle():
    pattern = re.compile(r"Copyright \(C\) 2026 cayossarian.")
    offenders = []
    for path in tracked():
        for number, line in enumerate(lines_of(path), 1):
            if pattern.search(line):
                offenders.append(f"{path}:{number}")
    assert offenders == []


def header_problems(lines, prefix):
    """One message per line after the handle line that is not the BSD text."""
    if prefix + HANDLE not in lines:
        return ["no handle line"]
    after = lines[lines.index(prefix + HANDLE) + 1 :]
    problems = []
    for number, text in enumerate(BSD_TEXT, 1):
        want = (prefix + text).rstrip()
        got = after[number - 1] if number <= len(after) else None
        if got != want:
            problems.append("line %d after the handle: want %r, got %r" % (number, want, got))
    return problems


def test_each_header_is_the_full_bsd_2_clause_text():
    for path, prefix in EXPECTED.items():
        assert header_problems(lines_of(path), prefix) == [], path


def test_a_cut_header_is_reported():
    for path, prefix in EXPECTED.items():
        whole = lines_of(path)
        start = whole.index(prefix + HANDLE)
        last = start + len(BSD_TEXT)
        cut = whole[:last] + whole[last + 1 :]
        assert header_problems(cut, prefix), (path, "last line removed")
        reworded = list(whole)
        reworded[start + 6] = reworded[start + 6].replace("must retain", "may retain")
        assert header_problems(reworded, prefix), (path, "condition reworded")
        spaced = list(whole)
        spaced[start + 2] += " "
        assert header_problems(spaced, prefix), (path, "blank line with trailing space")
