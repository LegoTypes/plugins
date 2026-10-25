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
