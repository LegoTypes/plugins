#!/usr/local/bin/python3
# Copyright (C) 2026 cayossarian
# All rights reserved.
# BSD 2-Clause License

"""
Unbound's generated configuration files, read without following any link (a file the plugin trusts is read as a
regular file only), for uu_zone_texts() (lib/snapshot.php), which runs it as root:

    python3 -I zone_read.py DIR MAX_BYTES

DIR is walked from / one component at a time, each opened relative to its parent with O_NOFOLLOW, so no path is
ever resolved through a link and no device behind one is ever looked up (devfs clones tun and tap interfaces on a
lookup). The directory's *.conf entries (not the dot files, as glob(3)) are opened the same way and O_NONBLOCK,
in byte order of their names, and each regular file's first MAX_BYTES are read; a larger one is cut after its
last line end at or before MAX_BYTES, so a line the cut falls in is dropped whole and a large blocklist file still
counts. A link, anything but a regular file, and a file that cannot be opened or read are skipped and counted.
Prints one JSON object on stdout, {"texts": [...], "skipped": n}: each kept file's bytes, base64, in order, and the
number of *.conf entries skipped, and exits 0; the caller reads any skip as a configuration it could not read,
since the skipped file may hold the root zone.

    python3 -I zone_read.py --file PATH MAX_BYTES

is the same for one file: PATH's directory is reached as DIR is, the file is opened and read as an entry is, and the
JSON is the same, the text of that one file or skipped 1 (a link, anything but a regular file, a file that cannot be
opened or read, a missing file).

    python3 -I zone_read.py --conf PATH MAX_BYTES MAX_FILES MAX_TOTAL

is Unbound's configuration as Unbound reads it, in this one process (so a directory that core replaces at an Unbound
start is looked at once): PATH's text with every "include:" / "include-toplevel:" line replaced in place by the
included files' text, an included file's own includes in turn. A relative include is resolved from the last
"directory:" line read so far (PATH's directory before any), as Unbound's parser does. A path with a * ? [ { is a glob
in its last component (a wildcard in a directory component, and a leading ~, are refused): braces are expanded in
order, each alternative's matches sorted, a dot file matched only by a pattern that names it. A glob with no match is
no files, and so is a listed entry that is gone when opened (core deletes and copies back its custom files at every
start); a path without a glob that is missing is a failed read, as it is for Unbound. Each file is read as an entry is,
so a link, a directory and any file that is no regular file is a failed read, and a file over MAX_BYTES is cut after
its last line end (an option past the cut is not seen). More than MAX_FILES files or MAX_TOTAL bytes together is a
failed read, which also ends an include loop. Prints {"texts": [the one expanded text], "skipped": 0}, or
{"texts": [], "skipped": 1} for a failed read; exit 1 and usage as above. An "include:" whose path is on the next
line is not followed (core never writes that form).

In both forms a DIR (or a PATH's directory) that is not reached this way is a failed read, never an empty one ("could
not look" must not read as "no root zone", which restores as recursion over the WAN): nothing on stdout, exit 1, as for
any other failure, which names only the exception's type on stderr, never a file's text. A usage error exits 2.
"""

import base64
import fnmatch
import json
import os
import re
import stat
import sys


def open_dir(path):
    """path's directory fd, reached from / without following a link, or None."""
    if not path.startswith('/'):
        return None
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    for name in path.split('/'):
        if name == '':
            continue
        if name in ('.', '..'):
            os.close(fd)
            return None
        try:
            child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
        except OSError:
            child = None
        os.close(fd)
        if child is None:
            return None
        fd = child
    return fd


def read_entry(dir_fd, name, max_bytes):
    """The entry's first max_bytes, cut after the last line end when it is larger, or None when it is skipped."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=dir_fd)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        data = b''
        while len(data) <= max_bytes:
            chunk = os.read(fd, max_bytes + 1 - len(data))
            if chunk == b'':
                break
            data += chunk
    except OSError:
        return None
    finally:
        os.close(fd)
    if len(data) > max_bytes:
        end = data.rfind(b'\n', 0, max_bytes)
        data = data[:end + 1] if end >= 0 else b''
    return data


INCLUDE = re.compile(rb'^\s*include(?:-toplevel)?:\s*(?:"([^"]+)"|\'([^\']+)\'|([^\s#"\']+))\s*(#.*)?$')
DIRECTORY = re.compile(rb'^\s*directory:\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s#"\']+))\s*(#.*)?$')
WILD = re.compile(r'[*?\[{]')


class Refused(Exception):
    """The configuration cannot be read as a whole."""


def braces(pattern):
    """The alternatives of a pattern's braces, in order (glob(3) GLOB_BRACE); the pattern itself without any."""
    start = pattern.find('{')
    if start < 0:
        return [pattern]
    depth = 0
    cuts = [start]
    for i in range(start, len(pattern)):
        if pattern[i] == '{':
            depth += 1
        elif pattern[i] == ',' and depth == 1:
            cuts.append(i)
        elif pattern[i] == '}':
            depth -= 1
            if depth == 0:
                cuts.append(i)
                out = []
                for a, b in zip(cuts, cuts[1:]):
                    out.extend(braces(pattern[:start] + pattern[a + 1:b] + pattern[i + 1:]))
                return out
    return [pattern]


def missing(dir_fd, name):
    """Whether name is not in the directory at all (a link is there, whatever it points at)."""
    try:
        os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return True
    except OSError:
        return False
    return False


def includes(target, cwd):
    """The files an include names, as (path, may_be_gone) in Unbound's order."""
    if target.startswith('~'):
        raise Refused()
    out = []
    magic = WILD.search(target) is not None
    for pattern in braces(target):
        pattern = os.path.normpath(os.path.join(cwd, pattern))
        directory, base = os.path.split(pattern)
        if WILD.search(directory) or '/' in base:
            raise Refused()
        if not magic or not re.search(r'[*?\[]', base):
            out.append((pattern, magic))
            continue
        dir_fd = open_dir(directory)
        if dir_fd is None:
            if os.path.lexists(directory):
                raise Refused()
            continue
        try:
            names = sorted(n for n in os.listdir(dir_fd)
                           if fnmatch.fnmatchcase(n, base) and (base.startswith('.') or not n.startswith('.')))
        finally:
            os.close(dir_fd)
        out.extend((directory + '/' + n, True) for n in names)
    return out


def read_conf(path, max_bytes, state):
    """path's text with its includes spliced in; state holds the files and bytes so far and the current directory."""
    state['files'] += 1
    directory, name = os.path.split(path)
    dir_fd = open_dir(directory) if name not in ('', '.', '..') else None
    if dir_fd is None:
        raise Refused()
    try:
        data = read_entry(dir_fd, os.fsencode(name), max_bytes)
    finally:
        os.close(dir_fd)
    if data is None:
        raise Refused()
    state['bytes'] += len(data)
    if state['files'] > state['max_files'] or state['bytes'] > state['max_total']:
        raise Refused()
    out = []
    lines = data.split(b'\n')
    if lines[-1] == b'':
        lines.pop()
    for line in lines:
        m = INCLUDE.match(line)
        if m is not None:
            target = os.fsdecode(m.group(1) or m.group(2) or m.group(3))
            for file, gone_ok in includes(target, state['cwd']):
                try:
                    out.append(read_conf(file, max_bytes, state))
                except Refused:
                    if not gone_ok or not entry_gone(file):
                        raise
            continue
        m = DIRECTORY.match(line)
        if m is not None:
            value = os.fsdecode(m.group(1) or m.group(2) or m.group(3) or b'')
            state['cwd'] = os.path.normpath(os.path.join(state['cwd'], value))
        out.append(line + b'\n')
    return b''.join(out)


def entry_gone(path):
    """Whether path's directory is reached and has no such entry."""
    directory, name = os.path.split(path)
    dir_fd = open_dir(directory)
    if dir_fd is None:
        return not os.path.lexists(directory)
    try:
        return missing(dir_fd, os.fsencode(name))
    finally:
        os.close(dir_fd)


def main_conf(path, max_bytes, max_files, max_total):
    """The --conf form: the expanded text, or skipped 1."""
    state = {'files': 0, 'bytes': 0, 'cwd': os.path.dirname(path), 'max_files': max_files, 'max_total': max_total}
    try:
        text = read_conf(path, max_bytes, state)
    except Refused:
        sys.stdout.write(json.dumps({'texts': [], 'skipped': 1}) + '\n')
        return 0
    sys.stdout.write(json.dumps({'texts': [base64.b64encode(text).decode('ascii')], 'skipped': 0}) + '\n')
    return 0


def main_file(path, max_bytes):
    """The --file form: the one file as the directory form prints it, or exit 1 when its directory is not reached."""
    directory, name = os.path.split(path)
    if name in ('', '.', '..'):
        sys.stderr.write('zone_read.py: PATH names no file\n')
        return 1
    dir_fd = open_dir(directory)
    if dir_fd is None:
        sys.stderr.write('zone_read.py: PATH\'s directory not reached without following a link\n')
        return 1
    try:
        data = read_entry(dir_fd, os.fsencode(name), max_bytes)
    finally:
        os.close(dir_fd)
    texts = [] if data is None else [base64.b64encode(data).decode('ascii')]
    sys.stdout.write(json.dumps({'texts': texts, 'skipped': 1 if data is None else 0}) + '\n')
    return 0


def main(argv):
    if len(argv) == 6 and argv[1] == '--conf' and all(a.isdigit() for a in argv[3:]):
        return main_conf(argv[2], int(argv[3]), int(argv[4]), int(argv[5]))
    if len(argv) == 4 and argv[1] == '--file' and argv[3].isdigit():
        return main_file(argv[2], int(argv[3]))
    if len(argv) != 3 or not argv[2].isdigit():
        sys.stderr.write('usage: zone_read.py DIR MAX_BYTES | --file PATH MAX_BYTES | '
                         '--conf PATH MAX_BYTES MAX_FILES MAX_TOTAL\n')
        return 2
    max_bytes = int(argv[2])
    dir_fd = open_dir(argv[1])
    if dir_fd is None:
        sys.stderr.write('zone_read.py: DIR not reached without following a link\n')
        return 1
    texts = []
    skipped = 0
    try:
        names = sorted((os.fsencode(n) for n in os.listdir(dir_fd)
                        if not n.startswith('.') and fnmatch.fnmatchcase(n, '*.conf')))
        for name in names:
            data = read_entry(dir_fd, name, max_bytes)
            if data is None:
                skipped += 1
            else:
                texts.append(base64.b64encode(data).decode('ascii'))
    finally:
        os.close(dir_fd)
    sys.stdout.write(json.dumps({'texts': texts, 'skipped': skipped}) + '\n')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv))
    except Exception as e:
        sys.stderr.write('zone_read.py: %s\n' % type(e).__name__)
        sys.exit(1)
