#!/usr/local/bin/python3
# Copyright (C) 2026 cayossarian
# All rights reserved.
# BSD 2-Clause License

"""
Unbound's generated configuration files, read without following any link (ruling R43, convention C3), for
uu_zone_texts() (lib/snapshot.php), which runs it as root:

    python3 -I zone_read.py DIR MAX_BYTES

DIR is walked from / one component at a time, each opened relative to its parent with O_NOFOLLOW, so no path is
ever resolved through a link and no device behind one is ever looked up (devfs clones tun and tap interfaces on a
lookup). The directory's *.conf entries (not the dot files, as glob(3)) are opened the same way and O_NONBLOCK,
in byte order of their names, and each regular file's first MAX_BYTES are read; a larger one is cut after its
last line end at or before MAX_BYTES (ruling R9), so a line the cut falls in is dropped whole. A link, anything
but a regular file, and a file that cannot be opened or read are skipped. Prints one JSON list on stdout: each kept
file's bytes, base64, in order, and exits 0. A DIR that is not reached this way is a failed read, never an empty
one (ruling R44: "could not look" must not read as "no root zone"): nothing on stdout, exit 1, as for any other
failure, which names only the exception's type on stderr, never a file's text. A usage error exits 2.
"""

import base64
import fnmatch
import json
import os
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


def main(argv):
    if len(argv) != 3 or not argv[2].isdigit():
        sys.stderr.write('usage: zone_read.py DIR MAX_BYTES\n')
        return 2
    max_bytes = int(argv[2])
    dir_fd = open_dir(argv[1])
    if dir_fd is None:
        sys.stderr.write('zone_read.py: DIR not reached without following a link\n')
        return 1
    texts = []
    try:
        names = sorted((os.fsencode(n) for n in os.listdir(dir_fd)
                        if not n.startswith('.') and fnmatch.fnmatchcase(n, '*.conf')))
        for name in names:
            data = read_entry(dir_fd, name, max_bytes)
            if data is not None:
                texts.append(base64.b64encode(data).decode('ascii'))
    finally:
        os.close(dir_fd)
    sys.stdout.write(json.dumps(texts) + '\n')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv))
    except Exception as e:
        sys.stderr.write('zone_read.py: %s\n' % type(e).__name__)
        sys.exit(1)
