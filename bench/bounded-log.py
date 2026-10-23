#!/usr/bin/env python3
"""Appends stdin to PATH; when PATH would pass MAX_BYTES it becomes PATH.1 (the previous .1 is
dropped) and a new PATH starts. A node's log then stays under 2 * MAX_BYTES however long a
campaign runs, below the campaign's per-file limit (2026-10-16: a 23 h soak wrote a 128 MiB
node log and every node died of SIGXFSZ).

    bounded-log.py PATH MAX_BYTES
"""
import os
import sys


def main():
    path, limit = sys.argv[1], int(sys.argv[2])
    out = open(path, "ab")
    size = out.tell()
    for line in sys.stdin.buffer:
        if size and size + len(line) > limit:
            out.close()
            os.replace(path, path + ".1")
            out = open(path, "ab")
            size = 0
        out.write(line)
        out.flush()
        size += len(line)


if __name__ == "__main__":
    main()
