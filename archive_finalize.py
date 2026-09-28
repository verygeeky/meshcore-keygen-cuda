#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Bengt-Erik Norum
"""Archive a key from a saved generator log.

Use this when you ran meshcore-keygen-fast by hand (for a long search, say) and
kept its output in a file. It checks the key and writes the same JSON as
archive_gen.py.

Usage:  ./archive_finalize.py <logfile> <prefix>
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import archive_gen  # noqa: E402
import check_key  # noqa: E402


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    logfile, prefix = sys.argv[1], sys.argv[2]
    with open(logfile, errors="replace") as fh:
        vals = check_key.parse_output(fh.read())
    if "public" not in vals:
        print(f"[{prefix}] no key in {logfile} (was the search stopped early?)")
        return 1
    path = archive_gen.save(prefix, vals)
    if not path:
        return 1
    n = len(archive_gen.update_index())
    print(f"[{prefix}] ARCHIVED  pub={vals['public']}  -> {os.path.relpath(path)}  [archive: {n}]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
