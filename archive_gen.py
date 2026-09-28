#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Bengt-Erik Norum
"""Generate vanity MeshCore keys and save them as MeshCore-style JSON.

For each hex prefix: run the GPU generator, check the result independently
(check_key.py, pure-Python Ed25519), and write

    archive/<prefix>.json  =  {"public_key": "<64 hex>", "private_key": "<128 hex>"}

plus archive/index.json listing prefix -> public key (no secrets in the index).
The per-prefix files hold PRIVATE KEYS: keep them out of git and off shared disks.

Usage:  ./archive_gen.py C0FFEE BEEF 5EED ...
Env:    MC_KEYGEN_BIN   generator binary (default: ./meshcore-keygen-fast)
        MC_ARCHIVE_DIR  output directory  (default: ./archive)
"""
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import check_key  # noqa: E402

KEYGEN = os.environ.get("MC_KEYGEN_BIN", os.path.join(HERE, "meshcore-keygen-fast"))
ARCHIVE = os.environ.get("MC_ARCHIVE_DIR", os.path.join(HERE, "archive"))


def update_index():
    rows = []
    for f in sorted(os.listdir(ARCHIVE)):
        if f.endswith(".json") and f != "index.json":
            with open(os.path.join(ARCHIVE, f)) as fh:
                d = json.load(fh)
            rows.append({"prefix": f[:-5], "public_key": d["public_key"]})
    with open(os.path.join(ARCHIVE, "index.json"), "w") as fh:
        json.dump(rows, fh, indent=2)
    return rows


def save(prefix: str, vals: dict) -> str | None:
    """Verify a parsed generator result and write it. Returns the path, or None."""
    errs = check_key.check(vals.get("public", ""), vals.get("private", ""),
                           vals.get("seed"), prefix)
    if errs:
        print(f"[{prefix}] REJECTED: " + "; ".join(errs), flush=True)
        return None
    os.makedirs(ARCHIVE, mode=0o700, exist_ok=True)
    path = os.path.join(ARCHIVE, prefix.lower() + ".json")
    rec = {"public_key": vals["public"].upper(), "private_key": vals["private"].upper()}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(rec, fh, indent=2)
    return path


def gen(prefix: str):
    t0 = time.time()
    r = subprocess.run([KEYGEN, prefix], capture_output=True, text=True)
    vals = check_key.parse_output(r.stdout)
    if "public" not in vals:
        print(f"[{prefix}] no key produced\n{r.stdout}\n{r.stderr}", flush=True)
        return None
    path = save(prefix, vals)
    if path:
        n = len(update_index())
        print(f"[{prefix}] OK  pub={vals['public']}  ({time.time() - t0:.0f}s)"
              f"  -> {os.path.relpath(path)}  [archive: {n}]", flush=True)
    return path


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(2)
    ok = all([gen(p) for p in sys.argv[1:]])
    sys.exit(0 if ok else 1)
