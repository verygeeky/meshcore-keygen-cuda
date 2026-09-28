#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Bengt-Erik Norum
"""Independently check a key produced by meshcore-keygen(-fast).

Uses only the Python standard library: a small, slow, textbook Ed25519
implementation that shares no code with the CUDA generators. It checks that

  * the 64-byte private key is clamp(SHA-512(seed))    (when a seed is given)
  * the public key is derived from the private key's first 32 bytes, the way
    MeshCore's ed25519_derive_pub() does it
  * the public key does not start with 00 or FF (MeshCore rejects those)
  * the public key starts with the expected prefix     (when --prefix is given)

Usage:
  ./meshcore-keygen-fast C0FFEE | ./check_key.py --prefix C0FFEE
  ./check_key.py --public <64 hex> --private <128 hex> [--seed <64 hex>]
"""
import argparse
import hashlib
import sys

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _recover_x(y, sign):
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P) % P
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P:
        x = x * SQRT_M1 % P
    if x & 1 != sign:
        x = P - x
    return x


_BY = 4 * pow(5, P - 2, P) % P
BASE = (_recover_x(_BY, 0), _BY, 1, _recover_x(_BY, 0) * _BY % P)  # extended coords


def _add(p, q):
    x1, y1, z1, t1 = p
    x2, y2, z2, t2 = q
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * t1 * t2 * D % P
    d = 2 * z1 * z2 % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _scalarmult(s, pt):
    acc = (0, 1, 1, 0)
    while s:
        if s & 1:
            acc = _add(acc, pt)
        pt = _add(pt, pt)
        s >>= 1
    return acc


def pub_from_private(priv: bytes) -> bytes:
    """Public key from the first 32 bytes of an expanded (clamped) private key."""
    x, y, z, _ = _scalarmult(int.from_bytes(priv[:32], "little"), BASE)
    zi = pow(z, P - 2, P)
    x, y = x * zi % P, y * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def expand_seed(seed: bytes) -> bytes:
    """MeshCore / orlp-ed25519 private key: clamp(SHA-512(seed))."""
    h = bytearray(hashlib.sha512(seed).digest())
    h[0] &= 248
    h[31] &= 63
    h[31] |= 64
    return bytes(h)


def check(public: str, private: str, seed: str | None = None, prefix: str | None = None) -> list[str]:
    """Return a list of problems (empty means the key is good)."""
    errs = []
    try:
        pub, priv = bytes.fromhex(public), bytes.fromhex(private)
    except ValueError:
        return ["public/private key is not valid hex"]
    if len(pub) != 32:
        errs.append(f"public key is {len(pub)} bytes, expected 32")
    if len(priv) != 64:
        errs.append(f"private key is {len(priv)} bytes, expected 64")
    if errs:
        return errs
    if seed is not None and expand_seed(bytes.fromhex(seed)) != priv:
        errs.append("private key is not clamp(SHA-512(seed))")
    if pub_from_private(priv) != pub:
        errs.append("public key does not match the private key")
    if pub[0] in (0x00, 0xFF):
        errs.append("public key starts with 00 or FF; MeshCore will refuse it")
    if prefix and not public.lower().startswith(prefix.lower()):
        errs.append(f"public key does not start with {prefix}")
    return errs


def parse_output(text: str) -> dict:
    """Pull 'Public key', 'Private key' and 'Seed' out of the generator's output."""
    out = {}
    for line in text.replace("\r", "\n").splitlines():
        label, sep, value = line.partition(":")
        if not sep:
            continue
        key = {"Public key": "public", "Private key": "private", "Seed": "seed"}.get(label.strip())
        if key:
            out[key] = value.strip()
    return out


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--public")
    ap.add_argument("--private")
    ap.add_argument("--seed")
    ap.add_argument("--prefix")
    a = ap.parse_args()
    if a.public or a.private:
        if not (a.public and a.private):
            ap.error("--public and --private go together")
        vals = {"public": a.public, "private": a.private, "seed": a.seed}
    else:
        vals = parse_output(sys.stdin.read())
        if "public" not in vals or "private" not in vals:
            sys.exit("no key found on stdin (did the generator finish?)")
    errs = check(vals["public"], vals["private"], vals.get("seed"), a.prefix)
    for e in errs:
        print("FAIL:", e)
    if errs:
        sys.exit(1)
    print(f"OK: {vals['public'][:16]}... is a valid MeshCore keypair")


if __name__ == "__main__":
    main()
