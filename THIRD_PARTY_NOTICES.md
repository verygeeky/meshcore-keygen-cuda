# Third-party notices

meshcore-keygen-cuda is licensed under the GNU General Public License,
version 3 or (at your option) any later version. See `LICENSE`.

No third-party source files are vendored. Two files adapt published
public-domain code. Other parts follow algorithms or formulas from the
sources below, and the notices are kept here. Every source listed is
public domain or under a GPL-compatible permissive license.

## TweetNaCl

- Used in: `ed25519_tweet.cuh` (SHA-512, field arithmetic, scalar-base
  multiplication and point packing, ported to CUDA/C++ and cut down to key
  derivation)
- Authors: Daniel J. Bernstein, Bernard van Gastel, Wesley Janssen, Tanja
  Lange, Peter Schwabe, Sjaak Smetsers
- Source: https://tweetnacl.cr.yp.to/
- License: public domain ("TweetNaCl is a self-contained public-domain C
  library")

## curve25519-donna (64-bit version)

- Used in: `ed25519_fast.cuh`. The `fe_mul` and `fe_sq` radix-2^51
  multiply/square formulas follow `fmul` and `fsquare` in
  `curve25519-donna-c64.c`.
- Author: Adam Langley
- Source: https://github.com/agl/curve25519-donna
- License: the header of `curve25519-donna-c64.c` reads:

  > Copyright 2008, Google Inc.
  > All rights reserved.
  >
  > Code released into the public domain.
  >
  > [...]
  >
  > Derived from public domain C code by Daniel J. Bernstein <djb@cr.yp.to>

  The repository as a whole ships this BSD-3-Clause license
  (`LICENSE.md`). It is reproduced here in case it is taken to apply. It is
  GPL-compatible either way:

  > Copyright 2008, Google Inc.
  > All rights reserved.
  >
  > Redistribution and use in source and binary forms, with or without
  > modification, are permitted provided that the following conditions are
  > met:
  >
  > * Redistributions of source code must retain the above copyright
  >   notice, this list of conditions and the following disclaimer.
  > * Redistributions in binary form must reproduce the above
  >   copyright notice, this list of conditions and the following disclaimer
  >   in the documentation and/or other materials provided with the
  >   distribution.
  > * Neither the name of Google Inc. nor the names of its
  >   contributors may be used to endorse or promote products derived from
  >   this software without specific prior written permission.
  >
  > THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  > "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  > LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  > A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
  > OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
  > SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
  > LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
  > DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
  > THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
  > (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  > OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Ed25519 reference implementation (ref10, SUPERCOP)

- Used in: `ed25519_fast.cuh`, where `fe_invert` uses the ref10 addition
  chain for z^(p-2)
- Authors: Daniel J. Bernstein, Niels Duif, Tanja Lange, Peter Schwabe,
  Bo-Yin Yang
- Source: https://ed25519.cr.yp.to/software.html
- License: public domain ("The Ed25519 software is in the public domain.")

## Algorithms and specifications (no code taken)

- RFC 8032, *Edwards-Curve Digital Signature Algorithm (EdDSA)*:
  https://www.rfc-editor.org/rfc/rfc8032. Key generation; TEST 1 is used in
  the test suite.
- Hisil, Wong, Carter, Dawson, *Twisted Edwards Curves Revisited* (2008):
  https://eprint.iacr.org/2008/522. Extended-coordinate point addition in
  `ed25519_fast.cuh`.
- FIPS 180-4 (SHA-512): round constants and initial hash values.
- MeshCore (MIT, Copyright (c) 2025 Scott Powell / rippleradios.com),
  https://github.com/meshcore-dev/MeshCore. No MeshCore code is included.
  Its behavior is matched where it matters for compatibility: the 64-byte
  private-key layout (clamped SHA-512 of the seed, as in its bundled
  orlp/ed25519 `ed25519_create_keypair`) and the rule that public keys may
  not start with `00` or `FF`.

## Build and runtime dependencies (not distributed with this repository)

| Dependency | Used for | License |
|---|---|---|
| NVIDIA CUDA Toolkit (nvcc, CUDA runtime) | building and running the GPU generators | NVIDIA CUDA Toolkit EULA (proprietary) |
| Python 3 standard library | `check_key.py`, `archive_*.py` | PSF License |
| PyNaCl (optional, manual cross-checks only) | `test_host` prints a PyNaCl one-liner | Apache-2.0 |

nvcc links the CUDA runtime into the binaries statically by default. This
repository ships source only. If you distribute compiled binaries, check
that the CUDA EULA's redistribution terms and the GPL's system-library
exception cover your case.
