# meshcore-keygen-cuda

A CUDA vanity key generator for [MeshCore](https://github.com/meshcore-dev/MeshCore)
nodes. Pick a hex prefix, and it searches Ed25519 keypairs on your NVIDIA GPU
until it finds one whose public key starts with that prefix. The result is
printed in the 64-byte private-key format that MeshCore imports.

```
$ ./meshcore-keygen-fast C0FFEE
GPU: NVIDIA GeForce RTX 5090 (sm_120, 170 SMs)
self-test: OK (Ed25519 verified on device)
target prefix: C0FFEE  (24 bit, ~16777216 keys expected)
grid: 2720 blocks x 256 threads x 48 work = 33423360 keys/launch
searching...  (Ctrl-C to stop)

FOUND in 0.1s (3.34e+07 tries)

Public key  : C0FFEE1DACBD31C0...
Private key : <128 hex characters>
Seed        : <64 hex characters>

MeshCore JSON (keep it secret):
{"public_key": "C0FFEE1DACBD31C0...", "private_key": "..."}
```

It is the same idea as the browser-based MeshCore key generators (see
[Related projects](#related-projects-and-credits)), run on a GPU instead.

## Why vanity prefixes?

Every MeshCore node (companion, repeater, room server) has an Ed25519 keypair.
Its identity is the 32-byte **public key**, usually shown as 64 hex
characters. In practice the first byte matters most: when a packet's path is
recorded, each repeater is listed by the first byte of its public key
(MeshCore FAQ; `PATH_HASH_SIZE 1` in the firmware; newer firmware can use 2 or
3 bytes). `00` and `FF` are reserved, which leaves 254 usable IDs.

The usual reason to pick a prefix is to avoid collisions. Two repeaters with
the same first byte still forward packets fine, but traceroute and path
analysis can't tell them apart. The MeshCore FAQ recommends choosing a first
byte that no other repeater within about 16 km (10 miles) uses, and links a
vanity generator for doing that. The other reason is recognition: a repeater
whose key starts with `C0FFEE` is easy to spot in path lists and logs.

## How long it takes

Each hex character you add multiplies the work by 16. For an n-character
prefix you expect to try 16^n keys. That is an average: you have a 63%
chance of finding a match within that many tries, and about 95% within three
times as many.

Times below are at about 195 million keys/s, measured with
`meshcore-keygen-fast` on one RTX 5090. Your GPU will be different; the tool
prints its live rate.

| Prefix length | Expected tries | Time at ~195 M keys/s |
|---:|---:|---:|
| 2 (one byte, e.g. a repeater ID) | 256 | instant |
| 4 | 65,536 | instant (one launch, ~0.2 s) |
| 6 | 16.8 million | ~0.1-0.2 s |
| 7 | 268 million | ~1.4 s |
| 8 | 4.29 billion | ~22 s |
| 9 | 68.7 billion | ~6 min |
| 10 | 1.10 trillion | ~1.6 hours |
| 11 | 17.6 trillion | ~25 hours |
| 12 | 281 trillion | ~17 days |

A longer prefix doesn't weaken the key. The other 256 - 4n bits of the public
key and the whole private key are still random.

## Requirements

- An NVIDIA GPU and a working driver.
- The CUDA Toolkit (for `nvcc`). The default build targets `sm_120` (RTX 50
  series), which needs CUDA 12.8 or newer. For other GPUs, set `ARCH` (below).
- A C++ compiler (`g++`) for the CPU tests.
- Python 3.10 or newer for `check_key.py` and the archive helpers. They use
  only the standard library.

It has been built and tested on Linux (CUDA 13.4, RTX 5090). The generators
read `/dev/urandom`, so they won't build on Windows as they are.

## Build

```
make                  # meshcore-keygen, meshcore-keygen-fast, verify_format
make ARCH=sm_89       # RTX 40 series (sm_86 = RTX 30, sm_75 = RTX 20, ...)
make test             # CPU-only tests; no GPU needed
make gpu-test         # generate real keys on the GPU and check them
```

If `nvcc` isn't on your `PATH`, add the toolkit's `bin` directory (for example
`export PATH=/opt/cuda/bin:$PATH` on Arch, or `/usr/local/cuda/bin` elsewhere).

There are two generators:

- `meshcore-keygen-fast` is the one to use. It uses radix-2^51 field
  arithmetic and a precomputed fixed-base comb table, so each candidate costs
  about 32 point additions and one field inversion.
- `meshcore-keygen` is the reference build. Its Ed25519 code is a direct port
  of TweetNaCl and is shared with the CPU test, which keeps it easy to audit.
  It's about 50 times slower (about 3.7 M keys/s on the same card).

## Usage

```
./meshcore-keygen-fast <hexprefix>
```

The prefix is matched against the start of the public key, ignoring case.
`C0FFEE`, `c0ffee`, `0xC0FFEE` and `prefix=C0FFEE` all work. Odd lengths are
fine (`ABC` matches `ABC...`). Prefixes starting with `00` or `FF` are
refused because MeshCore would reject the key.

Ctrl-C stops a search. While it runs, the tool prints its rate, the number of
tries so far and the percentage of the expected count.

`meshcore-keygen-fast` reads three optional environment variables for tuning
the launch grid: `MCK_BLOCKS`, `MCK_THREADS` and `MCK_WORK`. The defaults
(16 blocks per SM, 256 threads, 48 keys per thread) were tuned on an RTX 5090.

### Output

| Field | Size | What it is |
|---|---|---|
| `Public key` | 32 bytes, 64 hex | The node's identity. Safe to share. |
| `Private key` | 64 bytes, 128 hex | What MeshCore stores and imports: `clamp(SHA-512(seed))`, the clamped scalar followed by the signing nonce prefix. **Secret.** |
| `Seed` | 32 bytes, 64 hex | The standard RFC 8032 Ed25519 private key the other two come from. Useful with other Ed25519 libraries. **Secret.** MeshCore doesn't take it. |

The JSON line has the same shape as the files the browser generator
downloads: `{"public_key": ..., "private_key": ...}`, in uppercase hex.

To keep keys as files, `archive_gen.py` runs the generator, checks the result
and writes `archive/<prefix>.json` with owner-only permissions:

```
./archive_gen.py C0FFEE BEEF          # writes archive/c0ffee.json, archive/beef.json
./meshcore-keygen-fast 12345678 | tee run.log
./archive_finalize.py run.log 12345678   # archive a key from a saved log
```

`archive/` and `*.json` are in `.gitignore`. Keep them that way.

## Importing the key into MeshCore

MeshCore wants the **128-character private key**, not the 64-character seed.
Keys from this tool have been imported into MeshCore nodes and work.
Changing a node's key gives it a new identity: other nodes will see a new
contact or repeater. Before you import, export or write down the old key if
you might want it back.

### Companion node, in the MeshCore app

These steps come from the
[meshcore-web-keygen README](https://github.com/agessaman/meshcore-web-keygen):

1. Connect to the node in the MeshCore app.
2. Open Settings (gear icon) and tap **Manage Identity Key**.
3. Paste the 128-character private key and tap **Import Private Key**.
4. Tap the checkmark to save.

The app can also load the JSON through **Import Config** in its settings.

### Repeater or room server, from the command line

Run this on the serial console, or remotely from the node's command-line
screen in the app after logging in as admin:

```
set prv.key <128-character private key>
reboot
```

The firmware answers `OK, reboot to apply! New pubkey: ...`, or
`Error, bad key` if the key is the wrong length or its public key starts with
`00`/`FF`. MeshCore's `cli_commands.md` says "64 hex characters" for this
command, but the firmware source (`CommonCLI.cpp`, `PRV_KEY_SIZE 64`) and the
FAQ-linked generator both use 128.

### If import is missing

Key import can be compiled out: MeshCore's `platformio.ini` enables it with
`ENABLE_PRIVATE_KEY_IMPORT` and notes that it can be turned off for more
secure builds. If your firmware doesn't offer import, that's probably why.

## Verifying keys

Keys are checked at several levels:

1. At startup, each generator computes two known public keys on the GPU
   and exits if either is wrong.
2. `make test` (CPU only) checks the reference code against known
   vectors including RFC 8032 TEST 1, compares the fast code with the
   reference on 5,000 pseudo-random seeds, and runs `verify_format` and
   `check_key.py` on the RFC key.
3. `check_key.py` is a small, slow Ed25519 written in pure Python that
   shares no code with the CUDA side. It checks that the private key is
   `clamp(SHA-512(seed))`, that it produces the public key, the prefix, and
   the `00`/`FF` rule. `make gpu-test` pipes fresh GPU output into it.

To check a key yourself:

```
./meshcore-keygen-fast BEEF | python3 check_key.py --prefix BEEF
python3 check_key.py --public <64 hex> --private <128 hex> [--seed <64 hex>]
./verify_format <128-hex private key> <64-hex public key>
```

`verify_format` does what MeshCore does on import: it derives the public key
from the first 32 bytes of the private key.

## Security

- The private key and the seed *are* the node. Anyone who has either can
  impersonate it and read its direct messages. Don't paste them into chats,
  issues, screenshots or shared shells. The tool prints them to your terminal,
  so watch out for scrollback, `tee` logs and terminal recordings.
- Generate your own key and use it for one node. Don't use a key someone
  else generated for you, and don't reuse one across nodes.
- Each run reads 256 bits from `/dev/urandom`. Candidates are
  `SHA-512(random base || counter)`, so every key found is unpredictable
  without the base, which is never written anywhere.
- The tool makes no network calls, which is the main reason to prefer a
  local tool for keys you'll use for real. The browser generators also run
  locally in the page, but you're trusting whatever code the site serves that
  day.
- The browser tools need no install and are fine for prefixes up to 6 or 7
  characters. The meshcore-web-keygen README reports 12.3 M keys/s on an M4
  Pro, about 1/16 of the RTX 5090 rate above, so an 8-character prefix takes
  minutes in the browser and seconds here. Beyond that the difference is hours.
- A remote `set prv.key` sends the new private key over the mesh inside
  the admin session. Use the serial console when you can.

## Limitations

- NVIDIA/CUDA only, and only tested on Linux with one GPU. The tool uses
  device 0.
- Prefix only. No suffixes, patterns or regexes.
- Speed is decent but not the maximum possible. Every candidate is derived
  from a fresh seed (two SHA-512s, a comb multiplication and one field
  inversion) so that every result is also a standard Ed25519 seed. Tools that
  walk the clamped scalar instead (the web generator, for example) skip the
  hashing and can batch inversions.
- A launch can't be interrupted. Ctrl-C takes effect at the next kernel
  boundary, which is well under a second for both generators.
- The Ed25519 code is only used to derive public keys. It isn't constant-time
  and isn't meant for signing.

## Related projects and credits

### MeshCore

- MeshCore firmware, by Scott Powell / rippleradios.com (MIT):
  https://github.com/meshcore-dev/MeshCore, website https://meshcore.io.
  Details on identities, path hashes, `set prv.key` and the `00`/`FF` rule
  come from its `docs/faq.md`, `docs/payloads.md`, `src/MeshCore.h`,
  `src/Identity.cpp` and `src/helpers/CommonCLI.cpp`.
- MeshCore bundles [orlp/ed25519](https://github.com/orlp/ed25519) (zlib),
  whose `ed25519_create_keypair` defines the 64-byte private-key layout used
  here.

### Browser and other MeshCore key generators

- meshcore-web-keygen by agessaman, a browser generator using Rust/WASM
  workers: https://github.com/agessaman/meshcore-web-keygen, hosted at
  https://gessaman.com/mc-keygen/ (linked from the MeshCore FAQ) and
  https://agessaman.github.io/meshcore-web-keygen/. Import instructions:
  https://gessaman.com/mc-keygen/instructions/. This project started as a
  project inspired by it, with the goal of running the same prefix search
  on a local NVIDIA GPU, fast enough to make longer prefixes practical.
- MeshCore-Private-Key-Generator by valentinvieriu, another in-browser
  generator (WASM/libsodium):
  https://github.com/valentinvieriu/MeshCore-Private-Key-Generator
- meshcore-keygen by agessaman, a Python generator:
  https://github.com/agessaman/meshcore-keygen
- Other CUDA MeshCore generators written independently of this one:
  https://github.com/kesh33w/meshcore-cuda-vanity-keygen,
  https://github.com/LeoVerto/meshcore-vanity-gpu-miner,
  https://github.com/dfrederick15/MeshcoreCudaKeygen

### Ed25519

- RFC 8032, *Edwards-Curve Digital Signature Algorithm (EdDSA)*:
  https://www.rfc-editor.org/rfc/rfc8032
- Bernstein, Duif, Lange, Schwabe, Yang, *High-speed high-security
  signatures* and the public-domain ref10 code: https://ed25519.cr.yp.to/
- TweetNaCl (public domain), the basis of `ed25519_tweet.cuh`:
  https://tweetnacl.cr.yp.to/
- curve25519-donna by Adam Langley, source of the radix-2^51 multiply/square
  formulas: https://github.com/agl/curve25519-donna
- Hisil, Wong, Carter, Dawson, *Twisted Edwards Curves Revisited*:
  https://eprint.iacr.org/2008/522

### Other Ed25519 vanity generators

Prior art; no code from these is used.

- mkp224o, Tor onion-address vanity generator (CC0):
  https://github.com/cathugger/mkp224o
- solanity, CUDA Ed25519 vanity finder for Solana addresses (Apache-2.0):
  https://github.com/ChorusOne/solanity

See `THIRD_PARTY_NOTICES.md` for licenses and notices.

## License

Copyright (C) 2026 Bengt-Erik Norum.

meshcore-keygen-cuda is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by the Free
Software Foundation, either version 3 of the License, or (at your option) any
later version. It comes with no warranty. See `LICENSE` for the full text.
