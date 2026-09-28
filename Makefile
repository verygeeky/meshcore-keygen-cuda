# SPDX-License-Identifier: GPL-3.0-or-later
#
# meshcore-keygen-cuda
#
# ARCH is the GPU architecture to compile for. The default (sm_120) is the RTX 50
# series and needs CUDA >= 12.8. For other cards pick yours, for example
#   make ARCH=sm_89     # RTX 40 series
#   make ARCH=sm_86     # RTX 30 series
# or use an older arch: the driver JIT-compiles the embedded PTX for newer GPUs.
NVCC     ?= nvcc
ARCH     ?= sm_120
NVFLAGS  ?= -O3 -arch=$(ARCH)
CXX      ?= g++
CXXFLAGS ?= -O2 -Wall

BINS = meshcore-keygen meshcore-keygen-fast test_host verify_format

all: meshcore-keygen meshcore-keygen-fast verify_format

# reference generator: TweetNaCl-derived crypto, shared with the CPU test
meshcore-keygen: keygen.cu ed25519_tweet.cuh
	$(NVCC) $(NVFLAGS) keygen.cu -o $@

# optimized generator: radix-2^51 field arithmetic + fixed-base comb table
meshcore-keygen-fast: keygen_fast.cu ed25519_fast.cuh
	$(NVCC) $(NVFLAGS) keygen_fast.cu -o $@

# CPU unit test of the shared crypto; no GPU or CUDA toolkit needed
test_host: test_host.cpp ed25519_tweet.cuh ed25519_fast.cuh
	$(CXX) $(CXXFLAGS) test_host.cpp -o $@

# checks that a 64-byte MeshCore private key derives the given public key
verify_format: verify_format.cpp ed25519_tweet.cuh
	$(CXX) $(CXXFLAGS) verify_format.cpp -o $@

# RFC 8032 TEST 1, as a MeshCore 64-byte private key (clamped SHA-512 of the seed)
RFC1_SEED = 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60
RFC1_PRIV = 307c83864f2833cb427a2ef1c00a013cfdff2768d980c0a3a520f006904de94f9b4f0afe280b746a778684e75442502057b7473a03f08f96f5a38e9287e01f8f
RFC1_PUB  = d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a
PYTHON   ?= python3

# CPU-only tests: no GPU or CUDA toolkit needed
test: test_host verify_format
	./test_host
	./verify_format $(RFC1_PRIV) $(RFC1_PUB)
	$(PYTHON) check_key.py --seed $(RFC1_SEED) --private $(RFC1_PRIV) --public $(RFC1_PUB)

# end-to-end on the GPU: generate keys and check them with the independent
# pure-Python Ed25519 in check_key.py
GPU_TEST_PREFIX ?= C0FFEE
gpu-test: meshcore-keygen meshcore-keygen-fast
	./meshcore-keygen 5EED | $(PYTHON) check_key.py --prefix 5EED
	./meshcore-keygen-fast $(GPU_TEST_PREFIX) | $(PYTHON) check_key.py --prefix $(GPU_TEST_PREFIX)

clean:
	rm -f $(BINS)

.PHONY: all test gpu-test clean
