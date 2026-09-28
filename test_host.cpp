// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bengt-Erik Norum
//
// test_host.cpp: compile both Ed25519 implementations as plain C++ and test
// them with no GPU needed. keygen.cu / keygen_fast.cu run the same code on the
// device.
//   1. ed25519_tweet.cuh against known vectors (incl. RFC 8032 TEST 1)
//   2. ed25519_fast.cuh (radix-2^51 + comb table) against ed25519_tweet.cuh on
//      many pseudo-random seeds, plus its short SHA-512 against the full one
//   make test
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include "ed25519_tweet.cuh"
#include "ed25519_fast.cuh"

static void tohex(const u8 *b,int n,char *o){
  static const char*h="0123456789abcdef";
  for(int i=0;i<n;i++){ o[2*i]=h[b[i]>>4]; o[2*i+1]=h[b[i]&15]; } o[2*n]=0;
}

static int check(const char*label,const u8 seed[32],const char*exp){
  u8 pub[32]; char got[65],hs[65];
  ed25519_pubkey(pub,seed); tohex(pub,32,got); tohex(seed,32,hs);
  int ok=!strcmp(got,exp);
  printf("[%s] %s\n   seed %s\n   pub  %s\n   exp  %s\n",
         ok?"PASS":"FAIL",label, hs, got, exp);
  return ok;
}

int main(){
  int ok=1;
  u8 s0[32]={0};
  u8 s1[32]={1};                 // 01 00 00 ... 00
  u8 s2[32]; for(int i=0;i<32;i++) s2[i]=(u8)i;   // 00 01 02 ... 1f
  // RFC 8032 section 7.1, TEST 1
  const char *rfc1="9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
  u8 s3[32]; for(int i=0;i<32;i++){ unsigned v; sscanf(rfc1+2*i,"%2x",&v); s3[i]=(u8)v; }

  ok &= check("seed=00..00",       s0,"3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29");
  ok &= check("seed=01,00..00",    s1,"cecc1507dc1ddd7295951c290888f095adb9044d1b73d696e6df065d683bd4fc");
  ok &= check("seed=00,01,..,1f",  s2,"03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8");
  ok &= check("RFC 8032 TEST 1",   s3,"d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");

  // Reproduce the kernel's seed derivation for a fixed base+counter and print
  // seed+pub so they can be cross-checked with an independent library.
  {
    u8 base[32]; for(int i=0;i<32;i++) base[i]=(u8)(0xA0+i);
    unsigned long long counter=1234567ULL;
    u8 in[40]; for(int i=0;i<32;i++) in[i]=base[i];
    for(int i=0;i<8;i++) in[32+i]=(u8)(counter>>(8*i));
    u8 hh[64],seed[32],pub[32];
    ed_sha512(hh,in,40); for(int i=0;i<32;i++) seed[i]=hh[i];
    ed25519_pubkey(pub,seed);
    char hs[65],hp[65]; tohex(seed,32,hs); tohex(pub,32,hp);
    printf("\n[derivation demo] base=0xA0.. counter=1234567\n   seed %s\n   pub  %s\n",hs,hp);
    printf("   (cross-check with PyNaCl: python3 -c \"import nacl.signing;print(bytes(nacl.signing.SigningKey(bytes.fromhex('%s')).verify_key).hex())\")\n",hs);
  }

  // Cross-check the optimized implementation against the reference one.
  {
    gepre *table=build_table();
    const int N=5000;  int bad=0;
    unsigned long long x=0x243F6A8885A308D3ULL;          // xorshift64 PRNG, fixed start
    for(int n=0;n<N;n++){
      u8 seed[32],p1[32],p2[32],h1[64],h2[64];
      for(int i=0;i<32;i++){ x^=x<<13; x^=x>>7; x^=x<<17; seed[i]=(u8)x; }
      ed25519_pubkey(p1,seed);
      ed25519_pubkey_fast(p2,seed,table);
      ed_sha512(h1,seed,32); sha512_short(h2,seed,32);
      if(memcmp(p1,p2,32) || memcmp(h1,h2,64)){
        if(bad++<3){ char hs[65]; tohex(seed,32,hs); printf("   mismatch for seed %s\n",hs); }
      }
    }
    printf("\n[%s] fast vs reference on %d pseudo-random seeds (%d mismatches)\n",
           bad?"FAIL":"PASS",N,bad);
    ok &= !bad;
    free(table);
  }

  printf("\n%s\n", ok? "ALL TESTS PASS" : "*** TEST FAILURE ***");
  return ok?0:1;
}
