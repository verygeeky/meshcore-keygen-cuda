// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bengt-Erik Norum
//
// verify_format.cpp: check that a MeshCore 64-byte private key (128 hex, as the
// app exports it and `set prv.key` takes it) derives the given public key.
// MeshCore only uses the first 32 bytes (the clamped scalar) for that, via
// ed25519_derive_pub(); this does the same with the TweetNaCl-derived code.
//   ./verify_format <private key, 128 hex> <public key, 64 hex>
#include <cstdio>
#include <cstring>
#include "ed25519_tweet.cuh"

static int hx(char c){ if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10; if(c>='A'&&c<='F')return c-'A'+10; return -1; }
static void tohex(const u8*b,int n,char*o){ static const char*h="0123456789abcdef"; for(int i=0;i<n;i++){o[2*i]=h[b[i]>>4];o[2*i+1]=h[b[i]&15];} o[2*n]=0; }

int main(int argc,char**argv){
  if(argc<3){ fprintf(stderr,"usage: %s <priv128hex> <pub64hex>\n",argv[0]); return 2; }
  if(strlen(argv[1])!=128 || strlen(argv[2])!=64){
    fprintf(stderr,"private key must be 128 hex chars and public key 64\n"); return 2; }
  for(const char *p=argv[1]; *p; ++p) if(hx(*p)<0){ fprintf(stderr,"private key is not hex\n"); return 2; }
  u8 scalar[32];
  for(int i=0;i<32;i++) scalar[i]=(u8)((hx(argv[1][2*i])<<4)|hx(argv[1][2*i+1]));  // first 32 bytes
  gf p[4]; ed_scalarbase(p,scalar);
  u8 pub[32]; ed_packpoint(pub,p);
  char got[65]; tohex(pub,32,got);
  char want[65]; for(int i=0;i<64;i++){ char c=argv[2][i]; want[i]=(c>='A'&&c<='F')?c+32:c; } want[64]=0;
  printf("derived pub: %s\nexpected   : %s\nMATCH: %s\n", got, want, strcmp(got,want)?"NO":"YES");
  return strcmp(got,want)?1:0;
}
