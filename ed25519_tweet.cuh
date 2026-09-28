// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bengt-Erik Norum
//
// ed25519_tweet.cuh: Ed25519 seed -> public key (RFC 8032 key generation),
// usable from CUDA device code and from plain host C++ so the same code can be
// unit-tested on the CPU. Only the key-derivation path is included.
//
// Derived from TweetNaCl by D. J. Bernstein, B. van Gastel, W. Janssen,
// T. Lange, P. Schwabe and S. Smetsers (https://tweetnacl.cr.yp.to/), which is
// in the public domain. Changes: ported to CUDA/C++ (device qualifiers,
// __constant__ tables, ed_ prefixes), reduced to SHA-512 plus scalar-base
// multiplication and point packing. See THIRD_PARTY_NOTICES.md.
#pragma once
#include <cstdint>

#ifdef __CUDACC__
  #define DEV   __device__
  #define CONST __constant__
#else
  #define DEV   inline
  #define CONST const
#endif

typedef uint8_t  u8;
typedef uint64_t u64;
typedef int64_t  i64;
typedef i64      gf[16];

#ifndef ED_FOR
#define ED_FOR(i,n) for(i=0;i<(n);++i)
#endif

// ------------------------------- constants -------------------------------
CONST u64 ED_K[80] = {
  0x428a2f98d728ae22ULL,0x7137449123ef65cdULL,0xb5c0fbcfec4d3b2fULL,0xe9b5dba58189dbbcULL,
  0x3956c25bf348b538ULL,0x59f111f1b605d019ULL,0x923f82a4af194f9bULL,0xab1c5ed5da6d8118ULL,
  0xd807aa98a3030242ULL,0x12835b0145706fbeULL,0x243185be4ee4b28cULL,0x550c7dc3d5ffb4e2ULL,
  0x72be5d74f27b896fULL,0x80deb1fe3b1696b1ULL,0x9bdc06a725c71235ULL,0xc19bf174cf692694ULL,
  0xe49b69c19ef14ad2ULL,0xefbe4786384f25e3ULL,0x0fc19dc68b8cd5b5ULL,0x240ca1cc77ac9c65ULL,
  0x2de92c6f592b0275ULL,0x4a7484aa6ea6e483ULL,0x5cb0a9dcbd41fbd4ULL,0x76f988da831153b5ULL,
  0x983e5152ee66dfabULL,0xa831c66d2db43210ULL,0xb00327c898fb213fULL,0xbf597fc7beef0ee4ULL,
  0xc6e00bf33da88fc2ULL,0xd5a79147930aa725ULL,0x06ca6351e003826fULL,0x142929670a0e6e70ULL,
  0x27b70a8546d22ffcULL,0x2e1b21385c26c926ULL,0x4d2c6dfc5ac42aedULL,0x53380d139d95b3dfULL,
  0x650a73548baf63deULL,0x766a0abb3c77b2a8ULL,0x81c2c92e47edaee6ULL,0x92722c851482353bULL,
  0xa2bfe8a14cf10364ULL,0xa81a664bbc423001ULL,0xc24b8b70d0f89791ULL,0xc76c51a30654be30ULL,
  0xd192e819d6ef5218ULL,0xd69906245565a910ULL,0xf40e35855771202aULL,0x106aa07032bbd1b8ULL,
  0x19a4c116b8d2d0c8ULL,0x1e376c085141ab53ULL,0x2748774cdf8eeb99ULL,0x34b0bcb5e19b48a8ULL,
  0x391c0cb3c5c95a63ULL,0x4ed8aa4ae3418acbULL,0x5b9cca4f7763e373ULL,0x682e6ff3d6b2b8a3ULL,
  0x748f82ee5defb2fcULL,0x78a5636f43172f60ULL,0x84c87814a1f0ab72ULL,0x8cc702081a6439ecULL,
  0x90befffa23631e28ULL,0xa4506cebde82bde9ULL,0xbef9a3f7b2c67915ULL,0xc67178f2e372532bULL,
  0xca273eceea26619cULL,0xd186b8c721c0c207ULL,0xeada7dd6cde0eb1eULL,0xf57d4f7fee6ed178ULL,
  0x06f067aa72176fbaULL,0x0a637dc5a2c898a6ULL,0x113f9804bef90daeULL,0x1b710b35131c471bULL,
  0x28db77f523047d84ULL,0x32caab7b40c72493ULL,0x3c9ebe0a15c9bebcULL,0x431d67c49c100d4cULL,
  0x4cc5d4becb3e42b6ULL,0x597f299cfc657e2aULL,0x5fcb6fab3ad6faecULL,0x6c44198c4a475817ULL
};
CONST u8 ED_IV[64] = {
  0x6a,0x09,0xe6,0x67,0xf3,0xbc,0xc9,0x08, 0xbb,0x67,0xae,0x85,0x84,0xca,0xa7,0x3b,
  0x3c,0x6e,0xf3,0x72,0xfe,0x94,0xf8,0x2b, 0xa5,0x4f,0xf5,0x3a,0x5f,0x1d,0x36,0xf1,
  0x51,0x0e,0x52,0x7f,0xad,0xe6,0x82,0xd1, 0x9b,0x05,0x68,0x8c,0x2b,0x3e,0x6c,0x1f,
  0x1f,0x83,0xd9,0xab,0xfb,0x41,0xbd,0x6b, 0x5b,0xe0,0xcd,0x19,0x13,0x7e,0x21,0x79
};
CONST gf ED_gf0 = {0};
CONST gf ED_gf1 = {1};
CONST gf ED_D2  = {0xf159,0x26b2,0x9b94,0xebd6,0xb156,0x8283,0x149a,0x00e0,
                   0xd130,0xeef3,0x80f2,0x198e,0xfce7,0x56df,0xd9dc,0x2406};
CONST gf ED_X   = {0xd51a,0x8f25,0x2d60,0xc956,0xa7b2,0x9525,0xc760,0x692c,
                   0xdc5c,0xfdd6,0xe231,0xc0a4,0x53fe,0xcd6e,0x36d3,0x2169};
CONST gf ED_Y   = {0x6658,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,
                   0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666,0x6666};

// ------------------------------- SHA-512 ---------------------------------
#define ED_ROTR(x,c) (((x) >> (c)) | ((x) << (64 - (c))))
#define ED_Ch(x,y,z)  (((x) & (y)) ^ (~(x) & (z)))
#define ED_Maj(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define ED_S0(x) (ED_ROTR(x,28) ^ ED_ROTR(x,34) ^ ED_ROTR(x,39))
#define ED_S1(x) (ED_ROTR(x,14) ^ ED_ROTR(x,18) ^ ED_ROTR(x,41))
#define ED_s0(x) (ED_ROTR(x, 1) ^ ED_ROTR(x, 8) ^ ((x) >> 7))
#define ED_s1(x) (ED_ROTR(x,19) ^ ED_ROTR(x,61) ^ ((x) >> 6))

DEV static u64 ed_dl64(const u8 *x){ u64 i,u=0; ED_FOR(i,8) u=(u<<8)|x[i]; return u; }
DEV static void ed_ts64(u8 *x,u64 u){ int i; for(i=7;i>=0;--i){ x[i]=(u8)u; u>>=8; } }

DEV static int ed_hashblocks(u8 *x,const u8 *m,u64 n){
  u64 z[8],b[8],a[8],w[16],t; int i,j;
  ED_FOR(i,8) z[i]=a[i]=ed_dl64(x+8*i);
  while(n>=128){
    ED_FOR(i,16) w[i]=ed_dl64(m+8*i);
    ED_FOR(i,80){
      ED_FOR(j,8) b[j]=a[j];
      t=a[7]+ED_S1(a[4])+ED_Ch(a[4],a[5],a[6])+ED_K[i]+w[i%16];
      b[7]=t+ED_S0(a[0])+ED_Maj(a[0],a[1],a[2]);
      b[3]+=t;
      ED_FOR(j,8) a[(j+1)%8]=b[j];
      if(i%16==15)
        ED_FOR(j,16) w[j]+=w[(j+9)%16]+ED_s0(w[(j+1)%16])+ED_s1(w[(j+14)%16]);
    }
    ED_FOR(i,8){ a[i]+=z[i]; z[i]=a[i]; }
    m+=128; n-=128;
  }
  ED_FOR(i,8) ed_ts64(x+8*i,z[i]);
  return (int)n;
}
DEV static void ed_sha512(u8 *out,const u8 *m,u64 n){
  u8 h[64],x[256]; u64 i,b=n;
  ED_FOR(i,64) h[i]=ED_IV[i];
  ed_hashblocks(h,m,n);
  m+=n; n&=127; m-=n;
  ED_FOR(i,256) x[i]=0;
  ED_FOR(i,n) x[i]=m[i];
  x[n]=128;
  n=256-128*(n<112);
  x[n-9]=(u8)(b>>61);
  ed_ts64(x+n-8,b<<3);
  ed_hashblocks(h,x,n);
  ED_FOR(i,64) out[i]=h[i];
}

// --------------------------- field arithmetic ----------------------------
DEV static void ed_set(gf r,const gf a){ int i; ED_FOR(i,16) r[i]=a[i]; }
DEV static void ed_car(gf o){
  int i; i64 c;
  ED_FOR(i,16){ o[i]+=(1LL<<16); c=o[i]>>16; o[(i+1)*(i<15)]+=c-1+37*(c-1)*(i==15); o[i]-=c<<16; }
}
DEV static void ed_sel(gf p,gf q,int b){
  i64 t,i,c=~(b-1);
  ED_FOR(i,16){ t=c&(p[i]^q[i]); p[i]^=t; q[i]^=t; }
}
DEV static void ed_pack25519(u8 *o,const gf n){
  int i,j,b; gf m,t;
  ED_FOR(i,16) t[i]=n[i];
  ed_car(t); ed_car(t); ed_car(t);
  ED_FOR(j,2){
    m[0]=t[0]-0xffed;
    for(i=1;i<15;i++){ m[i]=t[i]-0xffff-((m[i-1]>>16)&1); m[i-1]&=0xffff; }
    m[15]=t[15]-0x7fff-((m[14]>>16)&1);
    b=(int)((m[15]>>16)&1);
    m[14]&=0xffff;
    ed_sel(t,m,1-b);
  }
  ED_FOR(i,16){ o[2*i]=(u8)(t[i]&0xff); o[2*i+1]=(u8)(t[i]>>8); }
}
DEV static void ed_A(gf o,const gf a,const gf b){ int i; ED_FOR(i,16) o[i]=a[i]+b[i]; }
DEV static void ed_Z(gf o,const gf a,const gf b){ int i; ED_FOR(i,16) o[i]=a[i]-b[i]; }
DEV static void ed_M(gf o,const gf a,const gf b){
  i64 i,j,t[31];
  ED_FOR(i,31) t[i]=0;
  ED_FOR(i,16) ED_FOR(j,16) t[i+j]+=a[i]*b[j];
  ED_FOR(i,15) t[i]+=38*t[i+16];
  ED_FOR(i,16) o[i]=t[i];
  ed_car(o); ed_car(o);
}
DEV static void ed_Sq(gf o,const gf a){ ed_M(o,a,a); }
DEV static void ed_inv(gf o,const gf i){
  gf c; int a; ed_set(c,i);
  for(a=253;a>=0;a--){ ed_Sq(c,c); if(a!=2&&a!=4) ed_M(c,c,i); }
  ed_set(o,c);
}

// ------------------------------ group ops --------------------------------
DEV static void ed_add(gf p[4],gf q[4]){
  gf a,b,c,d,t,e,f,g,h;
  ed_Z(a,p[1],p[0]); ed_Z(t,q[1],q[0]); ed_M(a,a,t);
  ed_A(b,p[0],p[1]); ed_A(t,q[0],q[1]); ed_M(b,b,t);
  ed_M(c,p[3],q[3]); ed_M(c,c,ED_D2);
  ed_M(d,p[2],q[2]); ed_A(d,d,d);
  ed_Z(e,b,a); ed_Z(f,d,c); ed_A(g,d,c); ed_A(h,b,a);
  ed_M(p[0],e,f); ed_M(p[1],h,g); ed_M(p[2],g,f); ed_M(p[3],e,h);
}
DEV static void ed_cswap(gf p[4],gf q[4],u8 b){ int i; ED_FOR(i,4) ed_sel(p[i],q[i],b); }
DEV static int ed_par(const gf a){ u8 d[32]; ed_pack25519(d,a); return d[0]&1; }
DEV static void ed_packpoint(u8 *r,gf p[4]){
  gf tx,ty,zi;
  ed_inv(zi,p[2]);
  ed_M(tx,p[0],zi);
  ed_M(ty,p[1],zi);
  ed_pack25519(r,ty);
  r[31]^=ed_par(tx)<<7;
}
DEV static void ed_scalarmult(gf p[4],gf q[4],const u8 *s){
  int i;
  ed_set(p[0],ED_gf0); ed_set(p[1],ED_gf1); ed_set(p[2],ED_gf1); ed_set(p[3],ED_gf0);
  for(i=255;i>=0;--i){
    u8 b=(s[i>>3]>>(i&7))&1;
    ed_cswap(p,q,b); ed_add(q,p); ed_add(p,p); ed_cswap(p,q,b);
  }
}
DEV static void ed_scalarbase(gf p[4],const u8 *s){
  gf q[4];
  ed_set(q[0],ED_X); ed_set(q[1],ED_Y); ed_set(q[2],ED_gf1); ed_M(q[3],ED_X,ED_Y);
  ed_scalarmult(p,q,s);
}

// Ed25519 public key from a 32-byte seed (RFC 8032 keypair derivation).
DEV static void ed25519_pubkey(u8 pk[32], const u8 seed[32]){
  u8 d[64]; gf p[4];
  ed_sha512(d, seed, 32);
  d[0]&=248; d[31]&=127; d[31]|=64;
  ed_scalarbase(p,d);
  ed_packpoint(pk,p);
}

#undef DEV
#undef CONST
