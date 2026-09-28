// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 Bengt-Erik Norum
//
// meshcore-keygen: MeshCore vanity Ed25519 key generator (CUDA), reference build.
//
// Finds an Ed25519 keypair whose public key (the MeshCore identity) begins with
// a chosen hex prefix, e.g.   ./meshcore-keygen C0FFEE
//
// The crypto lives in ed25519_tweet.cuh (derived from TweetNaCl, public domain)
// and is shared with a CPU unit test (test_host.cpp), so the same code is
// checked against known Ed25519 vectors. An on-device self-test runs at
// startup and aborts if anything is wrong.
//
// Build:  make meshcore-keygen      Run:  ./meshcore-keygen <hexprefix>

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <chrono>
#include <csignal>
#include <cuda_runtime.h>
#include "ed25519_tweet.cuh"

#define CUDA_CHECK(x) do{ cudaError_t e=(x); if(e!=cudaSuccess){ \
  fprintf(stderr,"CUDA error %s at %s:%d\n",cudaGetErrorString(e),__FILE__,__LINE__); exit(1);} }while(0)

// MeshCore firmware refuses keys whose public key starts with 00 or FF
// (LocalIdentity::validatePrivateKey), so those are never reported as a match.
__device__ static bool match_prefix(const u8 *pub,const u8 *target,int nbytes,int oddNibble){
  if(pub[0]==0x00 || pub[0]==0xFF) return false;
  for(int i=0;i<nbytes;i++) if(pub[i]!=target[i]) return false;
  if(oddNibble && ((pub[nbytes]>>4)!=(target[nbytes]>>4))) return false;
  return true;
}

__global__ void selftest_kernel(const u8 *seed,u8 *pub){
  u8 p[32]; ed25519_pubkey(p,seed);
  for(int i=0;i<32;i++) pub[i]=p[i];
}

// MeshCore's 64-byte private key: clamp(SHA-512(seed)), i.e. the expanded
// Ed25519 secret (scalar || nonce prefix).  The SHA-512 lives in device code only.
__global__ void expand_kernel(const u8 *seed,u8 *out){
  u8 h[64]; ed_sha512(h,seed,32);
  h[0]&=248; h[31]&=127; h[31]|=64;
  for(int i=0;i<64;i++) out[i]=h[i];
}

// vanity search: seed = SHA512(base32 || counter64)[:32]  -> fully random key.
__global__ void search_kernel(const u8 *base,unsigned long long startCounter,int work,
                              const u8 *target,int nbytes,int oddNibble,
                              int *found,u8 *outSeed,u8 *outPub){
  unsigned long long idx=(unsigned long long)blockIdx.x*blockDim.x+threadIdx.x;
  unsigned long long c0=startCounter+idx*(unsigned long long)work;
  u8 in[40]; int i;
  for(i=0;i<32;i++) in[i]=base[i];
  for(int w=0;w<work;++w){
    if(*found) return;
    unsigned long long counter=c0+(unsigned long long)w;
    for(i=0;i<8;i++) in[32+i]=(u8)(counter>>(8*i));
    u8 hh[64],seed[32],pub[32];
    ed_sha512(hh,in,40);
    for(i=0;i<32;i++) seed[i]=hh[i];
    ed25519_pubkey(pub,seed);
    if(match_prefix(pub,target,nbytes,oddNibble)){
      if(atomicCAS(found,0,1)==0){
        for(i=0;i<32;i++){ outSeed[i]=seed[i]; outPub[i]=pub[i]; }
      }
      return;
    }
  }
}

static volatile sig_atomic_t g_stop=0;
static void on_sigint(int){ g_stop=1; }
static void tohex(const u8 *b,int n,char *out){
  static const char *h="0123456789abcdef";
  for(int i=0;i<n;i++){ out[2*i]=h[b[i]>>4]; out[2*i+1]=h[b[i]&15]; } out[2*n]=0;
}
static void tohex_upper(const u8 *b,int n,char *out){
  static const char *h="0123456789ABCDEF";
  for(int i=0;i<n;i++){ out[2*i]=h[b[i]>>4]; out[2*i+1]=h[b[i]&15]; } out[2*n]=0;
}
static int hexval(char c){
  if(c>='0'&&c<='9') return c-'0';
  if(c>='a'&&c<='f') return c-'a'+10;
  if(c>='A'&&c<='F') return c-'A'+10;
  return -1;
}

int main(int argc,char**argv){
  if(argc<2){
    fprintf(stderr,"usage: %s <hexprefix>   (matched against the start of the public key)\n",argv[0]);
    return 2;
  }
  const char *arg=argv[1];
  if(!strncmp(arg,"--prefix=",9)) arg+=9; else if(!strncmp(arg,"prefix=",7)) arg+=7;
  if(!strncmp(arg,"0x",2)||!strncmp(arg,"0X",2)) arg+=2;

  int nib=(int)strlen(arg);
  if(nib<1||nib>64){ fprintf(stderr,"prefix must be 1..64 hex chars\n"); return 2; }
  u8 target[33]={0};
  for(int i=0;i<nib;i++){
    int v=hexval(arg[i]);
    if(v<0){ fprintf(stderr,"'%c' is not a hex digit\n",arg[i]); return 2; }
    if(i&1) target[i/2]|=(u8)v; else target[i/2]=(u8)(v<<4);
  }
  int nbytes=nib/2, oddNibble=nib&1;
  if(nib>=2 && (target[0]==0x00 || target[0]==0xFF)){
    fprintf(stderr,"MeshCore rejects public keys that start with 00 or FF; pick another prefix\n");
    return 2;
  }

  int dev=0; cudaDeviceProp prop;
  CUDA_CHECK(cudaGetDeviceProperties(&prop,dev));
  printf("GPU: %s (sm_%d%d, %d SMs)\n",prop.name,prop.major,prop.minor,prop.multiProcessorCount);

  // mandatory device self-test against known Ed25519 vectors
  {
    u8 s0[32]={0}, s1[32]; for(int i=0;i<32;i++) s1[i]=(u8)i;
    const char *exp0="3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29";
    const char *exp1="03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8";
    u8 *dSeed,*dPub; CUDA_CHECK(cudaMalloc(&dSeed,32)); CUDA_CHECK(cudaMalloc(&dPub,32));
    char got[65]; u8 pub[32];
    CUDA_CHECK(cudaMemcpy(dSeed,s0,32,cudaMemcpyHostToDevice));
    selftest_kernel<<<1,1>>>(dSeed,dPub); CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaMemcpy(pub,dPub,32,cudaMemcpyDeviceToHost)); tohex(pub,32,got);
    if(strcmp(got,exp0)){ fprintf(stderr,"SELF-TEST FAILED (vec0)\n got %s\n exp %s\n",got,exp0); return 1; }
    CUDA_CHECK(cudaMemcpy(dSeed,s1,32,cudaMemcpyHostToDevice));
    selftest_kernel<<<1,1>>>(dSeed,dPub); CUDA_CHECK(cudaDeviceSynchronize());
    CUDA_CHECK(cudaMemcpy(pub,dPub,32,cudaMemcpyDeviceToHost)); tohex(pub,32,got);
    if(strcmp(got,exp1)){ fprintf(stderr,"SELF-TEST FAILED (vec1)\n got %s\n exp %s\n",got,exp1); return 1; }
    cudaFree(dSeed); cudaFree(dPub);
    printf("self-test: OK (Ed25519 verified on device)\n");
  }

  u8 base[32];
  { FILE*f=fopen("/dev/urandom","rb"); if(!f||fread(base,1,32,f)!=32){ fprintf(stderr,"urandom failed\n"); return 1; } fclose(f); }

  u8 *dBase,*dTarget,*dOutSeed,*dOutPub; int *dFound;
  CUDA_CHECK(cudaMalloc(&dBase,32));   CUDA_CHECK(cudaMemcpy(dBase,base,32,cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMalloc(&dTarget,33)); CUDA_CHECK(cudaMemcpy(dTarget,target,33,cudaMemcpyHostToDevice));
  CUDA_CHECK(cudaMalloc(&dFound,sizeof(int)));
  CUDA_CHECK(cudaMalloc(&dOutSeed,32)); CUDA_CHECK(cudaMalloc(&dOutPub,32));
  int zero=0; CUDA_CHECK(cudaMemcpy(dFound,&zero,sizeof(int),cudaMemcpyHostToDevice));

  // work per thread is kept small so a launch stays short and Ctrl-C responds quickly
  int threads=256, blocks=prop.multiProcessorCount*32, work=2;
  unsigned long long perLaunch=(unsigned long long)blocks*threads*work;
  double expected=1.0; for(int i=0;i<nib;i++) expected*=16.0;
  printf("target prefix: %s  (%d bit, ~%.0f keys expected)\n",arg,nib*4,expected);
  printf("searching...  (Ctrl-C to stop)\n");
  signal(SIGINT,on_sigint);

  auto t0=std::chrono::steady_clock::now(); auto tlast=t0;
  unsigned long long counter=0, tried=0, triedAtLast=0; int found=0;
  while(!found && !g_stop){
    search_kernel<<<blocks,threads>>>(dBase,counter,work,dTarget,nbytes,oddNibble,dFound,dOutSeed,dOutPub);
    CUDA_CHECK(cudaGetLastError());
    CUDA_CHECK(cudaDeviceSynchronize());
    counter+=perLaunch; tried+=perLaunch;
    CUDA_CHECK(cudaMemcpy(&found,dFound,sizeof(int),cudaMemcpyDeviceToHost));
    auto now=std::chrono::steady_clock::now();
    double since=std::chrono::duration<double>(now-tlast).count();
    if(since>=1.0 && !found){
      double rate=(tried-triedAtLast)/since/1e6, tot=std::chrono::duration<double>(now-t0).count();
      printf("\r  %.1f Mkey/s   tried %.2e   %.0fs   (~%.0f%% of expected)   ",
             rate,(double)tried,tot,100.0*tried/expected); fflush(stdout);
      tlast=now; triedAtLast=tried;
    }
  }
  printf("\n");

  if(found){
    u8 seed[32],pub[32],priv[64];
    CUDA_CHECK(cudaMemcpy(seed,dOutSeed,32,cudaMemcpyDeviceToHost));
    CUDA_CHECK(cudaMemcpy(pub,dOutPub,32,cudaMemcpyDeviceToHost));
    { u8 *dPriv; CUDA_CHECK(cudaMalloc(&dPriv,64));
      expand_kernel<<<1,1>>>(dOutSeed,dPriv); CUDA_CHECK(cudaDeviceSynchronize());
      CUDA_CHECK(cudaMemcpy(priv,dPriv,64,cudaMemcpyDeviceToHost)); cudaFree(dPriv); }
    bool ok=true;
    for(int i=0;i<nbytes;i++) if(pub[i]!=target[i]) ok=false;
    if(oddNibble && ((pub[nbytes]>>4)!=(target[nbytes]>>4))) ok=false;
    char hseed[65],hpub[65],hpriv[129];
    tohex_upper(seed,32,hseed); tohex_upper(pub,32,hpub); tohex_upper(priv,64,hpriv);
    double tot=std::chrono::duration<double>(std::chrono::steady_clock::now()-t0).count();
    printf("FOUND%s in %.1fs (%.2e tries)\n\n", ok?"":" (WARNING: prefix mismatch!)", tot,(double)tried);
    printf("Public key  : %s\n",hpub);
    printf("Private key : %s\n",hpriv);
    printf("Seed        : %s\n",hseed);
    printf("\nMeshCore JSON (keep it secret):\n");
    printf("{\"public_key\": \"%s\", \"private_key\": \"%s\"}\n",hpub,hpriv);
    printf("\nImport the 128-hex Private key in the MeshCore app (Manage Identity Key),\n"
           "or on a repeater/room server with: set prv.key <Private key>, then reboot.\n");
  } else {
    printf("stopped without a match.\n");
  }
  cudaFree(dBase); cudaFree(dTarget); cudaFree(dFound); cudaFree(dOutSeed); cudaFree(dOutPub);
  return found?0:1;
}
