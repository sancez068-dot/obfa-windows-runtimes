
#define PY_SSIZE_T_CLEAN
#define Py_LIMITED_API 0x030B0000
#include <Python.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static const char* obfa_u8(PyObject *o, PyObject **hold){
    *hold = PyUnicode_AsUTF8String(o);
    return *hold ? PyBytes_AsString(*hold) : NULL;
}
static PyObject* obfa_tuple_from_stack(PyObject **st, int n, int *sp){
    PyObject *t=PyTuple_New(n); if(!t) return NULL;
    for(int i=n-1;i>=0;i--) PyTuple_SetItem(t,i,st[--(*sp)]);
    return t;
}

typedef struct { uint32_t s[8]; uint64_t bits; uint8_t b[64]; size_t n; } SHA;
static const uint32_t K[64]={
0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2};
static uint32_t R(uint32_t x,int n){return (x>>n)|(x<<(32-n));}
static void shac(SHA*c,const uint8_t*p){
 uint32_t w[64],a,b,d,e,f,g,h,t1,t2; int i;
 for(i=0;i<16;i++)w[i]=((uint32_t)p[i*4]<<24)|((uint32_t)p[i*4+1]<<16)|((uint32_t)p[i*4+2]<<8)|p[i*4+3];
 for(i=16;i<64;i++){uint32_t q=R(w[i-15],7)^R(w[i-15],18)^(w[i-15]>>3),r=R(w[i-2],17)^R(w[i-2],19)^(w[i-2]>>10);w[i]=w[i-16]+q+w[i-7]+r;}
 a=c->s[0];b=c->s[1];d=c->s[3];e=c->s[4];f=c->s[5];g=c->s[6];h=c->s[7]; uint32_t cc=c->s[2];
 for(i=0;i<64;i++){t1=h+(R(e,6)^R(e,11)^R(e,25))+((e&f)^((~e)&g))+K[i]+w[i];t2=(R(a,2)^R(a,13)^R(a,22))+((a&b)^(a&cc)^(b&cc));h=g;g=f;f=e;e=d+t1;d=cc;cc=b;b=a;a=t1+t2;}
 c->s[0]+=a;c->s[1]+=b;c->s[2]+=cc;c->s[3]+=d;c->s[4]+=e;c->s[5]+=f;c->s[6]+=g;c->s[7]+=h;
}
static void shai(SHA*c){int i;c->bits=0;c->n=0;uint32_t s[8]={0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19};memcpy(c->s,s,sizeof(s));}
static void shau(SHA*c,const void*p,size_t n){const uint8_t*x=p;while(n){size_t m=64-c->n;if(m>n)m=n;memcpy(c->b+c->n,x,m);c->n+=m;x+=m;n-=m;c->bits+=m*8;if(c->n==64){shac(c,c->b);c->n=0;}}}
static void shaf(SHA*c,uint8_t o[32]){size_t n=c->n; c->b[n++]=0x80; if(n>56){memset(c->b+n,0,64-n);shac(c,c->b);n=0;} memset(c->b+n,0,56-n);for(int i=0;i<8;i++)c->b[56+i]=(uint8_t)(c->bits>>(56-8*i));shac(c,c->b);for(int i=0;i<8;i++){o[i*4]=c->s[i]>>24;o[i*4+1]=c->s[i]>>16;o[i*4+2]=c->s[i]>>8;o[i*4+3]=c->s[i];}}
static void sha(const void*p,size_t n,uint8_t o[32]){SHA c;shai(&c);shau(&c,p,n);shaf(&c,o);}
static void hmac256(const uint8_t*k,size_t kn,const uint8_t*m,size_t mn,uint8_t o[32]){
 uint8_t kk[64],ih[32];memset(kk,0,64);if(kn>64)sha(k,kn,kk);else memcpy(kk,k,kn);
 for(int i=0;i<64;i++)kk[i]^=0x36;SHA c;shai(&c);shau(&c,kk,64);shau(&c,m,mn);shaf(&c,ih);
 for(int i=0;i<64;i++)kk[i]^=0x36^0x5c;shai(&c);shau(&c,kk,64);shau(&c,ih,32);shaf(&c,o);
 memset(kk,0,sizeof(kk));memset(ih,0,sizeof(ih));
}
static int external_root_from_env(uint8_t root[32], const uint8_t build[16], const uint8_t nd[32]){
 const char *env=getenv("OBFA_MASTER_KEY");
 if(!env)return 0;
 size_t n=strlen(env);
 if(n<32 || n>4096)return 0;
 uint8_t master[32],msg[56];
 SHA c; shai(&c); shau(&c,"OBFA-MASTER-V1:",15); shau(&c,env,n); shaf(&c,master);
 memcpy(msg,"root-v6:",8);memcpy(msg+8,build,16);memcpy(msg+24,nd,32);
 hmac256(master,32,msg,sizeof(msg),root);
 memset(master,0,sizeof(master));memset(msg,0,sizeof(msg));
 return 1;
}

static uint16_t u16(const uint8_t*p){return (uint16_t)p[0]<<8|p[1];}
static uint32_t u32(const uint8_t*p){return ((uint32_t)p[0]<<24)|((uint32_t)p[1]<<16)|((uint32_t)p[2]<<8)|p[3];}
static int eq(const uint8_t*a,const uint8_t*b,size_t n){uint8_t x=0;for(size_t i=0;i<n;i++)x|=a[i]^b[i];return x==0;}
static const uint8_t AES_S[256]={
0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16};
static uint8_t aes_xt(uint8_t x){return (uint8_t)((x<<1)^((x&0x80)?0x1b:0));}
static void aes256_expand(const uint8_t*k,uint8_t*rk){memcpy(rk,k,32);uint8_t t[4],rc=1;int n=32;while(n<240){memcpy(t,rk+n-4,4);if(n%32==0){uint8_t q=t[0];t[0]=AES_S[t[1]]^rc;t[1]=AES_S[t[2]];t[2]=AES_S[t[3]];t[3]=AES_S[q];rc=aes_xt(rc);}else if(n%32==16){for(int i=0;i<4;i++)t[i]=AES_S[t[i]];}for(int i=0;i<4;i++){rk[n]=rk[n-32]^t[i];n++;}}memset(t,0,sizeof(t));}
static void aes256_block(const uint8_t in[16],uint8_t out[16],const uint8_t*rk){uint8_t s[16];memcpy(s,in,16);for(int i=0;i<16;i++)s[i]^=rk[i];for(int round=1;round<=14;round++){for(int i=0;i<16;i++)s[i]=AES_S[s[i]];uint8_t t[16];for(int r=0;r<4;r++)for(int c=0;c<4;c++)t[r+4*c]=s[r+4*((c+r)&3)];memcpy(s,t,16);if(round<14){for(int c=0;c<4;c++){uint8_t*a=s+4*c,x=a[0],y=a[1],z=a[2],w=a[3],q=x^y^z^w;a[0]^=q^aes_xt(x^y);a[1]^=q^aes_xt(y^z);a[2]^=q^aes_xt(z^w);a[3]^=q^aes_xt(w^x);}}for(int i=0;i<16;i++)s[i]^=rk[round*16+i];}memcpy(out,s,16);memset(s,0,sizeof(s));}
static void aes256_ctr(uint8_t*d,size_t n,const uint8_t*key,const uint8_t iv0[16]){uint8_t rk[240],ctr[16],blk[16];aes256_expand(key,rk);memcpy(ctr,iv0,16);size_t pos=0;while(pos<n){aes256_block(ctr,blk,rk);size_t m=n-pos;if(m>16)m=16;for(size_t i=0;i<m;i++)d[pos+i]^=blk[i];pos+=m;for(int i=15;i>=0;i--){ctr[i]++;if(ctr[i])break;}}memset(rk,0,sizeof(rk));memset(ctr,0,sizeof(ctr));memset(blk,0,sizeof(blk));}
static int decrypt_blob(const uint8_t*blob,size_t n,const uint8_t*key,const uint8_t*ctx,size_t cn,uint8_t**out,size_t*on){
 if(n<32 || cn>UINT32_MAX)return 0;size_t m=n-32;uint8_t ek[32],mk[32],ivhash[32],tag[32],*x=malloc(m?m:1);if(!x)return 0;
 static const char ed[]="OBFA-AES256-CTR-ENC-V1:",md[]="OBFA-AES256-CTR-MAC-V1:",id[]="OBFA-AES256-CTR-IV-V1:";
 uint8_t*tmp=malloc(sizeof(ed)-1+cn);if(!tmp){free(x);return 0;}memcpy(tmp,ed,sizeof(ed)-1);memcpy(tmp+sizeof(ed)-1,ctx,cn);hmac256(key,32,tmp,sizeof(ed)-1+cn,ek);memcpy(tmp,md,sizeof(md)-1);memcpy(tmp+sizeof(md)-1,ctx,cn);hmac256(key,32,tmp,sizeof(md)-1+cn,mk);free(tmp);
 SHA sh;shai(&sh);shau(&sh,id,sizeof(id)-1);shau(&sh,ctx,cn);shaf(&sh,ivhash);
 size_t tn=4+cn+m;uint8_t*tm=malloc(tn?tn:1);if(!tm){free(x);memset(ek,0,32);memset(mk,0,32);return 0;}tm[0]=(uint8_t)(cn>>24);tm[1]=(uint8_t)(cn>>16);tm[2]=(uint8_t)(cn>>8);tm[3]=(uint8_t)cn;memcpy(tm+4,ctx,cn);memcpy(tm+4+cn,blob,m);hmac256(mk,32,tm,tn,tag);free(tm);
 if(!eq(tag,blob+m,32)){free(x);memset(ek,0,32);memset(mk,0,32);memset(ivhash,0,32);return 0;}memcpy(x,blob,m);aes256_ctr(x,m,ek,ivhash);*out=x;*on=m;memset(ek,0,32);memset(mk,0,32);memset(ivhash,0,32);memset(tag,0,32);return 1;
}

typedef struct {uint32_t off,count;uint16_t argc,ndefaults;uint32_t*args,*defaults;} FN;
typedef struct {uint32_t logical,physical,off,size;uint8_t nonce[16];const uint8_t*blob;size_t blob_len;} PAGE;
typedef struct {const uint8_t*src;size_t src_len;PAGE*pages;uint32_t count;uint8_t root[32];uint8_t build[16];uint8_t kind[16];uint8_t*cache;uint32_t cache_logical;size_t cache_len;int cache_valid;uint8_t runtime_key[32];int dynamic_mask;} PM;
typedef struct {uint8_t*prefix;size_t prefix_len;uint8_t*instr;size_t instr_len;PM codepm;PM constpm;uint32_t*cid_page,*cid_off,*cid_size;uint32_t cc;PyObject**pool;PyObject*globals;uint16_t fcnt;FN*fs;uint16_t reg_count;} CTX;

static void runtime_mask_range(const PM*m,uint32_t logical,size_t offset,uint8_t*buf,size_t n){
 if(!m->dynamic_mask || n==0)return;
 static const uint8_t label[]="OBFA-RUNTIME-MASK-V1:";
 while(n){
  uint64_t block=(uint64_t)(offset/32u);size_t skip=offset%32u;
  uint8_t msg[sizeof(label)-1+32+16+4+8],stream[32];size_t q=0;
  memcpy(msg+q,label,sizeof(label)-1);q+=sizeof(label)-1;
  memcpy(msg+q,m->runtime_key,32);q+=32;
  memcpy(msg+q,m->build,16);q+=16;
  msg[q++]=(uint8_t)(logical>>24);msg[q++]=(uint8_t)(logical>>16);msg[q++]=(uint8_t)(logical>>8);msg[q++]=(uint8_t)logical;
  for(int j=7;j>=0;j--)msg[q++]=(uint8_t)(block>>(j*8));
  sha(msg,q,stream);size_t take=32-skip;if(take>n)take=n;
  for(size_t j=0;j<take;j++)buf[j]^=stream[skip+j];
  memset(msg,0,sizeof(msg));memset(stream,0,sizeof(stream));buf+=take;offset+=take;n-=take;
 }
}
static int init_runtime_mask(uint8_t out[32]){
 PyObject*mod=PyImport_ImportModule("secrets");if(!mod)return 0;
 PyObject*raw=PyObject_CallMethod(mod,"token_bytes","i",32);Py_DECREF(mod);if(!raw)return 0;
 Py_buffer view;if(PyObject_GetBuffer(raw,&view,PyBUF_SIMPLE)<0){Py_DECREF(raw);return 0;}
 int ok=view.len==32;if(ok)memcpy(out,view.buf,32);PyBuffer_Release(&view);Py_DECREF(raw);return ok;
}
static int page_load(PM*m,uint32_t logical){
 if(m->cache_valid && m->cache_logical==logical)return 1;
 for(uint32_t i=0;i<m->count;i++) if(m->pages[i].logical==logical){
  uint8_t ctx[64];size_t cn=0;memcpy(ctx,"code-page:",10); /* overwritten below */
  const char*kind=(const char*)m->kind; size_t kl=strlen(kind);
  cn=kl; memcpy(ctx,kind,kl);memcpy(ctx+cn,m->build,16);cn+=16;memcpy(ctx+cn,&logical,4); /* native and packer use big-endian */
  ctx[cn+0]=(uint8_t)(logical>>24);ctx[cn+1]=(uint8_t)(logical>>16);ctx[cn+2]=(uint8_t)(logical>>8);ctx[cn+3]=(uint8_t)logical;cn+=4;memcpy(ctx+cn,m->pages[i].nonce,16);cn+=16;
  uint8_t*o=NULL;size_t on=0;if(!decrypt_blob(m->pages[i].blob,m->pages[i].blob_len,m->root,ctx,cn,&o,&on))return 0;
  if(m->cache){memset(m->cache,0,m->cache_len);free(m->cache);}m->cache=o;m->cache_len=on;m->cache_logical=logical;m->cache_valid=1;runtime_mask_range(m,logical,0,m->cache,m->cache_len);return 1;
 }
 return 0;
}
static int pm_read(PM*m,size_t off,uint8_t*out,size_t n){
 if(n==0)return 1; if(off>SIZE_MAX-n)return 0;
 for(uint32_t i=0;i<m->count;i++){
  PAGE*p=&m->pages[i]; if(off>=p->off && off<p->off+p->size){
   size_t rel=off-p->off, take=p->size-rel; if(take>n)take=n;
   if(!page_load(m,p->logical) || rel+take>m->cache_len)return 0;
   memcpy(out,m->cache+rel,take); runtime_mask_range(m,p->logical,rel,out,take); if(take<n)return pm_read(m,off+take,out+take,n-take); return 1;
  }
 }
 return 0;
}
static void pm_free(PM*m){free(m->pages);if(m->cache){memset(m->cache,0,m->cache_len);free(m->cache);}memset(m->runtime_key,0,sizeof(m->runtime_key));m->pages=NULL;m->cache=NULL;m->count=0;m->cache_valid=0;}

static int const_load(CTX*c,uint32_t cid,PyObject**out){
 if(cid>=c->cc)return 0;
 if(c->pool[cid]){Py_INCREF(c->pool[cid]);*out=c->pool[cid];return 1;}
 uint32_t pg=c->cid_page[cid],off=c->cid_off[cid],sz=c->cid_size[cid];
 uint8_t*buf=malloc(sz?sz:1);if(!buf)return 0;
 if(!pm_read(&c->constpm,0,buf,0)){memset(buf,0,sz);free(buf);return 0;}
 /* const page offsets are global offsets in each logical page; locate page directly and read there */
 for(uint32_t i=0;i<c->constpm.count;i++){PAGE*p=&c->constpm.pages[i];if(p->logical==pg){
   if(!page_load(&c->constpm,pg)){memset(buf,0,sz);free(buf);return 0;}
   if(off+sz>c->constpm.cache_len){memset(buf,0,sz);free(buf);return 0;}memcpy(buf,c->constpm.cache+off,sz);goto decoded;
 }}
 memset(buf,0,sz);free(buf);return 0;
decoded:
 if(sz<8){memset(buf,0,sz);free(buf);return 0;}uint32_t got=0,rsz=0;got=u32(buf);rsz=u32(buf+4);if(got!=cid||rsz+8!=sz){memset(buf,0,sz);free(buf);return 0;}
 const uint8_t*x=buf+8;size_t z=1;uint8_t t=x[0];PyObject*v=NULL;
 if(t=='N'&&sz==9)v=Py_None;else if(t=='T'&&sz==9)v=Py_True;else if(t=='F'&&sz==9)v=Py_False;
 else if(t=='I'&&sz==17){int64_t val=0;for(int j=0;j<8;j++)val=(val<<8)|x[1+j];v=PyLong_FromLongLong(val);}
 else if(t=='D'&&sz==17){double d;uint64_t u=0;for(int j=0;j<8;j++)u=(u<<8)|x[1+j];memcpy(&d,&u,8);v=PyFloat_FromDouble(d);}
 else if((t=='S'||t=='Y')&&sz>=13){uint32_t l=u32(x+1);if((size_t)13+l!=sz){memset(buf,0,sz);free(buf);return 0;}v=(t=='S')?PyUnicode_DecodeUTF8((const char*)x+5,l,"strict"):PyBytes_FromStringAndSize((const char*)x+5,l);}
 else {memset(buf,0,sz);free(buf);return 0;}
 memset(buf,0,sz);free(buf);if(!v)return 0;c->pool[cid]=v;Py_INCREF(v);*out=v;return 1;
}
static int getcst(CTX*c,uint32_t id,PyObject**v){return const_load(c,id,v);}
static int read_u8(PM*m,size_t off,uint8_t*v){return pm_read(m,off,v,1);}
static size_t ilen(uint8_t v){uint8_t f=v>>6;return 2+(f==0?1:(f==1?2:4))+(f==3?1:0);}
static uint32_t iargbuf(const uint8_t*p,uint8_t v){uint8_t f=v>>6;if(f==0)return p[2];if(f==1)return u16(p+2);return u32(p+2);}
static uint32_t ror32(uint32_t x,unsigned r){r&=31;return r?((x>>r)|(x<<(32-r))):x;}
static uint32_t invodd(uint32_t a){uint32_t x=1;for(int i=0;i<5;i++)x*=2-a*x;return x;}
static uint32_t decode_arg(uint32_t enc,const uint8_t build[16],uint8_t variant,int pool){uint8_t h[16];uint8_t in[18];memcpy(in,build,16);in[16]=variant&63;in[17]=pool?1:0;uint8_t d[32];sha(in,18,d);uint32_t odd=u32(d)|1u,add=u32(d+4);unsigned rot=d[8]&31;uint32_t y=ror32(enc,rot);return (uint32_t)((uint64_t)(y-add)*invodd(odd));}
static int seek_pad(CTX*c,uint32_t start,uint32_t idx,size_t*out){size_t p=start;for(uint32_t i=0;i<idx;i++){uint8_t v;if(!read_u8(&c->codepm,p+1,&v))return 0;size_t ln=ilen(v);if(ln>UINT32_MAX||p>c->instr_len-ln)return 0;p+=ln;}*out=p;return 1;}
static int logical_op(CTX*c,uint8_t phys,uint8_t var){var&=63;uint8_t vals[38],d[32];sha(c->codepm.build,16,d);for(int i=0;i<38;i++)vals[i]=i+1;for(int i=37;i>0;i--){int j=d[i%32]%(i+1);uint8_t t=vals[i];vals[i]=vals[j];vals[j]=t;}for(int i=0;i<38;i++){uint8_t want=(uint8_t)(vals[i]^((var+1)*0x3d&255));if(want==phys)return i+1;}return -1;}
static int fetch_inst(CTX*c,size_t p,uint8_t*buf,size_t cap,uint8_t*varout){uint8_t v;if(cap<2||!pm_read(&c->codepm,p,buf,2)||!read_u8(&c->codepm,p+1,&v))return 0;size_t n=ilen(v);if(n>cap||p>c->instr_len-n)return 0;if(!pm_read(&c->codepm,p,buf,n))return 0;*varout=v;return 1;}
static PyObject* rfn(CTX*c,int fi,PyObject**argv,int argc,PyObject*kwargs){
 if(fi<0||fi>=c->fcnt){PyErr_SetString(PyExc_RuntimeError,"bad function id");return NULL;}
 PyObject*local=(fi==0)?c->globals:PyDict_New();if(!local)return NULL;if(fi==0)Py_INCREF(local);FN*f=&c->fs[fi];
 if(argc>f->argc){PyErr_SetString(PyExc_TypeError,"too many positional arguments");Py_DECREF(local);return NULL;}
 for(int i=0;i<argc;i++){PyObject*k=NULL;if(!getcst(c,f->args[i],&k)){Py_DECREF(local);return NULL;}if(PyDict_SetItem(local,k,argv[i])<0){Py_DECREF(k);Py_DECREF(local);return NULL;}Py_DECREF(k);}
 if(kwargs && PyDict_Check(kwargs)){PyObject*key,*val;Py_ssize_t pos=0;while(PyDict_Next(kwargs,&pos,&key,&val)){int found=-1;for(uint16_t i=0;i<f->argc;i++){PyObject*k=NULL;if(!getcst(c,f->args[i],&k)){Py_DECREF(local);return NULL;}int eq=PyObject_RichCompareBool(k,key,Py_EQ);Py_DECREF(k);if(eq<0){Py_DECREF(local);return NULL;}if(eq){found=i;break;}}if(found<0){PyErr_SetObject(PyExc_TypeError,key);Py_DECREF(local);return NULL;}PyObject*k=NULL;if(!getcst(c,f->args[found],&k)){Py_DECREF(local);return NULL;}if(PyDict_Contains(local,k)){PyErr_SetString(PyExc_TypeError,"multiple values for argument");Py_DECREF(k);Py_DECREF(local);return NULL;}if(PyDict_SetItem(local,k,val)<0){Py_DECREF(k);Py_DECREF(local);return NULL;}Py_DECREF(k);}}
 for(int i=0;i<f->argc;i++){PyObject*k=NULL;if(!getcst(c,f->args[i],&k)){Py_DECREF(local);return NULL;}int present=PyDict_Contains(local,k);Py_DECREF(k);if(present<0){Py_DECREF(local);return NULL;}if(!present){int di=i-(f->argc-f->ndefaults);if(di<0||di>=f->ndefaults){PyErr_Format(PyExc_TypeError,"missing required argument at position %d",i+1);Py_DECREF(local);return NULL;}PyObject*dv=NULL;if(!getcst(c,f->defaults[di],&dv)){Py_DECREF(local);return NULL;}if(PyDict_SetItem(local,k,dv)<0){Py_DECREF(dv);Py_DECREF(local);return NULL;}Py_DECREF(dv);}}
 size_t stack_cap=(size_t)f->count*4u+128u; if(stack_cap>1000000u)stack_cap=1000000u; PyObject**st=calloc(stack_cap,sizeof(PyObject*));PyObject**regs=calloc(c->reg_count,sizeof(PyObject*));if(!st||!regs){free(st);free(regs);Py_DECREF(local);PyErr_NoMemory();return NULL;}int sp=0;uint32_t pc=0;PyObject*ret=NULL;
 uint32_t hpc[32]; int hsp=0; int hdepth[32];
 while(pc<f->count){size_t p;if(!seek_pad(c,f->off,pc,&p)){PyErr_SetString(PyExc_RuntimeError,"invalid instruction stream");goto vm_fail;}uint8_t inst[7],var=0;if(!fetch_inst(c,p,inst,sizeof(inst),&var)){PyErr_SetString(PyExc_RuntimeError,"truncated instruction");goto vm_fail;}int op=logical_op(c,inst[0],inst[1]);uint32_t rawarg=iargbuf(inst,inst[1]);pc++;if(op<1||op>38){PyErr_SetString(PyExc_RuntimeError,"invalid opcode");goto vm_fail;}
  PyObject*ka=NULL,*kb=NULL,*v=NULL;
  uint32_t a=rawarg; int is_pool = !(op==8||op==9||op==10||op==11||op==12||op==13||op==14||op==15||op==19||op==20||op==21||op==22||op==25||op==26||op==27||op==28||op==29||op==30||op==31||op==32||op==33||op==34||op==35||op==36); a=decode_arg(rawarg,c->codepm.build,inst[1],is_pool);
  if(op==1){if(a>=c->cc||!getcst(c,a,&v))goto vm_fail;if((size_t)sp>=stack_cap){Py_DECREF(v);PyErr_SetString(PyExc_RuntimeError,"VM stack limit exceeded");goto vm_fail;}st[sp++]=v;}
  else if(op==2){if(a>=c->cc||!getcst(c,a,&ka))goto vm_fail;v=PyDict_GetItemWithError(local,ka);if(!v)v=PyDict_GetItemWithError(c->globals,ka);if(!v)v=PyDict_GetItemWithError(PyEval_GetBuiltins(),ka);if(!v){PyErr_SetObject(PyExc_NameError,ka);Py_DECREF(ka);goto vm_fail;}Py_INCREF(v);st[sp++]=v;Py_DECREF(ka);}
  else if(op==3){if(sp<1||a>=c->cc||!getcst(c,a,&ka))goto vm_fail;v=st[--sp];if(PyDict_SetItem(local,ka,v)<0){Py_DECREF(v);Py_DECREF(ka);goto vm_fail;}Py_DECREF(v);Py_DECREF(ka);}
  else if(op==37){if(a>=c->cc||!getcst(c,a,&ka))goto vm_fail;v=PyDict_GetItemWithError(c->globals,ka);if(!v){if(PyErr_Occurred()){Py_DECREF(ka);goto vm_fail;}PyErr_SetObject(PyExc_NameError,ka);Py_DECREF(ka);goto vm_fail;}Py_INCREF(v);st[sp++]=v;Py_DECREF(ka);}
  else if(op==38){if(sp<1||a>=c->cc||!getcst(c,a,&ka))goto vm_fail;v=st[--sp];if(PyDict_SetItem(c->globals,ka,v)<0){Py_DECREF(v);Py_DECREF(ka);goto vm_fail;}Py_DECREF(v);Py_DECREF(ka);}
  else if(op==4){if(sp)Py_DECREF(st[--sp]);}
  else if(op==5){if(sp<2||a>=c->cc||!getcst(c,a,&ka))goto vm_fail;PyObject*b=st[--sp],*x=st[--sp];PyObject *ka_b=NULL; const char*s=obfa_u8(ka,&ka_b);if(!s){Py_XDECREF(ka_b);Py_DECREF(ka);Py_DECREF(x);Py_DECREF(b);goto vm_fail;}if(!strcmp(s,"add"))v=PyNumber_Add(x,b);else if(!strcmp(s,"sub"))v=PyNumber_Subtract(x,b);else if(!strcmp(s,"mul"))v=PyNumber_Multiply(x,b);else if(!strcmp(s,"truediv"))v=PyNumber_TrueDivide(x,b);else if(!strcmp(s,"floordiv"))v=PyNumber_FloorDivide(x,b);else if(!strcmp(s,"mod"))v=PyNumber_Remainder(x,b);else if(!strcmp(s,"pow"))v=PyNumber_Power(x,b,Py_None);else if(!strcmp(s,"or"))v=PyNumber_Or(x,b);else if(!strcmp(s,"and"))v=PyNumber_And(x,b);else if(!strcmp(s,"xor"))v=PyNumber_Xor(x,b);else if(!strcmp(s,"lshift"))v=PyNumber_Lshift(x,b);else if(!strcmp(s,"rshift"))v=PyNumber_Rshift(x,b);else {PyErr_SetString(PyExc_RuntimeError,"unknown binary operation");}Py_XDECREF(ka_b);Py_DECREF(ka);Py_DECREF(x);Py_DECREF(b);if(!v)goto vm_fail;if((size_t)sp>=stack_cap){Py_DECREF(v);PyErr_SetString(PyExc_RuntimeError,"VM stack limit exceeded");goto vm_fail;}st[sp++]=v;}
  else if(op==6){if(sp<1||a>=c->cc||!getcst(c,a,&ka))goto vm_fail;PyObject*x=st[--sp];PyObject *ka_b=NULL; const char*s=obfa_u8(ka,&ka_b);if(!s){Py_XDECREF(ka_b);Py_DECREF(ka);Py_DECREF(x);goto vm_fail;}if(!strcmp(s,"neg"))v=PyNumber_Negative(x);else if(!strcmp(s,"pos"))v=PyNumber_Positive(x);else if(!strcmp(s,"invert"))v=PyNumber_Invert(x);else if(!strcmp(s,"not")){int t=PyObject_IsTrue(x);if(t<0){Py_XDECREF(ka_b);Py_DECREF(ka);Py_DECREF(x);goto vm_fail;}v=PyBool_FromLong(!t);}Py_XDECREF(ka_b);Py_DECREF(ka);Py_DECREF(x);if(!v)goto vm_fail;if((size_t)sp>=stack_cap){Py_DECREF(v);PyErr_SetString(PyExc_RuntimeError,"VM stack limit exceeded");goto vm_fail;}st[sp++]=v;}
  else if(op==7){if(sp<2||a>=c->cc||!getcst(c,a,&ka))goto vm_fail;PyObject*b=st[--sp],*x=st[--sp];PyObject *ka_b=NULL; const char*s=obfa_u8(ka,&ka_b);int r=-1;if(s){if(!strcmp(s,"eq"))r=PyObject_RichCompareBool(x,b,Py_EQ);else if(!strcmp(s,"ne"))r=PyObject_RichCompareBool(x,b,Py_NE);else if(!strcmp(s,"lt"))r=PyObject_RichCompareBool(x,b,Py_LT);else if(!strcmp(s,"le"))r=PyObject_RichCompareBool(x,b,Py_LE);else if(!strcmp(s,"gt"))r=PyObject_RichCompareBool(x,b,Py_GT);else if(!strcmp(s,"ge"))r=PyObject_RichCompareBool(x,b,Py_GE);else if(!strcmp(s,"in"))r=PySequence_Contains(b,x);else if(!strcmp(s,"notin")){int q=PySequence_Contains(b,x);r=q<0?-1:!q;}else if(!strcmp(s,"is"))r=(x==b);else if(!strcmp(s,"isnot"))r=(x!=b);}Py_XDECREF(ka_b);Py_DECREF(ka);Py_DECREF(x);Py_DECREF(b);if(r<0)goto vm_fail;st[sp++]=PyBool_FromLong(r);}
  else if(op==8){size_t nn=a;if(nn>1024||sp<(int)nn+1)goto vm_fail;PyObject*fn=st[sp-(int)nn-1],*args=PyTuple_New((Py_ssize_t)nn);if(!args)goto vm_fail;for(int i=(int)nn-1;i>=0;i--)PyTuple_SetItem(args,i,st[--sp]);sp--;if(PyCapsule_CheckExact(fn)){void*ptr=PyCapsule_GetPointer(fn,"CAP");if(!ptr){Py_DECREF(fn);Py_DECREF(args);goto vm_fail;}PyObject** av=calloc(nn?nn:1,sizeof(PyObject*)); if(!av){Py_DECREF(fn);Py_DECREF(args);PyErr_NoMemory();goto vm_fail;} for(size_t ai=0;ai<nn;ai++) av[ai]=PyTuple_GetItem(args,(Py_ssize_t)ai); v=rfn(c,(int)(uintptr_t)ptr,av,(int)nn,NULL); free(av);}else v=PyObject_CallObject(fn,args);Py_DECREF(fn);Py_DECREF(args);if(!v)goto vm_fail;if((size_t)sp>=stack_cap){Py_DECREF(v);PyErr_SetString(PyExc_RuntimeError,"VM stack limit exceeded");goto vm_fail;}st[sp++]=v;}
  else if(op==9){if(sp){ret=st[--sp];}else{Py_INCREF(Py_None);ret=Py_None;}goto done;}
  else if(op==10){if(a>f->count)goto vm_fail;pc=a;}
  else if(op==11){if(!sp)goto vm_fail;PyObject*x=st[--sp];int t=PyObject_IsTrue(x);Py_DECREF(x);if(t<0)goto vm_fail;if(!t)pc=a;}
  else if(op==12||op==13||op==14){int n=(int)a;if(n<0||sp<n)goto vm_fail;PyObject*qv=NULL;if(op==12){qv=PyList_New(n);if(!qv)goto vm_fail;for(int i=n-1;i>=0;i--)PyList_SetItem(qv,i,st[--sp]);}else if(op==13){qv=PyTuple_New(n);if(!qv)goto vm_fail;for(int i=n-1;i>=0;i--)PyTuple_SetItem(qv,i,st[--sp]);}else{qv=PySet_New(NULL);if(!qv)goto vm_fail;for(int i=n-1;i>=0;i--){PyObject*t=st[--sp];if(PySet_Add(qv,t)<0){Py_DECREF(t);Py_DECREF(qv);goto vm_fail;}Py_DECREF(t);}}if((size_t)sp>=stack_cap){Py_DECREF(qv);PyErr_SetString(PyExc_RuntimeError,"VM stack limit exceeded");goto vm_fail;}st[sp++]=qv;}
  else if(op==15){int n=(int)a;if(n<0||sp<2*n)goto vm_fail;PyObject*d=PyDict_New();if(!d)goto vm_fail;for(int i=0;i<n;i++){PyObject*vv=st[--sp],*kk=st[--sp];if(PyDict_SetItem(d,kk,vv)<0){Py_DECREF(kk);Py_DECREF(vv);Py_DECREF(d);goto vm_fail;}Py_DECREF(kk);Py_DECREF(vv);}if((size_t)sp>=stack_cap){Py_DECREF(d);PyErr_SetString(PyExc_RuntimeError,"VM stack limit exceeded");goto vm_fail;}st[sp++]=d;}
  else if(op==16){if(sp<1||a>=c->cc||!getcst(c,a,&ka))goto vm_fail;PyObject*o=st[--sp];v=PyObject_GetAttr(o,ka);Py_DECREF(ka);Py_DECREF(o);if(!v)goto vm_fail;if((size_t)sp>=stack_cap){Py_DECREF(v);PyErr_SetString(PyExc_RuntimeError,"VM stack limit exceeded");goto vm_fail;}st[sp++]=v;}
  else if(op==17){if(sp<2||a>=c->cc||!getcst(c,a,&ka))goto vm_fail;PyObject*val=st[--sp],*obj=st[--sp];if(PyObject_SetAttr(obj,ka,val)<0){Py_DECREF(ka);Py_DECREF(val);Py_DECREF(obj);goto vm_fail;}Py_DECREF(ka);Py_DECREF(val);Py_DECREF(obj);}
  else if(op==18){if(sp<2){goto vm_fail;}PyObject*k=st[--sp],*o=st[--sp];v=PyObject_GetItem(o,k);Py_DECREF(k);Py_DECREF(o);if(!v)goto vm_fail;if((size_t)sp>=stack_cap){Py_DECREF(v);PyErr_SetString(PyExc_RuntimeError,"VM stack limit exceeded");goto vm_fail;}st[sp++]=v;}
  else if(op==19){if(sp<3)goto vm_fail;PyObject*k=st[--sp],*o=st[--sp],*val=st[--sp];if(PyObject_SetItem(o,k,val)<0){Py_DECREF(val);Py_DECREF(k);Py_DECREF(o);goto vm_fail;}Py_DECREF(val);Py_DECREF(k);Py_DECREF(o);}
  else if(op==20){if(!sp)goto vm_fail;PyObject*x=st[--sp];v=PyObject_GetIter(x);Py_DECREF(x);if(!v)goto vm_fail;if((size_t)sp>=stack_cap){Py_DECREF(v);PyErr_SetString(PyExc_RuntimeError,"VM stack limit exceeded");goto vm_fail;}st[sp++]=v;}
  else if(op==21){if(!sp||a>f->count)goto vm_fail;PyObject*it=st[sp-1];v=PyIter_Next(it);if(!v){if(PyErr_Occurred())goto vm_fail;Py_DECREF(st[--sp]);pc=a;}else{if((size_t)sp>=stack_cap){Py_DECREF(v);PyErr_SetString(PyExc_RuntimeError,"VM stack limit exceeded");goto vm_fail;}st[sp++]=v;}}
  else if(op==22){if(a>=c->fcnt)goto vm_fail;v=PyCapsule_New((void*)(uintptr_t)a,"CAP",NULL);if(!v)goto vm_fail;if((size_t)sp>=stack_cap){Py_DECREF(v);PyErr_SetString(PyExc_RuntimeError,"VM stack limit exceeded");goto vm_fail;}st[sp++]=v;}
  else if(op==23){if(a>=c->cc||!getcst(c,a,&ka))goto vm_fail;v=PyImport_Import(ka);Py_DECREF(ka);if(!v)goto vm_fail;if((size_t)sp>=stack_cap){Py_DECREF(v);PyErr_SetString(PyExc_RuntimeError,"VM stack limit exceeded");goto vm_fail;}st[sp++]=v;}
  else if(op==24){if(sp<1||a>=c->cc||!getcst(c,a,&ka))goto vm_fail;PyObject*mod=st[--sp];v=PyObject_GetAttr(mod,ka);Py_DECREF(ka);Py_DECREF(mod);if(!v)goto vm_fail;if((size_t)sp>=stack_cap){Py_DECREF(v);PyErr_SetString(PyExc_RuntimeError,"VM stack limit exceeded");goto vm_fail;}st[sp++]=v;}
  else if(op==26){uint16_t src=(uint16_t)(a>>16),dst=(uint16_t)a;if(src>=c->reg_count||dst>=c->reg_count)goto vm_fail;Py_XDECREF(regs[dst]);regs[dst]=regs[src];Py_XINCREF(regs[dst]);}
  else if(op==29){if(!sp)goto vm_fail;PyObject*t=st[sp-1];Py_INCREF(t);if((size_t)sp>=stack_cap){Py_DECREF(t);PyErr_SetString(PyExc_RuntimeError,"VM stack limit exceeded");goto vm_fail;}st[sp++]=t;}
  else if(op==30){int n=(int)a;if(n<0||sp<1)goto vm_fail;PyObject*seq=st[--sp];PyObject*fast=PySequence_Fast(seq,"cannot unpack value");Py_DECREF(seq);if(!fast)goto vm_fail;if(PySequence_Size(fast)!=n){Py_DECREF(fast);PyErr_SetString(PyExc_ValueError,"unpack length mismatch");goto vm_fail;}for(int i=0;i<n;i++){PyObject*t=PySequence_GetItem(fast,i);Py_INCREF(t);st[sp++]=t;}Py_DECREF(fast);}
  else if(op==31){int na=(int)(a>>16),nk=(int)(a&0xffff);if(na<0||nk<0||sp<1+na+2*nk)goto vm_fail;int base=sp-na-2*nk-1;PyObject*fn=st[base];Py_INCREF(fn);PyObject*args=PyTuple_New(na);PyObject*kw=PyDict_New();if(!args||!kw){Py_XDECREF(args);Py_XDECREF(kw);Py_DECREF(fn);goto vm_fail;}for(int i=0;i<na;i++){PyObject*t=st[base+1+i];Py_INCREF(t);PyTuple_SetItem(args,i,t);}for(int i=0;i<nk;i++){PyObject*k=st[base+1+na+2*i],*vv=st[base+1+na+2*i+1];if(!PyUnicode_Check(k)||PyDict_SetItem(kw,k,vv)<0){Py_DECREF(args);Py_DECREF(kw);Py_DECREF(fn);goto vm_fail;}}for(int i=0;i<1+na+2*nk;i++)Py_DECREF(st[base+i]);sp=base;if(PyCapsule_CheckExact(fn)){void*ptr=PyCapsule_GetPointer(fn,"CAP");if(!ptr){Py_DECREF(fn);Py_DECREF(args);Py_DECREF(kw);goto vm_fail;}PyObject** av=calloc(na?na:1,sizeof(PyObject*)); if(!av){Py_DECREF(fn);Py_DECREF(args);Py_DECREF(kw);PyErr_NoMemory();goto vm_fail;} for(int ai=0;ai<na;ai++) av[ai]=PyTuple_GetItem(args,(Py_ssize_t)ai); v=rfn(c,(int)(uintptr_t)ptr,av,na,kw); free(av);}else v=PyObject_Call(fn,args,kw);Py_DECREF(fn);Py_DECREF(args);Py_DECREF(kw);if(!v)goto vm_fail;st[sp++]=v;}
  else if(op==33){int na=(int)a;if(na<0||na>1024||sp<na+2)goto vm_fail;int base=sp-na-2;PyObject*obj=st[base],*name=st[base+1],*args=PyTuple_New(na);if(!args)goto vm_fail;for(int i=0;i<na;i++){PyObject*t=st[base+2+i];Py_INCREF(t);PyTuple_SetItem(args,i,t);}PyObject*fn=PyObject_GetAttr(obj,name);if(!fn){Py_DECREF(args);goto vm_fail;}if(PyCapsule_CheckExact(fn)){void*ptr=PyCapsule_GetPointer(fn,"CAP");if(!ptr){Py_DECREF(fn);Py_DECREF(args);goto vm_fail;}PyObject**margv=calloc((size_t)na+1,sizeof(PyObject*));if(!margv){Py_DECREF(fn);Py_DECREF(args);PyErr_NoMemory();goto vm_fail;}margv[0]=obj;Py_INCREF(obj);for(int i=0;i<na;i++){margv[i+1]=PyTuple_GetItem(args,i);Py_INCREF(margv[i+1]);}v=rfn(c,(int)(uintptr_t)ptr,margv,na+1,NULL);for(int i=0;i<na+1;i++)Py_DECREF(margv[i]);free(margv);}else v=PyObject_CallObject(fn,args);Py_DECREF(fn);Py_DECREF(args);for(int i=0;i<na+2;i++)Py_DECREF(st[base+i]);sp=base;if(!v)goto vm_fail;st[sp++]=v;}
  else if(op==34){if(hsp>=32)goto vm_fail;hpc[hsp]=a;hdepth[hsp]=sp;hsp++;}
  else if(op==35){if(hsp>0)hsp--;}
  else if(op==36){if(!sp){PyErr_SetString(PyExc_RuntimeError,"raise requires an exception");goto vm_fail;}PyObject*e=st[--sp];if(PyExceptionClass_Check(e)){PyErr_SetNone(e);}else if(PyExceptionInstance_Check(e)){PyErr_SetObject((PyObject*)Py_TYPE(e),e);}else{PyErr_SetString(PyExc_TypeError,"exceptions must derive from BaseException");Py_DECREF(e);goto vm_fail;}Py_DECREF(e);goto vm_fail;}
  else if(op==27){if(a>=c->fcnt||sp<2)goto vm_fail;PyObject*bases=st[--sp],*name=st[--sp];v=rfn(c,(int)a,NULL,0,NULL);if(!v){Py_DECREF(name);Py_DECREF(bases);goto vm_fail;}if(!PyTuple_Check(bases)){Py_DECREF(v);Py_DECREF(name);Py_DECREF(bases);goto vm_fail;}PyObject*cls=PyObject_CallFunctionObjArgs((PyObject*)&PyType_Type,name,bases,v,NULL);Py_DECREF(v);Py_DECREF(name);Py_DECREF(bases);if(!cls)goto vm_fail;if((size_t)sp>=stack_cap){Py_DECREF(cls);PyErr_SetString(PyExc_RuntimeError,"VM stack limit exceeded");goto vm_fail;}st[sp++]=cls;}
  else if(op==28){ret=PyDict_Copy(local);if(!ret)goto vm_fail;goto done;}
  else if(op==25){int n=(int)a;if(n<0||sp<n)goto vm_fail;PyObject*parts=PyTuple_New(n);if(!parts)goto vm_fail;for(int i=n-1;i>=0;i--){PyObject*t=st[--sp];PyObject*q=PyObject_Str(t);Py_DECREF(t);if(!q){Py_DECREF(parts);goto vm_fail;}PyTuple_SetItem(parts,i,q);}PyObject*sep=PyUnicode_FromString("");if(!sep){Py_DECREF(parts);goto vm_fail;}v=PyUnicode_Join(sep,parts);Py_DECREF(sep);Py_DECREF(parts);if(!v)goto vm_fail;if((size_t)sp>=stack_cap){Py_DECREF(v);PyErr_SetString(PyExc_RuntimeError,"VM stack limit exceeded");goto vm_fail;}st[sp++]=v;}
  continue;
vm_fail:
  if(PyErr_Occurred() && hsp>0){
    PyObject *et=NULL,*ev=NULL,*tb=NULL;
    PyErr_Fetch(&et,&ev,&tb);
    Py_XDECREF(et); Py_XDECREF(tb);
    while(sp>hdepth[hsp-1]) Py_XDECREF(st[--sp]);
    if(!ev){PyErr_SetString(PyExc_RuntimeError,"exception without value");goto done;}
    if((size_t)sp>=stack_cap){Py_DECREF(ev);PyErr_SetString(PyExc_RuntimeError,"VM stack limit exceeded");goto done;}
    st[sp++]=ev;
    pc=hpc[--hsp];
    PyErr_Clear();
    continue;
  }
  goto done;
 }

 PyErr_SetString(PyExc_RuntimeError,"native VM halted without return");
done:
 if(!ret && !PyErr_Occurred())PyErr_SetString(PyExc_RuntimeError,"native VM execution failed"); for(int i=0;i<sp;i++)Py_XDECREF(st[i]);for(uint16_t i=0;i<c->reg_count;i++)Py_XDECREF(regs[i]);free(regs);free(st);Py_DECREF(local);return ret;
}

static int parse_pages(const uint8_t**pp,size_t*remain,PAGE**out,uint32_t*count){
 const uint8_t*p=*pp;size_t n=*remain;if(n<2)return 0;uint16_t c=u16(p);p+=2;n-=2;PAGE*a=calloc(c,sizeof(PAGE));if(c&&!a)return 0;
 for(uint16_t i=0;i<c;i++){if(n<28){free(a);return 0;}a[i].logical=u32(p);a[i].physical=u32(p+4);memcpy(a[i].nonce,p+8,16);a[i].size=u32(p+24);p+=28;n-=28;if(a[i].size>n){free(a);return 0;}a[i].blob=p;a[i].blob_len=a[i].size;p+=a[i].size;n-=a[i].size;}
 *pp=p;*remain=n;*out=a;*count=c;return 1;
}
static int verify_manifest(const uint8_t*p,size_t n,const uint8_t*root){if(n<32)return 0;uint8_t h[32];hmac256(root,32,p,n-32,h);return eq(h,p+n-32,32);}

static PyObject* cv(PyObject*self,PyObject*args){
 Py_buffer pb;PyObject*globals;if(!PyArg_ParseTuple(args,"y*O!:run",&pb,&PyDict_Type,&globals))return NULL;const uint8_t*p=pb.buf;size_t n=pb.len;
 if(n<58+32||memcmp(p,"M6C2",4)||(p[4]!=4 && p[4]!=6)){PyBuffer_Release(&pb);PyErr_SetString(PyExc_ValueError,"invalid protected container");return NULL;}
 uint8_t build[16],nd[32];memcpy(build,p+6,16);memcpy(nd,p+22,32);size_t pos=54;uint32_t ml=u32(p+pos);pos+=4;if(ml>n-pos-2-32){PyBuffer_Release(&pb);PyErr_SetString(PyExc_ValueError,"invalid metadata size");return NULL;}
 uint8_t mctx[32];size_t mcn=(p[4]==6)?12:9;memcpy(mctx,p[4]==6?"metadata-v6:":"metadata:",mcn);memcpy(mctx+mcn,build,16);mcn+=16;uint8_t wrap[32];if(p[4]==6){uint8_t extroot[32];if(!external_root_from_env(extroot,build,nd))goto fail;hmac256(extroot,32,mctx,mcn,wrap);memset(extroot,0,sizeof(extroot));}else hmac256(nd,32,mctx,mcn,wrap);uint8_t*meta=NULL;size_t mn=0;if(!decrypt_blob(p+pos,ml,wrap,mctx,mcn,&meta,&mn)){PyBuffer_Release(&pb);PyErr_SetString(PyExc_ValueError,"metadata authentication failed");return NULL;}pos+=ml;
 if(mn<1 || (meta[0]!=4 && meta[0]!=6))goto fail;
 size_t mp=1;uint8_t root[32];
 if(meta[0]==6){
  if(!external_root_from_env(root,build,nd))goto fail;
 }else{
  uint8_t shares[96];
  for(int i=0;i<3;i++){if(mp+34>mn)goto fail;uint16_t sl=u16(meta+mp);mp+=2;if(sl!=32)goto fail;memcpy(shares+i*32,meta+mp,32);mp+=32;}
  uint8_t rmsg[117];memcpy(rmsg,"root:",5);memcpy(rmsg+5,build,16);memcpy(rmsg+21,shares,96);hmac256(nd,32,rmsg,sizeof(rmsg),root);memset(shares,0,sizeof(shares));
 }
 /* Final manifest authenticates every descriptor and encrypted page. */
 if(!verify_manifest(p,n,root))goto fail;
 uint32_t preflen;if(mp+4>mn)goto fail;preflen=u32(meta+mp);mp+=4;if(preflen<34||mp+preflen>mn)goto fail;uint8_t*prefix=malloc(preflen);if(!prefix)goto fail;memcpy(prefix,meta+mp,preflen);mp+=preflen;
 if(memcmp(prefix,"M5BC",4)||prefix[4]!=1)goto fail2;uint32_t fsz=u32(prefix+26),isz=u32(prefix+30);if(34u+fsz!=preflen)goto fail2;
 if(mp+4>mn)goto fail2;uint32_t cc=u32(meta+mp);mp+=4;uint32_t*cidp=calloc(cc,sizeof(uint32_t)),*cido=calloc(cc,sizeof(uint32_t)),*cids=calloc(cc,sizeof(uint32_t));PyObject**pool=calloc(cc,sizeof(PyObject*));if((cc&&(!cidp||!cido||!cids||!pool)))goto fail2;
 for(uint32_t i=0;i<cc;i++){if(mp+16>mn)goto fail2;uint32_t cid=u32(meta+mp),pg=u32(meta+mp+4),off=u32(meta+mp+8),sz=u32(meta+mp+12);mp+=16;if(cid>=cc)goto fail2;cidp[cid]=pg;cido[cid]=off;cids[cid]=sz;}
 if(mp+4>mn)goto fail2;uint32_t cdc=u32(meta+mp);mp+=4;PAGE*cd=NULL;for(uint32_t i=0;i<cdc;i++){if(mp+12>mn)goto fail2;/* descriptors stored as logical page, offset, size */mp+=12;}
 if(mp!=mn)goto fail2;
 const uint8_t*rp=p+pos;size_t rn=n-pos-32;PAGE*codepages=NULL,*constpages=NULL;uint32_t codecount=0,constcount=0;if(!parse_pages(&rp,&rn,&codepages,&codecount))goto fail2;if(!parse_pages(&rp,&rn,&constpages,&constcount))goto fail2;if(rn<4)goto fail2;uint32_t manlen=u32(rp);rp+=4;rn-=4;if(manlen>rn)goto fail2;rp+=manlen;rn-=manlen;if(rn!=0)goto fail2;
 /* Restore code page offsets from metadata, matching logical page ids. */
 size_t qmeta=1;
 if(meta[0]==4){for(int i=0;i<3;i++){if(qmeta+2>mn)goto fail2;uint16_t sl=u16(meta+qmeta);if(sl>64||qmeta+2+sl>mn)goto fail2;qmeta+=2+sl;}}
 qmeta+=4+preflen+4+cc*16+4;
 for(uint32_t i=0;i<cdc;i++){if(qmeta+12>mn)goto fail2;uint32_t pg=u32(meta+qmeta),off=u32(meta+qmeta+4),sz=u32(meta+qmeta+8);qmeta+=12;for(uint32_t j=0;j<codecount;j++)if(codepages[j].logical==pg){codepages[j].off=off;codepages[j].size=sz;}}
 CTX cx={0};cx.prefix=prefix;cx.prefix_len=preflen;cx.instr_len=isz;cx.codepm.src=p;cx.codepm.pages=codepages;cx.codepm.count=codecount;memcpy(cx.codepm.root,root,32);memcpy(cx.codepm.build,build,16);memcpy(cx.codepm.kind,"code-page:",10);cx.codepm.kind[10]=0;if(!init_runtime_mask(cx.codepm.runtime_key))goto fail2;cx.codepm.dynamic_mask=1;cx.constpm.src=p;cx.constpm.pages=constpages;cx.constpm.count=constcount;memcpy(cx.constpm.root,root,32);memcpy(cx.constpm.build,build,16);memcpy(cx.constpm.kind,"const-page:",11);cx.constpm.kind[11]=0;cx.cid_page=cidp;cx.cid_off=cido;cx.cid_size=cids;cx.cc=cc;cx.pool=pool;cx.globals=globals;cx.reg_count=16;
 uint16_t fcnt=u16(prefix+22);if(fcnt==0)goto fail2;cx.fcnt=fcnt;cx.fs=calloc(fcnt,sizeof(FN));if(!cx.fs)goto fail2;size_t ff=34;for(uint16_t fi=0;fi<fcnt;fi++){if(ff+14>preflen)goto fail3;uint32_t name=u32(prefix+ff);(void)name;ff+=4;cx.fs[fi].off=u32(prefix+ff);ff+=4;cx.fs[fi].argc=u16(prefix+ff);ff+=2;cx.fs[fi].args=calloc(cx.fs[fi].argc,sizeof(uint32_t));if(cx.fs[fi].argc&&!cx.fs[fi].args)goto fail3;for(uint16_t j=0;j<cx.fs[fi].argc;j++){if(ff+4>preflen)goto fail3;cx.fs[fi].args[j]=u32(prefix+ff);ff+=4;}if(ff+2>preflen)goto fail3;cx.fs[fi].ndefaults=u16(prefix+ff);ff+=2;cx.fs[fi].defaults=calloc(cx.fs[fi].ndefaults,sizeof(uint32_t));if(cx.fs[fi].ndefaults&&!cx.fs[fi].defaults)goto fail3;for(uint16_t j=0;j<cx.fs[fi].ndefaults;j++){if(ff+4>preflen)goto fail3;cx.fs[fi].defaults[j]=u32(prefix+ff);ff+=4;}if(ff+4>preflen)goto fail3;cx.fs[fi].count=u32(prefix+ff);ff+=4;if(cx.fs[fi].off>isz)goto fail3;}
 cx.codepm.cache=NULL;cx.constpm.cache=NULL;PyObject*res=rfn(&cx,0,NULL,0,NULL);for(uint32_t i=0;i<cc;i++)Py_XDECREF(pool[i]);free(pool);free(cidp);free(cido);free(cids);for(uint16_t i=0;i<fcnt;i++){free(cx.fs[i].args);free(cx.fs[i].defaults);}free(cx.fs);pm_free(&cx.codepm);pm_free(&cx.constpm);memset(prefix,0,preflen);free(prefix);memset(meta,0,mn);free(meta);PyBuffer_Release(&pb);memset(root,0,32);return res;
fail3:for(uint16_t i=0;i<fcnt;i++){free(cx.fs[i].args);free(cx.fs[i].defaults);}free(cx.fs);free(pool);free(cidp);free(cido);free(cids);free(codepages);free(constpages);free(prefix);goto fail;
fail2:free(pool);free(cidp);free(cido);free(cids);free(codepages);free(constpages);free(prefix);
fail:free(meta);memset(root,0,32);PyBuffer_Release(&pb);PyErr_SetString(PyExc_ValueError,"protected payload validation failed");return NULL;
}
static PyObject* features(PyObject*self,PyObject*args){return Py_BuildValue("{s:O,s:O}","runtime_page_mask",Py_True,"lazy_authenticated_pages",Py_True);}
static PyMethodDef methods[]={{"run",cv,METH_VARARGS,"Execute authenticated VM payload."},{"features",features,METH_NOARGS,"Report runtime capabilities."},{NULL,NULL,0,NULL}};
static struct PyModuleDef mod={PyModuleDef_HEAD_INIT,"__MODULE__",NULL,-1,methods};
PyMODINIT_FUNC PyInit___MODULE__(void){return PyModule_Create(&mod);}
