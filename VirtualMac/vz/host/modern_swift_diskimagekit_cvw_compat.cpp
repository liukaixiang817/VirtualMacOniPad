// Bounded adaptation of Swift BytecodeLayouts.cpp and Metadata.cpp at
// 5ea0a2a5d8e126628da27747739e8d017c1d4882. Apache 2.0 with runtime exception.
// Only the nine compact witness tables of genuine DiskImageKit27 are accepted.
// No global Swift interposition, registry handlers, device or disk access.
#include "modern_swift_diskimagekit_cvw_compat.h"
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <pthread.h>
#include <cstring>
#include <cstdint>

extern "C" {
void *swift_retain(void *);
void swift_release(void *);
void *swift_errorRetain(void *);
void swift_errorRelease(void *);
void *swift_unknownObjectRetain(void *);
void swift_unknownObjectRelease(void *);
void *swift_bridgeObjectRetain(void *);
void swift_bridgeObjectRelease(void *);
void *objc_retain(void *);
void objc_release(void *);
void swift_initStructMetadata(void *, size_t, size_t, const void *const *, uint32_t *);
}
namespace {
constexpr unsigned char DIK[16]={0x65,0x2b,0x07,0xa9,0x98,0xbe,0x31,0xd2,0x98,0xd7,0xff,0xca,0xf1,0x4a,0xca,0x5e};
constexpr unsigned char OldSwift[16]={0xf8,0x96,0xd1,0x45,0xe0,0x25,0x39,0xd6,0xaf,0xd3,0xbc,0x0a,0x2a,0xd4,0xf8,0x39};
constexpr unsigned char NewSwift[16]={0xc9,0xb3,0x6d,0xa7,0xbb,0x34,0x35,0xaf,0xbc,0x5d,0x91,0xec,0xbc,0xaa,0x9e,0xd0};
constexpr const char *Names[]={"ASIFCreationConfiguration","ASIFLayerCreationConfiguration",
    "RAWCreationConfiguration","OpenConfiguration","_ResolvedCreationConfiguration","DILogger",
    "IncompatibleStackingError","CorruptedImageError","UnsupportedFormatError"};
constexpr unsigned Fields[]={3,5,3,2,4,2,1,1,1};
using Destroy=void (*)(void *,const void *);
using Copy=void *(*)(void *,const void *,const void *);
struct Field { size_t offset=0,size=0; unsigned tag=0; const void *metadata=nullptr; Destroy destroy=nullptr; Copy copy=nullptr; };
struct Contract { VM27DIKCVWInfo info{}; unsigned count=0; Field fields[5]{}; };
struct StoredLayout { const void *metadata=nullptr; uint64_t words[16]{}; };
// Runtime metadata singletons live for the image/process lifetime. The bounded
// pool keeps their layout strings alive without attaching a global registry.
StoredLayout Stored[32];
pthread_mutex_t Lock=PTHREAD_MUTEX_INITIALIZER;
bool Read(const void *a,void *b,size_t n) {
    if(!a || !b || !n || n>4096)return false;
    vm_size_t copied=0;
    return vm_read_overwrite(mach_task_self(),(vm_address_t)a,n,(vm_address_t)b,&copied)==KERN_SUCCESS && copied==n;
}
bool UUID(const void *base,unsigned char out[16]) {
    mach_header_64 h{};if(!Read(base,&h,sizeof(h)) || h.magic!=MH_MAGIC_64 || h.cputype!=CPU_TYPE_ARM64 || h.ncmds>1024 || h.sizeofcmds>65536)return false;
    uintptr_t at=(uintptr_t)base+sizeof(h),end=at+h.sizeofcmds;unsigned found=0;
    for(unsigned i=0;i<h.ncmds;++i){load_command lc{};if(at>end || end-at<8 || !Read((void *)at,&lc,8) || lc.cmdsize<8 || lc.cmdsize%8 || lc.cmdsize>end-at)return false;
        if(lc.cmd==LC_UUID){uuid_command u{};if(lc.cmdsize!=sizeof(u) || !Read((void *)at,&u,sizeof(u)))return false;std::memcpy(out,u.uuid,16);++found;}at+=lc.cmdsize;}
    return at==end && found==1;
}
bool Owner(const void *p,const unsigned char uuid[16],const void **base=nullptr) {
    Dl_info d{};unsigned char actual[16]{};if(!p || !dladdr(p,&d) || !UUID(d.dli_fbase,actual) || std::memcmp(actual,uuid,16))return false;
    if(base)*base=d.dli_fbase;return true;
}
bool Swift(const void *p) { return Owner(p,OldSwift) || Owner(p,NewSwift); }
void *RawFunction(void *p) { return ptrauth_strip(p,ptrauth_key_function_pointer); }
bool Primitives() {
    return Swift(RawFunction((void *)&swift_retain)) && Swift(RawFunction((void *)&swift_release)) &&
        Swift(RawFunction((void *)&swift_errorRetain)) && Swift(RawFunction((void *)&swift_errorRelease)) &&
        Swift(RawFunction((void *)&swift_unknownObjectRetain)) && Swift(RawFunction((void *)&swift_unknownObjectRelease)) &&
        Swift(RawFunction((void *)&swift_bridgeObjectRetain)) && Swift(RawFunction((void *)&swift_bridgeObjectRelease)) &&
        Swift(RawFunction((void *)&swift_initStructMetadata));
}
const unsigned char *Authenticate(const void *slot,const void *word,unsigned discriminator) {
    if(!word)return nullptr;
    return (const unsigned char *)ptrauth_auth_data(word,ptrauth_key_process_independent_data,ptrauth_blend_discriminator(slot,discriminator));
}
const unsigned char *Table(const void *metadata) {
    const void *p=nullptr;if(!metadata || ((uintptr_t)metadata&7) || !Read((const unsigned char *)metadata-8,&p,8))return nullptr;
    return Authenticate((const unsigned char *)metadata-8,p,0x2e3f);
}
int Type(const void *metadata,const unsigned char **description=nullptr) {
    const void *a=nullptr,*b=nullptr,*ptr=nullptr;uintptr_t kind=0;
    if(!metadata || ((uintptr_t)metadata&7) || !Owner(metadata,DIK,&a) || !Read(metadata,&kind,8) || kind!=0x200 || !Read((const unsigned char *)metadata+8,&ptr,8))return -1;
    auto descriptor=Authenticate((const unsigned char *)metadata+8,ptr,0xae86);
    if(!Owner(descriptor,DIK,&b) || a!=b)return -1;
    uint32_t flags=0,num=0,vector=0;int32_t rel=0;
    if(!Read(descriptor,&flags,4) || !Read(descriptor+8,&rel,4) || !Read(descriptor+20,&num,4) || !Read(descriptor+24,&vector,4))return -1;
    char name[64]{};if(!Read(descriptor+8+rel,name,sizeof(name)) || !std::memchr(name,0,sizeof(name)))return -1;
    for(unsigned i=0;i<9;++i)if(!std::strcmp(name,Names[i])) {
        if(num!=Fields[i] || (i<6 ? (flags!=0x110051 || vector!=2) : ((flags&0xffff)!=0x51)))return -1;
        if(description)*description=descriptor;return (int)i;
    }
    return -1;
}
void *Witness(const unsigned char *table,unsigned offset,unsigned discriminator) {
    void *p=nullptr;if(!Read(table+offset,&p,8) || !p)return nullptr;
    p=ptrauth_auth_and_resign(p,ptrauth_key_function_pointer,ptrauth_blend_discriminator(table+offset,discriminator),ptrauth_key_function_pointer,0);
    return p;
}
bool Nested(Field &f) {
    auto table=Table(f.metadata);uint64_t size=0;uint32_t flags=0;
    if(!table || !Read(table+64,&size,8) || size>256 || !Read(table+80,&flags,4) || (flags&0x00d00000))return false;
    f.size=size;f.destroy=(Destroy)Witness(table,8,0x04f8);f.copy=(Copy)Witness(table,16,0xe3ba);
    // Signed witnesses come from the genuine field's actual native metadata;
    // their address is never fabricated from a requested provider name.
    Dl_info di{},ci{};
    return f.destroy && f.copy && dladdr(RawFunction((void *)f.destroy),&di) && dladdr(RawFunction((void *)f.copy),&ci) && di.dli_fbase && ci.dli_fbase;
}
bool Decode(const void *metadata,Contract &c) {
    int type=Type(metadata);if(type<0 || !Primitives())return false;
    auto table=Table(metadata);const void *same=nullptr;
    if(!table || !Owner(table,DIK,&same) || !Read(table+64,&c.info,24) || !c.info.size || c.info.size>256 || c.info.stride<c.info.size || c.info.stride>256 || (c.info.flags&0x00d00000) || (c.info.flags&0xff)!=7)return false;
    c.info.type=(unsigned)type+1;
    const void *word=nullptr;if(!Read((const unsigned char *)metadata-16,&word,8) || !word)return false;
    auto layout=Authenticate((const unsigned char *)metadata-16,word,0x8b65);
    layout=(const unsigned char *)((uintptr_t)layout&~(uintptr_t)1);
    uint64_t header[2]{};if(!Read(layout,header,16) || header[0] || header[1]>80 || header[1]%8)return false;
    uint64_t words[13]{};size_t count=header[1]/8+1;
    if(!Read(layout+16,words,count*8))return false;
    if(type>=6) {
        if(header[1]!=8 || words[0]!=(type==6?UINT64_C(0x0800000000000008):UINT64_C(0x0100000000000000)) || words[1] ||
            c.info.size!=(type==6?16u:8u) || c.info.stride!=c.info.size || c.info.flags!=0x02010007 || c.info.extraInhabitants!=0x7fffffff || !Owner(layout,DIK))return false;
    }
    size_t offset=0;
    for(size_t i=0;i<count;++i){uint64_t entry=words[i];unsigned tag=(unsigned)(entry>>56);size_t delta=entry&UINT64_C(0x00ffffffffffffff);
        if(delta>c.info.size-offset)return false;offset+=delta;
        if(!tag)return i+1==count && offset==c.info.size;
        if(c.count>=5)return false;auto &f=c.fields[c.count++];f.offset=offset;f.tag=tag;
        if(tag==12) { if(++i>=count)return false;f.metadata=(const void *)words[i];if(!Nested(f))return false; }
        else if(tag==1 || tag==5 || tag==8 || tag==10)f.size=8;
        else return false;
        if(f.size>c.info.size-offset)return false;offset+=f.size;
    }
    return false;
}
Contract Require(const void *metadata) { Contract c{};if(!Decode(metadata,c))__builtin_trap();return c; }
void Value(const Contract &c,const void *p) { if(!p || ((uintptr_t)p&(c.info.flags&0xff)))__builtin_trap(); }
void Pair(const Contract &c,void *d,const void *s) {
    Value(c,d);Value(c,s);uintptr_t a=(uintptr_t)d,b=(uintptr_t)s;
    if(a>UINTPTR_MAX-c.info.size || b>UINTPTR_MAX-c.info.size || !(a+c.info.size<=b || b+c.info.size<=a))__builtin_trap();
}
void DestroyFields(const Contract &c,void *value) {
    for(unsigned i=0;i<c.count;++i){auto &f=c.fields[i];auto at=(unsigned char *)value+f.offset;void *object=nullptr;
        if(f.tag==12){f.destroy(at,f.metadata);continue;}std::memcpy(&object,at,8);
        if(f.tag==1)swift_errorRelease(object);else if(f.tag==5)swift_unknownObjectRelease(object);
        else if(f.tag==8)swift_bridgeObjectRelease(object);else objc_release(object);
    }
}
void CopyFields(const Contract &c,void *dest,const void *src) {
    std::memcpy(dest,src,c.info.size);
    for(unsigned i=0;i<c.count;++i){auto &f=c.fields[i];auto at=(unsigned char *)dest+f.offset;auto source=(const unsigned char *)src+f.offset;void *object=nullptr;
        if(f.tag==12){f.copy(at,source,f.metadata);continue;}std::memcpy(&object,source,8);
        if(f.tag==1)swift_errorRetain(object);else if(f.tag==5)swift_unknownObjectRetain(object);
        else if(f.tag==8)swift_bridgeObjectRetain(object);else objc_retain(object);
    }
}
}
extern "C" int VM27DIKCVWQuery(const void *metadata,VM27DIKCVWInfo *info) {
    Contract c{};if(!info || !Decode(metadata,c))return 0;*info=c.info;return 1;
}
extern "C" void swift_cvw_destroy(void *p,const void *m) { auto c=Require(m);Value(c,p);DestroyFields(c,p); }
extern "C" void *swift_cvw_initWithCopy(void *d,const void *s,const void *m) { auto c=Require(m);Pair(c,d,s);CopyFields(c,d,s);return d; }
extern "C" void *swift_cvw_initWithTake(void *d,void *s,const void *m) { auto c=Require(m);Pair(c,d,s);std::memcpy(d,s,c.info.size);return d; }
extern "C" void *swift_cvw_assignWithCopy(void *d,const void *s,const void *m) {
    auto c=Require(m);Value(c,d);Value(c,s);
    // Copy assignment retains each source ownership before releasing the
    // destination in upstream BytecodeLayouts.cpp:2074. Exact self assignment
    // leaves the same live value and ownership, so preserve it without traffic.
    if(d==s)return d;
    Pair(c,d,s);alignas(16) unsigned char old[256];std::memcpy(old,d,c.info.size);CopyFields(c,d,s);DestroyFields(c,old);return d;
}
extern "C" void *swift_cvw_assignWithTake(void *d,void *s,const void *m) {
    auto c=Require(m);Pair(c,d,s);DestroyFields(c,d);std::memcpy(d,s,c.info.size);return d;
}
extern "C" void *swift_cvw_initializeBufferWithCopyOfBuffer(void *d,const void *s,const void *m) {
    auto c=Require(m);
    if(!(c.info.flags&0x00020000)){Pair(c,d,s);CopyFields(c,d,s);return d;}
    uintptr_t a=(uintptr_t)d,b=(uintptr_t)s;
    if(!d || !s || (a&7) || (b&7) || a>UINTPTR_MAX-24 || b>UINTPTR_MAX-24 || !(a+24<=b || b+24<=a))__builtin_trap();
    void *box=nullptr;std::memcpy(&box,s,8);if(!box || ((uintptr_t)box&7))__builtin_trap();
    std::memcpy(d,&box,8);swift_retain(box);return (unsigned char *)box+16;
}
extern "C" void swift_cvw_initStructMetadataWithLayoutString(void *metadata,size_t flags,size_t fields,
    const unsigned char *const *types,const unsigned char *tags,uint32_t *offsets) {
    int type=Type(metadata);if(type<0 || type>=6 || flags!=0x100 || fields!=Fields[type] || !types || !tags || offsets!=(uint32_t *)((unsigned char *)metadata+16) || !Primitives())__builtin_trap();
    const void *layouts[5]{};uint64_t sizes[5]{};uint32_t fieldFlags[5]{};
    for(size_t i=0;i<fields;++i){if(tags[i])__builtin_trap();auto table=Table(types[i]);if(!table || !Read(table+64,&sizes[i],8) || sizes[i]>256 || !Read(table+80,&fieldFlags[i],4) || (fieldFlags[i]&0x00d00000))__builtin_trap();layouts[i]=table+64;}
    auto table=Table(metadata);uint32_t oldFlags=0;const void *owner=nullptr;
    if(!table || !Owner(table,DIK,&owner) || !Read(table+80,&oldFlags,4) || !(oldFlags&0x00400000))__builtin_trap();
    pthread_mutex_lock(&Lock);StoredLayout *stored=nullptr;
    for(auto &row:Stored)if(row.metadata==metadata){pthread_mutex_unlock(&Lock);__builtin_trap();}
    for(auto &row:Stored)if(!row.metadata){stored=&row;break;}
    if(!stored){pthread_mutex_unlock(&Lock);__builtin_trap();}
    // The existing host runtime computes field offsets, padding, extra
    // inhabitants and common witnesses. All fields are real metadata, tags 0.
    swift_initStructMetadata(metadata,flags,fields,layouts,offsets);
    uint64_t size=0;if(!Read(table+64,&size,8) || size>256){pthread_mutex_unlock(&Lock);__builtin_trap();}
    size_t cursor=2,previous=0;uint32_t dependencies=0;
    for(size_t i=0;i<fields;++i){dependencies|=fieldFlags[i]&0x02000000;
        if(offsets[i]>size || sizes[i]>size-offsets[i]){pthread_mutex_unlock(&Lock);__builtin_trap();}
        if(!(fieldFlags[i]&0x00010000) || !sizes[i])continue;
        stored->words[cursor++]=UINT64_C(0x0c00000000000000)|(offsets[i]-previous);
        stored->words[cursor++]=(uintptr_t)types[i];previous=offsets[i]+sizes[i];
    }
    stored->words[1]=(cursor-2)*8;stored->words[cursor]=size-previous;
    auto slot=(unsigned char *)metadata-16;auto signedPointer=ptrauth_sign_unauthenticated((void *)stored->words,ptrauth_key_process_independent_data,ptrauth_blend_discriminator(slot,0x8b65));
    std::memcpy(slot,&signedPointer,8);
    // Old Swift's layout flags predate AddressableForDependencies. Preserve
    // this actual field property instead of inventing it for every value.
    uint32_t finalFlags=0;Read(table+80,&finalFlags,4);finalFlags|=dependencies;std::memcpy((void *)(table+80),&finalFlags,4);
    stored->metadata=metadata;pthread_mutex_unlock(&Lock);
}
