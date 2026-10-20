#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <ptrauth.h>
#include <objc/runtime.h>

struct MetadataResponse { void *metadata; uintptr_t state; };
extern "C" MetadataResponse __attribute__((swiftcall)) ownMetadata(uintptr_t)
    __asm__("_$s14VM27FixedModel16OwnStaticStorageCMa");
extern "C" unsigned char ownCN[] __asm__("_$s14VM27FixedModel16OwnStaticStorageCN");
extern "C" unsigned char ownCMn[] __asm__("_$s14VM27FixedModel16OwnStaticStorageCMn");
extern "C" unsigned char controlCN[] __asm__("_$s14VM27FixedModel16OwnStaticControlCN");
extern "C" unsigned char baseCN[] __asm__("_$ss28__ContiguousArrayStorageBaseCN");
extern "C" unsigned char baseCMn[] __asm__("_$ss28__ContiguousArrayStorageBaseCMn");
extern "C" void *swift_allocObject(void *, size_t, size_t);
extern "C" void *swift_retain(void *);
extern "C" void swift_release(void *);
extern "C" void swift_errorRelease(void *);
extern "C" void VM27StaticCNVerbatimNil(
    void * __attribute__((swift_indirect_result)), void *, void *, void *,
    void * __attribute__((swift_context)), void ** __attribute__((swift_error_result)))
    __attribute__((swiftcall));
extern "C" void VM27StaticCNWithUnsafeBufferOfObjects(
    void * __attribute__((swift_indirect_result)), void *, void *, void *,
    void * __attribute__((swift_context)), void ** __attribute__((swift_error_result)))
    __attribute__((swiftcall));
extern "C" void *VM27FixtureUInt64Metadata();
extern "C" void *VM27FixtureStringMetadata();
extern "C" void *VM27FixtureClassMetadata();
extern "C" bool VM27FixtureNilCheck(const void *, int32_t);
extern "C" bool VM27FixtureClassName(const void *);
extern "C" void VM27FixtureSetMode(int32_t);
extern "C" bool VM27FixtureSomeCheck(const void *, int32_t);
extern "C" void VM27FixtureSomeDestroy(void *, int32_t);
extern "C" uint64_t VM27FixturePayloadStats();
static unsigned checks = 0, destroyed = 0;
static void check(bool value, const char *what) {
    ++checks;
    if (!value) { std::fprintf(stderr, "FAIL %s\n", what); std::abort(); }
}
extern "C" void VM27FixtureOwnDestroyed(void *object) {
    check(object != nullptr, "deallocator actual object"); ++destroyed;
}
static uint32_t u32(const void *p) { uint32_t v; std::memcpy(&v,p,4); return v; }
static uint64_t u64(const void *p) { uint64_t v; std::memcpy(&v,p,8); return v; }
static void *dataAt(void *address, uintptr_t discriminator) {
    return ptrauth_auth_data(*static_cast<void **>(address), ptrauth_key_asda,
                            ptrauth_blend_discriminator(address,discriminator));
}
int main(int argc, char **argv) {
    const auto metadata = ownMetadata(0);
    check(metadata.metadata == ownCN && metadata.state == 0, "real CMa own CN state0");
    check(VM27FixtureClassName(ownCN), "real Swift own class name");
    check(u32(ownCN+40)==2 && u32(ownCN+48)==32 && u32(ownCN+56)==176 &&
          u32(ownCN+60)==24 && u64(ownCN+96)==16, "real176 AP24 N3 scalar fields");
    check(dataAt(ownCN+8,0xb5ab)==baseCN, "actual stock Base superclass");
    check(dataAt(ownCN+64,0xae86)==ownCMn, "owned class descriptor PAC");
    check(u32(baseCMn+24)==3 && u32(baseCMn+28)==18, "ordinary Mac Base genuinely N3 P18");
    auto cls = reinterpret_cast<Class>(ownCN);
    check(objc_getClass("_TtC14VM27FixedModel16OwnStaticStorage")==cls, "real registered distinct ObjC name");
    check(class_getSuperclass(cls)==reinterpret_cast<Class>(baseCN), "runtime superclass identity");
    check(class_getInstanceSize(cls)==32, "runtime instance32");
    void *types[] = {VM27FixtureUInt64Metadata(),VM27FixtureStringMetadata(),VM27FixtureClassMetadata()};
    if (argc==2 && std::strcmp(argv[1],"--none-trap")==0) {
        alignas(16) unsigned char result[128]; void *error=nullptr;
        void *object=swift_allocObject(ownCN,32,7);
        VM27StaticCNWithUnsafeBufferOfObjects(result,nullptr,nullptr,types[0],object,&error);
        std::fprintf(stderr,"Unexpected none return\n"); return 4;
    }
    for (int kind=0;kind<3;++kind) {
        for (unsigned iteration=0;iteration<128;++iteration) {
            alignas(16) unsigned char result[128]; std::memset(result,0xa7,sizeof(result));
            void *error=nullptr, *object=swift_allocObject(controlCN,32,7);
            VM27FixtureSetMode(0);
            VM27StaticCNWithUnsafeBufferOfObjects(result,nullptr,nullptr,types[kind],object,&error);
            check(error==nullptr && VM27FixtureSomeCheck(result,kind), "actual Swift some moved with R witness");
            if (kind==2) check(VM27FixturePayloadStats()==(uint64_t(iteration+1)<<32|iteration),"class payload stays alive through take");
            VM27FixtureSomeDestroy(result,kind);
            if (kind==2) check(VM27FixturePayloadStats()==(uint64_t(iteration+1)<<32|uint64_t(iteration+1)),"taken class payload destroyed once");
            std::memset(result,0xa7,sizeof(result));
            VM27FixtureSetMode(1);
            VM27StaticCNWithUnsafeBufferOfObjects(result,nullptr,nullptr,types[kind],object,&error);
            check(error!=nullptr, "actual generic Swift throw forwarded");
            bool untouched=true;for (unsigned char byte:result) untouched &= byte==0xa7;
            check(untouched,"error preserves all output bytes"); swift_errorRelease(error);
            swift_release(object);
        }
    }
    for (int kind=0; kind<3; ++kind) {
        alignas(16) unsigned char result[128]; std::memset(result,0xa7,sizeof(result));
        void *error = nullptr;
        VM27StaticCNVerbatimNil(result,nullptr,nullptr,types[kind],nullptr,&error);
        check(error==nullptr && VM27FixtureNilCheck(result,kind), "genuine generic nil value witness");
    }
    for (unsigned i=0;i<128;++i) {
        void *object = swift_allocObject(ownCN,32,7);
        check(object!=nullptr, "real own class heap allocation");
        check(dataAt(object,0x6ae1)==ownCN, "actual object ISA PAC");
        const uint64_t field0=UINT64_C(0x8170000000000000)+i,field1=UINT64_C(0xd0c0000000000000)+i;
        std::memcpy(static_cast<unsigned char *>(object)+16,&field0,sizeof(field0));
        std::memcpy(static_cast<unsigned char *>(object)+24,&field1,sizeof(field1));
        check(u64(static_cast<unsigned char *>(object)+16)==field0 &&
              u64(static_cast<unsigned char *>(object)+24)==field1,"actual own 16-byte inherited field storage");
        check(swift_retain(object)==object, "actual Swift retain");
        swift_release(object); check(destroyed==384+i, "retained object stays alive");
        swift_release(object); check(destroyed==384+i+1, "owned deallocator once");
    }
    check(VM27FixturePayloadStats()==(uint64_t(128)<<32|128),"all actual ARC payloads released");
    std::printf("OWN_STATIC_CN_MODEL checks=%u created=512 destroyed=%u some=384 thrown=384 payloadCreated=128 payloadDestroyed=128 oldN2=0 originalIdentity=0 nativeCPU=0\n",checks,destroyed);
}
