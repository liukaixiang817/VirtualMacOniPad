// App-private router for the six exact VZ27 compact witness imports only.
// New positive per-image import routing is mandatory. Never global interpose.
// Implementations/metadata provenance remain in the three scoped adapters.
#include "modern_swift_vz_cvw_router.h"
#define swift_cvw_destroy VM27CachingDestroy
#define swift_cvw_initWithCopy VM27CachingInitWithCopy
#define swift_cvw_assignWithCopy VM27CachingAssignWithCopy
#define swift_cvw_assignWithTake VM27CachingAssignWithTake
#define swift_cvw_initializeBufferWithCopyOfBuffer VM27CachingBufferCopy
#include "modern_swift_cvw_ownership_compat.h"
#undef swift_cvw_destroy
#undef swift_cvw_initWithCopy
#undef swift_cvw_assignWithCopy
#undef swift_cvw_assignWithTake
#undef swift_cvw_initializeBufferWithCopyOfBuffer
#include "modern_swift_efi_cvw_compat.h"
#include "modern_swift_view_adaptor_cvw_compat.h"
#include <cstring>
namespace {
unsigned Query(const void *metadata,VM27VZCVWInfo *out) {
    VM27CVWOwnershipInfo cache{};VM27EFICVWInfo efi{};VM27ViewCVWInfo view{};
    VM27VZCVWInfo value{};
    if(VM27CVWOwnershipQuery(metadata,&cache)) value={cache.size,cache.stride,cache.flags,cache.extraInhabitants,1};
    else if(VM27EFICVWQuery(metadata,&efi)) value={efi.size,efi.stride,efi.flags,efi.extraInhabitants,2};
    else if(VM27ViewCVWQuery(metadata,&view)) value={view.size,view.stride,view.flags,view.extraInhabitants,3};
    else return 0;
    if(out)*out=value;return value.type;
}
unsigned Require(const void *metadata) {unsigned type=Query(metadata,nullptr);if(!type)__builtin_trap();return type;}
}
extern "C" int VM27VZCVWQuery(const void *metadata,VM27VZCVWInfo *info) {if(!info)return 0;return Query(metadata,info)?1:0;}
extern "C" void swift_cvw_destroy(void *value,const void *metadata) {
    switch(Require(metadata)){case 1:VM27CachingDestroy(value,metadata);return;case 2:VM27EFICVWDestroy(value,metadata);return;case 3:VM27ViewCVWDestroy(value,metadata);return;default:__builtin_trap();}
}
extern "C" void *swift_cvw_initWithCopy(void *dest,const void *src,const void *metadata) {
    switch(Require(metadata)){case 1:return VM27CachingInitWithCopy(dest,src,metadata);case 2:return VM27EFICVWInitWithCopy(dest,src,metadata);case 3:return VM27ViewCVWInitWithCopy(dest,src,metadata);default:__builtin_trap();}
}
extern "C" void *swift_cvw_assignWithCopy(void *dest,const void *src,const void *metadata) {
    switch(Require(metadata)){case 1:return VM27CachingAssignWithCopy(dest,src,metadata);case 2:return VM27EFICVWAssignWithCopy(dest,src,metadata);case 3:return VM27ViewCVWAssignWithCopy(dest,src,metadata);default:__builtin_trap();}
}
extern "C" void *swift_cvw_assignWithTake(void *dest,void *src,const void *metadata) {
    switch(Require(metadata)){case 1:return VM27CachingAssignWithTake(dest,src,metadata);case 2:return VM27EFICVWAssignWithTake(dest,src,metadata);case 3:return VM27ViewCVWAssignWithTake(dest,src,metadata);default:__builtin_trap();}
}
extern "C" void *swift_cvw_initializeBufferWithCopyOfBuffer(void *dest,const void *src,const void *metadata) {
    switch(Require(metadata)){case 1:return VM27CachingBufferCopy(dest,src,metadata);case 2:return VM27EFICVWBufferCopy(dest,src,metadata);case 3:return VM27ViewCVWBufferCopy(dest,src,metadata);default:__builtin_trap();}
}
extern "C" unsigned swift_cvw_enumFn_getEnumTag(const void *value,const void *metadata) {
    unsigned type=Require(metadata);
    if(type==2)return VM27EFICVWGetEnumTag(value,metadata);
    if(type!=1||!value||((uintptr_t)value&7))__builtin_trap();
    // The authenticated CachingOptions getter is exactly LDRB + AND#1 + RET;
    // this is the original instruction contract, never a guessed enum layout.
    uint8_t byte=0;std::memcpy(&byte,(const uint8_t *)value+16,1);return byte&1;
}
