/* Keep the existing native translation and error semantics. Only a bounded
 * native call stack for the specific start failure is recorded; no VM memory,
 * saved-state bytes, exception payloads or user strings are inspected. */
#define VM27OwnedVZLocalizedStringOrEnglishKeyV1 VM27InheritedVZLocalizationV2
#include "vm27_owned_vz_localization_v1.m"
#undef VM27OwnedVZLocalizedStringOrEnglishKeyV1
#include <execinfo.h>
#include <dlfcn.h>
#include <errno.h>
#include <ptrauth.h>
#include <stdint.h>

static unsigned VM27VZFailureTraceCountV2;
__attribute__((visibility("default")))
NSString *VM27OwnedVZLocalizedStringOrEnglishKeyV1(NSBundle *bundle,NSString *key) {
 NSString *result=VM27InheritedVZLocalizationV2(bundle,key);
 if([key isEqualToString:@"The virtual machine failed to start."]) {
  unsigned count=__atomic_load_n(&VM27VZFailureTraceCountV2,__ATOMIC_RELAXED);
  while(count<2 && !__atomic_compare_exchange_n(&VM27VZFailureTraceCountV2,
    &count,count+1,1,__ATOMIC_RELAXED,__ATOMIC_RELAXED)){}
  if(count<2) {
   int savedErrno=errno;void *frames[24];int total=backtrace(frames,24);
   fprintf(stderr,"[VM27VZStartFailureTraceV2] sample=%u frames=%d nativeResultUnchanged=1\n",count+1,total);
   for(int i=0;i<total;++i) {
    void *pc=ptrauth_strip(frames[i],ptrauth_key_return_address);Dl_info info={0};
    if(!dladdr(pc,&info) || !info.dli_fbase || !info.dli_fname)continue;
    const char *name=info.dli_fname;
    for(const char *p=name;*p;++p)if(*p=='/')name=p+1;
    fprintf(stderr,"[VM27VZStartFailureTraceV2] frame=%d image=%s rva=0x%lx\n",i,name,
      (unsigned long)((uintptr_t)pc-(uintptr_t)info.dli_fbase));
   }
   errno=savedErrno;
  }
 }
 return result;
}
