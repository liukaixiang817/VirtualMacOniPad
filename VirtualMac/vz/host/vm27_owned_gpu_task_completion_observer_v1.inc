/* Only this owned VMM's exact PG class is interposed. Foundation, Metal and
 * all other processes are untouched. Every original callback runs once with
 * unchanged token/result/error; no stamp or event value is written here. */
#include <stdatomic.h>

typedef void (*VM27PGCompleteNativeV1)(id,SEL,uint64_t,uint32_t,NSError *);
static VM27PGCompleteNativeV1 VM27PGCompleteOriginalV1;
static Class VM27PGCompleteClassV1;
static SEL VM27PGCompleteSelectorV1;
static _Atomic(uint64_t) VM27PGCompleteCountV1;
static _Atomic(unsigned) VM27PGCompleteFailuresV1;

static __attribute__((noinline)) void VM27PGObserveCompleteV1(const char *stage,
 uint64_t sample,id receiver,uint64_t token,uint32_t result,NSError *error) {
 int saved=errno;
 @try {
  NSString *domain=error.domain,*message=error.localizedDescription;
  if(domain.length>128)domain=[domain substringToIndex:128];
  if(message.length>512)message=[message substringToIndex:512];
  char d[513]={0},m[2049]={0};
  if(domain && ![domain getCString:d maxLength:sizeof(d) encoding:NSUTF8StringEncoding])strcpy(d,"<unavailable>");
  if(message && ![message getCString:m maxLength:sizeof(m) encoding:NSUTF8StringEncoding])strcpy(m,"<unavailable>");
  for(char *s=d;*s;++s)if(*s=='\n'||*s=='\r')*s=' ';
  for(char *s=m;*s;++s)if(*s=='\n'||*s=='\r')*s=' ';
  dprintf(2,"[Independent27GPUParent] native-completion sample=%llu stage=%s pid=%d receiver=%p token=%llu result=%u error=%p domain=%s code=%ld description=%s nativeIMP=0x35b68 originalArgumentsUnchanged=1 eventWrites=0\n",
   (unsigned long long)sample,stage,getpid(),receiver,(unsigned long long)token,
   result,error,d,(long)error.code,m);
 } @catch(id exception) {
  (void)exception;dprintf(2,"[Independent27GPUParent] native-completion sample=%llu stage=%s observationException=1 originalCallbackUnchanged=1\n",(unsigned long long)sample,stage);
 }
 errno=saved;
}
static void VM27PGCompleteObservedV1(id receiver,SEL selector,uint64_t token,
 uint32_t result,NSError *error) {
 int incoming=errno;atomic_thread_fence(memory_order_acquire);
 VM27PGCompleteNativeV1 original=VM27PGCompleteOriginalV1;
 if(!original)_exit(70);
 bool exact=object_getClass(receiver)==VM27PGCompleteClassV1 && selector==VM27PGCompleteSelectorV1;
 uint64_t sample=exact?atomic_fetch_add_explicit(&VM27PGCompleteCountV1,1,memory_order_relaxed)+1:0;
 bool selected=sample && (sample<=16 || (sample<=(UINT64_C(1)<<20) && !(sample&(sample-1))));
 if(exact && result!=1) {
  unsigned n=atomic_load_explicit(&VM27PGCompleteFailuresV1,memory_order_relaxed);
  while(n<8 && !atomic_compare_exchange_weak_explicit(&VM27PGCompleteFailuresV1,&n,n+1,memory_order_relaxed,memory_order_relaxed)){}
  if(n<8)selected=true;
 }
 if(selected)VM27PGObserveCompleteV1("received",sample,receiver,token,result,error);
 errno=incoming;
 original(receiver,selector,token,result,error);
 int actual=errno;
 if(selected)VM27PGObserveCompleteV1("original-returned",sample,receiver,token,result,error);
 errno=actual;
}
static BOOL VM27PGInstallCompleteObserverV1(void) {
 static dispatch_once_t once;static BOOL installed=NO;
 dispatch_once(&once,^{
  const int saved=errno;
  Class cls=objc_getClass("PGRemoteTaskDeviceDelegate");
  SEL selector=sel_registerName("completeAsyncTokenID:success:error:");
  Method method=cls?class_getInstanceMethod(cls,selector):NULL;
  IMP native=method?method_getImplementation(method):NULL;
  const void *address=native?ptrauth_strip(native,ptrauth_key_function_pointer):NULL;
  Dl_info image={0};uint8_t uuid[16]={0};
  BOOL valid=method && address && dladdr(address,&image) && image.dli_fname &&
   !strcmp(image.dli_fname,PVGImagePathV1) &&
   PVGReadUUIDV1(image.dli_fbase,MH_DYLIB,uuid) && !memcmp(uuid,PVGImageUUIDV1,16) &&
   (uintptr_t)address==(uintptr_t)image.dli_fbase+0x35b68 &&
   (uintptr_t)cls==(uintptr_t)image.dli_fbase+0x84af0 &&
   method_getNumberOfArguments(method)==5 &&
   !strcmp(method_getTypeEncoding(method),"v36@0:8Q16I24@28");
  char type[32]={0};
  if(valid){method_getReturnType(method,type,sizeof(type));valid=!strcmp(type,"v");}
  const char *expected[]={"@",":","Q","I","@"};
  for(unsigned i=0;valid && i<5;++i){method_getArgumentType(method,i,type,sizeof(type));valid=!strcmp(type,expected[i]);}
  if(valid) {
   VM27PGCompleteOriginalV1=(VM27PGCompleteNativeV1)native;
   VM27PGCompleteClassV1=cls;VM27PGCompleteSelectorV1=selector;
   atomic_thread_fence(memory_order_release);
   IMP old=method_setImplementation(method,(IMP)VM27PGCompleteObservedV1);
   installed=ptrauth_strip(old,ptrauth_key_function_pointer)==address &&
    ptrauth_strip(method_getImplementation(method),ptrauth_key_function_pointer)==
     ptrauth_strip((IMP)VM27PGCompleteObservedV1,ptrauth_key_function_pointer);
   if(!installed)_exit(70);
  }
  dprintf(2,"[Independent27GPUParent] native-completion-observer installed=%d exactClass=%p originalRVA=0x35b68 scopedOwnedVMMOnly=1 typedOriginalCalledOnce=1 noFoundationOrMetalClassMutation=1 eventWrites=0\n",installed,cls);
  errno=saved;
 });
 return installed;
}
