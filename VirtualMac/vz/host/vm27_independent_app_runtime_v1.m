#import "vm27_independent_app_runtime_v1.h"
#include "vm27_independent_app_runtime_anchor_v1.h"
#include <CommonCrypto/CommonDigest.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#if !__has_feature(objc_arc)
#error Independent runtime requires ARC.
#endif
#if defined(VM27_INDEPENDENT_RUNTIME_TESTING) && TARGET_OS_IPHONE
#error Runtime fixture admission is forbidden on iOS.
#endif
@protocol VM27RuntimeActualVMV1 <NSObject>
- (dispatch_queue_t)queue;
- (NSInteger)state;
@end
static pthread_mutex_t RuntimeMutexV1=PTHREAD_MUTEX_INITIALIZER;
static NSString *LoadedRootV1;
static NSDictionary *LoadedManifestV1;
static NSMutableArray<NSValue *> *RetainedHandlesV1;
static id<VM27RuntimeActualVMV1> BoundVMV1;
static dispatch_queue_t BoundQueueV1;
static const char RuntimeQueueKeyV1;
static pid_t LoadedPIDV1;
static BOOL RuntimePoisonedV1;
static BOOL RefuseV1(NSError **out,NSString *reason) {
 if(out)*out=[NSError errorWithDomain:@"VirtualMac.Independent27Runtime" code:1
  userInfo:@{NSLocalizedDescriptionKey:reason}];
 return NO;
}
static NSData *DigestV1(NSData *data) {
 uint8_t digest[CC_SHA256_DIGEST_LENGTH];
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
 CC_SHA256(data.bytes,(CC_LONG)data.length,digest);
#pragma clang diagnostic pop
 return [NSData dataWithBytes:digest length:sizeof(digest)];
}
static NSString *HexV1(NSData *data) {
 NSMutableString *s=[NSMutableString stringWithCapacity:data.length*2];
 const uint8_t *p=data.bytes;for(NSUInteger i=0;i<data.length;i++)[s appendFormat:@"%02x",p[i]];return s;
}
static BOOL RelativeV1(id path) {
 if(![path isKindOfClass:NSString.class] || ![path length] || [path length]>1024 || [path hasPrefix:@"/"])return NO;
 for(NSString *part in [path componentsSeparatedByString:@"/"])
  if(!part.length || [part isEqual:@"."] || [part isEqual:@".."] ||
   [part rangeOfCharacterFromSet:NSCharacterSet.controlCharacterSet].location!=NSNotFound)return NO;
 return [path rangeOfString:@"VZHostCompat"].location==NSNotFound;
}
/* Every component is opened relative to the already admitted directory.
 * A final symlink, directory, changing inode, short read or extra byte fails. */
static NSData *ReadAtV1(int root,NSString *relative,size_t limit,NSError **error) {
 if(!RelativeV1(relative)){RefuseV1(error,@"Invalid runtime file path.");return nil;}
 NSArray *parts=[relative componentsSeparatedByString:@"/"];int dir=dup(root);
 if(dir<0){RefuseV1(error,@"Cannot duplicate the runtime directory.");return nil;}
 for(NSUInteger i=0;i+1<parts.count;i++) {
  int next=openat(dir,[parts[i] fileSystemRepresentation],O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);
  close(dir);dir=next;if(dir<0){RefuseV1(error,@"Runtime directory component is unavailable.");return nil;}
 }
 int fd=openat(dir,[[parts lastObject] fileSystemRepresentation],O_RDONLY|O_NOFOLLOW|O_CLOEXEC);close(dir);
 struct stat before={0},after={0};
 if(fd<0 || fstat(fd,&before) || !S_ISREG(before.st_mode) || before.st_size<=0 ||
  (uint64_t)before.st_size>limit) {
  if(fd>=0)close(fd);RefuseV1(error,@"Runtime file is unavailable or exceeds its bound.");return nil;
 }
 NSMutableData *data=[NSMutableData dataWithLength:(NSUInteger)before.st_size];size_t used=0;
 while(used<data.length) {
  ssize_t n=read(fd,(uint8_t *)data.mutableBytes+used,data.length-used);
  if(n<0 && errno==EINTR)continue;if(n<=0)break;used+=(size_t)n;
 }
 uint8_t extra;ssize_t trailing;do{trailing=read(fd,&extra,1);}while(trailing<0 && errno==EINTR);
 BOOL stable=used==data.length && trailing==0 && !fstat(fd,&after) && before.st_dev==after.st_dev &&
  before.st_ino==after.st_ino && before.st_size==after.st_size &&
  before.st_mtimespec.tv_sec==after.st_mtimespec.tv_sec && before.st_mtimespec.tv_nsec==after.st_mtimespec.tv_nsec &&
  before.st_ctimespec.tv_sec==after.st_ctimespec.tv_sec && before.st_ctimespec.tv_nsec==after.st_ctimespec.tv_nsec;
 if(close(fd))stable=NO;
 if(!stable){RefuseV1(error,@"Runtime file changed or could not be read completely.");return nil;}return data;
}
static BOOL U32V1(NSData *data,size_t at,uint32_t *out) {
 if(at>data.length || 4>data.length-at)return NO;memcpy(out,(const uint8_t *)data.bytes+at,4);return YES;
}
static uint32_t BE32V1(const uint8_t *p){return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];}
static BOOL ExtentV1(size_t at,size_t bytes,size_t limit){return at<=limit && bytes<=limit-at;}
static NSString *MachUUIDV1(NSData *data,uint32_t *signatureAt,uint32_t *signatureBytes) {
 uint32_t magic,ncmd,size;if(!U32V1(data,0,&magic) || magic!=MH_MAGIC_64 ||
  !U32V1(data,16,&ncmd) || !U32V1(data,20,&size) || ncmd>512 || !ExtentV1(32,size,data.length))return nil;
 size_t at=32,end=32+size;NSString *uuid=nil;BOOL foundSignature=NO;
 for(uint32_t i=0;i<ncmd;i++) {
  uint32_t cmd,bytes;if(!U32V1(data,at,&cmd) || !U32V1(data,at+4,&bytes) || bytes<8 || (bytes&7) || !ExtentV1(at,bytes,end))return nil;
  if(cmd==LC_UUID){if(bytes!=24 || uuid)return nil;uuid=HexV1([data subdataWithRange:NSMakeRange(at+8,16)]);}
  if(cmd==LC_CODE_SIGNATURE){if(bytes!=16 || foundSignature)return nil;foundSignature=YES;
   if(!U32V1(data,at+8,signatureAt) || !U32V1(data,at+12,signatureBytes))return nil;}
  at+=bytes;
 }
 return at==end && uuid && foundSignature && ExtentV1(*signatureAt,*signatureBytes,data.length)?uuid:nil;
}
/* The full signed-file digest is anchored by the final product manifest.
 * Additionally verify the actual SHA256 CodeDirectory and all code pages and
 * special slots, including genuine external Info/CodeResources when present. */
static BOOL SignatureV1(NSData *data,NSDictionary *row,NSDictionary *contents,NSError **error) {
 uint32_t start=0,bytes=0;NSString *uuid=MachUUIDV1(data,&start,&bytes);
 if(!uuid || ![uuid isEqual:row[@"uuid"]] || bytes<12)return RefuseV1(error,@"Runtime Mach-O identity or signature is invalid.");
 const uint8_t *file=data.bytes,*blob=file+start;uint32_t length=BE32V1(blob+4),count=BE32V1(blob+8);
 if(BE32V1(blob)!=0xfade0cc0 || length>bytes || length<12 || count>64 || !ExtentV1(12,(size_t)count*8,length))
  return RefuseV1(error,@"Invalid code-signature container.");
 NSMutableDictionary<NSNumber *,NSData *> *slots=[NSMutableDictionary dictionary];NSData *directory=nil;
 for(uint32_t i=0;i<count;i++) {
  uint32_t type=BE32V1(blob+12+i*8),offset=BE32V1(blob+16+i*8);
  if(!ExtentV1(offset,8,length))return RefuseV1(error,@"Invalid signature slot.");
  uint32_t n=BE32V1(blob+offset+4);if(n<8 || !ExtentV1(offset,n,length) || slots[@(type)])return RefuseV1(error,@"Invalid signature extent.");
  NSData *value=[NSData dataWithBytes:blob+offset length:n];slots[@(type)]=value;if(type==0)directory=value;
 }
 if(directory.length<44)return RefuseV1(error,@"A CodeDirectory is required.");
 const uint8_t *cd=directory.bytes;uint32_t version=BE32V1(cd+8),hashAt=BE32V1(cd+16),special=BE32V1(cd+24),code=BE32V1(cd+28),limit=BE32V1(cd+32);
 unsigned hashSize=cd[36],hashType=cd[37],page=cd[39];
 if(BE32V1(cd)!=0xfade0c02 || BE32V1(cd+4)!=directory.length || version<0x20001 ||
  hashSize!=32 || hashType!=2 || page>16 || !page || limit>start || special>64 ||
  hashAt<(size_t)special*32 || !ExtentV1(hashAt,(size_t)code*32,directory.length) ||
  code!=((uint64_t)limit+((uint64_t)1<<page)-1)>>page)
  return RefuseV1(error,@"Unsupported or inconsistent CodeDirectory.");
 if(version>=0x20300 && (directory.length<64 || BE32V1(cd+56)!=0 || (BE32V1(cd+60) && BE32V1(cd+60)!=limit)))
  return RefuseV1(error,@"Unsupported extended code limit.");
 NSString *actualCD=HexV1([DigestV1(directory) subdataWithRange:NSMakeRange(0,20)]);
 if(![actualCD isEqual:row[@"cdhash"]])return RefuseV1(error,@"CodeDirectory hash does not match the signed product.");
 for(uint32_t i=0;i<code;i++) {
  size_t at=(size_t)i<<page,n=MIN((size_t)1<<page,(size_t)limit-at);
  if(memcmp(DigestV1([NSData dataWithBytes:file+at length:n]).bytes,cd+hashAt+(size_t)i*32,32))
   return RefuseV1(error,@"Code-signature page hash mismatch.");
 }
 NSDictionary *external=row[@"signatureSlots"];
 if(external && ![external isKindOfClass:NSDictionary.class])return RefuseV1(error,@"Invalid external signature slots.");
 for(uint32_t i=1;i<=special;i++) {
  const uint8_t *expected=cd+hashAt-(size_t)i*32;uint8_t nonzero=0;for(unsigned j=0;j<32;j++)nonzero|=expected[j];
  NSData *value=slots[@(i)];NSString *idValue=external[[@(i) stringValue]];
  if(idValue){if(value || ![idValue isKindOfClass:NSString.class])return RefuseV1(error,@"Ambiguous special signature slot.");value=contents[idValue];}
  if(value){if(memcmp(DigestV1(value).bytes,expected,32))return RefuseV1(error,@"Special code-signature slot mismatch.");}
  else if(nonzero)return RefuseV1(error,@"Required special signature slot is missing.");
 }
 return YES;
}
static BOOL ProfileV1(void) {
#if defined(VM27_INDEPENDENT_RUNTIME_TESTING)
 return YES;
#else
 const char *keys[]={"hw.machine","kern.osrelease","kern.osversion"};
 const char *values[]={"iPad14,6","22.1.0","20B101"};
 for(unsigned i=0;i<3;i++){char actual[64]={0};size_t n=sizeof(actual);
  if(sysctlbyname(keys[i],actual,&n,NULL,0) || n!=strlen(values[i])+1 || memcmp(actual,values[i],n))return NO;}
 return YES;
#endif
}
static BOOL ValidateV1(NSString *root,NSDictionary **manifest,NSDictionary **contents,NSError **error) {
 if(![root isKindOfClass:NSString.class] || ![root isAbsolutePath] || !ProfileV1())return RefuseV1(error,@"The independent runtime requires its recorded device profile and absolute root.");
 char actual[PATH_MAX];if(!realpath(root.fileSystemRepresentation,actual) || ![root isEqual:[NSString stringWithUTF8String:actual]])
  return RefuseV1(error,@"Runtime root must be the actual canonical directory.");
 int fd=open(actual,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return RefuseV1(error,@"Runtime root cannot be opened.");
 NSData *raw=ReadAtV1(fd,@"VM27IndependentRuntimeManifestV1.plist",512*1024,error);
 if(!raw || raw.length!=VM27IndependentRuntimeManifestBytesV1 ||
  memcmp(DigestV1(raw).bytes,VM27IndependentRuntimeManifestSHA256V1,32)) {
  close(fd);return RefuseV1(error,@"Runtime manifest does not match the compiled final product.");
 }
 id parsed=[NSPropertyListSerialization propertyListWithData:raw options:NSPropertyListImmutable format:NULL error:error];
 if(![parsed isKindOfClass:NSDictionary.class] || ![parsed[@"schema"] isEqual:@1] || ![parsed[@"runtimeVersion"] isEqual:@27] ||
  ![parsed[@"files"] isKindOfClass:NSArray.class] || [parsed[@"files"] count]>256 ||
  ![parsed[@"loadOrder"] isKindOfClass:NSArray.class] || ![parsed[@"entries"] isKindOfClass:NSArray.class] ||
  ![parsed[@"childEntryContract"] isKindOfClass:NSDictionary.class]) {
  close(fd);return RefuseV1(error,@"Invalid independent runtime product schema.");
 }
 NSMutableDictionary *all=[NSMutableDictionary dictionary],*rows=[NSMutableDictionary dictionary];
 for(id row in parsed[@"files"]) {
  if(![row isKindOfClass:NSDictionary.class] || !RelativeV1(row[@"path"]) ||
   ![row[@"id"] isKindOfClass:NSString.class] || ![row[@"id"] length] || rows[row[@"id"]] ||
   ![row[@"sha256"] isKindOfClass:NSString.class] || [row[@"sha256"] length]!=64 ||
   ![row[@"bytes"] isKindOfClass:NSNumber.class]) {close(fd);return RefuseV1(error,@"Invalid product file record.");}
  NSData *data=ReadAtV1(fd,row[@"path"],64*1024*1024,error);
  if(!data || data.length!=[row[@"bytes"] unsignedLongLongValue] || ![HexV1(DigestV1(data)) isEqual:row[@"sha256"]]) {
   close(fd);return RefuseV1(error,@"A runtime file does not match the signed frozen product.");}
  all[row[@"id"]]=data;rows[row[@"id"]]=row;
 }
 BOOL closed=!close(fd);
 if(!closed)return RefuseV1(error,@"Runtime directory release failed.");
 for(NSDictionary *row in [rows allValues]) {
  if([row[@"kind"] isEqual:@"mach-o"] && !SignatureV1(all[row[@"id"]],row,all,error))return NO;
  if(![row[@"kind"] isEqual:@"mach-o"] && ![row[@"kind"] isEqual:@"resource"])return RefuseV1(error,@"Unknown runtime file kind.");
 }
 NSString *proof=parsed[@"dependencyProofID"];
 if(![proof isKindOfClass:NSString.class] || !all[proof] || ![rows[proof][@"kind"] isEqual:@"resource"])
  return RefuseV1(error,@"The finalized dependency and process-entry proof is required.");
 NSMutableSet *loaded=[NSMutableSet set];
 for(id key in parsed[@"loadOrder"]) {
  if(![key isKindOfClass:NSString.class] || [loaded containsObject:key] || ![rows[key][@"kind"] isEqual:@"mach-o"] ||
   ![rows[key][@"role"] isEqual:@"frontend"])return RefuseV1(error,@"Invalid frontend load order.");
  [loaded addObject:key];
 }
 if(!loaded.count || ![parsed[@"entries"] count])return RefuseV1(error,@"The actual frontend graph and entry definitions are required.");
 for(NSDictionary *entry in parsed[@"entries"]) {
  if(![entry isKindOfClass:NSDictionary.class] || ![loaded containsObject:entry[@"fileID"]] ||
   ![entry[@"symbol"] isKindOfClass:NSString.class] || ![entry[@"symbol"] length] ||
   ![entry[@"rva"] isKindOfClass:NSNumber.class])return RefuseV1(error,@"Invalid actual runtime entry.");
 }
 NSDictionary *child=parsed[@"childEntryContract"],*provider=rows[child[@"providerID"]],*image=rows[child[@"childID"]];
 if(!provider || !image || ![loaded containsObject:child[@"providerID"]] || ![image[@"role"] isEqual:@"child"] ||
  ![child[@"symbol"] isEqual:@"hv_vm_config_create"] || ![child[@"mainUUID"] isEqual:image[@"uuid"]] ||
  ![child[@"setupBLFileOffset"] isKindOfClass:NSNumber.class] || ![child[@"setupBLWord"] isKindOfClass:NSNumber.class] ||
  ![child[@"providerEntryRVA"] isKindOfClass:NSNumber.class])return RefuseV1(error,@"Missing genuine child VM setup entry contract.");
 uint32_t word=0;if(!U32V1(all[child[@"childID"]],[child[@"setupBLFileOffset"] unsignedLongLongValue],&word) ||
  word!=[child[@"setupBLWord"] unsignedIntValue] || word!=0x9404a45a)
  return RefuseV1(error,@"The child no longer has the reviewed original VM setup call.");
 *manifest=parsed;*contents=all;return YES;
}
BOOL VM27IndependentAppRuntimePreflightV1(NSString *root,NSError **error) {
 @try{NSDictionary *manifest=nil,*contents=nil;return ValidateV1(root,&manifest,&contents,error);}
 @catch(NSException *exception){(void)exception;return RefuseV1(error,@"Runtime preflight raised an exception.");}
}
static BOOL EntryV1(void *handle,NSString *path,NSString *symbol,NSNumber *rva,NSString *uuid,NSError **error) {
 dlerror();void *function=dlsym(handle,symbol.UTF8String);const char *failure=dlerror();Dl_info info={0};
 if(failure || !function || !dladdr(function,&info) || !info.dli_fbase || !info.dli_fname ||
  ![path isEqual:[NSString stringWithUTF8String:info.dli_fname]])return RefuseV1(error,@"Runtime entry resolved to an unexpected image.");
 const struct mach_header_64 *h=info.dli_fbase;
 if(h->magic!=MH_MAGIC_64 || h->ncmds>512 || h->sizeofcmds>1024*1024)return RefuseV1(error,@"Loaded runtime identity is invalid.");
 const uint8_t *at=(const uint8_t *)(h+1),*end=at+h->sizeofcmds;NSString *actual=nil;
 for(uint32_t i=0;i<h->ncmds;i++) {
  if((size_t)(end-at)<8)return RefuseV1(error,@"Loaded runtime command is truncated.");
  const struct load_command *lc=(const void *)at;
  if(lc->cmdsize<8 || lc->cmdsize>(size_t)(end-at))return RefuseV1(error,@"Loaded runtime command is invalid.");
  if(lc->cmd==LC_UUID){if(lc->cmdsize!=24 || actual)return RefuseV1(error,@"Loaded UUID is invalid.");actual=HexV1([NSData dataWithBytes:at+8 length:16]);}
  at+=lc->cmdsize;
 }
 uintptr_t code=(uintptr_t)function;
#if __has_feature(ptrauth_calls)
 code=(uintptr_t)__builtin_ptrauth_strip(function,0);
#endif
 if(at!=end || ![actual isEqual:uuid] || code<(uintptr_t)h || code-(uintptr_t)h!=rva.unsignedLongLongValue)
  return RefuseV1(error,@"Runtime entry UUID or original offset mismatch.");
 return YES;
}
BOOL VM27IndependentAppRuntimeLoadV1(NSString *root,NSError **error) {
 NSDictionary *manifest=nil,*contents=nil;
 @try{if(!ValidateV1(root,&manifest,&contents,error))return NO;}
 @catch(NSException *exception){(void)exception;return RefuseV1(error,@"Runtime validation raised an exception.");}
 if(pthread_mutex_lock(&RuntimeMutexV1))return RefuseV1(error,@"Runtime admission lock failed.");
 BOOL result=NO;
 @try {
  if(RuntimePoisonedV1 || (LoadedPIDV1 && LoadedPIDV1!=getpid())) {RefuseV1(error,@"Partial or inherited runtime state requires a fresh process.");}
  else if(LoadedRootV1){result=[LoadedRootV1 isEqual:root];if(!result)RefuseV1(error,@"A different runtime is already loaded.");}
  else {
   LoadedPIDV1=getpid();RetainedHandlesV1=[NSMutableArray array];NSMutableDictionary *rows=[NSMutableDictionary dictionary],*handles=[NSMutableDictionary dictionary];
   for(NSDictionary *row in manifest[@"files"])rows[row[@"id"]]=row;
   result=YES;
   for(NSString *key in manifest[@"loadOrder"]) {
    NSString *path=[root stringByAppendingPathComponent:rows[key][@"path"]];
    void *handle=dlopen(path.fileSystemRepresentation,RTLD_NOW|RTLD_GLOBAL);
    if(!handle){const char *reason=dlerror();RefuseV1(error,[NSString stringWithFormat:@"Independent runtime load failed: %s",reason?:"unknown error"]);result=NO;break;}
    NSValue *value=[NSValue valueWithPointer:handle];[RetainedHandlesV1 addObject:value];handles[key]=value;
   }
   for(NSDictionary *entry in manifest[@"entries"]) {
    if(!result)break;NSString *key=entry[@"fileID"];NSDictionary *row=rows[key];
    result=EntryV1([handles[key] pointerValue],[root stringByAppendingPathComponent:row[@"path"]],entry[@"symbol"],entry[@"rva"],row[@"uuid"],error);
   }
   if(result) {
    NSDictionary *child=manifest[@"childEntryContract"],*row=rows[child[@"providerID"]];
    /* Resolve the installed entry, but do not invoke it in the frontend. Its
     * child-only caller guard performs the real installation on VM setup. */
    result=EntryV1([handles[child[@"providerID"]] pointerValue],[root stringByAppendingPathComponent:row[@"path"]],
     child[@"symbol"],child[@"providerEntryRVA"],row[@"uuid"],error);
   }
   if(result){LoadedRootV1=[root copy];LoadedManifestV1=manifest;}
   else RuntimePoisonedV1=YES;
  }
 } @catch(NSException *exception){(void)exception;RuntimePoisonedV1=YES;result=RefuseV1(error,@"Runtime loading raised an exception; acquired handles remain retained.");}
 if(pthread_mutex_unlock(&RuntimeMutexV1))return RefuseV1(error,@"Runtime admission unlock failed.");return result;
}
BOOL VM27IndependentAppRuntimeBindGuestV1(id vm,dispatch_queue_t queue,NSError **error) {
 if(!pthread_main_np() || queue!=dispatch_get_main_queue())return RefuseV1(error,@"Guest binding must execute on the actual VM main queue.");
 if(pthread_mutex_lock(&RuntimeMutexV1))return RefuseV1(error,@"Guest binding lock failed.");BOOL result=NO;
 @try {
  Class cls=NSClassFromString(@"VZVirtualMachine");
  if(RuntimePoisonedV1 || !LoadedRootV1 || LoadedPIDV1!=getpid() || !cls || ![vm isKindOfClass:cls] ||
   ![vm respondsToSelector:@selector(queue)] || ![vm respondsToSelector:@selector(state)] || [(id<VM27RuntimeActualVMV1>)vm queue]!=queue)
   RefuseV1(error,@"The original loaded VM and its actual serial queue are required.");
  else if(BoundVMV1 && BoundVMV1!=vm && [BoundVMV1 state]!=0)RefuseV1(error,@"The previously bound VM has not stopped.");
  else {
   BoundVMV1=vm;BoundQueueV1=queue;
   dispatch_queue_set_specific(queue,&RuntimeQueueKeyV1,(__bridge void *)vm,NULL);result=YES;
  }
 } @catch(NSException *exception){(void)exception;result=RefuseV1(error,@"Original guest binding raised an exception.");}
 if(pthread_mutex_unlock(&RuntimeMutexV1))return RefuseV1(error,@"Guest binding unlock failed.");return result;
}
BOOL VM27IndependentAppRuntimeGuestStartedV1(NSError **error) {
 if(pthread_mutex_lock(&RuntimeMutexV1))return RefuseV1(error,@"Guest state lock failed.");BOOL result=NO;
 @try {
  if(RuntimePoisonedV1 || !LoadedRootV1 || LoadedPIDV1!=getpid() || !BoundVMV1 || !BoundQueueV1 ||
   dispatch_get_specific(&RuntimeQueueKeyV1)!=(__bridge void *)BoundVMV1 || [BoundVMV1 queue]!=BoundQueueV1 || [BoundVMV1 state]!=1)
   RefuseV1(error,@"Original VZ VM is not running on its bound serial queue.");
  else result=YES;
 } @catch(NSException *exception){(void)exception;result=RefuseV1(error,@"Original VM state getter raised an exception.");}
 if(pthread_mutex_unlock(&RuntimeMutexV1))return RefuseV1(error,@"Guest state unlock failed.");return result;
}
