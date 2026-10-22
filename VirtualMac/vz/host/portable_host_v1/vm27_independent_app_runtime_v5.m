#import "vm27_independent_app_runtime_v1.h"
#include "vm27_owned_app_child_startup_v2.h"
#include <mach-o/dyld.h>
#include "vm27_actual_executable_image_v1.h"
#include <limits.h>
__attribute__((visibility("hidden"))) BOOL VM27IndependentAppRuntimePreflightInheritedV2(NSString *,NSError **);
__attribute__((visibility("hidden"))) BOOL VM27IndependentAppRuntimeLoadInheritedV2(NSString *,NSError **);
__attribute__((visibility("hidden"))) BOOL VM27IndependentAppRuntimeGuestStartedInheritedV2(NSError **);
/* Keep the frozen signature, class, queue and entry checks in one state. */
#define VM27IndependentAppRuntimePreflightV1 VM27IndependentAppRuntimePreflightInheritedV2
#define VM27IndependentAppRuntimeLoadV1 VM27IndependentAppRuntimeLoadInheritedV2
#define VM27IndependentAppRuntimeGuestStartedV1 VM27IndependentAppRuntimeGuestStartedInheritedV2
#include "vm27_independent_app_runtime_v5_owner.inc"
#undef VM27IndependentAppRuntimePreflightV1
#undef VM27IndependentAppRuntimeLoadV1
#undef VM27IndependentAppRuntimeGuestStartedV1

typedef int (*ParentStartV3)(const VM27OwnedAppParentConfigurationV1 *,VM27OwnedAppParentV1 **);
typedef int (*ParentStateV3)(VM27OwnedAppParentV1 *,VM27OwnedAppParentStateV1 *);
static pthread_mutex_t BootstrapMutexV3=PTHREAD_MUTEX_INITIALIZER;
static VM27OwnedAppParentV1 *RetainedParentV3;
static ParentStateV3 ActualParentStateV3;
static pid_t BootstrapPIDV3;
static BOOL BootstrapReadyV3;

static BOOL HexStringV3(id value,NSUInteger length) {
 if(![value isKindOfClass:NSString.class] || [value length]!=length)return NO;
 for(NSUInteger i=0;i<length;i++) {
  unichar c=[value characterAtIndex:i];if(!((c>='0' && c<='9') || (c>='a' && c<='f')))return NO;
 }
 return YES;
}
static NSDictionary *FileV3(NSDictionary *manifest,id key) {
 if(![key isKindOfClass:NSString.class])return nil;
 for(NSDictionary *row in manifest[@"files"])if([row[@"id"] isEqual:key])return row;
 return nil;
}
static NSDictionary *BootstrapEntryV3(NSDictionary *manifest,NSString *provider,NSString *symbol) {
 NSDictionary *found=nil;
 for(NSDictionary *row in manifest[@"entries"])
  if([row[@"fileID"] isEqual:provider] && [row[@"symbol"] isEqual:symbol]) {
   if(found)return nil;found=row;
  }
 return found;
}
/* The registry accepts immediate .bundle children. The two Info plists and
 * the original child executable must be explicit anchored product files. */
static BOOL BootstrapManifestV3(NSDictionary *manifest,NSError **error) {
 NSDictionary *contract=manifest[@"parentBootstrapContract"];
 if(![contract isKindOfClass:NSDictionary.class] || contract.count!=6 ||
  !RelativeV1(contract[@"registryRoot"]) || !RelativeV1(contract[@"immediateBundle"]) ||
  ![contract[@"serviceIdentifier"] isEqual:@"com.apple.Virtualization.VirtualMachine"] ||
  ![contract[@"executableName"] isKindOfClass:NSString.class] || ![contract[@"executableName"] length] ||
  [contract[@"executableName"] length]>255 || [contract[@"executableName"] rangeOfString:@"/"].location!=NSNotFound ||
  !RelativeV1(contract[@"executableName"]))return RefuseV1(error,@"The genuine parent bootstrap contract is missing or invalid.");
 NSString *registry=contract[@"registryRoot"],*bundle=contract[@"immediateBundle"];
 if(![[bundle stringByDeletingLastPathComponent] isEqual:registry] || ![bundle hasSuffix:@".bundle"])
  return RefuseV1(error,@"The registered service bundle must be an immediate registry child.");
 NSDictionary *child=FileV3(manifest,contract[@"childID"]),*provider=FileV3(manifest,contract[@"providerID"]);
 NSString *service=[bundle stringByAppendingPathComponent:@"Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents"];
 NSString *executable=[[service stringByAppendingPathComponent:@"MacOS"] stringByAppendingPathComponent:contract[@"executableName"]];
 if(!child || !provider || ![child[@"role"] isEqual:@"child"] || ![child[@"kind"] isEqual:@"mach-o"] ||
  ![child[@"path"] isEqual:executable] || ![child[@"uuid"] isEqual:@"4a6a588d1afd30f5a64d6304eb79be0b"] ||
  !HexStringV3(child[@"sha256"],64) || !HexStringV3(child[@"cdhash"],40) ||
  ![manifest[@"childEntryContract"][@"childID"] isEqual:contract[@"childID"]] ||
  ![provider[@"kind"] isEqual:@"mach-o"] || ![provider[@"role"] isEqual:@"frontend"] ||
  ![manifest[@"loadOrder"] containsObject:contract[@"providerID"]])
  return RefuseV1(error,@"The original child or single owned bootstrap provider is not in the signed product.");
 NSString *required[]={ [bundle stringByAppendingPathComponent:@"Contents/Info.plist"],
  [service stringByAppendingPathComponent:@"Info.plist"] };
 for(unsigned i=0;i<2;i++) {
  NSUInteger matches=0;
  for(NSDictionary *row in manifest[@"files"])
   if([row[@"path"] isEqual:required[i]] && [row[@"kind"] isEqual:@"resource"])matches++;
  if(matches!=1)return RefuseV1(error,@"A genuine service registration Info.plist is missing or ambiguous.");
 }
 if(!BootstrapEntryV3(manifest,contract[@"providerID"],@"VM27OwnedAppParentStartWithScopedPolicyV2") ||
  !BootstrapEntryV3(manifest,contract[@"providerID"],@"VM27OwnedAppParentCopyStateV1"))
  return RefuseV1(error,@"The actual typed bootstrap entry definitions are required.");
 return YES;
}
static NSString *CodeHashV3(NSData *data,NSError **error) {
 uint32_t at=0,bytes=0;if(!MachUUIDV1(data,&at,&bytes) || bytes<12)return nil;
 const uint8_t *blob=(const uint8_t *)data.bytes+at;uint32_t length=BE32V1(blob+4),count=BE32V1(blob+8);
 if(BE32V1(blob)!=0xfade0cc0 || length>bytes || count>64 || !ExtentV1(12,(size_t)count*8,length))return nil;
 NSData *cd=nil;
 for(uint32_t i=0;i<count;i++)if(BE32V1(blob+12+8*i)==0) {
  uint32_t start=BE32V1(blob+16+8*i);
  if(cd || !ExtentV1(start,8,length))return nil;uint32_t n=BE32V1(blob+start+4);
  if(n<44 || !ExtentV1(start,n,length) || BE32V1(blob+start)!=0xfade0c02)return nil;
  cd=[NSData dataWithBytes:blob+start length:n];
 }
 if(!cd){RefuseV1(error,@"The running App has no primary CodeDirectory.");return nil;}
 return HexV1([DigestV1(cd) subdataWithRange:NSMakeRange(0,20)]);
}
/* This reads the running App's own signed flat bundle. Its hash is an
 * inspection expectation passed to the child, never a native authorization.
 * The child independently checks the live parent token/CD/CS/entitlements. */
static BOOL ActualSelfV3(NSString **bundleOut,NSString **nameOut,NSString **shaOut,NSString **cdOut,
 uid_t *ownerOut,NSError **error) {
 NSBundle *bundle=NSBundle.mainBundle;NSString *root=bundle.bundlePath;
 char canonical[PATH_MAX],actualExe[PATH_MAX];uint32_t capacity=sizeof(actualExe);
 if(![root hasSuffix:@".app"] || !realpath(root.fileSystemRepresentation,canonical) || _NSGetExecutablePath(actualExe,&capacity))
  return RefuseV1(error,@"The actual running flat App bundle is required.");
 root=[NSString stringWithUTF8String:canonical];
 char executable[PATH_MAX];if(!realpath(actualExe,executable))return RefuseV1(error,@"The running executable path is unavailable.");
 struct stat directory={0};
 if(lstat(canonical,&directory) || !S_ISDIR(directory.st_mode) || (directory.st_mode&0022))
  return RefuseV1(error,@"The running App bundle owner or mode is invalid.");
 int fd=open(canonical,O_RDONLY|O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return RefuseV1(error,@"The running App cannot be inspected.");
 NSData *info=ReadAtV1(fd,@"Info.plist",64*1024,error);
 id parsed=info?[NSPropertyListSerialization propertyListWithData:info options:NSPropertyListImmutable format:NULL error:error]:nil;
 NSString *name=[parsed isKindOfClass:NSDictionary.class]?parsed[@"CFBundleExecutable"]:nil;
 BOOL valid=[name isKindOfClass:NSString.class] && name.length<=255 && RelativeV1(name) && [name rangeOfString:@"/"].location==NSNotFound;
 NSString *path=valid?[root stringByAppendingPathComponent:name]:nil;
 if(!valid || ![path isEqual:[NSString stringWithUTF8String:executable]]) {
  close(fd);return RefuseV1(error,@"The actual executable differs from the App Info.plist.");
 }
 NSData *code=ReadAtV1(fd,name,2*1024*1024,error),*resources=ReadAtV1(fd,@"_CodeSignature/CodeResources",1024*1024,error);
 BOOL released=!close(fd);if(!released)return RefuseV1(error,@"The actual App inspection descriptor could not be released.");
 if(!code || !resources)return NO;
 /* Resolve the true executable by canonical path and its executable-only
  * symbol; safe Mach reads and the actual dyld set replace the index-0 guess. */
 VM27ActualExecutableImageV1 loaded={0};
 uint32_t signatureAt=0,signatureBytes=0;NSString *uuid=MachUUIDV1(code,&signatureAt,&signatureBytes);
 if(VM27ActualExecutableImageFindV1(executable,&loaded))
  return RefuseV1(error,@"The actual App main image is invalid.");
 NSString *loadedUUID=HexV1([NSData dataWithBytes:loaded.uuid length:sizeof(loaded.uuid)]);
 NSString *cd=CodeHashV3(code,error);
 if(!uuid || ![uuid isEqual:loadedUUID] || !cd)return RefuseV1(error,@"The inspected App differs from its actual main image.");
 NSDictionary *row=@{@"uuid":uuid,@"cdhash":cd,@"signatureSlots":@{@"1":@"info",@"3":@"resources"}};
 if(!SignatureV1(code,row,@{@"info":info,@"resources":resources},error))return NO;
 *bundleOut=root;*nameOut=name;*shaOut=HexV1(DigestV1(code));*cdOut=cd;*ownerOut=directory.st_uid;return YES;
}
static BOOL ParentReadyV3(NSError **error) {
 VM27OwnedAppParentStateV1 state={0};
 if(!BootstrapReadyV3 || BootstrapPIDV3!=getpid() || !RetainedParentV3 || !ActualParentStateV3 ||
  ActualParentStateV3(RetainedParentV3,&state) || state.ownerPID!=getpid() || state.childPID<=1 ||
  !state.spawned || !state.helloInstalled || state.startupStatus || state.controlStatus ||
  state.controlFinalInvalid || state.listenerFinalInvalid)
  return RefuseV1(error,@"The actual owned child startup and factory are not ready.");
 return YES;
}
BOOL VM27IndependentAppRuntimePreflightV1(NSString *root,NSError **error) {
 @try {NSDictionary *manifest=nil,*contents=nil;
  return ValidateV1(root,&manifest,&contents,error) && BootstrapManifestV3(manifest,error);
 }@catch(NSException *exception){(void)exception;return RefuseV1(error,@"Parent bootstrap preflight raised an exception.");}
}
BOOL VM27IndependentAppRuntimeLoadV1(NSString *root,NSError **error) {
 NSDictionary *manifest=nil,*contents=nil;
 @try {if(!ValidateV1(root,&manifest,&contents,error) || !BootstrapManifestV3(manifest,error))return NO;}
 @catch(NSException *exception){(void)exception;return RefuseV1(error,@"Parent bootstrap validation raised an exception.");}
 if(pthread_mutex_lock(&BootstrapMutexV3))return RefuseV1(error,@"Parent bootstrap admission lock failed.");
 BOOL result=NO;
 @try {
  if(BootstrapPIDV3 && BootstrapPIDV3!=getpid())RefuseV1(error,@"Inherited parent bootstrap requires a fresh App process.");
  else if(BootstrapReadyV3)result=VM27IndependentAppRuntimeLoadInheritedV2(root,error) && ParentReadyV3(error);
  else if(RetainedParentV3 || BootstrapPIDV3)RefuseV1(error,@"Partial child startup requires a fresh App process.");
  else if(VM27IndependentAppRuntimeLoadInheritedV2(root,error)) {
   BootstrapPIDV3=getpid();
   /* Until the true hello/factory is installed, inherited BindGuest refuses. */
   if(pthread_mutex_lock(&RuntimeMutexV1))abort();RuntimePoisonedV1=YES;if(pthread_mutex_unlock(&RuntimeMutexV1))abort();
   NSDictionary *contract=manifest[@"parentBootstrapContract"],*provider=FileV3(manifest,contract[@"providerID"]),*child=FileV3(manifest,contract[@"childID"]);
   NSUInteger index=[manifest[@"loadOrder"] indexOfObject:contract[@"providerID"]];
   void *handle=index<RetainedHandlesV1.count?RetainedHandlesV1[index].pointerValue:NULL;
   NSString *providerPath=[root stringByAppendingPathComponent:provider[@"path"]];
   NSDictionary *start=BootstrapEntryV3(manifest,contract[@"providerID"],@"VM27OwnedAppParentStartWithScopedPolicyV2"),
    *copy=BootstrapEntryV3(manifest,contract[@"providerID"],@"VM27OwnedAppParentCopyStateV1");
   if(handle && EntryV1(handle,providerPath,start[@"symbol"],start[@"rva"],provider[@"uuid"],error) &&
    EntryV1(handle,providerPath,copy[@"symbol"],copy[@"rva"],provider[@"uuid"],error)) {
    ParentStartV3 actualStart=(ParentStartV3)dlsym(handle,"VM27OwnedAppParentStartWithScopedPolicyV2");
    ActualParentStateV3=(ParentStateV3)dlsym(handle,"VM27OwnedAppParentCopyStateV1");
    NSString *bundle=nil,*name=nil,*sha=nil,*cd=nil;uid_t owner=0;
    if(actualStart && ActualParentStateV3 && ActualSelfV3(&bundle,&name,&sha,&cd,&owner,error)) {
     NSString *registry=[root stringByAppendingPathComponent:contract[@"registryRoot"]],*immediate=[root stringByAppendingPathComponent:contract[@"immediateBundle"]],
      *executable=[root stringByAppendingPathComponent:child[@"path"]];
     char *argv[]={ (char *)executable.fileSystemRepresentation,NULL },*environment[]={NULL};
     uint64_t nonce=0;do{arc4random_buf(&nonce,sizeof(nonce));}while(!nonce);
     VM27OwnedAppParentConfigurationV1 config={registry.fileSystemRepresentation,immediate.fileSystemRepresentation,
      [contract[@"serviceIdentifier"] UTF8String],[child[@"sha256"] UTF8String],[child[@"cdhash"] UTF8String],NULL,argv,environment,nonce,
      {bundle.fileSystemRepresentation,name.UTF8String,sha.UTF8String,cd.UTF8String,owner}};
     int status=actualStart(&config,&RetainedParentV3);
     if(!status){BootstrapReadyV3=YES;result=ParentReadyV3(error);}
     else RefuseV1(error,[NSString stringWithFormat:@"Owned child startup failed (%d); acquired process ownership remains retained.",status]);
    }
   }
   if(result){if(pthread_mutex_lock(&RuntimeMutexV1))abort();RuntimePoisonedV1=NO;if(pthread_mutex_unlock(&RuntimeMutexV1))abort();}
  }
 }@catch(NSException *exception){(void)exception;result=RefuseV1(error,@"Owned child startup raised an exception; acquired ownership remains retained.");}
 if(!result && BootstrapPIDV3){if(pthread_mutex_lock(&RuntimeMutexV1))abort();RuntimePoisonedV1=YES;if(pthread_mutex_unlock(&RuntimeMutexV1))abort();}
 if(pthread_mutex_unlock(&BootstrapMutexV3))return RefuseV1(error,@"Parent bootstrap admission unlock failed.");return result;
}
BOOL VM27IndependentAppRuntimeGuestStartedV1(NSError **error) {
 if(pthread_mutex_lock(&BootstrapMutexV3))return RefuseV1(error,@"Child state lock failed.");
 BOOL ready=ParentReadyV3(error);if(pthread_mutex_unlock(&BootstrapMutexV3))return RefuseV1(error,@"Child state unlock failed.");
 return ready && VM27IndependentAppRuntimeGuestStartedInheritedV2(error);
}
