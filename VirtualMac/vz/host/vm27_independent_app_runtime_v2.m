#import "vm27_independent_app_runtime_v1.h"
#include <objc/runtime.h>
__attribute__((visibility("hidden")))
BOOL VM27IndependentAppRuntimeBindGuestInheritedV1(id,dispatch_queue_t,NSError **);
/* The first version remains frozen. Keep its file/signature/load body and
 * strengthen only binding of the genuine registered VZ class to its image. */
#define VM27IndependentAppRuntimeBindGuestV1 VM27IndependentAppRuntimeBindGuestInheritedV1
#include "vm27_independent_app_runtime_v1.m"
#undef VM27IndependentAppRuntimeBindGuestV1
static BOOL ClassOwnerV2(id vm,NSError **error) {
 if(!LoadedRootV1 || !LoadedManifestV1 || LoadedPIDV1!=getpid() || RuntimePoisonedV1)
  return RefuseV1(error,@"The finalized runtime must be loaded before binding its original VM class.");
 Class cls=NSClassFromString(@"VZVirtualMachine");
 if(!cls || !vm || object_getClass(vm)!=cls)return RefuseV1(error,@"The object must have the original VZVirtualMachine class.");
 NSDictionary *image=nil;NSString *fileID=nil;
 for(NSDictionary *row in LoadedManifestV1[@"files"])
  if([row[@"uuid"] isEqual:@"418efc4809d93606918eb6f95baeffdc"] && [row[@"role"] isEqual:@"frontend"]) {
   if(image)return RefuseV1(error,@"Ambiguous original VZ image in the product.");image=row;fileID=row[@"id"];
  }
 const char *actual=class_getImageName(cls);
 NSString *path=image?[LoadedRootV1 stringByAppendingPathComponent:image[@"path"]]:nil;
 if(!actual || ![path isEqual:[NSString stringWithUTF8String:actual]])
  return RefuseV1(error,@"The registered VM class belongs to a different image.");
 NSDictionary *classEntry=nil;
 for(NSDictionary *entry in LoadedManifestV1[@"entries"])
  if([entry[@"fileID"] isEqual:fileID] && [entry[@"symbol"] isEqual:@"OBJC_CLASS_$_VZVirtualMachine"]) {
   if(classEntry)return RefuseV1(error,@"Ambiguous original VM class export contract.");classEntry=entry;
  }
 NSUInteger index=[LoadedManifestV1[@"loadOrder"] indexOfObject:fileID];
 if(!classEntry || index==NSNotFound || index>=RetainedHandlesV1.count)
  return RefuseV1(error,@"The finalized original VM class definition is missing.");
 void *handle=RetainedHandlesV1[index].pointerValue;
 if(!EntryV1(handle,path,classEntry[@"symbol"],classEntry[@"rva"],image[@"uuid"],error))return NO;
 dlerror();void *definition=dlsym(handle,"OBJC_CLASS_$_VZVirtualMachine");const char *failure=dlerror();
 if(failure || definition!=(__bridge void *)cls)return RefuseV1(error,@"The registered VM class differs from the actual strong export.");
 return YES;
}
BOOL VM27IndependentAppRuntimeBindGuestV1(id vm,dispatch_queue_t queue,NSError **error) {
 if(!pthread_main_np() || queue!=dispatch_get_main_queue())return RefuseV1(error,@"Guest binding must execute on the original VM main queue.");
 if(pthread_mutex_lock(&RuntimeMutexV1))return RefuseV1(error,@"Class identity lock failed.");BOOL actual=NO;
 @try{actual=ClassOwnerV2(vm,error);}
 @catch(NSException *exception){(void)exception;RefuseV1(error,@"Original VM class identity raised an exception.");}
 if(pthread_mutex_unlock(&RuntimeMutexV1))return RefuseV1(error,@"Class identity unlock failed.");
 return actual && VM27IndependentAppRuntimeBindGuestInheritedV1(vm,queue,error);
}
