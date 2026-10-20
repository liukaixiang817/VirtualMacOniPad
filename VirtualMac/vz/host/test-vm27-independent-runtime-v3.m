#define VM27_INDEPENDENT_RUNTIME_TESTING 1
#include "vm27_independent_app_runtime_v3.m"
#include <stdio.h>
#include <stdlib.h>
static unsigned ChecksV3;
static void CheckV3(BOOL result,const char *name){ChecksV3++;if(!result){fprintf(stderr,"FAIL %s\n",name);exit(1);}}
int main(int argc,const char *argv[]) {
 @autoreleasepool {
  if(argc!=2)return 64;NSString *root=[NSString stringWithUTF8String:argv[1]];NSError *error=nil;
  NSDictionary *manifest=nil,*contents=nil;
  CheckV3(ValidateV1(root,&manifest,&contents,&error),"actual frozen signed inert files remain valid");
  CheckV3(!BootstrapManifestV3(manifest,&error),"old load-only manifest cannot start a child");
  CheckV3(!VM27IndependentAppRuntimePreflightV1(root,&error),"public preflight requires genuine parent contract");
  CheckV3(!VM27IndependentAppRuntimeLoadV1(root,&error),"public load refuses before acquiring any state");
  CheckV3(!BootstrapPIDV3 && !RetainedParentV3 && !LoadedPIDV1 && !RetainedHandlesV1,"missing contract leaves no partial owner or loaded handles");
  CheckV3(!ParentReadyV3(&error),"absence of child is never ready");
  CheckV3(!VM27IndependentAppRuntimeGuestStartedV1(&error),"absence of actual child cannot be a running guest");
  NSString *bundle=@"child-flat/VMM.bundle",*service=[bundle stringByAppendingPathComponent:@"Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents"];
  NSDictionary *contract=@{@"registryRoot":@"child-flat",@"immediateBundle":bundle,@"serviceIdentifier":@"com.apple.Virtualization.VirtualMachine",
   @"childID":@"child",@"providerID":@"startup",@"executableName":@"com.apple.Virtualization.VirtualMachine"};
  NSDictionary *rows=@{@"schema":@1,@"runtimeVersion":@27,@"parentBootstrapContract":contract,
   @"childEntryContract":@{@"childID":@"child"},@"loadOrder":@[@"startup"],
   @"entries":@[@{@"fileID":@"startup",@"symbol":@"VM27OwnedAppParentStartWithScopedPolicyV2",@"rva":@16},
    @{@"fileID":@"startup",@"symbol":@"VM27OwnedAppParentCopyStateV1",@"rva":@32}],
   @"files":@[@{@"id":@"child",@"role":@"child",@"kind":@"mach-o",@"path":[[service stringByAppendingPathComponent:@"MacOS"] stringByAppendingPathComponent:contract[@"executableName"]],
    @"uuid":@"4a6a588d1afd30f5a64d6304eb79be0b",@"sha256":[@"a" stringByPaddingToLength:64 withString:@"a" startingAtIndex:0],@"cdhash":[@"b" stringByPaddingToLength:40 withString:@"b" startingAtIndex:0]},
    @{@"id":@"startup",@"role":@"frontend",@"kind":@"mach-o"},
    @{@"id":@"bundle-info",@"path":[bundle stringByAppendingPathComponent:@"Contents/Info.plist"],@"kind":@"resource"},
    @{@"id":@"service-info",@"path":[service stringByAppendingPathComponent:@"Info.plist"],@"kind":@"resource"}]};
  /* Only dictionary shape is exercised here. These synthetic rows are never
   * signed, anchored, loaded, spawned or passed to a native identity gate. */
  CheckV3(BootstrapManifestV3(rows,&error),"registration shape matches actual LargeRegistry layout");
  for(NSDictionary *change in @[@{@"registryRoot":@"../escape"},@{@"immediateBundle":@"child-flat/VMM.xpc"},
   @{@"immediateBundle":@"child-flat/nested/VMM.bundle"},@{@"serviceIdentifier":@"foreign.service"},
   @{@"executableName":@"../child"},@{@"childID":@"missing"},@{@"providerID":@"missing"},@{@"extra":@YES}]) {
   NSMutableDictionary *bad=[rows mutableCopy],*c=[contract mutableCopy];[c addEntriesFromDictionary:change];bad[@"parentBootstrapContract"]=c;
   CheckV3(!BootstrapManifestV3(bad,&error),"incorrect service registration shape refused");
  }
  NSMutableDictionary *bad=[rows mutableCopy];bad[@"entries"]=@[rows[@"entries"][0]];
  CheckV3(!BootstrapManifestV3(bad,&error),"missing exact state definition refused");
  bad=[rows mutableCopy];bad[@"entries"]=[rows[@"entries"] arrayByAddingObject:rows[@"entries"][0]];
  CheckV3(!BootstrapManifestV3(bad,&error),"ambiguous exact bootstrap definition refused");
  bad=[rows mutableCopy];bad[@"files"]=@[rows[@"files"][0],rows[@"files"][1],rows[@"files"][2]];
  CheckV3(!BootstrapManifestV3(bad,&error),"service Info missing refused");
  bad=[rows mutableCopy];bad[@"files"]=[rows[@"files"] arrayByAddingObject:rows[@"files"][2]];
  CheckV3(!BootstrapManifestV3(bad,&error),"ambiguous registration Info refused");
  bad=[rows mutableCopy];bad[@"loadOrder"]=@[];
  CheckV3(!BootstrapManifestV3(bad,&error),"bootstrap provider outside real load order refused");
  NSString *selfBundle=nil,*selfName=nil,*selfSHA=nil,*selfCD=nil;uid_t owner=0;
  CheckV3(!ActualSelfV3(&selfBundle,&selfName,&selfSHA,&selfCD,&owner,&error),"unbundled command line fixture cannot authorize an App parent");
  CheckV3(!RetainedParentV3 && !BootstrapReadyV3,"fixture never starts a child");
  printf("{\"checks\":%u,\"actualFrozenSignedMachOFixture\":true,\"syntheticRowsUsedOnlyForShape\":true,\"actualChildSpawn\":false,\"nativeCPUCalls\":0,\"guestBoot\":false}\n",ChecksV3);
 }
 return 0;
}
