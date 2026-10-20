#define VM27_INDEPENDENT_RUNTIME_TESTING 1
#include "vm27_independent_app_runtime_v1.m"
#include <stdio.h>
#include <stdlib.h>
static unsigned ChecksV1;
static void CheckV1(BOOL value,const char *name){ChecksV1++;if(!value){fprintf(stderr,"FAIL %s\n",name);exit(1);}}
int main(int argc,const char *argv[]) {
 @autoreleasepool {
  if(argc!=2)return 64;NSString *root=[NSString stringWithUTF8String:argv[1]];NSError *error=nil;
  NSDictionary *manifest=nil,*contents=nil;
  CheckV1(ValidateV1(root,&manifest,&contents,&error),"actual signed fixture preflight");
  CheckV1(VM27IndependentAppRuntimePreflightV1(root,&error),"public actual preflight");
  CheckV1(!LoadedPIDV1 && !BoundVMV1 && !RetainedHandlesV1,"preflight does not load or bind");
  for(NSString *path in @[@"",@"/absolute",@"../escape",@"x/../escape",@"x//y",@"./x",@"VZHostCompat.dylib",@"x\ny"])
   CheckV1(!RelativeV1(path),"bad relative path");
  CheckV1(RelativeV1(@"payload/Frameworks/own framework.dylib"),"normal relative file");
  CheckV1(!VM27IndependentAppRuntimePreflightV1(@"relative",&error),"relative root refused");
  CheckV1(!VM27IndependentAppRuntimePreflightV1([root stringByAppendingPathComponent:@".."],&error),"noncanonical root refused");
  int fd=open(root.fileSystemRepresentation,O_RDONLY|O_DIRECTORY);
  CheckV1(fd>=0,"actual directory open");
  CheckV1(!ReadAtV1(fd,@"symlink-provider",64*1024*1024,&error),"symlink refused");
  CheckV1(!ReadAtV1(fd,@"missing",64*1024*1024,&error),"missing file refused");
  CheckV1(!ReadAtV1(fd,@"fixture-provider.dylib",1,&error),"file bound enforced");
  CheckV1(!ReadAtV1(fd,@"directory",64*1024*1024,&error),"directory is not file");
  CheckV1(!close(fd),"directory close");
  NSDictionary *row=manifest[@"files"][0];NSData *data=contents[row[@"id"]];
  CheckV1(SignatureV1(data,row,contents,&error),"actual CodeDirectory and pages");
  NSMutableDictionary *badRow=[row mutableCopy];badRow[@"uuid"]=@"00000000000000000000000000000000";
  CheckV1(!SignatureV1(data,badRow,contents,&error),"wrong UUID refused");
  badRow=[row mutableCopy];badRow[@"cdhash"]=@"0000000000000000000000000000000000000000";
  CheckV1(!SignatureV1(data,badRow,contents,&error),"wrong actual CDHash refused");
  uint32_t csAt=0,csBytes=0;CheckV1(MachUUIDV1(data,&csAt,&csBytes)!=nil,"actual signature extent");
  NSMutableData *corrupt=[data mutableCopy];((uint8_t *)corrupt.mutableBytes)[csAt-1]^=1;
  CheckV1(!SignatureV1(corrupt,row,contents,&error),"changed actual code page refused");
  corrupt=[data mutableCopy];((uint8_t *)corrupt.mutableBytes)[csAt]^=1;
  CheckV1(!SignatureV1(corrupt,row,contents,&error),"changed superblob refused");
  for(size_t n=0;n<32;n++) {
   uint32_t at=0,length=0;CheckV1(!MachUUIDV1([data subdataWithRange:NSMakeRange(0,n)],&at,&length),"truncated header refused");
  }
  CheckV1(!VM27IndependentAppRuntimeGuestStartedV1(&error),"unbound guest cannot be started");
  CheckV1(!VM27IndependentAppRuntimeBindGuestV1([NSObject new],dispatch_get_main_queue(),&error),"fake guest cannot bind");
  CheckV1(VM27IndependentAppRuntimeLoadV1(root,&error),"actual inert frontend load and exact entry");
  CheckV1(LoadedPIDV1==getpid() && RetainedHandlesV1.count==1 && !RuntimePoisonedV1 && !BoundVMV1,"real load retains actual handle only");
  CheckV1(VM27IndependentAppRuntimeLoadV1(root,&error),"same actual runtime load");
  NSDictionary *entry=manifest[@"entries"][0];void *handle=RetainedHandlesV1[0].pointerValue;
  NSString *path=[root stringByAppendingPathComponent:row[@"path"]];
  CheckV1(!EntryV1(handle,path,entry[@"symbol"],@([entry[@"rva"] unsignedLongLongValue]+4),row[@"uuid"],&error),"wrong true entry offset refused");
  CheckV1(!EntryV1(handle,path,@"VM27AbsentFixtureEntry",entry[@"rva"],row[@"uuid"],&error),"absent entry refused");
  CheckV1(!EntryV1(handle,@"/different/provider",entry[@"symbol"],entry[@"rva"],row[@"uuid"],&error),"foreign image refused");
  CheckV1(!VM27IndependentAppRuntimeGuestStartedV1(&error),"loading does not claim guest state");
  NSString *provider=[root stringByAppendingPathComponent:row[@"path"]];NSData *original=[NSData dataWithContentsOfFile:provider];
  NSMutableData *changed=[original mutableCopy];((uint8_t *)changed.mutableBytes)[32]^=1;
  CheckV1([changed writeToFile:provider atomically:YES],"isolated fixture mutation");
  CheckV1(!VM27IndependentAppRuntimePreflightV1(root,&error),"signed product drift refused");
  CheckV1(!VM27IndependentAppRuntimeLoadV1(root,&error),"loaded product drift still refused");
  CheckV1([original writeToFile:provider atomically:YES],"isolated fixture restored");
  CheckV1(VM27IndependentAppRuntimePreflightV1(root,&error),"restored exact product");
  printf("{\"checks\":%u,\"actualSignedMachOFixture\":true,\"actualDlopenFixture\":true,\"nativeCPUCalls\":0,\"guestBoot\":false}\n",ChecksV1);
 }
 return 0;
}
