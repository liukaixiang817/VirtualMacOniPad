// Local guest provisioning only. Security arguments require an explicit mode;
// --prepare never changes security policy, radio state, or existing bonds.
#import <Foundation/Foundation.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <uuid/uuid.h>
#ifndef VM27_PROVISION_NATIVE_BUILD
#error Supply the audited guest build.
#endif
static NSString *const Root=@"/Library/PrivilegedHelperTools/VirtualMacSharedBluetoothClassicV1";
static NSData *readOwned(NSString *name){
 int fd=open([[Root stringByAppendingPathComponent:name]fileSystemRepresentation],O_RDONLY|O_NOFOLLOW|O_CLOEXEC);struct stat s;
 if(fd<0)return nil;
 if(fstat(fd,&s)||!S_ISREG(s.st_mode)||s.st_uid||s.st_nlink!=1||(s.st_mode&0077)||s.st_size<0||s.st_size>16384){close(fd);return nil;}
 NSMutableData *d=[NSMutableData dataWithLength:(NSUInteger)s.st_size];ssize_t n=read(fd,d.mutableBytes,d.length);close(fd);return n==(ssize_t)d.length?d:nil;
}
static BOOL createOwned(NSString *name,NSData *data){
 NSString *path=[Root stringByAppendingPathComponent:name];int fd=open(path.fileSystemRepresentation,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC,0600);
 if(fd<0)return NO;BOOL ok=write(fd,data.bytes,data.length)==(ssize_t)data.length;close(fd);if(!ok)unlink(path.fileSystemRepresentation);return ok;
}
static NSData *json(id value){return [NSJSONSerialization dataWithJSONObject:value options:NSJSONWritingSortedKeys error:NULL];}
static BOOL run(NSArray *arguments,NSString **output){
 NSTask *task=[NSTask new];NSPipe *pipe=[NSPipe pipe];task.executableURL=[NSURL fileURLWithPath:@"/usr/sbin/nvram"];task.arguments=arguments;
 task.standardInput=NSFileHandle.fileHandleWithNullDevice;task.standardOutput=pipe;task.standardError=pipe;
 if(![task launchAndReturnError:NULL])return NO;
 NSData *data=[pipe.fileHandleForReading readDataToEndOfFile];[task waitUntilExit];
 if(output)*output=[[NSString alloc]initWithData:data encoding:NSUTF8StringEncoding];return task.terminationStatus==0;
}
static NSString *arguments(void){
 NSString *out=nil;BOOL ok=run(@[@"boot-args"],&out);
 if(!ok)return [out containsString:@"data was not found"]?@"":nil;
 NSRange tab=[out rangeOfString:@"\t"];if(tab.location==NSNotFound)return nil;
 NSString *text=[out substringFromIndex:tab.location+1];if([text hasSuffix:@"\n"])text=[text substringToIndex:text.length-1];
 return text.length<=4096?text:nil;
}
int main(int argc,char **argv){@autoreleasepool{
 if(geteuid()||argc!=3)return 77;char build[32]={0},boot[64]={0};size_t a=sizeof(build),b=sizeof(boot);struct stat s;
 if(sysctlbyname("kern.osversion",build,&a,NULL,0)||strcmp(build,VM27_PROVISION_NATIVE_BUILD)||sysctlbyname("kern.bootsessionuuid",boot,&b,NULL,0)||strcmp(boot,argv[2])||
    lstat(Root.fileSystemRepresentation,&s)||!S_ISDIR(s.st_mode)||s.st_uid||(s.st_mode&0077))return 77;
 if(!strcmp(argv[1],"--prepare")){
  NSData *token=readOwned(@"exclusive-transport-token-v1");
  if(!token){uint8_t bytes[32];arc4random_buf(bytes,32);if(!createOwned(@"exclusive-transport-token-v1",[NSData dataWithBytes:bytes length:32]))return 73;memset(bytes,0,32);}
  else if(token.length!=32)return 77;
  uuid_t host;struct timespec timeout={2,0};char uuid[37]={0};if(gethostuuid(host,&timeout))return 77;uuid_unparse_upper(host,uuid);
  NSString *name=@"exclusive-hogp-selected-peers-v1.json";NSData *prior=readOwned(name);
  if(prior){id config=[NSJSONSerialization JSONObjectWithData:prior options:0 error:NULL];if(![config isKindOfClass:NSDictionary.class]||![config[@"guestHostUUID"]isEqual:@(uuid)])return 77;}
  else if(!createOwned(name,json(@{@"schema":@1,@"guestHostUUID":@(uuid),@"selectedPeerIdentifiers":@[],@"automaticBondedHID":@YES,@"nativeHIDOnly":@YES})))return 73;
  NSData *marker=[@"VM27-EXCLUSIVE-BLUETOOTH-V1\n" dataUsingEncoding:NSASCIIStringEncoding];prior=readOwned(@"exclusive-autoload-enabled-v1");
  if(prior?![prior isEqual:marker]:!createOwned(@"exclusive-autoload-enabled-v1",marker))return 77;
  puts("{\"prepared\":true,\"firstPairingRequested\":false,\"securityPolicyChanged\":false}");return 0;
 }
 if(strcmp(argv[1],"--configure-authorized-development-boot"))return 64;
 NSString *old=arguments();if(!old)return 74;
 NSString *backup=@"before-exclusive-development-boot-v1.json";NSData *saved=readOwned(backup);
 if(!saved){if(!createOwned(backup,json(@{@"schema":@1,@"bootArgumentsBefore":old,@"bootUUIDBefore":@(boot)})))return 73;}
 else{ id prior=[NSJSONSerialization JSONObjectWithData:saved options:0 error:NULL];if(![prior isKindOfClass:NSDictionary.class]||![prior[@"bootArgumentsBefore"]isKindOfClass:NSString.class])return 77;}
 NSMutableArray *tokens=[NSMutableArray array];
 for(NSString *token in [old componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet])
  if(token.length&&![token hasPrefix:@"bt-transport-override="]&&![token hasPrefix:@"amfi_get_out_of_my_way="]&&![token isEqual:@"-arm64e_preview_abi"])[tokens addObject:token];
 [tokens addObjectsFromArray:@[@"bt-transport-override=10",@"-arm64e_preview_abi",@"amfi_get_out_of_my_way=1"]];NSString *updated=[tokens componentsJoinedByString:@" "];
 if(![old isEqual:updated]&&!run(@[[@"boot-args="stringByAppendingString:updated]],NULL))return 77;
 if(![arguments()isEqual:updated])return 74;
 puts("{\"guestDevelopmentBootArgumentsConfigured\":true,\"originalArgumentsBackedUp\":true,\"rebootRequired\":true,\"systemVolumeModified\":false}");return 0;
}}
