#import "VM27SharedRadioBootArgumentsV1.h"
#include <objc/message.h>
#include <objc/runtime.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <CommonCrypto/CommonDigest.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static BOOL InstallationFile(NSString *path, off_t length, mode_t mode, NSString *expected) {
    int fd=open(path.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);struct stat st;
    if(fd<0)return NO;
    if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_nlink!=1||st.st_size!=length||
        (st.st_mode&07777)!=mode){close(fd);return NO;}
    NSMutableData *data=[NSMutableData dataWithLength:(NSUInteger)length];NSUInteger at=0;
    while(at<data.length){ssize_t n=read(fd,(uint8_t *)data.mutableBytes+at,data.length-at);
        if(n<0&&errno==EINTR)continue;if(n<=0){close(fd);return NO;}at+=(NSUInteger)n;}
    close(fd);uint8_t digest[CC_SHA256_DIGEST_LENGTH];CC_SHA256(data.bytes,(CC_LONG)data.length,digest);
    NSMutableString *sha=[NSMutableString string];for(unsigned i=0;i<sizeof(digest);++i)[sha appendFormat:@"%02x",digest[i]];
    return [sha isEqual:expected];
}
NSString *VM27SharedRadioInstallationLauncherV1(void) {
    NSString *bundled=[NSBundle.mainBundle pathForResource:@"install-launcher" ofType:nil];
    if(bundled)return bundled;
    NSString *launcher=@"/var/root/VirtualMac/install/install-launcher";
    if(!InstallationFile(launcher,53408,04755,@"b37c3355aa79bce190cd162aa9693b9c35555094039d90bb1e9cddb839091e13")||
       !InstallationFile(@"/var/root/VirtualMac/install/start-install.sh",10772,0755,
            @"5310f360c667a10d38244cfedd7788faca5c7a273b58bc877e19d1a18ce3a6f2"))return nil;
    return launcher;
}

static BOOL BootError(NSError **error, NSString *message) {
    if (error) *error=[NSError errorWithDomain:@"VM27SharedRadioBootArgumentsV1" code:1
        userInfo:@{NSLocalizedDescriptionKey:message}];
    return NO;
}
static BOOL ConfigureBootArguments(id auxiliary, NSString *nativeImage, BOOL automatic26, NSError **error) {
    Class cls=objc_getClass("VZMacAuxiliaryStorage");
    const char *image=cls?class_getImageName(cls):NULL;
    char actual[PATH_MAX],expected[PATH_MAX];
    if (!cls || ![auxiliary isKindOfClass:cls] || !image ||
        !realpath(image,actual) || !realpath(nativeImage.fileSystemRepresentation,expected) || strcmp(actual,expected))
        return BootError(error,@"The guest NVRAM is not owned by the selected native backend.");
    SEL getter=sel_registerName("_valueForNVRAMVariableNamed:error:");
    SEL setter=sel_registerName("_setValue:forNVRAMVariableNamed:error:");
    Method get=class_getInstanceMethod(cls,getter),set=class_getInstanceMethod(cls,setter);
    if (!get || !set || strcmp(method_getTypeEncoding(get),"@32@0:8@16^@24") ||
        strcmp(method_getTypeEncoding(set),"B40@0:8@16@24^@32"))
        return BootError(error,@"The native guest NVRAM method ABI changed.");
    NSError *failure=nil;
    id value=((id(*)(id,SEL,id,NSError **))objc_msgSend)(auxiliary,getter,@"boot-args",&failure);
    if (failure) { if(error)*error=failure; return NO; }
    NSString *arguments=nil;
    if ([value isKindOfClass:NSData.class]) arguments=[[NSString alloc]initWithData:value encoding:NSUTF8StringEncoding];
    else if ([value isKindOfClass:NSString.class]) arguments=value;
    else if (value) return BootError(error,@"The guest boot arguments have an unsupported representation.");
    if (value && !arguments) return BootError(error,@"The guest boot arguments are not UTF-8.");
    arguments=arguments?:@"";
    if (arguments.length>4096 || [arguments rangeOfString:@"\0"].location!=NSNotFound)
        return BootError(error,@"The guest boot arguments exceed their supported format.");
    NSMutableArray *tokens=[NSMutableArray array];
    for (NSString *token in [arguments componentsSeparatedByCharactersInSet:NSCharacterSet.whitespaceAndNewlineCharacterSet])
        if (token.length && ![token hasPrefix:@"bt-transport-override="] &&
            !(automatic26 && ([token hasPrefix:@"amfi_get_out_of_my_way="] || [token hasPrefix:@"mtknative="] ||
                               [token isEqual:@"-arm64e_preview_abi"]))) [tokens addObject:token];
    [tokens addObject:@"bt-transport-override=10"];
    if(automatic26)[tokens addObjectsFromArray:@[@"amfi_get_out_of_my_way=1",@"-arm64e_preview_abi",@"mtknative=1"]];
    NSString *updated=[tokens componentsJoinedByString:@" "];
    if (![updated isEqual:arguments] &&
        !((BOOL(*)(id,SEL,id,id,NSError **))objc_msgSend)(auxiliary,setter,updated,@"boot-args",error)) return NO;
    id readback=((id(*)(id,SEL,id,NSError **))objc_msgSend)(auxiliary,getter,@"boot-args",&failure);
    if ([readback isKindOfClass:NSData.class]) readback=[[NSString alloc]initWithData:readback encoding:NSUTF8StringEncoding];
    if (failure || ![readback isEqual:updated]) return BootError(error,@"The guest Bluetooth boot argument could not be verified.");
    return YES;
}
BOOL VM27SharedRadioBluetoothBootArgumentsV1(id auxiliary, NSString *nativeImage, NSError **error) {
    return ConfigureBootArguments(auxiliary,nativeImage,NO,error);
}
BOOL VM27SharedRadioAutomatic26BootArgumentsV1(id auxiliary, NSString *nativeImage, NSError **error) {
    return ConfigureBootArguments(auxiliary,nativeImage,YES,error);
}
