// Development supplement for the exact 25G83 virtual Bluetooth controller.
// Uses only real iPad discovery records. No RF RSSI, pairing, ACL connection or
// remote capabilities are invented. Restarting bluetoothd removes the hooks.
#import <Foundation/Foundation.h>
#include <objc/message.h>
#include <objc/runtime.h>
#include <dlfcn.h>
#include <libproc.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdatomic.h>
#include <errno.h>

typedef void (*CommandIMP)(id,SEL,uint16_t,const char *,uint16_t);
static CommandIMP Original;
static _Atomic(uint64_t) Generation;
static NSMutableDictionary<NSData *,NSDictionary *> *Devices;
static BOOL Active;
static Method CommandMethod;

static void event(id owner,uint8_t code,const uint8_t *parameters,uint8_t length) {
    ((void(*)(id,SEL,uint8_t,const char *,uint8_t))objc_msgSend)(owner,
        sel_registerName("_sendHciEvent:parameters:length:"),code,(const char *)parameters,length);
}
static void status(id owner,uint16_t command,uint8_t value) {
    ((void(*)(id,SEL,uint16_t,uint8_t))objc_msgSend)(owner,
        sel_registerName("sendHciCommandStatusEvent:status:"),command,value);
}
static void complete(id owner,uint16_t command,uint8_t value) {
    uint8_t response[]={1,(uint8_t)command,(uint8_t)(command>>8),value};event(owner,0x0e,response,sizeof(response));
}
static BOOL transfer(int fd,void *bytes,size_t length,BOOL sending,uint64_t generation,double deadline) {
    size_t offset=0;
    while(offset<length&&atomic_load(&Generation)==generation&&NSProcessInfo.processInfo.systemUptime<deadline) {
        struct pollfd item={fd,sending?POLLOUT:POLLIN,0};int ready=poll(&item,1,100);
        if(ready<0&&errno==EINTR)continue;if(ready<0)return NO;if(!ready)continue;
        ssize_t n=sending?send(fd,(uint8_t *)bytes+offset,length-offset,0):recv(fd,(uint8_t *)bytes+offset,length-offset,0);
        if(n<0&&(errno==EINTR||errno==EAGAIN))continue;if(n<=0)return NO;offset+=(size_t)n;
    }
    return offset==length;
}
static NSDictionary *discover(uint64_t generation) {
    int fd=socket(AF_INET,SOCK_STREAM,0);if(fd<0)return nil;int one=1;
    if(fcntl(fd,F_SETFL,O_NONBLOCK)||fcntl(fd,F_SETFD,FD_CLOEXEC)||setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one))) {close(fd);return nil;}
    struct sockaddr_in address={0};address.sin_len=sizeof(address);address.sin_family=AF_INET;address.sin_port=htons(39029);
    inet_pton(AF_INET,"10.0.2.4",&address.sin_addr);
    double deadline=NSProcessInfo.processInfo.systemUptime+14;
    int connected=connect(fd,(void *)&address,sizeof(address));
    if(connected&&errno!=EINPROGRESS){close(fd);return nil;}
    if(connected) {
        struct pollfd item={fd,POLLOUT,0};int result=poll(&item,1,2000),error=0;socklen_t size=sizeof(error);
        if(result<=0||getsockopt(fd,SOL_SOCKET,SO_ERROR,&error,&size)||error){close(fd);return nil;}
    }
    char request[]="VM27CLASSIC1 INQUIRE\n";uint32_t length=0;
    BOOL ok=transfer(fd,request,sizeof(request)-1,YES,generation,deadline)&&transfer(fd,&length,4,NO,generation,deadline);
    length=ntohl(length);if(!ok||!length||length>65536){close(fd);return nil;}
    NSMutableData *data=[NSMutableData dataWithLength:length];ok=transfer(fd,data.mutableBytes,length,NO,generation,deadline);close(fd);
    if(!ok)return nil;id reply=[NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];
    if(![reply isKindOfClass:NSDictionary.class]||[reply[@"schema"]unsignedIntValue]!=1||
       ![reply[@"source"]isEqual:@"iPad-native-classic-discovery"]||![reply[@"devices"]isKindOfClass:NSArray.class]||
       [reply[@"devices"]count]>128)return nil;
    return reply;
}
static void inquiry(id owner,dispatch_queue_t queue) {
    if(Active){status(owner,0x0401,0x0c);return;}
    Active=YES;uint64_t generation=atomic_fetch_add(&Generation,1)+1;status(owner,0x0401,0);
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED,0),^{@autoreleasepool {
        NSDictionary *reply=discover(generation);
        dispatch_async(queue,^{
            if(atomic_load(&Generation)!=generation)return;Active=NO;
            NSMutableDictionary *fresh=[NSMutableDictionary dictionary];
            if(reply&&[reply[@"status"]intValue]==0)for(id value in reply[@"devices"]) {
                if(![value isKindOfClass:NSDictionary.class]||![value[@"addressBase64"]isKindOfClass:NSString.class]||
                   ![value[@"name"]isKindOfClass:NSString.class]||![value[@"deviceClass"]isKindOfClass:NSNumber.class])continue;
                NSData *address=[[NSData alloc]initWithBase64EncodedString:value[@"addressBase64"]options:0];
                NSData *name=[value[@"name"]dataUsingEncoding:NSUTF8StringEncoding];
                uint32_t deviceClass=[value[@"deviceClass"]unsignedIntValue];
                if(address.length!=6||name.length>248||deviceClass>0xffffff)continue;
                const uint8_t *bytes=address.bytes;uint8_t little[6];unsigned nonzero=0;
                for(unsigned i=0;i<6;++i){little[i]=bytes[5-i];nonzero|=bytes[i];}if(!nonzero)continue;
                NSData *key=[NSData dataWithBytes:little length:6];
                fresh[key]=@{@"name":name,@"seen":@(NSProcessInfo.processInfo.systemUptime)};
                // Legacy Inquiry Result: no signal strength is asserted. R1
                // describes the virtual proxy's paging policy, not host RF.
                // Core specification Vol 4 Part E 7.7.2: 1 + 14 bytes.
                uint8_t result[15]={1};memcpy(result+1,little,6);result[7]=1;
                result[10]=(uint8_t)deviceClass;result[11]=(uint8_t)(deviceClass>>8);result[12]=(uint8_t)(deviceClass>>16);
                event(owner,0x02,result,sizeof(result));
            }
            Devices=fresh;uint8_t result=reply&&[reply[@"status"]intValue]==0?0:0x03;
            event(owner,0x01,&result,1);
            fprintf(stderr,"[VM27ClassicSupplement] actual inquiry results=%lu status=%u\n",(unsigned long)fresh.count,result);
        });
    }});
}
static void command(id owner,SEL selector,uint16_t opcode,const char *parameters,uint16_t length) {
    if(opcode!=0x0401&&opcode!=0x0402&&opcode!=0x0419) {Original(owner,selector,opcode,parameters,length);return;}
    if(length>255||(length&&!parameters)){status(owner,opcode,0x12);return;}
    NSData *input=[NSData dataWithBytes:parameters length:length];
    dispatch_queue_t queue=((dispatch_queue_t(*)(id,SEL))objc_msgSend)(owner,sel_registerName("dispatchQueue"));
    if(!queue){status(owner,opcode,0x03);return;}
    dispatch_async(queue,^{
        if(opcode==0x0401) {
            if(length!=5){status(owner,opcode,0x12);return;}inquiry(owner,queue);
        } else if(opcode==0x0402) {
            if(length){complete(owner,opcode,0x12);return;}
            atomic_fetch_add(&Generation,1);Active=NO;complete(owner,opcode,0);
        } else {
            if(length!=10){status(owner,opcode,0x12);return;}
            NSData *address=[input subdataWithRange:NSMakeRange(0,6)];NSDictionary *device=Devices[address];
            NSData *name=device[@"name"];
            BOOL known=name.length&&NSProcessInfo.processInfo.systemUptime-[device[@"seen"]doubleValue]<60;
            status(owner,opcode,0);uint8_t result[255]={0};result[0]=known?0:0x04;memcpy(result+1,address.bytes,6);
            if(known)memcpy(result+7,name.bytes,name.length);event(owner,0x07,result,sizeof(result));
        }
    });
}
static BOOL verified(Class cls,const char *selector,const char *types) {
    Method value=class_getInstanceMethod(cls,sel_registerName(selector));return value&&!strcmp(method_getTypeEncoding(value),types);
}
static int installSupplement(const char *expectedBoot) {
    char boot[64]={0},build[32]={0},path[PROC_PIDPATHINFO_MAXSIZE]={0};size_t n=sizeof(boot),m=sizeof(build);
    if(Original)return EALREADY;
    if(geteuid()||!expectedBoot||strlen(expectedBoot)!=36||sysctlbyname("kern.bootsessionuuid",boot,&n,NULL,0)||strcmp(boot,expectedBoot)||
       sysctlbyname("kern.osversion",build,&m,NULL,0)||strcmp(build,"25G83")||
       proc_pidpath(getpid(),path,sizeof(path))<=0||strcmp(path,"/usr/sbin/bluetoothd"))return EPERM;
    Class cls=NSClassFromString(@"BTVCHciManager");
    if(!verified(cls,"handleHciCommand:params:length:","v32@0:8S16*20S28")||
       !verified(cls,"sendHciCommandStatusEvent:status:","v24@0:8S16C20")||
       !verified(cls,"_sendHciEvent:parameters:length:","v32@0:8C16*20C28")||!verified(cls,"dispatchQueue","@16@0:8"))return EPROTONOSUPPORT;
    CommandMethod=class_getInstanceMethod(cls,sel_registerName("handleHciCommand:params:length:"));
    IMP old=method_getImplementation(CommandMethod);Dl_info image={0};
    if(!dladdr((const void *)old,&image)||!image.dli_fname||strcmp(image.dli_fname,path))return EPROTONOSUPPORT;
    Devices=[NSMutableDictionary dictionary];Original=(CommandIMP)old;
    method_setImplementation(CommandMethod,(IMP)command);
    fprintf(stderr,"[VM27ClassicSupplement] exact 25G83 native controller supplement installed; pairing unavailable\n");return 0;
}
__attribute__((visibility("default"))) int VM27SharedBluetoothClassicInstallationStatusV1=-1;
__attribute__((visibility("default"))) int VM27SharedBluetoothInstallClassicV1(const char *expectedBoot) {
    int result=installSupplement(expectedBoot);VM27SharedBluetoothClassicInstallationStatusV1=result;return result;
}
#if defined(VM27_CLASSIC_CLIENT_PROBE)
int main(int argc,char **argv) { @autoreleasepool {
    char boot[64]={0};size_t size=sizeof(boot);
    if(argc!=2||strlen(argv[1])!=36||sysctlbyname("kern.bootsessionuuid",boot,&size,NULL,0)||strcmp(boot,argv[1]))return EPERM;
    atomic_store(&Generation,1);NSDictionary *reply=discover(1);NSUInteger named=0;
    for(NSDictionary *device in reply[@"devices"])if([device[@"name"]isKindOfClass:NSString.class]&&[device[@"name"]length])++named;
    NSDictionary *report=@{@"schema":@1,@"hostReplyValidated":@(reply!=nil),@"status":reply[@"status"]?:@(-1),
        @"actualDeviceCount":@([reply[@"devices"]count]),@"actualNamedDeviceCount":@(named),
        @"nativeControllerHookInstalled":@NO,@"deviceIdentifiersRedacted":@YES};
    NSData *data=[NSJSONSerialization dataWithJSONObject:report options:NSJSONWritingPrettyPrinted|NSJSONWritingSortedKeys error:NULL];
    if(data){fwrite(data.bytes,1,data.length,stdout);fputc('\n',stdout);}return reply?0:1;
} }
#endif
