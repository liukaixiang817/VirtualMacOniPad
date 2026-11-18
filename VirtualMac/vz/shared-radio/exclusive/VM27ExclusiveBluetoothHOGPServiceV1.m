// Development-guest service. Configuration is root-owned, bound to this VM's
// host UUID, and lists guest peer UUIDs rather than hardware addresses or keys.
#import "VM27ExclusiveBluetoothHOGPV1.h"
#import "VM27ExclusiveBluetoothBondedHIDDiscoveryV1.h"
#include <libproc.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <uuid/uuid.h>
#include <signal.h>
#ifndef VM27_HOGP_NATIVE_BUILD
#define VM27_HOGP_NATIVE_BUILD "25G83"
#endif

static NSString *const Root=@"/Library/PrivilegedHelperTools/VirtualMacSharedBluetoothClassicV1";
static NSMutableDictionary<NSUUID *,VM27ExclusiveBluetoothHOGPV1 *> *Drivers;
static NSMutableDictionary<NSString *,NSDictionary *> *States;
static BOOL Stopping;
static BOOL NativeHIDOnly;
static dispatch_source_t TermSource,HOGPTimer;
static VM27ExclusiveBluetoothBondedHIDDiscoveryV1 *BondedDiscovery;
static NSSet<NSUUID *> *AutomaticPeers;
static NSData *secureRead(NSString *path){
    int fd=open(path.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);struct stat st;
    if(fd<0)return nil;
    if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_nlink!=1||(st.st_mode&0077)||st.st_size<=0||st.st_size>4096){close(fd);return nil;}
    NSMutableData *data=[NSMutableData dataWithLength:(NSUInteger)st.st_size];ssize_t count=read(fd,data.mutableBytes,data.length);close(fd);
    return count==(ssize_t)data.length?data:nil;
}
static void record(NSUUID *identifier,NSDictionary *status){
    NSMutableDictionary *row=[status mutableCopy];row[@"timestampUnix"]=@(NSDate.date.timeIntervalSince1970);
    // Peers are opaque dictionary keys held only in this process. The receipt
    // contains counts and protocol state, never report bytes or identifiers.
    States[identifier.UUIDString]=row;
    NSDictionary *out=@{@"schema":@1,@"processPID":@(getpid()),@"firstPairingRequested":@NO,@"peers":States.allValues};
    NSData *data=[NSJSONSerialization dataWithJSONObject:out options:NSJSONWritingSortedKeys error:NULL];
    NSString *path=[Root stringByAppendingPathComponent:@"exclusive-hogp-service-v1.json"];
    if(data&&[data writeToFile:path options:NSDataWritingAtomic error:NULL])chmod(path.fileSystemRepresentation,0600);
}
static void ensurePeer(NSUUID *identifier){
    if(Stopping||(Drivers[identifier]&&!Drivers[identifier].closed))return;
    VM27ExclusiveBluetoothHOGPV1 *driver=[[VM27ExclusiveBluetoothHOGPV1 alloc]initWithIdentifier:identifier];Drivers[identifier]=driver;
    driver.nativeHIDOnly=NativeHIDOnly;
    driver.statusHandler=^(NSDictionary *status){record(identifier,status);};
    [driver start];
}
int VM27StartExclusiveHOGPServiceV1(void){@autoreleasepool{
    char build[32]={0},path[PROC_PIDPATHINFO_MAXSIZE]={0};size_t n=sizeof(build);struct stat st;
    if(geteuid()||sysctlbyname("kern.osversion",build,&n,NULL,0)||strcmp(build,VM27_HOGP_NATIVE_BUILD)||
       proc_pidpath(getpid(),path,sizeof(path))<=0||(strcmp(path,"/Library/PrivilegedHelperTools/VirtualMacSharedBluetoothClassicV1/exclusive-hogp-service-v1")&&strcmp(path,"/usr/libexec/hidd"))||
       lstat(Root.fileSystemRepresentation,&st)||!S_ISDIR(st.st_mode)||st.st_uid||(st.st_mode&0077))return 77;
    NSData *data=secureRead([Root stringByAppendingPathComponent:@"exclusive-hogp-selected-peers-v1.json"]);
    id config=data?[NSJSONSerialization JSONObjectWithData:data options:0 error:NULL]:nil;
    uuid_t host;struct timespec timeout={2,0};char uuid[37]={0};
    if(gethostuuid(host,&timeout))return 77;uuid_unparse_upper(host,uuid);
    if(![config isKindOfClass:NSDictionary.class]||![config[@"schema"]isEqual:@1]||
       ![config[@"guestHostUUID"]isEqual:@(uuid)]||![config[@"selectedPeerIdentifiers"]isKindOfClass:NSArray.class]||
       (![config[@"selectedPeerIdentifiers"]count]&&![config[@"automaticBondedHID"]boolValue])||[config[@"selectedPeerIdentifiers"]count]>16)return 77;
    NSMutableArray<NSUUID *> *peers=[NSMutableArray array];
    for(id text in config[@"selectedPeerIdentifiers"]){if(![text isKindOfClass:NSString.class])return 77;NSUUID *identifier=[[NSUUID alloc]initWithUUIDString:text];if(!identifier||[peers containsObject:identifier])return 77;[peers addObject:identifier];}
    Drivers=[NSMutableDictionary dictionary];States=[NSMutableDictionary dictionary];
    NativeHIDOnly=[config[@"nativeHIDOnly"]boolValue];
    AutomaticPeers=[NSSet set];
    if([config[@"automaticBondedHID"]boolValue]){
        id saved=config[@"automaticBondedHIDPeerIdentifiers"]?:@[];
        if(![saved isKindOfClass:NSArray.class]||[saved count]>16)return 77;
        NSMutableSet *known=[NSMutableSet set];
        for(id text in saved){if(![text isKindOfClass:NSString.class])return 77;NSUUID *identifier=[[NSUUID alloc]initWithUUIDString:text];if(!identifier)return 77;[known addObject:identifier];}
        BondedDiscovery=[[VM27ExclusiveBluetoothBondedHIDDiscoveryV1 alloc]initWithKnownHIDIdentifiers:known];
        BondedDiscovery.identifiersChanged=^(NSSet<NSUUID *> *identifiers){
            AutomaticPeers=identifiers;
            // Cache only this guest's opaque HID peer IDs. Every use still
            // checks its current native bond; forgotten peers are removed.
            NSMutableDictionary *updated=[config mutableCopy];NSMutableArray *cached=[NSMutableArray array];
            for(NSUUID *identifier in identifiers)[cached addObject:identifier.UUIDString];
            updated[@"automaticBondedHIDPeerIdentifiers"]=[cached sortedArrayUsingSelector:@selector(compare:)];
            NSString *path=[Root stringByAppendingPathComponent:@"exclusive-hogp-selected-peers-v1.json"];
            NSData *data=[NSJSONSerialization dataWithJSONObject:updated options:NSJSONWritingSortedKeys error:NULL];
            if(data&&[data writeToFile:path options:NSDataWritingAtomic error:NULL])chmod(path.fileSystemRepresentation,0600);
            for(NSUUID *identifier in [Drivers.allKeys copy])if(![peers containsObject:identifier]&&![identifiers containsObject:identifier]){
                [Drivers[identifier]invalidate];[Drivers removeObjectForKey:identifier];[States removeObjectForKey:identifier.UUIDString];
            }
            for(NSUUID *identifier in identifiers){if(Drivers.count>=16)break;ensurePeer(identifier);}
        };
        [BondedDiscovery start];
    }
    if(strcmp(path,"/usr/libexec/hidd")){
        signal(SIGTERM,SIG_IGN);signal(SIGINT,SIG_IGN);
        TermSource=dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL,SIGTERM,0,dispatch_get_main_queue());
        dispatch_source_set_event_handler(TermSource,^{Stopping=YES;[BondedDiscovery invalidate];for(VM27ExclusiveBluetoothHOGPV1 *driver in Drivers.allValues)[driver invalidate];exit(0);});dispatch_resume(TermSource);
    }

    HOGPTimer=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,dispatch_get_main_queue());
    dispatch_source_set_timer(HOGPTimer,dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC),5*NSEC_PER_SEC,NSEC_PER_SEC/2);
    dispatch_source_set_event_handler(HOGPTimer,^{for(NSUUID *identifier in peers)ensurePeer(identifier);for(NSUUID *identifier in AutomaticPeers){if(Drivers.count>=16&&!Drivers[identifier])break;ensurePeer(identifier);}});dispatch_resume(HOGPTimer);
    return 0;
}}

#ifndef VM27_HOGP_EMBEDDED
int main(void){@autoreleasepool{int status=VM27StartExclusiveHOGPServiceV1();if(status)return status;CFRunLoopRun();return 0;}}
#endif
