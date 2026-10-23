#import <Foundation/Foundation.h>
static NSString *VZL(NSString *s){return s;}
#include "vm27_hibernate_store_v1.h"
#include <assert.h>

static void Store(NSString *path,NSData *data) {
    assert([data writeToFile:path atomically:NO]);assert(!chmod(path.fileSystemRepresentation,0600));
}
int main(void) {@autoreleasepool {
    char pattern[]="/private/tmp/vm27-hibernate-store-test.XXXXXX";
    char *directory=mkdtemp(pattern);assert(directory);
    NSString *bundle=[NSString stringWithUTF8String:directory];
    NSString *disk=[bundle stringByAppendingPathComponent:@"Disk.img"];
    NSString *model=[bundle stringByAppendingPathComponent:@"HardwareModel"];
    NSString *machine=[bundle stringByAppendingPathComponent:@"MachineIdentifier"];
    Store(disk,[NSData dataWithBytes:"disk" length:4]);
    Store(model,[NSData dataWithBytes:"model" length:5]);
    Store(machine,[NSData dataWithBytes:"machine" length:7]);
    assert([VM27HibernateDiskV4(bundle)[@"bytes"]isEqual:@4]);
    NSData *identity=VM27HibernateIdentityV4(bundle);assert(identity.length==32);
    Store(machine,[NSData dataWithBytes:"changed" length:7]);
    assert(![identity isEqual:VM27HibernateIdentityV4(bundle)]);
    NSString *root=VM27HibernateRootV4(bundle);assert(!mkdir(root.fileSystemRepresentation,0700));
    NSString *generation=NSUUID.UUID.UUIDString;
    NSString *stage=[root stringByAppendingPathComponent:generation];assert(!mkdir(stage.fileSystemRepresentation,0700));
    NSString *state=[stage stringByAppendingPathComponent:@"State.vzvmsave"];
    NSString *current=[root stringByAppendingPathComponent:@"Current.plist"];
    NSData *bytes=[NSMutableData dataWithLength:8192];Store(state,bytes);
    NSDictionary *record=@{@"Version":@1,@"Generation":generation,@"StateBytes":@8192};
    NSData *metadata=[NSPropertyListSerialization dataWithPropertyList:record format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil];
    Store(current,metadata);NSError *error=nil;
    assert([VM27HibernateReadV4(bundle,&error)isEqual:record] && !error);
    int fd=open(state.fileSystemRepresentation,O_WRONLY);assert(fd>=0 && !ftruncate(fd,4096));close(fd);
    error=nil;assert(!VM27HibernateReadV4(bundle,&error) && error);
    Store(state,bytes);assert(!unlink(state.fileSystemRepresentation));
    NSString *outside=[bundle stringByAppendingPathComponent:@"outside"];
    Store(outside,bytes);assert(!symlink(outside.fileSystemRepresentation,state.fileSystemRepresentation));
    error=nil;assert(!VM27HibernateReadV4(bundle,&error) && error);
    assert([NSData dataWithContentsOfFile:outside].length==8192);
    assert(!unlink(state.fileSystemRepresentation));Store(state,bytes);
    NSDictionary *escape=@{@"Version":@1,@"Generation":@"../outside",@"StateBytes":@8192};
    Store(current,[NSPropertyListSerialization dataWithPropertyList:escape format:NSPropertyListBinaryFormat_v1_0 options:0 error:nil]);
    error=nil;assert(!VM27HibernateReadV4(bundle,&error) && error);
    Store(current,metadata);assert(!chmod(current.fileSystemRepresentation,0644));
    error=nil;assert(!VM27HibernateReadV4(bundle,&error) && error);
    assert(!chmod(current.fileSystemRepresentation,0600));
    error=nil;assert(!VM27HibernateConsumeV4(bundle,escape,&error));
    assert([NSFileManager.defaultManager fileExistsAtPath:state]);
    error=nil;assert(VM27HibernateConsumeV4(bundle,record,&error));
    assert(![NSFileManager.defaultManager fileExistsAtPath:current]);
    assert(![NSFileManager.defaultManager fileExistsAtPath:state]);
    assert([NSData dataWithContentsOfFile:outside].length==8192);
    assert(!unlink(outside.fileSystemRepresentation));assert(!rmdir(root.fileSystemRepresentation));
    assert(!unlink(disk.fileSystemRepresentation));assert(!unlink(model.fileSystemRepresentation));
    assert(!unlink(machine.fileSystemRepresentation));
    assert(!rmdir(bundle.fileSystemRepresentation));
    printf("HIBERNATE_STORE_TEST valid truncated symlink traversal permissions stale-record consume: PASS\n");
    return 0;
}}
