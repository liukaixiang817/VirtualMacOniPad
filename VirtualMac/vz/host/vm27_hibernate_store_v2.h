#pragma once
#import <Foundation/Foundation.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <CommonCrypto/CommonDigest.h>
/* Private helper shared by the native controller and exact-source store tests. */
static NSError *VM27HibernateErrorV4(NSInteger code,NSString *reason) {
    return [NSError errorWithDomain:@"VirtualMac.Hibernate" code:code
        userInfo:@{NSLocalizedDescriptionKey:reason}];
}
static NSString *VM27HibernateRootV4(NSString *bundle) {
    return [bundle stringByAppendingPathComponent:@".VM27HibernateV1"];
}
static BOOL VM27HibernateOwnedV4(NSString *path,BOOL directory) {
    struct stat st;
    return !lstat(path.fileSystemRepresentation,&st) && st.st_uid==getuid() &&
        (directory?S_ISDIR(st.st_mode):(S_ISREG(st.st_mode)&&st.st_nlink==1)) &&
        !(st.st_mode&0077);
}
static NSDictionary *VM27HibernateDiskV4(NSString *bundle) {
    NSString *path=[bundle stringByAppendingPathComponent:@"Disk.img"];
    struct stat st;
    if(lstat(path.fileSystemRepresentation,&st)||!S_ISREG(st.st_mode)||st.st_nlink!=1)return nil;
    return @{@"device":@((uint64_t)st.st_dev),@"inode":@((uint64_t)st.st_ino),@"bytes":@((uint64_t)st.st_size),
        @"mtimeSeconds":@(st.st_mtimespec.tv_sec),@"mtimeNanos":@(st.st_mtimespec.tv_nsec)};
}
static NSData *VM27HibernateIdentityV4(NSString *bundle) {
    NSMutableData *data=[NSMutableData data];
    for(NSString *name in @[@"HardwareModel",@"MachineIdentifier"]) {
        NSData *part=[NSData dataWithContentsOfFile:[bundle stringByAppendingPathComponent:name]];
        if(!part.length || part.length>1024*1024)return nil;
        uint64_t length=part.length;[data appendBytes:&length length:sizeof(length)];[data appendData:part];
    }
    uint8_t hash[CC_SHA256_DIGEST_LENGTH];CC_SHA256(data.bytes,(CC_LONG)data.length,hash);
    return [NSData dataWithBytes:hash length:sizeof(hash)];
}
static NSDictionary *VM27HibernateReadV4(NSString *bundle,NSError **error) {
    NSString *root=VM27HibernateRootV4(bundle),*path=[root stringByAppendingPathComponent:@"Current.plist"];
    struct stat st;
    if(lstat(path.fileSystemRepresentation,&st)) {
        if(errno!=ENOENT && error)*error=VM27HibernateErrorV4(errno,VZL(@"The hibernation record could not be read."));
        return nil;
    }
    if(!VM27HibernateOwnedV4(root,YES)||!VM27HibernateOwnedV4(path,NO)||st.st_size>1024*1024) {
        if(error)*error=VM27HibernateErrorV4(EACCES,VZL(@"The hibernation record has an invalid owner or file type."));return nil;
    }
    NSDictionary *record=[NSDictionary dictionaryWithContentsOfFile:path];
    NSString *generation=[record isKindOfClass:NSDictionary.class]?record[@"Generation"]:nil;
    NSUUID *uuid=[generation isKindOfClass:NSString.class]?[[[NSUUID alloc]initWithUUIDString:generation]autorelease]:nil;
    NSString *stage=uuid?[root stringByAppendingPathComponent:uuid.UUIDString]:nil;
    if(![record[@"Version"]isEqual:@1]||![generation isEqual:uuid.UUIDString]||
       !VM27HibernateOwnedV4(stage,YES)||!VM27HibernateOwnedV4([stage stringByAppendingPathComponent:@"State.vzvmsave"],NO)) {
        if(error)*error=VM27HibernateErrorV4(EINVAL,VZL(@"The saved hibernation state is incomplete."));return nil;
    }
    NSString *statePath=[stage stringByAppendingPathComponent:@"State.vzvmsave"];
    struct stat stateStat={0};
    if(![record[@"StateBytes"]isKindOfClass:NSNumber.class] ||
       lstat(statePath.fileSystemRepresentation,&stateStat) || stateStat.st_size<=0 ||
       (uint64_t)stateStat.st_size!=[record[@"StateBytes"]unsignedLongLongValue]) {
        if(error)*error=VM27HibernateErrorV4(EINVAL,VZL(@"The hibernation file is truncated or has changed."));return nil;
    }
    return record;
}
/* Persist the directory entry before a saved marker is published/consumed. */
static BOOL VM27HibernateSyncDirectoryV5(NSString *path) {
    if(!VM27HibernateOwnedV4(path,YES))return NO;
    int fd=open(path.fileSystemRepresentation,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if(fd<0)return NO;
    struct stat st;BOOL ok=!fstat(fd,&st) && S_ISDIR(st.st_mode) && st.st_uid==getuid() && !(st.st_mode&0077) && !fsync(fd);
    close(fd);return ok;
}
static BOOL VM27HibernateConsumeV4(NSString *bundle,NSDictionary *record,NSError **error) {
    NSDictionary *current=VM27HibernateReadV4(bundle,error);
    if(!current || ![current isEqual:record])return NO;
    NSString *root=VM27HibernateRootV4(bundle);
    NSString *stage=[root stringByAppendingPathComponent:record[@"Generation"]];
    if(unlink([[root stringByAppendingPathComponent:@"Current.plist"]fileSystemRepresentation])) {
        if(error)*error=VM27HibernateErrorV4(errno,VZL(@"The restored state could not be marked as consumed."));return NO;
    }
    if(!VM27HibernateSyncDirectoryV5(root)) {
        if(error)*error=VM27HibernateErrorV4(EIO,VZL(@"The consumed state marker could not be flushed."));return NO;
    }
    /* A native restore may still map this inode. Unlink preserves its mappings. */
    unlink([[stage stringByAppendingPathComponent:@"State.vzvmsave"]fileSystemRepresentation]);
    rmdir(stage.fileSystemRepresentation);
    return YES;
}
