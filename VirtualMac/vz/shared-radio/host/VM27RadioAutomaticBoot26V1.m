#import "VM27RadioAutomaticBoot26V1.h"
#include "../guest/VM27RadioIMG4V1.inc"
#include <objc/message.h>
#include <objc/runtime.h>
#include <limits.h>
#include <sys/clonefile.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

static NSData *owned(NSString *path, NSUInteger limit) {
    int fd = open(path.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); struct stat st;
    if (fd < 0) return nil;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_uid != geteuid() || st.st_nlink != 1 ||
        (st.st_mode & 0022) || st.st_size <= 0 || (uint64_t)st.st_size > limit) { close(fd); return nil; }
    NSMutableData *data = [NSMutableData dataWithLength:(NSUInteger)st.st_size]; NSUInteger at = 0;
    while (at < data.length) { ssize_t n = read(fd, (uint8_t *)data.mutableBytes+at, data.length-at);
        if (n < 0 && errno == EINTR) continue; if (n <= 0) { close(fd); return nil; } at += (NSUInteger)n; }
    close(fd); return data;
}
static NSString *fail(NSError **error, NSString *message) {
    if (error) *error = [NSError errorWithDomain:@"VM27RadioAutomaticBoot26V1" code:1
        userInfo:@{NSLocalizedDescriptionKey:message}];
    return nil;
}

BOOL VM27RadioUseAutomaticBootROMV1(id loader, NSString *rom, NSString *expectedNativeImage, NSError **error) {
    Class native = objc_getClass("VZMacOSBootLoader");
    const char *image = native ? class_getImageName(native) : NULL;
    char actual[PATH_MAX], expected[PATH_MAX];
    SEL setter = sel_registerName("_setROMURL:");
    SEL getter = sel_registerName("_romURL");
    Method set = class_getInstanceMethod(native, setter);
    Method get = class_getInstanceMethod(native, getter);
    if (!native || ![loader isKindOfClass:native] || !image ||
        !realpath(image, actual) || !realpath(expectedNativeImage.fileSystemRepresentation, expected) ||
        strcmp(actual, expected) || !set || !get ||
        strcmp(method_getTypeEncoding(set), "v24@0:8@16") ||
        strcmp(method_getTypeEncoding(get), "@16@0:8")) {
        fail(error, @"The new guest boot loader does not match the selected native backend.");
        return NO;
    }
    NSURL *url = [NSURL fileURLWithPath:rom];
    ((void(*)(id, SEL, id))objc_msgSend)(loader, setter, url);
    if (![((id(*)(id, SEL))objc_msgSend)(loader, getter) isEqual:url]) {
        fail(error, @"The new guest ROM selection could not be verified.");
        return NO;
    }
    return YES;
}
static BOOL save(NSString *path, NSData *data) {
    int fd = open(path.fileSystemRepresentation, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return NO; NSUInteger at = 0; BOOL ok = YES;
    while (at < data.length) { ssize_t n = write(fd, (const uint8_t *)data.bytes+at, data.length-at);
        if (n < 0 && errno == EINTR) continue; if (n <= 0) { ok = NO; break; } at += (NSUInteger)n; }
    if (fsync(fd)) ok = NO; close(fd); return ok;
}
static uint32_t u32(NSData *data, NSUInteger offset) { uint32_t word; memcpy(&word,(const uint8_t *)data.bytes+offset,4); return word; }

NSString *VM27RadioAutomaticBoot26V1(NSString *bundle, NSString *firmware, NSError **error) {
    NSDictionary *options = [NSDictionary dictionaryWithContentsOfFile:[bundle stringByAppendingPathComponent:@"VirtualMac.plist"]];
    if (![options[@"AutomaticRadioInstallationV1"] isEqual:@YES]) return nil;
    struct stat st;
    if (lstat(bundle.fileSystemRepresentation,&st) || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode&0022))
        return fail(error,@"The new guest directory could not be verified.");
    NSString *state = [bundle stringByAppendingPathComponent:@"AutomaticRadio26-v1"];
    if (mkdir(state.fileSystemRepresentation,0700) && errno != EEXIST) return fail(error,@"The radio boot checkpoint could not be created.");
    if (lstat(state.fileSystemRepresentation,&st) || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode&0077))
        return fail(error,@"The radio checkpoint directory changed.");
    int lock = open([[state stringByAppendingPathComponent:@"lock"] fileSystemRepresentation],O_RDWR|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);
    if (lock < 0) return fail(error,@"The radio checkpoint lock could not be opened.");
    BOOL locked = !fstat(lock,&st) && S_ISREG(st.st_mode) && st.st_uid == geteuid() && st.st_nlink == 1 &&
        (st.st_mode&0777) == 0600 && !flock(lock,LOCK_EX|LOCK_NB);
    if (!locked) { close(lock); return fail(error,@"The new guest is already being prepared."); }
    NSString *result = nil;
    @try {
        NSData *machine = owned([bundle stringByAppendingPathComponent:@"MachineIdentifier"],128);
        NSData *hardware = owned([bundle stringByAppendingPathComponent:@"HardwareModel"],512);
        NSData *rom = owned(firmware,1024*1024);
        if (machine.length < 32 || hardware.length < 64 || ![radioSHA(rom) isEqual:@"6d010540a047ec71a54cb96565171f8f2e0e191dd5dbef2403f3863409afa845"])
            return fail(error,@"The new guest identity or selected backend firmware changed.");
        NSString *romPath = [state stringByAppendingPathComponent:@"AVPBooter.bin"];
        NSString *receiptPath = [state stringByAppendingPathComponent:@"Boot.plist"];
        NSData *receiptData = owned(receiptPath,16384);
        NSDictionary *receipt = receiptData ? [NSPropertyListSerialization propertyListWithData:receiptData options:0 format:NULL error:NULL] : nil;
        if (receipt) {
            if (![receipt[@"MachineSHA256"] isEqual:radioSHA(machine)] || ![receipt[@"HardwareSHA256"] isEqual:radioSHA(hardware)] ||
                ![receipt[@"ROMHash"] isEqual:radioSHA(owned(romPath,1024*1024))])
                return fail(error,@"The radio boot receipt does not match this guest.");
            NSData *current=owned([bundle stringByAppendingPathComponent:@"AuxiliaryStorage"],33570816);
            NSUInteger region=[receipt[@"LLBOffset"]unsignedIntegerValue];
            if(current.length!=33570816||region>current.length||0x200000>current.length-region)
                return fail(error,@"The prepared guest LLB region changed.");
            NSString *actual=radioSHA([current subdataWithRange:NSMakeRange(region,0x200000)]);
            if(![actual isEqual:receipt[@"PreparedLLBRegionSHA256"]]){
                // Resume only the crash window between saving the receipt
                // and the atomic activation. An OS update is not this case.
                NSData *staged=owned([state stringByAppendingPathComponent:@"AuxiliaryStorage.staged"],33570816);
                if(![radioSHA(current)isEqual:receipt[@"OriginalAuxSHA256"]]||
                   ![radioSHA(staged)isEqual:receipt[@"PreparedAuxSHA256"]]||
                   rename([state stringByAppendingPathComponent:@"AuxiliaryStorage.staged"].fileSystemRepresentation,
                          [bundle stringByAppendingPathComponent:@"AuxiliaryStorage"].fileSystemRepresentation))
                    return fail(error,@"The guest boot images changed after radio preparation.");
            }
            return romPath;
        }
        NSString *auxPath = [bundle stringByAppendingPathComponent:@"AuxiliaryStorage"];
        NSData *aux = owned(auxPath,33570816);
        if (aux.length != 33570816) return fail(error,@"The new guest NVRAM storage is unsupported.");
        NSUInteger selected = 0; uint32_t generation = 0;
        for (NSUInteger at=0x4000; at<=0x5000; at+=0x1000) {
            if (memcmp((const uint8_t *)aux.bytes+at,"HUFA",4)) continue;
            uint32_t version=u32(aux,at+4),g=u32(aux,at+8),offset=u32(aux,at+12);
            if (version!=1 || !g || (offset!=0x20000 && offset!=0x220000) || g==generation)
                return fail(error,@"The guest LLB descriptor is unsupported.");
            if (g>generation) { generation=g; selected=0x4000+offset; }
        }
        if (!selected || selected+0x200000>aux.length) return fail(error,@"The guest LLB region could not be identified.");
        NSData *tail = [aux subdataWithRange:NSMakeRange(selected,0x200000)]; NSUInteger oldSize=0;
        if (!radioBody(tail,&oldSize)) return fail(error,@"The guest boot image is malformed.");
        NSDictionary *image=radioImage([tail subdataWithRange:NSMakeRange(0,oldSize)]);
        // Only these audited public LLB payloads select an automatic
        // boot profile. Other builds retain their original boot path.
        if (!image || !radioString(image[@"parts"][1],"illb")) return nil;
        NSDictionary *profiles=@{
            @"670486e29384e91f461afde5b10902e20ef0e49b57d5f71cb836980de68eb3dd":
                @{@"Build":@"24G90",@"Bytes":@483048,@"Offset":@0x67cc,@"Before":@0xaa1b03e0},
            @"26eaa53a9955185e868099847f29d257b834bfb5aee7a3c188aa1cc18e8daef3":
                @{@"Build":@"25G83",@"Bytes":@638296,@"Offset":@0x6400,@"Before":@0xaa1b03e0},
            @"51471abf25e766fe62180a5c7d69ab8b0e3158e62c9aa6bbb4a87ad919938689":
                @{@"Build":@"26A5416b",@"Bytes":@691000,@"Offset":@0x6734,@"Before":@0xaa1403e0},
            @"bd1f08322c8b1c4c2b4d4ea1b127e8c91e929e19c5c598465da5f61f19a4aba5":
                @{@"Build":@"26B131",@"Bytes":@690952,@"Offset":@0x6734,@"Before":@0xaa1403e0}};
        NSDictionary *profile=profiles[radioSHA(image[@"payload"])];if(!profile)return nil;
        NSMutableData *llb=[image[@"payload"] mutableCopy];
        NSUInteger edit=[profile[@"Offset"]unsignedIntegerValue];
        uint32_t before=[profile[@"Before"]unsignedIntValue],after=0xd2800000;
        if (llb.length!=[profile[@"Bytes"]unsignedIntegerValue] || edit>llb.length || llb.length-edit<4 || u32(llb,edit)!=before)
            return fail(error,@"The audited guest LLB profile changed.");
        memcpy((uint8_t *)llb.mutableBytes+edit,&after,4);
        NSData *replacement=radioReplace(image,llb); if (!replacement) return fail(error,@"The guest LLB could not be encoded.");
        NSData *logoTail=[tail subdataWithRange:NSMakeRange(oldSize,tail.length-oldSize)]; NSUInteger logoSize=0;
        if (!radioBody(logoTail,&logoSize)) return fail(error,@"The original guest logo is malformed.");
        NSData *logo=[logoTail subdataWithRange:NSMakeRange(0,logoSize)]; NSDictionary *logoImage=radioImage(logo);
        if (!logoImage || !radioString(logoImage[@"parts"][1],"logo") || replacement.length+logo.length>tail.length)
            return fail(error,@"The new guest LLB region has an unsupported layout.");
        for (NSUInteger at=oldSize+logoSize;at<tail.length;at++) if (((const uint8_t *)tail.bytes)[at])
            return fail(error,@"The guest LLB region contains unexpected data.");
        NSMutableData *candidate=[aux mutableCopy]; memset((uint8_t *)candidate.mutableBytes+selected,0,0x200000);
        memcpy((uint8_t *)candidate.mutableBytes+selected,replacement.bytes,replacement.length);
        memcpy((uint8_t *)candidate.mutableBytes+selected+replacement.length,logo.bytes,logo.length);
        NSMutableData *newROM=[rom mutableCopy];
        if (u32(rom,0x2b68)!=0xaa1403e0) return fail(error,@"The audited backend ROM profile changed.");
        memcpy((uint8_t *)newROM.mutableBytes+0x2b68,&after,4);
        NSString *disk=[bundle stringByAppendingPathComponent:@"Disk.img"];
        if (lstat(disk.fileSystemRepresentation,&st) || !S_ISREG(st.st_mode) || st.st_uid!=geteuid() || st.st_nlink!=1 || (st.st_mode&0022))
            return fail(error,@"The new guest disk could not be checkpointed.");
        NSString *diskBackup=[state stringByAppendingPathComponent:@"Disk.before-radio.img"];
        NSString *auxBackup=[state stringByAppendingPathComponent:@"AuxiliaryStorage.before-radio"];
        if (clonefile(disk.fileSystemRepresentation,diskBackup.fileSystemRepresentation,CLONE_NOFOLLOW) || !save(auxBackup,aux) || !save(romPath,newROM))
            return fail(error,@"The new guest radio checkpoint could not be completed.");
        // Every byte outside the chosen LLB region is taken from this current
        // AuxiliaryStorage read, including NVRAM written by the installer.
        if (![owned(auxPath,33570816) isEqual:aux]) return fail(error,@"Guest NVRAM changed during preparation.");
        NSString *staging=[state stringByAppendingPathComponent:@"AuxiliaryStorage.staged"];
        if (!save(staging,candidate)) return fail(error,@"The prepared guest LLB could not be saved.");
        NSDictionary *record=@{@"Schema":@1,@"GuestBuild":profile[@"Build"],@"MachineSHA256":radioSHA(machine),
            @"HardwareSHA256":radioSHA(hardware),@"ROMHash":radioSHA(newROM),@"OriginalAuxSHA256":radioSHA(aux),
            @"PreparedAuxSHA256":radioSHA(candidate),@"LLBOffset":@(selected),@"DiskCheckpointCreated":@YES,
            @"PreparedLLBRegionSHA256":radioSHA([candidate subdataWithRange:NSMakeRange(selected,0x200000)]),
            @"NVRAMOutsideLLBPreserved":@YES,@"AuthenticatedRootDisableRequested":@NO};
        NSData *recordData=[NSPropertyListSerialization dataWithPropertyList:record format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL];
        if (!save(receiptPath,recordData)) return fail(error,@"The new guest radio receipt could not be saved.");
        if (rename(staging.fileSystemRepresentation,auxPath.fileSystemRepresentation)) {
            unlink(receiptPath.fileSystemRepresentation);
            return fail(error,@"The prepared guest LLB could not be activated.");
        }
        result=romPath;
    } @finally { close(lock); }
    return result;
}
