// Henge Build104 SoftwareIdentity.swift version2 algorithm, adapted to the
// Objective-C VZ host. Native VZ opaque identifiers remain their genuine data.
#import "VMAppleAccountProfileV1.h"
#include "VMAppleAccountRuntimeV1.h"
#include <CommonCrypto/CommonDigest.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

NSString *const VMAppleAccountProfileFileV1 = @"AppleAccountIdentity.plist";
NSString *const VMAppleAccountProfileOptionV1 = @"AppleAccountIdentityV1";
static NSString *const ActiveDirectory = @"/var/mobile/Library/VirtualMacAppleAccountV1";

static BOOL Fail(NSError **error, NSString *message) {
    if (error) *error = [NSError errorWithDomain:@"VMAppleAccountProfileV1" code:1
        userInfo:@{NSLocalizedDescriptionKey:message}];
    return NO;
}
static NSString *Hex(NSData *data) {
    const uint8_t *bytes = data.bytes;
    NSMutableString *result = [NSMutableString stringWithCapacity:data.length * 2];
    for (NSUInteger i = 0; i < data.length; ++i) [result appendFormat:@"%02x", bytes[i]];
    return result;
}
static NSData *Digest(NSData *data) {
    if (!data || data.length > UINT32_MAX) return nil;
    uint8_t bytes[32];
    CC_SHA256(data.bytes, (CC_LONG)data.length, bytes);
    return [NSData dataWithBytes:bytes length:sizeof(bytes)];
}
BOOL VMAppleAccountSupportsBuildV1(NSString *build) {
    // Identity preparation is independent of the kernel compatibility table.
    // The actual restore manifest supplies this bounded Apple build identifier.
    if (![build isKindOfClass:NSString.class] || build.length < 4 || build.length >= 16) return NO;
    NSRegularExpression *pattern = [NSRegularExpression
        regularExpressionWithPattern:@"\\A[0-9]{2,3}[A-Z][0-9]{1,6}[a-z]?\\z" options:0 error:nil];
    return [pattern numberOfMatchesInString:build options:0 range:NSMakeRange(0, build.length)] == 1;
}
static BOOL ValidMLB(NSString *value) {
    if (![value isKindOfClass:NSString.class] || value.length != 17) return NO;
    NSString *alphabet = @"0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
    NSUInteger sum = 0;
    for (NSUInteger i = 0; i < 17; ++i) {
        NSRange digit = [alphabet rangeOfString:[value substringWithRange:NSMakeRange(i, 1)]];
        if (digit.location == NSNotFound) return NO;
        sum += digit.location * (i % 2 ? 3 : 1);
    }
    return sum % 34 == 0;
}
static NSString *BoardPrefix(NSString *serial) {
    if (![serial isKindOfClass:NSString.class] || serial.length != 12) return nil;
    NSString *years = @"CDFGHJKLMNPQRSTVWXYZ";
    NSString *yearCode = [serial substringWithRange:NSMakeRange(3, 1)];
    NSUInteger index = [years rangeOfString:yearCode].location;
    if (index == NSNotFound || [@"CDFGHJKLWXYZ" rangeOfString:yearCode].location == NSNotFound) return nil;
    NSString *half = index % 2 ? @"123456789CDFGHJKLMNPQRTVWXY" : @"123456789CDFGHJKLMNPQRTVWX";
    NSString *weekCode = [serial substringWithRange:NSMakeRange(4, 1)];
    if ([half rangeOfString:weekCode].location == NSNotFound) return nil;
    NSUInteger week = [@"123456789CDFGHJKLMNPQRSTVWXYZ" rangeOfString:weekCode].location;
    if (week == NSNotFound) return nil;
    week += index % 2 ? 27 : 0;
    NSUInteger year = index / 2;
    if (!week) { week = 53; year = (year + 9) % 10; }
    return [NSString stringWithFormat:@"C07%lu%02lu", (unsigned long)year, (unsigned long)week];
}
static NSData *MACBytes(NSString *text) {
    if (![text isKindOfClass:NSString.class] || text.length != 17) return nil;
    NSArray *parts = [text componentsSeparatedByString:@":"];
    if (parts.count != 6) return nil;
    uint8_t bytes[8] = {0};
    for (NSUInteger i = 0; i < 6; ++i) {
        NSString *part = parts[i];
        if (part.length != 2 || [part rangeOfCharacterFromSet:
            [[NSCharacterSet characterSetWithCharactersInString:@"0123456789abcdef"] invertedSet]].location != NSNotFound) return nil;
        unsigned value = 0;
        if (![[NSScanner scannerWithString:part] scanHexInt:&value]) return nil;
        bytes[i] = (uint8_t)value;
    }
    if (bytes[0] || bytes[1] != 0x16 || bytes[2] != 0xcb) return nil;
    return [NSData dataWithBytes:bytes length:sizeof(bytes)];
}
BOOL VMAppleAccountProfileValidV1(NSDictionary *profile) {
    if (![profile isKindOfClass:NSDictionary.class] || ![profile[@"Schema"] isEqual:@1] ||
        ![profile[@"IdentityVersion"] isEqual:@2] || ![profile[@"UUID"] isKindOfClass:NSString.class] ||
        ![[NSUUID alloc] initWithUUIDString:profile[@"UUID"]] || !VMAppleAccountSupportsBuildV1(profile[@"GuestBuild"]) ||
        ![profile[@"Model"] isEqual:@"Macmini8,1"] || !ValidMLB(profile[@"MLB"])) return NO;
    NSString *serial = profile[@"Serial"], *prefix = BoardPrefix(serial);
    if (!prefix || ![serial hasPrefix:@"C07"] || ![serial hasSuffix:@"JYVX"] ||
        [serial rangeOfCharacterFromSet:[[NSCharacterSet characterSetWithCharactersInString:
            @"0123456789ABCDEFGHJKLMNPQRSTUVWXYZ"] invertedSet]].location != NSNotFound ||
        ![profile[@"MLB"] hasPrefix:prefix] || ![[profile[@"MLB"] substringWithRange:NSMakeRange(11, 4)] isEqual:@"KXPG"]) return NO;
    NSArray *macs = profile[@"MACAddresses"];
    if (![macs isKindOfClass:NSArray.class] || macs.count != 4 || [NSSet setWithArray:macs].count != 4) return NO;
    for (id mac in macs) if (!MACBytes(mac)) return NO;
    return YES;
}
NSDictionary *VMAppleAccountMakeProfileV1(NSString *build, NSError **error) {
    if (!VMAppleAccountSupportsBuildV1(build)) {
        Fail(error, @"The macOS restore build identifier is invalid."); return nil;
    }
    NSString *alphabet = @"0123456789ABCDEFGHJKLMNPQRSTUVWXYZ", *years = @"CDFGHJKLMNPQRSTVWXYZ";
    NSString *weeks = @"0123456789CDFGHJKLMNPQRTVWX123456789CDFGHJKLMNPQRTVWXY";
    unsigned year = 2018 + arc4random_uniform(6), week = 1 + arc4random_uniform(52);
    unsigned base = year >= 2020 ? 2020 : 2010;
    unichar yearCode = [years characterAtIndex:(year - base) * 2 + (week >= 27 ? 1 : 0)];
    unsigned line = arc4random_uniform(3400), copy = line > 1155 ? (line - 1155 + 67) / 68 : 0;
    unsigned remainder = line - copy * 68;
    NSString *serial = [NSString stringWithFormat:@"C07%C%C%C%C%CJYVX", yearCode, [weeks characterAtIndex:week],
        [alphabet characterAtIndex:copy], [alphabet characterAtIndex:remainder / 34], [alphabet characterAtIndex:remainder % 34]];
    NSString *prefix = BoardPrefix(serial);
    NSArray *parts = @[@"200",@"600",@"403",@"404",@"405",@"303",@"108",@"207",@"609",@"501",@"306",@"102",@"701",@"301",@"501",@"101",@"300",@"130",@"100",@"270",@"310",@"902",@"104",@"401",@"902",@"500",@"700",@"802"];
    NSArray *middle = @[@"GU",@"4N",@"J9",@"QX",@"OP",@"CD",@"GU"];
    NSArray *suffix = @[@"1H",@"1M",@"AD",@"1F",@"A8",@"UE",@"JA",@"JC",@"8C",@"CB",@"FB"];
    NSString *mlb;
    do {
        mlb = [NSString stringWithFormat:@"%@%@%@KXPG%@", prefix,
            parts[arc4random_uniform((uint32_t)parts.count)], middle[arc4random_uniform((uint32_t)middle.count)],
            suffix[arc4random_uniform((uint32_t)suffix.count)]];
    } while (!ValidMLB(mlb));
    uint32_t tail = arc4random_uniform(0x1000000);
    NSMutableArray *macs = [NSMutableArray array];
    for (unsigned i = 0; i < 4; ++i) {
        uint32_t value = (tail + i) & 0xffffff;
        [macs addObject:[NSString stringWithFormat:@"00:16:cb:%02x:%02x:%02x", value >> 16, value >> 8 & 255, value & 255]];
    }
    NSDictionary *profile = @{ @"Schema":@1, @"IdentityVersion":@2, @"UUID":NSUUID.UUID.UUIDString,
        @"GuestBuild":build, @"Model":@"Macmini8,1", @"Serial":serial, @"MLB":mlb,
        @"MACAddresses":macs, @"CreatedAt":NSDate.date };
    if (!VMAppleAccountProfileValidV1(profile)) { Fail(error, @"The new Apple Account identity did not pass validation."); return nil; }
    return profile;
}
BOOL VMAppleAccountSaveNewProfileV1(NSDictionary *profile, NSString *directory, NSError **error) {
    if (!VMAppleAccountProfileValidV1(profile)) return Fail(error, @"The Apple Account identity is invalid.");
    NSString *path = [directory stringByAppendingPathComponent:VMAppleAccountProfileFileV1];
    if ([NSFileManager.defaultManager fileExistsAtPath:path])
        return [[NSDictionary dictionaryWithContentsOfFile:path] isEqual:profile] || Fail(error, @"This installation already has a different Apple Account identity.");
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:profile format:NSPropertyListBinaryFormat_v1_0 options:0 error:error];
    if (!data || ![data writeToFile:path options:NSDataWritingAtomic error:error]) return NO;
    if (chmod(path.fileSystemRepresentation, 0600)) return Fail(error, @"The Apple Account identity could not be protected.");
    int file = open(path.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    BOOL durable = file >= 0 && !fsync(file);
    if (file >= 0) close(file);
    int folder = open(directory.fileSystemRepresentation, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    durable = durable && folder >= 0 && !fsync(folder);
    if (folder >= 0) close(folder);
    if (!durable) return Fail(error, @"The Apple Account identity could not be saved durably.");
    return YES;
}
BOOL VMAppleAccountBindRestoredProfileV1(NSString *attempt, NSString *bundle, NSError **error) {
    NSString *source = [attempt stringByAppendingPathComponent:VMAppleAccountProfileFileV1];
    if (![NSFileManager.defaultManager fileExistsAtPath:source]) return YES;
    NSDictionary *original = [NSDictionary dictionaryWithContentsOfFile:source];
    if (!VMAppleAccountProfileValidV1(original)) return Fail(error, @"The installation identity is missing or damaged.");
    NSData *machine = [NSData dataWithContentsOfFile:[bundle stringByAppendingPathComponent:@"MachineIdentifier"]];
    NSData *hardware = [NSData dataWithContentsOfFile:[bundle stringByAppendingPathComponent:@"HardwareModel"]];
    if (machine.length < 16 || machine.length > 1024 || hardware.length < 16 || hardware.length > 1024)
        return Fail(error, @"The restored native Mac identity could not be bound.");
    NSMutableDictionary *profile = [original mutableCopy];
    profile[@"MachineIdentifierSHA256"] = Hex(Digest(machine));
    profile[@"HardwareModelSHA256"] = Hex(Digest(hardware));
    return VMAppleAccountSaveNewProfileV1(profile, bundle, error);
}
BOOL VMAppleAccountPrepareBootV1(NSString *bundle, NSDictionary *options, BOOL native27, NSError **error) {
    NSString *path = [bundle stringByAppendingPathComponent:VMAppleAccountProfileFileV1];
    NSString *active = [ActiveDirectory stringByAppendingPathComponent:@"Active.handoff"];
    if (![NSFileManager.defaultManager fileExistsAtPath:path] && !options[VMAppleAccountProfileOptionV1]) {
        if (unlink(active.fileSystemRepresentation) && errno != ENOENT) return Fail(error, @"The previous account identity handoff could not be cleared.");
        return YES;
    }
    NSDictionary *profile = [NSDictionary dictionaryWithContentsOfFile:path];
    if (!VMAppleAccountProfileValidV1(profile) || ![profile[@"UUID"] isEqual:options[VMAppleAccountProfileOptionV1]])
        return Fail(error, @"The saved Apple Account identity is missing or does not match this Mac.");
    if (!native27) return Fail(error, @"Select the complete macOS 27 backend to start this Apple Account Mac.");
    if ([NSFileManager.defaultManager fileExistsAtPath:
            [bundle stringByAppendingPathComponent:@".VM27HibernateV1/Current.plist"]])
        return Fail(error, @"Discard this Mac's saved hibernation state before starting with Apple Account support.");
    if (![options[@"MACAddress"] isEqual:profile[@"MACAddresses"][0]])
        return Fail(error, @"Restore this Mac's saved network address before signing in to Apple Account.");
    NSData *machine = [NSData dataWithContentsOfFile:[bundle stringByAppendingPathComponent:@"MachineIdentifier"]];
    NSData *hardware = [NSData dataWithContentsOfFile:[bundle stringByAppendingPathComponent:@"HardwareModel"]];
    NSData *machineHash = Digest(machine), *hardwareHash = Digest(hardware);
    if (![Hex(machineHash) isEqual:profile[@"MachineIdentifierSHA256"]] || ![Hex(hardwareHash) isEqual:profile[@"HardwareModelSHA256"]])
        return Fail(error, @"This Mac's native machine identity changed. Its Apple Account profile cannot be reused.");
    NSString *library = bundle.stringByDeletingLastPathComponent;
    for (NSString *name in [NSFileManager.defaultManager contentsOfDirectoryAtPath:library error:nil]) {
        NSString *other = [library stringByAppendingPathComponent:name];
        if ([other isEqual:bundle] || ![name hasSuffix:@".bundle"]) continue;
        NSDictionary *saved = [NSDictionary dictionaryWithContentsOfFile:[other stringByAppendingPathComponent:VMAppleAccountProfileFileV1]];
        if ([saved[@"UUID"] isEqual:profile[@"UUID"]]) return Fail(error, @"Another Mac in this library has the same Apple Account identity.");
    }
    if (![NSFileManager.defaultManager createDirectoryAtPath:ActiveDirectory withIntermediateDirectories:NO
        attributes:@{NSFilePosixPermissions:@0700} error:error] && errno != EEXIST) return NO;
    struct stat st;
    if (lstat(ActiveDirectory.fileSystemRepresentation, &st) || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 0077))
        return Fail(error, @"The private Apple Account handoff directory is unavailable.");
    VMAppleAccountHandoffV1 handoff = {0};
    memcpy(handoff.magic, "VMAID001", 8); handoff.schema = 1; handoff.appPID = (uint32_t)getpid();
    [[[NSUUID alloc] initWithUUIDString:profile[@"UUID"]] getUUIDBytes:handoff.profileUUID];
    if (strlcpy(handoff.bundlePath, bundle.fileSystemRepresentation, sizeof(handoff.bundlePath)) >= sizeof(handoff.bundlePath))
        return Fail(error, @"The Mac's bundle path is too long.");
    strlcpy(handoff.build, [profile[@"GuestBuild"] UTF8String], sizeof(handoff.build));
    strlcpy(handoff.serial, [profile[@"Serial"] UTF8String], sizeof(handoff.serial));
    strlcpy(handoff.mlb, [profile[@"MLB"] UTF8String], sizeof(handoff.mlb));
    strlcpy(handoff.model, [profile[@"Model"] UTF8String], sizeof(handoff.model));
    for (NSUInteger i = 0; i < 4; ++i) memcpy(handoff.mac[i], MACBytes(profile[@"MACAddresses"][i]).bytes, 8);
    memcpy(handoff.machineSHA256, machineHash.bytes, 32); memcpy(handoff.hardwareSHA256, hardwareHash.bytes, 32);
    NSData *data = [NSData dataWithBytes:&handoff length:sizeof(handoff)];
    if (![data writeToFile:active options:NSDataWritingAtomic error:error]) return NO;
    if (chmod(active.fileSystemRepresentation, 0600)) return Fail(error, @"The identity handoff could not be protected.");
    return YES;
}
