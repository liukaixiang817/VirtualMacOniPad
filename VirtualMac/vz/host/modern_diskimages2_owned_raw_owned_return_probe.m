/* Original DI2 bounded object/descriptor calls on a new owned RAW fixture.
 * No guest image, attach, guessed C++ aggregate or emulated DI2 implementation. */
#include <stddef.h>
#include <stdint.h>
#include "diskimages227-owned-raw-pins.h"
#import <Foundation/Foundation.h>
#import <objc/message.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <objc/runtime.h>
#include <ptrauth.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int FilePin(const struct ImagePin *pin) {
    FILE *file = fopen(pin->path, "rb"); if (!file) return 0;
    unsigned char bytes[8192], digest[32]; size_t size, total = 0;
    CC_SHA256_CTX ctx; CC_SHA256_Init(&ctx);
    while ((size = fread(bytes, 1, sizeof(bytes), file))) { total += size; CC_SHA256_Update(&ctx, bytes, (CC_LONG)size); }
    int valid = !ferror(file); valid &= fclose(file) == 0; CC_SHA256_Final(digest, &ctx);
    return valid && total == pin->bytes && !memcmp(digest, pin->sha, 32);
}
static int Identity(const void *address, const struct ImagePin *pin, uintptr_t expectedRVA, int checkRVA) {
    Dl_info info = {0}; if (!dladdr(address, &info) || !info.dli_fbase || !info.dli_fname) return 0;
    const struct mach_header_64 *header = info.dli_fbase;
    if (header->magic != MH_MAGIC_64 || header->filetype != MH_DYLIB || header->ncmds > 256 || header->sizeofcmds > 32768) return 0;
    const unsigned char *at = (const void *)(header + 1), *end = at + header->sizeofcmds;
    char uuid[33] = {0}, actual[4096], expected[4096]; unsigned found = 0;
    for (unsigned i = 0; i < header->ncmds; ++i) {
        if ((size_t)(end - at) < 8) return 0;
        const struct load_command *command = (const void *)at;
        if (command->cmdsize < 8 || command->cmdsize % 8 || command->cmdsize > (size_t)(end - at)) return 0;
        if (command->cmd == LC_UUID) {
            if (command->cmdsize != sizeof(struct uuid_command)) return 0;
            for (unsigned k = 0; k < 16; ++k) snprintf(uuid + k * 2, 3, "%02x", at[8 + k]); ++found;
        }
        at += command->cmdsize;
    }
    uintptr_t rva = (uintptr_t)address - (uintptr_t)header;
    if (at != end || found != 1 || strcmp(uuid, pin->uuid) ||
        !realpath(info.dli_fname, actual) || !realpath(pin->path, expected) || strcmp(actual, expected) ||
        (checkRVA && rva != expectedRVA)) return 0;
    printf("{\"record\":\"identity\",\"UUID\":\"%s\",\"path\":\"%s\",\"RVA\":\"0x%llx\"}\n", uuid, actual, (unsigned long long)rva);
    return 1;
}

/* These are the original four scalar/object Objective-C method ABIs. No
 * private C++ expected<>, unique_ptr, locked-resource or UIO structure is
 * declared in this caller. objc_msgSend retains its normal IMP authentication. */
typedef id (*InitParams)(id, SEL, NSURL *, NSInteger, NSError **);
// The pinned original method allocates/initializes DIImageHandle and returns
// it directly (+1), despite the method name not belonging to the new family.
// Consume this owned result exactly once; an additional retain leaks it.
typedef id (*OpenParams)(id, SEL, NSError **) __attribute__((ns_returns_retained));
typedef int (*IntGetter)(id, SEL);
typedef NSInteger (*IntegerGetter)(id, SEL);
typedef uint64_t (*SecurityCounter)(uint32_t);
static unsigned APICalls, Opens, Handles, fdReadCalls, fdWriteCalls, checks;

static void Log(NSDictionary *record) {
    NSData *json = [NSJSONSerialization dataWithJSONObject:record options:0 error:NULL];
    if (!json) abort();
    fwrite([json bytes], 1, [json length], stdout); putchar('\n');
}
static BOOL Require(BOOL condition, NSString *stage) {
    if (!condition) Log(@{ @"record": @"failure", @"stage": stage, @"errno": @(errno), @"DI2APICalls": @(APICalls) });
    else ++checks;
    return condition;
}
static void OriginalError(NSString *stage, NSError *error) {
    Log(@{ @"record": @"originalError", @"stage": stage, @"hasNSError": @(error != nil),
           @"domain": error ? [error domain] : @"", @"code": error ? @([error code]) : @0,
           @"DI2APICalls": @(APICalls) });
}
static BOOL CountersZero(SecurityCounter counter, NSString *phase) {
    for (uint32_t i = 0; i < 10; ++i) {
        uint64_t actual = counter(i);
        Log(@{ @"record": @"securityCounter", @"phase": phase, @"entry": @(i), @"calls": @(actual) });
        if (!Require(actual == 0, @"no desktop Authorization/Keychain/Session invocation")) return NO;
    }
    return YES;
}

static int OwnedCycle(Class paramsClass, Class handleClass, const char *path,
                      const struct stat *originalStat, BOOL reopen) {
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    id params = nil, handle = nil;
    int result = 80, borrowed = -1;
    @try {
    NSURL *url = [NSURL fileURLWithPath:[NSString stringWithUTF8String:path]];
    NSError *error = nil;
    id allocation = [paramsClass alloc];
    ++APICalls;
    params = ((InitParams)objc_msgSend)(allocation, sel_registerName("initWithURL:openMode:error:"), url, 2, &error);
    if (!params || error) { OriginalError(@"init strict RW parameters", error); goto finish; }
    if (!Require(object_getClass(params) == paramsClass, @"genuine params instance class")) goto finish;
    ++APICalls;
    int internalMode = ((IntGetter)objc_msgSend)(params, sel_registerName("UIOOpenMode"));
    if (!Require(internalMode == 1, @"public mode 2 maps to strict internal RW 1")) goto finish;
    error = nil; ++APICalls; ++Opens;
    handle = ((OpenParams)objc_msgSend)(params, sel_registerName("openWithError:"), &error);
    if (!handle || error) { OriginalError(@"original openWithError", error); goto finish; }
    ++Handles;
    if (!Require(object_getClass(handle) == handleClass, @"genuine DIImageHandle instance class")) goto finish;
    ++APICalls;
    borrowed = ((IntGetter)objc_msgSend)(handle, sel_registerName("fileDescriptor"));
    struct stat descriptorStat;
    if (!Require(borrowed >= 0 && fstat(borrowed, &descriptorStat) == 0 && S_ISREG(descriptorStat.st_mode) &&
                 descriptorStat.st_dev == originalStat->st_dev && descriptorStat.st_ino == originalStat->st_ino &&
                 descriptorStat.st_size == 131072, @"actual borrowed fd identifies owned 128KiB regular file")) goto finish;
    int flags = fcntl(borrowed, F_GETFL);
    if (!Require(flags >= 0 && (flags & O_ACCMODE) == O_RDWR, @"actual fd remains strict read/write")) goto finish;
    ++APICalls;
    NSInteger reportedMode = ((IntegerGetter)objc_msgSend)(handle, sel_registerName("openMode"));
    Log(@{ @"record": @"originalHandle", @"reopen": @(reopen), @"fileDescriptor": @(borrowed),
           @"device": @((uint64_t)descriptorStat.st_dev), @"inode": @((uint64_t)descriptorStat.st_ino),
           @"bytes": @(descriptorStat.st_size), @"publicRequestedMode": @2, @"internalMode": @(internalMode),
           @"reportedHandleMode": @(reportedMode), @"actualPOSIXAccessMode": @(flags & O_ACCMODE) });
    unsigned char expected[4096], observed[4096];
    for (unsigned i = 0; i < sizeof(expected); ++i) expected[i] = (unsigned char)(i * 13 + 7);
    ++fdReadCalls;
    if (!Require(pread(borrowed, observed, sizeof(observed), 4096) == sizeof(observed), @"original-fd bounded pread")) goto finish;
    if (!reopen) {
        unsigned char zero[4096] = {0};
        if (!Require(memcmp(observed, zero, sizeof(zero)) == 0, @"owned RAW initially zero")) goto finish;
        ++fdWriteCalls;
        if (!Require(pwrite(borrowed, expected, sizeof(expected), 4096) == sizeof(expected), @"original-fd one bounded pwrite")) goto finish;
        // iOS's public SDK declares fsync, which also flushes this own file's
        // data. Do not invent an unavailable fdatasync declaration or ABI.
        if (!Require(fsync(borrowed) == 0, @"original-fd data persistence")) goto finish;
        ++fdReadCalls;
        if (!Require(pread(borrowed, observed, sizeof(observed), 4096) == sizeof(observed), @"original-fd read after write")) goto finish;
    }
    if (!Require(memcmp(observed, expected, sizeof(expected)) == 0, reopen ? @"original reopened fd persistent readback" : @"original fd write readback")) goto finish;
    result = 0;
    } @finally {
        // Also execute on an original framework NSException. The outer caller
        // still records failure; it must never present exception cleanup as a
        // successful RAW lifecycle or suppress a real C++/kernel failure.
        [handle release]; [params release];
        [pool drain];
    }
finish:
    if (borrowed >= 0) {
        BOOL closed = NO;
        for (unsigned attempt = 0; attempt < 10; ++attempt) {
            errno = 0;
            if (fcntl(borrowed, F_GETFD) == -1 && errno == EBADF) { closed = YES; break; }
            usleep(10000);
        }
        if (!Require(closed, @"genuine handle destruction closes borrowed fd")) result = 81;
        Log(@{ @"record": @"originalLifecycle", @"reopen": @(reopen), @"borrowedFD": @(borrowed),
               @"closedByFramework": @(closed), @"borrowedFDCloseCallsByProbe": @0 });
    }
    return result;
}

static BOOL MissingFileError(Class paramsClass, const char *path) {
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    BOOL okay = NO;
    id params = nil, opened = nil;
    @try {
    char missing[4096];
    if (snprintf(missing, sizeof(missing), "%s.missing", path) >= (int)sizeof(missing)) return NO;
    struct stat state; errno = 0;
    okay = lstat(missing, &state) == -1 && errno == ENOENT;
    NSError *error = nil;
    if (okay) {
        NSURL *url = [NSURL fileURLWithPath:[NSString stringWithUTF8String:missing]];
        ++APICalls;
        params = ((InitParams)objc_msgSend)([paramsClass alloc], sel_registerName("initWithURL:openMode:error:"), url, 2, &error);
        if (params && !error) { ++APICalls; ++Opens; opened = ((OpenParams)objc_msgSend)(params, sel_registerName("openWithError:"), &error); }
        okay = !opened && error != nil;
        OriginalError(@"owned nonexistent RAW path", error);
        errno = 0; okay &= lstat(missing, &state) == -1 && errno == ENOENT;
    }
    } @finally { [opened release]; [params release]; [pool drain]; }
    return Require(okay, @"real framework NSError and no missing-file creation");
}

int main(int argc, char **argv) {
    if (argc != 2 || strcmp(argv[1], "--owned-raw")) return 64;
    if (setvbuf(stdout, NULL, _IOLBF, 0)) return 64;
    struct rlimit cpu = {3, 4}, files = {128, 128};
    if (setrlimit(RLIMIT_CPU, &cpu) || setrlimit(RLIMIT_NOFILE, &files)) return 64;
    alarm(10); // The parent must also observe actual wait, absence and cleanup after abnormal exit.
    Log(@{ @"record": @"start", @"PID": @(getpid()), @"DI2APICalls": @0, @"ownedRAWBytesLimit": @131072 });
    for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
        const char *path = _dyld_get_image_name(i);
        if (path && strstr(path, "DiskImages2")) { fprintf(stderr, "preexisting DI2 image: %s\n", path); return 65; }
    }
    for (unsigned i = 0; i < 5; ++i) if (objc_lookUpClass(ClassNames[i])) return 65;
    for (unsigned i = 0; i < ImageCount; ++i) if (!FilePin(&Images[i])) return 66;
    void *library = dlopen(Images[DI2Index].path, RTLD_NOW | RTLD_LOCAL | RTLD_FIRST);
    if (!library) { fprintf(stderr, "genuine27 DI2 dlopen: %s\n", dlerror()); return 67; }
    void *compat = dlopen(Images[CompatIndex].path, RTLD_NOLOAD | RTLD_NOW | RTLD_LOCAL | RTLD_FIRST);
    if (!compat) return 68;
    for (unsigned i = 0; i < ProviderSymbolCount; ++i) {
        const struct ProviderSymbol *row = &ProviderSymbols[i]; void *entry = dlsym(compat, row->name + 1);
        if (!entry || !Identity(row->data ? entry : ptrauth_strip(entry, ptrauth_key_function_pointer), &Images[row->image], 0, 0)) return 68;
    }
    Class classes[5] = {0};
    for (unsigned i = 0; i < 5; ++i) {
        char name[160]; snprintf(name, sizeof(name), "OBJC_CLASS_$_%s", ClassNames[i]);
        classes[i] = dlsym(library, name);
        if (!classes[i] || !Identity(classes[i], &Images[DI2Index], 0, 0) || objc_lookUpClass(ClassNames[i]) != classes[i]) return 69;
    }
    for (unsigned i = 0; i < MethodCount; ++i) {
        const struct MethodPin *pin = &Methods[i];
        Method method = class_getInstanceMethod(objc_lookUpClass(pin->className), sel_registerName(pin->selector));
        if (!method || strcmp(method_getTypeEncoding(method), pin->encoding) ||
            !Identity(ptrauth_strip((void *)method_getImplementation(method), ptrauth_key_function_pointer), &Images[DI2Index], pin->rva, 1)) return 70;
    }
    SecurityCounter counter = (SecurityCounter)dlsym(compat, "VM27DI2SecurityCallCount");
    if (!counter || !Identity(ptrauth_strip((void *)counter, ptrauth_key_function_pointer), &Images[SecurityIndex], 0, 0)) return 71;
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];
    int result = 72, initial = -1;
    char path[4096]; path[0] = 0;
    BOOL created = NO, cleaned = NO;
    @try {
        if (!CountersZero(counter, @"before")) goto cleanup;
        if (snprintf(path, sizeof(path), "%s/owned-raw-XXXXXX", OwnedDirectory) >= (int)sizeof(path)) goto cleanup;
        initial = mkstemp(path); if (initial < 0) goto cleanup; created = YES;
        if (fchmod(initial, 0600) || ftruncate(initial, 131072)) goto cleanup;
        struct stat originalStat;
        if (fstat(initial, &originalStat) || !S_ISREG(originalStat.st_mode) || originalStat.st_size != 131072) goto cleanup;
        Log(@{ @"record": @"ownedFile", @"path": [NSString stringWithUTF8String:path], @"bytes": @131072,
               @"device": @((uint64_t)originalStat.st_dev), @"inode": @((uint64_t)originalStat.st_ino), @"mode": @0600 });
        if (close(initial)) goto cleanup; initial = -1;
        result = OwnedCycle(classes[0], classes[1], path, &originalStat, NO);
        if (result) goto cleanup;
        result = OwnedCycle(classes[0], classes[1], path, &originalStat, YES);
        if (result) goto cleanup;
        result = MissingFileError(classes[0], path) ? 0 : 82;
        if (!CountersZero(counter, @"after")) result = 83;
    } @catch (NSException *exception) {
        Log(@{ @"record": @"exception", @"name": [exception name], @"reason": [exception reason] ?: @"" }); result = 84;
    }
cleanup:
    if (initial >= 0) close(initial); // Only the probe's own creation fd.
    if (created) {
        cleaned = unlink(path) == 0;
        if (!cleaned && !result) result = 85;
        Log(@{ @"record": @"cleanup", @"path": [NSString stringWithUTF8String:path], @"removed": @(cleaned) });
    }
    Log(@{ @"record": @"summary", @"PID": @(getpid()), @"exit": @(result), @"passed": result == 0 ? @YES : @NO,
           @"genuine27UUID": @"a456d4a4d6ab3549965d0400f3552de3", @"DI2APICalls": @(APICalls),
           @"originalOpenCalls": @(Opens), @"originalHandles": @(Handles), @"checks": @(checks),
           @"originalFDReads": @(fdReadCalls), @"originalFDWrites": @(fdWriteCalls),
           @"ownedRAWBytes": @131072, @"borrowedFDCloseCallsByProbe": @0, @"cleanupComplete": @(cleaned),
           @"attachCalls": @0, @"guestDiskCalls": @0, @"VMGPUCalls": @0, @"completeDI2OrVMMClaimed": @NO });
    [pool drain]; dlclose(compat); dlclose(library); alarm(0);
    return result;
}
