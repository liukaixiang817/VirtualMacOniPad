#define _DARWIN_C_SOURCE 1
#include "vm27_owned_vz_cache_confstr_v1.h"
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>

/* A named parent-only API, never a global libc interposer. Deployment must
 * first create the two owned directories. No creation, chmod or cache content
 * writes occur in this adapter. The original VZ caller owns later cache use. */
#define VM27_CACHE_PATH "/private/var/mobile/Library/VirtualMacIndependent27Cache-v1/virtualization/"
#define VM27_APP_MAIN "/private/preboot/3BAC96003F990D2A2530F3FB8BF9293399970140D40FBF3A5A9A6CCCCF018C0C30F94334FCD17DF3DC7434C1EA34FC3E/dopamine-FUG16w/procursus/Applications/VirtualMacIndependent27.app/VirtualMacIndependent27"
#define VM27_PARENT_VZ "/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/parent-flat/VZ27.dylib"
extern int csops(pid_t, unsigned int, void *, size_t);

static bool CacheImageUUIDV1(const void *image, const uint8_t expected[16]) {
    if (!image) return false;
    const struct mach_header_64 *header = image;
    if (header->magic != MH_MAGIC_64 || !header->ncmds ||
        header->ncmds > 2048 || header->sizeofcmds > 65536) return false;
    const uint8_t *at = (const uint8_t *)(header + 1);
    const uint8_t *end = at + header->sizeofcmds;
    unsigned matches = 0;
    for (uint32_t i = 0; i < header->ncmds; ++i) {
        if ((size_t)(end-at) < sizeof(struct load_command)) return false;
        const struct load_command *command = (const struct load_command *)at;
        if (command->cmdsize < 8 || (command->cmdsize & 7) ||
            command->cmdsize > (size_t)(end-at)) return false;
        if (command->cmd == LC_UUID) {
            if (command->cmdsize != sizeof(struct uuid_command) || ++matches != 1 ||
                memcmp(((const struct uuid_command *)command)->uuid, expected, 16)) return false;
        }
        at += command->cmdsize;
    }
    return at == end && matches == 1;
}

static bool CacheParentEligibleV1(void *caller) {
    static const uint8_t vzUUID[16] = {
        0x41,0x8e,0xfc,0x48,0x09,0xd9,0x36,0x06,0x91,0x8e,0xb6,0xf9,0x5b,0xae,0xff,0xdc};
    static const uint8_t libcUUID[16] = {
        0xda,0xd0,0xce,0x08,0x8f,0x35,0x3f,0xf4,0x89,0x9e,0x43,0xdc,0x44,0xeb,0x65,0xa7};
    if (getuid() != 501 || geteuid() != 501 || getpid() <= 1) {
        fprintf(stderr, "[VM27OwnedCacheV1] admission=0 stage=uid pid=%d uid=%u euid=%u\n",
            (int)getpid(), (unsigned)getuid(), (unsigned)geteuid()); return false;
    }
    uint32_t status = 0;
    int codeResult = csops(getpid(), 0, &status, sizeof(status));
    if (codeResult || (status & UINT32_C(0x04000001)) != UINT32_C(0x04000001)) {
        fprintf(stderr, "[VM27OwnedCacheV1] admission=0 stage=code-status result=%d status=%08x errno=%d\n",
            codeResult, status, errno); return false;
    }
    char executable[4096], canonical[4096];
    uint32_t capacity = sizeof(executable);
    if (_NSGetExecutablePath(executable, &capacity)) {
        fprintf(stderr, "[VM27OwnedCacheV1] admission=0 stage=app-path-capacity required=%u\n", capacity); return false;
    }
    if (!realpath(executable, canonical)) {
        fprintf(stderr, "[VM27OwnedCacheV1] admission=0 stage=app-path-realpath errno=%d\n", errno); return false;
    }
    if (strcmp(canonical, VM27_APP_MAIN)) {
        fprintf(stderr, "[VM27OwnedCacheV1] admission=0 stage=app-path-mismatch actual=%s\n", canonical); return false;
    }
    Dl_info owner = {0}, native = {0};
    if (!caller || !dladdr(caller, &owner) || !owner.dli_fname ||
        strcmp(owner.dli_fname, VM27_PARENT_VZ) || !CacheImageUUIDV1(owner.dli_fbase, vzUUID)) {
        fprintf(stderr, "[VM27OwnedCacheV1] admission=0 stage=parent-owner caller=%p path=%s base=%p\n",
            caller, owner.dli_fname ? owner.dli_fname : "(none)", owner.dli_fbase); return false;
    }
    void *rawNative = ptrauth_strip((void *)&confstr, ptrauth_key_function_pointer);
    if (!dladdr(rawNative, &native) || !native.dli_fname ||
        strcmp(native.dli_fname, "/usr/lib/system/libsystem_c.dylib") ||
        !CacheImageUUIDV1(native.dli_fbase, libcUUID) ||
        (uintptr_t)rawNative-(uintptr_t)native.dli_fbase != (uintptr_t)UINT64_C(0x1421c)) {
        fprintf(stderr, "[VM27OwnedCacheV1] admission=0 stage=native-owner function=%p path=%s base=%p\n",
            rawNative, native.dli_fname ? native.dli_fname : "(none)", native.dli_fbase); return false;
    }
    return true;
}

static bool CacheDirectoryStatV1(int fd, uid_t owner, bool privateDirectory) {
    struct stat value;
    if (fd < 0 || fstat(fd, &value)) return false;
    if (!S_ISDIR(value.st_mode) || value.st_uid != owner ||
        (privateDirectory && (value.st_gid != 501 || (value.st_mode & 07777) != 0700)) ||
        (!privateDirectory && (value.st_mode & 0022))) {
        fprintf(stderr, "[VM27OwnedCacheV1] directory=0 stage=directory-fields uid=%u gid=%u mode=%04o expectedUID=%u private=%u\n",
            (unsigned)value.st_uid, (unsigned)value.st_gid, (unsigned)(value.st_mode & 07777),
            (unsigned)owner, privateDirectory ? 1U : 0U);
        errno = EACCES;
        return false;
    }
    return true;
}

static bool CacheOpenCheckedComponentV1(int *fd, const char *component,
    uid_t owner, bool privateDirectory) {
    int next = openat(*fd, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int outcome = errno;
    if (next < 0)
        fprintf(stderr, "[VM27OwnedCacheV1] directory=0 stage=component-open component=%s errno=%d\n", component, outcome);
    if (close(*fd)) {
        outcome = errno;
        if (next >= 0) (void)close(next);
        *fd = -1; errno = outcome; return false;
    }
    *fd = next; errno = outcome;
    bool valid = CacheDirectoryStatV1(next, owner, privateDirectory);
    if (!valid && next >= 0) {
        int reason = errno;
        fprintf(stderr, "[VM27OwnedCacheV1] directory=0 stage=component-stat component=%s expectedUID=%u private=%u errno=%d\n",
            component, (unsigned)owner, privateDirectory ? 1U : 0U, reason);
        errno = reason;
    }
    return valid;
}

static bool CacheActualDirectoryV1(void) {
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    bool valid = CacheDirectoryStatV1(fd, 0, false);
    const char *components[] = {"private", "var", "mobile", "Library",
        "VirtualMacIndependent27Cache-v1", "virtualization"};
    for (size_t i = 0; valid && i < sizeof(components)/sizeof(components[0]); ++i)
        valid = CacheOpenCheckedComponentV1(&fd, components[i], i < 2 ? 0 : 501, i >= 4);
    int outcome = errno;
    if (fd >= 0 && close(fd)) {outcome = errno; valid = false;}
    errno = outcome;
    return valid;
}

typedef size_t (*CacheNativeConfstrV1)(int, char *, size_t);
typedef bool (*CacheEligibleV1)(void *);
typedef bool (*CacheDirectoryV1)(void);

static size_t CacheCoreV1(int name, char *buffer, size_t capacity,
    CacheNativeConfstrV1 native, CacheEligibleV1 eligible, void *caller,
    CacheDirectoryV1 directory) {
    int incomingErrno = errno;
    size_t result = native(name, buffer, capacity);
    int nativeErrno = errno;
    if (name != _CS_DARWIN_USER_CACHE_DIR || result != 0) {
        errno = nativeErrno; return result;
    }
    if (!eligible(caller)) {errno = nativeErrno; return 0;}
    if (!directory()) {
        int directoryErrno = errno ? errno : EACCES;
        fprintf(stderr, "[VM27OwnedCacheV1] nativeResult=0 nativeErrno=%d ownDirectoryValid=0 directoryErrno=%d\n",
            nativeErrno, directoryErrno);
        errno = directoryErrno; return 0;
    }
    /* POSIX required length includes NUL; copy at most capacity-1 bytes and
     * always terminate a nonempty supplied buffer. NULL/zero are size queries. */
    static const char path[] = VM27_CACHE_PATH;
    size_t required = sizeof(path);
    if (buffer && capacity) {
        size_t copy = required-1;
        if (copy >= capacity) copy = capacity-1;
        if (copy) memcpy(buffer, path, copy);
        buffer[copy] = '\0';
    }
    fprintf(stderr, "[VM27OwnedCacheV1] nativeResult=0 nativeErrno=%d ownDirectoryValid=1 required=%zu backend=owned-parent-cache path=%s\n",
        nativeErrno, required, path);
    errno = incomingErrno;
    return required;
}

size_t VM27OwnedVZCacheConfstrV1(int name, char *buffer, size_t capacity) {
    void *caller = ptrauth_strip(__builtin_return_address(0), ptrauth_key_return_address);
    return CacheCoreV1(name, buffer, capacity, &confstr,
        &CacheParentEligibleV1, caller, &CacheActualDirectoryV1);
}
