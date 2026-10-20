// Bounded own-allocation probe. Its five calls bind strongly to one private dylib.
// No VM, GPU, disk image, IPC, capability override or Apple object is exercised.
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <malloc/malloc.h>
#include <ptrauth.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include "allocator-full-five-pins.h"

extern void *ProbeMalloc(size_t, uint64_t) __asm("_malloc_type_malloc");
extern void *ProbeCalloc(size_t, size_t, uint64_t) __asm("_malloc_type_calloc");
extern void *ProbeRealloc(void *, size_t, uint64_t) __asm("_malloc_type_realloc");
extern int ProbePosix(void **, size_t, size_t, uint64_t) __asm("_malloc_type_posix_memalign");
extern void *ProbeZone(malloc_zone_t *, size_t, size_t, uint64_t,
    malloc_zone_malloc_options_t) __asm("_malloc_type_zone_malloc_with_options");

_Static_assert(sizeof(void *) == 8 && sizeof(size_t) == 8 && sizeof(malloc_type_id_t) == 8,
    "Audited Darwin LP64 ABI");
_Static_assert(sizeof(malloc_zone_malloc_options_t) == 8 &&
    MALLOC_ZONE_MALLOC_DEFAULT_ALIGN == 8 && MALLOC_ZONE_MALLOC_OPTION_CLEAR == 1 &&
    MALLOC_ZONE_MALLOC_OPTION_CANONICAL_TAG == 2, "Audited SDK options");

static const char *Names[5] = {"malloc_type_malloc", "malloc_type_calloc",
    "malloc_type_realloc", "malloc_type_posix_memalign", "malloc_type_zone_malloc_with_options"};
static unsigned Checks, Failures, Calls[5], Created, Released, Live, ZonesCreated, ZonesDestroyed;
static size_t RequestedBytes;
static const char *API = "identity", *Case = "initial";
static struct stat InitialFile;
static const void *ProviderBase;

static void Check(bool pass, const char *name) {
    ++Checks;
    if (!pass) ++Failures;
    printf("{\"record\":\"check\",\"id\":%u,\"api\":\"%s\",\"case\":\"%s\","
        "\"name\":\"%s\",\"passed\":%s}\n", Checks, API, Case, name, pass ? "true" : "false");
}

static bool SameStat(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_size == b->st_size &&
        a->st_uid == b->st_uid && a->st_gid == b->st_gid && a->st_mode == b->st_mode &&
        a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec &&
        a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
        a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec &&
        a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
}

static bool FileIdentity(const char *phase, bool first) {
    int fd = open(PinPath, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat a, b;
    bool ok = fstat(fd, &a) == 0 && S_ISREG(a.st_mode) && a.st_nlink == 1 &&
        a.st_uid == geteuid() && !(a.st_mode & 0022) && a.st_size == (off_t)PinBytes;
    CC_SHA256_CTX sha; unsigned char bytes[4096], digest[32]; size_t total = 0;
    if (!CC_SHA256_Init(&sha)) ok = false;
    while (ok) {
        ssize_t n = read(fd, bytes, sizeof(bytes));
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) { ok = false; break; }
        if (n == 0) break;
        if (total > PinBytes || (size_t)n > PinBytes - total) { ok = false; break; }
        total += (size_t)n;
        if (!CC_SHA256_Update(&sha, bytes, (CC_LONG)n)) ok = false;
    }
    if (ok) ok = fstat(fd, &b) == 0 && SameStat(&a, &b) && total == PinBytes;
    if (close(fd)) ok = false;
    char hex[65] = "";
    if (ok) {
        ok = CC_SHA256_Final(digest, &sha) != 0;
        for (unsigned i = 0; i < 32; ++i) (void)snprintf(hex + 2 * i, 3, "%02x", digest[i]);
        hex[64] = 0; ok = ok && !strcmp(hex, PinSHA);
    }
    if (ok && first) InitialFile = a;
    else if (ok) ok = SameStat(&a, &InitialFile);
    printf("{\"record\":\"file\",\"phase\":\"%s\",\"bytes\":%zu,\"sha256\":\"%s\","
        "\"exact\":%s,\"sameOriginalInodeMetadata\":%s}\n", phase, total, hex,
        ok ? "true" : "false", ok ? "true" : "false");
    return ok;
}

static bool HeaderIdentity(const void *base) {
    const struct mach_header_64 *h = base;
    if (!h || h->magic != MH_MAGIC_64 || (uint32_t)h->cputype != 0x0100000c ||
        (uint32_t)h->cpusubtype != PinSubtype || h->filetype != MH_DYLIB ||
        h->ncmds > 128 || h->sizeofcmds > 16384) return false;
    const unsigned char *commands = (const unsigned char *)(h + 1);
    size_t at = 0; unsigned uuidCount = 0, buildCount = 0;
    bool uuidOK = false, buildOK = false;
    for (unsigned i = 0; i < h->ncmds; ++i) {
        if (at > h->sizeofcmds || h->sizeofcmds - at < sizeof(struct load_command)) return false;
        struct load_command c; memcpy(&c, commands + at, sizeof(c));
        if (c.cmdsize < sizeof(c) || (c.cmdsize & 7) || c.cmdsize > h->sizeofcmds - at) return false;
        if (c.cmd == LC_UUID) {
            if (c.cmdsize != sizeof(struct uuid_command)) return false;
            ++uuidCount; uuidOK = !memcmp(commands + at + 8, PinUUID, 16);
        } else if (c.cmd == LC_BUILD_VERSION) {
            if (c.cmdsize < sizeof(struct build_version_command)) return false;
            struct build_version_command b; memcpy(&b, commands + at, sizeof(b));
            ++buildCount; buildOK = b.platform == PinPlatform && b.minos == PinMinOS && b.sdk == PinSDK;
        }
        at += c.cmdsize;
    }
    return at == h->sizeofcmds && uuidCount == 1 && buildCount == 1 && uuidOK && buildOK;
}

static bool LoadedIdentity(const char *phase) {
    void *entries[5] = {(void *)&ProbeMalloc, (void *)&ProbeCalloc, (void *)&ProbeRealloc,
        (void *)&ProbePosix, (void *)&ProbeZone};
    bool all = true;
    for (unsigned i = 0; i < 5; ++i) {
        void *entry = ptrauth_strip(entries[i], ptrauth_key_function_pointer);
        Dl_info d = {0}; struct stat loaded;
        bool ok = dladdr(entry, &d) && d.dli_fbase && d.dli_fname &&
            stat(d.dli_fname, &loaded) == 0 && SameStat(&InitialFile, &loaded) &&
            HeaderIdentity(d.dli_fbase) && (uintptr_t)entry >= (uintptr_t)d.dli_fbase &&
            (uintptr_t)entry - (uintptr_t)d.dli_fbase == PinRVAs[i];
        if (ok && ProviderBase && ProviderBase != d.dli_fbase) ok = false;
        if (ok) ProviderBase = d.dli_fbase;
        printf("{\"record\":\"binding\",\"phase\":\"%s\",\"symbol\":\"%s\","
            "\"rva\":%llu,\"uuid\":\"%s\",\"fileSHA256\":\"%s\",\"exact\":%s}\n",
            phase, Names[i], (unsigned long long)(d.dli_fbase ? (uintptr_t)entry -
            (uintptr_t)d.dli_fbase : 0), PinUUIDHex, PinSHA, ok ? "true" : "false");
        all = all && ok;
    }
    unsigned providerCount = 0, forbidden = 0;
    uint32_t images = _dyld_image_count();
    if (images > 4096) return false;
    for (uint32_t i = 0; i < images; ++i) {
        const char *name = _dyld_get_image_name(i);
        if (!name) return false;
        if ((const void *)_dyld_get_image_header(i) == ProviderBase) ++providerCount;
        if (strstr(name, "/Hypervisor.framework/") || strstr(name, "/Virtualization.framework/") ||
            strstr(name, "/Metal.framework/") || strstr(name, "/VideoToolbox.framework/")) ++forbidden;
    }
    all = all && providerCount == 1 && forbidden == 0 && _dyld_image_count() == images;
    printf("{\"record\":\"census\",\"phase\":\"%s\",\"imageCount\":%u,"
        "\"privateProviderImages\":%u,\"forbiddenFrameworks\":%u,\"exact\":%s}\n",
        phase, images, providerCount, forbidden, all ? "true" : "false");
    return all;
}

static bool Pattern(void *pointer, size_t size, unsigned seed, bool write) {
    if (!pointer || size > 8192 || !malloc_zone_from_ptr(pointer) || malloc_size(pointer) < size) return false;
    unsigned char *p = pointer;
    for (size_t i = 0; i < size; ++i) {
        unsigned char expected = (unsigned char)(seed + 29 * i + (i >> 3));
        if (write) p[i] = expected;
        else if (p[i] != expected) return false;
    }
    return true;
}

static bool Zero(void *pointer, size_t size) {
    if (!pointer || size > 8192 || !malloc_zone_from_ptr(pointer) || malloc_size(pointer) < size) return false;
    const unsigned char *p = pointer;
    for (size_t i = 0; i < size; ++i) if (p[i]) return false;
    return true;
}

static void Adopt(void *p, size_t bytes) {
    Check(bytes <= 8192 && RequestedBytes <= 65536 - bytes, "boundedRequestedStorage");
    RequestedBytes += bytes;
    if (p) { ++Created; ++Live; }
}

static void Release(void *p, malloc_zone_t *zone, bool custom) {
    if (!p) return;
    malloc_zone_t *owner = malloc_zone_from_ptr(p);
    Check(owner != NULL, "realAllocationOwner");
    if (custom) Check(owner == zone, "customZoneOwner");
    if (!owner) return; // Keep failed unknown ownership explicit; never guess a free.
    if (custom) malloc_zone_free(owner, p); else free(p);
    ++Released; if (Live) --Live; else Check(false, "liveAllocationUnderflow");
}

static void RunMalloc(uint64_t type) {
    API = Names[0]; Case = "nonzero-pattern";
    ++Calls[0]; void *p = ProbeMalloc(257, type); Adopt(p, 257);
    Check(p != NULL, "allocated"); Check(Pattern(p, 257, 17, true), "writePattern");
    Check(Pattern(p, 257, 17, false), "patternReadback"); Release(p, NULL, false);
    Case = "zero-size-observation";
    ++Calls[0]; p = ProbeMalloc(0, type); Adopt(p, 0);
    Check(!p || malloc_zone_from_ptr(p) != NULL, "zeroResultHasOwnerIfNonNull"); Release(p, NULL, false);
    Case = "overflow-failure"; errno = 0;
    ++Calls[0]; p = ProbeMalloc(SIZE_MAX, type); int saved = errno;
    Check(p == NULL, "oversizedNull"); Check(saved == ENOMEM, "oversizedENOMEM");
    if (p) { Adopt(p, 0); Release(p, NULL, false); }
}

static void RunCalloc(uint64_t type) {
    API = Names[1]; Case = "clear-and-pattern";
    ++Calls[1]; void *p = ProbeCalloc(7, 37, type); Adopt(p, 259);
    Check(p != NULL, "allocated"); Check(Zero(p, 259), "allRequestedBytesZero");
    Check(Pattern(p, 259, 23, true), "writePattern");
    Check(Pattern(p, 259, 23, false), "patternReadback"); Release(p, NULL, false);
    Case = "multiplication-overflow"; errno = 0;
    ++Calls[1]; p = ProbeCalloc(SIZE_MAX / 2 + 1, 2, type); int saved = errno;
    Check(p == NULL, "overflowNull"); Check(saved == ENOMEM, "overflowENOMEM");
    if (p) { Adopt(p, 0); Release(p, NULL, false); }
    Case = "zero-count-observation";
    ++Calls[1]; p = ProbeCalloc(0, 73, type); Adopt(p, 0);
    Check(!p || malloc_zone_from_ptr(p) != NULL, "zeroResultHasOwnerIfNonNull"); Release(p, NULL, false);
}

static void RunRealloc(uint64_t type) {
    API = Names[2]; Case = "null-input";
    ++Calls[2]; void *p = ProbeRealloc(NULL, 129, type); Adopt(p, 129);
    Check(p != NULL, "allocated"); Check(Pattern(p, 129, 41, true), "writePattern");
    if (!p) return;
    Case = "grow-preserves-prefix";
    ++Calls[2]; void *next = ProbeRealloc(p, 2049, type);
    Check(next != NULL, "growSucceeded");
    if (next) p = next;
    Check(Pattern(p, 129, 41, false), "oldPrefixPreserved");
    if (!next) { Release(p, NULL, false); return; }
    RequestedBytes += 2049;
    Check(Pattern(p, 2049, 59, true), "writeGrownPattern");
    Case = "shrink-preserves-prefix";
    ++Calls[2]; next = ProbeRealloc(p, 61, type);
    Check(next != NULL, "shrinkSucceeded");
    if (next) p = next;
    Check(Pattern(p, 61, 59, false), "shrinkPrefixPreserved");
    Case = "failure-preserves-input"; errno = 0;
    ++Calls[2]; next = ProbeRealloc(p, SIZE_MAX, type); int saved = errno;
    Check(next == NULL, "oversizedNull"); Check(saved == ENOMEM, "oversizedENOMEM");
    if (next) p = next;
    Check(Pattern(p, 61, 59, false), "failureOriginalDataPreserved"); Release(p, NULL, false);
}

static void RunPosix(uint64_t type) {
    API = Names[3]; Case = "legal-nonmultiple-size";
    void *p = NULL; ++Calls[3]; int rc = ProbePosix(&p, 4096, 257, type); Adopt(p, 257);
    Check(rc == 0 && p != NULL, "allocated"); Check(p && !((uintptr_t)p & 4095), "exactAlignment");
    Check(Pattern(p, 257, 71, true), "writePattern");
    Check(Pattern(p, 257, 71, false), "patternReadback"); Release(p, NULL, false);
    Case = "invalid-alignment";
    uintptr_t sentinel = (uintptr_t)0x17017; p = (void *)sentinel;
    ++Calls[3]; rc = ProbePosix(&p, 24, 64, type);
    Check(rc == EINVAL, "invalidReturnsEINVAL"); Check((uintptr_t)p == sentinel, "failureOutputUnchanged");
    if ((uintptr_t)p != sentinel && p) { Adopt(p, 0); Release(p, NULL, false); }
    Case = "oversized-failure"; p = (void *)sentinel;
    ++Calls[3]; rc = ProbePosix(&p, 64, SIZE_MAX, type);
    Check(rc == ENOMEM, "oversizedReturnsENOMEM"); Check((uintptr_t)p == sentinel, "failureOutputUnchanged");
    if ((uintptr_t)p != sentinel && p) { Adopt(p, 0); Release(p, NULL, false); }
}

static void RunZone(uint64_t type) {
    API = Names[4];
    malloc_zone_t *zone = malloc_create_zone(0, 0);
    Case = "owned-zone-lifetime"; Check(zone != NULL, "customZoneCreated");
    if (!zone) return;
    ++ZonesCreated;
    for (unsigned custom = 0; custom < 2; ++custom) {
        for (unsigned options = 0; options < 4; ++options) {
            Case = custom ? "custom-explicit-alignment" : "default-explicit-alignment";
            ++Calls[4]; void *p = ProbeZone(custom ? zone : NULL, 64, 256, type, options); Adopt(p, 256);
            Check(p != NULL, "allocated"); Check(p && !((uintptr_t)p & 63), "exactAlignment");
            if (options & 1) Check(Zero(p, 256), "clearBeforeWrite");
            if (options & 2) Check(p && ((uintptr_t)p >> 56) == 0, "realCanonicalUntaggedPointer");
            Check(Pattern(p, 256, 83 + options, true), "writePattern");
            Check(Pattern(p, 256, 83 + options, false), "patternReadback");
            Release(p, zone, custom != 0);
        }
    }
    Case = "default-alignment-nonmultiple-size";
    ++Calls[4]; void *p = ProbeZone(NULL, 8, 63, type, 1); Adopt(p, 63);
    Check(p != NULL, "allocated"); Check(Zero(p, 63), "clearBeforeWrite"); Release(p, NULL, false);
    Case = "invalid-alignment";
    ++Calls[4]; p = ProbeZone(zone, 24, 96, type, 0);
    Check(p == NULL, "invalidAlignmentNull"); if (p) { Adopt(p, 0); Release(p, zone, true); }
    Case = "explicit-nonmultiple-size";
    ++Calls[4]; p = ProbeZone(zone, 64, 63, type, 0);
    Check(p == NULL, "invalidSizeNull"); if (p) { Adopt(p, 0); Release(p, zone, true); }
    Case = "owned-zone-lifetime"; malloc_destroy_zone(zone); ++ZonesDestroyed;
    Check(Live == 0, "allZoneAllocationsReleasedBeforeDestroy");
}

int main(int argc, char **argv) {
    setbuf(stdout, NULL);
    struct rlimit cpu = {5, 5}, core = {0, 0};
    if (setrlimit(RLIMIT_CPU, &cpu) || setrlimit(RLIMIT_CORE, &core)) return 78;
    alarm(10);
    if (argc != 3 || strcmp(argv[1], "--library") || strcmp(argv[2], PinPath)) return 78;
    printf("{\"record\":\"start\",\"pid\":%d,\"target\":\"%s\",\"fiveStrongImports\":true,"
        "\"VMCalls\":0,\"GPUCalls\":0}\n", getpid(), PinTarget);
    bool file = FileIdentity("before", true); Check(file, "fileBeforeExact");
    bool loaded = file && LoadedIdentity("before"); Check(loaded, "fiveLoadedBindingsBeforeExact");
    if (file && loaded) {
        const uint64_t types[2] = {0, UINT64_C(0xfedcba9876543210)};
        for (unsigned i = 0; i < 2; ++i) {
            RunMalloc(types[i]); RunCalloc(types[i]); RunRealloc(types[i]);
            RunPosix(types[i]); RunZone(types[i]);
        }
    }
    API = "identity"; Case = "final";
    Check(Live == 0 && Created == Released, "allOwnAllocationsReleased");
    Check(ZonesCreated == 2 && ZonesCreated == ZonesDestroyed, "allCustomZonesDestroyed");
    Check(RequestedBytes <= 65536, "totalRequestedStorageBound");
    Check(FileIdentity("after", false), "fileAfterExact");
    Check(loaded && LoadedIdentity("after"), "fiveLoadedBindingsAfterExact");
    printf("{\"record\":\"summary\",\"pid\":%d,\"checks\":%u,\"failures\":%u,"
        "\"calls\":[%u,%u,%u,%u,%u],\"created\":%u,\"released\":%u,\"live\":%u,"
        "\"zonesCreated\":%u,\"zonesDestroyed\":%u,\"requestedBytes\":%zu,"
        "\"allFiveSemanticsPassed\":%s,\"unknownOptionsTrapTested\":false,"
        "\"typedTelemetryImplemented\":false,\"full27VMMProved\":false}\n",
        getpid(), Checks, Failures, Calls[0], Calls[1], Calls[2], Calls[3], Calls[4], Created,
        Released, Live, ZonesCreated, ZonesDestroyed, RequestedBytes,
        Failures == 0 ? "true" : "false");
    alarm(0); return Failures ? 83 : 0;
}
