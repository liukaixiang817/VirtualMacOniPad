// Native VZ integration of the supplied Henge software-identity semantics.
// It changes only a VM explicitly bound to this App's private identity handoff.
#include "VMAppleAccountRuntimeV1.h"
#include "VMAppleAccountSysctlBlobsV1.h"
#include "reference/legacy_dtree.h"
#include "reference/legacy_vmm.h"
#include <CommonCrypto/CommonDigest.h>
#include <errno.h>
#include <fcntl.h>
#include <libkern/OSCacheControl.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef VM_APPLE_ACCOUNT_OBSERVE_ONLY
#define VM_APPLE_ACCOUNT_OBSERVE_ONLY 0
#endif
#ifndef VM_APPLE_ACCOUNT_TREE_ONLY
#define VM_APPLE_ACCOUNT_TREE_ONLY 0
#endif

typedef struct {
    const char *build, *version;
    uint64_t versionDelta, originalHandler, padding, textStart, textBytes;
    unsigned procComm;
} AccountKernelV1;
static const AccountKernelV1 Kernels[] = {
    {"24G90", "Darwin Kernel Version 24.6.0: Mon Jul 14 11:30:18 PDT 2025; root:xnu-11417.140.69~1/RELEASE_ARM64_VMAPPLE",
     0x138e9c3, 0xfffffe00083d2d20, 0xfffffe0007d81380, 0xfffffe0007d7c000, 0x8ec000, 0x5cc},
    {"25G83", "Darwin Kernel Version 25.6.0: Fri Jul 31 19:16:43 PDT 2026; root:xnu-12377.161.14~5/RELEASE_ARM64_VMAPPLE",
     0x325715f, 0xfffffe000a29b0d4, 0xfffffe0009c18490, 0xfffffe0009c0c000, 0x94c000, 0x5cc},
    {"26A5416b", "Darwin Kernel Version 27.0.0: Tue Aug 11 22:03:18 PDT 2026; root:xnu-13432.1.9~3/RELEASE_ARM64_VMAPPLE",
     0x34c0e7f, 0xfffffe000a501a1c, 0xfffffe0009e4c490, 0xfffffe0009e44000, 0x98c000, 0x5bc},
    {"26B123", "Darwin Kernel Version 27.2.0: Wed Oct 14 23:44:09 PDT 2026; root:xnu-13432.41.4~25/RELEASE_ARM64_VMAPPLE",
     0x354895f, 0xfffffe000a58961c, 0xfffffe0009ed0490, 0xfffffe0009ec8000, 0x990000, 0x5bc},
    // The actual 26B131 VM kernel's complete __text is byte-identical to 26B123.
    {"26B131", "Darwin Kernel Version 27.2.0: Wed Oct 14 23:44:09 PDT 2026; root:xnu-13432.41.4~25/RELEASE_ARM64_VMAPPLE",
     0x354895f, 0xfffffe000a58961c, 0xfffffe0009ed0490, 0xfffffe0009ec8000, 0x990000, 0x5bc},
};
static VMAppleAccountHandoffV1 Identity;
static const AccountKernelV1 *Kernel;
static pthread_once_t InitializeOnce = PTHREAD_ONCE_INIT;
static bool Enabled;
static unsigned KernelFinished, KernelAttempts;
static uint64_t FirstCPU;
typedef struct { uint8_t *host; uint64_t ipa, flags; size_t bytes; } AccountMapV1;
static AccountMapV1 Maps[64];
static size_t MapCount;
static bool MapsInvalid;
static pthread_mutex_t MapLock = PTHREAD_MUTEX_INITIALIZER;

static bool terminated(const char *value, size_t capacity) {
    return memchr(value, 0, capacity) != NULL;
}
static bool readOwned(const char *path, void *out, size_t size, bool exact) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat st;
    bool good = !fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
        st.st_nlink == 1 && !(st.st_mode & 0022) && st.st_size > 0 &&
        (exact ? (uint64_t)st.st_size == size : (uint64_t)st.st_size <= size);
    size_t at = 0, total = good ? (size_t)st.st_size : 0;
    while (good && at < total) {
        ssize_t n = read(fd, (uint8_t *)out + at, total - at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { good = false; break; }
        at += (size_t)n;
    }
    close(fd);
    return good;
}
static bool verifyNativeFile(const char *name, const uint8_t expected[32]) {
    char path[1200];
    int length = snprintf(path, sizeof(path), "%s/%s", Identity.bundlePath, name);
    if (length < 0 || (size_t)length >= sizeof(path)) return false;
    uint8_t data[1024] = {0}, digest[32];
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat st;
    bool good = !fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_uid == geteuid() &&
        st.st_nlink == 1 && !(st.st_mode & 0022) && st.st_size >= 16 && st.st_size <= 1024;
    if (good) {
        ssize_t count = read(fd, data, (size_t)st.st_size);
        good = count == st.st_size;
        if (good) {
            CC_SHA256(data, (CC_LONG)count, digest);
            good = !memcmp(digest, expected, 32);
        }
    }
    close(fd);
    return good;
}
static void initialize(void) {
    if (VM_APPLE_ACCOUNT_OBSERVE_ONLY) return;
    const char *folder = "/var/mobile/Library/VirtualMacAppleAccountV1";
    struct stat st;
    if (lstat(folder, &st) || !S_ISDIR(st.st_mode) || st.st_uid != geteuid() || (st.st_mode & 0077)) return;
    VMAppleAccountHandoffV1 candidate = {0};
    if (!readOwned("/var/mobile/Library/VirtualMacAppleAccountV1/Active.handoff", &candidate, sizeof(candidate), true)) return;
    if (memcmp(candidate.magic, "VMAID001", 8) || candidate.schema != 1 || candidate.appPID != (uint32_t)getppid()) return;
    if (!terminated(candidate.build, sizeof(candidate.build)) ||
        !terminated(candidate.serial, sizeof(candidate.serial)) ||
        !terminated(candidate.mlb, sizeof(candidate.mlb)) ||
        !terminated(candidate.model, sizeof(candidate.model)) ||
        !terminated(candidate.bundlePath, sizeof(candidate.bundlePath))) return;
    if (strlen(candidate.serial) != 12 || !hv_legacy_mlb_valid(candidate.mlb) ||
        strcmp(candidate.model, "Macmini8,1") ||
        (strncmp(candidate.bundlePath, "/var/mobile/Media/VirtualMac/", sizeof("/var/mobile/Media/VirtualMac/") - 1) &&
         strncmp(candidate.bundlePath, "/private/var/mobile/Media/VirtualMac/", sizeof("/private/var/mobile/Media/VirtualMac/") - 1))) return;
    for (size_t i = 0; i < sizeof(Kernels) / sizeof(Kernels[0]); ++i)
        if (!strcmp(Kernels[i].build, candidate.build)) Kernel = &Kernels[i];
    Identity = candidate;
    if (!verifyNativeFile("MachineIdentifier", Identity.machineSHA256) ||
        !verifyNativeFile("HardwareModel", Identity.hardwareSHA256)) return;
    Enabled = true;
    dprintf(2, "[AppleAccountV1] bound software identity accepted build=%s kernelPolicyAudited=%u identifiersLogged=0\n",
        Identity.build, Kernel != NULL);
}
bool VMAppleAccountBeforeRunV1(void) {
    pthread_once(&InitializeOnce, initialize);
    return Enabled;
}
void VMAppleAccountRecordFirstCPUV1(uint64_t cpu) {
    if (!VMAppleAccountBeforeRunV1() || !cpu) return;
    uint64_t expected = 0;
    (void)__atomic_compare_exchange_n(&FirstCPU, &expected, cpu, false, __ATOMIC_RELEASE, __ATOMIC_RELAXED);
}
void VMAppleAccountCPUResetV1(uint64_t cpu, uint64_t pc) {
    if (!Enabled || cpu != __atomic_load_n(&FirstCPU, __ATOMIC_ACQUIRE) || pc >= UINT64_C(0x100000000) ||
        !__atomic_load_n(&KernelFinished, __ATOMIC_ACQUIRE)) return;
    // KcgenOS and MainOS may run sequentially in one VMM. The genuine VMM's
    // successful primary-PC write back into physical ROM is the reset event;
    // resetting only on App relaunch loses the MainOS identity and policy.
    __atomic_store_n(&KernelAttempts, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&KernelFinished, 0, __ATOMIC_RELEASE);
    dprintf(2, "[AppleAccountV1] primary guest reset rearmed the same identity\n");
}
bool VMAppleAccountKernelPendingV1(void) {
    return (VM_APPLE_ACCOUNT_OBSERVE_ONLY || (VMAppleAccountBeforeRunV1() && Kernel != NULL)) &&
        !__atomic_load_n(&KernelFinished, __ATOMIC_ACQUIRE);
}
// Reflect successful native map operations, including the teardown/remap used
// by KcgenOS -> MainOS. Keeping a stale host allocation makes physical reads
// ambiguous and can dereference memory that the native VMM has already freed.
static void changeMappings(uint64_t ipa, size_t bytes, bool protect, uint64_t flags) {
    AccountMapV1 next[64];
    size_t count = 0;
    uint64_t end = ipa + bytes;
    for (size_t i = 0; i < MapCount; ++i) {
        AccountMapV1 m = Maps[i];
        uint64_t mEnd = m.ipa + m.bytes;
        AccountMapV1 pieces[3];
        size_t n = 0;
        if (mEnd <= ipa || m.ipa >= end) pieces[n++] = m;
        else {
            uint64_t lo = m.ipa > ipa ? m.ipa : ipa, hi = mEnd < end ? mEnd : end;
            if (m.ipa < lo) pieces[n++] = (AccountMapV1){m.host, m.ipa, m.flags, (size_t)(lo - m.ipa)};
            if (protect) pieces[n++] = (AccountMapV1){m.host + lo - m.ipa, lo, flags, (size_t)(hi - lo)};
            if (hi < mEnd) pieces[n++] = (AccountMapV1){m.host + hi - m.ipa, hi, m.flags, (size_t)(mEnd - hi)};
        }
        if (n > 64 - count) { MapsInvalid = true; return; }
        memcpy(next + count, pieces, n * sizeof(*pieces));
        count += n;
    }
    memcpy(Maps, next, count * sizeof(*Maps));
    MapCount = count;
}
void VMAppleAccountRecordMapV1(void *host, uint64_t ipa, size_t bytes, uint64_t flags) {
    if (!host || !bytes || ipa > UINT64_MAX - bytes) return;
    pthread_mutex_lock(&MapLock);
    changeMappings(ipa, bytes, false, 0);
    if (MapCount < sizeof(Maps) / sizeof(Maps[0])) Maps[MapCount++] = (AccountMapV1){host, ipa, flags, bytes};
    else MapsInvalid = true;
    pthread_mutex_unlock(&MapLock);
}
void VMAppleAccountRecordUnmapV1(uint64_t ipa, size_t bytes) {
    if (!bytes || ipa > UINT64_MAX - bytes) return;
    pthread_mutex_lock(&MapLock);
    changeMappings(ipa, bytes, false, 0);
    pthread_mutex_unlock(&MapLock);
}
void VMAppleAccountRecordProtectV1(uint64_t ipa, size_t bytes, uint64_t flags) {
    if (!bytes || ipa > UINT64_MAX - bytes) return;
    pthread_mutex_lock(&MapLock);
    changeMappings(ipa, bytes, true, flags);
    pthread_mutex_unlock(&MapLock);
}
bool VMAppleAccountOverrideConfigReadV1(uint64_t address, uint32_t syndrome, uint64_t original, uint64_t *out) {
    (void)original;
    if (!Enabled || !out || address < 0x400000 || address >= 0x401000 ||
        (syndrome >> 26) != 0x24 || !(syndrome & (1u << 24)) || (syndrome & (1u << 6))) return false;
    size_t bytes = (size_t)1 << ((syndrome >> 22) & 3), offset = (size_t)(address - 0x400000);
    const uint8_t *source = NULL;
    if (offset >= 0x500 && offset < 0x520 && bytes <= 0x520 - offset)
        source = (const uint8_t *)Identity.serial + offset - 0x500;
    else if (offset >= 0x540 && offset < 0x560 && bytes <= 0x560 - offset)
        source = (const uint8_t *)Identity.model + offset - 0x540;
    else if (offset >= 0x40 && offset < 0x60 && bytes <= 8 - (offset & 7))
        source = Identity.mac[(offset - 0x40) / 8] + (offset & 7);
    if (!source) return false;
    uint64_t value = 0;
    memcpy(&value, source, bytes);
    if ((syndrome & (1u << 21)) && bytes < 8 && (value & (UINT64_C(1) << (bytes * 8 - 1))))
        value |= ~((UINT64_C(1) << (bytes * 8)) - 1);
    if (!(syndrome & (1u << 15))) value = (uint32_t)value;
    *out = value;
    return true;
}

// MapLock must be held. Each returned range is one real mapped host allocation;
// pointers into unrelated VMM objects, unmapped ranges and ROM writes are refused.
static uint8_t *physical(uint64_t ipa, size_t size, bool write) {
    if (MapsInvalid) return NULL;
    uint8_t *result = NULL;
    for (size_t i = 0; i < MapCount; ++i) {
        AccountMapV1 *m = &Maps[i];
        if (ipa < m->ipa || size > m->bytes || ipa - m->ipa > m->bytes - size || (write && !(m->flags & 2))) continue;
        if (result) return NULL;
        result = m->host + (ipa - m->ipa);
    }
    return result;
}
typedef struct {
    uint64_t virtBase, physBase, pc, pcPA, tcr, ttbr1;
    uint8_t *tree;
    size_t treeSize;
} AccountBootV1;
static uint8_t *virtual(const AccountBootV1 *, uint64_t, size_t, bool);
static bool bootAt(uint64_t address, uint64_t ramBase, uint64_t ramSize, AccountBootV1 *boot) {
    const uint8_t *args = address >> 40 == 0xfffffe ? virtual(boot, address, 112, false) : physical(address, 112, false);
    if (!args) return false;
    uint64_t treePA;
    size_t treeSize;
    HvLegacyDTFields fields;
    if (!hv_legacy_dt_boot_args(args, 112, ramBase, ramSize, &treePA, &treeSize)) return false;
    uint8_t *tree = physical(treePA, treeSize, true);
    if (!tree || !hv_legacy_dt_fields(tree, treeSize, &fields)) return false;
    memcpy(&boot->virtBase, args + 8, 8);
    memcpy(&boot->physBase, args + 16, 8);
    boot->tree = tree;
    boot->treeSize = treeSize;
    return true;
}
static bool translate(const AccountBootV1 *boot, uint64_t address, uint64_t *result, bool instruction) {
    // Same non-LPA2 16KiB kernel TCR admitted by the existing native CPU
    // VM27RunDiagnosticVirtualReadV37. boot_args describes a separate physical
    // map alias; it must not be mistaken for the executable kernel mapping.
    if (boot->tcr != UINT64_C(0x000800226511a511) || address >> 47 != UINT64_C(0x1ffff)) return false;
    const uint64_t mask = UINT64_C(0x0000ffffffffc000);
    uint64_t table = boot->ttbr1 & mask;
    bool executeNever = false;
    for (unsigned level = 1; level <= 3; ++level) {
        unsigned shift = 14 + 11 * (3 - level);
        uint64_t index = address >> shift & 2047;
        uint8_t *p = physical(table + index * 8, 8, false);
        uint64_t descriptor;
        if (!p) return false;
        memcpy(&descriptor, p, 8);
        if (descriptor & 0x3000) return false;
        unsigned type = (unsigned)(descriptor & 3);
        uint64_t output = descriptor & mask;
        if (level < 3 && type == 3) {
            executeNever |= (descriptor & (UINT64_C(1) << 59)) != 0;
            table = output;
            continue;
        }
        if (!((level == 2 && type == 1) || (level == 3 && type == 3)) || !(descriptor & (UINT64_C(1) << 10))) return false;
        uint64_t low = (UINT64_C(1) << shift) - 1;
        if (output & low) return false;
        if (instruction && (executeNever || (descriptor & (UINT64_C(1) << 53)))) return false;
        *result = output | (address & low);
        return true;
    }
    return false;
}
static uint8_t *virtualAccess(const AccountBootV1 *boot, uint64_t address, size_t size, bool write, bool instruction) {
    if (!size || address > UINT64_MAX - size) return NULL;
    uint64_t first, last;
    if (!translate(boot, address, &first, instruction) || !translate(boot, address + size - 1, &last, instruction) ||
        last < first || last - first != size - 1) return NULL;
    return physical(first, size, write);
}
static uint8_t *virtual(const AccountBootV1 *boot, uint64_t address, size_t size, bool write) {
    return virtualAccess(boot, address, size, write, false);
}
static bool findBoot(const uint64_t registers[31], AccountBootV1 *boot) {
    uint64_t base = UINT64_MAX, end = 0;
    for (size_t i = 0; i < MapCount; ++i) {
        AccountMapV1 *m = &Maps[i];
        if (!(m->flags & 2) || m->bytes < 0x100000 || m->ipa < 0x10000000) continue;
        if (m->ipa < base) base = m->ipa;
        if (m->ipa + m->bytes > end) end = m->ipa + m->bytes;
    }
    if (base >= end) return false;
    for (unsigned i = 0; i < 31; ++i)
        if (bootAt(registers[i], base, end - base, boot)) return true;
    // Match only page-aligned boot_args as in the reference, and only within
    // the first1GiB. A second distinct active-looking tree is ambiguous.
    bool found = false;
    uint64_t limit = end - base < 0x40000000 ? end : base + 0x40000000;
    for (uint64_t at = base; at + 112 <= limit; at += 0x4000) {
        AccountBootV1 candidate = *boot;
        if (!bootAt(at, base, end - base, &candidate)) continue;
        if (found && candidate.tree != boot->tree) return false;
        *boot = candidate;
        found = true;
    }
    return found;
}
static bool branch(uint64_t from, uint64_t to, uint32_t *word) {
    int64_t delta = (int64_t)(to - from);
    if ((delta & 3) || delta < -0x8000000 || delta >= 0x8000000) return false;
    *word = 0x14000000 | ((uint32_t)(delta / 4) & 0x3ffffff);
    return true;
}
static bool installPolicy(const AccountBootV1 *boot) {
    static const uint32_t prefix[] = {0xd503237f, 0xd100c3ff, 0xa9014ff4,
        0xa9027bfd, 0x910083fd, 0xaa0303f3, 0xb9000fff};
    uint64_t handlerVA = 0;
    uint8_t *handler = NULL;
    unsigned matches = 0;
    for (size_t i = 0; i < MapCount; ++i) {
        AccountMapV1 *m = &Maps[i];
        if (!(m->flags & 2) || m->bytes < sizeof(prefix) || m->ipa < 0x10000000) continue;
        size_t bytes = m->bytes < 0x40000000 ? m->bytes : 0x40000000;
        const uint8_t *at = m->host, *end = m->host + bytes;
        while ((size_t)(end - at) >= 104) {
            uint8_t *p = memmem(at, (size_t)(end - at), prefix, sizeof(prefix));
            if (!p) break;
            at = p + 4;
            if (!hv_legacy_vmm_match(p, (size_t)(end - p))) continue;
            uint64_t pa = m->ipa + (uint64_t)(p - m->host);
            uint64_t va = boot->pc + pa - boot->pcPA;
            if (virtualAccess(boot, va, 104, false, true) != p) continue;
            uint64_t slide = va - Kernel->originalHandler;
            uint64_t liveText = Kernel->textStart + slide;
            // iBoot can retain a second complete decoded KC in RAM. Its broad
            // early mappings may still be executable. Only the image whose
            // independently audited kernel text contains the executing PC is
            // eligible; byte-identical staging copies are never patched.
            if (boot->pc < liveText || boot->pc - liveText >= Kernel->textBytes) continue;
            if (va < Kernel->versionDelta) continue;
            const uint8_t *version = virtual(boot, va - Kernel->versionDelta, strlen(Kernel->version) + 1, false);
            if (!version || memcmp(version, Kernel->version, strlen(Kernel->version) + 1)) continue;
            uint32_t adrp, add;
            memcpy(&adrp, p + 28, 4); memcpy(&add, p + 32, 4);
            int64_t imm = ((adrp >> 5 & 0x7ffff) << 2) | (adrp >> 29 & 3);
            if (imm & (1 << 20)) imm -= 1 << 21;
            uint64_t key = ((va + 28) & ~UINT64_C(0xfff)) + imm * 4096 + (add >> 10 & 0xfff);
            uint8_t *name = virtual(boot, key, 12, false);
            if (!name || memcmp(name, "vmm-present", 12)) continue;
            handlerVA = va; handler = p; ++matches;
        }
    }
    if (matches != 1 || !handler) {
        dprintf(2, "[AppleAccountV1] no unique verified live kernel handler matches=%u\n", matches);
        return false;
    }
    uint64_t paddingVA = Kernel->padding + handlerVA - Kernel->originalHandler;
    const uint8_t *source = Kernel->procComm == 0x5cc ? VMAppleAccountSysctlProc5CCV1 : VMAppleAccountSysctlProc5BCV1;
    size_t bytes = sizeof(VMAppleAccountSysctlProc5CCV1);
    unsigned returnOffset = VMAppleAccountSysctlProc5CCReturnV1;
    if (sizeof(VMAppleAccountSysctlProc5BCV1) != bytes || VMAppleAccountSysctlProc5BCReturnV1 != returnOffset) return false;
    uint8_t *padding = virtualAccess(boot, paddingVA, bytes, true, true);
    if (!padding) return false;
    for (size_t i = 0; i < bytes; ++i) if (padding[i]) return false;
    uint32_t enter, leave;
    if (!branch(handlerVA + 56, paddingVA, &enter) ||
        !branch(paddingVA + returnOffset, handlerVA + 60, &leave)) return false;
    uint8_t code[sizeof(VMAppleAccountSysctlProc5CCV1)];
    memcpy(code, source, bytes); memcpy(code + returnOffset, &leave, 4);
    memcpy(padding, code, bytes);
    sys_icache_invalidate(padding, bytes);
    if (memcmp(padding, code, bytes)) return false;
    __atomic_store_n((uint32_t *)(handler + 56), enter, __ATOMIC_RELEASE);
    sys_icache_invalidate(handler + 56, 4);
    return true;
}
int VMAppleAccountEarlyKernelV1(uint64_t pc, const uint64_t registers[31], uint64_t tcr, uint64_t ttbr1) {
    if (!VMAppleAccountKernelPendingV1() || pc >> 40 != 0xfffffe) return 0;
    unsigned attempt = __atomic_fetch_add(&KernelAttempts, 1, __ATOMIC_RELAXED);
    if (attempt >= 8) return Enabled ? -1 : 0;
    pthread_mutex_lock(&MapLock);
    if (__atomic_load_n(&KernelFinished, __ATOMIC_ACQUIRE)) {
        pthread_mutex_unlock(&MapLock);
        return 0;
    }
    AccountBootV1 boot = {.tcr=tcr, .ttbr1=ttbr1};
    bool found = findBoot(registers, &boot);
    dprintf(2, "[AppleAccountV1] early native kernel boundary ordinal=%u bootArgsAndRootTreeVerified=%u observeOnly=%u\n",
            attempt + 1, found, VM_APPLE_ACCOUNT_OBSERVE_ONLY);
    int result = 0;
    if (found && VM_APPLE_ACCOUNT_OBSERVE_ONLY) {
        __atomic_store_n(&KernelFinished, 1, __ATOMIC_RELEASE);
        result = 1;
    } else if (found) {
        boot.pc = pc; boot.tcr = tcr; boot.ttbr1 = ttbr1;
        if (!translate(&boot, pc, &boot.pcPA, true)) {
            dprintf(2, "[AppleAccountV1] native kernel translation admission failed tcr=0x%llx\n", (unsigned long long)tcr);
            pthread_mutex_unlock(&MapLock);
            return -1;
        }
        // Both operations happen before allowing this same owner vCPU to
        // reenter the early kernel. No account daemon can run between them.
        bool tree = hv_legacy_dt_apply(boot.tree, boot.treeSize, Identity.mlb, Identity.model);
        bool policy = tree && (VM_APPLE_ACCOUNT_TREE_ONLY || installPolicy(&boot));
        if (tree && policy) {
            __atomic_store_n(&KernelFinished, 1, __ATOMIC_RELEASE);
            dprintf(2, "[AppleAccountV1] native board identity installed build=%s scopedPolicy=%u\n", Identity.build, !VM_APPLE_ACCOUNT_TREE_ONLY);
            result = 1;
        } else {
            dprintf(2, "[AppleAccountV1] exact early-kernel compatibility admission failed tree=%u policy=%u\n", tree, policy);
            result = -1;
        }
    }
    pthread_mutex_unlock(&MapLock);
    return result;
}
