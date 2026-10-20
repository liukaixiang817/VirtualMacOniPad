/* Genuine libquarantine loader and metadata only. Never call a qtn export. */
#include <stddef.h>
#include <stdint.h>
#include "libquarantine27-pins.h"
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int UUIDForAddress(const void *address, char uuid[33], Dl_info *info) {
    if (!dladdr(address, info) || !info->dli_fbase || !info->dli_fname) return 0;
    const struct mach_header_64 *header = info->dli_fbase;
    if (header->magic != MH_MAGIC_64 || header->filetype != MH_DYLIB ||
        header->ncmds > 256 || header->sizeofcmds > 32768) return 0;
    const unsigned char *at = (const unsigned char *)(header + 1);
    const unsigned char *end = at + header->sizeofcmds; unsigned count = 0;
    for (unsigned i = 0; i < header->ncmds; ++i) {
        if ((size_t)(end - at) < 8) return 0;
        const struct load_command *command = (const void *)at;
        if (command->cmdsize < 8 || command->cmdsize % 8 || command->cmdsize > (size_t)(end - at)) return 0;
        if (command->cmd == LC_UUID) {
            if (command->cmdsize != sizeof(struct uuid_command)) return 0;
            for (unsigned k = 0; k < 16; ++k) snprintf(uuid + k * 2, 3, "%02x", at[8 + k]);
            ++count;
        }
        at += command->cmdsize;
    }
    return at == end && count == 1;
}
static int FilePin(const char *path, size_t size, const unsigned char sha[32]) {
    FILE *file = fopen(path, "rb"); if (!file) return 0;
    unsigned char buffer[8192], digest[32]; size_t bytes, total = 0;
    CC_SHA256_CTX context; CC_SHA256_Init(&context);
    while ((bytes = fread(buffer, 1, sizeof(buffer), file))) {
        CC_SHA256_Update(&context, buffer, (CC_LONG)bytes); total += bytes;
    }
    int valid = !ferror(file); valid &= fclose(file) == 0;
    CC_SHA256_Final(digest, &context);
    return valid && total == size && !memcmp(digest, sha, 32);
}
int main(int argc, char **argv) {
    int load = argc == 2 && !strcmp(argv[1], "--load-only");
    if (!(load || (argc == 2 && !strcmp(argv[1], "--inventory")))) return 64;
    printf("{\"record\":\"start\",\"PID\":%d,\"loadOnly\":%s,\"qtnAPICalls\":0}\n", getpid(), load ? "true" : "false");
    void *handles[8] = {0}; unsigned missing = 0, requiredMissing = 0, identities = 0;
    for (unsigned i = 0; i < 8; ++i) {
        handles[i] = dlopen(SystemImages[i], RTLD_NOLOAD | RTLD_NOW | RTLD_LOCAL | RTLD_FIRST);
        printf("{\"record\":\"image\",\"path\":\"%s\",\"alreadyLoaded\":%s}\n", SystemImages[i], handles[i] ? "true" : "false");
    }
    for (unsigned i = 0; i < 42; ++i) {
        const struct Symbol *row = &RequiredSymbols[i];
        const void *symbol = handles[row->owner] ? dlsym(handles[row->owner], row->name + 1) : NULL;
        if (!symbol) { ++missing; if (!row->allocator) ++requiredMissing; printf("{\"record\":\"symbol\",\"index\":%u,\"name\":\"%s\",\"requestedOwner\":\"%s\",\"found\":false}\n", i, row->name, SystemImages[row->owner]); continue; }
        /* Data pointers are not stripped as function pointers. */
        if (!row->data) symbol = ptrauth_strip((void *)symbol, ptrauth_key_function_pointer);
        Dl_info info = {0}; char uuid[33];
        if (!UUIDForAddress(symbol, uuid, &info)) { ++identities; continue; }
        printf("{\"record\":\"symbol\",\"index\":%u,\"name\":\"%s\",\"requestedOwner\":\"%s\",\"found\":true,\"actualOwner\":\"%s\",\"UUID\":\"%s\",\"RVA\":\"0x%llx\"}\n",
            i, row->name, SystemImages[row->owner], info.dli_fname, uuid,
            (unsigned long long)((uintptr_t)symbol - (uintptr_t)info.dli_fbase));
    }
    if (!load) {
        for (unsigned i = 0; i < 8; ++i) if (handles[i]) dlclose(handles[i]);
        printf("{\"record\":\"summary\",\"PID\":%d,\"symbols\":42,\"missing\":%u,\"identityFailures\":%u,\"qtnLibraryLoaded\":false,\"qtnAPICalls\":0,\"diskVMGPUCalls\":0}\n", getpid(), missing, identities);
        return identities ? 1 : 0;
    }
    if (identities || requiredMissing || missing > ExpectedMissingSystemAllocator) return 65;
#if VM27_QTN_IOS
    if (!FilePin(AllocatorPath, AllocatorBytes, AllocatorSHA)) return 66;
    void *allocator = dlopen(AllocatorPath, RTLD_NOW | RTLD_LOCAL | RTLD_FIRST);
    if (!allocator) { fprintf(stderr, "allocator dlopen: %s\n", dlerror()); return 66; }
    for (unsigned i = 0; i < 2; ++i) {
        void *entry = dlsym(allocator, i ? "malloc_type_malloc" : "malloc_type_calloc");
        if (!entry) return 66;
        Dl_info info = {0}; char uuid[33], actual[4096], expected[4096];
        entry = ptrauth_strip(entry, ptrauth_key_function_pointer);
        if (!UUIDForAddress(entry, uuid, &info) || strcmp(uuid, AllocatorUUID) ||
            !realpath(info.dli_fname, actual) || !realpath(AllocatorPath, expected) || strcmp(actual, expected)) return 66;
    }
#endif
    if (!FilePin(QuarantinePath, QuarantineBytes, QuarantineSHA)) return 67;
    void *library = dlopen(QuarantinePath, RTLD_NOW | RTLD_LOCAL | RTLD_FIRST);
    if (!library) { fprintf(stderr, "genuine27 libquarantine dlopen: %s\n", dlerror()); return 68; }
    unsigned exports = 0;
    for (unsigned i = 0; i < 9; ++i) {
        void *entry = dlsym(library, QtnNames[i] + 1);
        if (!entry) return 69;
        entry = ptrauth_strip(entry, ptrauth_key_function_pointer);
        Dl_info info = {0}; char uuid[33], actual[4096], expected[4096];
        if (!UUIDForAddress(entry, uuid, &info) || strcmp(uuid, "7fd4ae2286ef382b83f5adf9336c1160") ||
            !realpath(info.dli_fname, actual) || !realpath(QuarantinePath, expected) || strcmp(actual, expected) ||
            (uintptr_t)entry - (uintptr_t)info.dli_fbase != QtnRVAs[i]) return 69;
        printf("{\"record\":\"qtnExport\",\"name\":\"%s\",\"UUID\":\"%s\",\"path\":\"%s\",\"RVA\":\"0x%llx\",\"calls\":0}\n",
               QtnNames[i], uuid, actual, (unsigned long long)QtnRVAs[i]); ++exports;
    }
    dlclose(library);
#if VM27_QTN_IOS
    dlclose(allocator);
#endif
    for (unsigned i = 0; i < 8; ++i) if (handles[i]) dlclose(handles[i]);
    printf("{\"record\":\"summary\",\"PID\":%d,\"symbols\":42,\"missingSystem\":%u,\"identityFailures\":0,\"genuine27UUID\":\"7fd4ae2286ef382b83f5adf9336c1160\",\"qtnExportIdentities\":%u,\"qtnLibraryLoaded\":true,\"qtnAPICalls\":0,\"diskVMGPUCalls\":0,\"passed\":true}\n", getpid(), missing, exports);
    return 0;
}
