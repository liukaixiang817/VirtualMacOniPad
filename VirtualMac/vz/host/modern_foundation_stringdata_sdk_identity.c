#include "modern_foundation_stringdata_sdk_identity.h"
#include "foundation-sdk-pins.h"
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

bool VM27FoundationProbeBegin(void) {
    if (setvbuf(stdout, NULL, _IOLBF, 0)) return false;
    printf("{\"record\":\"start\",\"PID\":%d,\"conversionCallsSoFar\":0}\n", getpid());
    FILE *file = fopen(PrivateProviderPath, "rb"); if (!file) return false;
    CC_SHA256_CTX context; CC_SHA256_Init(&context);
    unsigned char block[8192], digest[32]; size_t count, total = 0;
    while ((count = fread(block, 1, sizeof(block), file))) {
        CC_SHA256_Update(&context, block, (CC_LONG)count); total += count;
    }
    bool valid = !ferror(file); valid &= fclose(file) == 0;
    CC_SHA256_Final(digest, &context);
    if (!valid || total != PrivateProviderBytes || memcmp(digest, PrivateProviderSHA, 32)) return false;
    void *library = dlopen(PrivateProviderPath, RTLD_NOLOAD | RTLD_NOW | RTLD_LOCAL | RTLD_FIRST);
    if (!library) { fprintf(stderr, "Foundation private provider NOLOAD: %s\n", dlerror()); return false; }
    void *entry = dlsym(library, OriginalSymbol + 1);
    void *natural = dlsym(library, NaturalSymbol + 1);
    if (!entry || !natural) { dlclose(library); return false; }
    entry = ptrauth_strip(entry, ptrauth_key_function_pointer);
    natural = ptrauth_strip(natural, ptrauth_key_function_pointer);
    Dl_info info = {0}; char actual[4096], canonical[4096];
    if (entry != natural || !dladdr(entry, &info) || !info.dli_fbase || !info.dli_fname ||
        !realpath(info.dli_fname, actual) || !realpath(PrivateProviderPath, canonical) || strcmp(actual, canonical)) {
        dlclose(library); return false;
    }
    const struct mach_header_64 *header = info.dli_fbase;
    if (header->magic != MH_MAGIC_64 || header->filetype != MH_DYLIB || header->ncmds > 256 || header->sizeofcmds > 32768) {
        dlclose(library); return false;
    }
    const unsigned char *at = (const void *)(header + 1), *end = at + header->sizeofcmds;
    char uuid[33] = {0}; unsigned found = 0;
    for (unsigned i = 0; i < header->ncmds; ++i) {
        if ((size_t)(end - at) < 8) { dlclose(library); return false; }
        const struct load_command *command = (const void *)at;
        if (command->cmdsize < 8 || command->cmdsize % 8 || command->cmdsize > (size_t)(end - at)) { dlclose(library); return false; }
        if (command->cmd == LC_UUID) {
            if (command->cmdsize != sizeof(struct uuid_command)) { dlclose(library); return false; }
            for (unsigned k = 0; k < 16; ++k) snprintf(uuid + k * 2, 3, "%02x", at[8 + k]); ++found;
        }
        at += command->cmdsize;
    }
    uintptr_t rva = (uintptr_t)entry - (uintptr_t)info.dli_fbase;
    if (at != end || found != 1 || strcmp(uuid, PrivateProviderUUID) || rva != PrivateAliasRVA) {
        dlclose(library); return false;
    }
    printf("{\"record\":\"identity\",\"name\":\"%s\",\"UUID\":\"%s\",\"path\":\"%s\",\"RVA\":\"0x%llx\",\"naturalAliasSameAddress\":true}\n",
           OriginalSymbol, uuid, actual, (unsigned long long)rva);
    dlclose(library);
    return true;
}
