#include "modern_hpke_original_sdk_identity.h"
#include "hpke-sdk-pins.h"
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static bool Identity(const void *address, const char *name, bool data, bool native, uintptr_t expectedRVA) {
    if (!data) address = ptrauth_strip((void *)address, ptrauth_key_function_pointer);
    Dl_info info = {0}; char uuid[33] = {0};
    if (!dladdr(address, &info) || !info.dli_fbase || !info.dli_fname) return false;
    const struct mach_header_64 *header = info.dli_fbase;
    if (header->magic != MH_MAGIC_64 || header->ncmds > 512 || header->sizeofcmds > 65536) return false;
    const unsigned char *at = (const unsigned char *)(header + 1), *end = at + header->sizeofcmds;
    unsigned count = 0;
    for (unsigned k = 0; k < header->ncmds; ++k) {
        if ((size_t)(end - at) < 8) return false;
        const struct load_command *command = (const void *)at;
        if (command->cmdsize < 8 || command->cmdsize % 8 || command->cmdsize > (size_t)(end - at)) return false;
        if (command->cmd == LC_UUID) {
            if (command->cmdsize != 24) return false;
            for (unsigned i = 0; i < 16; ++i) snprintf(uuid + i * 2, 3, "%02x", at[8 + i]);
            ++count;
        }
        at += command->cmdsize;
    }
    const char *expected = native ? NativeCryptoUUID : PrivateProviderUUID;
    const char *expectedPath = native ? NativeCryptoPath : PrivateProviderPath;
    char actualPath[4096], canonical[4096];
    if (at != end || count != 1 || strcmp(uuid, expected)) return false;
    if (native) {
        // A dyld-cache image need not have an on-disk file. Require its exact
        // system install path and live LC_UUID instead of filesystem realpath.
        if (strcmp(info.dli_fname, expectedPath)) return false;
        snprintf(actualPath, sizeof(actualPath), "%s", info.dli_fname);
    } else if (!realpath(info.dli_fname, actualPath) ||
               !realpath(expectedPath, canonical) || strcmp(actualPath, canonical)) return false;
    uintptr_t rva = (uintptr_t)address - (uintptr_t)info.dli_fbase;
    if (expectedRVA && rva != expectedRVA) return false;
    printf("{\"record\":\"identity\",\"name\":\"%s\",\"data\":%s,\"nativeP256\":%s,\"UUID\":\"%s\",\"path\":\"%s\",\"RVA\":\"0x%llx\"}\n",
           name, data ? "true" : "false", native ? "true" : "false", uuid, actualPath, (unsigned long long)rva);
    return true;
}
bool VM27HPKEMetadataIdentity(const void *metadata, const char *name, bool native) {
    return Identity(metadata, name, true, native, 0);
}
bool VM27HPKEProbeBegin(void) {
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("{\"record\":\"start\",\"PID\":%d,\"cryptoAPICallsSoFar\":0}\n", getpid());
    FILE *file = fopen(PrivateProviderPath, "rb"); if (!file) return false;
    CC_SHA256_CTX context; CC_SHA256_Init(&context);
    unsigned char block[8192], digest[32]; size_t count, bytes = 0;
    while ((count = fread(block, 1, sizeof(block), file))) {
        CC_SHA256_Update(&context, block, (CC_LONG)count); bytes += count;
    }
    bool valid = !ferror(file); valid &= fclose(file) == 0;
    CC_SHA256_Final(digest, &context);
    if (!valid || bytes != PrivateProviderBytes || memcmp(digest, PrivateProviderSHA, 32)) return false;
    void *image = dlopen(PrivateProviderPath, RTLD_NOLOAD | RTLD_NOW | RTLD_LOCAL | RTLD_FIRST);
    if (!image) { fprintf(stderr, "HPKE provider NOLOAD: %s\n", dlerror()); return false; }
    for (unsigned i = 0; i < 23; ++i) {
        const struct Symbol *row = &RequiredSymbols[i];
        void *entry = dlsym(image, row->name + 1);
        if (!entry || !Identity(entry, row->name, row->data, row->native, row->rva)) {
            Dl_info debug = {0}; if (entry) dladdr(row->data ? entry : ptrauth_strip(entry,ptrauth_key_function_pointer), &debug);
            fprintf(stderr,"identity rejected %s entry=%p image=%s expectedUUID=%s expectedRVA=0x%llx dlerror=%s\n",row->name,entry,debug.dli_fname?debug.dli_fname:"(none)",row->native?NativeCryptoUUID:PrivateProviderUUID,(unsigned long long)row->rva,dlerror());
            dlclose(image); return false;
        }
    }
    dlclose(image);
    printf("{\"record\":\"identityGate\",\"symbols\":23,\"privateNaturalAliases\":16,\"nativeP256Entries\":7,\"cryptoAPICallsSoFar\":0,\"passed\":true}\n");
    return true;
}
