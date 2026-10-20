/* Readonly old-system symbol discovery. Never invoke a CryptoKit/Swift entry. */
#include "hpke-system-inventory-pins.h"
#include <dlfcn.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int UUIDForAddress(const void *address, char uuid[33], Dl_info *info) {
    if (!dladdr(address, info) || !info->dli_fbase || !info->dli_fname) return 0;
    const struct mach_header_64 *header = info->dli_fbase;
    if (header->magic != MH_MAGIC_64 || header->filetype != MH_DYLIB ||
        header->ncmds > 512 || header->sizeofcmds > 65536) return 0;
    const unsigned char *at = (const unsigned char *)(header + 1), *end = at + header->sizeofcmds;
    unsigned count = 0;
    for (unsigned i = 0; i < header->ncmds; ++i) {
        if ((size_t)(end - at) < 8) return 0;
        const struct load_command *command = (const void *)at;
        if (command->cmdsize < 8 || command->cmdsize % 8 || command->cmdsize > (size_t)(end - at)) return 0;
        if (command->cmd == LC_UUID) {
            if (command->cmdsize != 24) return 0;
            for (unsigned k = 0; k < 16; ++k) snprintf(uuid + k * 2, 3, "%02x", at[8 + k]);
            ++count;
        }
        at += command->cmdsize;
    }
    return at == end && count == 1;
}
int main(int argc, char **argv) {
    if (argc != 2 || strcmp(argv[1], "--inventory")) return 64;
    setvbuf(stdout, NULL, _IOLBF, 0);
    printf("{\"record\":\"start\",\"PID\":%d,\"cryptoAPICalls\":0,\"metadataAccessorCalls\":0}\n", getpid());
    void *handles[HPKE_IMAGE_COUNT] = {0};
    unsigned absent = 0, missing = 0, identityFailures = 0, providerMissing = 0, DI2Missing = 0;
    for (unsigned i = 0; i < HPKE_IMAGE_COUNT; ++i) {
        handles[i] = dlopen(SystemImages[i], RTLD_NOW | RTLD_LOCAL | RTLD_FIRST);
        if (!handles[i]) ++absent;
        printf("{\"record\":\"image\",\"index\":%u,\"path\":\"%s\",\"loaded\":%s}\n", i, SystemImages[i], handles[i] ? "true" : "false");
        if (!handles[i]) fprintf(stderr, "system image %s: %s\n", SystemImages[i], dlerror());
    }
    for (unsigned i = 0; i < HPKE_SYMBOL_COUNT; ++i) {
        const struct Symbol *row = &RequiredSymbols[i];
        const void *entry = handles[row->owner] ? dlsym(handles[row->owner], row->name + 1) : NULL;
        if (!entry) {
            ++missing; providerMissing += row->provider; DI2Missing += row->DI2;
            printf("{\"record\":\"symbol\",\"index\":%u,\"name\":\"%s\",\"requestedOwner\":\"%s\",\"providerImport\":%s,\"DI2Original\":%s,\"found\":false}\n",
                   i, row->name, SystemImages[row->owner], row->provider ? "true" : "false", row->DI2 ? "true" : "false");
            continue;
        }
        /* Data-address identity stays unsigned data; only function pointers
           are stripped for dladdr discovery. Neither kind is invoked. */
        if (!row->data) entry = ptrauth_strip((void *)entry, ptrauth_key_function_pointer);
        Dl_info info = {0}; char uuid[33];
        if (!UUIDForAddress(entry, uuid, &info)) {
            ++identityFailures;
            printf("{\"record\":\"symbol\",\"index\":%u,\"name\":\"%s\",\"found\":true,\"identityFailure\":true}\n", i, row->name);
            continue;
        }
        printf("{\"record\":\"symbol\",\"index\":%u,\"name\":\"%s\",\"requestedOwner\":\"%s\",\"providerImport\":%s,\"DI2Original\":%s,\"found\":true,\"data\":%s,\"actualOwner\":\"%s\",\"UUID\":\"%s\",\"RVA\":\"0x%llx\"}\n",
               i, row->name, SystemImages[row->owner], row->provider ? "true" : "false", row->DI2 ? "true" : "false",
               row->data ? "true" : "false", info.dli_fname, uuid, (unsigned long long)((uintptr_t)entry - (uintptr_t)info.dli_fbase));
    }
    for (unsigned i = 0; i < HPKE_IMAGE_COUNT; ++i) if (handles[i]) dlclose(handles[i]);
    printf("{\"record\":\"summary\",\"PID\":%d,\"symbols\":%u,\"providerImports\":187,\"DI2OriginalSymbols\":21,\"missing\":%u,\"providerImportMissing\":%u,\"DI2OriginalMissing\":%u,\"absentImages\":%u,\"identityFailures\":%u,\"cryptoAPICalls\":0,\"metadataAccessorCalls\":0,\"P256Objects\":0,\"privateHPKEProviderLoaded\":false,\"diskVMGPUCalls\":0}\n",
           getpid(), HPKE_SYMBOL_COUNT, missing, providerMissing, DI2Missing, absent, identityFailures);
    /* Missing symbols are discovery results, never successful load evidence. */
    return identityFailures ? 1 : 0;
}
