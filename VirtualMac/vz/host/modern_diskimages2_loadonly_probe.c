/* Genuine DI2 closure and runtime metadata only. No DI2 method or disk API. */
#include <stddef.h>
#include <stdint.h>
#include "diskimages227-pins.h"
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
int main(int argc, char **argv) {
    if (argc != 2 || strcmp(argv[1], "--load-only")) return 64;
    if (setvbuf(stdout, NULL, _IOLBF, 0)) return 64;
    printf("{\"record\":\"start\",\"PID\":%d,\"DI2APICalls\":0}\n", getpid());
    for (uint32_t i = 0; i < _dyld_image_count(); ++i) {
        const char *path = _dyld_get_image_name(i);
        if (path && strstr(path, "DiskImages2")) { fprintf(stderr, "preexisting DI2 image: %s\n", path); return 65; }
    }
    for (unsigned i = 0; i < ImageCount; ++i) if (!FilePin(&Images[i])) { fprintf(stderr, "file identity failed: %s\n", Images[i].path); return 66; }
    void *library = dlopen(Images[DI2Index].path, RTLD_NOW | RTLD_LOCAL | RTLD_FIRST);
    if (!library) { fprintf(stderr, "genuine27 DI2 dlopen: %s\n", dlerror()); return 67; }
    void *compat = dlopen(Images[CompatIndex].path, RTLD_NOLOAD | RTLD_NOW | RTLD_LOCAL | RTLD_FIRST);
    if (!compat) { fprintf(stderr, "DI2 compat was not loaded\n"); return 68; }
    for (unsigned i = 0; i < ProviderSymbolCount; ++i) {
        const struct ProviderSymbol *row = &ProviderSymbols[i]; void *entry = dlsym(compat, row->name + 1);
        if (!entry) { fprintf(stderr, "provider export missing: %s\n", row->name); return 68; }
        if (!row->data) entry = ptrauth_strip(entry, ptrauth_key_function_pointer);
        if (!Identity(entry, &Images[row->image], 0, 0)) { fprintf(stderr, "provider identity failed: %s\n", row->name); return 68; }
    }
    for (unsigned i = 0; i < 5; ++i) {
        char symbol[160]; if (snprintf(symbol, sizeof(symbol), "OBJC_CLASS_$_%s", ClassNames[i]) >= (int)sizeof(symbol)) return 69;
        Class cls = dlsym(library, symbol);
        if (!cls || !Identity(cls, &Images[DI2Index], 0, 0) || objc_lookUpClass(ClassNames[i]) != cls) {
            fprintf(stderr, "DI2 class identity/registration conflict: %s\n", ClassNames[i]); return 69;
        }
        printf("{\"record\":\"class\",\"name\":\"%s\",\"actualPrivateDI2Class\":true}\n", ClassNames[i]);
    }
    for (unsigned i = 0; i < MethodCount; ++i) {
        const struct MethodPin *row = &Methods[i]; Class cls = objc_lookUpClass(row->className);
        Method method = class_getInstanceMethod(cls, sel_registerName(row->selector));
        if (!method || strcmp(method_getTypeEncoding(method), row->encoding)) { fprintf(stderr, "DI2 method ABI mismatch: %s %s\n", row->className, row->selector); return 70; }
        void *entry = ptrauth_strip((void *)method_getImplementation(method), ptrauth_key_function_pointer);
        if (!Identity(entry, &Images[DI2Index], row->rva, 1)) return 70;
        printf("{\"record\":\"method\",\"class\":\"%s\",\"selector\":\"%s\",\"actualOriginalRVA\":\"0x%llx\",\"calls\":0}\n", row->className, row->selector, (unsigned long long)row->rva);
    }
    dlclose(compat);
    /* Registered Objective-C classes retain their mapped image. dlclose
       drops our reference, but process exit is the actual lifecycle boundary. */
    dlclose(library);
    printf("{\"record\":\"summary\",\"PID\":%d,\"genuine27UUID\":\"a456d4a4d6ab3549965d0400f3552de3\",\"privateProviders\":%u,\"classes\":5,\"methods\":%u,\"DI2APICalls\":0,\"diskVMGPUCalls\":0,\"passed\":true}\n", getpid(), ProviderSymbolCount, MethodCount);
    return 0;
}
