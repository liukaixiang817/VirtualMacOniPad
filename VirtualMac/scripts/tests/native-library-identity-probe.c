/* Inspect a frozen private library's identity and exports; invoke no target API. */
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>
extern kern_return_t mach_vm_read_overwrite(vm_map_read_t, mach_vm_address_t,
    mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);
static void string(const char *s) {
    putchar('"');
    if (s) for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        if (*p == '"' || *p == '\\') putchar('\\');
        if (*p < 32) printf("\\u%04x", *p); else putchar(*p);
    }
    putchar('"');
}
static int read_own(uintptr_t address, void *out, size_t bytes) {
    mach_vm_size_t copied = 0;
    kern_return_t rc = mach_vm_read_overwrite(mach_task_self(), address, bytes, (uintptr_t)out, &copied);
    return rc == KERN_SUCCESS && copied == bytes;
}
static int image_uuid(void *header, char result[33]) {
    struct mach_header_64 h = {0}; unsigned char commands[16384];
    if (!read_own((uintptr_t)header, &h, sizeof(h)) || h.magic != MH_MAGIC_64 ||
        h.filetype != MH_DYLIB || h.cputype != CPU_TYPE_ARM64 || h.ncmds > 256 ||
        h.sizeofcmds > sizeof(commands) || !read_own((uintptr_t)header + sizeof(h), commands, h.sizeofcmds)) return 0;
    unsigned at = 0, found = 0;
    for (unsigned i = 0; i < h.ncmds; ++i) {
        struct load_command c;
        if (at > h.sizeofcmds || h.sizeofcmds - at < sizeof(c)) return 0;
        memcpy(&c, commands + at, sizeof(c));
        if (c.cmdsize < sizeof(c) || (c.cmdsize & 7) || c.cmdsize > h.sizeofcmds - at) return 0;
        if (c.cmd == LC_UUID) {
            if (c.cmdsize != 24 || ++found != 1) return 0;
            for (unsigned j = 0; j < 16; ++j) sprintf(result + 2 * j, "%02x", commands[at + 8 + j]);
        }
        at += c.cmdsize;
    }
    return found == 1 && at == h.sizeofcmds;
}
int main(int argc, char **argv) {
    struct rlimit cpu = {3, 3}, core = {0, 0};
    if (setrlimit(RLIMIT_CPU, &cpu) || setrlimit(RLIMIT_CORE, &core)) return 78;
    alarm(8); setbuf(stdout, NULL);
    if (argc < 4 || argc > 132 || strlen(argv[2]) != 32) return 64;
    for (unsigned i = 0; i < 32; ++i) if (!strchr("0123456789abcdef", argv[2][i])) return 64;
    printf("{\"record\":\"start\",\"PID\":%d,\"UID\":%u,\"targetCalls\":0,\"VMCalls\":0,\"GPUCalls\":0}\n", getpid(), getuid());
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (!handle) { printf("{\"record\":\"dlopen\",\"loaded\":false,\"error\":"); string(dlerror()); puts("}"); return 66; }
    void *owner = NULL; int failures = 0;
    for (int i = 3; i < argc; ++i) {
        void *entry = dlsym(handle, argv[i]); Dl_info info = {0}; char uuid[33] = {0};
        void *raw = ptrauth_strip(entry, ptrauth_key_function_pointer);
        int located = entry ? dladdr(raw, &info) : 0;
        int identity = located && info.dli_fbase && image_uuid(info.dli_fbase, uuid) && !strcmp(uuid, argv[2]);
        if (!owner && identity) owner = info.dli_fbase;
        identity = identity && owner == info.dli_fbase;
        printf("{\"record\":\"export\",\"symbol\":"); string(argv[i]);
        printf(",\"found\":%s,\"dladdrReturn\":%d,\"provider\":", entry ? "true" : "false", located); string(info.dli_fname);
        printf(",\"UUID\":"); string(uuid); printf(",\"sameExpectedImage\":%s}\n", identity ? "true" : "false");
        if (!identity) ++failures;
    }
    int closed = dlclose(handle);
    printf("{\"record\":\"summary\",\"exports\":%d,\"failures\":%d,\"closeReturn\":%d,\"targetCalls\":0}\n", argc - 3, failures, closed);
    alarm(0); return failures || closed ? 68 : 0;
}
