/* iPadOS16's Bluetooth HAL accepts only a native audio server. A VMM is not
 * one. Disable only that unsupported endpoint in our own child; leave the
 * normal HAL/speaker and all other XPC clients untouched. */
#include <dlfcn.h>
#include <errno.h>
#include <limits.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <xpc/xpc.h>

/* Private iPadOS entry point present in the captured native HAL import table;
 * the public SDK deliberately marks its ordinary declaration unavailable. */
extern xpc_connection_t VM27NativeCreateMachService(const char *, dispatch_queue_t,
    uint64_t) __asm("_xpc_connection_create_mach_service");

static int own_child(void) {
    static const char path[] = "/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/child-flat/VMM.bundle/Contents/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/MacOS/com.apple.Virtualization.VirtualMachine";
    char executable[PATH_MAX], canonical[PATH_MAX];
    uint32_t size = sizeof(executable);
    return geteuid() == 501 && _NSGetExecutablePath(executable, &size) == 0 &&
        realpath(executable, canonical) && strcmp(canonical, path) == 0;
}

static int native_bluetooth_caller(const void *caller) {
    static const uint8_t uuid[16] = {
        0xc3,0x69,0x80,0x98,0xe6,0xca,0x37,0x4a,
        0x94,0xec,0x50,0x4a,0xe0,0x4c,0x93,0x4b
    };
    Dl_info info = {0};
    if (!dladdr(caller, &info) || !info.dli_fbase ||
        (uintptr_t)caller - (uintptr_t)info.dli_fbase != 0x367a8)
        return 0;
    const struct mach_header_64 *header = info.dli_fbase;
    if (header->magic != MH_MAGIC_64 || header->ncmds > 256 ||
        header->sizeofcmds > 65536)
        return 0;
    const uint8_t *cursor = (const uint8_t *)(header + 1);
    const uint8_t *end = cursor + header->sizeofcmds;
    for (uint32_t index = 0; index < header->ncmds; index++) {
        if ((size_t)(end - cursor) < sizeof(struct load_command)) return 0;
        const struct load_command *command = (const void *)cursor;
        if (command->cmdsize < sizeof(*command) ||
            command->cmdsize > (size_t)(end - cursor)) return 0;
        if (command->cmd == LC_UUID)
            return command->cmdsize == sizeof(struct uuid_command) &&
                memcmp(((const struct uuid_command *)command)->uuid, uuid, 16) == 0;
        cursor += command->cmdsize;
    }
    return 0;
}

__attribute__((noinline)) static xpc_connection_t bluetooth_audio_unavailable(
    const char *name, dispatch_queue_t queue, uint64_t flags) {
    const void *caller = ptrauth_strip(__builtin_return_address(0),
        ptrauth_key_return_address);
    if (name && strcmp(name, "com.apple.BTAudioHALPlugin.xpc") == 0 &&
        native_bluetooth_caller(caller) && own_child()) {
        static unsigned logged;
        if (!__atomic_exchange_n(&logged, 1, __ATOMIC_RELAXED))
            dprintf(2, "[VM27Audio] Bluetooth HAL unavailable for owned VMM; native speaker path retained\n");
        /* The actual plugin tests this NULL before installing a handler or
         * resuming a connection (UUID above, instructions 0x367a8/0x367ac).
         * No connection, successful registration, or audio identity is faked. */
        errno = ENOTSUP;
        return NULL;
    }
    return VM27NativeCreateMachService(name, queue, flags);
}

__attribute__((used)) static const struct {
    const void *replacement;
    const void *replacee;
} interpose __attribute__((section("__DATA,__interpose"))) = {
    (const void *)&bluetooth_audio_unavailable,
    (const void *)&VM27NativeCreateMachService
};
