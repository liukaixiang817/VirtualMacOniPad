/* HOST-only: compile the genuine VMM policy; never apply a sandbox policy. */
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <mach-o/loader.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

struct profile {
    char *builtin;
    unsigned char *data;
    size_t size;
};
typedef struct profile *(*compile_file_fn)(const char *, void *, char **);
typedef void (*free_profile_fn)(struct profile *);
_Static_assert(sizeof(struct profile) == 24, "actual LP64 profile ABI");
_Static_assert(offsetof(struct profile, data) == 8, "actual profile data slot");
_Static_assert(offsetof(struct profile, size) == 16, "actual profile size slot");

static const char *const profile_path =
    "/System/Library/Frameworks/Virtualization.framework/Versions/A/XPCServices/"
    "com.apple.Virtualization.VirtualMachine.xpc/Contents/Resources/"
    "com.apple.Virtualization.VirtualMachine.sb";

static int print_identity(const void *symbol, const char *label) {
    Dl_info identity;
    if (!dladdr(symbol, &identity) || !identity.dli_fbase || !identity.dli_fname ||
        strcmp(identity.dli_fname, "/usr/lib/libsandbox.1.dylib"))
        return -1;
    const struct mach_header_64 *header = identity.dli_fbase;
    if (header->magic != MH_MAGIC_64 || header->ncmds > 256 || header->sizeofcmds > 65536)
        return -1;
    const unsigned char *cursor = (const unsigned char *)(header + 1);
    const unsigned char *end = cursor + header->sizeofcmds;
    const unsigned char *uuid = NULL;
    for (uint32_t i = 0; i < header->ncmds; ++i) {
        if ((size_t)(end - cursor) < sizeof(struct load_command)) return -1;
        const struct load_command *command = (const struct load_command *)cursor;
        if (command->cmdsize < 8 || command->cmdsize > (size_t)(end - cursor)) return -1;
        if (command->cmd == LC_UUID) {
            if (uuid || command->cmdsize != sizeof(struct uuid_command)) return -1;
            uuid = ((const struct uuid_command *)cursor)->uuid;
        }
        cursor += command->cmdsize;
    }
    if (cursor != end || !uuid) return -1;
    static const unsigned char expected[16] = {
        0x64, 0x8b, 0x6e, 0xc9, 0xb8, 0x0a, 0x36, 0x73,
        0xac, 0x47, 0xf6, 0xf7, 0x80, 0x6b, 0xb1, 0x58
    };
    if (memcmp(uuid, expected, sizeof(expected))) return -1;
    printf("%s_provider=%s\n%s_uuid=", label, identity.dli_fname, label);
    for (size_t i = 0; i < 16; ++i) printf("%02x", uuid[i]);
    printf("\n");
    return 0;
}

int main(int argc, char **argv) {
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc != 2) return 2;
    struct rlimit cpu = {10, 10};
    struct rlimit core = {0, 0};
    if (setrlimit(RLIMIT_CPU, &cpu) || setrlimit(RLIMIT_CORE, &core)) return 3;
    void *library = dlopen("/usr/lib/libsandbox.1.dylib", RTLD_NOW | RTLD_LOCAL);
    if (!library) { fprintf(stderr, "dlopen: %s\n", dlerror()); return 4; }
    compile_file_fn compile_file = (compile_file_fn)dlsym(library, "sandbox_compile_file");
    free_profile_fn free_profile = (free_profile_fn)dlsym(library, "sandbox_free_profile");
    if (!compile_file || !free_profile || print_identity((const void *)compile_file, "compile") ||
        print_identity((const void *)free_profile, "free")) return 5;
    printf("profile_path=%s\nparameters=NULL\ncompile_calls=1\n", profile_path);
    char *error = NULL;
    errno = 0;
    struct profile *profile = compile_file(profile_path, NULL, &error);
    int saved_errno = errno;
    printf("compile_result_nonnull=%d\ncompile_errno=%d\n", profile != NULL, saved_errno);
    if (!profile) {
        printf("compile_error=%s\n", error ? error : "(none)");
        free(error);
        dlclose(library);
        return 6;
    }
    printf("profile_builtin=%s\nprofile_size=%zu\nprofile_data_nonnull=%d\n",
           profile->builtin ? profile->builtin : "(null)", profile->size, profile->data != NULL);
    if (profile->builtin || !profile->data || !profile->size || profile->size > 4 * 1024 * 1024) {
        free_profile(profile);
        free(error);
        dlclose(library);
        return 7;
    }
    int fd = open(argv[1], O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
    if (fd < 0) { free_profile(profile); free(error); dlclose(library); return 8; }
    size_t offset = 0;
    while (offset < profile->size) {
        ssize_t written = write(fd, profile->data + offset, profile->size - offset);
        if (written <= 0) { close(fd); free_profile(profile); free(error); dlclose(library); return 9; }
        offset += (size_t)written;
    }
    if (close(fd)) { free_profile(profile); free(error); dlclose(library); return 10; }
    printf("compiled_bytes_written=%zu\npolicy_apply_calls=0\n", offset);
    free_profile(profile);
    free(error);
    dlclose(library);
    return 0;
}
