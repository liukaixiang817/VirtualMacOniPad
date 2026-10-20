/* Independent fixed8MiB app-private capacity scope; old2MiB source/providers
 * stay unchanged. Info.plist still64KiB. Real SHA/UUID/owner/FD paths retained. */
#include "modern_xpc_large_bundle_registry.h"
#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/loader.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_SERVICES 16
#define MAX_FILE (8 * 1024 * 1024)
struct FilePin {
    char relative[4096];
    unsigned char digest[32];
    dev_t device;
    ino_t inode;
    uint64_t bytes;
    mode_t mode;
};
struct Service {
    VM27LargeServiceInfo info;
    struct FilePin bundleInfo, serviceInfo, code;
    VM27LWCRPolicy *policy;
};
struct VM27LargeBundleRegistry {
    pthread_mutex_t lock;
    int rootFD;
    char root[4096];
    struct stat rootStat;
    struct Service services[MAX_SERVICES];
    size_t count;
};
struct VM27LargeServicePlan {
    int rootFD;
    char root[4096];
    struct stat rootStat;
    struct Service service;
};
static _Atomic uint64_t gRegistrations, gServices, gPlans, gDestroyed, gVerify, gMessages;
#define COUNT(variable) atomic_fetch_add_explicit(&(variable), 1, memory_order_relaxed)

static bool Name(const char *name, size_t maximum) {
    size_t length = name ? strnlen(name, maximum + 1) : 0;
    if (!length || length > maximum || !strcmp(name, ".") || !strcmp(name, "..")) return false;
    for (size_t i = 0; i < length; ++i) {
        unsigned char c = (unsigned char)name[i];
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')) return false;
    }
    return true;
}
static bool Suffix(const char *name, const char *suffix) {
    size_t n = strlen(name), s = strlen(suffix);
    return n > s && !strcmp(name + n - s, suffix);
}
static bool Owned(const struct stat *state, bool directory) {
    return state->st_uid == geteuid() && !(state->st_mode & 0022) &&
        (directory ? S_ISDIR(state->st_mode) : S_ISREG(state->st_mode)) &&
        (directory || state->st_nlink == 1);
}
/* Every component is traversed with openat/O_NOFOLLOW, rooted in an owned FD. */
static int OpenRelative(int root, const char *relative, bool directory) {
    if (!relative || !*relative || relative[0] == '/' || strnlen(relative, 4096) >= 4096) { errno = EINVAL; return -1; }
    char path[4096]; strcpy(path, relative);
    int parent = fcntl(root, F_DUPFD_CLOEXEC, 3);
    if (parent < 0) return -1;
    char *component = path;
    for (;;) {
        char *slash = strchr(component, '/');
        if (slash) *slash = 0;
        if (!Name(component, 255)) { close(parent); errno = EINVAL; return -1; }
        bool isDirectory = slash || directory;
        int fd = openat(parent, component, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | (isDirectory ? O_DIRECTORY : 0));
        int saved = errno; close(parent);
        if (fd < 0) { errno = saved; return -1; }
        struct stat state;
        if (fstat(fd, &state) || !Owned(&state, isDirectory)) { close(fd); errno = EACCES; return -1; }
        if (!slash) return fd;
        parent = fd; component = slash + 1;
    }
}
static int ReadFile(int root, const char *relative, uint64_t limit,
                    struct FilePin *pin, unsigned char **contents) {
    if (contents) *contents = NULL;
    int fd = OpenRelative(root, relative, false);
    if (fd < 0) return errno;
    struct stat before = {0}, after = {0};
    if (fstat(fd, &before) || before.st_size <= 0 || (uint64_t)before.st_size > limit || limit > MAX_FILE) { close(fd); return EINVAL; }
    unsigned char *data = malloc((size_t)before.st_size);
    if (!data) { close(fd); return ENOMEM; }
    size_t at = 0;
    while (at < (size_t)before.st_size) {
        ssize_t count = read(fd, data + at, (size_t)before.st_size - at);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) { free(data); close(fd); return EIO; }
        at += (size_t)count;
    }
    if (fstat(fd, &after) || before.st_dev != after.st_dev || before.st_ino != after.st_ino ||
        !Owned(&after, false) || before.st_uid != after.st_uid || before.st_mode != after.st_mode || before.st_nlink != after.st_nlink ||
        before.st_size != after.st_size || before.st_mtimespec.tv_sec != after.st_mtimespec.tv_sec ||
        before.st_mtimespec.tv_nsec != after.st_mtimespec.tv_nsec || before.st_ctimespec.tv_sec != after.st_ctimespec.tv_sec ||
        before.st_ctimespec.tv_nsec != after.st_ctimespec.tv_nsec) { free(data); close(fd); return ESTALE; }
    close(fd);
    memset(pin, 0, sizeof(*pin)); strcpy(pin->relative, relative);
    pin->device = before.st_dev; pin->inode = before.st_ino;
    pin->bytes = (uint64_t)before.st_size; pin->mode = before.st_mode;
    CC_SHA256(data, (CC_LONG)at, pin->digest);
    if (contents) *contents = data; else free(data);
    return 0;
}
static int Text(CFDictionaryRef dictionary, const char *key, char *output, size_t capacity) {
    CFStringRef name = CFStringCreateWithCString(NULL, key, kCFStringEncodingUTF8);
    if (!name) return ENOMEM;
    CFTypeRef value = CFDictionaryGetValue(dictionary, name); CFRelease(name);
    if (!value || CFGetTypeID(value) != CFStringGetTypeID() ||
        !CFStringGetCString((CFStringRef)value, output, (CFIndex)capacity, kCFStringEncodingUTF8)) return EINVAL;
    return 0;
}
static int Plist(int root, const char *relative, struct FilePin *pin,
                 char *identifier, char *executable, bool service) {
    unsigned char *contents = NULL;
    int status = ReadFile(root, relative, 65536, pin, &contents);
    if (status) return status;
    CFDataRef data = CFDataCreate(NULL, contents, (CFIndex)pin->bytes); free(contents);
    if (!data) return ENOMEM;
    CFErrorRef error = NULL;
    CFPropertyListRef object = CFPropertyListCreateWithData(NULL, data, kCFPropertyListImmutable, NULL, &error);
    CFRelease(data); if (error) CFRelease(error);
    if (!object || CFGetTypeID(object) != CFDictionaryGetTypeID()) { if (object) CFRelease(object); return EINVAL; }
    status = Text((CFDictionaryRef)object, "CFBundleIdentifier", identifier, 161);
    if (!status && !Name(identifier, 160)) status = EINVAL;
    if (!status && service) {
        status = Text((CFDictionaryRef)object, "CFBundleExecutable", executable, 256);
        if (!status && !Name(executable, 255)) status = EINVAL;
        char package[16] = {0};
        if (!status) status = Text((CFDictionaryRef)object, "CFBundlePackageType", package, sizeof(package));
        if (!status && strcmp(package, "XPC!")) status = ENOTSUP;
    }
    CFRelease(object); return status;
}
static void Hex(const unsigned char *bytes, size_t count, char *text) {
    for (size_t i = 0; i < count; ++i) snprintf(text + i * 2, 3, "%02x", bytes[i]);
}
static int Code(int root, const char *relative, struct Service *service) {
    unsigned char *data = NULL;
    int status = ReadFile(root, relative, MAX_FILE, &service->code, &data);
    if (status) return status;
    if (!(service->code.mode & S_IXUSR) || service->code.bytes < sizeof(struct mach_header_64)) { free(data); return EACCES; }
    struct mach_header_64 header; memcpy(&header, data, sizeof(header));
    if (header.magic != MH_MAGIC_64 || (uint32_t)header.cputype != 0x100000c ||
        header.filetype != MH_EXECUTE || !header.ncmds || header.ncmds > 256 ||
        header.sizeofcmds > service->code.bytes - sizeof(header)) { free(data); return ENOTSUP; }
    size_t at = sizeof(header); unsigned uuids = 0, signatures = 0;
    for (unsigned i = 0; i < header.ncmds; ++i) {
        struct load_command command;
        if (at > sizeof(header) + header.sizeofcmds || sizeof(header) + header.sizeofcmds - at < sizeof(command)) { status = EINVAL; break; }
        memcpy(&command, data + at, sizeof(command));
        if (command.cmdsize < 8 || command.cmdsize & 7 || command.cmdsize > sizeof(header) + header.sizeofcmds - at) { status = EINVAL; break; }
        if (command.cmd == LC_UUID) {
            if (command.cmdsize != 24) { status = EINVAL; break; }
            ++uuids; Hex(data + at + 8, 16, service->info.executableUUID);
        } else if (command.cmd == LC_CODE_SIGNATURE) {
            if (command.cmdsize != sizeof(struct linkedit_data_command)) { status = EINVAL; break; }
            struct linkedit_data_command signature; memcpy(&signature, data + at, sizeof(signature));
            if (signature.dataoff > service->code.bytes || signature.datasize > service->code.bytes - signature.dataoff || signature.datasize < 12) { status = EINVAL; break; }
            ++signatures;
        }
        at += command.cmdsize;
    }
    if (!status && (at != sizeof(header) + header.sizeofcmds || uuids != 1 || signatures != 1)) status = EINVAL;
    free(data);
    if (!status) {
        service->info.executableBytes = service->code.bytes;
        Hex(service->code.digest, 32, service->info.executableSHA256);
    }
    /* Signature bounds/whole-file identity here, not native AMFI authenticity. */
    return status;
}
static int Path(char *output, size_t capacity, const char *format,
                const char *first, const char *second, const char *third) {
    int count = snprintf(output, capacity, format, first, second, third);
    return count > 0 && (size_t)count < capacity ? 0 : ENAMETOOLONG;
}
int VM27LargeBundleRegistryCreate(const char *root, VM27LargeBundleRegistry **result) {
    if (!result) return EINVAL; *result = NULL;
    if (!root || !*root || root[0] != '/' || strnlen(root, 4096) >= 4096) return EINVAL;
    char canonical[4096]; if (!realpath(root, canonical)) return errno;
    int fd = open(canonical, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY);
    if (fd < 0) return errno;
    struct stat state;
    if (fstat(fd, &state) || !Owned(&state, true) || (state.st_mode & 0077)) { close(fd); return EACCES; }
    VM27LargeBundleRegistry *registry = calloc(1, sizeof(*registry));
    if (!registry) { close(fd); return ENOMEM; }
    int status = pthread_mutex_init(&registry->lock, NULL);
    if (status) { free(registry); close(fd); return status; }
    registry->rootFD = fd; registry->rootStat = state; strcpy(registry->root, canonical);
    *result = registry; return 0;
}
void VM27LargeBundleRegistryRelease(VM27LargeBundleRegistry *registry) {
    if (!registry) return;
    /* Caller must join registry users; independent plans own duplicated FDs. */
    for (size_t i = 0; i < registry->count; ++i) VM27LWCRPolicyRelease(registry->services[i].policy);
    close(registry->rootFD); if (pthread_mutex_destroy(&registry->lock)) abort(); free(registry);
}
int VM27LargeBundleRegistryRegister(VM27LargeBundleRegistry *registry,
                              const char *absoluteBundlePath, uint64_t flags,
                              xpc_object_t requirement) {
    if (!registry || !absoluteBundlePath) return EINVAL;
    if (flags != 2) return ENOTSUP;
    size_t length = strlen(registry->root);
    if (strncmp(absoluteBundlePath, registry->root, length) || absoluteBundlePath[length] != '/') return EACCES;
    const char *bundle = absoluteBundlePath + length + 1;
    if (!Name(bundle, 255) || !Suffix(bundle, ".bundle")) return EINVAL;
    VM27LWCRPolicy *policy = NULL;
    int status = VM27LWCRPolicyCreate(requirement, &policy);
    if (status) return status;
    struct Service *staged = calloc(MAX_SERVICES, sizeof(*staged));
    if (!staged) { VM27LWCRPolicyRelease(policy); return ENOMEM; }
    char path[4096], bundleIdentifier[161] = {0}; struct FilePin bundleInfo = {0};
    status = Path(path, sizeof(path), "%s/Contents/Info.plist", bundle, "", "");
    if (!status) status = Plist(registry->rootFD, path, &bundleInfo, bundleIdentifier, NULL, false);
    if (!status) status = Path(path, sizeof(path), "%s/Contents/XPCServices", bundle, "", "");
    int fd = status ? -1 : OpenRelative(registry->rootFD, path, true);
    if (!status && fd < 0) status = errno;
    DIR *directory = fd >= 0 ? fdopendir(fd) : NULL;
    if (fd >= 0 && !directory) { status = errno; close(fd); }
    size_t count = 0;
    if (directory) for (;;) {
        errno = 0; struct dirent *entry = readdir(directory);
        if (!entry) { if (errno) status = errno; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        if (!Name(entry->d_name, 255) || !Suffix(entry->d_name, ".xpc")) { status = ENOTSUP; break; }
        if (count == MAX_SERVICES) { status = ENOSPC; break; }
        struct Service *service = &staged[count]; char executable[256] = {0};
        status = Path(path, sizeof(path), "%s/Contents/XPCServices/%s/Contents/Info.plist", bundle, entry->d_name, "");
        if (!status) status = Plist(registry->rootFD, path, &service->serviceInfo, service->info.serviceIdentifier, executable, true);
        if (!status) status = Path(path, sizeof(path), "%s/Contents/XPCServices/%s/Contents/MacOS/%s", bundle, entry->d_name, executable);
        if (!status) status = Code(registry->rootFD, path, service);
        if (!status) status = Path(service->info.executablePath, sizeof(service->info.executablePath), "%s/%s", registry->root, path, "");
        if (status) break;
        strcpy(service->info.bundleIdentifier, bundleIdentifier);
        service->info.flags = flags; service->bundleInfo = bundleInfo;
        for (size_t i = 0; i < count; ++i)
            if (!strcmp(staged[i].info.serviceIdentifier, service->info.serviceIdentifier)) status = EEXIST;
        if (status) break;
        ++count;
    }
    if (directory && closedir(directory) && !status) status = errno;
    if (!status && !count) status = ENOENT;
    for (size_t i = 0; !status && i < count; ++i) {
        VM27LargeServicePlan pending = {.rootFD = registry->rootFD,
            .rootStat = registry->rootStat, .service = staged[i]};
        strcpy(pending.root, registry->root);
        status = VM27LargeServicePlanVerify(&pending);
    }
    if (!status) {
        int lock = pthread_mutex_lock(&registry->lock);
        if (lock) status = lock;
        else {
            if (count > MAX_SERVICES - registry->count) status = ENOSPC;
            for (size_t i = 0; i < count; ++i) for (size_t j = 0; j < registry->count; ++j)
                if (!strcmp(staged[i].info.serviceIdentifier, registry->services[j].info.serviceIdentifier) ||
                    !strcmp(staged[i].info.bundleIdentifier, registry->services[j].info.bundleIdentifier)) status = EEXIST;
            if (!status) {
                for (size_t i = 0; i < count; ++i) {
                    if (!VM27LWCRPolicyRetain(policy)) abort();
                    staged[i].policy = policy; registry->services[registry->count++] = staged[i]; COUNT(gServices);
                }
                COUNT(gRegistrations);
            }
            if (pthread_mutex_unlock(&registry->lock)) abort();
        }
    }
    free(staged); VM27LWCRPolicyRelease(policy); return status;
}
int VM27LargeBundleRegistryCopyServicePlan(VM27LargeBundleRegistry *registry,
                                     const char *identifier,
                                     VM27LargeServicePlan **result) {
    if (!result) return EINVAL; *result = NULL;
    if (!registry || !Name(identifier, 160)) return EINVAL;
    int status = pthread_mutex_lock(&registry->lock); if (status) return status;
    status = ENOENT; VM27LargeServicePlan *plan = NULL;
    for (size_t i = 0; i < registry->count; ++i) if (!strcmp(registry->services[i].info.serviceIdentifier, identifier)) {
        plan = calloc(1, sizeof(*plan)); if (!plan) { status = ENOMEM; break; }
        plan->rootFD = fcntl(registry->rootFD, F_DUPFD_CLOEXEC, 3);
        if (plan->rootFD < 0) { status = errno; free(plan); plan = NULL; break; }
        plan->rootStat = registry->rootStat; plan->service = registry->services[i];
        strcpy(plan->root, registry->root);
        if (!VM27LWCRPolicyRetain(plan->service.policy)) abort();
        COUNT(gPlans); status = 0; break;
    }
    if (pthread_mutex_unlock(&registry->lock)) abort();
    if (!status) {
        status = VM27LargeServicePlanVerify(plan);
        if (status) VM27LargeServicePlanRelease(plan); else *result = plan;
    }
    return status;
}
void VM27LargeServicePlanRelease(VM27LargeServicePlan *plan) {
    if (!plan) return;
    close(plan->rootFD); VM27LWCRPolicyRelease(plan->service.policy); COUNT(gDestroyed); free(plan);
}
int VM27LargeServicePlanCopyInfo(const VM27LargeServicePlan *plan,
                                 VM27LargeServiceInfo *result) {
    if (!plan || !result) return EINVAL;
    *result = plan->service.info; return 0;
}
int VM27LargeServicePlanVerify(const VM27LargeServicePlan *plan) {
    COUNT(gVerify); if (!plan) return EINVAL;
    struct stat root;
    if (fstat(plan->rootFD, &root) || root.st_dev != plan->rootStat.st_dev || root.st_ino != plan->rootStat.st_ino || !Owned(&root, true) || (root.st_mode & 0077)) return ESTALE;
    int currentRoot = open(plan->root, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_DIRECTORY);
    if (currentRoot < 0) return errno;
    bool sameRoot = fstat(currentRoot, &root) == 0 && root.st_dev == plan->rootStat.st_dev && root.st_ino == plan->rootStat.st_ino;
    close(currentRoot);
    if (!sameRoot) return ESTALE;
    const struct FilePin *pins[] = {&plan->service.bundleInfo, &plan->service.serviceInfo, &plan->service.code};
    for (unsigned i = 0; i < 3; ++i) {
        struct FilePin actual;
        int status = ReadFile(plan->rootFD, pins[i]->relative, i == 2 ? MAX_FILE : 65536, &actual, NULL);
        if (status) return status;
        if (actual.device != pins[i]->device || actual.inode != pins[i]->inode || actual.mode != pins[i]->mode ||
            actual.bytes != pins[i]->bytes || memcmp(actual.digest, pins[i]->digest, 32)) return ESTALE;
    }
    return 0;
}
int VM27LargeServicePlanCheckReceivedMessage(const VM27LargeServicePlan *plan,
                                             xpc_object_t message,
                                             VM27LWCRMessageResult *result) {
    COUNT(gMessages);
    int status = VM27LargeServicePlanVerify(plan);
    if (status) { if (result) { memset(result, 0, sizeof(*result)); result->result = status; } return status; }
    return VM27LWCRPolicyCheckReceivedMessage(plan->service.policy, message, result);
}
void VM27LargeBundleRegistryCopyStats(VM27LargeBundleRegistryStats *result) {
    if (!result) return;
#define LOAD(field, variable) result->field = atomic_load_explicit(&(variable), memory_order_relaxed)
    LOAD(registrations, gRegistrations); LOAD(registeredServices, gServices);
    LOAD(plansCreated, gPlans); LOAD(plansDestroyed, gDestroyed);
    LOAD(verificationCalls, gVerify); LOAD(messageChecks, gMessages);
#undef LOAD
}
