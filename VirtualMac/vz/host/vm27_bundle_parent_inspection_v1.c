/* Parser provenance: modern_xpc_approved_code.c:46-140, SHA256
 * e57128b2cf8b6b9cd8109ac1da18f644af34e0b5b81bc5103bd570d5b5853ee7.
 * This independent version preserves its thin/ad-hoc format, full code-page,
 * embedded-slot and unsupported-format checks. The only signature extension
 * is authenticating required external slots 1/3 from actual guarded file FDs.
 * The old parser, provider symbols, kernel/native gates and frozen artifacts
 * are untouched. No constructors or execution/trust-policy API is present. */
#include "vm27_bundle_parent_inspection_v1.h"
#include <CommonCrypto/CommonDigest.h>
#include <CoreFoundation/CoreFoundation.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <mach-o/loader.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define VM27_PARENT_CODE_LIMIT_V1 (2U * 1024U * 1024U)
#define VM27_PARENT_INFO_LIMIT_V1 (64U * 1024U)
#define VM27_PARENT_RESOURCES_LIMIT_V1 (1024U * 1024U)
#define VM27_PARENT_DIRECTORY_LIMIT_V1 128U

typedef struct {
    int fd, parentFD;
    char name[NAME_MAX + 1];
    struct stat before;
} DirectoryV1;
typedef struct {
    int fd, parentFD;
    const char *name;
    struct stat before;
    unsigned char *data;
    size_t count;
} FileV1;

static uint32_t BE(const unsigned char *p) {
    return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 | (uint32_t)p[2] << 8 | p[3];
}
static bool Nonzero(const unsigned char *p, size_t count) {
    for (size_t i = 0; i < count; ++i) if (p[i]) return true;
    return false;
}
static void Hex(const unsigned char *p, size_t count, char *out) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < count; ++i) {
        out[2 * i] = digits[p[i] >> 4]; out[2 * i + 1] = digits[p[i] & 15];
    }
    out[2 * count] = 0;
}
static bool HexValid(const char *p, size_t count) {
    if (!p || strnlen(p, count + 1) != count) return false;
    for (size_t i = 0; i < count; ++i)
        if (!((p[i] >= '0' && p[i] <= '9') || (p[i] >= 'a' && p[i] <= 'f'))) return false;
    return true;
}
static bool Component(const char *name) {
    size_t count = name ? strnlen(name, NAME_MAX + 1) : 0;
    return count && count <= NAME_MAX && !strchr(name, '/') &&
        strcmp(name, ".") && strcmp(name, "..");
}
static bool SameObject(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino &&
        a->st_uid == b->st_uid && a->st_mode == b->st_mode;
}
static bool SameFile(const struct stat *a, const struct stat *b) {
    return SameObject(a, b) && a->st_size == b->st_size && a->st_nlink == b->st_nlink &&
        a->st_mtimespec.tv_sec == b->st_mtimespec.tv_sec &&
        a->st_mtimespec.tv_nsec == b->st_mtimespec.tv_nsec &&
        a->st_ctimespec.tv_sec == b->st_ctimespec.tv_sec &&
        a->st_ctimespec.tv_nsec == b->st_ctimespec.tv_nsec;
}
static int DirectoryAppend(DirectoryV1 *dirs, size_t *count, int parent,
                           const char *name, uid_t owner, bool exactOwner) {
    if (*count >= VM27_PARENT_DIRECTORY_LIMIT_V1) return E2BIG;
    int flags = O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC;
    int fd = parent < 0 ? open("/", flags) : openat(parent, name, flags);
    if (fd < 0) return errno;
    struct stat state;
    int status = fstat(fd, &state) ? errno : 0;
    if (!status && (!S_ISDIR(state.st_mode) || (state.st_mode & 0022) ||
        (exactOwner ? state.st_uid != owner : state.st_uid != owner && state.st_uid != 0)))
        status = EACCES;
    if (status) { close(fd); return status; }
    DirectoryV1 *entry = &dirs[*count];
    entry->fd = fd; entry->parentFD = parent; entry->before = state;
    if (name) memcpy(entry->name, name, strlen(name) + 1);
    ++*count; return 0;
}
static int OpenBundle(const char *path, uid_t owner, DirectoryV1 *dirs, size_t *count) {
    size_t bytes = path ? strnlen(path, 4096) : 0;
    if (bytes < 6 || bytes >= 4096 || path[0] != '/' || path[bytes - 1] == '/' ||
        strcmp(path + bytes - 4, ".app")) return EINVAL;
    int status = DirectoryAppend(dirs, count, -1, NULL, owner, false);
    const char *at = path + 1;
    while (!status && *at) {
        const char *slash = strchr(at, '/');
        size_t size = slash ? (size_t)(slash - at) : strlen(at);
        if (!size || size > NAME_MAX) return EINVAL;
        char name[NAME_MAX + 1]; memcpy(name, at, size); name[size] = 0;
        if (!Component(name)) return EINVAL;
        status = DirectoryAppend(dirs, count, dirs[*count - 1].fd, name, owner, !slash);
        at += size; if (*at == '/') ++at;
    }
    return status;
}
static int ReadFile(int parent, const char *name, uid_t owner, size_t limit, FileV1 *file) {
    file->parentFD = parent; file->name = name;
    file->fd = openat(parent, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (file->fd < 0) return errno;
    if (fstat(file->fd, &file->before)) return errno;
    const struct stat *st = &file->before;
    if (!S_ISREG(st->st_mode) || st->st_uid != owner || st->st_nlink != 1 ||
        (st->st_mode & 0022) || st->st_size <= 0) return EACCES;
    if ((uint64_t)st->st_size > limit) return EFBIG;
    file->count = (size_t)st->st_size;
    file->data = malloc(file->count);
    if (!file->data) return ENOMEM;
    size_t at = 0;
    while (at < file->count) {
        ssize_t actual = pread(file->fd, file->data + at, file->count - at, (off_t)at);
        if (actual < 0 && errno == EINTR) continue;
        if (actual <= 0) return actual < 0 ? errno : EIO;
        at += (size_t)actual;
    }
    return 0;
}
static int FilesStable(const FileV1 files[3]) {
    for (size_t i = 0; i < 3; ++i) {
        struct stat current, named;
        if (fstat(files[i].fd, &current) ||
            fstatat(files[i].parentFD, files[i].name, &named, AT_SYMLINK_NOFOLLOW)) return errno;
        if (!SameFile(&files[i].before, &current) || !SameFile(&files[i].before, &named)) return ESTALE;
    }
    return 0;
}
static int DirectoriesStable(const DirectoryV1 *dirs, size_t count) {
    for (size_t i = 0; i < count; ++i) {
        struct stat current, named;
        if (fstat(dirs[i].fd, &current)) return errno;
        if (!SameObject(&dirs[i].before, &current)) return ESTALE;
        if (dirs[i].parentFD >= 0) {
            if (fstatat(dirs[i].parentFD, dirs[i].name, &named, AT_SYMLINK_NOFOLLOW)) return errno;
            if (!SameObject(&dirs[i].before, &named)) return ESTALE;
        }
    }
    return 0;
}
static int CopyDictionary(const FileV1 *file, CFDictionaryRef *out) {
    CFDataRef bytes = CFDataCreate(NULL, file->data, (CFIndex)file->count);
    if (!bytes) return ENOMEM;
    CFErrorRef error = NULL;
    CFPropertyListRef value = CFPropertyListCreateWithData(NULL, bytes, kCFPropertyListImmutable, NULL, &error);
    CFRelease(bytes); if (error) CFRelease(error);
    if (!value || CFGetTypeID(value) != CFDictionaryGetTypeID()) {
        if (value) CFRelease(value); return EINVAL;
    }
    *out = (CFDictionaryRef)value; return 0;
}
static int Inspect(const FileV1 files[3], const char *name, VM27BundleParentInspectionV1 *out) {
    const unsigned char *data = files[0].data; size_t count = files[0].count;
    if (count < 32) return EINVAL;
    struct mach_header_64 header; memcpy(&header, data, sizeof(header));
    if (header.magic != MH_MAGIC_64 || (uint32_t)header.cputype != 0x100000c || header.filetype != MH_EXECUTE ||
        !header.ncmds || header.ncmds > 256 || header.sizeofcmds > count - sizeof(header)) return ENOTSUP;
    size_t at = 32, end = at + header.sizeofcmds, signatureAt = 0, signatureSize = 0;
    unsigned uuids = 0, signatures = 0;
    for (unsigned i = 0; i < header.ncmds; ++i) {
        struct load_command command;
        if (at > end || end - at < 8) return EINVAL;
        memcpy(&command, data + at, 8);
        if (command.cmdsize < 8 || command.cmdsize & 7 || command.cmdsize > end - at) return EINVAL;
        if (command.cmd == LC_UUID) {
            if (command.cmdsize != 24) return EINVAL;
            ++uuids; Hex(data + at + 8, 16, out->executableUUID);
        } else if (command.cmd == LC_CODE_SIGNATURE) {
            if (command.cmdsize != 16) return EINVAL;
            struct linkedit_data_command c; memcpy(&c, data + at, sizeof(c));
            signatureAt = c.dataoff; signatureSize = c.datasize; ++signatures;
        }
        at += command.cmdsize;
    }
    if (at != end || uuids != 1 || signatures != 1 || signatureAt < end || signatureAt > count ||
        signatureSize < 12 || signatureSize > count - signatureAt) return EINVAL;
    const unsigned char *signature = data + signatureAt;
    if (BE(signature) != 0xfade0cc0) return EINVAL;
    uint32_t length = BE(signature + 4), blobs = BE(signature + 8);
    if (length < 12 || length > signatureSize || blobs > 16 || blobs > (length - 12) / 8) return EINVAL;
    const unsigned char *cd = NULL, *xml = NULL;
    uint32_t cdSize = 0, xmlSize = 0;
    uint32_t types[16] = {0}, offsets[16] = {0}, sizes[16] = {0};
    for (unsigned i = 0; i < blobs; ++i) {
        uint32_t type = BE(signature + 12 + i * 8), start = BE(signature + 16 + i * 8);
        if (start < 12 + 8 * blobs || start > length || length - start < 8) return EINVAL;
        uint32_t size = BE(signature + start + 4);
        if (size < 8 || size > length - start) return EINVAL;
        for (unsigned j = 0; j < i; ++j)
            if (types[j] == type || (start < offsets[j] + sizes[j] && offsets[j] < start + size)) return EINVAL;
        types[i] = type; offsets[i] = start; sizes[i] = size;
        uint32_t magic = BE(signature + start);
        if (type == 0) { if (magic != 0xfade0c02) return EINVAL; cd = signature + start; cdSize = size; }
        else if (type == 2) { if (magic != 0xfade0c01) return EINVAL; }
        else if (type == 5) { if (magic != 0xfade7171) return EINVAL; xml = signature + start; xmlSize = size; }
        else if (type == 7) { if (magic != 0xfade7172) return EINVAL; }
        else if (type == 0x10000) { if (magic != 0xfade0b01 || size != 8) return ENOTSUP; }
        else return ENOTSUP;
    }
    if (!cd || cdSize < 88 || BE(cd + 8) != 0x20400 || BE(cd + 12) != 2 ||
        cd[36] != 32 || cd[37] != 2 || cd[38] != 0 || (cd[39] != 12 && cd[39] != 14) ||
        BE(cd + 40) || BE(cd + 44) || BE(cd + 48) || BE(cd + 52) || Nonzero(cd + 56, 8)) return ENOTSUP;
    uint32_t hashAt = BE(cd + 16), identifier = BE(cd + 20), special = BE(cd + 24), pages = BE(cd + 28), limit = BE(cd + 32);
    if (special < 3 || special > 7 || hashAt > cdSize || hashAt < 88 + special * 32 ||
        pages > (cdSize - hashAt) / 32 || identifier < 88 || identifier >= hashAt - special * 32 ||
        !memchr(cd + identifier, 0, hashAt - special * 32 - identifier) || !limit || limit != signatureAt) return EINVAL;
    size_t page = (size_t)1 << cd[39];
    if ((limit + page - 1) / page != pages) return EINVAL;
    unsigned char digest[32];
    for (unsigned i = 0; i < pages; ++i) {
        size_t begin = (size_t)i * page, bytes = limit - begin;
        if (bytes > page) bytes = page;
        CC_SHA256(data + begin, (CC_LONG)bytes, digest);
        if (memcmp(digest, cd + hashAt + i * 32, 32)) return EBADMSG;
    }
    for (unsigned slot = 1; slot <= special; ++slot) {
        const unsigned char *claimed = cd + hashAt - slot * 32;
        const unsigned char *blob = NULL; size_t bytes = 0;
        if (slot == 1 || slot == 3) {
            if (!Nonzero(claimed, 32)) return ENOTSUP;
            const FileV1 *external = &files[slot == 1 ? 1 : 2];
            blob = external->data; bytes = external->count;
        } else if (slot == 2 || slot == 5 || slot == 7) {
            for (unsigned i = 0; i < blobs; ++i)
                if (types[i] == slot) { blob = signature + offsets[i]; bytes = sizes[i]; }
        }
        if (blob) {
            CC_SHA256(blob, (CC_LONG)bytes, digest);
            if (memcmp(digest, claimed, 32)) return EBADMSG;
            if (slot == 1) { out->externalInfoSlotVerified = true; Hex(digest, 32, out->infoPlistSHA256); }
            if (slot == 3) { out->externalResourcesSlotVerified = true; Hex(digest, 32, out->codeResourcesSHA256); }
        } else if (Nonzero(claimed, 32)) return ENOTSUP;
    }
    for (unsigned i = 0; i < blobs; ++i)
        if ((types[i] == 2 || types[i] == 5 || types[i] == 7) && types[i] > special) return EINVAL;
    if (xml) {
        FileV1 entitlement = {.data = (unsigned char *)xml + 8, .count = xmlSize - 8};
        CFDictionaryRef dictionary = NULL;
        int status = CopyDictionary(&entitlement, &dictionary); if (status) return status;
        CFTypeRef value = CFDictionaryGetValue(dictionary, CFSTR("com.apple.private.virtualization.plugin"));
        out->signedPluginPresent = value != NULL;
        out->signedPluginIsBoolean = value && CFGetTypeID(value) == CFBooleanGetTypeID();
        out->signedPluginValue = out->signedPluginIsBoolean && CFBooleanGetValue((CFBooleanRef)value);
        CFRelease(dictionary);
    }
    CFDictionaryRef info = NULL, resources = NULL;
    int status = CopyDictionary(&files[1], &info);
    if (!status) status = CopyDictionary(&files[2], &resources);
    if (!status) {
        CFStringRef expected = CFStringCreateWithCString(NULL, name, kCFStringEncodingUTF8);
        CFTypeRef actual = CFDictionaryGetValue(info, CFSTR("CFBundleExecutable"));
        if (!expected || !actual || CFGetTypeID(actual) != CFStringGetTypeID() || !CFEqual(expected, actual)) status = EINVAL;
        if (expected) CFRelease(expected);
    }
    if (info) CFRelease(info); if (resources) CFRelease(resources);
    if (status) return status;
    CC_SHA256(cd, cdSize, digest); Hex(digest, 20, out->executableCDHash);
    CC_SHA256(data, (CC_LONG)count, digest); Hex(digest, 32, out->executableSHA256);
    out->executableBytes = count; out->infoPlistBytes = files[1].count; out->codeResourcesBytes = files[2].count;
    out->codePages = pages; out->codePagesVerified = out->embeddedSlotsVerified = true;
    out->infoExecutableNameMatched = out->codeResourcesIsDictionary = true;
    return 0;
}

int VM27BundleParentInspectV1(const VM27BundleParentConfigurationV1 *configuration,
                            VM27BundleParentInspectionV1 *result) {
    if (!result) return EINVAL;
    memset(result, 0, sizeof(*result));
    if (!configuration || !Component(configuration->executableName) ||
        !HexValid(configuration->reviewedExecutableSHA256, 64) ||
        !HexValid(configuration->reviewedExecutableCDHash, 40)) return EINVAL;
    DirectoryV1 dirs[VM27_PARENT_DIRECTORY_LIMIT_V1] = {{0}}; size_t directoryCount = 0;
    FileV1 files[3] = {{.fd = -1}, {.fd = -1}, {.fd = -1}};
    VM27BundleParentInspectionV1 inspected = {0};
    int status = OpenBundle(configuration->bundlePath, configuration->expectedOwnerUID, dirs, &directoryCount);
    int bundleFD = !status ? dirs[directoryCount - 1].fd : -1;
    if (!status) status = ReadFile(bundleFD, configuration->executableName,
        configuration->expectedOwnerUID, VM27_PARENT_CODE_LIMIT_V1, &files[0]);
    if (!status) status = ReadFile(bundleFD, "Info.plist", configuration->expectedOwnerUID,
        VM27_PARENT_INFO_LIMIT_V1, &files[1]);
    if (!status) status = DirectoryAppend(dirs, &directoryCount, bundleFD, "_CodeSignature",
        configuration->expectedOwnerUID, true);
    if (!status) status = ReadFile(dirs[directoryCount - 1].fd, "CodeResources", configuration->expectedOwnerUID,
        VM27_PARENT_RESOURCES_LIMIT_V1, &files[2]);
    if (!status) status = Inspect(files, configuration->executableName, &inspected);
    if (!status && (strcmp(inspected.executableSHA256, configuration->reviewedExecutableSHA256) ||
        strcmp(inspected.executableCDHash, configuration->reviewedExecutableCDHash))) status = EACCES;
    if (!status) status = FilesStable(files);
    if (!status) status = DirectoriesStable(dirs, directoryCount);
    for (size_t i = 0; i < 3; ++i) {
        free(files[i].data);
        if (files[i].fd >= 0 && close(files[i].fd) && !status) status = errno;
    }
    while (directoryCount) if (close(dirs[--directoryCount].fd) && !status) status = errno;
    if (!status) {
        inspected.formatVersion = 1; inspected.actualOwnerUID = configuration->expectedOwnerUID;
        inspected.descriptorsAndNamesStable = true;
        /* No code path can promote unperformed whole-resource/native checks. */
        *result = inspected;
    }
    return status;
}
