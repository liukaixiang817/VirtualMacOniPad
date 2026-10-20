#include "vm27_bundle_child_inspection_v1.h"
/* Reuse the full frozen reader. Its historical flat-parent entry is hidden
 * under a distinct name; its real parser and FD/name checks are unchanged. */
__attribute__((visibility("hidden")))
int VM27BundleParentInspectInheritedChildV1(const VM27BundleParentConfigurationV1 *,
                                         VM27BundleParentInspectionV1 *);
#define VM27BundleParentInspectV1 VM27BundleParentInspectInheritedChildV1
#include "vm27_bundle_parent_inspection_v1.c"
#undef VM27BundleParentInspectV1

static int OpenChildBundleV1(const char *path, uid_t owner,
                             DirectoryV1 *dirs, size_t *count) {
    size_t bytes = path ? strnlen(path, 4096) : 0;
    if (bytes < 6 || bytes >= 4096 || path[0] != '/' || path[bytes - 1] == '/' ||
        strcmp(path + bytes - 4, ".xpc")) return EINVAL;
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

int VM27BundleChildInspectV1(const VM27BundleParentConfigurationV1 *c,
                            VM27BundleParentInspectionV1 *result) {
    if (!result) return EINVAL;
    memset(result, 0, sizeof(*result));
    if (!c || !Component(c->executableName) ||
        !HexValid(c->reviewedExecutableSHA256, 64) ||
        !HexValid(c->reviewedExecutableCDHash, 40)) return EINVAL;
    DirectoryV1 dirs[VM27_PARENT_DIRECTORY_LIMIT_V1] = {{0}};
    size_t count = 0;
    FileV1 files[3] = {{.fd = -1}, {.fd = -1}, {.fd = -1}};
    VM27BundleParentInspectionV1 inspected = {0};
    int status = OpenChildBundleV1(c->bundlePath, c->expectedOwnerUID, dirs, &count);
    if (!status) status = DirectoryAppend(dirs, &count, dirs[count - 1].fd,
        "Contents", c->expectedOwnerUID, true);
    int contents = !status ? dirs[count - 1].fd : -1;
    if (!status) status = DirectoryAppend(dirs, &count, contents,
        "MacOS", c->expectedOwnerUID, true);
    if (!status) status = ReadFile(dirs[count - 1].fd, c->executableName,
        c->expectedOwnerUID, 8U * 1024U * 1024U, &files[0]);
    if (!status && !(files[0].before.st_mode & S_IXUSR)) status = EACCES;
    if (!status) status = ReadFile(contents, "Info.plist", c->expectedOwnerUID,
        VM27_PARENT_INFO_LIMIT_V1, &files[1]);
    if (!status) status = DirectoryAppend(dirs, &count, contents,
        "_CodeSignature", c->expectedOwnerUID, true);
    if (!status) status = ReadFile(dirs[count - 1].fd, "CodeResources", c->expectedOwnerUID,
        VM27_PARENT_RESOURCES_LIMIT_V1, &files[2]);
    if (!status) status = Inspect(files, c->executableName, &inspected);
    if (!status && (strcmp(inspected.executableSHA256, c->reviewedExecutableSHA256) ||
        strcmp(inspected.executableCDHash, c->reviewedExecutableCDHash))) status = EACCES;
    if (!status) status = FilesStable(files);
    if (!status) status = DirectoriesStable(dirs, count);
    for (size_t i = 0; i < 3; ++i) {
        free(files[i].data);
        if (files[i].fd >= 0 && close(files[i].fd) && !status) status = errno;
    }
    while (count) if (close(dirs[--count].fd) && !status) status = errno;
    if (!status) {
        inspected.formatVersion = 1; inspected.actualOwnerUID = c->expectedOwnerUID;
        inspected.descriptorsAndNamesStable = true; *result = inspected;
    }
    return status;
}
