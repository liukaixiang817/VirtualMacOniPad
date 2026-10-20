#include "vm27_owned_gpu_parent_inspection_v1.h"
/* Keep the frozen signature parser and guarded FD/name reader byte-for-byte.
 * Separate hidden names avoid exporting the historical inspection APIs from
 * the new task shim. No original source file is changed. */
#define VM27BundleChildInspectV1 VM27GPUFrozenChildInspectV1
#define VM27BundleParentInspectInheritedChildV1 VM27GPUFrozenParentInspectV1
#include "vm27_bundle_child_inspection_v1.c"
#undef VM27BundleParentInspectInheritedChildV1
#undef VM27BundleChildInspectV1

int VM27OwnedGPUInspectActualParentV1(const char *bundlePath, const char *name,
    uid_t owner, const char *kernelCD, VM27BundleParentInspectionV1 *result) {
    if (!result) return EINVAL;
    memset(result, 0, sizeof(*result));
    if (!Component(name) || !HexValid(kernelCD, 40)) return EINVAL;
    DirectoryV1 dirs[VM27_PARENT_DIRECTORY_LIMIT_V1] = {{0}};
    size_t count = 0;
    FileV1 files[3] = {{.fd = -1}, {.fd = -1}, {.fd = -1}};
    VM27BundleParentInspectionV1 inspected = {0};
    int status = OpenChildBundleV1(bundlePath, owner, dirs, &count);
    if (!status) status = DirectoryAppend(dirs, &count, dirs[count - 1].fd,
        "Contents", owner, true);
    int contents = !status ? dirs[count - 1].fd : -1;
    if (!status) status = DirectoryAppend(dirs, &count, contents,
        "MacOS", owner, true);
    if (!status) status = ReadFile(dirs[count - 1].fd, name, owner,
        8U * 1024U * 1024U, &files[0]);
    if (!status && !(files[0].before.st_mode & S_IXUSR)) status = EACCES;
    if (!status) status = ReadFile(contents, "Info.plist", owner,
        VM27_PARENT_INFO_LIMIT_V1, &files[1]);
    if (!status) status = DirectoryAppend(dirs, &count, contents,
        "_CodeSignature", owner, true);
    if (!status) status = ReadFile(dirs[count - 1].fd, "CodeResources", owner,
        VM27_PARENT_RESOURCES_LIMIT_V1, &files[2]);
    if (!status) status = Inspect(files, name, &inspected);
    if (!status && strcmp(inspected.executableCDHash, kernelCD)) status = EACCES;
    if (!status) status = FilesStable(files);
    if (!status) status = DirectoriesStable(dirs, count);
    for (size_t i = 0; i < 3; ++i) {
        free(files[i].data);
        if (files[i].fd >= 0 && close(files[i].fd) && !status) status = errno;
    }
    while (count) if (close(dirs[--count].fd) && !status) status = errno;
    if (!status) {
        inspected.formatVersion = 1;
        inspected.actualOwnerUID = owner;
        inspected.descriptorsAndNamesStable = true;
        *result = inspected;
    }
    return status;
}

