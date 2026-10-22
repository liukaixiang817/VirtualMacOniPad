#ifndef VM27_OWNED_APPLICATION_LOG_V2_H
#define VM27_OWNED_APPLICATION_LOG_V2_H
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

/* Match the existing child descriptor contract on a fresh installation too.
 * Repair only the current user's single-link regular file, never a symlink,
 * another owner's file or another inode. Darwin may inherit the temporary
 * directory group; normalize our own descriptor to the caller's group.
 * Preserve all existing log bytes. */
static inline int VM27OpenOwnedApplicationLogV2(const char *path,
                                               uid_t owner, gid_t group) {
    int fd = open(path, O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW |
                        O_CLOEXEC | O_NONBLOCK, 0600);
    if (fd < 0) return -1;
    struct stat before, after, named;
    int failure = 0;
    if (fstat(fd, &before)) failure = errno;
    else if (!S_ISREG(before.st_mode) || before.st_nlink != 1 ||
             before.st_uid != owner) failure = EACCES;
    else if (before.st_gid != group && fchown(fd, (uid_t)-1, group)) failure = errno;
    else if (fchmod(fd, 0600)) failure = errno;
    else if (fstat(fd, &after) || lstat(path, &named)) failure = errno;
    else if (!S_ISREG(named.st_mode) || named.st_dev != after.st_dev ||
             named.st_ino != after.st_ino || after.st_nlink != 1 ||
             after.st_uid != owner || after.st_gid != group ||
             (after.st_mode & 07777) != 0600) failure = EACCES;
    if (!failure && fd < 3) {
        int copy = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (copy < 0) failure = errno;
        else { close(fd); fd = copy; }
    }
    if (failure) { close(fd); errno = failure; return -1; }
    return fd;
}
#endif
