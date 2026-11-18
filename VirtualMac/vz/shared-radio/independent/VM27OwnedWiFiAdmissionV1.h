#pragma once
#include <stdbool.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
extern int proc_pidpath(int, void *, uint32_t);

static inline bool VM27OwnedWiFiPeerAllowedV1(int fd, uid_t expectedUID,
                                             const char *expectedExecutable) {
    uid_t uid = (uid_t)-1; gid_t gid; pid_t pid = 0;
    int type = 0; socklen_t size = sizeof(pid), typeSize = sizeof(type);
    struct sockaddr_un address; socklen_t addressSize = sizeof(address);
    char path[4096], actual[PATH_MAX], expected[PATH_MAX];
    return !getpeername(fd, (void *)&address, &addressSize) && address.sun_family == AF_UNIX &&
        !getsockopt(fd, SOL_SOCKET, SO_TYPE, &type, &typeSize) && type == SOCK_STREAM &&
        !getpeereid(fd, &uid, &gid) && uid == expectedUID &&
        !getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &pid, &size) && size == sizeof(pid) && pid > 1 &&
        proc_pidpath(pid, path, sizeof(path)) > 0 &&
        realpath(path, actual) && realpath(expectedExecutable, expected) && !strcmp(actual, expected);
}
