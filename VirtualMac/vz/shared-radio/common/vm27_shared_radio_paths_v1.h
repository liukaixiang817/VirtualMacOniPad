#ifndef VM27_SHARED_RADIO_PATHS_V1_H
#define VM27_SHARED_RADIO_PATHS_V1_H
#include <stdbool.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#define VM27_SHARED_RADIO_HOST_DIRECTORY_V1 "/var/mobile/Library/VirtualMacSharedRadio-v1"
#define VM27_SHARED_RADIO_BLE_SOCKET_V1 VM27_SHARED_RADIO_HOST_DIRECTORY_V1 "/bluetooth-btvc-v1.sock"
#define VM27_SHARED_RADIO_CLASSIC_SOCKET_V1 VM27_SHARED_RADIO_HOST_DIRECTORY_V1 "/bluetooth-classic-v1.sock"
#define VM27_SHARED_RADIO_PEER_SOCKET_V1 VM27_SHARED_RADIO_HOST_DIRECTORY_V1 "/bluetooth-peer-v1.sock"
static inline bool VM27SharedRadioPrepareHostDirectoryV1(void) {
    struct stat st;
    if (lstat(VM27_SHARED_RADIO_HOST_DIRECTORY_V1,&st)) {
        if (errno!=ENOENT || mkdir(VM27_SHARED_RADIO_HOST_DIRECTORY_V1,0700)) return false;
        if (lstat(VM27_SHARED_RADIO_HOST_DIRECTORY_V1,&st)) return false;
    }
    return S_ISDIR(st.st_mode) && st.st_uid==geteuid() && !(st.st_mode&0077);
}
#endif
