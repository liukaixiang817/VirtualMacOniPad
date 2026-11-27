#pragma once
#include <stdbool.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
extern int proc_pidpath(int, void *, uint32_t);

static inline bool VM27OwnedWiFiAdmissionFailureV1(const char *stage) {
    int saved=errno;static unsigned observations;
    unsigned count=__atomic_load_n(&observations,__ATOMIC_RELAXED);
    while(count<4) {
        if(__atomic_compare_exchange_n(&observations,&count,count+1,false,__ATOMIC_RELAXED,__ATOMIC_RELAXED)) {
            fprintf(stderr,"[OwnedWiFiAdmission] rejected stage=%s errno=%d pathsAndCredentialsLogged=0\n",stage,saved);break;
        }
    }
    errno=saved;return false;
}

static inline bool VM27OwnedWiFiPeerAllowedV1(int fd, uid_t expectedUID,
                                             const char *expectedExecutable) {
    uid_t uid = (uid_t)-1; gid_t gid; pid_t pid = 0;
    int type = 0; socklen_t size = sizeof(pid), typeSize = sizeof(type);
    struct sockaddr_un address; socklen_t addressSize = sizeof(address);
    char path[4096], actual[PATH_MAX], expected[PATH_MAX];
    if(getpeername(fd,(void *)&address,&addressSize))return VM27OwnedWiFiAdmissionFailureV1("peer-address");
    if(address.sun_family!=AF_UNIX)return VM27OwnedWiFiAdmissionFailureV1("peer-family");
    if(getsockopt(fd,SOL_SOCKET,SO_TYPE,&type,&typeSize)||type!=SOCK_STREAM)return VM27OwnedWiFiAdmissionFailureV1("socket-type");
    if(getpeereid(fd,&uid,&gid)||uid!=expectedUID)return VM27OwnedWiFiAdmissionFailureV1("peer-uid");
    if(getsockopt(fd,SOL_LOCAL,LOCAL_PEERPID,&pid,&size)||size!=sizeof(pid)||pid<=1)return VM27OwnedWiFiAdmissionFailureV1("peer-pid");
    if(proc_pidpath(pid,path,sizeof(path))<=0)return VM27OwnedWiFiAdmissionFailureV1("peer-executable");
    if(!realpath(path,actual))return VM27OwnedWiFiAdmissionFailureV1("peer-canonical-path");
    if(!realpath(expectedExecutable,expected))return VM27OwnedWiFiAdmissionFailureV1("expected-canonical-path");
    if(strcmp(actual,expected))return VM27OwnedWiFiAdmissionFailureV1("executable-mismatch");
    return true;
}
