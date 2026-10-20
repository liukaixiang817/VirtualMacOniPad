#ifndef VM27_OWNED_QGA_CONNECTION_LEASE_V3_H
#define VM27_OWNED_QGA_CONNECTION_LEASE_V3_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
typedef enum {VM27QGAValidV3=0,VM27QGAInvalidV3,VM27QGAStaleV3,VM27QGAExpiredV3,VM27QGANativeFailureV3,VM27QGACancelledV3} VM27QGAResultV3;
/* Private caller serializes operations on its actual QGA queue. The duplicate
 * and socket identity belong exclusively to one real SDK connection epoch. */
typedef struct {
    int ownedFD,originalFD,originalStatusFlags;
    bool statusChanged;
    pid_t pid;
    dev_t device;
    ino_t inode;
    uint64_t epoch,generation,deadlineNS;
    bool active;
} VM27OwnedQGALeaseV3;

#ifdef __cplusplus
extern "C" {
#endif
__attribute__((visibility("hidden"))) VM27QGAResultV3 VM27OwnedQGALeaseCreateV3(VM27OwnedQGALeaseV3 *,int actualFD,uint64_t actualEpoch,uint64_t actualGeneration);
__attribute__((visibility("hidden"))) VM27QGAResultV3 VM27OwnedQGALeaseCheckV3(const VM27OwnedQGALeaseV3 *,int actualFD,uint64_t actualEpoch,uint64_t actualGeneration);
__attribute__((visibility("hidden"))) VM27QGAResultV3 VM27OwnedQGALeaseSendV3(VM27OwnedQGALeaseV3 *,int actualFD,uint64_t actualEpoch,uint64_t actualGeneration,const void *,size_t);
__attribute__((visibility("hidden"))) VM27QGAResultV3 VM27OwnedQGALeaseCloseV3(VM27OwnedQGALeaseV3 *,bool shutdownActualOldSocket);
#ifdef __cplusplus
}
#endif
#endif
