#include "vm27_no_mac_haptic_port_v1.h"
#include <errno.h>
#include <pthread.h>
static pthread_mutex_t mutex=PTHREAD_MUTEX_INITIALIZER;
static VM27HapticRejectV1 rejected;
uint32_t VM27NoHapticV1(void) {
    pthread_mutex_lock(&mutex);
    ++rejected.statusRequests;
    pthread_mutex_unlock(&mutex);
    errno=ENOTSUP;
    return (uint32_t)ENOTSUP;
}
int VM27RejectHapticV1(uint32_t status,uint64_t device,int64_t pattern,uint64_t options) {
    if (status!=(uint32_t)ENOTSUP) { errno=EINVAL; return EINVAL; }
    pthread_mutex_lock(&mutex);
    ++rejected.patternRequests;
    rejected.rejectedStatus=status;
    rejected.device=device;
    rejected.pattern=pattern;
    rejected.options=options;
    pthread_mutex_unlock(&mutex);
    errno=ENOTSUP;
    return ENOTSUP;
}
int VM27CopyHapticRejectV1(VM27HapticRejectV1 *report) {
    if (!report) { errno=EINVAL; return EINVAL; }
    pthread_mutex_lock(&mutex);
    *report=rejected;
    pthread_mutex_unlock(&mutex);
    return 0;
}
