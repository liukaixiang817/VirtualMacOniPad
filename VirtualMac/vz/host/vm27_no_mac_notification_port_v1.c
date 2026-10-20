#include "vm27_no_mac_notification_port_v1.h"
#include <errno.h>
#include <pthread.h>
static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static VM27HostNoteErrorsV1 errors;
uint32_t VM27NoWatcherV1(void) {
    pthread_mutex_lock(&mutex);
    ++errors.watcherRequests;
    errors.lastError = ENOTSUP;
    pthread_mutex_unlock(&mutex);
    errno = ENOTSUP;
    return ENOTSUP;
}
static int refuse(VM27BorrowedHostNoteCallbackV1 callback, uint32_t code,
                  void *context, int registration) {
    if (!callback || !context || (code != 1502 && code != 1503)) {
        errno = EINVAL;
        return EINVAL;
    }
    pthread_mutex_lock(&mutex);
    if (registration) ++errors.registerRequests; else ++errors.removeRequests;
    errors.lastCode = code;
    errors.lastError = ENOTSUP;
    /* Numeric diagnostics are not a retained/dereferenceable context. */
    errors.borrowedContextAddress = (uintptr_t)context;
    pthread_mutex_unlock(&mutex);
    errno = ENOTSUP;
    return ENOTSUP;
}
int VM27NoRegisterV1(VM27BorrowedHostNoteCallbackV1 callback, uint32_t code, void *context) {
    return refuse(callback, code, context, 1);
}
int VM27NoRemoveV1(VM27BorrowedHostNoteCallbackV1 callback, uint32_t code, void *context) {
    return refuse(callback, code, context, 0);
}
int VM27CopyHostNoteErrorsV1(VM27HostNoteErrorsV1 *report) {
    if (!report) { errno = EINVAL; return EINVAL; }
    pthread_mutex_lock(&mutex);
    *report = errors;
    pthread_mutex_unlock(&mutex);
    return 0;
}
