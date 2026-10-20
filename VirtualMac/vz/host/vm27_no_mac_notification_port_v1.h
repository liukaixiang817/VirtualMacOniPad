#ifndef VM27_NO_MAC_NOTIFICATION_PORT_V1_H
#define VM27_NO_MAC_NOTIFICATION_PORT_V1_H
#include <stdint.h>
typedef void (*VM27BorrowedHostNoteCallbackV1)(uint32_t, const void *, uint32_t, void *);
typedef struct {
    uint64_t watcherRequests, registerRequests, removeRequests;
    uint32_t lastCode, lastError;
    uintptr_t borrowedContextAddress;
    uint64_t callbacksStored, callbacksInvoked;
} VM27HostNoteErrorsV1;
/* UIKit profile: error status, never a boolean "watcher present" result.
 * The ported original caller must reject this capability without updating
 * the original macOS screen-observation state. */
uint32_t VM27NoWatcherV1(void);
/* Borrowed callback/context; never stored, retained, invoked, or registered. */
int VM27NoRegisterV1(VM27BorrowedHostNoteCallbackV1, uint32_t code, void *context);
int VM27NoRemoveV1(VM27BorrowedHostNoteCallbackV1, uint32_t code, void *context);
int VM27CopyHostNoteErrorsV1(VM27HostNoteErrorsV1 *report);
#endif
