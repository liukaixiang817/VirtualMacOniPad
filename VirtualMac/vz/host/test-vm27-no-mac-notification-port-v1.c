#include "vm27_no_mac_notification_port_v1.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
static unsigned checks, failures, callbackCalls, contextsFreed;
static void check(int ok) { ++checks; if (!ok) ++failures; }
static void callback(uint32_t code, const void *data, uint32_t bytes, void *context) {
    (void)code; (void)data; (void)bytes; (void)context; ++callbackCalls;
}
int main(void) {
    for (unsigned round = 0; round < 128; ++round) {
        uint64_t *context = malloc(sizeof(*context)); check(context != NULL);
        if (!context) break;
        *context = round;
        check(VM27NoWatcherV1() == ENOTSUP); check(errno == ENOTSUP);
        for (uint32_t code = 1502; code <= 1503; ++code) {
            check(VM27NoRegisterV1(callback, code, context) == ENOTSUP);
            check(errno == ENOTSUP);
            check(VM27NoRemoveV1(callback, code, context) == ENOTSUP);
            check(errno == ENOTSUP);
            check(*context == round);
        }
        VM27HostNoteErrorsV1 report;
        check(VM27CopyHostNoteErrorsV1(&report) == 0);
        check(report.watcherRequests == round+1);
        check(report.registerRequests == (round+1)*2);
        check(report.removeRequests == (round+1)*2);
        check(report.lastError == ENOTSUP && report.lastCode == 1503);
        check(report.borrowedContextAddress == (uintptr_t)context);
        check(report.callbacksStored == 0 && report.callbacksInvoked == 0);
        check(callbackCalls == 0);
        check(VM27NoRegisterV1(NULL, 1502, context) == EINVAL);
        check(VM27NoRemoveV1(callback, 1501, context) == EINVAL);
        check(VM27NoRegisterV1(callback, 1503, NULL) == EINVAL);
        check(VM27CopyHostNoteErrorsV1(NULL) == EINVAL);
        free(context); ++contextsFreed;
    }
    check(contextsFreed == 128); check(callbackCalls == 0);
    printf("{\"checks\":%u,\"failures\":%u,\"contextsFreed\":%u,\"callbacks\":%u,\"registrations\":0,\"VZCalls\":0}\n",
           checks, failures, contextsFreed, callbackCalls);
    return failures ? 1 : 0;
}
