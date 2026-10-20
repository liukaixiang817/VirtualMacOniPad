/* HOST-only candidate, not part of a compiled or installed product.
 * Include after the frozen Metal12 implementation in a fresh successor unit.
 * Only native completeResources commit call2ce88/return2ce8c may enter this
 * proper void(id,SEL) adapter. All native wait, resource-copy, completed-handler
 * and tail-token paths remain unchanged. A nil command buffer stays nil. */
static __attribute__((noinline)) void VM27ObservePagingBufferCandidateV1(
    const char *stage, uint64_t sample, id buffer, uintptr_t expectedBuffer) {
    int savedErrno = errno;
    @try {
        NSUInteger status = buffer ?
            ((NSUInteger (*)(id, SEL))objc_msgSend)(buffer, sel_registerName("status")) : 0;
        NSError *error = buffer ?
            ((id (*)(id, SEL))objc_msgSend)(buffer, sel_registerName("error")) : nil;
        char domain[2049], description[2049];
        ErrorTextV6(error.domain, domain);
        ErrorTextV6(error.localizedDescription, description);
        fprintf(stderr, "[Independent27GPU] native-paging-buffer sample=%llu stage=%s pid=%d callerRVA=0x2ce8c buffer=%p bufferPresent=%d callbackBufferMatches=%d status=%lu actualNSError=%p errorDomain=%s errorCode=%ld errorDescription=%s originalCommitCallsPlanned=1 originalCompletedHandlerWhole=1 eventWrites=0\n",
            (unsigned long long)sample, stage, (int)getpid(), buffer, buffer != nil,
            (uintptr_t)buffer == expectedBuffer, (unsigned long)status, error,
            domain, (long)error.code, description);
    } @catch (NSException *exception) {
        (void)exception;
        fprintf(stderr, "[Independent27GPU] native-paging-buffer sample=%llu stage=%s pid=%d observationException=1 originalCommitAndCompletedHandlerWhole=1 eventWrites=0\n",
            (unsigned long long)sample, stage, (int)getpid());
    }
    errno = savedErrno;
}
static __attribute__((noinline)) void VM27ObservePagingCompletedCandidateV1(
    id buffer, uintptr_t expectedBuffer, uint64_t sample, bool selected) {
    int savedErrno = errno;
    @try {
        NSUInteger status = ((NSUInteger (*)(id, SEL))objc_msgSend)(buffer, sel_registerName("status"));
        if (selected) VM27ObservePagingBufferCandidateV1("completed", sample, buffer, expectedBuffer);
        if (status == MTLCommandBufferStatusError) {
            static _Atomic(unsigned) errors = 0;
            unsigned ordinal = atomic_load_explicit(&errors, memory_order_relaxed);
            while (ordinal < 8 && !atomic_compare_exchange_weak_explicit(&errors, &ordinal, ordinal + 1,
                   memory_order_relaxed, memory_order_relaxed)) {}
            if (ordinal < 8 && !selected)
                VM27ObservePagingBufferCandidateV1("completed-error", sample, buffer, expectedBuffer);
        }
    } @catch (NSException *exception) {
        (void)exception; /* Observation cannot change the actual native callback. */
    }
    errno = savedErrno;
}
void VM27OwnedGPUTaskObservePagingCommitV1(id buffer, SEL ignored) {
    const void *caller = __builtin_return_address(0);
    int incomingErrno = errno;
    RequireV1(caller, 0x2ce8c);
    (void)ignored; /* The fresh C tail stub preserves x0 and LR, not a generated SEL. */
    static _Atomic(uint64_t) submissions = 0;
    uint64_t sample = atomic_fetch_add_explicit(&submissions, 1, memory_order_relaxed) + 1;
    bool selected = sample <= 16 || (sample <= (UINT64_C(1) << 20) && sample && !(sample & (sample - 1)));
    uintptr_t expectedBuffer = (uintptr_t)buffer; /* Never retain buffer in its own callbacks. */
    if (buffer) {
        RequireSignalMethodV10(buffer, "commit", "v", NULL, NULL);
        RequireSignalMethodV10(buffer, "status", @encode(NSUInteger), NULL, NULL);
        RequireSignalMethodV10(buffer, "addCompletedHandler:", "v", "@?", NULL);
        if (selected) {
            RequireSignalMethodV10(buffer, "error", "@", NULL, NULL);
            RequireSignalMethodV10(buffer, "addScheduledHandler:", "v", "@?", NULL);
            ((void (*)(id, SEL, MTLCommandBufferHandler))objc_msgSend)(buffer,
                sel_registerName("addScheduledHandler:"), ^(id<MTLCommandBuffer> actualBuffer) {
                    VM27ObservePagingBufferCandidateV1("scheduled", sample, actualBuffer, expectedBuffer);
                });
        }
        ((void (*)(id, SEL, MTLCommandBufferHandler))objc_msgSend)(buffer,
            sel_registerName("addCompletedHandler:"), ^(id<MTLCommandBuffer> actualBuffer) {
                VM27ObservePagingCompletedCandidateV1(actualBuffer, expectedBuffer, sample, selected);
            });
    }
    if (selected) VM27ObservePagingBufferCandidateV1("before-commit", sample, buffer, expectedBuffer);
    errno = incomingErrno;
    ((void (*)(id, SEL))objc_msgSend)(buffer, sel_registerName("commit"));
    int nativeErrno = errno;
    if (selected) {
        VM27ObservePagingBufferCandidateV1("after-commit", sample, buffer, expectedBuffer);
        if (buffer) dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC),
            dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
                VM27ObservePagingBufferCandidateV1("after-native-commit-delay", sample, buffer, expectedBuffer);
            });
    }
    errno = nativeErrno;
}
