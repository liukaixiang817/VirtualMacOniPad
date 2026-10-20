/* Included only by the V3 disk observer after its exact Child admission and
 * verified inherited-stderr writer. The native callback/context are opaque:
 * no callback substitution, queue operation, context dereference or retry. */
#include <dispatch/dispatch.h>

/* Apple XNU bsd/sys/kdebug_private.h, user-space SPI declaration:
 * https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/kdebug_private.h
 * Native libsystem_kernel export is independently present in the frozen
 * current-native-header-export-index-v3. All four payload arguments are 64-bit. */
extern int kdebug_trace(uint32_t, uint64_t, uint64_t, uint64_t, uint64_t);
_Static_assert(sizeof(uint64_t) == 8 && sizeof(uintptr_t) == 8 && sizeof(int) == 4,
               "actual arm64e kdebug_trace ABI");

enum { CompletionSyncV1 = 0, CompletionStatusV1, CompletionSplitV1,
       CompletionPackedV1, CompletionKindsV1, CompletionDetailedPairsV1 = 8 };
typedef struct {
    _Atomic uint64_t started, returned, firstNS, lastEntryNS, lastReturnNS;
} CompletionCountersV1;
typedef struct {
    uint64_t ordinal, entryNS;
    unsigned kind;
    uintptr_t callerRVA, queue, context, callback;
    uint32_t debugid;
    uint64_t args[4];
    bool selected, detailed;
} CompletionTokenV1;
static CompletionCountersV1 CompletionCountsV1[CompletionKindsV1];

static const char *CompletionKindV1(unsigned kind) {
    static const char *names[] = {"dispatch-sync", "guest-status", "used-split", "used-packed"};
    return kind < CompletionKindsV1 ? names[kind] : "invalid";
}
static void CompletionEmitV1(const char *stage, const CompletionTokenV1 *token,
                             uint64_t now, uint64_t nativeStart, int result, int nativeErrno) {
    char text[1024];
    bool returned = nativeStart != 0;
    int bytes = snprintf(text, sizeof(text),
        "[VM27OwnedCompletionV1] stage=%s kind=%s ordinal=%llu pid=%d "
        "callerRVA=0x%llx entryNS=%llu nowNS=%llu nativeStartNS=%llu nativeDurationKnown=%u "
        "nativeElapsedNS=%llu queue=0x%llx context=0x%llx callback=0x%llx "
        "debugid=0x%x arg1=0x%llx arg2=0x%llx arg3=0x%llx arg4=0x%llx "
        "nativeResultKnown=%u nativeResult=%d nativeErrnoCaptured=%d "
        "rawPointersOnly=1 contextMemoryNotRead=1 callbackSubstituted=0 originalDelegateExactlyOnceSourceContract=1\n",
        stage, CompletionKindV1(token->kind), (unsigned long long)token->ordinal, (int)getpid(),
        (unsigned long long)token->callerRVA, (unsigned long long)token->entryNS,
        (unsigned long long)now, (unsigned long long)nativeStart,
        returned && now >= nativeStart ? 1U : 0U,
        (unsigned long long)(returned && now >= nativeStart ? now - nativeStart : 0),
        (unsigned long long)token->queue, (unsigned long long)token->context,
        (unsigned long long)token->callback, token->debugid,
        (unsigned long long)token->args[0], (unsigned long long)token->args[1],
        (unsigned long long)token->args[2], (unsigned long long)token->args[3],
        returned && token->kind != CompletionSyncV1 ? 1U : 0U, result, nativeErrno);
    EmitBytesV2(text, bytes);
}
static void CompletionBeginV1(CompletionTokenV1 *token) {
    CompletionCountersV1 *counts = &CompletionCountsV1[token->kind];
    token->entryNS = NowV2();
    token->ordinal = atomic_fetch_add_explicit(&counts->started, 1, memory_order_relaxed) + 1;
    token->detailed = token->ordinal <= CompletionDetailedPairsV1;
    uint64_t zero = 0;
    (void)atomic_compare_exchange_strong_explicit(&counts->firstNS, &zero, token->entryNS,
                                                 memory_order_relaxed, memory_order_relaxed);
    atomic_store_explicit(&counts->lastEntryNS, token->entryNS, memory_order_relaxed);
    if (token->detailed) CompletionEmitV1("entry", token, token->entryNS, 0, 0, 0);
}
static void CompletionEndV1(const CompletionTokenV1 *token, uint64_t nativeStart,
                            uint64_t nativeEnd, int result, int nativeErrno) {
    CompletionCountersV1 *counts = &CompletionCountsV1[token->kind];
    atomic_store_explicit(&counts->lastReturnNS, nativeEnd, memory_order_relaxed);
    atomic_fetch_add_explicit(&counts->returned, 1, memory_order_relaxed);
    if (token->detailed) CompletionEmitV1("return", token, nativeEnd, nativeStart, result, nativeErrno);
}
static void CompletionSummaryV1(unsigned second) {
    uint64_t now = NowV2();
    for (unsigned kind = 0; kind < CompletionKindsV1; ++kind) {
        CompletionCountersV1 *counts = &CompletionCountsV1[kind];
        uint64_t started = atomic_load_explicit(&counts->started, memory_order_relaxed);
        uint64_t returned = atomic_load_explicit(&counts->returned, memory_order_relaxed);
        char text[1024];
        int bytes = snprintf(text, sizeof(text),
            "[VM27OwnedCompletionV1] stage=watch-summary watchIteration=%u kind=%s "
            "started=%llu returned=%llu outstandingFromCounterSnapshot=%llu nowNS=%llu firstNS=%llu "
            "lastEntryNS=%llu lastReturnNS=%llu countersNonAtomicSnapshot=1 "
            "allDisksAtExactChildSites=1 noGuestCompletionConclusionFromMissingRecords=1\n",
            second, CompletionKindV1(kind), (unsigned long long)started,
            (unsigned long long)returned, (unsigned long long)(started > returned ? started - returned : 0),
            (unsigned long long)now,
            (unsigned long long)atomic_load_explicit(&counts->firstNS, memory_order_relaxed),
            (unsigned long long)atomic_load_explicit(&counts->lastEntryNS, memory_order_relaxed),
            (unsigned long long)atomic_load_explicit(&counts->lastReturnNS, memory_order_relaxed));
        EmitBytesV2(text, bytes);
    }
}

void VM27OwnedChildCompletionDispatchSyncV1(dispatch_queue_t queue, void *context,
                                          dispatch_function_t originalCallback) {
    int incoming = errno;
    void *caller = ptrauth_strip(__builtin_return_address(0), ptrauth_key_return_address);
    void *callback = (void *)ptrauth_strip(originalCallback, ptrauth_key_function_pointer);
    DiskAdmissionV2 gate = {0}, callbackGate = {0};
    CompletionTokenV1 token = {.kind = CompletionSyncV1};
    token.selected = !AdmissionV2(caller, &gate) && gate.callerRVA == 0x36fbb4 &&
        !AdmissionV2(callback, &callbackGate) && callbackGate.callerRVA == 0x370990;
    uint64_t nativeStart = 0;
    if (token.selected) {
        token.callerRVA = gate.callerRVA; token.queue = (uintptr_t)queue;
        token.context = (uintptr_t)context; token.callback = (uintptr_t)callback;
        CompletionBeginV1(&token); nativeStart = NowV2();
    }
    errno = incoming;
    dispatch_sync_f(queue, context, originalCallback);
    int nativeErrno = errno;
    if (token.selected) CompletionEndV1(&token, nativeStart, NowV2(), 0, nativeErrno);
    errno = nativeErrno;
}

int VM27OwnedChildCompletionKdebugTraceV1(uint32_t debugid, uint64_t arg1, uint64_t arg2,
                                         uint64_t arg3, uint64_t arg4) {
    int incoming = errno;
    void *caller = ptrauth_strip(__builtin_return_address(0), ptrauth_key_return_address);
    DiskAdmissionV2 gate = {0};
    CompletionTokenV1 token = {.args = {arg1, arg2, arg3, arg4}, .debugid = debugid};
    if (!AdmissionV2(caller, &gate)) {
        token.callerRVA = gate.callerRVA;
        if (debugid == 0x0620000c && gate.callerRVA == 0x1f87d4)
            { token.selected = true; token.kind = CompletionStatusV1; }
        else if (debugid == 0x06200004 && gate.callerRVA == 0x2702f8)
            { token.selected = true; token.kind = CompletionSplitV1; }
        else if (debugid == 0x06200004 && gate.callerRVA == 0x26ccdc)
            { token.selected = true; token.kind = CompletionPackedV1; }
    }
    uint64_t nativeStart = 0;
    if (token.selected) { CompletionBeginV1(&token); nativeStart = NowV2(); }
    errno = incoming;
    int result = kdebug_trace(debugid, arg1, arg2, arg3, arg4);
    int nativeErrno = errno;
    if (token.selected) CompletionEndV1(&token, nativeStart, NowV2(), result, nativeErrno);
    errno = nativeErrno; return result;
}
