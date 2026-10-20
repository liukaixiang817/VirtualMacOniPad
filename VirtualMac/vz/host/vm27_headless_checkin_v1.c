#include "vm27_headless_checkin_v1.h"
#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdatomic.h>
#include <unistd.h>

/* All state belongs to this helper image in this process. No system LS API,
 * daemon, host title, filesystem, VM, CPU, GPU or native trap is used. */
static pthread_mutex_t StateLock = PTHREAD_MUTEX_INITIALIZER;
static CFDictionaryRef State;
static pid_t StatePID;
static uid_t StateUID;
static _Atomic(pid_t) EntryPID;
typedef struct { unsigned nodes; size_t bytes; } Budget;

/* A fork child rejects the inherited registration before touching the parent
 * mutex, so a fork concurrent with a locked parent cannot deadlock this API. */
static bool SameProcess(void) {
    pid_t pid = getpid(), expected = 0;
    atomic_compare_exchange_strong_explicit(&EntryPID, &expected, pid,
        memory_order_relaxed, memory_order_relaxed);
    return atomic_load_explicit(&EntryPID, memory_order_relaxed) == pid;
}

static bool Charge(Budget *b, size_t bytes) {
    if (++b->nodes > 512 || bytes > 65536 - b->bytes) return false;
    b->bytes += bytes;
    return true;
}

/* The input contract requires live CF objects. Depth/node/byte budgets bound
 * the tree before CF's deep-copy API. A cyclic array/dictionary fails at the
 * depth bound; arbitrary invalid addresses are not a CF input contract. */
static bool Valid(CFTypeRef v, unsigned depth, Budget *b) {
    if (!v || depth > 8) return false;
    CFTypeID type = CFGetTypeID(v);
    if (type == CFStringGetTypeID()) {
        CFIndex length = CFStringGetLength(v);
        return length >= 0 && length <= 4096 && Charge(b, (size_t)length * 2);
    }
    if (type == CFDataGetTypeID()) {
        CFIndex length = CFDataGetLength(v);
        return length >= 0 && length <= 65536 && Charge(b, (size_t)length);
    }
    if (type == CFNumberGetTypeID()) {
        double value = 0;
        return (!CFNumberIsFloatType(v) ||
            (CFNumberGetValue(v, kCFNumberFloat64Type, &value) && isfinite(value))) && Charge(b, 8);
    }
    if (type == CFBooleanGetTypeID()) return Charge(b, 1);
    if (type == CFDateGetTypeID()) return isfinite(CFDateGetAbsoluteTime(v)) && Charge(b, 8);
    if (type == CFArrayGetTypeID()) {
        CFIndex count = CFArrayGetCount(v);
        if (count < 0 || count > 256 || !Charge(b, (size_t)count * 8)) return false;
        for (CFIndex i = 0; i < count; ++i)
            if (!Valid(CFArrayGetValueAtIndex(v, i), depth + 1, b)) return false;
        return true;
    }
    if (type == CFDictionaryGetTypeID()) {
        CFIndex count = CFDictionaryGetCount(v);
        if (count < 0 || count > 256 || !Charge(b, (size_t)count * 16)) return false;
        const void *keys[256], *values[256];
        CFDictionaryGetKeysAndValues(v, keys, values);
        for (CFIndex i = 0; i < count; ++i)
            if (!keys[i] || CFGetTypeID(keys[i]) != CFStringGetTypeID() ||
                !Valid(keys[i], depth + 1, b) || !Valid(values[i], depth + 1, b)) return false;
        return true;
    }
    return false;
}

static CFTypeRef Fail(int error) { errno = error; return NULL; }

CFTypeRef _LSApplicationCheckIn(int32_t session, CFDictionaryRef information) {
    if (session != -2) return Fail(EINVAL); /* No information read on this path. */
    if (!SameProcess()) return Fail(EPERM);
    if (!information || CFGetTypeID(information) != CFDictionaryGetTypeID()) return Fail(EINVAL);
    Budget b = {0, 0};
    if (!Valid(information, 0, &b)) return Fail(E2BIG);
    CFPropertyListRef copy = CFPropertyListCreateDeepCopy(kCFAllocatorDefault, information, kCFPropertyListImmutable);
    if (!copy || CFGetTypeID(copy) != CFDictionaryGetTypeID()) {
        if (copy) CFRelease(copy);
        return Fail(ENOMEM);
    }
    pid_t pid = getpid(); uid_t uid = geteuid();
    int rc = pthread_mutex_lock(&StateLock);
    if (rc) { CFRelease(copy); return Fail(rc); }
    if (State) {
        bool owner = StatePID == pid && StateUID == uid;
        bool equal = owner && CFEqual(CFDictionaryGetValue(State, CFSTR("BundleInfo")), copy);
        CFTypeRef result = equal ? State : NULL;
        rc = pthread_mutex_unlock(&StateLock); CFRelease(copy);
        if (rc) return Fail(rc);
        if (!owner) return Fail(EPERM);
        if (!equal) return Fail(EALREADY);
        return result;
    }
    int64_t p = pid, u = uid;
    CFNumberRef pidObject = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &p);
    CFNumberRef uidObject = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &u);
    CFUUIDRef instance = CFUUIDCreate(kCFAllocatorDefault);
    const void *keys[] = {CFSTR("Scope"), CFSTR("PID"), CFSTR("UID"), CFSTR("Instance"), CFSTR("BundleInfo")};
    const void *values[] = {CFSTR("VM27 private headless application check-in"), pidObject, uidObject, instance, copy};
    CFDictionaryRef record = pidObject && uidObject && instance ? CFDictionaryCreate(kCFAllocatorDefault,
        keys, values, 5, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks) : NULL;
    if (pidObject) CFRelease(pidObject);
    if (uidObject) CFRelease(uidObject);
    if (instance) CFRelease(instance);
    CFRelease(copy);
    if (record) { StatePID = pid; StateUID = uid; State = record; }
    rc = pthread_mutex_unlock(&StateLock);
    if (rc) return Fail(rc);
    if (!record) return Fail(ENOMEM);
    return record; /* Borrowed: State retains it until this process exits. */
}

int32_t VM27CopyPrivateHeadlessCheckInState(CFDictionaryRef *output) {
    if (!output || *output) { errno = EINVAL; return -50; }
    if (!SameProcess()) { errno = EPERM; return -600; }
    int rc = pthread_mutex_lock(&StateLock);
    if (rc) { errno = rc; return -1; }
    bool registered = State != NULL;
    bool owner = registered && StatePID == getpid() && StateUID == geteuid();
    CFDictionaryRef record = owner ? CFRetain(State) : NULL;
    rc = pthread_mutex_unlock(&StateLock);
    if (rc) { if (record) CFRelease(record); errno = rc; return -1; }
    if (!record) { errno = registered ? EPERM : ENOENT; return -600; }
    *output = record;
    return 0;
}
