#include "modern_cpu_native_scalar_bridge.h"
#include <string.h>

bool VZKernelCPUReadModernScalarValue(VZKernelCPU *cpu, const VZ27ScalarReadOps *ops,
    uint32_t field, uint64_t *out, VZKernelNativeScalarBridgeResult *r) {
    if (!r) return false;
    memset(r, 0, sizeof(*r)); r->nativeReadStatus = VZ_KERNEL_BAD_ARGUMENT;
    if (!cpu || !ops || !out) return false;
    if (field >= VZ27_SCALAR_READ_COUNT) {
        r->nativeReadStatus = VZ_KERNEL_UNSUPPORTED;
        return false;
    }
    VZKernelNativeSnapshot native;
    VZKernelNativeReadDiagnostics d; VZKernelLifecycleResult lifecycle;
    r->nativeReadStatus = VZKernelCPUReadNativeFields(cpu, &native, &d, &lifecycle);
    if (r->nativeReadStatus != VZ_KERNEL_OK) return false;
    r->snapshotRead = true; r->ownerThread = native.ownerThread;
    r->generation = native.generation; r->nativeContextVersion = native.nativeVersionAfter;
    if (ops->thread != native.ownerThread) return false;
    // The bounded helper reads only these 34 explicit value slots. This is a
    // local private input cache with neither a version nor a kernel pointer;
    // it is never returned to a VMM or used with the public modern wrapper.
    _Alignas(16) unsigned char cache[VZ27_SCALAR_CACHE_BYTES] = {0};
    for (unsigned i = 0; i < VZ27_SCALAR_READ_COUNT; ++i) {
        const VZKernelNativeObservation *o = &native.observations[i];
        if (o->field.logicalIdentifier != i || o->field.domain != VZ_NATIVE_SCALAR ||
            o->field.modernValueKind != VZ_NATIVE_MODERN_SCALAR_VALUE ||
            !o->modernValueCorrespondenceEstablished || o->high ||
            o->field.nativeOffset > sizeof(cache) - o->field.bytes) return false;
        memcpy(cache + o->field.nativeOffset, &o->low, o->field.bytes);
    }
    uint64_t value = 0;
    r->boundedHelperBridgeInvoked = true;
    r->original27HelperAccepted = VZ27ScalarReadCache(ops, cache, sizeof(cache), field, &value);
    if (!r->original27HelperAccepted) return false;
    r->valueEqualsNative = value == native.observations[field].low;
    if (!r->valueEqualsNative) return false;
    *out = value;
    return true;
}
