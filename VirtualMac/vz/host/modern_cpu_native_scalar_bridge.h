// A private value route from a genuine independently owned native CPU to the
// audited original27 scalar leaf. No Apple USER/context/exit is supplied.
#ifndef VZ_MODERN_CPU_NATIVE_SCALAR_BRIDGE_H
#define VZ_MODERN_CPU_NATIVE_SCALAR_BRIDGE_H
#include "modern_cpu_native_fields.h"
#include "modern_cpu_scalar_read_bridge.h"
typedef struct {
    VZKernelStatus nativeReadStatus;
    bool snapshotRead, boundedHelperBridgeInvoked, original27HelperAccepted;
    bool valueEqualsNative;
    uint64_t ownerThread, generation, nativeContextVersion;
} VZKernelNativeScalarBridgeResult;

// field 0..33 only. Native physical CPSR/VIEW, raw get_context publication,
// extended vector state and all setters remain unsupported. Caller owns
// separate output/result objects. originalOps must refer only to the exact
// genuine27 3810..3934 leaf with the existing immutable identity/byte gate.
// Result output is diagnostic; *out commits only after verified parity.
bool VZKernelCPUReadModernScalarValue(VZKernelCPU *, const VZ27ScalarReadOps *,
    uint32_t field, uint64_t *out, VZKernelNativeScalarBridgeResult *);
#endif
