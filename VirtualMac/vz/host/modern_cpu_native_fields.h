// Fixed, read-only values from this module's own native CPU. This is not a
// replacement modern context page, Apple USER/VIEW, or architectural reset.
#ifndef VZ_MODERN_CPU_NATIVE_FIELDS_H
#define VZ_MODERN_CPU_NATIVE_FIELDS_H
#include "modern_cpu_kernel_lifecycle.h"

#define VZ_KERNEL_NATIVE_FIELD_COUNT 78U
#define VZ_KERNEL_NATIVE_MARKER_FIRST 74U

typedef enum {
    VZ_NATIVE_SCALAR = 1,
    VZ_NATIVE_SIMD,
    VZ_NATIVE_SYSTEM,
    VZ_NATIVE_PHYSICAL_CPSR,
    VZ_NATIVE_SYNCHRONIZATION
} VZKernelNativeFieldDomain;

// A bridge kind describes an established *value* correspondence, never the
// validity of injecting a raw pointer into an original modern consumer.
typedef enum {
    VZ_NATIVE_MODERN_SCALAR_VALUE = 1,
    VZ_NATIVE_MODERN_SIMD_VALUE,
    VZ_NATIVE_MODERN_DIRECT_SYSTEM_VALUE,
    VZ_NATIVE_MODERN_REQUIRES_VIEW,
    VZ_NATIVE_MODERN_METADATA_ONLY
} VZKernelModernValueKind;

typedef struct {
    uint32_t index;
    VZKernelNativeFieldDomain domain;
    uint32_t logicalIdentifier;
    uint32_t nativeOffset;
    uint32_t bytes;
    VZKernelModernValueKind modernValueKind;
    uint64_t nativeReadinessMask;
    char name[24];
} VZKernelNativeField;

typedef struct {
    VZKernelNativeField field;
    uint64_t low, high;
    // False when the old ordinary getter would first perform native op8.
    // The raw bytes remain a physical cache observation; no op8 is called.
    bool nativeLogicalValueReady;
    bool modernValueCorrespondenceEstablished;
} VZKernelNativeObservation;

typedef struct {
    uint64_t ownerThread, generation, nativeVersionBefore, nativeVersionAfter;
    uint32_t count;
    bool versionStable, synchronizationMarkersStable;
    VZKernelNativeObservation observations[VZ_KERNEL_NATIVE_FIELD_COUNT];
} VZKernelNativeSnapshot;

typedef struct {
    uint32_t attemptedReads, completedFields, failedFieldIndex;
    bool versionReadBefore, versionReadAfter, markersReadBefore, markersReadAfter;
    bool markersStable;
} VZKernelNativeReadDiagnostics;

// Index 0..77 is a fixed audited whitelist. No arbitrary offset API exists.
// On failure this function leaves out unchanged.
VZKernelStatus VZKernelNativeFieldAt(uint32_t index, VZKernelNativeField *out);

// Exact native version, module TLS, live owner/generation and fixed self-reads
// are required. No native operation is made. Output commits only after both
// version checks and all four unchanged synchronization markers. Same-thread
// cleanup ownership is retained on every failure. This module has no run API.
// Caller must not alias output storage to kernel pages or any live handle.
VZKernelStatus VZKernelCPUReadNativeFields(VZKernelCPU *, VZKernelNativeSnapshot *,
    VZKernelNativeReadDiagnostics *, VZKernelLifecycleResult *);
#endif
