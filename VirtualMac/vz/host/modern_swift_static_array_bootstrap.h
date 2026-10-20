#pragma once
#include <stdint.h>

// This is a private two-phase loader, not a Swift CN data export. No DIKit
// handle is returned until all three ISA slots and page protections are valid.
struct VM27StaticArrayBootstrapReport {
    uint32_t checks;
    uint32_t requiredImports;
    uint32_t factoryCalls;
    uint32_t requirementBindingsAuthenticated;
    uint32_t authenticatedBefore;
    uint32_t authenticatedAfter;
    uint32_t rollbackAuthenticated;
    uint32_t pageProtectionBefore;
    uint32_t pageMaximumBefore;
    uint32_t pageProtectionAfter;
    uint32_t pageMaximumAfter;
    uint32_t pagesChanged;
    uint32_t rolledBack;
    uint32_t protectionRestored;
    uint32_t handlePublished;
    uint32_t failureStage;
};

#ifdef __cplusplus
extern "C" {
#endif
// A deliberately invalid ISA placeholder. It must never be consumed by Swift.
extern const unsigned char VM27StaticArrayUninitializedISA[16];
// failureAfterWrite is a diagnostic-only rollback control: 0, 1, 2 or 3.
// On any failure, the owning isolated process must exit; the partially loaded
// framework must never be reused through global ObjC/Swift type discovery.
int VM27StaticArrayBootstrapLoad(const char *imagePath, const char *factoryPath,
                                unsigned failureAfterWrite,
                                VM27StaticArrayBootstrapReport *report,
                                void **publishedImage);
#ifdef __cplusplus
}
#endif
