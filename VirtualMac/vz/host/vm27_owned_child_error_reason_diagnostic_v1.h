#pragma once
#ifdef __cplusplus
extern "C" {
#endif
/* Exact selected original two-pointer, explicit-output Error construction ABI.
 * The selected callers do not consume x0/x8 as a returned object. */
__attribute__((visibility("default")))
void VM27OwnedChildBuildErrorReasonDiagnosticV1(void *destination, void *movedString);
#ifdef __cplusplus
}
#endif
