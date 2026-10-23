#pragma once
/* Exact Runtime176 ->179 lifecycle-only transition. Audit verifies whole guest
 * CPU/GPU/device providers and VMM sections. No broad version fallback. */
#define VM27HibernateRuntimeMatchesV4 VM27HibernateRuntimeMatchesInheritedV7
#include "vm27_hibernate_runtime_compat_v7.h"
#undef VM27HibernateRuntimeMatchesV4
static BOOL VM27HibernateRuntimeMatchesV4(NSData *saved,NSData *current) {
 if(VM27HibernateRuntimeMatchesInheritedV7(saved,current))return YES;
 if(![saved isKindOfClass:NSData.class] || saved.length!=32 || current.length!=32)return NO;
 static const uint8_t expectedSaved[32]={141,220,156,167,161,216,58,142,132,88,224,3,65,193,246,73,55,49,164,253,69,98,82,6,196,244,120,96,114,232,18,22};
 static const uint8_t expectedCurrent[32]={231,41,236,154,8,139,67,3,28,58,110,36,67,132,135,140,140,227,251,227,1,141,127,43,20,25,132,86,251,172,22,41};
 return !memcmp(saved.bytes,expectedSaved,32) && !memcmp(current.bytes,expectedCurrent,32);
}
