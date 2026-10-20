#pragma once
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
struct VM27VZCVWInfo { size_t size,stride;uint32_t flags,extraInhabitants,type; };
// Genuine VZ27 only: type1 CachingOptions,2 EFISignature,3 ViewAdaptor.
int VM27VZCVWQuery(const void *,struct VM27VZCVWInfo *);
void swift_cvw_destroy(void *,const void *);
void *swift_cvw_initWithCopy(void *,const void *,const void *);
void *swift_cvw_assignWithCopy(void *,const void *,const void *);
void *swift_cvw_assignWithTake(void *,void *,const void *);
void *swift_cvw_initializeBufferWithCopyOfBuffer(void *,const void *,const void *);
unsigned swift_cvw_enumFn_getEnumTag(const void *,const void *);
#ifdef __cplusplus
}
#endif
