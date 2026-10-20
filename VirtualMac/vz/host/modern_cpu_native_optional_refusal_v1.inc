/* Include after the actual Factory public lifecycle. No native context is exposed. */
#include "modern_cpu_optional_abi_v1.h"
hv_return_t VM27CPUFactoryRefuseOptionalFeatureV1(hv_vcpu_t identity) {
 if(!PublicBeginV6())return Mach(VZ_KERNEL_BUSY);
 VM27CPUFactoryBorrowV2 *borrow=NULL;
 hv_return_t status=VM27CPUFactoryBorrowAcquireV2(identity,&borrow);
 if(!status) {
  VM27CPUFactoryViewV2 view={0};
  status=VM27CPUFactoryBorrowViewV2(borrow,&view);
  if(!status)status=Mach(VZ_KERNEL_UNSUPPORTED);
  /* Refusal cannot hide a failed release: preserve the actual borrow for drain. */
  hv_return_t release=VM27CPUFactoryBorrowReleaseV2(borrow);
  if(release){PublicDeferredBorrowV6=borrow;status=release;}
 }
 PublicEndV6();return status;
}
