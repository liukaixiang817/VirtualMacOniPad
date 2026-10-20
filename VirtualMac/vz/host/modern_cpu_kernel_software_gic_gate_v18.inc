// Include after a new lifecycle TU inheriting frozen Life14 definitions.
// Kernel native6 writes requested6f8=1c00/effective40b0=3c00. Native9 sets
// ICH_HCR_EL2 from40b0. Its dirty bit2 rebuild is (40b0&3c00)|(6f8&~2000).
// The SYS gate uses requested6f8 & (VM2068|VM2070) &1c00; exact native1
// constants ffffffffffffc3ff/1c00 preserve those trap bits for nativeISA1/2.
static bool SoftwareGICReadV18(InitializationAccess *a,
 VZKernelSoftwareGICTrapReceiptV18 *r,uint32_t off,uint64_t *out) {
 ++r->attemptedReads;
 bool ok=(off==0x6f8 || off==0x40b0) && InitializationOwned(a) &&
  a->cpu->nativeContext<=UINTPTR_MAX-off-8 &&
  VM27CPUSelfMappedRangeV1((const void *)(a->cpu->nativeContext+off),8,false,NULL) &&
  a->cpu->vm->ops.readMemory(a->cpu->vm->ops.context,
   (const void *)(a->cpu->nativeContext+off),8,out) && InitializationOwned(a);
 if(!ok){r->failedNativeOffset=off;r->status=VZ_KERNEL_CONTEXT_UNREADABLE;}
 return ok;
}
// For a future genuine Run wrapper: invoke only while it already holds the
// exact CPU operation guard. The external entry below acquires that guard.
static VZKernelStatus SoftwareGICCheckOwnedV18(VZKernelCPU *cpu,
 const VZKernelRunPendingRequestV14 *q,VZKernelSoftwareGICTrapReceiptV18 *r,
 VZKernelLifecycleResult *lifecycle) {
 VZKernelStatus s=PendingRequestOwnedV14(cpu,q);
 if(s==VZ_KERNEL_OK)s=Version(cpu,lifecycle);
 InitializationAccess a={cpu,NULL,lifecycle,VZ_KERNEL_OK};
 if(s==VZ_KERNEL_OK && !SoftwareGICReadV18(&a,r,0x6f8,&r->requestedICHControl))s=r->status;
 if(s==VZ_KERNEL_OK && !SoftwareGICReadV18(&a,r,0x40b0,&r->effectiveICHControl))s=r->status;
 if(s==VZ_KERNEL_OK) {
  r->actualFieldsRead=true;
  r->commonAndBothGroupTrapsEnabled=(r->requestedICHControl&UINT64_C(0x1c00))==UINT64_C(0x1c00) &&
   (r->effectiveICHControl&UINT64_C(0x1c00))==UINT64_C(0x1c00);
  r->nativeGICDisabled=!(r->requestedICHControl&1) && !(r->effectiveICHControl&1);
  if(!r->commonAndBothGroupTrapsEnabled || !r->nativeGICDisabled)s=VZ_KERNEL_UNSUPPORTED;
 }
 if(s==VZ_KERNEL_OK && !InitializationOwned(&a))s=a.boundaryStatus;
 if(a.boundaryStatus!=VZ_KERNEL_OK)s=a.boundaryStatus;
 r->status=s;return s;
}
VZKernelStatus VZKernelCPUCheckSoftwareGICTrapV18(VZKernelCPU *cpu,
 const VZKernelRunPendingRequestV14 *input,VZKernelSoftwareGICTrapReceiptV18 *out,
 VZKernelLifecycleResult *outLifecycle) {
 if(!cpu || !input || !out || !outLifecycle)return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelStatus s=BeginCPUOperation(cpu);
 if(s!=VZ_KERNEL_OK){if(s!=VZ_KERNEL_BUSY)EndOperation(&cpu->operationInProgress);return s;}
 const void *p[]={input,out,outLifecycle};const size_t n[]={sizeof(*input),sizeof(*out),sizeof(*outLifecycle)};
 if(!PendingRangesV14(cpu,p,n,3)){EndOperation(&cpu->operationInProgress);return VZ_KERNEL_BAD_ARGUMENT;}
 VZKernelRunPendingRequestV14 q=*input;VZKernelSoftwareGICTrapReceiptV18 r={0};
 VZKernelLifecycleResult lifecycle={0};r.failedNativeOffset=UINT32_MAX;
 s=SoftwareGICCheckOwnedV18(cpu,&q,&r,&lifecycle);CPUResult(cpu,&lifecycle);Finish(&lifecycle,s);
 *out=r;*outLifecycle=lifecycle;EndOperation(&cpu->operationInProgress);return s;
}
