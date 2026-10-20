// Include after Life14 or a new TU inheriting its exact registry definitions.
// Current kernel80ac878..c898 consumes all 64 bits of its x0 slot mask; op10
// writes record+10 cancellation before issuing genuine thread wakeups.
struct VZKernelCPUWakeOwnerV17 {
 VZKernelCPUBorrowV5 *borrow;
 VZKernelCPU *cpu;
 VZKernelRunPendingRequestV14 identity;
 pthread_mutex_t mutex;
 pthread_cond_t idle;
 pthread_t ownerPthread,signalPthread;
 unsigned inFlight,queued;
 bool draining,idleInitialized;
};
bool VZKernelReadPhysicalCounterFrequencyV17(void *context,uint64_t *out) {
 (void)context;if(!out)return false;
#if defined(__aarch64__)
 uint64_t value;__asm__ volatile("mrs %0, cntfrq_el0":"=r"(value));
 if(!value || value>UINT32_MAX)return false;*out=value;return true;
#else
 return false;
#endif
}
static bool WakeOutputV17(VZKernelCPUWakeOwnerV17 *o,const void *p,size_t n) {
 return VZKernelCPUOutputRangeDisjointV12(p,n) &&
  PendingOutputDisjointV3(p,n,o,sizeof(*o));
}
static VZKernelStatus WakeIdentityV17(VZKernelCPUWakeOwnerV17 *o) {
 VZKernelCPU *cpu=o->cpu;VZKernelVM *vm=cpu->vm;
 Lock(&RegistryMutex);Lock(&vm->mutex);
 VZKernelCPURegistryEntryV5 *e=cpu->registryEntry;
 bool live=RegisteredVM==vm && BorrowRegisteredLockedV5(o->borrow) && vm->live && cpu->live &&
  e->creationComplete && e->identityIssued && e->published && !e->draining;
 bool exact=live && o->identity.schemaVersion==1 && !o->identity.reserved &&
  o->identity.validatedKernelProfile==vm->ops.validatedKernelProfile &&
  o->identity.validatedKernelProfile==VZ_KERNEL_PROFILE_IPADOS_16_1_1 &&
  o->identity.nativeHVISA==vm->nativeHVISA && VZKernelNativeISAHasValidatedContextV2(vm->nativeHVISA) &&
  o->identity.expectedVMEpoch==vm->generation && o->identity.expectedPublicIdentity==e->publicIdentity &&
  o->identity.expectedOwnerThread==cpu->owner && o->identity.expectedCPUGeneration==cpu->generation &&
  o->identity.expectedReturnedSlotWord==cpu->returnedSlot && cpu->returnedSlot<64;
 Unlock(&vm->mutex);Unlock(&RegistryMutex);
 return !live?VZ_KERNEL_NOT_LIVE:exact?VZ_KERNEL_OK:VZ_KERNEL_BAD_ARGUMENT;
}
static VZKernelStatus WakeVersionV17(VZKernelCPUWakeOwnerV17 *o) {
 VZKernelCPU *cpu=o->cpu;uint64_t version=0;
 VZKernelStatus s=WakeIdentityV17(o);if(s!=VZ_KERNEL_OK)return s;
 if(cpu->nativeContext>UINTPTR_MAX-0x4008 ||
  !VM27CPUSelfMappedRangeV1((const void *)(cpu->nativeContext+0x4000),8,false,NULL) ||
  !cpu->vm->ops.readMemory(cpu->vm->ops.context,(const void *)(cpu->nativeContext+0x4000),8,&version))
  return VZ_KERNEL_CONTEXT_UNREADABLE;
 s=WakeIdentityV17(o);if(s!=VZ_KERNEL_OK)return s;
 return version==VZ_KERNEL_NATIVE_CONTEXT_VERSION?VZ_KERNEL_OK:VZ_KERNEL_CONTEXT_VERSION_MISMATCH;
}
VZKernelStatus VZKernelCPUWakeOwnerCreateV17(const VZKernelRunPendingRequestV14 *q,
 VZKernelCPUWakeOwnerV17 **out) {
 if(!q || !out || !VZKernelCPUOutputRangeDisjointV12(q,sizeof(*q)) ||
  !VZKernelCPUOutputRangeDisjointV12(out,sizeof(*out)) ||
  !PendingOutputDisjointV3(q,sizeof(*q),out,sizeof(*out)))return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelCPUWakeOwnerV17 *o=calloc(1,sizeof(*o));if(!o)return VZ_KERNEL_OUT_OF_MEMORY;
 o->identity=*q;o->ownerPthread=pthread_self();
 if(pthread_mutex_init(&o->mutex,NULL)){free(o);return VZ_KERNEL_OUT_OF_MEMORY;}
 if(pthread_cond_init(&o->idle,NULL)) {
  pthread_mutex_destroy(&o->mutex);free(o);return VZ_KERNEL_OUT_OF_MEMORY;
 }
 o->idleInitialized=true;
 VZKernelStatus s=VZKernelCPUBorrowIdentityV5(q->expectedPublicIdentity,&o->borrow);
 if(s==VZ_KERNEL_OK)s=VZKernelCPUBorrowHandleV5(o->borrow,&o->cpu);
 bool entered=false;
 if(s==VZ_KERNEL_OK){s=BeginCPUOperation(o->cpu);entered=s!=VZ_KERNEL_BUSY;}
 if(s==VZ_KERNEL_OK)s=PendingRequestOwnedV14(o->cpu,q);
 if(s==VZ_KERNEL_OK && q->expectedReturnedSlotWord>=64)s=VZ_KERNEL_BAD_ARGUMENT;
 VZKernelLifecycleResult r={0};if(s==VZ_KERNEL_OK)s=Version(o->cpu,&r);
 if(entered)EndOperation(&o->cpu->operationInProgress);
 if(s==VZ_KERNEL_OK){*out=o;return s;}
 o->draining=true;
 if(o->borrow && VZKernelCPUReleaseBorrowV5(o->borrow)!=VZ_KERNEL_OK){*out=o;return VZ_KERNEL_NATIVE_ERROR;}
 pthread_cond_destroy(&o->idle);pthread_mutex_destroy(&o->mutex);free(o);return s;
}
VZKernelStatus VZKernelCPUWakeOwnerSignalV17(VZKernelCPUWakeOwnerV17 *o,
 const VZKernelRunPendingRequestV14 *input,VZKernelCPUWakeReceiptV17 *out) {
 if(!o || !input || !out)return VZ_KERNEL_BAD_ARGUMENT;
 // The scheduler's actual attachment pins o across this entry. Reject aliases
 // before copying the identity or publishing a receipt into caller memory.
 if(!WakeOutputV17(o,input,sizeof(*input)) || !WakeOutputV17(o,out,sizeof(*out)) ||
  !PendingOutputDisjointV3(input,sizeof(*input),out,sizeof(*out)))return VZ_KERNEL_BAD_ARGUMENT;
 VZKernelRunPendingRequestV14 q=*input;VZKernelCPUWakeReceiptV17 r={0};
 Lock(&o->mutex);
 if(o->draining){Unlock(&o->mutex);r.status=VZ_KERNEL_NOT_LIVE;r.callbackDraining=true;*out=r;return r.status;}
 if(memcmp(&q,&o->identity,sizeof(q))){Unlock(&o->mutex);r.status=VZ_KERNEL_BAD_ARGUMENT;*out=r;return r.status;}
 // Native10 callbacks remain outside this mutex. Concurrent sources queue;
 // a synchronous recursive signal cannot wait for its own unfinished call.
 if((o->inFlight && pthread_equal(o->signalPthread,pthread_self())) || o->queued==UINT_MAX) {
  Unlock(&o->mutex);r.status=VZ_KERNEL_BUSY;*out=r;return r.status;
 }
 ++o->queued;Unlock(&o->mutex);
 // Count this admitted caller before dropping the lock: Drain must retain
 // the owner during identity validation as well as while cond_wait sleeps.
 VZKernelStatus s=WakeIdentityV17(o);
 Lock(&o->mutex);
 while(s==VZ_KERNEL_OK && !o->draining && o->inFlight) {
  if(pthread_cond_wait(&o->idle,&o->mutex))s=VZ_KERNEL_NATIVE_ERROR;
 }
 --o->queued;
 if(s!=VZ_KERNEL_OK || o->draining) {
  if(o->draining){s=VZ_KERNEL_NOT_LIVE;r.callbackDraining=true;}
  Unlock(&o->mutex);r.status=s;*out=r;return s;
 }
 o->inFlight=1;o->signalPthread=pthread_self();Unlock(&o->mutex);
 // The CPU, generation, publication and actual context version may have
 // changed while queued. Revalidate all of them before the real native10.
 s=WakeVersionV17(o);
 if(s==VZ_KERNEL_OK) {
  r.versionVerified=r.identityVerified=true;r.nativeSlotMask=UINT64_C(1)<<o->identity.expectedReturnedSlotWord;
  r.nativeInvoked=true;
  r.nativeReturn=o->cpu->vm->ops.nativeTrap(o->cpu->vm->ops.context,10,(void *)(uintptr_t)r.nativeSlotMask);
  s=r.nativeReturn?VZ_KERNEL_NATIVE_ERROR:WakeVersionV17(o);
 }
 if(r.nativeInvoked){VZKernelStatus notified=GICWakeNotifyV30(&q,s);if(s==VZ_KERNEL_OK)s=notified;}
 Lock(&o->mutex);--o->inFlight;
 int notified=pthread_cond_broadcast(&o->idle);Unlock(&o->mutex);
 if(notified && s==VZ_KERNEL_OK)s=VZ_KERNEL_NATIVE_ERROR;
 r.status=s;*out=r;return s;
}
VZKernelStatus VZKernelCPUWakeOwnerDrainV17(VZKernelCPUWakeOwnerV17 *o) {
 if(!o)return VZ_KERNEL_BAD_ARGUMENT;
 if(!pthread_equal(o->ownerPthread,pthread_self()))return VZ_KERNEL_WRONG_THREAD;
 Lock(&o->mutex);o->draining=true;bool busy=o->inFlight!=0 || o->queued!=0;
 int notified=o->idleInitialized?pthread_cond_broadcast(&o->idle):0;Unlock(&o->mutex);
 return notified?VZ_KERNEL_NATIVE_ERROR:busy?VZ_KERNEL_BUSY:VZ_KERNEL_OK;
}
VZKernelStatus VZKernelCPUWakeOwnerDestroyV17(VZKernelCPUWakeOwnerV17 *o) {
 VZKernelStatus s=VZKernelCPUWakeOwnerDrainV17(o);if(s!=VZ_KERNEL_OK)return s;
 if(o->borrow) {
  s=VZKernelCPUReleaseBorrowV5(o->borrow);if(s!=VZ_KERNEL_OK)return s;
  o->borrow=NULL;o->cpu=NULL;
 }
 // A failed pthread destroy retains this draining allocation for an exact
 // retry, without releasing the same CPU borrow twice.
 if(o->idleInitialized) {
  if(pthread_cond_destroy(&o->idle))return VZ_KERNEL_BUSY;
  o->idleInitialized=false;
 }
 if(pthread_mutex_destroy(&o->mutex))return VZ_KERNEL_BUSY;
 memset(o,0,sizeof(*o));free(o);return VZ_KERNEL_OK;
}
