/* Main queue only. The original VZ27 implementation owns the VM state. */
static BOOL VZIndependent27RequestVMStateV44(BOOL resume) {
    if(pthread_main_np())VM27LockManualRequestV1();
    if (!pthread_main_np() || !VZIndependent27SourceRouteSelected() ||
        !gVirtualMachine || gIndependent27VMStateTransitionPendingV44 ||
        gIndependent27OwnerClosePending || gIndependent27InputClosePending ||
        gIndependent27VMStateEpochV44==UINT64_MAX) return NO;
    id vm=gVirtualMachine;
    SEL operation=S(resume?"resumeWithCompletionHandler:":"pauseWithCompletionHandler:");
    SEL capability=S(resume?"canResume":"canPause");
    if (![vm respondsToSelector:operation] || ![vm respondsToSelector:capability] ||
        ![vm respondsToSelector:S("queue")] ||
        ((dispatch_queue_t(*)(id,SEL))objc_msgSend)(vm,S("queue"))!=dispatch_get_main_queue() ||
        ((NSInteger(*)(id,SEL))objc_msgSend)(vm,S("state"))!=(resume?2:1) ||
        !((BOOL(*)(id,SEL))objc_msgSend)(vm,capability)) return NO;
    [vm retain];
    const uint64_t ticket=++gIndependent27VMStateEpochV44;
    gIndependent27VMStateTransitionPendingV44=YES;
    [gIndependent27Clipboard setSuspended:YES];
    [(VZHUDView *)gHUDView refreshMenu];
    fprintf(stderr,"[Independent27LifecycleV44] request=%s ticket=%llu nativeState=%ld\n",
        resume?"resume":"pause",(unsigned long long)ticket,
        (long)((NSInteger(*)(id,SEL))objc_msgSend)(vm,S("state")));
    __block BOOL finished=NO;
    void (^finish)(NSError *)=^(NSError *error) {
        if (finished) return;
        finished=YES;
        BOOL current=gVirtualMachine==vm && ticket==gIndependent27VMStateEpochV44;
        NSInteger actual=((NSInteger(*)(id,SEL))objc_msgSend)(vm,S("state"));
        if(current) {
            gIndependent27VMStateTransitionPendingV44=NO;
            if(!error && actual!=(resume?1:2))
                error=[NSError errorWithDomain:@"VirtualMac.NativeLifecycle" code:EPROTO
                    userInfo:@{NSLocalizedDescriptionKey:@"The virtual machine did not reach the requested state."}];
            if(actual==1) {
                VZIndependent27ResumeActualInput();
                [gIndependent27Clipboard setSuspended:NO];
            }
            [(VZHUDView *)gHUDView refreshMenu];
            VM27LockTransitionFinishedV1(vm,ticket,resume,actual,error==nil);
            if(error)
                VZPresentFailureReport(UIApplication.sharedApplication.keyWindow.rootViewController,
                    VZL(@"Virtual Mac"),error.localizedDescription,error.debugDescription,
                    VZFailureSupportOptionSuggestDebugLogging);
        }
        fprintf(stderr,"[Independent27LifecycleV44] completion=%s ticket=%llu sameOwner=%d nativeState=%ld nativeError=%ld verified=%d\n",
            resume?"resume":"pause",(unsigned long long)ticket,current,(long)actual,
            (long)error.code,current && !error && actual==(resume?1:2));
        [vm release];
    };
    void (^submit)(void)=^{
        if(gVirtualMachine!=vm || ticket!=gIndependent27VMStateEpochV44 ||
           !((BOOL(*)(id,SEL))objc_msgSend)(vm,capability)) {
            finish([NSError errorWithDomain:@"VirtualMac.NativeLifecycle" code:EBUSY
                userInfo:@{NSLocalizedDescriptionKey:@"The virtual machine state changed. Try again when it is ready."}]);
            return;
        }
        @try {
            ((void(*)(id,SEL,id))objc_msgSend)(vm,operation,^(NSError *error){
                if(pthread_main_np()) finish(error);
                else dispatch_async(dispatch_get_main_queue(),^{finish(error);});
            });
        } @catch(NSException *exception) {
            finish([NSError errorWithDomain:@"VirtualMac.NativeLifecycle" code:EIO
                userInfo:@{NSLocalizedDescriptionKey:exception.reason?:@"The virtual machine operation failed."}]);
        }
    };
    if(!resume && gIndependent27InputQueueV3) {
        VM27InputQueueV3 *input=[gIndependent27InputQueueV3 retain];
        gIndependent27InputClosePending=YES;
        [input closeWithCompletion:^(VM27InputResult result){
            gIndependent27InputClosePending=NO;
            if((result==VM27InputOK || result==VM27InputClosed) && gIndependent27InputQueueV3==input) {
                [gIndependent27InputQueueV3 release];gIndependent27InputQueueV3=nil;
                submit();
            } else {
                finish([NSError errorWithDomain:@"VirtualMac.NativeLifecycle" code:EIO
                    userInfo:@{NSLocalizedDescriptionKey:@"Input could not be released before pausing."}]);
            }
            [input release];
        }];
    } else submit();
    return YES; /* Admission only; success requires the genuine completion. */
}
