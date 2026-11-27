// Main-thread state for one explicit request from the currently bound guest.
static NSString *VM27RadioColdBundleV1,*VM27RadioColdRequestV1,*VM27RadioLastColdRequestV1;
static void VM27RadioCancelColdRestartV1(void) {
    [VM27RadioColdBundleV1 release];VM27RadioColdBundleV1=nil;
    [VM27RadioColdRequestV1 release];VM27RadioColdRequestV1=nil;
}
static void VM27RadioObserveColdRestartV1(void) {
    static dispatch_once_t once;static id observer;
    dispatch_once(&once,^{
        observer=[[NSNotificationCenter.defaultCenter addObserverForName:VM27RadioColdRestartNotificationV1
            object:nil queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *notification){
            id owner=gVirtualMachineDelegate;SEL action=NSSelectorFromString(@"radioColdRestartRequestedV1:");
            if(owner && [owner respondsToSelector:action])
                ((void(*)(id,SEL,id))objc_msgSend)(owner,action,notification);
        }] retain];
    });
    (void)observer;
}
