- (void)radioColdRestartRequestedV1:(NSNotification *)notification {
    NSCAssert(pthread_main_np(),@"Cold restart ownership requires main.");
    NSString *bundle=notification.object,*request=notification.userInfo[@"RequestID"];
    if(!VZIndependent27SourceRouteSelected() || !gVirtualMachine || gForceStopPending ||
       VM27HibernateOperationPendingV4() || VM27RadioColdBundleV1 ||
       ![notification.userInfo[@"GuestBuild"] isEqual:@"26B131"] ||
       ![bundle isKindOfClass:NSString.class] || ![bundle isEqual:self.activeVMBundlePath] ||
       ![request isKindOfClass:NSString.class] || ![[[NSUUID alloc]initWithUUIDString:request] autorelease] ||
       [request isEqual:VM27RadioLastColdRequestV1])return;
    VM27RadioColdBundleV1=[bundle copy];VM27RadioColdRequestV1=[request copy];
    [VM27RadioLastColdRequestV1 release];VM27RadioLastColdRequestV1=[request copy];
    printf("[VirtualMac] radio cold restart: requesting normal guest shutdown\n");
    VM27RadioColdShutdownV1(bundle,request,^(BOOL success){
        // A shutdown can close QGA before its final reply. Only the actual
        // stopped callback and completed native teardown admit a restart.
        printf("[VirtualMac] radio cold shutdown agentReply=%d actualStopRequired=1\n",success);
    });
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,60*NSEC_PER_SEC),dispatch_get_main_queue(),^{
        if(![VM27RadioColdRequestV1 isEqual:request])return;
        VM27RadioCancelColdRestartV1();
        VZPresentFailureReport(self,VZL(@"Wi-Fi and Bluetooth Setup"),
            VZL(@"The virtual Mac did not shut down. Shut it down normally, then start it again to finish radio setup."),
            nil,VZFailureSupportOptionNone);
    });
}
