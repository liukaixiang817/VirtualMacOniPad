/* Native admission only. A successful check is not a saved/restored VM. */
static BOOL VM27HibernateNativeAdmissionV2(id vm,id configuration) {
    if(!pthread_main_np() || !VZIndependent27SourceRouteSelected() || !vm || vm!=gVirtualMachine)
        return NO;
    SEL save=S("saveMachineStateToURL:completionHandler:");
    SEL restore=S("restoreMachineStateFromURL:completionHandler:");
    BOOL canSave=[vm respondsToSelector:save],canRestore=[vm respondsToSelector:restore];
    SEL validate=S("validateSaveRestoreSupportWithError:");
    BOOL hasValidation=configuration && [configuration respondsToSelector:validate];
    NSError *error=nil;BOOL accepted=NO;
    @try {
        if(canSave && canRestore && hasValidation)
            accepted=((BOOL(*)(id,SEL,NSError **))objc_msgSend)(configuration,validate,&error);
    } @catch(NSException *exception) {
        error=[NSError errorWithDomain:@"VirtualMac.HibernateAdmission" code:EIO
            userInfo:@{NSLocalizedDescriptionKey:exception.reason?:@"Native validation raised an exception."}];
    }
    fprintf(stderr,"[VM27HibernateV2] stage=native-configuration-admission state=%ld saveAPI=%d restoreAPI=%d validationAPI=%d accepted=%d errorDomain=%s errorCode=%ld detail=%s\n",
        (long)((NSInteger(*)(id,SEL))objc_msgSend)(vm,S("state")),canSave,canRestore,hasValidation,
        accepted,error.domain.UTF8String?:"none",(long)error.code,error.description.UTF8String?:"none");
    for(NSString *key in @[@"platform",@"storageDevices",@"networkDevices",@"audioDevices",@"graphicsDevices",
        @"pointingDevices",@"keyboards",@"directorySharingDevices",@"socketDevices",@"serialPorts",@"usbControllers"]) {
        SEL getter=NSSelectorFromString(key);
        if(![configuration respondsToSelector:getter])continue;
        id value=((id(*)(id,SEL))objc_msgSend)(configuration,getter);
        NSArray *objects=[value isKindOfClass:NSArray.class]?value:(value?@[value]:@[]);
        NSMutableArray *names=[NSMutableArray array];
        for(id object in objects)[names addObject:NSStringFromClass([object class])];
        fprintf(stderr,"[VM27HibernateV2] configuration=%s actualClasses=%s\n",key.UTF8String,names.description.UTF8String);
    }
    return accepted;
}
