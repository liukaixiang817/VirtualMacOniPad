_Static_assert(sizeof(hv_feature_reg_t)==4,"Actual SDK feature selector ABI");
hv_return_t hv_vcpu_config_get_feature_reg(hv_vcpu_config_t config,
    hv_feature_reg_t feature,uint64_t *out) {
    if(!PublicBeginV6())return Mach(VZ_KERNEL_BUSY);
    Lock();bool valid=Output(out,sizeof(*out));Unlock();
    if(!valid){PublicEndV6();return Mach(VZ_KERNEL_BAD_ARGUMENT);}
    VM27CPUConfigBorrowV3 *borrow=NULL;
    hv_return_t status=VM27CPUConfigBorrowObjectV3((const void *)config,&borrow);
    uint64_t value=0;
    if(!status) {
        VM27CPUCapabilitiesV2 capabilities={0};
        VM27CPUConfigAcquireCapabilitiesV2(&capabilities);
        status=capabilities.featureSeedKnown?
            Mach(VM27CPUOwnProfileGetFeatureV1(&capabilities.featureSeed,
                (uint32_t)feature,&value)):Mach(VZ_KERNEL_UNSUPPORTED);
        hv_return_t released=VM27CPUConfigReleaseBorrowV3(borrow);
        if(released){PublicDeferredConfigV7=borrow;status=released;}
    }
    if(!status)*out=value;
    PublicEndV6();return status;
}
