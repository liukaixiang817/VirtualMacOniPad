#include "vm27_hv_public_vm_bootstrap_v9.h"
// Exercise the complete frozen Root8 behavior against the new combined root
// before installing a controller. No old fixture is edited or skipped.
#define main FoundationMainV9
#include "test-vm27-hv-public-vm-bootstrap-v8.m"
#undef main
static unsigned GICWakesV9;
static int32_t GICTrapV9(void *opaque,uint64_t op,void *packet) {
 Mock *m=opaque;
 if(op==10){CHECK((uintptr_t)packet==1);++GICWakesV9;return 0;}
 int32_t status=Trap(opaque,op,packet);
 if(op==6 && !status){Put(m,0x4100,1);Put(m,0x6f8,0x1c00);Put(m,0x40b0,0x3c00);}
 return status;
}
typedef struct {hv_vcpu_t id;hv_return_t spi,icc;} GICForeignV9;
static void *GICForeignAccessV9(void *opaque) {
 GICForeignV9 *f=opaque;uint64_t value=55;
 f->spi=hv_gic_set_spi(40,true);f->icc=hv_gic_get_icc_reg(f->id,(hv_gic_icc_reg_t)0xc230,&value);
 CHECK(f->icc==BAD && value==55);return NULL;
}
int main(void) {
 CHECK(!FoundationMainV9());unsigned foundationChecks=Checks;
 alarm(20);Mock m={0};
 m.context=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 m.host=mmap(NULL,0x8000,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);
 CHECK(m.context!=MAP_FAILED && m.host!=MAP_FAILED && !((uintptr_t)m.host&0x3fff));
 VZKernelLifecycleOps ops={1,VZ_KERNEL_PROFILE_IPADOS_16_1_1,&m,GICTrapV9,Thread,Read};
 VZKernelInitWriter writer={&m,Write};
 CHECK(!VM27HVVMInstallNativeOpsV1(&ops,&writer));m.config=hv_vm_config_create();
 CHECK(!_hv_vm_config_set_isa(m.config,2));CHECK(!hv_vm_create(m.config));
 CHECK(!VM27HVVMGetOwnedVMV1(&m.vm) && m.vm);
 hv_gic_config_t config=hv_gic_config_create();CHECK(config);
 size_t size=99;CHECK(!hv_gic_get_distributor_size(&size) && size==0x10000);
 CHECK(!hv_gic_get_redistributor_size(&size) && size==0x20000);
 CHECK(!hv_gic_get_redistributor_region_size(&size) && size==0x800000);
 CHECK(hv_gic_get_distributor_size((size_t *)(void *)config)==BAD);
 uint32_t first=77,count=88;CHECK(!hv_gic_get_spi_interrupt_range(&first,&count) && first==32 && count==988);
 CHECK(hv_gic_get_spi_interrupt_range(&first,&first)==BAD && first==32);
 uint32_t intid=88;CHECK(!hv_gic_get_intid((hv_gic_intid_t)30,&intid) && intid==30);
 CHECK(hv_gic_get_intid((hv_gic_intid_t)25,&intid)==(hv_return_t)UINT32_C(0xfae9400f) && intid==30);
 CHECK(hv_gic_config_set_distributor_base((hv_gic_config_t)(void *)1,0)==BAD);
 CHECK(hv_gic_config_set_distributor_base(config,1)==BAD);
 CHECK(hv_gic_create((hv_gic_config_t)(void *)1)==BAD);
 CHECK(hv_gic_create(config)==BAD);
 CHECK(!hv_gic_config_set_distributor_base(config,0x10000));
 CHECK(!hv_gic_config_set_redistributor_base(config,0));
 CHECK(hv_gic_create(config)==BAD); // Actual engine rejects overlapping regions.
 CHECK(!hv_gic_config_set_redistributor_base(config,0x200000));
 CHECK(hv_gic_config_set_msi_interrupt_range(config,31,1)==BAD);
 CHECK(hv_gic_config_set_msi_interrupt_range(config,1000,100)==BAD);
 CHECK(!hv_gic_config_set_msi_region_base(config,0x1000000));
 CHECK(!hv_gic_config_set_msi_interrupt_range(config,900,16));
 CHECK(!hv_gic_create(config));CHECK(hv_gic_create(config)==BUSY);
 uint64_t value=99;CHECK(!hv_gic_get_msi_reg((hv_gic_msi_reg_t)8,&value) && value==((900u<<16)|16));
 CHECK(hv_gic_get_msi_reg((hv_gic_msi_reg_t)0x40,&value)==BAD && value==((900u<<16)|16));
 CHECK(hv_gic_get_distributor_reg((hv_gic_distributor_reg_t)4,(uint64_t *)(void *)config)==BAD);
 CHECK(!hv_gic_get_distributor_reg((hv_gic_distributor_reg_t)4,&value) && (value&31)==31);
 CHECK(!hv_vm_map(m.host,0x40000000,0x4000,7));hv_vcpu_exit_t *exit=NULL;
 CHECK(!hv_vcpu_create(&m.cpu,&exit,NULL));CHECK(m.cpu && exit);
 CHECK(!hv_vcpu_set_sys_reg(m.cpu,(hv_sys_reg_t)0xc005,0x80000001));
 hv_ipa_t base=99;CHECK(!hv_gic_get_redistributor_base(m.cpu,&base) && base==0x200000);
 CHECK(!hv_gic_get_redistributor_reg(m.cpu,(hv_gic_redistributor_reg_t)8,&value) && value>>32==1);
 CHECK(!hv_gic_set_icc_reg(m.cpu,(hv_gic_icc_reg_t)0xc230,0xff));
 CHECK(!hv_gic_get_icc_reg(m.cpu,(hv_gic_icc_reg_t)0xc230,&value) && value==0xf8);
 CHECK(hv_gic_get_icc_reg(m.cpu,(hv_gic_icc_reg_t)0xc230,(uint64_t *)(void *)exit)==BAD);
 value=77;CHECK(hv_gic_get_ich_reg(m.cpu,(hv_gic_ich_reg_t)0xe658,&value)==(hv_return_t)UINT32_C(0xfae9400f) && value==77);
 CHECK(!hv_gic_set_icc_reg(m.cpu,(hv_gic_icc_reg_t)0xc667,1));
 CHECK(!hv_gic_set_distributor_reg((hv_gic_distributor_reg_t)0,2));
 CHECK(!hv_gic_set_distributor_reg((hv_gic_distributor_reg_t)0x84,1u<<8));
 CHECK(!hv_gic_set_distributor_reg((hv_gic_distributor_reg_t)0x104,1u<<8));
 CHECK(!hv_gic_set_distributor_reg((hv_gic_distributor_reg_t)0x6140,1));
 CHECK(!hv_gic_set_spi(40,true));CHECK(GICWakesV9>0);
 CHECK(!hv_gic_get_icc_reg(m.cpu,(hv_gic_icc_reg_t)0xc660,&value) && value==40);
 CHECK(!hv_gic_set_spi(40,false));CHECK(!hv_gic_set_icc_reg(m.cpu,(hv_gic_icc_reg_t)0xc661,40));
 CHECK(!hv_gic_get_icc_reg(m.cpu,(hv_gic_icc_reg_t)0xc662,&value) && value==1023);
 GICForeignV9 foreign={m.cpu,ERROR,ERROR};pthread_t t;
 CHECK(!pthread_create(&t,NULL,GICForeignAccessV9,&foreign));CHECK(!pthread_join(t,NULL));CHECK(!foreign.spi);
 CHECK(!hv_gic_set_spi(40,false));CHECK(hv_gic_set_spi(900,true)==BAD);
 CHECK(hv_gic_send_msi(0x1000000,900)==BAD);CHECK(!hv_gic_send_msi(0x1000040,900));
 CHECK(hv_gic_set_msi_reg((hv_gic_msi_reg_t)0x40,UINT64_C(1)<<32)==BAD);
 CHECK(!hv_gic_set_msi_reg((hv_gic_msi_reg_t)0x40,900));
 CHECK(!hv_gic_reset());CHECK(!hv_gic_get_distributor_reg((hv_gic_distributor_reg_t)0,&value) && !(value&3));
 CHECK(hv_vm_destroy()==BUSY && !m.calls[2]);
 CHECK(hv_gic_state_create()==NULL);size=99;
 CHECK(hv_gic_state_get_size((hv_gic_state_t)(void *)config,&size)==(hv_return_t)UINT32_C(0xfae9400f) && size==99);
 VM27CPUFactoryBorrowV2 *probe=NULL;hv_return_t acquired=VM27CPUFactoryBorrowAcquireV2(m.cpu,&probe);
 if(acquired)fprintf(stderr,"Root9 pre-destroy acquire=%08x\n",(uint32_t)acquired);
 CHECK(!acquired);
 if(probe)CHECK(!VM27CPUFactoryBorrowReleaseV2(probe));
 hv_return_t destroy=hv_vcpu_destroy(m.cpu);
 if(destroy)fprintf(stderr,"Root9 CPU destroy status=%08x native7=%u\n",(uint32_t)destroy,m.calls[7]);
 CHECK(!destroy && m.calls[7]==1);
 CHECK(!hv_vm_unmap(0x40000000,0x4000));CHECK(!hv_vm_destroy() && m.calls[2]==1);
 CHECK(VM27HVVMUninstallNativeOpsV1()==BUSY);
 CFRelease((CFTypeRef)config);CFRelease((CFTypeRef)m.config);
 CHECK(!VM27HVVMUninstallNativeOpsV1());CHECK(!VM27HVDrainGICBorrowV9());
 CHECK(!munmap(m.context,0x8000) && !munmap(m.host,0x8000));
 printf("{\"checks\":%u,\"foundationChecks\":%u,\"actualRootGICFactoryRegistry\":true,\"actualCPUOwner\":true,\"hostMockNative10\":%u,\"nativeCallsExecuted\":0,\"deviceExecuted\":false,\"full27Backend\":false}\n",Checks,foundationChecks,GICWakesV9);
 return 0;
}
