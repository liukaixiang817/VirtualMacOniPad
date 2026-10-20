#include "modern_cpu_native_self_memory_v1.h"
#include <mach/mach.h>
#include <string.h>
#include <unistd.h>
_Static_assert(sizeof(vm_address_t)==8 && sizeof(vm_size_t)==8 && sizeof(vm_offset_t)==8,
    "Audited SDK LP64 vm messages");
_Static_assert(sizeof(mach_port_t)==4 && sizeof(mach_msg_type_number_t)==4,
    "Audited SDK task/count widths");
bool VM27CPUSelfMappedRangeV1(const void *address,size_t bytes,bool writable,
    VM27CPUSelfMappedReceiptV1 *out) {
    VM27CPUSelfMappedReceiptV1 r={0};r.writableRequested=writable;
    uintptr_t start=(uintptr_t)address;
    if(!start || !bytes || bytes>UINTPTR_MAX-start)goto finish;
    uintptr_t cursor=start,end=start+bytes;
    // A valid RAM backing may comprise many independent 128 MiB named entries.
    // Bound the traversal by genuine process page geometry, rather than eight
    // arbitrary regions. Small CPU/context ranges retain the original budget.
    int nativePage=getpagesize();
    if(nativePage<=0 || ((unsigned)nativePage&((unsigned)nativePage-1)))goto finish;
    size_t queryBudget=bytes/(size_t)nativePage+2;
    if(queryBudget<8)queryBudget=8;
    for(size_t attempt=0;attempt<queryBudget && cursor<end;++attempt) {
        vm_address_t region=cursor;vm_size_t length=0;
        vm_region_basic_info_data_64_t info={0};
        mach_msg_type_number_t count=VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t object=MACH_PORT_NULL;
        ++r.queries;
        r.queryStatus=vm_region_64(mach_task_self(),&region,&length,
            VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&count,&object);
        if(object!=MACH_PORT_NULL) {
            r.portReleaseStatus=mach_port_deallocate(mach_task_self(),object);
            if(r.portReleaseStatus==KERN_SUCCESS)++r.releasedObjectPorts;
        }
        if(r.queryStatus!=KERN_SUCCESS || r.portReleaseStatus!=KERN_SUCCESS ||
            count!=VM_REGION_BASIC_INFO_COUNT_64 || !length || region>cursor ||
            length>UINTPTR_MAX-region || region+length<=cursor ||
            !(info.protection&VM_PROT_READ) ||
            (writable && !(info.protection&VM_PROT_WRITE)))goto finish;
        if(!attempt)r.firstRegionStart=region;
        r.finalRegionEnd=region+length;
        cursor=region+length<end ? region+length : end;
    }
    r.requestedRangeMapped=cursor==end;
finish:
    if(out)*out=r;
    return r.requestedRangeMapped;
}
bool VM27CPUSelfReadV1(void *opaque,const void *address,size_t bytes,void *out) {
    (void)opaque;
    if(!out || !VM27CPUSelfMappedRangeV1(address,bytes,false,NULL))return false;
    vm_size_t copied=0;
    return vm_read_overwrite(mach_task_self(),(vm_address_t)address,
        (vm_size_t)bytes,(vm_address_t)out,&copied)==KERN_SUCCESS && copied==bytes;
}
bool VM27CPUSelfWriteV1(void *opaque,void *address,size_t bytes,const void *value) {
    (void)opaque;
    // Every genuine typed CPU field is <=16B. No general bulk writer exists.
    if(!value || bytes>16 || !VM27CPUSelfMappedRangeV1(address,bytes,true,NULL))return false;
    if(vm_write(mach_task_self(),(vm_address_t)address,(vm_offset_t)value,
        (mach_msg_type_number_t)bytes)!=KERN_SUCCESS)return false;
    unsigned char actual[16];
    return VM27CPUSelfReadV1(NULL,address,bytes,actual) && !memcmp(actual,value,bytes);
}
