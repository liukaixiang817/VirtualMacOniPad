/* Actual HOST posix_spawn and Mach rights. Only this standalone test's own
 * task ports change; no device, VM, daemon or borrowed task is addressed. */
#include <errno.h>
#include <mach/mach.h>
#include <signal.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
extern int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t *, mach_port_t [], uint32_t);
static int Release(mach_port_array_t a, mach_msg_type_number_t n) {
    int status=0;
    for (unsigned i=0;a && i<n;i++) if(MACH_PORT_VALID(a[i]) && mach_port_deallocate(mach_task_self(),a[i])) status=1;
    if(a && vm_deallocate(mach_task_self(),(vm_address_t)a,n*sizeof(*a)))status=1;
    return status;
}
static int Child(void) {
    alarm(5); mach_port_array_t a=NULL;mach_msg_type_number_t n=0;
    if(mach_ports_lookup(mach_task_self(),&a,&n) || n!=3 || !a)return 2;
    for(unsigned i=0;i<3;i++) {
        if(!MACH_PORT_VALID(a[i]))return 3;
        mach_msg_header_t h={0};h.msgh_bits=MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,0);
        h.msgh_size=sizeof(h);h.msgh_remote_port=a[i];h.msgh_id=100+(int)i;
        if(mach_msg(&h,MACH_SEND_MSG|MACH_SEND_TIMEOUT,sizeof(h),0,MACH_PORT_NULL,1000,MACH_PORT_NULL))return 4;
    }
    return Release(a,n);
}
static bool Received(mach_port_t port, int expected, bool absent) {
    struct {mach_msg_header_t header;unsigned char trailer[256];} b={0};
    mach_msg_return_t r=mach_msg(&b.header,MACH_RCV_MSG|MACH_RCV_TIMEOUT,0,sizeof(b),port,absent?20:1000,MACH_PORT_NULL);
    return absent?r==MACH_RCV_TIMED_OUT:r==MACH_MSG_SUCCESS && b.header.msgh_id==expected;
}
int main(int argc,char **argv) {
    if(argc==2 && !strcmp(argv[1],"--child"))return Child();
    alarm(10);mach_port_array_t original=NULL,before=NULL,after=NULL;
    mach_msg_type_number_t originalCount=0,count=0,afterCount=0;
    if(mach_ports_lookup(mach_task_self(),&original,&originalCount) || originalCount!=3)return 10;
    mach_port_t ports[4]={0};
    for(unsigned i=0;i<4;i++) {
        if(mach_port_allocate(mach_task_self(),MACH_PORT_RIGHT_RECEIVE,&ports[i]) ||
           mach_port_insert_right(mach_task_self(),ports[i],ports[i],MACH_MSG_TYPE_MAKE_SEND))return 11;
    }
    if(mach_ports_register(mach_task_self(),ports,3) || mach_ports_lookup(mach_task_self(),&before,&count) || count!=3)return 12;
    bool parentSlot2Valid=MACH_PORT_VALID(before[2]);
    mach_port_t childPorts[3]={before[0],before[1],ports[3]};posix_spawnattr_t a;
    if(posix_spawnattr_init(&a))return 13;
    int attrStatus=posix_spawnattr_set_registered_ports_np(&a,childPorts,3);
    pid_t child=0;char *arguments[]={argv[0],"--child",NULL},*environment[]={NULL};
    int spawnStatus=attrStatus?attrStatus:posix_spawn(&child,argv[0],NULL,&a,arguments,environment);
    int destroyStatus=posix_spawnattr_destroy(&a);
    bool unchanged=!mach_ports_lookup(mach_task_self(),&after,&afterCount) && afterCount==count;
    for(unsigned i=0;unchanged && i<count;i++)unchanged=before[i]==after[i];
    bool zero=false,one=false,endpoint=false,oldParent2Absent=false,reaped=false;int exitStatus=-1;
    if(!spawnStatus) {
        zero=Received(ports[0],100,false);one=Received(ports[1],101,false);
        endpoint=Received(ports[3],102,false);oldParent2Absent=Received(ports[2],0,true);
        int state=0;pid_t got;do{got=waitpid(child,&state,0);}while(got<0 && errno==EINTR);
        reaped=got==child;exitStatus=reaped && WIFEXITED(state)?WEXITSTATUS(state):-1;
    }
    int restore=mach_ports_register(mach_task_self(),original,originalCount);
    int release=Release(before,count)|Release(after,afterCount)|Release(original,originalCount);
    for(unsigned i=0;i<4;i++) {
        if(mach_port_deallocate(mach_task_self(),ports[i]))release=1;
        if(mach_port_mod_refs(mach_task_self(),ports[i],MACH_PORT_RIGHT_RECEIVE,-1))release=1;
    }
    bool passed=parentSlot2Valid && !attrStatus && !spawnStatus && !destroyStatus && unchanged && zero && one && endpoint && oldParent2Absent && reaped && !exitStatus && !restore && !release;
    printf("{\"passed\":%s,\"parentSlot2Valid\":%s,\"parentThreeSlotsUnchanged\":%s,\"setattrStatus\":%d,\"spawnStatus\":%d,\"childSlot0ActualPort\":%s,\"childSlot1ActualPort\":%s,\"childSlot2ActualEndpoint\":%s,\"oldParent2NotDelivered\":%s,\"childPID\":%d,\"childReaped\":%s,\"childExit\":%d,\"ownParentPortsRestored\":%s}\n",
        passed?"true":"false",parentSlot2Valid?"true":"false",unchanged?"true":"false",attrStatus,spawnStatus,
        zero?"true":"false",one?"true":"false",endpoint?"true":"false",oldParent2Absent?"true":"false",
        (int)child,reaped?"true":"false",exitStatus,restore?"false":"true");
    return passed?0:20;
}
