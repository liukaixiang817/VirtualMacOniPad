/* Owned ordinary IPC preparation only: no Start/Main/bind/original VM/CPU/GPU.
 * The build supplies exact library pins and signs only new owned copies. */
#include "vm27_owned_startup_coordinator_v2.h"
#include "vm27_headless_checkin_v1.h"
#include "vm27_client_registration_v1.h"
#include "owned_v2_preparation_pins.h"
#include <CommonCrypto/CommonDigest.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <ptrauth.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
extern char **environ;
extern void xpc_dictionary_get_audit_token(xpc_object_t, audit_token_t *);
extern int csops_audittoken(pid_t, unsigned, void *, size_t, audit_token_t *);
#if VM27_PREP_CHILD
__attribute__((used,section("__TEXT,__const"))) const unsigned char VM27OwnedFilePayload[2300000] = {[0]=0x27,[2299999]=0x73};
#endif
static _Atomic unsigned Checks,Failures;
static _Atomic int FirstStatus;
static volatile sig_atomic_t WallExpired;
static _Atomic unsigned ChildRegistrations;
static _Atomic int ParentFactoryStatus;
/* Advisory deadline only: neither process signals a saved PID from a handler.
 * Root's separate isolated process-group supervisor supplies the hard deadline. */
static void Wall(int sig) { (void)sig; WallExpired=1; }
static bool Check(bool ok,int status,const char *label) {
    atomic_fetch_add(&Checks,1);
    if(!ok) { atomic_fetch_add(&Failures,1); int zero=0; atomic_compare_exchange_strong(&FirstStatus,&zero,status?status:EIO); }
    printf("{\"record\":\"check\",\"PID\":%d,\"label\":\"%s\",\"passed\":%s,\"status\":%d}\n",getpid(),label,ok?"true":"false",ok?0:status); return ok;
}
static bool Wait(dispatch_semaphore_t sem,unsigned seconds,const char *label) { return Check(!dispatch_semaphore_wait(sem,dispatch_time(DISPATCH_TIME_NOW,(int64_t)seconds*NSEC_PER_SEC)),ETIMEDOUT,label); }
static bool Drain(dispatch_queue_t queue,const char *label) {
    dispatch_semaphore_t marker=dispatch_semaphore_create(0);
    dispatch_async(queue,^{dispatch_semaphore_signal(marker);});
    bool completed=Wait(marker,2,label);
    /* On timeout the queued block still borrows marker: retain it until exit. */
    if(completed)dispatch_release(marker);return completed;
}
static uint64_t Now(void) { struct timespec t={0};if(clock_gettime(CLOCK_MONOTONIC,&t))return 0;return (uint64_t)t.tv_sec*NSEC_PER_SEC+(uint64_t)t.tv_nsec; }
static int PollChild(VM27LargePrivateServiceConsumer *consumer,pid_t pid,VM27LargePrivateConsumerState *state,unsigned seconds) {
    uint64_t started=Now();if(!started)return EIO;
    for(;;){
        int status=VM27LargePrivateServiceConsumerWait(consumer,false,state);
        if(status==EALREADY){int copied=VM27LargePrivateServiceConsumerCopyState(consumer,state);if(copied)return copied;}
        if(!state->started||state->childPID!=pid)return EPROTO;
        if(state->reaped)return 0;
        if(status!=EAGAIN)return status;
        uint64_t now=Now();if(!now)return EIO;if(now-started>=(uint64_t)seconds*NSEC_PER_SEC)return ETIMEDOUT;
        struct timespec nap={.tv_nsec=10000000};while(nanosleep(&nap,&nap)&&errno==EINTR){}
    }
}
static int KillAndPollChild(VM27LargePrivateServiceConsumer *consumer,pid_t pid,VM27LargePrivateConsumerState *state) {
    /* This main thread is the sole waiter. No signal handler/queue ever reaps.
     * Until our WNOHANG call reaps it, this direct child PID cannot be reused. */
    int status=VM27LargePrivateServiceConsumerWait(consumer,false,state);
    if(status==EALREADY){int copied=VM27LargePrivateServiceConsumerCopyState(consumer,state);if(copied)return copied;}
    if(!state->started||state->childPID!=pid)return EPROTO;
    if(state->reaped)return 0;
    if(status!=EAGAIN)return status;
    int killed=kill(pid,SIGKILL);int error=killed?errno:0;
    if(!Check(!killed||error==ESRCH,error,"failure-kills-only-direct-owned-unreaped-child"))return error;
    return PollChild(consumer,pid,state,2);
}
static unsigned char *Read(const char *path,size_t *count) {
    *count=0; int fd=open(path,O_RDONLY|O_CLOEXEC|O_NOFOLLOW); if(fd<0)return NULL;
    struct stat before,after; unsigned char *data=NULL;
    if(!fstat(fd,&before)&&S_ISREG(before.st_mode)&&before.st_uid==geteuid()&&before.st_nlink==1&&!(before.st_mode&0022)&&before.st_size>0&&before.st_size<=8*1024*1024) data=malloc((size_t)before.st_size);
    size_t at=0;
    while(data&&at<(size_t)before.st_size) { ssize_t got=pread(fd,data+at,(size_t)before.st_size-at,(off_t)at);if(got<0&&errno==EINTR)continue;if(got<=0){free(data);data=NULL;break;}at+=(size_t)got; }
    if(data&&(fstat(fd,&after)||before.st_dev!=after.st_dev||before.st_ino!=after.st_ino||before.st_size!=after.st_size||before.st_mtimespec.tv_sec!=after.st_mtimespec.tv_sec||before.st_mtimespec.tv_nsec!=after.st_mtimespec.tv_nsec||before.st_ctimespec.tv_sec!=after.st_ctimespec.tv_sec||before.st_ctimespec.tv_nsec!=after.st_ctimespec.tv_nsec)) { free(data);data=NULL; }
    if(close(fd)&&data){free(data);data=NULL;}if(data)*count=at;return data;
}
static void Digest(const void *data,size_t count,char out[65]) { unsigned char d[32];CC_SHA256(data,(CC_LONG)count,d);for(unsigned i=0;i<32;++i)snprintf(out+2*i,3,"%02x",d[i]); }
static bool NoVM(void) {
    for(uint32_t i=0;i<_dyld_image_count();++i){const char *p=_dyld_get_image_name(i);if(!p||strstr(p,"/Virtualization.framework/")||strstr(p,"/Hypervisor.framework/")||strstr(p,"/ParavirtualizedGraphics.framework/")||strstr(p,"/VirtualMachine.xpc/"))return false;}return true;
}
static bool Libraries(const char *root) {
    void *functions[]={ (void *)VM27OriginalV9TransportCopyABI,(void *)VM27BundleParentInspectV1,(void *)VM27OwnedStartupChildPrepareV2,(void *)VM27ApprovedCodeInspectBytes,(void *)VM27LWCRPolicyCreate,(void *)VM27PrivateEndpointCopyABI,(void *)VM27LargeBundleRegistryCreate,(void *)VM27LargePrivateServiceConsumerCreate,(void *)VM27CopyPrivateHeadlessCheckInState,(void *)VM27ClientRegistrationReceiveV1 };
    bool all=Check(NoVM(),EACCES,"no-original-or-native-VM-images");
    for(unsigned i=0;i<10;++i){
        Dl_info info={0};char path[4096],actual[4096],hash[65]={0},uuid[33]={0};int n=snprintf(path,sizeof(path),"%s/libs/%s",root,VM27PrepLibraryPins[i].name);
        bool good=n>0&&n<(int)sizeof(path)&&dladdr(ptrauth_strip(functions[i],ptrauth_key_function_pointer),&info)&&info.dli_fbase&&info.dli_fname&&realpath(info.dli_fname,actual)&&!strcmp(actual,path);
        if(good){const struct mach_header_64 *h=info.dli_fbase;const struct load_command *c=(const void *)(h+1);for(unsigned k=0;k<h->ncmds;++k){if(c->cmd==LC_UUID&&c->cmdsize==24){const unsigned char *b=(const void *)((const char *)c+8);for(unsigned j=0;j<16;++j)snprintf(uuid+2*j,3,"%02x",b[j]);}c=(const void *)((const char *)c+c->cmdsize);} }
        size_t count=0;unsigned char *b=good?Read(path,&count):NULL;if(b){Digest(b,count,hash);free(b);}
        good=good&&b&&count==VM27PrepLibraryPins[i].bytes&&!strcmp(hash,VM27PrepLibraryPins[i].SHA)&&!strcmp(uuid,VM27PrepLibraryPins[i].UUID);
        all=Check(good,EACCES,"actual-strong-library-path-UUID-file-pin")&&all;
        printf("{\"record\":\"library\",\"PID\":%d,\"name\":\"%s\",\"SHA256\":\"%s\",\"UUID\":\"%s\",\"matched\":%s}\n",getpid(),VM27PrepLibraryPins[i].name,hash,uuid,good?"true":"false");
    }return all;
}
static bool Peer(xpc_object_t message,pid_t pid,const char *expected) {
    audit_token_t token={{0}};xpc_dictionary_get_audit_token(message,&token);unsigned char hash[20]={0};unsigned flags=0;char hex[41]={0};
    int cd=csops_audittoken(pid,5,hash,sizeof(hash),&token),st=csops_audittoken(pid,0,&flags,sizeof(flags),&token);
    for(unsigned i=0;i<20;++i)snprintf(hex+2*i,3,"%02x",hash[i]);
    bool matched=token.val[5]==(unsigned)pid&&token.val[7]&&token.val[1]==geteuid()&&!cd&&!st&&(flags&1)&&!strcmp(hex,expected);
    printf("{\"record\":\"peer\",\"PID\":%d,\"peerPID\":%u,\"version\":%u,\"kernelCD\":\"%s\",\"flags\":%u,\"cdStatus\":%d,\"csStatus\":%d,\"matched\":%s}\n",getpid(),token.val[5],token.val[7],hex,flags,cd,st,matched?"true":"false");return matched;
}
static void ReleasePorts(mach_port_array_t p,mach_msg_type_number_t n) { if(p){for(unsigned i=0;i<n;++i)if(MACH_PORT_VALID(p[i]))Check(!mach_port_deallocate(mach_task_self(),p[i]),EIO,"owned-registered-send-right-release");Check(!vm_deallocate(mach_task_self(),(vm_address_t)p,n*sizeof(mach_port_t)),EIO,"owned-registered-port-array-release");} }
static bool MainBundle(const char *path,const char *executable,const char *identifier) {
    /* Observation of the same genuine CF main bundle used by V2/registration.
     * No direct plist substitute, caller-installed CF bundle, or fallback. */
    CFBundleRef bundle=CFBundleGetMainBundle();CFDictionaryRef info=bundle?CFBundleGetInfoDictionary(bundle):NULL;
    CFURLRef bundleURL=bundle?CFBundleCopyBundleURL(bundle):NULL,executableURL=bundle?CFBundleCopyExecutableURL(bundle):NULL;
    char bundlePath[4096]={0},executablePath[4096]={0},canonicalBundle[4096]={0},canonicalExecutable[4096]={0},expectedExecutable[4096];
    int n=snprintf(expectedExecutable,sizeof(expectedExecutable),"%s/%s",path,executable);
    bool good=info&&CFGetTypeID(info)==CFDictionaryGetTypeID()&&bundleURL&&executableURL&&n>0&&n<(int)sizeof(expectedExecutable)&&CFURLGetFileSystemRepresentation(bundleURL,true,(UInt8 *)bundlePath,sizeof(bundlePath))&&CFURLGetFileSystemRepresentation(executableURL,true,(UInt8 *)executablePath,sizeof(executablePath))&&realpath(bundlePath,canonicalBundle)&&realpath(executablePath,canonicalExecutable)&&!strcmp(canonicalBundle,path)&&!strcmp(canonicalExecutable,expectedExecutable);
    const char *name=strrchr(executable,'/');name=name?name+1:executable;
    const CFStringRef keys[]={CFSTR("CFBundleIdentifier"),CFSTR("CFBundleExecutable"),CFSTR("CFBundleDisplayName")};const char *values[]={identifier,name,VM27_PREP_TITLE};
    for(unsigned i=0;i<3;++i){CFTypeRef value=info?CFDictionaryGetValue(info,keys[i]):NULL;CFStringRef expected=CFStringCreateWithCString(NULL,values[i],kCFStringEncodingUTF8);good=good&&value&&CFGetTypeID(value)==CFStringGetTypeID()&&expected&&CFEqual(value,expected);if(expected)CFRelease(expected);}
    if(bundleURL)CFRelease(bundleURL);if(executableURL)CFRelease(executableURL);
    printf("{\"record\":\"actualCFMainBundle\",\"PID\":%d,\"bundlePath\":\"%s\",\"executablePath\":\"%s\",\"matched\":%s,\"directPlistSubstitute\":false}\n",getpid(),canonicalBundle,canonicalExecutable,good?"true":"false");
    return Check(good,ENOENT,"actual-main-CFBundle-path-executable-and-info-values");
}
static int Child(int argc,char **argv) {
    /* root,parent bundle,name,parent SHA/CD,nonce,parent PID,child SHA/CD */
    if(argc!=10)return 64;
    pid_t parent=(pid_t)strtol(argv[7],NULL,10);uint64_t nonce=strtoull(argv[6],NULL,10);
    size_t count=0;unsigned char *bytes=Read(argv[0],&count);VM27ApprovedCodeInfo own={0};int inspected=bytes?VM27ApprovedCodeInspectBytes(bytes,count,&own):EIO;
    Check(!inspected&&count>2*1024*1024&&count<=8*1024*1024&&!strcmp(own.fileSHA256,argv[8])&&!strcmp(own.CDHash,argv[9])&&own.pagesVerified&&own.embeddedSlotsVerified&&own.pluginIsBoolean&&own.pluginValue,inspected?inspected:EACCES,"actual-large-code-only-child-pages-and-signed-Boolean");free(bytes);
    char ownBundle[4096];snprintf(ownBundle,sizeof(ownBundle),"%s/Owned.bundle/Contents/XPCServices/One.xpc",argv[1]);
    if(!MainBundle(ownBundle,"Contents/MacOS/VM27OwnedPreparationChild",VM27_ORIGINAL_VM_SERVICE)||!Libraries(argv[1])||atomic_load(&Failures))return 78;
    VM27OwnedStartupConfigurationV2 config={.parent={.formatVersion=1,.kind=VM27OriginalV9ParentFlatBundle,.expectedParentPID=parent,.source.flatBundle={.bundlePath=argv[2],.executableName=argv[3],.reviewedExecutableSHA256=argv[4],.reviewedExecutableCDHash=argv[5],.expectedOwnerUID=0}},.bootstrapNonce=nonce};
    VM27OwnedStartupChildV2 *child=NULL;xpc_object_t hello=NULL;int prepared=VM27OwnedStartupChildPrepareV2(&config,&child,&hello);
    Check(!prepared&&child&&hello,prepared,"real-V2-Prepare-no-fallback");
    printf("{\"record\":\"prepare\",\"PID\":%d,\"status\":%d,\"StartCalls\":0,\"MainCalls\":0,\"bindCalls\":0}\n",getpid(),prepared);
    if(prepared){if(child){VM27OwnedStartupChildStopV2(child);VM27OwnedStartupChildReleaseV2(&child);}return 78;}
    dispatch_queue_t queue=NULL;Check(!VM27OwnedStartupChildCopyControlQueueV2(child,&queue)&&queue,EIO,"real-V2-control-serial-queue");
    dispatch_semaphore_t finish=dispatch_semaphore_create(0),invalid=dispatch_semaphore_create(0);mach_port_array_t ports=NULL;mach_msg_type_number_t portCount=0;xpc_connection_t channel=NULL;
    Check(!mach_ports_lookup(mach_task_self(),&ports,&portCount)&&portCount==3&&MACH_PORT_VALID(ports[2]),EIO,"exact-own-inherited-slot2");
    int connected=queue&&ports&&portCount==3?VM27PrivateEndpointConnectSendRight(ports[2],queue,&channel):EINVAL;Check(!connected&&channel,connected,"own-actual-control-endpoint-connect");
    if(!channel)return 78;
    __block bool committed=false;
    xpc_connection_set_event_handler(channel,^(xpc_object_t event){
        if(event==XPC_ERROR_CONNECTION_INVALID){dispatch_semaphore_signal(invalid);return;}
        if(xpc_get_type(event)!=XPC_TYPE_DICTIONARY)return;
        if(!Check(Peer(event,parent,argv[5]),EACCES,"child-actual-parent-audit-CD-CS_VALID"))return;
        const char *method=xpc_dictionary_get_string(event,"privateMethod");
        if(method&&!strcmp(method,"VM27.owned-v2.stop.v1")){
            bool shape=xpc_dictionary_get_count(event)==2&&xpc_get_type(xpc_dictionary_get_value(event,"nonce"))==XPC_TYPE_UINT64&&xpc_dictionary_get_uint64(event,"nonce")==nonce;
            Check(shape&&committed,EPROTO,"own-stop-after-actual-registration-commit");
            xpc_object_t reply=xpc_dictionary_create_reply(event);if(reply){xpc_dictionary_set_int64(reply,"stopStatus",shape&&committed?0:EPROTO);xpc_connection_send_message(channel,reply);xpc_release(reply);xpc_connection_send_barrier(channel,^{dispatch_semaphore_signal(finish);});}return;
        }
        xpc_object_t reply=NULL;int status=VM27OwnedStartupChildReceiveControlV2(child,event,&reply);atomic_fetch_add(&ChildRegistrations,1);
        Check(!status&&reply,status,"real-V2-received-title-registration");
        CFStringRef title=NULL;int copied=!status?VM27OriginalV9TransportCopyServerRegisteredClientDisplayName(&title):status;
        CFStringRef expected=CFStringCreateWithCString(NULL,VM27_PREP_TITLE,kCFStringEncodingUTF8);
        committed=!copied&&title&&expected&&CFEqual(title,expected);Check(committed,copied?copied:EPROTO,"actual-parent-CFMainBundle-title-committed");
        if(title)CFRelease(title);if(expected)CFRelease(expected);if(reply){xpc_connection_send_message(channel,reply);xpc_release(reply);}
        printf("{\"record\":\"registration\",\"PID\":%d,\"status\":%d,\"committed\":%s}\n",getpid(),status,committed?"true":"false");
    });xpc_connection_resume(channel);xpc_connection_send_message(channel,hello);xpc_release(hello);
    Wait(finish,8,"own-stop-ACK-sent-before-cancel");xpc_connection_cancel(channel);
    bool drained=Wait(invalid,2,"child-control-finalINVALID")&&Drain(queue,"child-control-bounded-serial-drain");
    if(drained){int stopped=VM27OwnedStartupChildStopV2(child);Check(!stopped,stopped,"real-V2-off-queue-Stop");if(!stopped){int released=VM27OwnedStartupChildReleaseV2(&child);Check(!released&&!child,released,"real-V2-release-after-external-drain");if(!released){xpc_release(channel);dispatch_release(queue);dispatch_release(finish);dispatch_release(invalid);ReleasePorts(ports,portCount);}}}
    VM27OriginalV9TransportStats stats={0};VM27OriginalV9TransportCopyStats(&stats);VM27OriginalV9TransportRegistrationStats reg={0};VM27OriginalV9TransportCopyRegistrationStats(&reg);
    Check(atomic_load(&ChildRegistrations)==1&&reg.registrationCommits==1&&stats.originalHandlerCalls==0&&stats.serverInstancesBound==0,EIO,"one-title-commit-zero-original-handler-or-bind");Libraries(argv[1]);
    printf("{\"record\":\"childSummary\",\"PID\":%d,\"failures\":%u,\"status\":%d,\"drained\":%s,\"originalVMMExecuted\":false,\"VMCalls\":0,\"CPUProbeCalls\":0}\n",getpid(),atomic_load(&Failures),atomic_load(&FirstStatus),drained?"true":"false");return atomic_load(&Failures)?78:0;
}
static xpc_object_t Requirement(void) {
    xpc_object_t r=xpc_dictionary_create(NULL,NULL,0),e=xpc_dictionary_create(NULL,NULL,0),q=xpc_array_create(NULL,0),s=xpc_array_create(NULL,0),m=xpc_array_create(NULL,0);
    xpc_object_t one=xpc_int64_create(1),five=xpc_int64_create(5),key=xpc_string_create(VM27_PLUGIN_ENTITLEMENT),yes=xpc_bool_create(true);
    xpc_array_append_value(s,one);xpc_array_append_value(s,key);xpc_array_append_value(m,five);xpc_array_append_value(m,yes);xpc_array_append_value(q,s);xpc_array_append_value(q,m);xpc_dictionary_set_value(e,"$query",q);xpc_dictionary_set_value(r,"entitlements",e);xpc_release(e);xpc_release(q);xpc_release(s);xpc_release(m);xpc_release(one);xpc_release(five);xpc_release(key);xpc_release(yes);return r;
}
static int Parent(int argc,char **argv) {
    /* actual canonical package root,parent SHA/CD,child SHA/CD */
    if(argc!=6)return 64;char root[4096],self[4096],bundle[4096],registered[4096];
    if(!realpath(argv[1],root)||!realpath(argv[0],self))return 64;
    snprintf(bundle,sizeof(bundle),"%s/VM27OwnedPreparation.app",root);snprintf(registered,sizeof(registered),"%s/Owned.bundle",root);
    char expectedSelf[4096];snprintf(expectedSelf,sizeof(expectedSelf),"%s/VM27OwnedPreparation",bundle);
    if(!Check(!strcmp(self,expectedSelf)&&geteuid()==0,EACCES,"actual-flat-parent-path-and-explicit-root-owner"))return 78;
    if(!MainBundle(bundle,"VM27OwnedPreparation","com.virtualmac.diagnostics.owned-v2-preparation"))return 78;
    VM27BundleParentConfigurationV1 config={bundle,"VM27OwnedPreparation",argv[2],argv[3],0};VM27BundleParentInspectionV1 inspected={0};int inspection=VM27BundleParentInspectV1(&config,&inspected);
    Check(!inspection&&inspected.externalInfoSlotVerified&&inspected.externalResourcesSlotVerified&&!inspected.wholeBundleResourcesValidated&&!inspected.nativeBooleanValidated,inspection,"actual-parent-external-slots-not-native-authorization");
    if(!Libraries(root)||atomic_load(&Failures))return 78;
    VM27LargeBundleRegistry *registry=NULL;VM27LargePrivateServiceConsumer *consumer=NULL;xpc_object_t requirement=Requirement();
    Check(!VM27LargeBundleRegistryCreate(root,&registry),EIO,"owned-Large-registry-create");int registeredStatus=registry?VM27LargeBundleRegistryRegister(registry,registered,2,requirement):EINVAL;Check(!registeredStatus,registeredStatus,"actual-Large-tree-registration");
    int created=!registeredStatus?VM27LargePrivateServiceConsumerCreate(registry,VM27_ORIGINAL_VM_SERVICE,argv[4],argv[5],requirement,VM27LargeConsumerExplicitApprovedCode,&consumer):registeredStatus;xpc_release(requirement);Check(!created&&consumer,created,"existing-explicit-approved-mode-no-strict-fallback");
    if(created){if(registry)VM27LargeBundleRegistryRelease(registry);return 78;}
    dispatch_queue_t queue=dispatch_queue_create("VM27.owned.V2.parent",DISPATCH_QUEUE_SERIAL);dispatch_semaphore_t ready=dispatch_semaphore_create(0),peerFinal=dispatch_semaphore_create(0),listenerFinal=dispatch_semaphore_create(0),serviceFinal=dispatch_semaphore_create(0),stopAck=dispatch_semaphore_create(0),admissionClosed=dispatch_semaphore_create(0);
    __block pid_t pid=0;__block xpc_connection_t peer=NULL;__block unsigned peerCount=0;__block bool admissionOpen=true,helloProcessed=false;atomic_store(&ParentFactoryStatus,EINPROGRESS);
    uint64_t nonce=0;arc4random_buf(&nonce,sizeof(nonce));if(!nonce)nonce=1;
    xpc_connection_t listener=VM27OriginalV9TransportConnectionCreate(NULL,queue);
    if(!listener)return 78;
    xpc_connection_set_event_handler(listener,^(xpc_object_t event){
        if(event==XPC_ERROR_CONNECTION_INVALID){dispatch_semaphore_signal(listenerFinal);return;}if(xpc_get_type(event)!=XPC_TYPE_CONNECTION)return;
        if(!admissionOpen){xpc_connection_cancel((xpc_connection_t)event);return;}
        ++peerCount;if(!Check(!peer&&peerCount==1,EPROTO,"one-own-direct-child-peer")){xpc_connection_cancel((xpc_connection_t)event);return;}
        peer=(xpc_connection_t)xpc_retain(event);xpc_connection_set_target_queue(peer,queue);
        xpc_connection_set_event_handler(peer,^(xpc_object_t message){
            if(message==XPC_ERROR_CONNECTION_INVALID){dispatch_semaphore_signal(peerFinal);return;}if(xpc_get_type(message)!=XPC_TYPE_DICTIONARY)return;
            if(!Check(!helloProcessed,EPROTO,"exactly-one-actual-child-hello"))return;helloProcessed=true;
            if(!Check(Peer(message,pid,argv[5]),EACCES,"parent-real-owned-child-kernel-identity")){atomic_store(&ParentFactoryStatus,EACCES);dispatch_semaphore_signal(ready);return;}
            int factory=VM27OwnedStartupParentInstallFactoryV2(consumer,message,nonce);atomic_store(&ParentFactoryStatus,factory);Check(!factory,factory,"actual-received-hello-real-Large-factory");dispatch_semaphore_signal(ready);
        });xpc_connection_resume(peer);
    });xpc_connection_resume(listener);xpc_endpoint_t endpoint=xpc_endpoint_create(listener);
    char childPath[4096],nonceText[32],pidText[32];snprintf(childPath,sizeof(childPath),"%s/Owned.bundle/Contents/XPCServices/One.xpc/Contents/MacOS/VM27OwnedPreparationChild",root);snprintf(nonceText,sizeof(nonceText),"%llu",(unsigned long long)nonce);snprintf(pidText,sizeof(pidText),"%d",getpid());
    char *arguments[]={childPath,root,bundle,"VM27OwnedPreparation",argv[2],argv[3],nonceText,pidText,argv[4],argv[5],NULL};
    char *const *argumentPointer=arguments;
    __block int spawnStatus=EINVAL;
    dispatch_sync(queue,^{spawnStatus=VM27LargePrivateServiceConsumerSpawn(consumer,endpoint,argumentPointer,environ,&pid);});
    Check(!spawnStatus&&pid>1,spawnStatus,"spawn-and-exact-PID-publication-on-peer-queue");
    bool gotHello=!spawnStatus&&Wait(ready,3,"real-child-hello-factory-completed");
    xpc_connection_t service=NULL;bool nativeDrained=true,stopped=false;
    if(gotHello&&!atomic_load(&ParentFactoryStatus)){
        service=VM27OriginalV9TransportConnectionCreate(VM27_ORIGINAL_VM_SERVICE,queue);Check(service!=NULL,errno,"factory-created-suspended-native-client");
        if(service){
            xpc_connection_set_event_handler(service,^(xpc_object_t event){if(event==XPC_ERROR_CONNECTION_INVALID)dispatch_semaphore_signal(serviceFinal);});
            int status=VM27OriginalV9TransportRegisterClientDisplayNameFromMainBundle(service);Check(!status,status,"actual-main-CFBundle-title-helper-and-reply-commit");
            if(!status){
                xpc_object_t stop=xpc_dictionary_create(NULL,NULL,0);xpc_dictionary_set_string(stop,"privateMethod","VM27.owned-v2.stop.v1");xpc_dictionary_set_uint64(stop,"nonce",nonce);
                xpc_connection_send_message_with_reply(peer,stop,queue,^(xpc_object_t reply){bool ok=xpc_get_type(reply)==XPC_TYPE_DICTIONARY&&Peer(reply,pid,argv[5])&&xpc_dictionary_get_count(reply)==1&&xpc_get_type(xpc_dictionary_get_value(reply,"stopStatus"))==XPC_TYPE_INT64&&!xpc_dictionary_get_int64(reply,"stopStatus");Check(ok,EPROTO,"owned-stop-real-ACK-after-registration-reply");dispatch_semaphore_signal(stopAck);});xpc_release(stop);stopped=Wait(stopAck,3,"owned-stop-ACK-received");
            }
            /* Cleanup callback only. Inactive server listener never handles it. */
            xpc_connection_activate(service);xpc_connection_cancel(service);nativeDrained=Wait(serviceFinal,2,"owned-native-client-finalINVALID-no-service-handshake-claim");
        }
    }
    /* Close admission on the owning queue before reading peer on a timeout.
     * FINAL + marker publish a stable peer and exclude a later acceptance. */
    dispatch_async(queue,^{admissionOpen=false;xpc_connection_cancel(listener);dispatch_semaphore_signal(admissionClosed);});
    bool listenerDrained=Wait(admissionClosed,2,"parent-listener-admission-closed")&&Wait(listenerFinal,2,"parent-listener-finalINVALID")&&Drain(queue,"parent-listener-bounded-serial-drain");
    bool peerDrained=false;
    if(listenerDrained){if(peer)xpc_connection_cancel(peer);peerDrained=(!peer||Wait(peerFinal,2,"parent-control-finalINVALID"))&&Drain(queue,"parent-control-bounded-serial-drain");}
    VM27LargePrivateConsumerState state={0};
    if(pid>1){
        bool failed=atomic_load(&Failures)||!stopped||WallExpired;
        int waited=failed?KillAndPollChild(consumer,pid,&state):PollChild(consumer,pid,&state,3);
        if(!failed&&waited==ETIMEDOUT){Check(false,waited,"owned-child-natural-exit-poll-deadline");waited=KillAndPollChild(consumer,pid,&state);}
        Check(!waited&&state.reaped,waited,"actual-direct-child-WNOHANG-wait-and-reap");
        Check(state.observedWaitExit==0&&state.absent,ESRCH,"owned-child-clean-exit-and-kernel-absence");
    }
    if(peerDrained&&listenerDrained&&nativeDrained){VM27OriginalV9TransportClearClient();if(service)xpc_release(service);if(peer)xpc_release(peer);xpc_release(endpoint);xpc_release(listener);if(!pid||state.reaped){Check(!VM27LargePrivateServiceConsumerRelease(consumer),EIO,"reaped-consumer-release-after-actual-drain");VM27LargeBundleRegistryRelease(registry);}dispatch_release(ready);dispatch_release(peerFinal);dispatch_release(listenerFinal);dispatch_release(serviceFinal);dispatch_release(stopAck);dispatch_release(admissionClosed);dispatch_release(queue);}
    Libraries(root);VM27OriginalV9TransportStats stats={0};VM27OriginalV9TransportCopyStats(&stats);Check(!stats.originalHandlerCalls&&!stats.serverInstancesBound,EIO,"zero-original-handler-and-instance-bind");
    printf("{\"record\":\"parentSummary\",\"PID\":%d,\"childPID\":%d,\"failures\":%u,\"status\":%d,\"factoryStatus\":%d,\"childReaped\":%s,\"waitExit\":%d,\"wallExpired\":%s,\"StartCalls\":0,\"MainCalls\":0,\"bindCalls\":0,\"originalHandlerCalls\":0,\"ownNativeCleanupCallback\":true,\"serviceHandshakeProven\":false,\"CPUProbeCalls\":0,\"full27Ready\":false}\n",getpid(),pid,atomic_load(&Failures),atomic_load(&FirstStatus),atomic_load(&ParentFactoryStatus),state.reaped?"true":"false",state.observedWaitExit,WallExpired?"true":"false");return atomic_load(&Failures)?78:0;
}
int main(int argc,char **argv) {
    setbuf(stdout,NULL);struct rlimit cpu={5,5};if(setrlimit(RLIMIT_CPU,&cpu))return 78;signal(SIGALRM,Wall);alarm(15);
    printf("{\"record\":\"scope\",\"PID\":%d,\"childRole\":%s,\"CPUlimit\":5,\"advisoryWallSeconds\":15,\"hardWallProvidedByExternalRunner\":true,\"originalVMMExecuted\":false,\"CPUProbeCalls\":0}\n",getpid(),VM27_PREP_CHILD?"true":"false");
    int status=VM27_PREP_CHILD?Child(argc,argv):Parent(argc,argv);alarm(0);Check(!WallExpired,ETIMEDOUT,"advisory-wall-expiration-is-final-failure");
    if(atomic_load(&Failures)&&!status)status=78;
    printf("{\"record\":\"processSummary\",\"PID\":%d,\"failures\":%u,\"wallExpired\":%s,\"exitStatus\":%d,\"CPUProbeCalls\":0,\"full27Ready\":false}\n",getpid(),atomic_load(&Failures),WallExpired?"true":"false",status);return status;
}
