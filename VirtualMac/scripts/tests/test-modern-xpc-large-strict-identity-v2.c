/* Explicit local doubles only. No received kernel message, Security gate,
 * csops query, spawned child, signature deployment or VMM execution is real. */
#include "modern_xpc_large_private_consumer_v2.c"
#include <mach-o/dyld.h>
#include <stdio.h>
#include <sys/resource.h>

static unsigned Checks, Failures, NativeCalls, CodeCalls, StatusCalls, ExplicitCalls;
static int NativeRC, VerifyRC, CopyRC, CodeRC, CodeErr, StatusRC, StatusErr;
static unsigned NativeFault;
static audit_token_t Token;
static VM27LargeServiceInfo Info;
static unsigned char Digest[20];
static uint32_t Flags;
static char ReviewedSHA[65], ReviewedCD[41];
static unsigned char FakePlan;

static void Check(bool value, const char *label) {
    ++Checks;
    if (!value) { ++Failures; printf("{\"record\":\"failure\",\"label\":\"%s\"}\n", label); }
}
void xpc_dictionary_get_audit_token(xpc_object_t message, audit_token_t *out) {
    (void)message; *out = Token;
}
int csops_audittoken(pid_t pid, unsigned op, void *buffer, size_t size, audit_token_t *token) {
    Check(pid == (pid_t)Token.val[5] && !memcmp(token, &Token, sizeof(Token)), "double-query-reuses-exact-message-token");
    if (op == 5) {
        ++CodeCalls; Check(size == 20, "double-CD-query-exact-size");
        if (CodeRC) { errno = CodeErr; return CodeRC; }
        memcpy(buffer, Digest, 20); return 0;
    }
    ++StatusCalls; Check(op == 0 && size == sizeof(Flags), "double-status-query-exact-operation-and-size");
    if (StatusRC) { errno = StatusErr; return StatusRC; }
    memcpy(buffer, &Flags, sizeof(Flags)); return 0;
}
int VM27LargeServicePlanVerify(const VM27LargeServicePlan *plan) { (void)plan; return VerifyRC; }
int VM27LargeServicePlanCopyInfo(const VM27LargeServicePlan *plan, VM27LargeServiceInfo *out) { (void)plan; if (CopyRC) return CopyRC; *out = Info; return 0; }
int VM27LargeServicePlanCheckReceivedMessage(const VM27LargeServicePlan *plan, xpc_object_t message, VM27LWCRMessageResult *out) {
    (void)plan; (void)message; ++NativeCalls;
    *out = (VM27LWCRMessageResult){ .hasRemoteConnection=true, .taskCreated=true,
        .entitlementsValidated=true, .entitlementPresent=true,
        .entitlementIsBoolean=true, .entitlementValue=true, .result=NativeRC };
    switch (NativeFault) {
    case 1: out->hasRemoteConnection=false; break;
    case 2: out->taskCreated=false; break;
    case 3: out->entitlementsValidated=false; break;
    case 4: out->entitlementPresent=false; break;
    case 5: out->entitlementIsBoolean=false; break;
    case 6: out->entitlementValue=false; break;
    case 7: out->entitlementReadError=true; break;
    case 8: out->result=EACCES; break;
    }
    return NativeRC;
}
int VM27ApprovedCodeCheckReceivedMessage(const VM27ApprovedCodePolicy *policy, xpc_object_t message, VM27ApprovedCodeMessageResult *out) {
    (void)policy; (void)message; ++ExplicitCalls; memset(out, 0, sizeof(*out)); out->result=EACCES; return EACCES;
}
/* Link-only doubles for unchanged functions that this fixture never invokes. */
int VM27LWCRPolicyCreate(xpc_object_t requirement, VM27LWCRPolicy **out) { (void)requirement; *out=NULL; return ENOTSUP; }
void VM27LWCRPolicyRelease(VM27LWCRPolicy *policy) { (void)policy; }
int VM27LargeBundleRegistryCopyServicePlan(VM27LargeBundleRegistry *registry, const char *name, VM27LargeServicePlan **out) { (void)registry; (void)name; *out=NULL; return ENOTSUP; }
void VM27LargeServicePlanRelease(VM27LargeServicePlan *plan) { (void)plan; }
int VM27ApprovedCodeInspectBytes(const unsigned char *data, size_t bytes, VM27ApprovedCodeInfo *out) { (void)data; (void)bytes; memset(out,0,sizeof(*out)); return ENOTSUP; }
int VM27ApprovedCodePolicyCreate(const char *path, const char *SHA, const char *CD, xpc_object_t req, VM27ApprovedCodePolicy **out) { (void)path; (void)SHA; (void)CD; (void)req; *out=NULL; return ENOTSUP; }
void VM27ApprovedCodePolicyRelease(VM27ApprovedCodePolicy *policy) { (void)policy; }
int VM27PrivateEndpointCopySendRight(xpc_endpoint_t endpoint, mach_port_t *out) { (void)endpoint; *out=MACH_PORT_NULL; return ENOTSUP; }
int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t *attr, mach_port_t ports[], uint32_t count) { (void)attr; (void)ports; (void)count; return ENOTSUP; }

static void Reset(VM27LargePrivateServiceConsumerV2 *consumer) {
    memset(consumer, 0, sizeof(*consumer));
    pthread_mutex_init(&consumer->mutex, NULL);
    consumer->plan=(VM27LargeServicePlan *)&FakePlan;
    consumer->mode=VM27LargeConsumerV2StrictNative;
    consumer->state.started=true; consumer->state.childPID=getpid();
    memset(ReviewedSHA, 'a', 64); ReviewedSHA[64]=0;
    static const char alphabet[]="0123456789abcdef";
    for (unsigned i=0;i<20;++i) { Digest[i]=(unsigned char)i; ReviewedCD[2*i]=alphabet[i>>4]; ReviewedCD[2*i+1]=alphabet[i&15]; }
    ReviewedCD[40]=0;
    memcpy(consumer->reviewedSHA256, ReviewedSHA, 65); memcpy(consumer->reviewedCDHash, ReviewedCD, 41);
    memset(&Info,0,sizeof(Info)); memcpy(Info.executableSHA256,ReviewedSHA,65); Info.flags=2; Info.executableBytes=2300000;
    Token=(audit_token_t){{0}}; Token.val[5]=(uint32_t)getpid(); Token.val[7]=19;
    Flags=1; NativeRC=VerifyRC=CopyRC=CodeRC=CodeErr=StatusRC=StatusErr=0; NativeFault=0;
    NativeCalls=CodeCalls=StatusCalls=ExplicitCalls=0;
}
static void Finish(VM27LargePrivateServiceConsumerV2 *consumer) { pthread_mutex_destroy(&consumer->mutex); }
static void Reject(xpc_object_t message, VM27LargePrivateServiceConsumerV2 *consumer, int wanted, const char *label) {
    VM27ApprovedCodeMessageResult out; memset(&out,0xff,sizeof(out));
    int rc=VM27LargePrivateServiceConsumerV2CheckMessage(consumer,message,&out);
    Check(rc==wanted && out.result==wanted && !out.explicitApprovedCodeAccepted && !consumer->state.messagesAccepted, label);
    Check(!ExplicitCalls,"strict-never-calls-explicit-policy-double");
}
static bool NoOriginalImages(void) {
    for (uint32_t i=0;i<_dyld_image_count();++i) { const char *p=_dyld_get_image_name(i);
        if (!p || strstr(p,"/Virtualization.framework/") || strstr(p,"/Hypervisor.framework/") || strstr(p,"/ParavirtualizedGraphics.framework/") || strstr(p,"/VirtualMachine.xpc/")) return false;
    }
    return true;
}
int main(void) {
    setbuf(stdout,NULL); alarm(15); struct rlimit cpu={5,5}; if (setrlimit(RLIMIT_CPU,&cpu)) return 70;
    xpc_object_t message=xpc_dictionary_create(NULL,NULL,0);
    VM27LargePrivateServiceConsumerV2 consumer; VM27ApprovedCodeMessageResult out;
    Check(message && NoOriginalImages(),"owned-local-dictionary-and-no-original-frameworks");
    Reset(&consumer); NativeRC=EACCES; Reject(message,&consumer,EACCES,"native-deny-preserved"); Check(NativeCalls==1&&!CodeCalls&&!StatusCalls,"native-deny-no-identity-queries"); Finish(&consumer);
    Reset(&consumer); NativeRC=EIO; Reject(message,&consumer,EIO,"native-query-error-preserved"); Check(!CodeCalls&&!StatusCalls,"native-error-no-identity-queries"); Finish(&consumer);
    for (unsigned fault=1;fault<=8;++fault) { Reset(&consumer); NativeFault=fault; Reject(message,&consumer,EPROTO,"inconsistent-native-success-fails-closed"); Check(!CodeCalls&&!StatusCalls,"native-inconsistency-no-identity-queries"); Finish(&consumer); }
    Reset(&consumer); CodeRC=-1; CodeErr=EPERM; Reject(message,&consumer,EPERM,"actual-code-query-error-propagated"); Check(CodeCalls==1&&!StatusCalls,"code-query-error-stops-status-query"); Finish(&consumer);
    Reset(&consumer); CodeRC=-1; CodeErr=0; Reject(message,&consumer,EIO,"code-query-error-zero-errno-fails-closed"); Finish(&consumer);
    Reset(&consumer); StatusRC=-1; StatusErr=ESRCH; Reject(message,&consumer,ESRCH,"actual-status-query-error-propagated"); Check(CodeCalls==1&&StatusCalls==1,"status-error-after-real-CD-result-double"); Finish(&consumer);
    Reset(&consumer); StatusRC=-1; StatusErr=0; Reject(message,&consumer,EIO,"status-query-error-zero-errno-fails-closed"); Finish(&consumer);
    Reset(&consumer); Digest[0]^=1; Reject(message,&consumer,EACCES,"CDHash-mismatch-refused"); Check(CodeCalls==1&&StatusCalls==1,"CD-mismatch-retains-real-query-results-double"); Finish(&consumer);
    Reset(&consumer); Flags=0; Reject(message,&consumer,EACCES,"missing-CS-VALID-refused"); Finish(&consumer);
    Reset(&consumer); Info.executableSHA256[0]='b'; Reject(message,&consumer,EACCES,"creation-reviewed-SHA-mismatch-refused"); Check(!CodeCalls&&!StatusCalls,"SHA-mismatch-before-kernel-query"); Finish(&consumer);
    Reset(&consumer); CopyRC=EIO; Reject(message,&consumer,EIO,"plan-copy-error-refused"); Finish(&consumer);
    Reset(&consumer); Info.flags=1; Reject(message,&consumer,EACCES,"original-flags2-required"); Finish(&consumer);
    Reset(&consumer); Info.executableBytes=8*1024*1024+1; Reject(message,&consumer,EACCES,"8MiB-bound-preserved"); Finish(&consumer);
    Reset(&consumer); VerifyRC=ESTALE; Reject(message,&consumer,ESTALE,"outer-file-pin-refusal-preserved"); Check(!NativeCalls&&!CodeCalls&&!StatusCalls,"stale-pin-no-native-or-kernel-query"); Finish(&consumer);
    Reset(&consumer); consumer.state.started=false; Reject(message,&consumer,EACCES,"unstarted-consumer-refused"); Check(!NativeCalls,"unstarted-before-native-gate"); Finish(&consumer);
    Reset(&consumer); consumer.state.reaped=true; Reject(message,&consumer,EACCES,"reaped-consumer-refused"); Finish(&consumer);
    Reset(&consumer); ++Token.val[5]; Reject(message,&consumer,EACCES,"wrong-spawned-PID-refused"); Finish(&consumer);
    Reset(&consumer); Token.val[7]=0; Reject(message,&consumer,EACCES,"missing-PID-version-refused"); Finish(&consumer);
    Reset(&consumer); consumer.childVersion=20; Reject(message,&consumer,EACCES,"changed-PID-version-refused"); Finish(&consumer);
    Reset(&consumer); Token.val[5]=1; consumer.state.childPID=1; Reject(message,&consumer,EACCES,"invalid-low-audit-PID-refused-after-native"); Check(!CodeCalls&&!StatusCalls,"invalid-low-PID-no-kernel-query"); Finish(&consumer);
    Reset(&consumer); Token.val[5]=UINT32_MAX; consumer.state.childPID=(pid_t)UINT32_MAX; Reject(message,&consumer,EACCES,"invalid-large-audit-PID-refused-after-native"); Check(!CodeCalls&&!StatusCalls,"invalid-large-PID-no-kernel-query"); Finish(&consumer);
    Reset(&consumer); consumer.reviewedCDHash[0]='x'; Reject(message,&consumer,EINVAL,"malformed-reviewed-CD-refused"); Check(!NativeCalls,"malformed-pin-before-native-gate"); Finish(&consumer);
    Reset(&consumer); memset(&out,0xff,sizeof(out));
    Check(!VM27LargePrivateServiceConsumerV2CheckMessage(&consumer,message,&out) && !out.result && out.nativePolicy.entitlementsValidated && out.nativePolicy.entitlementIsBoolean && out.nativePolicy.entitlementValue && out.filePinMatched && out.auditTokenPresent && out.auditPID==(uint32_t)getpid() && out.auditPIDVersion==19 && !strcmp(out.kernelCDHash,ReviewedCD) && out.codeHashMatched && out.codeStatus==1 && out.dynamicCodeValid && !out.explicitApprovedCodeAccepted && consumer.state.messagesAccepted==1 && NativeCalls==1 && CodeCalls==1 && StatusCalls==1 && !ExplicitCalls,"only-native-success-plus-token-CD-CS-valid-accepted-double");
    Check(consumer.childVersion==19 && consumer.state.messageChecks==1,"unchanged-PID-version-state-and-accounting"); Finish(&consumer);
    xpc_release(message); Check(NoOriginalImages(),"no-original-frameworks-after");
    printf("{\"record\":\"summary\",\"checks\":%u,\"failures\":%u,\"explicitLocalDoubles\":true,\"realReceivedMessages\":0,\"realNativePolicyChecks\":0,\"realCsopsQueries\":0,\"childSpawns\":0,\"originalFrameworkCalls\":0,\"deviceOperations\":false,\"signatureOperations\":0,\"CPUFixProven\":false}\n",Checks,Failures);
    return Failures ? 1 : 0;
}
