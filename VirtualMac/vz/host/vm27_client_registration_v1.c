/* Application-private client title registration, not a host LS registry.
 * No native VM/CPU/GPU operations, daemon registration, system policy or files.
 * Live CF inputs must not be concurrently mutated during these calls. */
#include "vm27_client_registration_v1.h"
#include <errno.h>
#include <mach/message.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
extern void xpc_dictionary_get_audit_token(xpc_object_t, audit_token_t *);
extern void xpc_connection_get_audit_token(xpc_connection_t, audit_token_t *);
extern int csops_audittoken(pid_t, unsigned int, void *, size_t, audit_token_t *);
_Static_assert(sizeof(int32_t)==4 && sizeof(void *)==8 && sizeof(audit_token_t)==32,"Consumed LP64 ABI");
const CFStringRef _kLSPIDKey=CFSTR("pid");
static pthread_mutex_t Lock=PTHREAD_MUTEX_INITIALIZER;
static _Atomic pid_t OwnPID;
static bool Configured;
static pid_t PeerPID;
static char PeerCD[41];
static uint64_t Nonce;
static audit_token_t Token;
static CFDictionaryRef Identity;
static CFStringRef DisplayName;
static int ProcessGate(void) {
    pid_t current=getpid(),zero=0;
    (void)atomic_compare_exchange_strong(&OwnPID,&zero,current);
    return atomic_load(&OwnPID)==current?0:EPERM;
}
static bool HexCD(const char *s) {
    if(!s || strnlen(s,41)!=40)return false;
    for(unsigned i=0;i<40;++i)if(!((s[i]>='0'&&s[i]<='9')||(s[i]>='a'&&s[i]<='f')))return false;
    return true;
}
static int KernelPeer(audit_token_t token) {
    if(token.val[5]!=(uint32_t)PeerPID || !token.val[7])return EACCES;
    unsigned char bytes[20]={0};unsigned flags=0;char cd[41]={0};
    if(csops_audittoken(PeerPID,5,bytes,sizeof(bytes),&token) ||
       csops_audittoken(PeerPID,0,&flags,sizeof(flags),&token) || !(flags&1))return EACCES;
    static const char h[]="0123456789abcdef";
    for(unsigned i=0;i<20;++i){cd[2*i]=h[bytes[i]>>4];cd[2*i+1]=h[bytes[i]&15];}
    return strcmp(cd,PeerCD)?EACCES:0;
}
int VM27ClientRegistrationConfigureV1(pid_t pid,const char *cd,uint64_t nonce) {
    int rc=ProcessGate();if(rc)return rc;
    if(pid<=1 || pid==getpid() || !HexCD(cd) || !nonce)return EINVAL;
    if(pthread_mutex_lock(&Lock))return EIO;
    rc=Configured?EALREADY:0;
    if(!rc){PeerPID=pid;memcpy(PeerCD,cd,41);Nonce=nonce;Configured=true;}
    pthread_mutex_unlock(&Lock);return rc;
}
int VM27ClientRegistrationReceiveV1(xpc_object_t message) {
    int rc=ProcessGate();if(rc)return rc;
    if(!message || xpc_get_type(message)!=XPC_TYPE_DICTIONARY)return EINVAL;
    if(pthread_mutex_lock(&Lock))return EIO;
    if(!Configured){pthread_mutex_unlock(&Lock);return ENOTCONN;}
    xpc_connection_t peer=xpc_dictionary_get_remote_connection(message);
    audit_token_t actual={{0}},connection={{0}};
    xpc_dictionary_get_audit_token(message,&actual);
    if(peer)xpc_connection_get_audit_token(peer,&connection);
    if(!peer || memcmp(&actual,&connection,sizeof(actual)) ||
       xpc_connection_get_euid(peer)!=actual.val[1])rc=EACCES;
    else rc=KernelPeer(actual);
    xpc_object_t method=xpc_dictionary_get_value(message,"privateMethod"),n=xpc_dictionary_get_value(message,"nonce"),title=xpc_dictionary_get_value(message,"clientDisplayName");
    const char *text=NULL;size_t bytes=0;
    if(!rc && (xpc_dictionary_get_count(message)!=3 || !method || xpc_get_type(method)!=XPC_TYPE_STRING ||
       strcmp(xpc_string_get_string_ptr(method),"VM27.register-client-title.v1") || !n || xpc_get_type(n)!=XPC_TYPE_UINT64 ||
       xpc_uint64_get_value(n)!=Nonce || !title || xpc_get_type(title)!=XPC_TYPE_STRING))rc=EPROTO;
    if(!rc){text=xpc_string_get_string_ptr(title);bytes=xpc_string_get_length(title);if(!text || !bytes || bytes>4096 || strnlen(text,4097)!=bytes)rc=EINVAL;}
    CFStringRef copied=!rc?CFStringCreateWithBytes(NULL,(const UInt8 *)text,(CFIndex)bytes,kCFStringEncodingUTF8,false):NULL;
    if(!rc && (!copied || CFStringGetLength(copied)>4096))rc=copied?EINVAL:ENOMEM;
    if(!rc && Identity)rc=memcmp(&Token,&actual,sizeof(actual)) || !CFEqual(DisplayName,copied)?EALREADY:0;
    if(!rc && !Identity){
        int64_t pid=PeerPID,uid=actual.val[1],version=actual.val[7];
        CFNumberRef p=CFNumberCreate(NULL,kCFNumberSInt64Type,&pid),u=CFNumberCreate(NULL,kCFNumberSInt64Type,&uid),v=CFNumberCreate(NULL,kCFNumberSInt64Type,&version);
        CFUUIDRef uuid=CFUUIDCreate(NULL);CFStringRef instance=uuid?CFUUIDCreateString(NULL,uuid):NULL;
        const void *keys[]={CFSTR("Scope"),_kLSPIDKey,CFSTR("UID"),CFSTR("PIDVersion"),CFSTR("Instance")};
        const void *values[]={CFSTR("VM27 authenticated private client"),p,u,v,instance};
        CFDictionaryRef identity=p&&u&&v&&instance?CFDictionaryCreate(NULL,keys,values,5,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks):NULL;
        if(!identity)rc=ENOMEM;
        else{Identity=identity;DisplayName=copied;copied=NULL;Token=actual;}
        if(instance)CFRelease(instance);if(uuid)CFRelease(uuid);if(v)CFRelease(v);if(u)CFRelease(u);if(p)CFRelease(p);
    }
    if(copied)CFRelease(copied);pthread_mutex_unlock(&Lock);return rc;
}
CFArrayRef _LSCopyMatchingApplicationsWithItems(int32_t session,uint32_t count,const CFStringRef *keys,const CFTypeRef *values) {
    int rc=ProcessGate();if(rc){errno=rc;return NULL;}
    if(session!=-2 || count!=1 || !keys || !values || !keys[0] || !values[0]){errno=EINVAL;return NULL;}
    if(CFGetTypeID(keys[0])!=CFStringGetTypeID() || !CFEqual(keys[0],_kLSPIDKey) ||
       CFGetTypeID(values[0])!=CFNumberGetTypeID() || CFNumberIsFloatType((CFNumberRef)values[0])){errno=EINVAL;return NULL;}
    int64_t requested=0;if(!CFNumberGetValue((CFNumberRef)values[0],kCFNumberSInt64Type,&requested) || requested<=1 || requested>INT32_MAX){errno=EINVAL;return NULL;}
    if(pthread_mutex_lock(&Lock)){errno=EIO;return NULL;}
    rc=!Identity || requested!=PeerPID?ENOENT:KernelPeer(Token);
    const void *one[]={Identity};CFArrayRef result=!rc?CFArrayCreate(NULL,one,1,&kCFTypeArrayCallBacks):NULL;
    if(!rc && !result)rc=ENOMEM;
    pthread_mutex_unlock(&Lock);if(rc)errno=rc;return result;
}
CFTypeRef _LSCopyApplicationInformationItem(int32_t session,CFTypeRef identity,CFStringRef key) {
    int rc=ProcessGate();if(rc){errno=rc;return NULL;}
    if(session!=-2 || !identity || !key){errno=EINVAL;return NULL;}
    if(pthread_mutex_lock(&Lock)){errno=EIO;return NULL;}
    rc=!Identity || identity!=Identity?ENOENT:KernelPeer(Token);
    if(!rc && (CFGetTypeID(key)!=CFStringGetTypeID() || !CFEqual(key,CFSTR("LSDisplayName"))))rc=EINVAL;
    CFTypeRef result=!rc?CFRetain(DisplayName):NULL;
    pthread_mutex_unlock(&Lock);if(rc)errno=rc;return result;
}
