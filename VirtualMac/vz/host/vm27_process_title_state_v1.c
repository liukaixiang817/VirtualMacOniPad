#include "vm27_process_title_state_v1.h"
#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <unistd.h>
_Static_assert(sizeof(int32_t)==4 && sizeof(void *)==8,"Original consumed LP64 ABI");
const CFStringRef _kLSDisplayNameKey=CFSTR("LSDisplayName");
static pthread_once_t Once=PTHREAD_ONCE_INIT;
static pthread_mutex_t Lock=PTHREAD_MUTEX_INITIALIZER;
static CFDictionaryRef Identity;
static CFStringRef DisplayName;
static pid_t IdentityPID;
static void Initialize(void) {
    int64_t pid=getpid(),uid=getuid();CFUUIDRef nonce=CFUUIDCreate(NULL);
    CFNumberRef p=CFNumberCreate(NULL,kCFNumberSInt64Type,&pid);
    CFNumberRef u=CFNumberCreate(NULL,kCFNumberSInt64Type,&uid);
    CFStringRef n=nonce?CFUUIDCreateString(NULL,nonce):NULL;
    if(p && u && n) {
        const void *keys[]={CFSTR("Scope"),CFSTR("PID"),CFSTR("UID"),CFSTR("Instance")};
        const void *values[]={CFSTR("VM27PrivateProcessDisplayName"),p,u,n};
        Identity=CFDictionaryCreate(NULL,keys,values,4,&kCFTypeDictionaryKeyCallBacks,&kCFTypeDictionaryValueCallBacks);
        if(Identity)IdentityPID=(pid_t)pid;
    }
    if(n)CFRelease(n);if(u)CFRelease(u);if(p)CFRelease(p);if(nonce)CFRelease(nonce);
}
CFTypeRef _LSGetCurrentApplicationASN(void) {
    if(pthread_once(&Once,Initialize)){errno=EIO;return NULL;}
    if(!Identity){errno=ENOMEM;return NULL;}
    if(IdentityPID!=getpid()){errno=ECHILD;return NULL;}
    return Identity;
}
int32_t _LSSetApplicationInformationItem(int32_t session,CFTypeRef identity,
    CFStringRef key,CFTypeRef value,CFTypeRef *unsupportedOutput) {
    // Original VZ uses only (-2, this getter's identity, LSDisplayName, string,
    // NULL). A nonnull private out has unknown broader meaning; never touch it.
    if(unsupportedOutput || session!=-2 || !identity || !key || !value){errno=EINVAL;return -50;}
    CFTypeRef owned=_LSGetCurrentApplicationASN();
    if(!owned)return errno==ENOMEM?-108:-50;
    if(identity!=owned){errno=EINVAL;return -50;}
    if(CFGetTypeID(key)!=CFStringGetTypeID() || !CFEqual(key,_kLSDisplayNameKey) ||
       CFGetTypeID(value)!=CFStringGetTypeID()){errno=EINVAL;return -50;}
    CFStringRef copied=CFStringCreateCopy(NULL,(CFStringRef)value);
    if(!copied){errno=ENOMEM;return -108;}
    if(pthread_mutex_lock(&Lock)){CFRelease(copied);errno=EIO;return -50;}
    CFStringRef previous=DisplayName;DisplayName=copied;
    pthread_mutex_unlock(&Lock);
    if(previous)CFRelease(previous);
    return 0; // A real immutable display-name snapshot is now retained.
}
CFStringRef VM27CopyPrivateProcessDisplayName(void) {
    if(!_LSGetCurrentApplicationASN() || pthread_mutex_lock(&Lock))return NULL;
    CFStringRef copied=DisplayName?(CFStringRef)CFRetain(DisplayName):NULL;
    pthread_mutex_unlock(&Lock);return copied;
}
