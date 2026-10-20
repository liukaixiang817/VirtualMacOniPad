#include "vm27_owned_app_parent_identity_v1.h"
#include "modern_xpc_original_instance_transport_v10.h"
#include "modern_xpc_original_instance_pins.h"
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <errno.h>
#include <mach-o/loader.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
typedef struct __SecTask *SecTaskRef;
extern SecTaskRef SecTaskCreateWithAuditToken(CFAllocatorRef,audit_token_t);
extern CFTypeRef SecTaskCopyValueForEntitlement(SecTaskRef,CFStringRef,CFErrorRef *);
extern Boolean SecTaskEntitlementsValidated(SecTaskRef);
extern int csops_audittoken(pid_t,unsigned int,void *,size_t,audit_token_t *);
extern void xpc_dictionary_get_audit_token(xpc_object_t,audit_token_t *);
typedef void (*ActualAuditV1)(xpc_connection_t,audit_token_t *);
typedef xpc_object_t (*ActualEntitlementV1)(xpc_connection_t,const char *);
static pthread_once_t IdentityOnceV1=PTHREAD_ONCE_INIT;
static ActualAuditV1 ActualAuditGetterV1;
static ActualEntitlementV1 ActualEntitlementGetterV1;
static int IdentityABIStatusV1=ENOTSUP;
static void HexBytesV1(const uint8_t *p,size_t n,char *out) {
 static const char digits[]="0123456789abcdef";
 for(size_t i=0;i<n;i++){out[2*i]=digits[p[i]>>4];out[2*i+1]=digits[p[i]&15];}out[2*n]=0;
}
static bool ExactEntryV1(void *entry,const char *path,uintptr_t rva,const char *uuid) {
 if(!entry || !path || !uuid)return false;
#if __has_feature(ptrauth_calls)
 entry=__builtin_ptrauth_strip(entry,0);
#endif
 Dl_info d={0};if(!dladdr(entry,&d) || !d.dli_fname || strcmp(path,d.dli_fname) || !d.dli_fbase)return false;
 const struct mach_header_64 *h=d.dli_fbase;
 if(h->magic!=MH_MAGIC_64 || h->filetype!=MH_DYLIB || !h->ncmds || h->ncmds>256 || !h->sizeofcmds || h->sizeofcmds>16384 ||
  (uintptr_t)entry<(uintptr_t)h || (uintptr_t)entry-(uintptr_t)h!=rva)return false;
 const uint8_t *at=(const uint8_t *)(h+1),*end=at+h->sizeofcmds;bool found=false;
 for(uint32_t i=0;i<h->ncmds;i++) {
  if((size_t)(end-at)<8)return false;const struct load_command *c=(const void *)at;
  if(c->cmdsize<8 || c->cmdsize&7 || c->cmdsize>(size_t)(end-at))return false;
  if(c->cmd==LC_UUID){char actual[33];if(found || c->cmdsize!=24)return false;HexBytesV1(at+8,16,actual);if(strcmp(actual,uuid))return false;found=true;}
  at+=c->cmdsize;
 }
 return at==end && found;
}
static void InitIdentityV1(void) {
 VM27OriginalV10TransportABI abi={0};if(VM27OriginalV10TransportCopyABI(&abi) ||
  !abi.exactSystemProvider || !abi.exactGetterCode || !abi.exactSecurityProvider)return;
 /* The V10 ABI has already checked exact getter SHA64, UUID and loaded image.
  * Require these lookups to be those same actual entries before using them. */
 void *library=dlopen("/usr/lib/system/libxpc.dylib",RTLD_NOW|RTLD_LOCAL);if(!library)return;
 ActualAuditGetterV1=(ActualAuditV1)dlsym(library,"xpc_connection_get_audit_token");
 ActualEntitlementGetterV1=(ActualEntitlementV1)dlsym(library,"xpc_connection_copy_entitlement_value");
 bool exact=ExactEntryV1((void *)ActualAuditGetterV1,"/usr/lib/system/libxpc.dylib",abi.auditGetterRVA,abi.providerUUID) &&
  ExactEntryV1((void *)ActualEntitlementGetterV1,"/usr/lib/system/libxpc.dylib",abi.entitlementGetterRVA,abi.providerUUID) &&
  ExactEntryV1((void *)SecTaskCreateWithAuditToken,VM27_ORIGINAL_SECURITY_PATH,abi.secTaskCreateRVA,abi.securityUUID) &&
  ExactEntryV1((void *)SecTaskCopyValueForEntitlement,VM27_ORIGINAL_SECURITY_PATH,abi.secTaskCopyRVA,abi.securityUUID) &&
  ExactEntryV1((void *)SecTaskEntitlementsValidated,VM27_ORIGINAL_SECURITY_PATH,abi.secTaskValidatedRVA,abi.securityUUID);
 if(exact)IdentityABIStatusV1=0;
 /* Retain the actual provider handle for callback/function pointer lifetime. */
}
static bool ActualBooleanV1(xpc_connection_t connection,SecTaskRef task,const char *key,int *error) {
 CFStringRef name=CFStringCreateWithCString(kCFAllocatorDefault,key,kCFStringEncodingUTF8);
 if(!name){*error=ENOMEM;return false;}
 CFErrorRef failure=NULL;CFTypeRef value=SecTaskCopyValueForEntitlement(task,name,&failure);
 bool sec=value && !failure && CFGetTypeID(value)==CFBooleanGetTypeID() && CFBooleanGetValue((CFBooleanRef)value);
 if(failure){*error=EACCES;CFRelease(failure);}if(value)CFRelease(value);CFRelease(name);
 xpc_object_t native=ActualEntitlementGetterV1(connection,key);
 bool peer=native && xpc_get_type(native)==XPC_TYPE_BOOL && xpc_bool_get_value(native);
 if(native)xpc_release(native);return sec && peer;
}
int VM27OwnedAppCheckActualParentMessageV1(xpc_object_t message,VM27OwnedAppParentIdentityV1 *out) {
 if(!out)return EINVAL;memset(out,0,sizeof(*out));
 if(!message || xpc_get_type(message)!=XPC_TYPE_DICTIONARY)return EPROTO;
 pthread_once(&IdentityOnceV1,InitIdentityV1);if(IdentityABIStatusV1)return IdentityABIStatusV1;
 pid_t parent=getppid();if(parent<=1)return EACCES;
 audit_token_t token={{0}},connectionToken={{0}};xpc_dictionary_get_audit_token(message,&token);
 xpc_connection_t connection=xpc_dictionary_get_remote_connection(message);
 if(!connection || token.val[5]!=(uint32_t)parent || !token.val[7])return EACCES;
 ActualAuditGetterV1(connection,&connectionToken);if(memcmp(&token,&connectionToken,sizeof(token)))return EACCES;
 uint8_t digest[20]={0};uint32_t status=0;
 if(csops_audittoken(parent,5,digest,sizeof(digest),&token) || csops_audittoken(parent,0,&status,sizeof(status),&token) || !(status&1))return EACCES;
 SecTaskRef task=SecTaskCreateWithAuditToken(kCFAllocatorDefault,token);if(!task)return EACCES;
 bool validated=SecTaskEntitlementsValidated(task);int error=0;uint32_t mask=0;
 if(ActualBooleanV1(connection,task,"com.apple.private.virtualization",&error))mask=3;
 else if(ActualBooleanV1(connection,task,"com.apple.security.virtualization",&error))mask=1;
 CFRelease(task);
 if(error || !(mask&1) || getppid()!=parent)return error?error:EACCES;
 VM27OwnedAppParentIdentityV1 actual={token.val[5],token.val[7],status,mask,{0},validated};HexBytesV1(digest,20,actual.kernelCDHash);*out=actual;return 0;
}
