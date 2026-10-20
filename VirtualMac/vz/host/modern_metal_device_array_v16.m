/* Retain frozen V9 implementation under a private, unexported C entry. */
#define VM27OwnedChildInitializeVMResultDiagnosticV1 VM27InheritedChildInitializeVMResultDiagnosticV1
#include "modern_metal_device_array_v17.m"
#undef VM27OwnedChildInitializeVMResultDiagnosticV1
#include "vm27_owned_child_exception_bridge_v1.h"

void *VM27ChildInitExceptionOriginalV1(void *caller,int *log) {
    void *original=VM27ChildInitializeOriginalV1(caller);
    *log=VM27ChildInitializeLogV1()?1:0;return original;
}
void VM27ChildInitExceptionEnterV1(void) {
    dprintf(2,"[VM27OwnedChildVMResultV1] stage=enter callerRVA=0x24a78 originalRVA=0x2e9b24 originalCallNext=1 resultNotClaimed=1 exceptionObservation=passthrough-rethrow\n");
}
void VM27ChildInitExceptionReturnedV1(const void *result) {VM27ChildInitializeObserveV1(result);}
static BOOL VM27ExceptionTextReadV1(const char *source,char out[1025]) {
    static const char hex[]="0123456789abcdef";size_t count=0;
    if(!source || (uintptr_t)source>UINTPTR_MAX-256)return NO;
    for(unsigned i=0;i<256;++i) {
        unsigned char c=0;
        if(!PVGSelfReadV1(source+i,1,&c))return NO;
        if(!c){out[count]=0;return YES;}
        if(c>=32 && c<=126 && c!='"' && c!='\\')out[count++]=(char)c;
        else {out[count++]='\\';out[count++]='x';out[count++]=hex[c>>4];out[count++]=hex[c&15];}
    }
    out[count]=0;return YES;
}
void VM27ChildInitExceptionTextV1(const char *kind,const char *name,const char *reason,const void *typeInfo) {
    int saved=errno;char actualName[1025]={0},actualReason[1025]={0};
    uintptr_t words[2]={0};
    if(!name && typeInfo && PVGSelfReadV1(typeInfo,sizeof(words),words)) {
        /* Genuine Darwin LP64 type_info stores its native name pointer at +8.
         * Mask only its documented nonunique-name bit, never call an unknown
         * exception object or infer its what() layout. */
        name=(const char*)(words[1]&UINT64_C(0x7fffffffffffffff));
    }
    BOOL nameRead=VM27ExceptionTextReadV1(name,actualName),reasonRead=VM27ExceptionTextReadV1(reason,actualReason);
    dprintf(2,"[VM27OwnedChildExceptionV1] kind=%s callerRVA=0x24a78 originalRVA=0x2e9b24 typeNameReadable=%u actualTypeName=\"%s\" reasonReadable=%u actualReason=\"%s\" unavailable=%u originalExceptionRethrown=1 resultUnmodified=1\n",
        kind,nameRead?1U:0U,nameRead?actualName:"Unavailable",reasonRead?1U:0U,reasonRead?actualReason:"Unavailable",(!nameRead && !reasonRead)?1U:0U);
    errno=saved;
}
