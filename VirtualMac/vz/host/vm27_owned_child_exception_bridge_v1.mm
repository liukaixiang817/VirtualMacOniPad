#import <Foundation/Foundation.h>
#include "vm27_owned_child_exception_bridge_v1.h"
#include "vm27_owned_child_vm_result_diagnostic_v1.h"
#include <cxxabi.h>
#include <exception>
#include <typeinfo>
#include <errno.h>
#include <ptrauth.h>

static void VM27LogCppExceptionV1(const std::exception &error) noexcept {
    /* Only a genuine caught std::exception base gets its real virtual what().
     * A logging-side exception is contained; it never replaces the original. */
    try {
        const char *name=typeid(error).name();const char *reason=error.what();
        VM27ChildInitExceptionTextV1("cpp-std-exception",name,reason,nullptr);
    } catch(...) {VM27ChildInitExceptionTextV1("cpp-diagnostic-unavailable",nullptr,nullptr,nullptr);}
}
static void VM27LogUnknownCppExceptionV1(void) noexcept {
    try {
        const std::type_info *type=__cxxabiv1::__cxa_current_exception_type();
        VM27ChildInitExceptionTextV1("cpp-unknown",nullptr,nullptr,type);
    } catch(...) {VM27ChildInitExceptionTextV1("cpp-unknown-unavailable",nullptr,nullptr,nullptr);}
}
static void VM27LogObjCExceptionV1(NSException *error) noexcept {
    try {
        @try {
            const char *name=[[error name] UTF8String];const char *reason=[[error reason] UTF8String];
            VM27ChildInitExceptionTextV1("objc-ns-exception",name,reason,nullptr);
        } @catch(...) {VM27ChildInitExceptionTextV1("objc-diagnostic-unavailable",nullptr,nullptr,nullptr);}
    } catch(...) {VM27ChildInitExceptionTextV1("objc-diagnostic-cpp-unavailable",nullptr,nullptr,nullptr);}
}
extern "C" __attribute__((visibility("default")))
void VM27OwnedChildInitializeVMResultDiagnosticV1(void *result,void *actualVM,void *actualConfig) {
    int incoming=errno,log=0;void *caller=ptrauth_strip(__builtin_return_address(0),ptrauth_key_return_address);
    typedef void(*NativeInitializeV1)(void*,void*,void*);
    NativeInitializeV1 original=(NativeInitializeV1)VM27ChildInitExceptionOriginalV1(caller,&log);
    if(log)VM27ChildInitExceptionEnterV1();
    @try {
        try {
            errno=incoming;original(result,actualVM,actualConfig);int nativeErrno=errno;
            if(log)VM27ChildInitExceptionReturnedV1(result);
            errno=nativeErrno;
        } catch(const std::exception &error) {
            int nativeErrno=errno;if(log)VM27LogCppExceptionV1(error);
            errno=nativeErrno;throw;
        } catch(...) {
            int nativeErrno=errno;if(log)VM27LogUnknownCppExceptionV1();
            errno=nativeErrno;throw;
        }
    } @catch(NSException *error) {
        int nativeErrno=errno;if(log)VM27LogObjCExceptionV1(error);
        errno=nativeErrno;@throw;
    }
}
