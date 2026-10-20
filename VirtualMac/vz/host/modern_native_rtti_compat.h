#ifndef VM27_NATIVE_RTTI_COMPAT_H
#define VM27_NATIVE_RTTI_COMPAT_H
#include <stddef.h>
#include <stdint.h>
namespace __cxxabiv1 {class __si_class_type_info;}
extern void VM27SiCompleteDestructor(__cxxabiv1::__si_class_type_info*) noexcept
    __asm("__ZN10__cxxabiv120__si_class_type_infoD1Ev");
extern void VM27SiBaseDestructor(__cxxabiv1::__si_class_type_info*) noexcept
    __asm("__ZN10__cxxabiv120__si_class_type_infoD2Ev");
extern "C" int VM27NativeRTTIABIStatus();
extern "C" uint64_t VM27NativeRTTICompleteCalls();
extern "C" uint64_t VM27NativeRTTIBaseCalls();
#endif
