#include <mach/mach_types.h>
extern kern_return_t _start(kmod_info_t *, void *);
extern kern_return_t _stop(kmod_info_t *, void *);
#define VM27_MODULE_DECL(name, version, start, stop) KMOD_EXPLICIT_DECL(name, version, start, stop)
#ifndef VM27_MODULE_VERSION
#define VM27_MODULE_VERSION "0.1.0"
#endif
__attribute__((visibility("default"))) VM27_MODULE_DECL(VM27_MODULE_ID, VM27_MODULE_VERSION, _start, _stop)
__private_extern__ kmod_start_func_t *_realmain = 0;
__private_extern__ kmod_stop_func_t *_antimain = 0;
__private_extern__ int _kext_apple_cc = __APPLE_CC__;
