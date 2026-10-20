#ifndef VM27_NO_MAC_CURSOR_PORT_V1_H
#define VM27_NO_MAC_CURSOR_PORT_V1_H
#ifdef __cplusplus
extern "C" {
#endif
/* Independent own-UIKit profile: the original macOS VZ view's system-cursor
 * coupling is an unavailable capability. This raises an explicit exception
 * before that method acquires an AppKit mouse tracker or changes host cursor
 * state. No SLS/CGS export, property value, cursor operation or success result
 * is supplied. Genuine VZ input sender/frame/VM methods are separate. */
_Noreturn void VM27NoMacV1(void);
#ifdef __cplusplus
}
#endif
#endif
