#ifndef VM27_MAC_INPUT_UNAVAILABLE_V1_H
#define VM27_MAC_INPUT_UNAVAILABLE_V1_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Own UIKit/headless profile: these entries never consume a Mac event and
 * never produce an NSTouch Class, Swift metadata, or an event-field value. */
__attribute__((noreturn, visibility("default")))
void VM27MacInputUnavailableV1(void);
__attribute__((noreturn, visibility("default")))
double VM27MacDoubleUnavailableV1(const void *event, int32_t field);
__attribute__((noreturn, visibility("default")))
int64_t VM27MacIntegerUnavailableV1(const void *event, int32_t field);
#ifdef __cplusplus
}
#endif
#endif
