#ifndef VM27_OWN_UIKIT_INGRESS_VALUES_V1_H
#define VM27_OWN_UIKIT_INGRESS_VALUES_V1_H
#include "modern_input_packet_v2.h"
typedef struct { double x, y, width, height; } VM27InputViewportV1;
typedef struct {
    uint64_t primaryContact;
    double normalizedX, normalizedY;
    bool hasPosition, pressed;
} VM27OwnPointerStateV1;
typedef struct { double x, y; int64_t buttons; } VM27OwnPointerArgumentsV1;
/* Own UI policy: one direct touch controls the left pointer button. Multiple
 * contacts cancel that owned button, leaving the two-contact pan to scrolling.
 * No CG/NSEvent, raw hardware field, mouse grab, or host cursor is synthesized.
 * Result/state outputs are unchanged on errors/Empty; commit next state only
 * when the genuine sender is about to be entered. */
VM27InputResult vm27_own_pointer_arguments_v1(const VM27InputPacket *,
    VM27InputViewportV1, const VM27OwnPointerStateV1 *,
    VM27OwnPointerArgumentsV1 *, VM27OwnPointerStateV1 *next);
/* Existing app usage-to-Mac-key table, independent of any backend image.
 * Original27 value initializer requires type 0=down, 1=up and 16-bit keycode. */
VM27InputResult vm27_own_key_arguments_v1(const VM27InputPacket *,
    int64_t *type, uint16_t *keycode);
#endif
