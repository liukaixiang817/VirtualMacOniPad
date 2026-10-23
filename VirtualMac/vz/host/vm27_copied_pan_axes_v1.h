#ifndef VM27_COPIED_PAN_AXES_V1_H
#define VM27_COPIED_PAN_AXES_V1_H
#include "modern_vz_scroll_normalization_v1.h"
#include <math.h>

/* UIPan translation is in screen x/y. VZ's private wheel constructor follows
 * the HID scroll axis order: its first component is vertical. Keep the native
 * HID getter path unchanged; only copied UIKit pan values need this rotation.
 * This is the same screen-to-wheel mapping used by the full13 input route. */
static inline VM27InputResult vm27_copied_pan_arguments_v1(double x, double y,
    double speed, uint32_t phase, VM27VZProcessedScrollArgumentsV1 *output)
{
    if (!output || !isfinite(speed) || speed < 0.01 || speed > 1.0)
        return VM27InputInvalid;
    VM27VZProcessedScrollArgumentsV1 args;
    VM27InputResult result = vm27_vz_processed_scroll_arguments_v1(-y,x,0,phase,&args);
    if (result != VM27InputOK) return result;
    args.normalized_x = args.scrolling_x * speed;
    args.normalized_y = args.scrolling_y * speed;
    *output = args;
    return VM27InputOK;
}
#endif
