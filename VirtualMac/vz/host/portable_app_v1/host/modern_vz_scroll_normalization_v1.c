#include "modern_vz_scroll_normalization_v1.h"
#include <math.h>

VM27InputResult vm27_vz_processed_scroll_arguments_v1(double x, double y,
    double z, uint32_t native_phase, VM27VZProcessedScrollArgumentsV1 *output) {
    if (!output || !isfinite(x) || !isfinite(y) || !isfinite(z) || z != 0.0 ||
        x <= -32768.0 || x >= 32768.0 || y <= -32768.0 || y >= 32768.0)
        return VM27InputInvalid;
    uint64_t phase;
    switch (native_phase) {
    case 1: phase = 1; break;  /* genuine HID began -> original VZ began */
    case 2: phase = 4; break;  /* changed */
    case 4: phase = 8; break;  /* ended */
    case 8: phase = 16; break; /* cancelled */
    default: return VM27InputUnsupported;
    }
    VM27VZProcessedScrollArgumentsV1 value = { x, y, x / 10.0, y / 10.0, phase, 0 };
    *output = value;
    return VM27InputOK;
}
