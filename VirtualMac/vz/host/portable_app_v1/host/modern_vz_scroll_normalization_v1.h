#ifndef VM27_VZ_SCROLL_NORMALIZATION_V1_H
#define VM27_VZ_SCROLL_NORMALIZATION_V1_H
#include "modern_input_packet_v2.h"

/* Own precise, processed-point pan domain. This implements the actual original
 * VZ initWithEvent: fallback (second group = raw / 10); it is not a claim of
 * measured hardware acceleration. The caller supplies genuine type6 getter
 * values and named native phase, after checking the native producer identity.
 * This domain has no hardware momentum and maps that explicit absence to 0.
 */
typedef struct {
    double scrolling_x, scrolling_y;
    double normalized_x, normalized_y;
    uint64_t scroll_phase, momentum_phase;
} VM27VZProcessedScrollArgumentsV1;
VM27InputResult vm27_vz_processed_scroll_arguments_v1(double x, double y,
    double z, uint32_t native_phase, VM27VZProcessedScrollArgumentsV1 *output);
#endif
