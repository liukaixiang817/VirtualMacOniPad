#ifndef VM27_MODERN_IOKIT_DOUBLE_EVENT_PACKETS_H
#define VM27_MODERN_IOKIT_DOUBLE_EVENT_PACKETS_H

#include <stdint.h>

// The native allocator supplies the exact size/type/options header and zeros
// the full packet. These writers preserve those bytes and all reserved bytes.
// The layouts come from both complete original27 machine constructors, rather
// than the old fixed-point Force type32 constructor.
void vm27_iokit_write_force_stage_packet(uint8_t *packet, uint32_t index,
    uint32_t stage, double progress, double stage_pressure, double pressure,
    double accumulated_pressure, double overall_progress);
void vm27_iokit_write_touch_radius_packet(uint8_t *packet, uint32_t usage_page,
    uint32_t usage, uint32_t mask, uint32_t touching, double x, double y,
    double z, double pressure, double major_radius, double minor_radius);

#endif
