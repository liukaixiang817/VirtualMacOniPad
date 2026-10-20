// Exact original27 double packet fields for genuine native HIDEvent objects.
// This component has no object constructor, runtime registration, or device I/O.
#include "modern_iokit_double_event_packets.h"
#include <string.h>

static void write16(uint8_t *packet, unsigned offset, uint16_t value) {
    memcpy(packet + offset, &value, sizeof(value));
}
static void write32(uint8_t *packet, unsigned offset, uint32_t value) {
    memcpy(packet + offset, &value, sizeof(value));
}
static void write_double(uint8_t *packet, unsigned offset, double value) {
    // No arithmetic: preserve signed zero, infinities, and NaN payload bits.
    memcpy(packet + offset, &value, sizeof(value));
}
void vm27_iokit_write_force_stage_packet(uint8_t *packet, uint32_t index,
    uint32_t stage, double progress, double stage_pressure, double pressure,
    double accumulated_pressure, double overall_progress) {
    write32(packet, 16, index);
    packet[20] = (uint8_t)stage;
    write_double(packet, 24, progress);
    write_double(packet, 32, stage_pressure);
    write_double(packet, 40, pressure);
    write_double(packet, 48, accumulated_pressure);
    write_double(packet, 56, overall_progress);
}
void vm27_iokit_write_touch_radius_packet(uint8_t *packet, uint32_t usage_page,
    uint32_t usage, uint32_t mask, uint32_t touching, double x, double y,
    double z, double pressure, double major_radius, double minor_radius) {
    write16(packet, 16, (uint16_t)usage_page);
    write16(packet, 18, (uint16_t)usage);
    write_double(packet, 24, z);
    write_double(packet, 32, pressure);
    packet[40] = touching != 0;
    write32(packet, 44, mask);
    write_double(packet, 48, x);
    write_double(packet, 56, y);
    write_double(packet, 64, major_radius);
    write_double(packet, 72, minor_radius);
}
