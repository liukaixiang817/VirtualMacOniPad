#ifndef VM27_MODERN_INPUT_PACKET_V2_H
#define VM27_MODERN_INPUT_PACKET_V2_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* V3 adds a discriminated pointer-button payload using an existing scalar
 * slot. sizeof and every V2 field offset remain unchanged.
 * Own copied values only. No Apple object or Apple event ABI is represented. */
typedef enum {
    VM27InputOK = 0, VM27InputEmpty, VM27InputUnsupported, VM27InputInvalid,
    VM27InputStaleEpoch, VM27InputStaleSequence, VM27InputWrongCoordinates,
    VM27InputQueueFull, VM27InputClosed, VM27InputBusy, VM27InputNoMemory,
    VM27InputWrongThread, VM27InputUnavailable
} VM27InputResult;

typedef enum {
    VM27InputTouch = 1, VM27InputHover, VM27InputKey, VM27InputPan,
    VM27InputPinch, VM27InputRotation, VM27InputPointerButtons
} VM27InputSource;

typedef enum {
    VM27InputBegan = 1, VM27InputChanged, VM27InputStationary,
    VM27InputEnded, VM27InputCancelled, VM27InputContactSnapshot
} VM27InputPhase;

enum {
    VM27InputHasPosition = UINT64_C(1) << 0,
    VM27InputHasProcessedScroll = UINT64_C(1) << 1,
    VM27InputHasHIDUsage = UINT64_C(1) << 2,
    VM27InputHasModifiers = UINT64_C(1) << 3,
    VM27InputHasScaleDelta = UINT64_C(1) << 4,
    VM27InputHasRotationRadians = UINT64_C(1) << 5,
    VM27InputHasPhase = UINT64_C(1) << 6,
    VM27InputHasContacts = UINT64_C(1) << 7,
    VM27InputHasPointerButtons = UINT64_C(1) << 8
};

enum {
    VM27InputCapsLock = 1 << 0, VM27InputShift = 1 << 1,
    VM27InputControl = 1 << 2, VM27InputAlternate = 1 << 3,
    VM27InputCommand = 1 << 4, VM27InputNumericPad = 1 << 5
};

typedef struct {
    uint64_t owner_epoch, contact_generation;
    double view_x_points, view_y_points;
    uint32_t phase;
} VM27InputContact;

typedef struct {
    uint32_t version, source;
    uint64_t owner_epoch, event_sequence, coordinate_generation, present;
    double monotonic_timestamp_seconds;
    double view_x_points, view_y_points;
    double processed_scroll_x_points, processed_scroll_y_points;
    double additive_scale_delta, rotation_delta_radians;
    uint32_t hid_usage_page;
    union { uint32_t hid_usage; uint32_t pointer_buttons; };
    uint32_t named_modifiers, phase;
    bool pressed;
    size_t contact_count;
    const VM27InputContact *contacts;
} VM27InputPacket;

typedef struct VM27InputQueue VM27InputQueue;
typedef struct VM27InputLease VM27InputLease;

/* Queue capacity 1..1024; contacts at most 32. A queue has one immutable epoch
 * and coordinate generation. Publication validates before committing sequence
 * or timestamp; every unsuccessful function leaves its output unchanged.
 * No CGEvent raw/accelerated/momentum/sender fields or key-repeat are available.
 */
VM27InputResult vm27_input_queue_create(uint64_t epoch, uint64_t coordinates,
                                      size_t capacity, VM27InputQueue **output);
VM27InputResult vm27_input_queue_publish(VM27InputQueue *, const VM27InputPacket *);
VM27InputResult vm27_input_queue_acquire(VM27InputQueue *, VM27InputLease **output);
const VM27InputPacket *vm27_input_lease_packet(const VM27InputLease *);
/* Recheck immediately before delivery. A disconnected lease remains readable
 * for cleanup but is no longer current. It never contains borrowed UIKit data.
 */
bool vm27_input_lease_is_current(const VM27InputLease *);
typedef VM27InputResult (*VM27InputDelivery)(const VM27InputPacket *, void *context);
/* Execute one short own sink under admission's mutex. Close waits for an
 * admitted sink to finish. The sink must not reenter this queue or its leases;
 * a mere is_current readback alone is not atomic delivery admission. */
VM27InputResult vm27_input_lease_deliver(const VM27InputLease *, VM27InputDelivery, void *context);
void vm27_input_lease_release(VM27InputLease **);
/* Close rejects publication, discards pending packets, and reports Busy while
 * consumer leases drain. Calling close again is permitted. Destroy requires a
 * closed queue with no leases, after every producer/consumer has stopped and
 * all already-entered publish/acquire/deliver/close calls have finished. No
 * thread may access the queue during or after destroy. Closed/no leases alone
 * does not provide lifetime admission for concurrently running C callers.
 */
VM27InputResult vm27_input_queue_close(VM27InputQueue *, uint64_t epoch);
VM27InputResult vm27_input_queue_destroy(VM27InputQueue **);
/* Own timestamp conversion only; it does not prove a hardware clock origin. */
VM27InputResult vm27_input_timestamp_nanoseconds(double seconds, uint64_t *output);

#endif
