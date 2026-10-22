#include "modern_input_packet_v3_buttons.h"
#include <math.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    VM27InputPacket packet;
    VM27InputContact contacts[];
} VM27InputNode;

struct VM27InputQueue {
    pthread_mutex_t mutex;
    uint64_t epoch, coordinates, last_sequence;
    double last_timestamp;
    size_t capacity, head, count, leases;
    bool closed, pan_coalescing_v5;
    pid_t owner_pid;
    VM27InputNode **nodes;
};

struct VM27InputLease {
    VM27InputQueue *queue;
    VM27InputNode *node;
};

static VM27InputResult validate(const VM27InputPacket *packet)
{
    if (!packet || packet->version != 1 || !packet->owner_epoch ||
        !packet->event_sequence || !packet->coordinate_generation ||
        !isfinite(packet->monotonic_timestamp_seconds) ||
        packet->monotonic_timestamp_seconds < 0) return VM27InputInvalid;
    uint64_t required = VM27InputHasPhase, allowed = required;
    switch (packet->source) {
    case VM27InputTouch:
        required |= VM27InputHasContacts;
        allowed = required;
        if (packet->phase != VM27InputContactSnapshot) return VM27InputInvalid;
        break;
    case VM27InputHover:
        required |= VM27InputHasPosition;
        allowed = required;
        break;
    case VM27InputPointerButtons:
        required |= VM27InputHasPosition | VM27InputHasPointerButtons;
        allowed = required;
        if (packet->pointer_buttons & ~UINT32_C(7)) return VM27InputUnsupported;
        if (packet->phase != VM27InputBegan && packet->phase != VM27InputChanged &&
            packet->phase != VM27InputStationary && packet->phase != VM27InputEnded &&
            packet->phase != VM27InputCancelled) return VM27InputUnsupported;
        if ((packet->phase == VM27InputCancelled || packet->phase == VM27InputEnded) &&
            packet->pointer_buttons) return VM27InputInvalid;
        break;
    case VM27InputKey:
        required |= VM27InputHasHIDUsage | VM27InputHasModifiers;
        allowed = required;
        if (packet->phase != VM27InputBegan && packet->phase != VM27InputEnded &&
            packet->phase != VM27InputCancelled) return VM27InputUnsupported;
        if (packet->hid_usage_page != 7 || !packet->hid_usage || packet->hid_usage > UINT16_MAX ||
            packet->named_modifiers & ~UINT32_C(63) ||
            packet->pressed != (packet->phase == VM27InputBegan)) return VM27InputInvalid;
        break;
    case VM27InputPan:
        required |= VM27InputHasProcessedScroll | VM27InputHasPosition;
        allowed = required;
        break;
    case VM27InputPinch:
        required |= VM27InputHasScaleDelta | VM27InputHasPosition;
        allowed = required;
        break;
    case VM27InputRotation:
        required |= VM27InputHasRotationRadians | VM27InputHasPosition;
        allowed = required;
        break;
    default: return VM27InputUnsupported;
    }
    if ((packet->present & required) != required) return VM27InputInvalid;
    if (packet->present & ~allowed) return VM27InputUnsupported;
    if (packet->source != VM27InputTouch &&
        (packet->phase < VM27InputBegan || packet->phase > VM27InputCancelled)) return VM27InputInvalid;
    if ((packet->present & VM27InputHasPosition) &&
        (!isfinite(packet->view_x_points) || !isfinite(packet->view_y_points))) return VM27InputInvalid;
    if ((packet->present & VM27InputHasProcessedScroll) &&
        (!isfinite(packet->processed_scroll_x_points) || !isfinite(packet->processed_scroll_y_points))) return VM27InputInvalid;
    if ((packet->present & VM27InputHasScaleDelta) && !isfinite(packet->additive_scale_delta)) return VM27InputInvalid;
    if ((packet->present & VM27InputHasRotationRadians) && !isfinite(packet->rotation_delta_radians)) return VM27InputInvalid;
    if (!(packet->present & VM27InputHasContacts)) {
        if (packet->contact_count || packet->contacts) return VM27InputInvalid;
    } else {
        if (packet->contact_count > 32 || (packet->contact_count && !packet->contacts) ||
            (!packet->contact_count && packet->contacts)) return VM27InputInvalid;
        for (size_t index = 0; index < packet->contact_count; index++) {
            const VM27InputContact *contact = &packet->contacts[index];
            if (contact->owner_epoch != packet->owner_epoch || !contact->contact_generation ||
                !isfinite(contact->view_x_points) || !isfinite(contact->view_y_points) ||
                contact->phase < VM27InputBegan || contact->phase > VM27InputCancelled) return VM27InputInvalid;
            for (size_t prior = 0; prior < index; prior++)
                if (packet->contacts[prior].contact_generation == contact->contact_generation) return VM27InputInvalid;
        }
    }
    return VM27InputOK;
}

VM27InputResult vm27_input_queue_create(uint64_t epoch, uint64_t coordinates,
                                      size_t capacity, VM27InputQueue **output)
{
    if (!output || !epoch || !coordinates || !capacity || capacity > 1024) return VM27InputInvalid;
    VM27InputQueue *queue = calloc(1, sizeof(*queue));
    if (!queue) return VM27InputNoMemory;
    queue->nodes = calloc(capacity, sizeof(*queue->nodes));
    if (!queue->nodes) { free(queue); return VM27InputNoMemory; }
    if (pthread_mutex_init(&queue->mutex, NULL)) {
        free(queue->nodes); free(queue); return VM27InputUnavailable;
    }
    queue->epoch = epoch; queue->coordinates = coordinates; queue->capacity = capacity;
    queue->owner_pid = getpid();
    queue->pan_coalescing_v5 = true;
    *output = queue;
    return VM27InputOK;
}

/* Replace only an unleased, adjacent motion snapshot. Every key/button
 * edge, contact begin/end/cancel and generation boundary remains in FIFO.
 * The newest copied coordinates and actual receipt time replace old motion;
 * no native completion or guest cursor acknowledgement is synthesized. */
static bool replaceable_motion_v4(const VM27InputPacket *old,const VM27InputPacket *next) {
    if(!old || old->source!=next->source)return false;
    if(next->source==VM27InputHover)
        return (old->phase==VM27InputChanged || old->phase==VM27InputStationary) &&
            (next->phase==VM27InputChanged || next->phase==VM27InputStationary);
    if(next->source==VM27InputPointerButtons)
        return old->pointer_buttons==next->pointer_buttons &&
            (old->phase==VM27InputChanged || old->phase==VM27InputStationary) &&
            (next->phase==VM27InputChanged || next->phase==VM27InputStationary);
    if(next->source==VM27InputTouch && old->contact_count==1 && next->contact_count==1) {
        const VM27InputContact *a=old->contacts,*b=next->contacts;
        return a && b && a->owner_epoch==b->owner_epoch && a->contact_generation==b->contact_generation &&
            (a->phase==VM27InputChanged || a->phase==VM27InputStationary) &&
            (b->phase==VM27InputChanged || b->phase==VM27InputStationary);
    }
    return false;
}
/* Only the checked own adapter uses this for a finite A/B diagnostic.
 * Disabling requires an empty, unleased queue; restoring never rewrites input. */
VM27InputResult vm27_input_queue_pan_diagnostic_policy_v1(VM27InputQueue *queue,
    uint64_t epoch,uint64_t coordinates,bool enabled) {
    if(!queue || queue->owner_pid!=getpid())return VM27InputStaleEpoch;
    pthread_mutex_lock(&queue->mutex);
    VM27InputResult result=VM27InputOK;
    if(queue->closed)result=VM27InputClosed;
    else if(queue->epoch!=epoch)result=VM27InputStaleEpoch;
    else if(queue->coordinates!=coordinates)result=VM27InputWrongCoordinates;
    else if(!enabled && (queue->count || queue->leases))result=VM27InputBusy;
    else queue->pan_coalescing_v5=enabled;
    pthread_mutex_unlock(&queue->mutex);return result;
}
/* Preserve scroll distance while preventing a120Hz pan stream from becoming
 * multiple back-to-back native sends at each60Hz pump. Only adjacent changed
 * packets merge; began/end/cancel, other input and acquired leases are barriers.
 * If the sum exceeds the original native range, retain both original packets. */
static bool merge_pending_pan_v5(const VM27InputPacket *old,VM27InputPacket *next) {
    const uint64_t fields=VM27InputHasPhase|VM27InputHasPosition|VM27InputHasProcessedScroll;
    if(!old || old->source!=VM27InputPan || next->source!=VM27InputPan ||
       old->phase!=VM27InputChanged || next->phase!=VM27InputChanged ||
       old->present!=fields || next->present!=fields ||
       old->owner_epoch!=next->owner_epoch ||
       old->coordinate_generation!=next->coordinate_generation)return false;
    double x=old->processed_scroll_x_points+next->processed_scroll_x_points;
    double y=old->processed_scroll_y_points+next->processed_scroll_y_points;
    if(!isfinite(x) || !isfinite(y) || x<=-32768.0 || x>=32768.0 ||
       y<=-32768.0 || y>=32768.0)return false;
    next->processed_scroll_x_points=x;next->processed_scroll_y_points=y;
    return true;
}
VM27InputResult vm27_input_queue_publish(VM27InputQueue *queue, const VM27InputPacket *packet)
{
    if (!queue) return VM27InputInvalid;
    if (queue->owner_pid != getpid()) return VM27InputStaleEpoch;
    VM27InputResult result = validate(packet);
    if (result != VM27InputOK) return result;
    /* The caller owns the scalar/contact input until this call returns. */
    VM27InputNode *node = malloc(sizeof(*node) + packet->contact_count * sizeof(*node->contacts));
    if (!node) return VM27InputNoMemory;
    node->packet = *packet;
    if (packet->contact_count) memcpy(node->contacts, packet->contacts, packet->contact_count * sizeof(*node->contacts));
    node->packet.contacts = packet->contact_count ? node->contacts : NULL;
    pthread_mutex_lock(&queue->mutex);
    if (queue->closed) result = VM27InputClosed;
    else if (packet->owner_epoch != queue->epoch) result = VM27InputStaleEpoch;
    else if (packet->coordinate_generation != queue->coordinates) result = VM27InputWrongCoordinates;
    else if (packet->event_sequence <= queue->last_sequence ||
             packet->monotonic_timestamp_seconds < queue->last_timestamp) result = VM27InputStaleSequence;
    else if (queue->count && queue->nodes[(queue->head+queue->count-1)%queue->capacity] &&
        (replaceable_motion_v4(&queue->nodes[(queue->head+queue->count-1)%queue->capacity]->packet,packet) ||
         (queue->pan_coalescing_v5 && merge_pending_pan_v5(&queue->nodes[(queue->head+queue->count-1)%queue->capacity]->packet,&node->packet)))) {
        size_t tail=(queue->head+queue->count-1)%queue->capacity;
        VM27InputNode *replaced=queue->nodes[tail];queue->nodes[tail]=node;
        queue->last_sequence=packet->event_sequence;
        queue->last_timestamp=packet->monotonic_timestamp_seconds;
        free(replaced);
    }
    else if (queue->count == queue->capacity) result = VM27InputQueueFull;
    else {
        queue->nodes[(queue->head + queue->count) % queue->capacity] = node;
        queue->count++;
        queue->last_sequence = packet->event_sequence;
        queue->last_timestamp = packet->monotonic_timestamp_seconds;
    }
    pthread_mutex_unlock(&queue->mutex);
    if (result != VM27InputOK) free(node);
    return result;
}

VM27InputResult vm27_input_queue_acquire(VM27InputQueue *queue, VM27InputLease **output)
{
    if (!queue || !output) return VM27InputInvalid;
    if (queue->owner_pid != getpid()) return VM27InputStaleEpoch;
    VM27InputLease *lease = malloc(sizeof(*lease));
    if (!lease) return VM27InputNoMemory;
    VM27InputResult result = VM27InputOK;
    pthread_mutex_lock(&queue->mutex);
    if (queue->closed) result = VM27InputClosed;
    else if (!queue->count) result = VM27InputEmpty;
    else if (queue->leases == SIZE_MAX) result = VM27InputBusy;
    else {
        lease->queue = queue; lease->node = queue->nodes[queue->head];
        queue->nodes[queue->head] = NULL;
        queue->head = (queue->head + 1) % queue->capacity;
        queue->count--; queue->leases++;
    }
    pthread_mutex_unlock(&queue->mutex);
    if (result != VM27InputOK) { free(lease); return result; }
    *output = lease;
    return result;
}

const VM27InputPacket *vm27_input_lease_packet(const VM27InputLease *lease)
{
    return lease && lease->queue->owner_pid == getpid() ? &lease->node->packet : NULL;
}

bool vm27_input_lease_is_current(const VM27InputLease *lease)
{
    if (!lease) return false;
    VM27InputQueue *queue = lease->queue;
    if (queue->owner_pid != getpid()) return false;
    pthread_mutex_lock(&queue->mutex);
    bool current = !queue->closed;
    pthread_mutex_unlock(&queue->mutex);
    return current;
}

VM27InputResult vm27_input_lease_deliver(const VM27InputLease *lease, VM27InputDelivery delivery, void *context)
{
    if (!lease || !delivery) return VM27InputInvalid;
    VM27InputQueue *queue = lease->queue;
    if (queue->owner_pid != getpid()) return VM27InputStaleEpoch;
    pthread_mutex_lock(&queue->mutex);
    VM27InputResult result = queue->closed ? VM27InputClosed : delivery(&lease->node->packet, context);
    pthread_mutex_unlock(&queue->mutex);
    return result;
}

void vm27_input_lease_release(VM27InputLease **reference)
{
    if (!reference || !*reference) return;
    VM27InputLease *lease = *reference;
    /* A copied reference in a forked child cannot mutate its parent's stream.
     * Leave child cleanup to process teardown; do not enter inherited locks. */
    if (lease->queue->owner_pid != getpid()) { *reference = NULL; return; }
    pthread_mutex_lock(&lease->queue->mutex);
    lease->queue->leases--;
    free(lease->node);
    pthread_mutex_unlock(&lease->queue->mutex);
    free(lease); *reference = NULL;
}

VM27InputResult vm27_input_queue_close(VM27InputQueue *queue, uint64_t epoch)
{
    if (!queue) return VM27InputInvalid;
    if (queue->owner_pid != getpid()) return VM27InputStaleEpoch;
    pthread_mutex_lock(&queue->mutex);
    VM27InputResult result;
    if (epoch != queue->epoch) result = VM27InputStaleEpoch;
    else {
        queue->closed = true;
        for (size_t index = 0; index < queue->count; index++) {
            size_t slot = (queue->head + index) % queue->capacity;
            free(queue->nodes[slot]); queue->nodes[slot] = NULL;
        }
        queue->count = 0;
        result = queue->leases ? VM27InputBusy : VM27InputOK;
    }
    pthread_mutex_unlock(&queue->mutex);
    return result;
}

VM27InputResult vm27_input_queue_destroy(VM27InputQueue **reference)
{
    if (!reference || !*reference) return VM27InputInvalid;
    VM27InputQueue *queue = *reference;
    if (queue->owner_pid != getpid()) return VM27InputStaleEpoch;
    pthread_mutex_lock(&queue->mutex);
    if (!queue->closed || queue->leases) {
        pthread_mutex_unlock(&queue->mutex); return VM27InputBusy;
    }
    pthread_mutex_unlock(&queue->mutex);
    pthread_mutex_destroy(&queue->mutex);
    free(queue->nodes); free(queue); *reference = NULL;
    return VM27InputOK;
}

VM27InputResult vm27_input_timestamp_nanoseconds(double seconds, uint64_t *output)
{
    if (!output || !isfinite(seconds) || seconds < 0) return VM27InputInvalid;
    double nanoseconds = seconds * 1e9;
    if (!isfinite(nanoseconds) || nanoseconds >= 0x1p64) return VM27InputInvalid;
    *output = (uint64_t)floor(nanoseconds);
    return VM27InputOK;
}
