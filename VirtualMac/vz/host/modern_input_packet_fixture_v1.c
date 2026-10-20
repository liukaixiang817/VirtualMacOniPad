#include "modern_input_packet_v1.h"
#include <math.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>

static _Atomic unsigned checks;
static unsigned rejected_cases;
static void require(bool value)
{
    atomic_fetch_add(&checks, 1);
    if (!value) { fprintf(stderr, "Own packet fixture failed\n"); abort(); }
}
static VM27InputPacket pan(uint64_t sequence)
{
    return (VM27InputPacket){.version = 1, .source = VM27InputPan,
        .owner_epoch = 19, .coordinate_generation = 23, .event_sequence = sequence,
        .monotonic_timestamp_seconds = (double)sequence,
        .present = VM27InputHasPhase | VM27InputHasPosition | VM27InputHasProcessedScroll,
        .phase = VM27InputChanged, .view_x_points = 127.5, .view_y_points = -5.25,
        .processed_scroll_x_points = -3.5, .processed_scroll_y_points = 12.75};
}
static void admission_and_lifetime(void)
{
    VM27InputQueue *queue = NULL;
    require(vm27_input_queue_create(19, 23, 1, &queue) == VM27InputOK);
    VM27InputQueue *same = queue;
    require(vm27_input_queue_create(0, 23, 1, &same) == VM27InputInvalid && same == queue);
    require(vm27_input_queue_create(19, 0, 1, &same) == VM27InputInvalid && same == queue);
    require(vm27_input_queue_create(19, 23, 0, &same) == VM27InputInvalid && same == queue);
    require(vm27_input_queue_create(19, 23, 1025, &same) == VM27InputInvalid && same == queue);
    VM27InputPacket first = pan(1), second = pan(2);
    require(vm27_input_queue_publish(queue, &first) == VM27InputOK);
    require(vm27_input_queue_publish(queue, &second) == VM27InputQueueFull);
    require(vm27_input_queue_publish(queue, &first) == VM27InputStaleSequence);
    VM27InputLease *lease = NULL;
    require(vm27_input_queue_acquire(queue, &lease) == VM27InputOK);
    require(vm27_input_lease_packet(lease)->event_sequence == 1);
    VM27InputLease *unchanged = lease;
    require(vm27_input_queue_acquire(queue, &unchanged) == VM27InputEmpty && unchanged == lease);
    require(vm27_input_queue_publish(queue, &second) == VM27InputOK);
    require(vm27_input_queue_close(queue, 18) == VM27InputStaleEpoch);
    require(vm27_input_lease_is_current(lease));
    require(vm27_input_queue_destroy(&same) == VM27InputBusy && same == queue);
    require(vm27_input_queue_close(queue, 19) == VM27InputBusy);
    require(!vm27_input_lease_is_current(lease));
    require(vm27_input_lease_packet(lease)->processed_scroll_y_points == 12.75);
    require(vm27_input_queue_publish(queue, &second) == VM27InputClosed);
    require(vm27_input_queue_acquire(queue, &unchanged) == VM27InputClosed && unchanged == lease);
    vm27_input_lease_release(&lease);
    require(lease == NULL);
    require(vm27_input_queue_close(queue, 19) == VM27InputOK);
    require(vm27_input_queue_destroy(&queue) == VM27InputOK && queue == NULL);
}
static void rejected_publication(void)
{
    VM27InputQueue *queue = NULL;
    require(vm27_input_queue_create(19, 23, 4, &queue) == VM27InputOK);
    for (unsigned variation = 0; variation < 20; variation++) {
        VM27InputPacket bad = pan(1);
        switch (variation) {
        case 0: bad.version = 2; break;
        case 1: bad.owner_epoch = 0; break;
        case 2: bad.event_sequence = 0; break;
        case 3: bad.coordinate_generation = 0; break;
        case 4: bad.monotonic_timestamp_seconds = NAN; break;
        case 5: bad.monotonic_timestamp_seconds = INFINITY; break;
        case 6: bad.monotonic_timestamp_seconds = -1; break;
        case 7: bad.source = 99; break;
        case 8: bad.present &= ~VM27InputHasPhase; break;
        case 9: bad.present |= UINT64_C(1) << 63; break;
        case 10: bad.phase = 99; break;
        case 11: bad.view_x_points = NAN; break;
        case 12: bad.view_y_points = INFINITY; break;
        case 13: bad.processed_scroll_x_points = NAN; break;
        case 14: bad.processed_scroll_y_points = INFINITY; break;
        case 15: bad.contact_count = 1; break;
        case 16: bad.contacts = (const VM27InputContact *)&bad; break;
        case 17: bad.owner_epoch = 20; break;
        case 18: bad.coordinate_generation = 24; break;
        case 19: bad.present |= VM27InputHasScaleDelta; break;
        }
        require(vm27_input_queue_publish(queue, &bad) != VM27InputOK);
        VM27InputLease *unchanged = NULL;
        require(vm27_input_queue_acquire(queue, &unchanged) == VM27InputEmpty && unchanged == NULL);
        rejected_cases++;
    }
    VM27InputPacket valid = pan(1);
    require(vm27_input_queue_publish(queue, &valid) == VM27InputOK);
    VM27InputLease *lease = NULL;
    require(vm27_input_queue_acquire(queue, &lease) == VM27InputOK);
    require(vm27_input_lease_packet(lease)->event_sequence == 1);
    vm27_input_lease_release(&lease);
    VM27InputPacket backwards = pan(2); backwards.monotonic_timestamp_seconds = 0.5;
    require(vm27_input_queue_publish(queue, &backwards) == VM27InputStaleSequence);
    require(vm27_input_queue_publish(queue, &(VM27InputPacket){0}) == VM27InputInvalid);
    valid = pan(2);
    require(vm27_input_queue_publish(queue, &valid) == VM27InputOK);
    require(vm27_input_queue_close(queue, 19) == VM27InputOK);
    require(vm27_input_queue_destroy(&queue) == VM27InputOK);
}
static void copied_contact_snapshot(void)
{
    VM27InputQueue *queue = NULL;
    require(vm27_input_queue_create(19, 23, 4, &queue) == VM27InputOK);
    VM27InputContact contacts[2] = {{19, 1, -0.0, 17.0, VM27InputBegan},
                                  {19, 9, 3.25, 8.5, VM27InputEnded}};
    VM27InputPacket packet = {.version = 1, .source = VM27InputTouch, .owner_epoch = 19,
        .event_sequence = 1, .coordinate_generation = 23, .monotonic_timestamp_seconds = 0.25,
        .present = VM27InputHasContacts | VM27InputHasPhase, .phase = VM27InputContactSnapshot,
        .contacts = contacts, .contact_count = 2};
    require(vm27_input_queue_publish(queue, &packet) == VM27InputOK);
    contacts[0].view_x_points = 9999; contacts[1].contact_generation = 888;
    VM27InputLease *lease = NULL;
    require(vm27_input_queue_acquire(queue, &lease) == VM27InputOK);
    const VM27InputPacket *copy = vm27_input_lease_packet(lease);
    require(copy != &packet && copy->contacts != contacts && copy->contact_count == 2);
    require(signbit(copy->contacts[0].view_x_points) && copy->contacts[0].view_y_points == 17);
    require(copy->contacts[1].contact_generation == 9 && copy->contacts[1].phase == VM27InputEnded);
    vm27_input_lease_release(&lease);
    packet.event_sequence = 2;
    for (unsigned variation = 0; variation < 7; variation++) {
        VM27InputPacket bad = packet;
        VM27InputContact invalid[2] = {{19, 1, 1, 2, VM27InputChanged}, {19, 9, 3, 4, VM27InputStationary}};
        bad.contacts = invalid;
        switch (variation) {
        case 0: invalid[0].owner_epoch = 20; break;
        case 1: invalid[0].contact_generation = 0; break;
        case 2: invalid[1].contact_generation = 1; break;
        case 3: invalid[0].view_x_points = NAN; break;
        case 4: invalid[1].view_y_points = INFINITY; break;
        case 5: invalid[0].phase = VM27InputContactSnapshot; break;
        case 6: bad.contact_count = 33; break;
        }
        require(vm27_input_queue_publish(queue, &bad) != VM27InputOK);
        rejected_cases++;
    }
    require(vm27_input_queue_publish(queue, &packet) == VM27InputOK);
    require(vm27_input_queue_close(queue, 19) == VM27InputOK);
    require(vm27_input_queue_destroy(&queue) == VM27InputOK);
}
static void own_units_and_key_namespace(void)
{
    uint64_t output = 777;
    const double invalid[] = {-1, NAN, INFINITY, 0x1p64 / 1e9, 1e308};
    for (size_t i = 0; i < sizeof(invalid) / sizeof(invalid[0]); i++) {
        require(vm27_input_timestamp_nanoseconds(invalid[i], &output) == VM27InputInvalid && output == 777);
        rejected_cases++;
    }
    require(vm27_input_timestamp_nanoseconds(1.25, &output) == VM27InputOK && output == 1250000000);
    require(vm27_input_timestamp_nanoseconds(-0.0, &output) == VM27InputOK && output == 0);
    require(vm27_input_timestamp_nanoseconds(nextafter(0x1p64 / 1e9, 0), &output) == VM27InputOK);
    VM27InputQueue *queue = NULL;
    require(vm27_input_queue_create(19, 23, 4, &queue) == VM27InputOK);
    VM27InputPacket key = {.version = 1, .source = VM27InputKey, .owner_epoch = 19,
        .coordinate_generation = 23, .event_sequence = 1, .monotonic_timestamp_seconds = 1,
        .present = VM27InputHasPhase | VM27InputHasHIDUsage | VM27InputHasModifiers,
        .phase = VM27InputBegan, .hid_usage_page = 7, .hid_usage = 4,
        .named_modifiers = VM27InputShift | VM27InputCommand, .pressed = true};
    require(vm27_input_queue_publish(queue, &key) == VM27InputOK);
    VM27InputLease *lease = NULL;
    require(vm27_input_queue_acquire(queue, &lease) == VM27InputOK);
    require(vm27_input_lease_packet(lease)->hid_usage == 4 && vm27_input_lease_packet(lease)->pressed);
    vm27_input_lease_release(&lease);
    for (unsigned variation = 0; variation < 6; variation++) {
        VM27InputPacket bad = key; bad.event_sequence = 2;
        switch (variation) {
        case 0: bad.hid_usage_page = 1; break;
        case 1: bad.hid_usage = 0; break;
        case 2: bad.hid_usage = UINT32_MAX; break;
        case 3: bad.named_modifiers |= 64; break;
        case 4: bad.pressed = false; break;
        case 5: bad.phase = VM27InputStationary; break;
        }
        require(vm27_input_queue_publish(queue, &bad) != VM27InputOK);
        rejected_cases++;
    }
    require(vm27_input_queue_close(queue, 19) == VM27InputOK);
    require(vm27_input_queue_destroy(&queue) == VM27InputOK);
}

enum { stream_count = 2048 };
typedef struct {
    VM27InputQueue *queue;
    _Atomic unsigned finished;
    _Atomic unsigned seen[stream_count + 1];
} Stream;
static VM27InputResult accept_snapshot(const VM27InputPacket *packet, void *context)
{
    Stream *stream = context;
    uint64_t sequence = packet->event_sequence;
    require(sequence >= 1 && sequence <= stream_count);
    require(packet->owner_epoch == 19 && packet->coordinate_generation == 23);
    require(packet->contact_count == 2 && packet->contacts[0].view_x_points == (double)sequence);
    require(packet->contacts[1].view_y_points == -(double)sequence);
    require(atomic_fetch_add(&stream->seen[sequence], 1) == 0);
    return VM27InputOK;
}
static void *produce(void *context)
{
    Stream *stream = context;
    for (uint64_t sequence = 1; sequence <= stream_count; sequence++) {
        VM27InputContact contacts[2] = {{19, 1, (double)sequence, 0, VM27InputChanged},
            {19, 2, 0, -(double)sequence, VM27InputStationary}};
        VM27InputPacket packet = {.version = 1, .source = VM27InputTouch, .owner_epoch = 19,
            .coordinate_generation = 23, .event_sequence = sequence, .monotonic_timestamp_seconds = (double)sequence,
            .present = VM27InputHasContacts | VM27InputHasPhase, .phase = VM27InputContactSnapshot,
            .contact_count = 2, .contacts = contacts};
        VM27InputResult result;
        do {
            result = vm27_input_queue_publish(stream->queue, &packet);
            if (result == VM27InputQueueFull) sched_yield();
        } while (result == VM27InputQueueFull);
        require(result == VM27InputOK);
        contacts[0].view_x_points = NAN; contacts[1].view_y_points = INFINITY;
    }
    return NULL;
}
static void *consume(void *context)
{
    Stream *stream = context;
    while (atomic_load(&stream->finished) < stream_count) {
        VM27InputLease *lease = NULL;
        VM27InputResult result = vm27_input_queue_acquire(stream->queue, &lease);
        if (result == VM27InputEmpty) { sched_yield(); continue; }
        require(result == VM27InputOK && lease != NULL);
        require(vm27_input_lease_deliver(lease, accept_snapshot, stream) == VM27InputOK);
        vm27_input_lease_release(&lease);
        require(lease == NULL);
        atomic_fetch_add(&stream->finished, 1);
    }
    return NULL;
}
static void concurrent_stream(void)
{
    Stream stream = {0};
    require(vm27_input_queue_create(19, 23, 7, &stream.queue) == VM27InputOK);
    pthread_t producer, consumers[4];
    require(pthread_create(&producer, NULL, produce, &stream) == 0);
    for (unsigned i = 0; i < 4; i++) require(pthread_create(&consumers[i], NULL, consume, &stream) == 0);
    require(pthread_join(producer, NULL) == 0);
    for (unsigned i = 0; i < 4; i++) require(pthread_join(consumers[i], NULL) == 0);
    require(atomic_load(&stream.finished) == stream_count);
    for (unsigned i = 1; i <= stream_count; i++) require(atomic_load(&stream.seen[i]) == 1);
    require(vm27_input_queue_close(stream.queue, 19) == VM27InputOK);
    require(vm27_input_queue_destroy(&stream.queue) == VM27InputOK);
}

typedef struct {
    VM27InputQueue *queue;
    VM27InputLease *lease;
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    bool entered, proceed;
    _Atomic bool close_started, close_finished;
    VM27InputResult delivered, closed;
    unsigned calls;
} Race;
static VM27InputResult held_sink(const VM27InputPacket *packet, void *context)
{
    Race *race = context;
    require(packet->processed_scroll_x_points == -3.5);
    pthread_mutex_lock(&race->mutex);
    race->calls++; race->entered = true;
    pthread_cond_broadcast(&race->condition);
    while (!race->proceed) pthread_cond_wait(&race->condition, &race->mutex);
    pthread_mutex_unlock(&race->mutex);
    return VM27InputOK;
}
static void *held_delivery(void *context)
{
    Race *race = context;
    race->delivered = vm27_input_lease_deliver(race->lease, held_sink, race);
    return NULL;
}
static void *close_race(void *context)
{
    Race *race = context;
    atomic_store(&race->close_started, true);
    race->closed = vm27_input_queue_close(race->queue, 19);
    atomic_store(&race->close_finished, true);
    return NULL;
}
static void disconnect_and_fork_boundary(void)
{
    Race race = {0};
    require(pthread_mutex_init(&race.mutex, NULL) == 0 && pthread_cond_init(&race.condition, NULL) == 0);
    require(vm27_input_queue_create(19, 23, 1, &race.queue) == VM27InputOK);
    VM27InputPacket packet = pan(1);
    require(vm27_input_queue_publish(race.queue, &packet) == VM27InputOK);
    require(vm27_input_queue_acquire(race.queue, &race.lease) == VM27InputOK);
    pthread_t delivery, closer;
    require(pthread_create(&delivery, NULL, held_delivery, &race) == 0);
    pthread_mutex_lock(&race.mutex);
    while (!race.entered) pthread_cond_wait(&race.condition, &race.mutex);
    pthread_mutex_unlock(&race.mutex);
    /* The queue mutex is held by another thread at fork. Child PID rejection
     * must precede inherited locking/allocation and must not invoke a sink. */
    pid_t child = fork();
    require(child >= 0);
    if (child == 0) {
        VM27InputLease *untouched = race.lease;
        VM27InputQueue *same = race.queue;
        if (vm27_input_queue_publish(race.queue, &packet) != VM27InputStaleEpoch) _exit(10);
        if (vm27_input_queue_acquire(race.queue, &untouched) != VM27InputStaleEpoch || untouched != race.lease) _exit(11);
        if (vm27_input_lease_is_current(race.lease) || vm27_input_lease_packet(race.lease)) _exit(12);
        if (vm27_input_queue_close(race.queue, 19) != VM27InputStaleEpoch) _exit(13);
        if (vm27_input_queue_destroy(&same) != VM27InputStaleEpoch || same != race.queue) _exit(14);
        if (vm27_input_lease_deliver(race.lease, held_sink, &race) != VM27InputStaleEpoch) _exit(15);
        _exit(0);
    }
    int status;
    require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    require(pthread_create(&closer, NULL, close_race, &race) == 0);
    while (!atomic_load(&race.close_started)) sched_yield();
    require(!atomic_load(&race.close_finished));
    pthread_mutex_lock(&race.mutex);
    race.proceed = true; pthread_cond_broadcast(&race.condition);
    pthread_mutex_unlock(&race.mutex);
    require(pthread_join(delivery, NULL) == 0 && pthread_join(closer, NULL) == 0);
    require(race.delivered == VM27InputOK && race.closed == VM27InputBusy);
    require(race.calls == 1 && !vm27_input_lease_is_current(race.lease));
    require(vm27_input_lease_deliver(race.lease, held_sink, &race) == VM27InputClosed && race.calls == 1);
    vm27_input_lease_release(&race.lease);
    require(vm27_input_queue_destroy(&race.queue) == VM27InputOK);
    pthread_cond_destroy(&race.condition); pthread_mutex_destroy(&race.mutex);
}
int main(void)
{
    alarm(15);
    admission_and_lifetime(); rejected_publication(); copied_contact_snapshot();
    own_units_and_key_namespace(); concurrent_stream(); disconnect_and_fork_boundary();
    alarm(0);
    printf("{\"checks\":%u,\"rejectedOwnPacketsAndUnits\":%u,\"copiedConcurrentSnapshots\":2048,"
        "\"consumerThreads\":4,\"forkedForeignOwnerRejected\":true,\"disconnectWaitedForOwnSink\":true,"
        "\"UIKitEventsCaptured\":false,\"AppleEventsCreated\":false,\"originalUHKExecuted\":false,"
        "\"deviceOperations\":0,\"nativeHVCalls\":0,\"nativeVMCalls\":0,\"full27Backend\":false}\n",
        atomic_load(&checks), rejected_cases);
    return 0;
}
