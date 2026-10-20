#import "modern_input_packet_lease_private_v2.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static unsigned checks;
#define CHECK(condition) do { checks++; if (!(condition)) { \
    fprintf(stderr, "CHECK_FAILED line=%d\n", __LINE__); abort(); } } while (0)

static VM27InputPacket packet(uint64_t sequence)
{
    return (VM27InputPacket){.version = 1, .source = VM27InputHover,
        .owner_epoch = 77, .coordinate_generation = 88, .event_sequence = sequence,
        .present = VM27InputHasPosition | VM27InputHasPhase,
        .monotonic_timestamp_seconds = (double)sequence, .phase = VM27InputChanged,
        .view_x_points = 12.5, .view_y_points = -0.0};
}
static VM27InputResult count_sink(const VM27InputPacket *input, void *opaque)
{
    unsigned *count = opaque; (*count)++;
    return input && input->owner_epoch == 77 ? VM27InputOK : VM27InputInvalid;
}
static VM27InputResult throw_sink(const VM27InputPacket *input, void *opaque)
{
    (void)input; (void)opaque;
    @throw [NSException exceptionWithName:@"OwnFixtureSinkException" reason:@"own negative" userInfo:nil];
}
typedef struct {
    pthread_mutex_t mutex;
    pthread_cond_t condition;
    bool entered, release, close_started, close_done;
    unsigned calls;
    VM27InputQueue *queue;
    __unsafe_unretained VM27InputPacketLeaseV2 *lease;
    VM27InputResult delivery_result, close_result;
} Race;

static VM27InputResult held_sink(const VM27InputPacket *input, void *opaque)
{
    Race *race = opaque;
    pthread_mutex_lock(&race->mutex);
    race->entered = true; race->calls++;
    pthread_cond_broadcast(&race->condition);
    while (!race->release) pthread_cond_wait(&race->condition, &race->mutex);
    pthread_mutex_unlock(&race->mutex);
    return input->event_sequence == 3 ? VM27InputOK : VM27InputInvalid;
}
static void *deliver_thread(void *opaque)
{
    Race *race = opaque;
    @autoreleasepool {
        race->delivery_result = [race->lease deliverToSink:held_sink context:race];
    }
    return NULL;
}
static void *close_thread(void *opaque)
{
    Race *race = opaque;
    pthread_mutex_lock(&race->mutex);
    race->close_started = true; pthread_cond_broadcast(&race->condition);
    pthread_mutex_unlock(&race->mutex);
    VM27InputResult result = vm27_input_queue_close(race->queue, 77);
    pthread_mutex_lock(&race->mutex);
    race->close_result = result; race->close_done = true;
    pthread_cond_broadcast(&race->condition);
    pthread_mutex_unlock(&race->mutex);
    return NULL;
}

int main(void)
{
    alarm(15);
    VM27InputQueue *queue = NULL;
    CHECK(vm27_input_queue_create(77, 88, 8, &queue) == VM27InputOK);
    __weak NSObject *weak_owner;
    unsigned sink_calls = 0;
    @autoreleasepool {
        NSObject *owner = [[NSObject alloc] init]; weak_owner = owner;
        CHECK(vm27_input_objc_lease_take_v2(owner, NULL) == nil);
        for (uint64_t sequence = 1; sequence <= 2; sequence++) {
            VM27InputPacket input = packet(sequence);
            CHECK(vm27_input_queue_publish(queue, &input) == VM27InputOK);
            VM27InputLease *raw = NULL;
            CHECK(vm27_input_queue_acquire(queue, &raw) == VM27InputOK);
            VM27InputLease *original = raw;
            CHECK(vm27_input_objc_lease_take_v2(nil, &raw) == nil && raw == original);
            VM27InputPacketLeaseV2 *lease = vm27_input_objc_lease_take_v2(owner, &raw);
            CHECK(lease != nil && raw == NULL && lease.isCurrent);
            CHECK(lease.packet->event_sequence == sequence);
            if (sequence == 1) {
                CHECK([lease deliverToSink:count_sink context:&sink_calls] == VM27InputOK);
                CHECK([lease deliverToSink:NULL context:NULL] == VM27InputInvalid);
                CHECK([lease deliverToSink:throw_sink context:NULL] == VM27InputInvalid);
                CHECK([lease deliverToSink:count_sink context:&sink_calls] == VM27InputOK);
            } else {
                pid_t child = fork(); CHECK(child >= 0);
                if (!child) {
                    unsigned called = 0;
                    bool passed = lease.packet == NULL && !lease.isCurrent &&
                        [lease deliverToSink:count_sink context:&called] == VM27InputStaleEpoch && !called;
                    _exit(passed ? 0 : 19);
                }
                int status; CHECK(waitpid(child, &status, 0) == child);
                CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
            }
        }
        VM27InputPacket input = packet(3);
        CHECK(vm27_input_queue_publish(queue, &input) == VM27InputOK);
        VM27InputLease *raw = NULL;
        CHECK(vm27_input_queue_acquire(queue, &raw) == VM27InputOK);
        VM27InputPacketLeaseV2 *lease = vm27_input_objc_lease_take_v2(owner, &raw);
        owner = nil; CHECK(weak_owner != nil);
        Race race = {.queue = queue, .lease = lease};
        CHECK(!pthread_mutex_init(&race.mutex, NULL) && !pthread_cond_init(&race.condition, NULL));
        pthread_t consumer, closer;
        CHECK(!pthread_create(&consumer, NULL, deliver_thread, &race));
        pthread_mutex_lock(&race.mutex);
        while (!race.entered) pthread_cond_wait(&race.condition, &race.mutex);
        pthread_mutex_unlock(&race.mutex);
        CHECK(!pthread_create(&closer, NULL, close_thread, &race));
        pthread_mutex_lock(&race.mutex);
        while (!race.close_started) pthread_cond_wait(&race.condition, &race.mutex);
        struct timespec limit; CHECK(!clock_gettime(CLOCK_REALTIME, &limit));
        limit.tv_nsec += 100000000;
        if (limit.tv_nsec >= 1000000000) { limit.tv_sec++; limit.tv_nsec -= 1000000000; }
        int waited = 0;
        while (!race.close_done && !waited) waited = pthread_cond_timedwait(&race.condition, &race.mutex, &limit);
        CHECK(waited == ETIMEDOUT && !race.close_done);
        race.release = true; pthread_cond_broadcast(&race.condition);
        pthread_mutex_unlock(&race.mutex);
        CHECK(!pthread_join(consumer, NULL) && !pthread_join(closer, NULL));
        CHECK(race.calls == 1 && race.delivery_result == VM27InputOK && race.close_result == VM27InputBusy);
        CHECK(!lease.isCurrent && lease.packet != NULL);
        CHECK([lease deliverToSink:count_sink context:&sink_calls] == VM27InputClosed);
        CHECK(sink_calls == 2);
        CHECK(!pthread_cond_destroy(&race.condition) && !pthread_mutex_destroy(&race.mutex));
    }
    CHECK(weak_owner == nil);
    /* All producer/consumer/close threads joined and all wrappers drained. */
    CHECK(vm27_input_queue_destroy(&queue) == VM27InputOK && queue == NULL);
    printf("{\"checks\":%u,\"actualFoundationLeaseWrapperExecuted\":true,"
        "\"atomicCloseWaitedForSink\":true,\"sinkExceptionDidNotEscapeMutex\":true,"
        "\"ownerKeptUntilLeaseDrain\":true,\"forkedOwnerRejected\":true,"
        "\"UIKitEventsCaptured\":false,\"deviceOperations\":0,\"nativeHVCalls\":0,\"nativeVMCalls\":0}\n", checks);
    return 0;
}
