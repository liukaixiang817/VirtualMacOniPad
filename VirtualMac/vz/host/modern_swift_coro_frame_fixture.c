// Ordinary Mac allocation fixture; contains no VZ, VMM or device operations.
#include <assert.h>
#include <malloc/malloc.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern void *VM27CandidateFrameAlloc(size_t, uint64_t) __asm("_swift_coroFrameAlloc");
static const size_t frame_sizes[] = {0, 1, 2, 7, 15, 16, 17, 24, 32, 40, 48,
    72, 176, 255, 256, 257, 4095, 4096, 4097, 16384, 65536};
static const uint64_t type_ids[] = {0, 1, 0xa766, 0x94b9, 0x9b7d, 0xd773,
    0xffff, UINT64_C(0x123456789abcdef0), UINT64_MAX};

typedef struct { size_t worker; size_t allocations; size_t checks; } Worker;

static void *run_worker(void *opaque) {
    Worker *worker = opaque;
    for (size_t round = 0; round < 8; ++round) {
        for (size_t i = 0; i < sizeof(frame_sizes) / sizeof(frame_sizes[0]); ++i) {
            for (size_t j = 0; j < sizeof(type_ids) / sizeof(type_ids[0]); ++j) {
                size_t requested = frame_sizes[i];
                size_t size = requested ? requested : 1;
                unsigned char *frame = VM27CandidateFrameAlloc(requested, type_ids[j]);
                assert(frame != NULL);
                assert((uintptr_t)frame % 16 == 0);
                assert(malloc_size(frame) >= size);
                worker->checks += 3;
                unsigned char pattern = (unsigned char)(round + i + 3 * j + worker->worker);
                memset(frame, pattern, size);
                assert(frame[0] == pattern && frame[size / 2] == pattern && frame[size - 1] == pattern);
                worker->checks += 3;
                // The same real malloc owner used by the original coroutine
                // cleanup accepts this frame; no synthetic pointer is returned.
                free(frame);
                worker->allocations += 1;
            }
        }
    }
    return NULL;
}

int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--allocation-failure") == 0) {
        volatile size_t impossible_size = (size_t)1 << 53;
        volatile void *result = VM27CandidateFrameAlloc(impossible_size, UINT64_MAX);
        (void)result;
        return 99;
    }
    assert(argc == 1);
    Worker workers[4] = {{0, 0, 0}, {1, 0, 0}, {2, 0, 0}, {3, 0, 0}};
    pthread_t threads[4];
    for (size_t i = 0; i < 4; ++i) assert(pthread_create(&threads[i], NULL, run_worker, &workers[i]) == 0);
    for (size_t i = 0; i < 4; ++i) assert(pthread_join(threads[i], NULL) == 0);
    size_t allocations = 0, checks = 0;
    for (size_t i = 0; i < 4; ++i) {
        allocations += workers[i].allocations;
        checks += workers[i].checks;
    }
    printf("{\"allocations\":%zu,\"freedFrames\":%zu,\"checks\":%zu,\"failures\":0,\"workers\":4}\n",
           allocations, allocations, checks);
    return 0;
}
