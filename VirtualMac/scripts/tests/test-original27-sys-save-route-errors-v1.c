/* Only local mocked getters and the real private selector lookup execute.
 * The generated two-call blocks are pinned original27 save instructions.
 * Synthetic values below are test sentinels, never native defaults. */
#include "modern_cpu_kernel_system.h"
#include "original27-sys-save-blocks.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

#define MOCK_HV_BAD_ARGUMENT UINT32_C(0xfae94003)
enum { SAVED_OBJECT_BYTES = 0x778 };
typedef struct {
    unsigned calls, failAt;
    bool writeBeforeFailure, privateLookup;
    uint32_t ids[2];
} Mock;
static uint32_t Get(Mock *mock, uint32_t id, uint64_t *out) {
    unsigned at = mock->calls++;
    assert(at < 2); mock->ids[at] = id;
    if (mock->privateLookup) {
        VZKernelSysDescriptor descriptor;
        VZKernelStatus status = VZKernelSysLookup(id, &descriptor);
        if (status != VZ_KERNEL_OK) return MOCK_HV_BAD_ARGUMENT;
    }
    if (at == mock->failAt) {
        if (mock->writeBeforeFailure) *out = UINT64_C(0xfeed0000) + at;
        return MOCK_HV_BAD_ARGUMENT;
    }
    *out = UINT64_C(0x27000000) + at;
    return 0;
}
static uint32_t SaveBlock(Mock *mock, const Original27SaveCall calls[2],
                          unsigned char saved[SAVED_OBJECT_BYTES], unsigned *committed) {
    for (unsigned i = 0; i < 2; ++i) {
        assert(calls[i].saveOffset % sizeof(uint64_t) == 0);
        assert(calls[i].saveOffset <= SAVED_OBJECT_BYTES - sizeof(uint64_t));
        /* Exact STR XZR staging before get; CBNZ precedes LDR/STR commit. */
        uint64_t staged = 0;
        uint32_t status = Get(mock, calls[i].identifier, &staged);
        if (status) return status;
        memcpy(saved + calls[i].saveOffset, &staged, sizeof(staged));
        ++*committed;
    }
    return 0;
}
static void CheckObject(const unsigned char saved[SAVED_OBJECT_BYTES],
                        const Original27SaveCall calls[2], unsigned committed) {
    unsigned char expected[SAVED_OBJECT_BYTES];
    memset(expected, 0xa5, sizeof(expected));
    assert(committed <= 2 && calls[0].saveOffset != calls[1].saveOffset);
    for (unsigned i = 0; i < committed; ++i) {
        uint64_t value = UINT64_C(0x27000000) + i;
        memcpy(expected + calls[i].saveOffset, &value, sizeof(value));
    }
    /* Both real save slots and every other byte, including the final canary,
     * must match. A failing getter may change staging, never this object. */
    assert(!memcmp(saved, expected, sizeof(expected)));
}
int main(void) {
    unsigned cases = 0;
    const Original27SaveCall *blocks[] = {Original27PhysicalTimerSave,
                                         Original27SCXTNUMSave};
    for (unsigned block = 0; block < 2; ++block) {
        const Original27SaveCall *calls = blocks[block];
        for (unsigned i = 0; i < 2; ++i) {
            VZKernelSysDescriptor out, before;
            memset(&out, 0xa5, sizeof(out)); before = out;
            assert(VZKernelSysLookup(calls[i].identifier, &out) == VZ_KERNEL_UNSUPPORTED);
            assert(!memcmp(&out, &before, sizeof(out)));
        }
        unsigned char saved[SAVED_OBJECT_BYTES];
        memset(saved, 0xa5, sizeof(saved));
        unsigned committed = 0; Mock complete = {.failAt=2};
        assert(!SaveBlock(&complete, calls, saved, &committed));
        assert(complete.calls==2 && committed==2);
        assert(complete.ids[0]==calls[0].identifier && complete.ids[1]==calls[1].identifier);
        CheckObject(saved, calls, 2);
        ++cases;
        for (unsigned failed = 0; failed < 2; ++failed) {
            for (unsigned partial = 0; partial < 2; ++partial) {
                memset(saved, 0xa5, sizeof(saved));committed=0;
                Mock mock = {.failAt=failed,.writeBeforeFailure=partial};
                assert(SaveBlock(&mock,calls,saved,&committed)==MOCK_HV_BAD_ARGUMENT);
                assert(mock.calls==failed+1 && committed==failed);
                assert(mock.ids[0]==calls[0].identifier);
                if(failed)assert(mock.ids[1]==calls[1].identifier);
                CheckObject(saved, calls, failed);
                ++cases;
            }
        }
        memset(saved, 0xa5, sizeof(saved));committed=0;
        Mock current = {.failAt=2,.privateLookup=true};
        assert(SaveBlock(&current,calls,saved,&committed)==MOCK_HV_BAD_ARGUMENT);
        assert(current.calls==1 && committed==0);
        assert(current.ids[0]==calls[0].identifier);
        CheckObject(saved, calls, 0);
        ++cases;
    }
    assert(cases==12);
    printf("PASS: %u original27 two-call save/error cases; synthetic host mocks, no CPU/native calls\n",cases);
    return 0;
}
