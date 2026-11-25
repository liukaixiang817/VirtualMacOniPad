#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "reference/legacy_vmm.h"

void VMAppleAccountTestStubV1(const void *request, uint64_t nzcv, uint64_t output[10]);
static const char *names[] = {
#define VM_APPLE_ACCOUNT_PROCESS(name) name,
#include "VMAppleAccountProcessesV1.def"
#undef VM_APPLE_ACCOUNT_PROCESS
    "WindowServer", "kernel_task", "bluetoothd", "softwareupdated", "unknown",
    "sysct", "sysctl-extra", "AKD", "akd ", "AuthenticationServicesAgent-extra"
};
static unsigned checks;
static void check(const uint8_t *proc, uint32_t nzcv) {
    uint64_t result[10] = {0};
    const void *request = proc;
    VMAppleAccountTestStubV1(&request, nzcv, result);
    unsigned expected = (nzcv & (1u << 30)) ? 0 : 1;
    if (proc && hv_legacy_vmm_process_at(proc, 0x700, VM_APPLE_ACCOUNT_PROC_COMM, NULL)) expected = 0;
    char name[33];
    if (hv_legacy_vmm_process_name_at(proc, 0x700, VM_APPLE_ACCOUNT_PROC_COMM, name) &&
        !strcmp(name, "Setup Assistant")) expected = 0;
    assert(result[0] == expected);
    assert(result[1] == nzcv);
    for (unsigned i = 2; i < 10; ++i) assert(result[i] == i + 7);
    ++checks;
}
int main(void) {
    for (unsigned flags = 0; flags < 16; ++flags) {
        check(NULL, flags << 28);
        for (unsigned n = 0; n < sizeof(names) / sizeof(names[0]); ++n) {
            uint8_t proc[0x700] = {0};
            size_t offset = VM_APPLE_ACCOUNT_PROC_COMM;
            size_t length = strlen(names[n]);
            memcpy(proc + offset, names[n], length < 16 ? length : 16);
            memcpy(proc + offset + 17, names[n], length < 32 ? length + 1 : 32);
            check(proc, flags << 28);
            proc[offset] ^= 1;
            check(proc, flags << 28);
            proc[offset] ^= 1;
            proc[offset + (length < 16 ? length : 16)] = 'X';
            check(proc, flags << 28);
            memset(proc + offset + 17, 'X', 33);
            check(proc, flags << 28);
        }
    }
    printf("Native ARM64 scoped sysctl stub: %u cases passed, proc_comm=0x%x\n", checks, VM_APPLE_ACCOUNT_PROC_COMM);
    return 0;
}
