#include "modern_gic_v3_engine_v1.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "vm27_id_aa64isar3_v1.inc"

int main(void) {
    // Actual faulting guest MRS: d5380674, S3_0_C0_C6_3 -> X20.
    const uint32_t observed = 0x6236028d;
    unsigned passed = 0;
    for (unsigned rt = 0; rt < 32; ++rt) {
        uint32_t esr = (observed & ~(31u << 5)) | rt << 5;
        for (unsigned flags = 0; flags < 16; ++flags) {
            for (unsigned mode = 0; mode < 32; ++mode) {
                VM27GICTrapResultV1 output;
                memset(&output, 0xa5, sizeof output);
                VM27GICTrapResultV1 before = output;
                _Bool handled = VM27IDAA64ISAR3PrepareV1(esr, flags << 28 | mode, &output);
                assert(handled == (mode == 4 || mode == 5));
                if (handled) {
                    assert(output.handled && output.is64Bit && !output.write && !output.signExtend);
                    assert(!output.controllerStateCommitted && output.registerIndex == rt);
                    assert(output.bytes == 8 && output.readValue == 0);
                } else assert(!memcmp(&output, &before, sizeof output));
                ++passed;
            }
        }
        // Preserve undefined handling for writes, another ID register, a
        // different exception class, and an invalid instruction length.
        const uint32_t rejected[] = {esr & ~1u, esr ^ (1u << 17),
            esr ^ (1u << 26), esr & ~(1u << 25)};
        for (unsigned i = 0; i < sizeof rejected / sizeof rejected[0]; ++i) {
            VM27GICTrapResultV1 output;
            memset(&output, 0xa5, sizeof output);
            VM27GICTrapResultV1 before = output;
            assert(!VM27IDAA64ISAR3PrepareV1(rejected[i], 5, &output));
            assert(!memcmp(&output, &before, sizeof output));
            ++passed;
        }
    }
    assert(!VM27IDAA64ISAR3PrepareV1(observed, 5, NULL));
    printf("ID_AA64ISAR3 native-exit policy: %u cases passed\n", passed + 1);
}
