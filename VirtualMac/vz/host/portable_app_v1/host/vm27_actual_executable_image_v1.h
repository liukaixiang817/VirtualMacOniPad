#ifndef VM27_ACTUAL_EXECUTABLE_IMAGE_V1_H
#define VM27_ACTUAL_EXECUTABLE_IMAGE_V1_H
#include <stdint.h>
#include <mach-o/loader.h>
#ifdef __cplusplus
extern "C" {
#endif
/* Process-local role identity only. This never grants signature/native rights.
 * The caller still compares the UUID and validates its signed product file. */
typedef struct {
    const struct mach_header_64 *header;
    uint8_t uuid[16];
    uint32_t ncmds, sizeofcmds, dyldIndex;
} VM27ActualExecutableImageV1;
__attribute__((visibility("hidden")))
int VM27ActualExecutableImageFindV1(const char *canonicalExecutable,
                                  VM27ActualExecutableImageV1 *out);
__attribute__((visibility("hidden")))
int VM27ActualExecutableImageFindSelfV1(VM27ActualExecutableImageV1 *out);
#ifdef __cplusplus
}
#endif
#endif
