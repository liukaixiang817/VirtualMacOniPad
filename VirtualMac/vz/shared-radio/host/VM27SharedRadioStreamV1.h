#import "VM27SharedRadioHostV1.h"
// Borrowed descriptors. Run off the main thread; the owner must keep the main
// run loop alive and close descriptors only after this function returns.
FOUNDATION_EXPORT int VM27SharedRadioServeStreamV1(int input, int output, int cancellation,
                                                  VM27SharedRadioHostV1 *host);
