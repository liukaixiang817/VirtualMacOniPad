#ifndef VM27_HEADLESS_CHECKIN_V1_H
#define VM27_HEADLESS_CHECKIN_V1_H
#include <CoreFoundation/CoreFoundation.h>
#include <stdint.h>

/* Original VMM passes w0=-2 and a borrowed, live CFDictionary. Its one caller
 * ignores x0. The genuine API's nullable 64-bit CF object ABI is proven;
 * its precise public typedef and caller ownership are private/unresolved.
 * Input is a live CF property-list tree, not concurrently mutated during the
 * call. The original main-bundle info path supplies this borrowed input.
 * This implementation returns a borrowed process-lifetime PRIVATE record,
 * never an OS LaunchServices ASN or daemon registration result. */
CFTypeRef _LSApplicationCheckIn(int32_t session, CFDictionaryRef information);

/* Caller provides a valid 8-byte output slot initially NULL. Success retains
 * the real immutable record for the caller; failure does not write the slot. */
int32_t VM27CopyPrivateHeadlessCheckInState(CFDictionaryRef *output);
#endif
