#pragma once
#import <Foundation/Foundation.h>
#include <stddef.h>

// Called only by the macOS 27 server's shader cache, with bytes kept alive for
// this synchronous call. Returns autoreleased immutable library data, or nil.
// nil preserves the caller's original native Metal path and error contract.
NSData *VZModernConvertUnknownShader(const void *bytes, size_t size,
                                    NSString *inputHash);

// Optional positive publication after a real nonnil/error-free native library.
// No GPU work; any cache failure leaves the existing native result unchanged.
void VZModernRecordSuccessfulNativeLibrary(NSData *converted,
                                          NSString *inputHash);
