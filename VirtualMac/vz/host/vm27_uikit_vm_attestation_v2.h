#pragma once
#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
#ifdef __cplusplus
extern "C" {
#endif
/* Query only: this hidden entry cannot enroll or replace a factory owner. */
__attribute__((visibility("hidden"))) BOOL VM27UIKitActualVirtualMachineAttestedV2(
    id vm, Class originalClass, NSError * _Nullable * _Nullable error);
#ifdef __cplusplus
}
#endif
NS_ASSUME_NONNULL_END
