/* Exact owned-system runtime pins. iOS code derives from actual PID33273
 * xpc-code-native-v1; Mac getter reads from local PID62099. No fallback. */
#include <TargetConditionals.h>
#if TARGET_OS_IPHONE
#define VM27_ORIGINAL_XPC_UUID "7a0ca8d2728537ddae972efaa1de763e"
#define VM27_ORIGINAL_AUDIT_SHA64 "60a2d4d02aeb3b9c2e99a7be2f812d0844b28d7d3c2d495921bbd0acd90c8290"
#define VM27_ORIGINAL_ENTITLEMENT_SHA64 "a212cc76d2c4f614f5369f51f1b2d740e3b79d1360a8c0addf8a0d36f3880ff4"
#define VM27_ORIGINAL_SECURITY_PATH "/System/Library/Frameworks/Security.framework/Security"
#define VM27_ORIGINAL_SECURITY_UUID "d0585f533f5c349fa16ba9710274e733"
#else
#define VM27_ORIGINAL_XPC_UUID "0791121fb5fc3f84bf04115e86d2d882"
#define VM27_ORIGINAL_AUDIT_SHA64 "266c41d9d0c3133908149fe25d396f6d00ddec256d4757c4faff4c9e41a39f6c"
#define VM27_ORIGINAL_ENTITLEMENT_SHA64 "1d96698ab5fb0ac3db1ee2d93f7ba3a932e7f0816091ccde4a8611393cdeb307"
#define VM27_ORIGINAL_SECURITY_PATH "/System/Library/Frameworks/Security.framework/Versions/A/Security"
#define VM27_ORIGINAL_SECURITY_UUID "7b094bb2dd4d3a818c295879451255f5"
#endif
