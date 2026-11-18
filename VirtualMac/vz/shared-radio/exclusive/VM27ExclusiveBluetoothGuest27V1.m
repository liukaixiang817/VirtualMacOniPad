// Audited 27.0 / 26A5416b variant. Event/data/activation/link-agent ivars have
// the same verified layout as 25G83. Its inquiry-complete method has no status
// argument; the core mutex functions have independently audited locations.
#define VM27_EXCLUSIVE_NATIVE_BUILD "26A5416b"
#define VM27_EXCLUSIVE_NATIVE_UUID_BYTES 0xc5,0x06,0x74,0xec,0x23,0xf5,0x3f,0x03,0x87,0xb2,0x19,0x95,0xad,0xa4,0x74,0x71
#define VM27_EXCLUSIVE_CORE_LOCK_RVA 0xfa4fc
#define VM27_EXCLUSIVE_CORE_UNLOCK_RVA 0xfa60c
#define VM27_EXCLUSIVE_INQUIRY_HAS_STATUS 0
#define VM27_EXCLUSIVE_RECEIPT_SUFFIX "/exclusive-before-main-27-v1.json"
#define VM27InstallExclusiveBluetoothV15 VM27InstallExclusiveBluetooth27V1
#define VM27ExclusiveBluetoothInstallationStatusV15 VM27ExclusiveBluetoothInstallationStatus27V1
#include "VM27ExclusiveBluetoothGuestV15.m"
