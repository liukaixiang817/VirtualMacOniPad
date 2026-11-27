#pragma once

// Helpers are compiled for one audited guest build. A profile adds no support
// for other point releases and never relaxes runtime build or payload checks.
#ifndef VM27_RADIO_GUEST_MAJOR
#define VM27_RADIO_GUEST_MAJOR 26
#endif

#if VM27_RADIO_GUEST_MAJOR == 15
#define VM27_RADIO_GUEST_BUILD "24G90"
#define VM27_RADIO_BLUETOOTH_MODULE "VM27ExclusiveBluetoothGuest15V1.dylib"
#define VM27_RADIO_BLUETOOTH_CONSTRUCTOR "exclusive-before-main-15-v1.json"
#define VM27_RADIO_PREPARE_COMPONENT "radio-prepare-boot15-v1"
#define VM27_RADIO_PREPARE_HELPER "com.virtualmac.RadioPrepareBoot15V1"
#define VM27_RADIO_BOOT_ROOT "/Library/VirtualMac/SharedRadio/Boot15"
#elif VM27_RADIO_GUEST_MAJOR == 26
#define VM27_RADIO_GUEST_BUILD "25G83"
#define VM27_RADIO_BLUETOOTH_MODULE "VM27ExclusiveBluetoothGuestV15.dylib"
#define VM27_RADIO_BLUETOOTH_CONSTRUCTOR "exclusive-before-main-v15.json"
#define VM27_RADIO_PREPARE_COMPONENT "radio-prepare-boot26-v1"
#define VM27_RADIO_PREPARE_HELPER "com.virtualmac.RadioPrepareBoot26V1"
#define VM27_RADIO_BOOT_ROOT "/Library/VirtualMac/SharedRadio/Boot26"
#elif VM27_RADIO_GUEST_MAJOR == 27
#if defined(VM27_RADIO_GUEST_BUILD_26B131)
#define VM27_RADIO_GUEST_BUILD "26B131"
#else
#define VM27_RADIO_GUEST_BUILD "26A5416b"
#endif
#define VM27_RADIO_BLUETOOTH_MODULE "VM27ExclusiveBluetoothGuest27V1.dylib"
#define VM27_RADIO_BLUETOOTH_CONSTRUCTOR "exclusive-before-main-27-v1.json"
#define VM27_RADIO_PREPARE_COMPONENT "radio-prepare-boot27-v1"
#define VM27_RADIO_PREPARE_HELPER "com.virtualmac.RadioPrepareBoot27V1"
#define VM27_RADIO_BOOT_ROOT "/Library/VirtualMac/SharedRadio/Boot27"
#else
#error Unsupported automatic radio guest profile
#endif

#define VM27_RADIO_PREPARE_PATH "/Library/PrivilegedHelperTools/" VM27_RADIO_PREPARE_HELPER
