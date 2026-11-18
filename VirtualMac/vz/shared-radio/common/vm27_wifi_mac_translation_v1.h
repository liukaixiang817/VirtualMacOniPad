#pragma once
#include <stddef.h>
#include <stdint.h>
// Translate one guest's Ethernet identity while keeping the native Skywalk
// identity unchanged. Returns -1 for malformed supported packets, else 0/1.
int vm27_wifi_mac_translate_v1(uint8_t *,size_t,const uint8_t from[6],const uint8_t to[6]);
