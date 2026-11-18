// Bluetooth-only raw transport. No CoreBluetooth manager or profile proxy.
#pragma once
#include <stdint.h>
#include <stddef.h>
typedef struct VM27BTRawChannel VM27BTRawChannel;
// protocol is one of hci, acl, sco, iso. create never changes radio power.
VM27BTRawChannel *VM27BTRawOpen(const char *protocol, int *error);
void VM27BTRawClose(VM27BTRawChannel *channel);
int VM27BTRawFD(VM27BTRawChannel *channel);
int VM27BTRawWrite(VM27BTRawChannel *channel, const void *packet, size_t length);
// Returns packet length, 0 when empty, -1 on error. Strips only the audited
// optional 8-byte Apple controller footer after a complete standard HCI packet.
int VM27BTRawRead(VM27BTRawChannel *channel, void *packet, size_t capacity);
