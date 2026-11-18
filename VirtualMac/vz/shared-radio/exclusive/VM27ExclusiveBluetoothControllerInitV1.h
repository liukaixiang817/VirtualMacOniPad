#pragma once
#include "VM27ExclusiveBluetoothSkywalkV1.h"
#include <poll.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
static double VM27BTMonotonic(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec+t.tv_nsec/1e9;}
// These completions belong to lease preparation, before guest readiness. Never
// inject them into a guest HCI queue that did not issue the commands.
static int VM27BTPrepareCommandResult(VM27BTRawChannel *hci,uint16_t opcode,const uint8_t *parameters,uint8_t count,uint8_t *response,size_t responseSize){
 uint8_t command[258]={(uint8_t)opcode,(uint8_t)(opcode>>8),count};if(count)memcpy(command+3,parameters,count);
 double deadline=VM27BTMonotonic()+2;
 while(VM27BTRawWrite(hci,command,3+count)){
  if(errno!=EAGAIN)return errno;if(VM27BTMonotonic()>=deadline)return ETIMEDOUT;usleep(1000);
 }
 while(VM27BTMonotonic()<deadline){
  uint8_t event[65536];int length=VM27BTRawRead(hci,event,sizeof(event));
  if(length<0)return errno;
  if(length>=6&&event[0]==0x0e&&(event[3]|event[4]<<8)==opcode){
   fprintf(stderr,"[ExclusiveBluetooth] prepare opcode=%04x status=%u\n",opcode,event[5]);
   if(event[5]||length<6+(int)responseSize)return EPROTO;
   if(response&&responseSize)memcpy(response,event+6,responseSize);return 0;
  }
  if(length>=6&&event[0]==0x0f&&(event[4]|event[5]<<8)==opcode&&event[2]){
   fprintf(stderr,"[ExclusiveBluetooth] prepare opcode=%04x status=%u\n",opcode,event[2]);return EPROTO;
  }
  if(!length){struct pollfd p={VM27BTRawFD(hci),POLLIN,0};int result=poll(&p,1,20);if(result<0&&errno!=EINTR)return errno;}
 }return ETIMEDOUT;
}
static int VM27BTPrepareCommand(VM27BTRawChannel *hci,uint16_t opcode,const uint8_t *parameters,uint8_t count){return VM27BTPrepareCommandResult(hci,opcode,parameters,count,NULL,0);}
static int VM27BTPrepareController(VM27BTRawChannel *hci,const uint8_t guestState[7]){
 if(guestState[0]>1)return EPROTO;
 // Stopping bluetoothd alone leaves controller connections and offload state
 // alive. HCI Reset establishes a new owner, without deleting host bond files.
 static const uint8_t allEvents[8]={255,255,255,255,255,255,255,255},enabled=1,leHost[2]={1,0};
 int error=VM27BTPrepareCommand(hci,0x0c03,NULL,0);if(error)return error;
 if((error=VM27BTPrepareCommand(hci,0x0c01,allEvents,8)))return error;
 if((error=VM27BTPrepareCommand(hci,0x2001,allEvents,8)))return error;
 if((error=VM27BTPrepareCommand(hci,0x0c6d,leHost,2)))return error;
 if((error=VM27BTPrepareCommand(hci,0x0c56,&enabled,1)))return error;
 if((error=VM27BTPrepareCommand(hci,0x0c7a,&enabled,1)))return error;
 // Restore the guest's current random address after Reset, before active scan.
 // The seed is private transport metadata, never a log or a command-line arg.
 if(guestState[0]&&(error=VM27BTPrepareCommand(hci,0x2005,guestState+1,6)))return error;
 return 0;
}
