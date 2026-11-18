#import <Foundation/Foundation.h>
#include "VM27ExclusiveBluetoothSkywalkV1.h"
#include <mach/mach.h>
#include <dlfcn.h>
#include <errno.h>
#include <uuid/uuid.h>
#include <string.h>
// ABI: Apple XNU xnu-8792.41.9 bsd/skywalk/channel/os_channel.h,
// verified against this iPad's 20B101 bluetoothd PCIe transport. Retain all
// immutable fields returned by get_next_slot; only sp_len changes on TX.
typedef struct {uint16_t flags,length;uint32_t index;uint64_t external,buffer,metadata,pad[4];} Slot;
_Static_assert(sizeof(Slot)==64 && offsetof(Slot,buffer)==16,"Skywalk slot ABI");
struct VM27BTRawChannel {void *channel,*rx,*tx;uint8_t type;};
static struct {
 CFMutableDictionaryRef (*matching)(const char *);
 mach_port_t (*service)(mach_port_t,CFDictionaryRef);
 CFTypeRef (*search)(mach_port_t,const char *,CFStringRef,CFAllocatorRef,uint32_t);
 kern_return_t (*release)(mach_port_t);
 void *(*create)(const unsigned char *,uint32_t);
 void (*destroy)(void *);
 int (*fd)(void *),(*sync)(void *,uint32_t);
 uint32_t (*ringID)(void *,uint32_t);
 void *(*rx)(void *,uint32_t),*(*tx)(void *,uint32_t);
 void *(*next)(void *,void *,Slot *);
 void (*set)(void *,void *,const Slot *);
 int (*advance)(void *,void *);
 BOOL loaded;
} api;
static BOOL load(void) {
 static dispatch_once_t once;dispatch_once(&once,^{
  void *io=dlopen("/System/Library/Frameworks/IOKit.framework/IOKit",RTLD_NOW|RTLD_LOCAL);
  void *system=dlopen("/usr/lib/libSystem.B.dylib",RTLD_NOW|RTLD_LOCAL);
#define IO(field,name) api.field=dlsym(io,name)
#define SYS(field,name) api.field=dlsym(system,name)
  IO(matching,"IOServiceMatching");IO(service,"IOServiceGetMatchingService");
  IO(search,"IORegistryEntrySearchCFProperty");IO(release,"IOObjectRelease");
  SYS(create,"os_channel_create");SYS(destroy,"os_channel_destroy");SYS(fd,"os_channel_get_fd");
  SYS(sync,"os_channel_sync");SYS(ringID,"os_channel_ring_id");SYS(rx,"os_channel_rx_ring");SYS(tx,"os_channel_tx_ring");
  SYS(next,"os_channel_get_next_slot");SYS(set,"os_channel_set_slot_properties");SYS(advance,"os_channel_advance_slot");
#undef IO
#undef SYS
  api.loaded=api.matching&&api.service&&api.search&&api.release&&api.create&&api.destroy&&api.fd&&api.sync&&api.ringID&&api.rx&&api.tx&&api.next&&api.set&&api.advance;
 });return api.loaded;
}
VM27BTRawChannel *VM27BTRawOpen(const char *protocol,int *error) { @autoreleasepool {
 int failure=ENOSYS;VM27BTRawChannel *result=NULL;
 uint8_t type=!strcmp(protocol,"hci")?4:!strcmp(protocol,"acl")?2:!strcmp(protocol,"sco")?3:!strcmp(protocol,"iso")?5:0;
 if(!type){failure=EINVAL;goto done;}
 if(!load())goto done;
 CFMutableDictionaryRef match=api.matching("AppleConvergedIPCInterface");
 if(!match){failure=ENOMEM;goto done;}
 CFStringRef name=CFStringCreateWithCString(NULL,protocol,kCFStringEncodingASCII);
 CFDictionarySetValue(match,CFSTR("ACIPCInterfaceProtocol"),name);CFRelease(name);
 mach_port_t service=api.service(MACH_PORT_NULL,match);
 if(!service){failure=ENODEV;goto done;}
 CFTypeRef value=api.search(service,"IOService",CFSTR("IOSkywalkNexusUUID"),NULL,1);
 api.release(service);
 char text[37]={0};uuid_t uuid;
 BOOL valid=value&&CFGetTypeID(value)==CFStringGetTypeID()&&CFStringGetCString(value,text,sizeof(text),kCFStringEncodingASCII)&&uuid_parse(text,uuid)==0;
 if(value)CFRelease(value);
 if(!valid){failure=EPROTO;goto done;}
 errno=0;void *channel=api.create(uuid,0);
 if(!channel){failure=errno?errno:EIO;goto done;}
 result=calloc(1,sizeof(*result));
 if(!result){api.destroy(channel);failure=ENOMEM;goto done;}
 result->channel=channel;result->type=type;
 result->tx=api.tx(channel,api.ringID(channel,0));
 result->rx=api.rx(channel,api.ringID(channel,2));
 if(!result->tx||!result->rx){VM27BTRawClose(result);result=NULL;failure=EPROTO;goto done;}
 failure=0;
 done:if(error)*error=failure;return result;
} }
void VM27BTRawClose(VM27BTRawChannel *c){if(c){if(c->channel)api.destroy(c->channel);free(c);}}
int VM27BTRawFD(VM27BTRawChannel *c){return c?api.fd(c->channel):-1;}
int VM27BTRawWrite(VM27BTRawChannel *c,const void *packet,size_t length){
 if(!c||!packet||!length||length>65535){errno=EINVAL;return -1;}
 Slot p={0};void *slot=api.next(c->tx,NULL,&p);
 if(!slot){errno=EAGAIN;return -1;}
 if(length>p.length||!p.buffer){errno=EMSGSIZE;return -1;}
 memcpy((void *)(uintptr_t)p.buffer,packet,length);p.length=(uint16_t)length;
 api.set(c->tx,slot,&p);
 int r=api.advance(c->tx,slot);if(r){errno=r;return -1;}
 r=api.sync(c->channel,0);if(r){errno=r;return -1;}return 0;
}
int VM27BTRawRead(VM27BTRawChannel *c,void *packet,size_t capacity){
 if(!c||!packet){errno=EINVAL;return -1;}
 Slot p={0};void *slot=api.next(c->rx,NULL,&p);if(!slot)return 0;
 const uint8_t *b=(const uint8_t *)(uintptr_t)p.buffer;size_t n=p.length,expected=0;
 if(b&&c->type==4&&n>=2)expected=2+b[1];
 else if(b&&c->type==2&&n>=4)expected=4+(b[2]|(b[3]<<8));
 else if(b&&c->type==3&&n>=3)expected=3+b[2];
 else if(b&&c->type==5&&n>=4)expected=4+((b[2]|(b[3]<<8))&0x3fff);
 BOOL valid=expected&&(n==expected||n==expected+8)&&expected<=capacity;
 if(valid)memcpy(packet,b,expected);
 int r=api.advance(c->rx,slot);if(!r)r=api.sync(c->channel,1);
 if(r||!valid){errno=r?r:EPROTO;return -1;}return (int)expected;
}
