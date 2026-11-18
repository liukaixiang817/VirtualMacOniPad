// Exact-build native transport replacement. Raw HCI belongs to macOS; no
// advertisement reconstruction, GATT emulation or host pairing approval.
#import <Foundation/Foundation.h>
#include <objc/runtime.h>
#include <objc/message.h>
#include <libproc.h>
#include <sys/sysctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <dlfcn.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdatomic.h>
#include <ptrauth.h>
#include <mach-o/loader.h>
#ifndef VM27_EXCLUSIVE_NATIVE_BUILD
#define VM27_EXCLUSIVE_NATIVE_BUILD "25G83"
#endif
#ifndef VM27_EXCLUSIVE_NATIVE_UUID_BYTES
#define VM27_EXCLUSIVE_NATIVE_UUID_BYTES 0x8b,0xa8,0x89,0x50,0x82,0x6a,0x3f,0x86,0x94,0x45,0x5e,0x0e,0xa7,0x83,0xfc,0xdf
#endif
#ifndef VM27_EXCLUSIVE_CORE_LOCK_RVA
#define VM27_EXCLUSIVE_CORE_LOCK_RVA 0xe6314
#define VM27_EXCLUSIVE_CORE_UNLOCK_RVA 0xe6410
#endif
#ifndef VM27_EXCLUSIVE_INQUIRY_HAS_STATUS
#define VM27_EXCLUSIVE_INQUIRY_HAS_STATUS 1
#endif
#ifndef VM27_EXCLUSIVE_RECEIPT_SUFFIX
#define VM27_EXCLUSIVE_RECEIPT_SUFFIX "/exclusive-before-main-v15.json"
#endif
#if VM27_EXCLUSIVE_INQUIRY_HAS_STATUS
#define VM27_EXCLUSIVE_INQUIRY_SELECTOR "sendHciInquiryCompleteEvent:"
#define VM27_EXCLUSIVE_INQUIRY_ENCODING "v20@0:8I16"
#else
#define VM27_EXCLUSIVE_INQUIRY_SELECTOR "sendHciInquiryCompleteEvent"
#define VM27_EXCLUSIVE_INQUIRY_ENCODING "v16@0:8"
#endif
static void (*CoreLock)(void),(*CoreUnlock)(void);
static Ivar EventIvar,DataIvar;
#include <os/log.h>
static os_log_t Log;
static void step(int value){os_log_with_type(Log,OS_LOG_TYPE_DEFAULT,"VM27Exclusive stage=%{public}d",value);}
static dispatch_queue_t Queue,DeliveryQueue;
static id Manager;
static NSMutableData *Output,*Input;
static dispatch_source_t Reader,Writer,Listener,Heartbeat;
static int Connection=-1,Server=-1;
static uint8_t TransportToken[32],GuestAddressState[7];
static _Atomic(BOOL) Attached;
static BOOL Installed,WriterPaused,TXCheckPending;
static NSMutableArray<NSDictionary *> *PendingTX;
static NSMutableDictionary<NSNumber *,NSNumber *> *OutstandingCommands;
static _Atomic(uint64_t) ConnectionGeneration;
static dispatch_group_t ConnectionSources;
static void drainPendingTX(void);
static BOOL callbacksReady(void){return Manager&&object_getIvar(Manager,EventIvar)&&object_getIvar(Manager,DataIvar);}
static BOOL nativeReady(void){return callbacksReady()&&*((uint8_t *)(__bridge void *)Manager+8);}
static unsigned long long Commands,Events,ACLTx,ACLRx;
static Method CmdMethod,DataMethod,EventMethod,PacketMethod;
static IMP OldCmd,OldData,OldEvent,OldPacket,OldInquiry,OldHciEnabled,OldLeEnabled,OldLmp,OldComplete,OldStatus;
static void (^EventCompletion)(int,char *,uint16_t);
static void (^DataCompletion)(int,char *,uint16_t);
static BOOL supportedNativeImage(const void *image){
 const struct mach_header_64 *header=image;
 if(header->magic!=MH_MAGIC_64||header->filetype!=MH_EXECUTE||header->ncmds>1024||header->sizeofcmds>1048576)return NO;
 const uint8_t expected[16]={VM27_EXCLUSIVE_NATIVE_UUID_BYTES};
 const uint8_t *cursor=(const uint8_t *)(header+1),*end=cursor+header->sizeofcmds;
 for(unsigned i=0;i<header->ncmds;++i){
  if((size_t)(end-cursor)<sizeof(struct load_command))return NO;
  const struct load_command *command=(const void *)cursor;
  if(command->cmdsize<sizeof(*command)||command->cmdsize>(size_t)(end-cursor))return NO;
  if(command->cmd==LC_UUID)return command->cmdsize==sizeof(struct uuid_command)&&!memcmp(((const struct uuid_command *)command)->uuid,expected,16);
  cursor+=command->cmdsize;
 }return NO;
}
static void disconnect(void){
 atomic_store(&Attached,NO);++ConnectionGeneration;[PendingTX removeAllObjects];[OutstandingCommands removeAllObjects];TXCheckPending=NO;
 // GCD can still have a handler queued after cancellation. Keep the descriptor
 // alive until both sources have acknowledged cancellation, so a reused fd
 // cannot receive an old handler. A connection generation fences queued RX.
 int descriptor=Connection;Connection=-1;
 dispatch_group_t sources=ConnectionSources;ConnectionSources=nil;
 if(Reader){dispatch_source_cancel(Reader);Reader=nil;}
 if(Writer){if(WriterPaused)dispatch_resume(Writer);dispatch_source_cancel(Writer);Writer=nil;WriterPaused=NO;}
 if(descriptor>=0){if(sources)dispatch_group_notify(sources,Queue,^{close(descriptor);});else close(descriptor);}

 [Output setLength:0];[Input setLength:0];
 fprintf(stderr,"[ExclusiveBluetoothGuest] detached commands=%llu events=%llu ACLTx=%llu ACLRx=%llu\n",Commands,Events,ACLTx,ACLRx);
}
static BOOL append(uint8_t type,const void *bytes,size_t count){
 if(Connection<0||count>65535||Output.length+count+5>1048576){if(Connection>=0)disconnect();return NO;}
 uint32_t n=htonl((uint32_t)count+1);[Output appendBytes:&n length:4];[Output appendBytes:&type length:1];if(count)[Output appendBytes:bytes length:count];if(Writer&&WriterPaused){WriterPaused=NO;dispatch_resume(Writer);}return YES;
}
// The native simulator schedules activation asynchronously. Preserve the first
// real HCI reset/configuration commands until its completion is ready; never
// feed a leftover host event into a partially initialized HCI core.
static void drainPendingTX(void){
 if(Connection<0||!atomic_load(&Attached)||!PendingTX.count||TXCheckPending)return;
 TXCheckPending=YES;uint64_t generation=ConnectionGeneration;
 dispatch_async(DeliveryQueue,^{BOOL ready=callbacksReady();dispatch_async(Queue,^{
  if(generation!=ConnectionGeneration)return;TXCheckPending=NO;
  if(!ready){dispatch_after(dispatch_time(DISPATCH_TIME_NOW,50*NSEC_PER_MSEC),Queue,^{if(generation==ConnectionGeneration)drainPendingTX();});return;}
  NSArray *packets=[PendingTX copy];[PendingTX removeAllObjects];
  for(NSDictionary *entry in packets){NSData *data=entry[@"data"];uint8_t type=[entry[@"type"]unsignedCharValue];if(!append(type,data.bytes,data.length))break;if(type==1){++Commands;if(data.length>=3){const uint8_t *b=data.bytes;NSNumber *opcode=@(b[0]|b[1]<<8);OutstandingCommands[opcode]=@([OutstandingCommands[opcode]unsignedIntValue]+1);}}else ++ACLTx;}
 });});
}
static BOOL writePacket(id owner,SEL selector,char *bytes,uint16_t length,uint16_t *written,void(*destructor)(void *),uint8_t type){
 (void)owner;(void)selector;if(written)*written=0;
 if(!bytes||!length)return NO;
 // Copy synchronously before invoking the native buffer destructor. No native
 // controller queue waits for network I/O or performs a blocking socket call.
 NSData *copy=[NSData dataWithBytes:bytes length:length];
 BOOL available=Installed;
 if(available)dispatch_async(Queue,^{
  if(type==1&&copy.length==9){const uint8_t *b=copy.bytes;if(b[0]==5&&b[1]==0x20){GuestAddressState[0]=1;memcpy(GuestAddressState+1,b+3,6);}}
  if(PendingTX.count>=64){disconnect();return;}
  [PendingTX addObject:@{@"type":@(type),@"data":copy}];drainPendingTX();
 });
 if(destructor)destructor(bytes);return YES;
}
static BOOL writeCommand(id o,SEL s,char *b,uint16_t n,uint16_t *w,void(*d)(void *)){if(!Installed)return ((BOOL(*)(id,SEL,char *,uint16_t,uint16_t *,void(*)(void *)))OldCmd)(o,s,b,n,w,d);return writePacket(o,s,b,n,w,d,1);}
static BOOL writeData(id o,SEL s,char *b,uint16_t n,uint16_t *w,void(*d)(void *)){if(!Installed)return ((BOOL(*)(id,SEL,char *,uint16_t,uint16_t *,void(*)(void *)))OldData)(o,s,b,n,w,d);return writePacket(o,s,b,n,w,d,2);}
static void virtualEvent(id o,SEL s,void *packet){if(!Installed)((void(*)(id,SEL,void *))OldEvent)(o,s,packet);}
static void virtualData(id o,SEL s,void *packet){if(!Installed)((void(*)(id,SEL,void *))OldPacket)(o,s,packet);}
// A native simulator timer can survive a controller power transition. Its
// inquiry event constructor allocates from an already retired HCI pool. Stop
// simulator events before construction; physical RX bypasses these methods.
#if VM27_EXCLUSIVE_INQUIRY_HAS_STATUS
static void simulatedInquiryComplete(id o,SEL s,unsigned status){if(!Installed)((void(*)(id,SEL,unsigned))OldInquiry)(o,s,status);}
#else
static void simulatedInquiryComplete(id o,SEL s){if(!Installed)((void(*)(id,SEL))OldInquiry)(o,s);}
#endif
static BOOL simulatedHciEventEnabled(id o,SEL s,uint8_t type){return Installed?NO:((BOOL(*)(id,SEL,uint8_t))OldHciEnabled)(o,s,type);}
static BOOL simulatedLeEventEnabled(id o,SEL s,uint8_t type){return Installed?NO:((BOOL(*)(id,SEL,uint8_t))OldLeEnabled)(o,s,type);}
static void simulatedLmp(id o,SEL s,void *packet){if(!Installed)((void(*)(id,SEL,void *))OldLmp)(o,s,packet);}
static void simulatedComplete(id o,SEL s,uint16_t opcode,uint8_t status,char *bytes,uint8_t length){if(!Installed)((void(*)(id,SEL,uint16_t,uint8_t,char *,uint8_t))OldComplete)(o,s,opcode,status,bytes,length);}
static void simulatedStatus(id o,SEL s,uint16_t opcode,uint8_t status){if(!Installed)((void(*)(id,SEL,uint16_t,uint8_t))OldStatus)(o,s,opcode,status);}
static void incoming(uint8_t type,const uint8_t *b,size_t n){
 if(type==0x7d&&n==0){atomic_store(&Attached,YES);drainPendingTX();fprintf(stderr,"[ExclusiveBluetoothGuest] raw controller attached\n");return;}
 if(type==0x7f&&n==0)return;
 BOOL event=type==4&&n>=2&&n==(size_t)2+b[1];
 BOOL data=type==2&&n>=4&&n==(size_t)4+(b[2]|(b[3]<<8));
 if(!atomic_load(&Attached)||(!event&&!data)){disconnect();return;}
 // During startup the HCI core must receive replies to its own reset and
 // capability commands before RF activation can complete. Unsolicited events
 // still wait for activation. Never use activation as a dependency of its
 // own initialization command completions.
 BOOL initializationReply=NO;
 if(event&&n>=6&&(b[0]==0x0e||b[0]==0x0f)){
  unsigned offset=b[0]==0x0e?3:4;NSNumber *opcode=@(b[offset]|b[offset+1]<<8);
  unsigned outstanding=[OutstandingCommands[opcode]unsignedIntValue];
  if(outstanding){initializationReply=YES;if(outstanding==1)[OutstandingCommands removeObjectForKey:opcode];else OutstandingCommands[opcode]=@(outstanding-1);}
 }
 uint64_t generation=atomic_load(&ConnectionGeneration);
 NSData *copy=[NSData dataWithBytes:b length:n];if(event)++Events;else ++ACLRx;
 dispatch_async(DeliveryQueue,^{
  // Use the native HCI core lock and current completion without the virtual
  // simulator's queue ownership. Native callback owns this malloc buffer.
  if(generation!=atomic_load(&ConnectionGeneration)||!atomic_load(&Attached)||!callbacksReady()||(!nativeReady()&&!initializationReply))return;
  CoreLock();
  if(generation!=atomic_load(&ConnectionGeneration)||!atomic_load(&Attached)){CoreUnlock();return;}
  void (^completion)(int,char *,uint16_t)=[object_getIvar(Manager,event?EventIvar:DataIvar)copy];
  if(completion){char *owned=malloc(copy.length);if(owned){memcpy(owned,copy.bytes,copy.length);completion(0,owned,(uint16_t)copy.length);}}
  CoreUnlock();
 });
}
static void acceptConnection(void){
 struct sockaddr_in peer={0};socklen_t length=sizeof(peer);int fd=accept(Server,(void *)&peer,&length);
 if(fd<0){step(1000+errno);return;}step(100);if(peer.sin_family!=AF_INET||ntohl(peer.sin_addr.s_addr)!=INADDR_LOOPBACK||Connection>=0){step(200);close(fd);return;}
 // Authenticate the root relay before exposing the raw controller stream.
 struct pollfd ready={fd,POLLIN,0};uint8_t supplied[32];size_t received=0;
 while(received<sizeof(supplied)){if(poll(&ready,1,1000)<=0){step(300);close(fd);return;}ssize_t n=read(fd,supplied+received,sizeof(supplied)-received);if(n<=0){step(4000+errno);close(fd);return;}received+=n;}
 unsigned difference=0;for(unsigned i=0;i<32;++i)difference|=supplied[i]^TransportToken[i];memset(supplied,0,sizeof(supplied));
 if(difference){step(500);close(fd);return;}step(600);
 int one=1;setsockopt(fd,SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one));fcntl(fd,F_SETFL,O_NONBLOCK);fcntl(fd,F_SETFD,FD_CLOEXEC);
 Connection=fd;++ConnectionGeneration;TXCheckPending=NO;[Output setLength:0];[Input setLength:0];[Output appendBytes:"VM27BTRAW2\n"length:11];[Output appendBytes:GuestAddressState length:sizeof(GuestAddressState)];
 ConnectionSources=dispatch_group_create();dispatch_group_t sources=ConnectionSources;
 uint64_t generation=atomic_load(&ConnectionGeneration);
 dispatch_group_enter(sources);dispatch_group_enter(sources);
 Reader=dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,fd,0,Queue);
 dispatch_source_set_cancel_handler(Reader,^{dispatch_group_leave(sources);});
 dispatch_source_set_event_handler(Reader,^{
  if(Connection!=fd||generation!=atomic_load(&ConnectionGeneration))return;
  uint8_t bytes[8192];ssize_t n=read(fd,bytes,sizeof(bytes));
  if(n<=0){if(n==0||(errno!=EAGAIN&&errno!=EINTR))disconnect();return;}[Input appendBytes:bytes length:n];
  if(Input.length>131072){disconnect();return;}
  while(Input.length>=5){const uint8_t *b=Input.bytes;uint32_t size;memcpy(&size,b,4);size=ntohl(size);
   if(!size||size>65536){disconnect();return;}if(Input.length<size+4)break;
   incoming(b[4],b+5,size-1);if(Connection<0)return;[Input replaceBytesInRange:NSMakeRange(0,size+4)withBytes:NULL length:0];
  }
 });dispatch_resume(Reader);
 Writer=dispatch_source_create(DISPATCH_SOURCE_TYPE_WRITE,fd,0,Queue);
 dispatch_source_set_cancel_handler(Writer,^{dispatch_group_leave(sources);});
 WriterPaused=NO;
 dispatch_source_set_event_handler(Writer,^{
  if(Connection!=fd||generation!=atomic_load(&ConnectionGeneration))return;
  if(Output.length){ssize_t count=write(fd,Output.bytes,Output.length);if(count>0)[Output replaceBytesInRange:NSMakeRange(0,count)withBytes:NULL length:0];else if(count<0&&errno!=EAGAIN&&errno!=EINTR){disconnect();return;}}
  if(!Output.length&&Writer){WriterPaused=YES;dispatch_suspend(Writer);}
 });dispatch_resume(Writer);
}
static BOOL method(Class cls,const char *name,const char *types){Method m=class_getInstanceMethod(cls,sel_registerName(name));Dl_info d={0};return m&&!strcmp(method_getTypeEncoding(m),types)&&dladdr((void *)method_getImplementation(m),&d)&&d.dli_fname&&!strcmp(d.dli_fname,"/usr/sbin/bluetoothd");}
static id blockAt(id object,ptrdiff_t offset){unsigned count=0;Ivar *ivars=class_copyIvarList([object class],&count);id result=nil;
 for(unsigned i=0;i<count;++i)if(ivar_getOffset(ivars[i])==offset&&!strncmp(ivar_getTypeEncoding(ivars[i]),"@",1))result=object_getIvar(object,ivars[i]);free(ivars);return result;}
__attribute__((visibility("default"))) int VM27ExclusiveBluetoothInstallationStatusV15=-1;
__attribute__((visibility("default"))) int VM27InstallExclusiveBluetoothV15(const char *expectedBoot,const char *tokenHex){
 if(!tokenHex||strlen(tokenHex)!=64)return VM27ExclusiveBluetoothInstallationStatusV15=EINVAL;
 for(unsigned i=0;i<32;++i){unsigned byte=0;if(sscanf(tokenHex+2*i,"%2x",&byte)!=1)return VM27ExclusiveBluetoothInstallationStatusV15=EINVAL;TransportToken[i]=(uint8_t)byte;}
 Log=os_log_create("com.virtualmac.shared-radio","ExclusiveBluetooth");
 if(Installed)return EALREADY;char boot[64]={0},build[32]={0},path[PROC_PIDPATHINFO_MAXSIZE]={0};size_t n=sizeof(boot),m=sizeof(build);
 if(geteuid()||!expectedBoot||sysctlbyname("kern.bootsessionuuid",boot,&n,NULL,0)||strcmp(boot,expectedBoot)||sysctlbyname("kern.osversion",build,&m,NULL,0)||strcmp(build,VM27_EXCLUSIVE_NATIVE_BUILD)||proc_pidpath(getpid(),path,sizeof(path))<=0||strcmp(path,"/usr/sbin/bluetoothd"))return VM27ExclusiveBluetoothInstallationStatusV15=EPERM;
 Class cls=NSClassFromString(@"BTVCHciManager");
 if(!method(cls,"transportWriteCmd:length:amountWritten:dtor:","B44@0:8*16S24^S28^?36")||!method(cls,"transportWriteData:length:amountWritten:dtor:","B44@0:8*16S24^S28^?36")||!method(cls,"sendHciEventPacket:","v24@0:8^{BTVirtualHCIPacket=^{?}}16")||!method(cls,"sendHciData:","v24@0:8^{BTVirtualHCIPacket=^{?}}16"))return VM27ExclusiveBluetoothInstallationStatusV15=EPROTONOSUPPORT;
 if(!method(cls,VM27_EXCLUSIVE_INQUIRY_SELECTOR,VM27_EXCLUSIVE_INQUIRY_ENCODING)||!method(cls,"_isHciEventEnabled:","B20@0:8C16")||!method(cls,"_isHciLeEventEnabled:","B20@0:8C16")||!method(cls,"sendLmpEventPacket:","v24@0:8^{BTVirtualHCIPacket=^{?}}16"))return VM27ExclusiveBluetoothInstallationStatusV15=EPROTONOSUPPORT;
 if(!method(cls,"_sendHciCommandCompleteEvent:status:params:length:","v36@0:8S16C20*24C32")||!method(cls,"sendHciCommandStatusEvent:status:","v24@0:8S16C20"))return VM27ExclusiveBluetoothInstallationStatusV15=EPROTONOSUPPORT;
 Dl_info native={0};if(!dladdr((void *)method_getImplementation(class_getInstanceMethod(cls,sel_registerName("transportWriteCmd:length:amountWritten:dtor:"))),&native)||!native.dli_fbase)return VM27ExclusiveBluetoothInstallationStatusV15=EPROTONOSUPPORT;
 const uint8_t lockCode[16]={0x7f,0x23,0x03,0xd5,0xf6,0x57,0xbd,0xa9,0xf4,0x4f,0x01,0xa9,0xfd,0x7b,0x02,0xa9},unlockCode[16]={0x7f,0x23,0x03,0xd5,0xf4,0x4f,0xbe,0xa9,0xfd,0x7b,0x01,0xa9,0xfd,0x43,0x00,0x91};
 const uint8_t *base=native.dli_fbase;
 if(!supportedNativeImage(base))return VM27ExclusiveBluetoothInstallationStatusV15=EPROTONOSUPPORT;
 if(memcmp(base+VM27_EXCLUSIVE_CORE_LOCK_RVA,lockCode,16)||memcmp(base+VM27_EXCLUSIVE_CORE_UNLOCK_RVA,unlockCode,16))return VM27ExclusiveBluetoothInstallationStatusV15=EPROTONOSUPPORT;
 CoreLock=ptrauth_sign_unauthenticated((void *)(base+VM27_EXCLUSIVE_CORE_LOCK_RVA),ptrauth_key_function_pointer,0);
 CoreUnlock=ptrauth_sign_unauthenticated((void *)(base+VM27_EXCLUSIVE_CORE_UNLOCK_RVA),ptrauth_key_function_pointer,0);
 unsigned count=0;Ivar *ivars=class_copyIvarList(cls,&count);
 for(unsigned i=0;i<count;++i){if(ivar_getOffset(ivars[i])==0xd0)EventIvar=ivars[i];if(ivar_getOffset(ivars[i])==0xe0)DataIvar=ivars[i];}free(ivars);
 if(!EventIvar||!DataIvar)return VM27ExclusiveBluetoothInstallationStatusV15=EPROTONOSUPPORT;
 Manager=((id(*)(id,SEL))objc_msgSend)(cls,sel_registerName("sharedManager"));
 // Existing virtual transport stores NSData addresses in display byte order.
 // Its HCI decoder (25G83 RVA 25c8d0) reverses the six wire bytes. Capture this
 // pre-handover value and track subsequent physical 0x2005 writes on Queue.
 Class agentClass=NSClassFromString(@"BTVCLinkAgent");
 if(method(agentClass,"getConnectionManager","@16@0:8")){
  id agent=blockAt(Manager,0xc0);id connections=agent?((id(*)(id,SEL))objc_msgSend)(agent,sel_registerName("getConnectionManager")):nil;
  id address=connections?blockAt(connections,0x18):nil;
  if([address isKindOfClass:NSData.class]&&[address length]==6){const uint8_t *bytes=[address bytes];unsigned any=0;for(unsigned i=0;i<6;++i){GuestAddressState[i+1]=bytes[5-i];any|=bytes[i];}GuestAddressState[0]=any!=0;}
 }
 // Do not wait for the HCI core mutex on the simulator command queue:
 // its command path can itself be awaited by the thread holding that mutex.
 DeliveryQueue=dispatch_get_main_queue(); // Native HCI scheduler and callbacks share this owner thread.
 EventCompletion=[blockAt(Manager,0xd0)copy];DataCompletion=[blockAt(Manager,0xe0)copy];
 if(!DeliveryQueue)return VM27ExclusiveBluetoothInstallationStatusV15=ENODEV;
 Server=socket(AF_INET,SOCK_STREAM,0);if(Server<0)return VM27ExclusiveBluetoothInstallationStatusV15=errno;
 int reusable=1;setsockopt(Server,SOL_SOCKET,SO_REUSEADDR,&reusable,sizeof(reusable));
 struct sockaddr_in address={0};address.sin_len=sizeof(address);address.sin_family=AF_INET;address.sin_addr.s_addr=htonl(INADDR_LOOPBACK);address.sin_port=htons(39032);
 if(bind(Server,(void *)&address,sizeof(address))||listen(Server,1)){int e=errno;close(Server);Server=-1;return VM27ExclusiveBluetoothInstallationStatusV15=e;}
 fcntl(Server,F_SETFL,O_NONBLOCK);fcntl(Server,F_SETFD,FD_CLOEXEC);
 Queue=dispatch_queue_create("com.virtualmac.exclusive-bluetooth",DISPATCH_QUEUE_SERIAL);Output=[NSMutableData data];Input=[NSMutableData data];PendingTX=[NSMutableArray array];OutstandingCommands=[NSMutableDictionary dictionary];
 CmdMethod=class_getInstanceMethod(cls,sel_registerName("transportWriteCmd:length:amountWritten:dtor:"));DataMethod=class_getInstanceMethod(cls,sel_registerName("transportWriteData:length:amountWritten:dtor:"));EventMethod=class_getInstanceMethod(cls,sel_registerName("sendHciEventPacket:"));PacketMethod=class_getInstanceMethod(cls,sel_registerName("sendHciData:"));
 OldCmd=method_setImplementation(CmdMethod,(IMP)writeCommand);OldData=method_setImplementation(DataMethod,(IMP)writeData);OldEvent=method_setImplementation(EventMethod,(IMP)virtualEvent);OldPacket=method_setImplementation(PacketMethod,(IMP)virtualData);
 OldInquiry=method_setImplementation(class_getInstanceMethod(cls,sel_registerName(VM27_EXCLUSIVE_INQUIRY_SELECTOR)),(IMP)simulatedInquiryComplete);
 OldHciEnabled=method_setImplementation(class_getInstanceMethod(cls,sel_registerName("_isHciEventEnabled:")),(IMP)simulatedHciEventEnabled);
 OldLeEnabled=method_setImplementation(class_getInstanceMethod(cls,sel_registerName("_isHciLeEventEnabled:")),(IMP)simulatedLeEventEnabled);
 OldLmp=method_setImplementation(class_getInstanceMethod(cls,sel_registerName("sendLmpEventPacket:")),(IMP)simulatedLmp);
 OldComplete=method_setImplementation(class_getInstanceMethod(cls,sel_registerName("_sendHciCommandCompleteEvent:status:params:length:")),(IMP)simulatedComplete);
 OldStatus=method_setImplementation(class_getInstanceMethod(cls,sel_registerName("sendHciCommandStatusEvent:status:")),(IMP)simulatedStatus);
 Listener=dispatch_source_create(DISPATCH_SOURCE_TYPE_READ,Server,0,Queue);dispatch_source_set_event_handler(Listener,^{acceptConnection();});dispatch_resume(Listener);
 Heartbeat=dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,Queue);dispatch_source_set_timer(Heartbeat,DISPATCH_TIME_NOW,2*NSEC_PER_SEC,100*NSEC_PER_MSEC);
 dispatch_source_set_event_handler(Heartbeat,^{
  if(Connection>=0)append(0x7e,NULL,0);
 });dispatch_resume(Heartbeat);Installed=YES;
 fprintf(stderr,"[ExclusiveBluetoothGuest] native raw transport installed loopbackPort=39032\n");return VM27ExclusiveBluetoothInstallationStatusV15=0;
}

// launchd supplies this module for the native service's next invocation. Its
// constructor runs after Objective-C class registration, before bluetoothd main.
// The secure marker/token exist only in the explicitly provisioned development
// guest; no iPad or Mac host process can satisfy the installer identity guards.
__attribute__((constructor)) static void installBeforeNativeMain(void){@autoreleasepool{
 char path[PROC_PIDPATHINFO_MAXSIZE]={0};
 if(geteuid()||proc_pidpath(getpid(),path,sizeof(path))<=0||strcmp(path,"/usr/sbin/bluetoothd"))return;
 const char *root="/Library/PrivilegedHelperTools/VirtualMacSharedBluetoothClassicV1";
 char file[PATH_MAX];snprintf(file,sizeof(file),"%s/exclusive-transport-token-v1",root);
 int fd=open(file,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);struct stat info;uint8_t token[32];
 if(fd<0)return;
 BOOL secure=!fstat(fd,&info)&&S_ISREG(info.st_mode)&&!info.st_uid&&info.st_nlink==1&&!(info.st_mode&0077)&&info.st_size==32&&read(fd,token,sizeof(token))==sizeof(token);close(fd);if(!secure)return;
 char hex[65]={0},boot[64]={0};size_t size=sizeof(boot);for(unsigned i=0;i<32;++i)snprintf(hex+i*2,3,"%02x",token[i]);memset(token,0,sizeof(token));
 int result=sysctlbyname("kern.bootsessionuuid",boot,&size,NULL,0)?errno:VM27InstallExclusiveBluetoothV15(boot,hex);memset(hex,0,sizeof(hex));
 snprintf(file,sizeof(file),"%s" VM27_EXCLUSIVE_RECEIPT_SUFFIX,root);
 fd=open(file,O_WRONLY|O_CREAT|O_NOFOLLOW|O_CLOEXEC,0600);
 if(fd>=0){if(!fstat(fd,&info)&&S_ISREG(info.st_mode)&&!info.st_uid&&info.st_nlink==1&&!(info.st_mode&0077)&&!ftruncate(fd,0))dprintf(fd,"{\"schema\":1,\"bootUUID\":\"%s\",\"bluetoothdPID\":%d,\"installerResult\":%d,\"constructorInstall\":true}\n",boot,getpid(),result);close(fd);}
}}
