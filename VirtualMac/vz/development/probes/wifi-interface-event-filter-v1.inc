// Development-only, bounded IF-event transaction. SET_BIT / RESET_BIT return
// success without changing this firmware's mask. Use the native SET_MASK ABI,
// reading the current mask immediately before changing event 54 alone.
// A separately exec'd guardian restores the bit if the parent dies or hangs.
#include <mach-o/dyld.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <limits.h>
static BOOL FilterInterfaceEvents;
static NSString *IFEventFilterNonce;
static NSDictionary *readFilterReceipt(void){
 int fd=open(Receipt,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);struct stat st;
 if(fd<0)return nil;
 if(fstat(fd,&st)||!S_ISREG(st.st_mode)||st.st_uid||st.st_nlink!=1||(st.st_mode&0777)!=0600||st.st_size<2||st.st_size>32768){close(fd);return nil;}
 NSMutableData *data=[NSMutableData dataWithLength:(NSUInteger)st.st_size];size_t at=0;
 while(at<data.length){ssize_t n=read(fd,(uint8_t *)data.mutableBytes+at,data.length-at);if(n<0&&errno==EINTR)continue;if(n<=0){close(fd);return nil;}at+=(size_t)n;}
 close(fd);id value=[NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];return [value isKindOfClass:NSDictionary.class]?value:nil;
}
static int readIFEventMask(uint8_t mask[64],size_t *count){
 uint8_t input[68]={1,0,68,64},response[68]={0};int result=iovar(NO,"event_msgs_ext",0,input,sizeof(input),response,sizeof(response));
 // Firmware writes len/maxgetsize and mask, but leaves version/command in
 // this in-place GET_VAR buffer untouched. Do not parse the old name bytes
 // as a returned version. The request version is explicitly 1 above.
 if(result)return result;
 if(response[2]<7||response[2]>64||response[2]!=response[3])return EPROTO;
 *count=response[2];memcpy(mask,response+4,*count);return 0;
}
static int setIFEventBit(BOOL enabled){
 uint8_t mask[64]={0};size_t length=0;int read=readIFEventMask(mask,&length);if(read)return read;
 if(enabled)mask[6]|=0x40;else mask[6]&=(uint8_t)~0x40;
 uint8_t request[68]={1,3,0,0};request[2]=(uint8_t)length;memcpy(request+4,mask,length);
 return iovar(YES,"event_msgs_ext",0,request,sizeof(request),NULL,0);
}
static BOOL restoreOwnedIFEventFilter(NSString *expectedNonce){
 NSDictionary *record=readFilterReceipt();if(!record)return access(Receipt,F_OK)!=0;
 if(![record[@"ifEventFilterPending"]boolValue])return YES;
 NSString *nonce=record[@"ifEventFilterNonce"];
 if(![nonce isKindOfClass:NSString.class]||![[NSUUID alloc]initWithUUIDString:nonce]||(expectedNonce&&![nonce isEqual:expectedNonce])||![record[@"ifEventOriginallyEnabled"]boolValue])return NO;
 uint8_t mask[64]={0};size_t count=0;int read=readIFEventMask(mask,&count);if(read)return NO;
 if(mask[6]&0x40)return YES;
 struct timeval boot={0};size_t size=sizeof(boot);
 if(sysctlbyname("kern.boottime",&boot,&size,NULL,0)||[record[@"ifEventFilterBootSeconds"]longLongValue]!=(long long)boot.tv_sec)return NO;
 if(setIFEventBit(YES)||readIFEventMask(mask,&count))return NO;
 return (mask[6]&0x40)!=0;
}
static int runIFEventGuardian(NSString *nonce,int readyDescriptor){
 NSDictionary *record=readFilterReceipt();uint8_t mask[64]={0};size_t count=0;
 if(![record[@"ifEventFilterNonce"]isEqual:nonce]||![record[@"ifEventFilterPending"]boolValue]||readIFEventMask(mask,&count))return 75;
 uint8_t ready=1;if(write(readyDescriptor,&ready,1)!=1)return 75;close(readyDescriptor);
 sleep(8);
 record=readFilterReceipt();if(!record||![record[@"ifEventFilterNonce"]isEqual:nonce])return 0;
 return restoreOwnedIFEventFilter(nonce)?0:75;
}
static BOOL startIFEventGuardian(NSString *nonce){
 char executable[PATH_MAX],resolved[PATH_MAX],descriptor[16],nonceText[37];uint32_t size=sizeof(executable);
 if(_NSGetExecutablePath(executable,&size)||!realpath(executable,resolved)||![nonce getCString:nonceText maxLength:sizeof(nonceText) encoding:NSASCIIStringEncoding])return NO;
 int ends[2];if(pipe(ends))return NO;snprintf(descriptor,sizeof(descriptor),"%d",ends[1]);
 pid_t child=fork();if(child<0){close(ends[0]);close(ends[1]);return NO;}
 if(!child){
  close(ends[0]);int null=open("/dev/null",O_RDWR);if(null>=0){dup2(null,0);dup2(null,1);dup2(null,2);if(null>2&&null!=ends[1])close(null);}
  execl(resolved,resolved,"--restore-owned-interface-event-filter",nonceText,descriptor,(char *)NULL);_exit(127);
 }
 close(ends[1]);struct pollfd p={ends[0],POLLIN,0};uint8_t ready=0;BOOL started=poll(&p,1,4000)>0&&read(ends[0],&ready,1)==1&&ready==1;close(ends[0]);
 if(!started){kill(child,SIGTERM);waitpid(child,NULL,0);}return started;
}
static BOOL beginOwnedIFEventFilter(void){
 if(!FilterInterfaceEvents)return YES;
 uint8_t original[64]={0},actual[64]={0};size_t length=0,actualLength=0;int result=readIFEventMask(original,&length);
 Report[@"interfaceEventMaskReadStatus"]=@(result);if(result)return NO;
 Report[@"interfaceEvent54OriginallyEnabled"]=@((original[6]&0x40)!=0);if(!(original[6]&0x40))return NO;
 struct timeval boot={0};size_t size=sizeof(boot);if(sysctlbyname("kern.boottime",&boot,&size,NULL,0))return NO;
 NSMutableDictionary *record=[readFilterReceipt()mutableCopy];if(!record)return NO;IFEventFilterNonce=NSUUID.UUID.UUIDString;
 record[@"ifEventFilterPending"]=@YES;record[@"ifEventFilterNonce"]=IFEventFilterNonce;record[@"ifEventOriginallyEnabled"]=@YES;record[@"ifEventFilterBootSeconds"]=@((long long)boot.tv_sec);
 NSData *data=[NSJSONSerialization dataWithJSONObject:record options:0 error:NULL];int fd=open(Receipt,O_WRONLY|O_TRUNC|O_NOFOLLOW|O_CLOEXEC);if(fd<0)return NO;
 BOOL stored=write(fd,data.bytes,data.length)==(ssize_t)data.length&&!fsync(fd);close(fd);if(!stored||!startIFEventGuardian(IFEventFilterNonce))return NO;
 Report[@"interfaceEventRestoreGuardianReady"]=@YES;
 double started=NSProcessInfo.processInfo.systemUptime;
 result=setIFEventBit(NO);Report[@"interfaceEvent54ResetStatus"]=@(result);Report[@"interfaceEventResetMilliseconds"]=@((NSProcessInfo.processInfo.systemUptime-started)*1000);if(result)return NO;
 if(readIFEventMask(actual,&actualLength)||length!=actualLength)return NO;
 Report[@"interfaceEvent54EnabledAfterReset"]=@((actual[6]&0x40)!=0);
 NSMutableArray *changed=[NSMutableArray array];for(size_t i=0;i<length;i++)for(unsigned bit=0;bit<8;bit++)if((original[i]^actual[i])&(1u<<bit))[changed addObject:@(i*8+bit)];Report[@"interfaceEventChangedBitIndexes"]=changed;
 original[6]&=(uint8_t)~0x40;BOOL exact=!memcmp(original,actual,length);Report[@"onlyInterfaceEvent54Changed"]=@(exact);return exact;
}
