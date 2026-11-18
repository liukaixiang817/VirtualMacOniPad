// Minimal Darwin BPF ABI, checked against the local macOS SDK's net/bpf.h.
// iPhoneOS SDK omits that header. A BPF descriptor is attached only to ap1;
// this probe never configures host addresses, routes, DNS, or forwarding.
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <poll.h>
#include <ifaddrs.h>
#include <net/if_dl.h>
struct VM27BPFHeader {int32_t seconds,microseconds;uint32_t captured,original;uint16_t header;};
_Static_assert(sizeof(struct VM27BPFHeader)==20,"Darwin LP64 BPF header");
#define VM27_BIOCGBLEN _IOR('B',102,unsigned)
#define VM27_BIOCGDLT _IOR('B',106,unsigned)
#define VM27_BIOCSETIF _IOW('B',108,struct ifreq)
#define VM27_BIOCIMMEDIATE _IOW('B',112,unsigned)
#define VM27_BIOCSHDRCMPLT _IOW('B',117,unsigned)
#define VM27_BIOCSSEESENT _IOW('B',119,unsigned)
static void put16(uint8_t *p,uint16_t x){p[0]=x>>8;p[1]=x&255;}
static uint16_t read16(const uint8_t *p){return (uint16_t)p[0]<<8|p[1];}
static uint16_t ipv4Checksum(const uint8_t *p,size_t count){uint32_t sum=0;for(size_t i=0;i+1<count;i+=2)sum+=read16(p+i);while(sum>>16)sum=(sum&65535)+(sum>>16);return (uint16_t)~sum;}
static int LeaseBSDControl=-1;static short LeaseOriginalFlags;static BOOL LeaseBSDChanged;
static BOOL recoverAuxiliaryBSDDataLease(NSDictionary *receipt);
static BOOL acquireAuxiliaryBSDDataLease(void){
 struct ifreq interface={0};strlcpy(interface.ifr_name,"ap1",sizeof(interface.ifr_name));LeaseBSDControl=socket(AF_INET,SOCK_DGRAM,0);if(LeaseBSDControl<0||ioctl(LeaseBSDControl,SIOCGIFFLAGS,&interface))return NO;
 LeaseOriginalFlags=interface.ifr_flags;Report[@"auxiliaryBSDFlagsBeforeStationConversion"]=@(LeaseOriginalFlags);if(LeaseOriginalFlags&IFF_UP)return YES;
 NSMutableDictionary *receipt=[[NSJSONSerialization JSONObjectWithData:[NSData dataWithContentsOfFile:@(Receipt)]options:0 error:NULL]mutableCopy];if(!receipt)return NO;receipt[@"originalAuxiliaryBSDFlags"]=@(LeaseOriginalFlags);
 NSData *saved=[NSJSONSerialization dataWithJSONObject:receipt options:0 error:NULL];int fd=open(Receipt,O_WRONLY|O_TRUNC|O_NOFOLLOW);if(fd<0)return NO;BOOL stored=write(fd,saved.bytes,saved.length)==(ssize_t)saved.length&&!fsync(fd);close(fd);if(!stored)return NO;
 interface.ifr_flags=LeaseOriginalFlags|IFF_UP;int result=ioctl(LeaseBSDControl,SIOCSIFFLAGS,&interface);Report[@"auxiliaryBSDEarlyEnableErrno"]=@(result?errno:0);LeaseBSDChanged=!result;return !result;
}
static BOOL releaseAuxiliaryBSDDataLease(void){
 BOOL restored=YES;if(LeaseBSDChanged){restored=recoverAuxiliaryBSDDataLease(@{@"originalAuxiliaryBSDFlags":@(LeaseOriginalFlags)});if(restored)LeaseBSDChanged=NO;Report[@"auxiliaryBSDEarlyFlagsRestored"]=@(restored);}
 if(LeaseBSDControl>=0){close(LeaseBSDControl);LeaseBSDControl=-1;}return restored;
}
// Recovery caller must first prove this lease's endpoint is inactive or its
// saved MAC still matches. Restore only IFF_UP; running/dynamic flags can change.
static BOOL recoverAuxiliaryBSDDataLease(NSDictionary *receipt){
 NSNumber *saved=receipt[@"originalAuxiliaryBSDFlags"];if(!saved)return YES;
 if(![saved isKindOfClass:NSNumber.class]||saved.intValue<-32768||saved.intValue>32767)return NO;
 struct ifreq interface={0};strlcpy(interface.ifr_name,"ap1",sizeof(interface.ifr_name));
 int fd=socket(AF_INET,SOCK_DGRAM,0);if(fd<0)return NO;
 BOOL restored=NO;if(!ioctl(fd,SIOCGIFFLAGS,&interface)){
  short desired=(short)((interface.ifr_flags&~IFF_UP)|(saved.shortValue&IFF_UP));
  if(desired==interface.ifr_flags)restored=YES;else{interface.ifr_flags=desired;restored=!ioctl(fd,SIOCSIFFLAGS,&interface);}
  if(restored)restored=!ioctl(fd,SIOCGIFFLAGS,&interface)&&((interface.ifr_flags&IFF_UP)==(saved.shortValue&IFF_UP));
 }
 close(fd);return restored;
}
static BOOL verifyAuxiliaryDHCP(const uint8_t mac[6],NSMutableDictionary *report){
 int fd=-1,openError=0;for(unsigned i=0;i<256;i++){char name[32];snprintf(name,sizeof(name),"/dev/bpf%u",i);fd=open(name,O_RDWR|O_NONBLOCK|O_CLOEXEC);if(fd>=0)break;openError=errno;if(errno!=EBUSY)break;}
 report[@"auxiliaryBPFOpenErrno"]=@(fd<0?openError:0);if(fd<0)return NO;
 BOOL offer=NO,flagsChanged=NO;int control=-1;short originalFlags=0;
 unsigned enabled=1,disabled=0,linkType=0,capacity=0;struct ifreq interface={0};strlcpy(interface.ifr_name,"ap1",sizeof(interface.ifr_name));
 control=socket(AF_INET,SOCK_DGRAM,0);if(control<0)goto done;
 if(ioctl(control,SIOCGIFFLAGS,&interface))goto done;originalFlags=interface.ifr_flags;report[@"auxiliaryBSDFlagsBefore"]=@(originalFlags);
 if(!(originalFlags&IFF_UP)){
  NSMutableDictionary *receipt=[[NSJSONSerialization JSONObjectWithData:[NSData dataWithContentsOfFile:@(Receipt)]options:0 error:NULL]mutableCopy];if(!receipt)goto done;
  receipt[@"originalAuxiliaryBSDFlags"]=@(originalFlags);NSData *saved=[NSJSONSerialization dataWithJSONObject:receipt options:0 error:NULL];int identity=open(Receipt,O_WRONLY|O_TRUNC|O_NOFOLLOW);if(identity<0)goto done;
  BOOL persisted=write(identity,saved.bytes,saved.length)==(ssize_t)saved.length&&!fsync(identity);close(identity);if(!persisted)goto done;
  interface.ifr_flags=originalFlags|IFF_UP;int flagStatus=ioctl(control,SIOCSIFFLAGS,&interface);report[@"auxiliaryBSDEnableErrno"]=@(flagStatus?errno:0);if(flagStatus)goto done;flagsChanged=YES;
 }
 int result=ioctl(fd,VM27_BIOCSETIF,&interface);report[@"auxiliaryBPFAttachErrno"]=@(result?errno:0);if(result)goto done;
 struct ifaddrs *addresses=NULL;if(!getifaddrs(&addresses)){
  for(struct ifaddrs *row=addresses;row;row=row->ifa_next)if(row->ifa_addr&&row->ifa_addr->sa_family==AF_LINK&&!strcmp(row->ifa_name,"ap1")){
   const struct sockaddr_dl *link=(const void *)row->ifa_addr;report[@"auxiliaryBSDMACMatchesFirmware"]=@(link->sdl_alen==6&&!memcmp(LLADDR(link),mac,6));}
  freeifaddrs(addresses);
 }
 result=ioctl(fd,VM27_BIOCGDLT,&linkType);report[@"auxiliaryBPFDataLinkType"]=@(linkType);if(result||linkType!=1)goto done;
 if(ioctl(fd,VM27_BIOCGBLEN,&capacity)||capacity<20||capacity>524288)goto done;
 if(ioctl(fd,VM27_BIOCIMMEDIATE,&enabled)||ioctl(fd,VM27_BIOCSHDRCMPLT,&enabled)||ioctl(fd,VM27_BIOCSSEESENT,&disabled))goto done;
 {
  uint8_t packet[342]={0};memset(packet,255,6);memcpy(packet+6,mac,6);put16(packet+12,0x0800);
  uint8_t *ip=packet+14,*udp=ip+20,*dhcp=udp+8;ip[0]=0x45;put16(ip+2,sizeof(packet)-14);ip[8]=64;ip[9]=17;memset(ip+16,255,4);put16(ip+10,ipv4Checksum(ip,20));
  put16(udp,68);put16(udp+2,67);put16(udp+4,sizeof(packet)-34); // IPv4 permits a zero UDP checksum.
  dhcp[0]=1;dhcp[1]=1;dhcp[2]=6;arc4random_buf(dhcp+4,4);dhcp[10]=0x80;memcpy(dhcp+28,mac,6);uint32_t transaction=0;memcpy(&transaction,dhcp+4,4);
  uint8_t options[]={99,130,83,99,53,1,1,61,7,1,0,0,0,0,0,0,55,6,1,3,6,51,54,58,255};memcpy(options+10,mac,6);memcpy(dhcp+236,options,sizeof(options));
  NSMutableData *buffer=[NSMutableData dataWithLength:capacity];unsigned received=0,malformed=0,sent=0;int lastWriteError=0;NSMutableDictionary *types=[NSMutableDictionary dictionary];
  double started=NSProcessInfo.processInfo.systemUptime,nextSend=started;
  while(!Stop&&NSProcessInfo.processInfo.systemUptime-started<10&&!offer){
   double now=NSProcessInfo.processInfo.systemUptime;if(now>=nextSend&&sent<3){ssize_t n=write(fd,packet,sizeof(packet));if(n==(ssize_t)sizeof(packet))sent++;else lastWriteError=errno;nextSend=now+2;}
   struct pollfd descriptor={.fd=fd,.events=POLLIN};int ready=poll(&descriptor,1,100);if(ready<=0)continue;ssize_t count=read(fd,buffer.mutableBytes,buffer.length);if(count<=0)continue;
   const uint8_t *bytes=buffer.bytes;size_t cursor=0;
   while(cursor+sizeof(struct VM27BPFHeader)<=(size_t)count){
    struct VM27BPFHeader header;memcpy(&header,bytes+cursor,sizeof(header));if(header.header<18||header.header>(size_t)count-cursor||header.captured>(size_t)count-cursor-header.header){malformed++;break;}
    const uint8_t *frame=bytes+cursor+header.header;size_t length=header.captured;received++;
    if(length>=14){NSString *type=[NSString stringWithFormat:@"etherType-%04x",read16(frame+12)];types[type]=@([types[type]unsignedIntValue]+1);}
    if(length>=14+20+8+240&&read16(frame+12)==0x0800){
     const uint8_t *network=frame+14;size_t ihl=(network[0]&15)*4;size_t total=read16(network+2);
     if(network[0]>>4==4&&ihl>=20&&network[9]==17&&total>=ihl+8+240&&total<=length-14&&!(read16(network+6)&0x3fff)){
      const uint8_t *datagram=network+ihl;size_t udpLength=read16(datagram+4);
      if(read16(datagram)==67&&read16(datagram+2)==68&&udpLength>=248&&udpLength<=total-ihl){
       const uint8_t *reply=datagram+8;uint32_t xid=0;memcpy(&xid,reply+4,4);
       if(reply[0]==2&&reply[1]==1&&reply[2]==6&&xid==transaction&&!memcmp(reply+28,mac,6)&&!memcmp(reply+236,options,4)){
        for(size_t at=240;at<udpLength-8;){uint8_t type=reply[at++];if(type==255)break;if(!type)continue;if(at>=udpLength-8)break;uint8_t size=reply[at++];if(size>udpLength-8-at)break;
         if(type==53&&size==1&&reply[at]==2)offer=YES;at+=size;}
       }
      }
     }
    }
    size_t step=(header.header+header.captured+3)&~(size_t)3;if(step>(size_t)count-cursor)break;cursor+=step;
   }
  }
  report[@"auxiliaryDHCPDiscoverFramesWritten"]=@(sent);report[@"auxiliaryBPFWriteErrno"]=@(lastWriteError);report[@"auxiliaryBPFReceivedFrames"]=@(received);report[@"auxiliaryBPFMalformedRecords"]=@(malformed);
  report[@"auxiliaryBPFEtherTypeCounts"]=types;
  memset(packet,0,sizeof(packet));[buffer resetBytesInRange:NSMakeRange(0,buffer.length)];
 }
done:
 if(flagsChanged){interface.ifr_flags=originalFlags;int restored=ioctl(control,SIOCSIFFLAGS,&interface);report[@"auxiliaryBSDFlagsRestored"]=@(!restored);}
 if(control>=0)close(control);
 close(fd);report[@"auxiliaryRealDHCPOfferVerified"]=@(offer);report[@"hostIPOrRoutingChanged"]=@NO;return offer;
}
