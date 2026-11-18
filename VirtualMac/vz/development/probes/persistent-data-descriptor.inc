// The root actor owns one physical capture descriptor. A guest owns only a
// logical data lease; releasing that lease must not detach the native port.
// No descriptor is sent to a guest. Old capture queues are flushed before
// every activation and at detach, and the per-session buffer/MAC is erased.
#define VM27_BIOCGETIF _IOR('B',107,struct ifreq)
#define VM27_BIOCFLUSH _IO('B',104)
static int PhysicalDataBPF=-1;
static unsigned PhysicalDataBPFCreateCount,PhysicalDataBPFDrainCount;
static BOOL PhysicalDataBPFArmed;
static void physicalDataReferenceReport(const char *action,int status){
 NSDictionary *entry=@{@"phase":@"owned-physical-data-reference",@"action":@(action),
  @"status":@(status),@"createCount":@(PhysicalDataBPFCreateCount),
  @"drainCount":@(PhysicalDataBPFDrainCount),@"armed":@(PhysicalDataBPFArmed),
  @"physicalDescriptorRetained":@(PhysicalDataBPF>=0),@"descriptorExported":@NO};
 NSData *data=[NSJSONSerialization dataWithJSONObject:entry options:NSJSONWritingSortedKeys error:NULL];
 if(data){fwrite(data.bytes,1,data.length,stderr);fputc('\n',stderr);fflush(stderr);}
}
static BOOL physicalDataReferenceOwned(unsigned *capacity){
 if(PhysicalDataBPF<0||!capacity)return NO;
 struct ifreq interface={0};unsigned linkType=0;int flags=fcntl(PhysicalDataBPF,F_GETFD);
 return flags>=0&&(flags&FD_CLOEXEC)&&
  !ioctl(PhysicalDataBPF,VM27_BIOCGETIF,&interface)&&
  !strcmp(interface.ifr_name,"ap1")&&
  !ioctl(PhysicalDataBPF,VM27_BIOCGDLT,&linkType)&&linkType==1&&
  !ioctl(PhysicalDataBPF,VM27_BIOCGBLEN,capacity)&&*capacity>=20&&*capacity<=524288;
}
static BOOL physicalDrainDataReference(const char *action){
 PhysicalDataBPFArmed=NO;
 if(PhysicalDataBPF<0)return YES;
 unsigned capacity=0;
 if(!physicalDataReferenceOwned(&capacity)){physicalDataReferenceReport(action,EPERM);return NO;}
 int result=ioctl(PhysicalDataBPF,VM27_BIOCFLUSH,(void *)NULL);
 PhysicalDataBPFDrainCount++;
 physicalDataReferenceReport(action,result?errno:0);
 return !result;
}
static BOOL brokerReleaseDataPlane(int *descriptor){
 if(!descriptor)return NO;
 if(!ManagedStationBroker){if(*descriptor>=0)close(*descriptor);*descriptor=-1;return YES;}
 int old=*descriptor;*descriptor=-1;
 // A foreign/reused descriptor is never adopted as this physical object.
 if(old>=0&&old!=PhysicalDataBPF){PhysicalDataBPFArmed=NO;return NO;}
 return physicalDrainDataReference("virtual-lease-detached");
}
static BOOL physicalOpenDataPlane(int *descriptor,unsigned *capacity){
 if(!descriptor||!capacity||Stop||!ManagedStationAssociated||
    !PhysicalVerifiedCredential||!ManagedActivePMKDigestValid||
    !physicalPreparedIdentityValid()||physicalVerifiedAssociationState()!=2)return NO;
 *descriptor=-1;
 if(PhysicalDataBPF<0){
  struct ifreq interface={0};strlcpy(interface.ifr_name,"ap1",sizeof(interface.ifr_name));
  unsigned one=1,zero=0;int fd=-1;
  for(unsigned i=0;i<256;i++){
   char path[32];snprintf(path,sizeof(path),"/dev/bpf%u",i);
   fd=open(path,O_RDWR|O_NONBLOCK|O_CLOEXEC);if(fd>=0||errno!=EBUSY)break;
  }
  if(fd<0)return NO;
  if(ioctl(fd,VM27_BIOCSETIF,&interface)||ioctl(fd,VM27_BIOCGBLEN,capacity)||
     *capacity<20||*capacity>524288||ioctl(fd,VM27_BIOCIMMEDIATE,&one)||
     ioctl(fd,VM27_BIOCSHDRCMPLT,&one)||ioctl(fd,VM27_BIOCSSEESENT,&zero)){
   close(fd);return NO;
  }
  PhysicalDataBPF=fd;PhysicalDataBPFCreateCount++;
 }
 if(!physicalDrainDataReference("before-virtual-lease-activation")||
    !physicalDataReferenceOwned(capacity))return NO;
 PhysicalDataBPFArmed=YES;*descriptor=PhysicalDataBPF;
 physicalDataReferenceReport("virtual-lease-activated",0);return YES;
}
// The OS closes this physical FD at process exit, after the existing atexit
// station cleanup. No virtual lease closes or duplicates this descriptor.
