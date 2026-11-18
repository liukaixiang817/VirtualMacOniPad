// First-install routing preference for our own Wi-Fi interface. Keep the
// isolated Ethernet service as the fallback; preserve existing IP settings.
#import <SystemConfiguration/SystemConfiguration.h>
static BOOL VM27WiFiSetupSafeDirectory(NSString *path){
 struct stat st;if(lstat(path.fileSystemRepresentation,&st)){
  if(errno!=ENOENT||mkdir(path.fileSystemRepresentation,0700))return NO;
 }
 return !lstat(path.fileSystemRepresentation,&st)&&S_ISDIR(st.st_mode)&&st.st_uid==0&&!(st.st_mode&0022);
}
static NSString *VM27WiFiOwnBSDName(void){
 io_service_t owner=IOServiceGetMatchingService(kIOMainPortDefault,IOServiceMatching("VM27SharedWiFiInterfaceV1"));
 if(!owner)return nil;io_iterator_t iterator=0;
 kern_return_t status=IORegistryEntryCreateIterator(owner,kIOServicePlane,kIORegistryIterateRecursively,&iterator);
 IOObjectRelease(owner);if(status)return nil;NSString *name=nil;
 for(io_registry_entry_t entry;(entry=IOIteratorNext(iterator));IOObjectRelease(entry)){
  // The published BSD child is IOSkywalkLegacyEthernet on 24G90. Avoid a
  // guessed class suffix; read the actual BSD property within our own tree.
  CFTypeRef value=IORegistryEntryCreateCFProperty(entry,CFSTR("BSD Name"),kCFAllocatorDefault,0);
  if(!value)continue;
  NSString *candidate=CFGetTypeID(value)==CFStringGetTypeID()?(__bridge NSString *)value:nil;
  BOOL valid=candidate.length>2&&candidate.length<16&&[candidate hasPrefix:@"en"];
  for(NSUInteger i=2;i<candidate.length;i++)if([candidate characterAtIndex:i]<'0'||[candidate characterAtIndex:i]>'9')valid=NO;
  if(valid)name=[candidate copy];CFRelease(value);
  if(name){IOObjectRelease(entry);break;}
 }
 IOObjectRelease(iterator);return name;
}
static BOOL VM27PrepareNativeWiFiNetworkV1(void){
 NSString *directory=@"/Library/VirtualMac/SharedRadio";
 NSString *receipt=[directory stringByAppendingPathComponent:@"NetworkSetupV1.plist"];
 if(!VM27WiFiSetupSafeDirectory(@"/Library")||!VM27WiFiSetupSafeDirectory(@"/Library/VirtualMac")||!VM27WiFiSetupSafeDirectory(directory))return NO;
 struct stat existing;
 if(!lstat(receipt.fileSystemRepresentation,&existing)){
  if(!S_ISREG(existing.st_mode)||existing.st_uid||existing.st_nlink!=1||(existing.st_mode&0077)||existing.st_size>4096)return NO;
  NSDictionary *record=[NSDictionary dictionaryWithContentsOfFile:receipt];
  // This is a one-time default. Respect subsequent user service ordering.
  return [record[@"Schema"]isEqual:@1]&&[record[@"PriorityPrepared"]isEqual:@YES];
 }
 if(errno!=ENOENT)return NO;NSString *bsd=VM27WiFiOwnBSDName();if(!bsd)return NO;
 SCPreferencesRef preferences=SCPreferencesCreate(NULL,CFSTR("VirtualMac Wi-Fi first-install routing"),NULL);
 if(!preferences)return NO;if(!SCPreferencesLock(preferences,false)){CFRelease(preferences);return NO;}
 SCNetworkSetRef current=SCNetworkSetCopyCurrent(preferences);CFArrayRef services=SCNetworkServiceCopyAll(preferences);
 NSString *identifier=nil;
 if(services)for(CFIndex i=0;i<CFArrayGetCount(services);i++){
  SCNetworkServiceRef service=(SCNetworkServiceRef)CFArrayGetValueAtIndex(services,i);
  SCNetworkInterfaceRef interface=SCNetworkServiceGetInterface(service);
  CFStringRef name=interface?SCNetworkInterfaceGetBSDName(interface):NULL;
  if(name&&CFEqual(name,(__bridge CFStringRef)bsd)){identifier=[(__bridge NSString *)SCNetworkServiceGetServiceID(service)copy];break;}
 }
 BOOL created=NO;
 if(!identifier&&current){
  CFArrayRef interfaces=SCNetworkInterfaceCopyAll();
  if(interfaces)for(CFIndex i=0;i<CFArrayGetCount(interfaces);i++){
   SCNetworkInterfaceRef interface=(SCNetworkInterfaceRef)CFArrayGetValueAtIndex(interfaces,i);
   CFStringRef name=SCNetworkInterfaceGetBSDName(interface),type=SCNetworkInterfaceGetInterfaceType(interface);
   if(!name||!CFEqual(name,(__bridge CFStringRef)bsd)||!type||!CFEqual(type,kSCNetworkInterfaceTypeIEEE80211))continue;
   SCNetworkServiceRef service=SCNetworkServiceCreate(preferences,interface);
   if(service){
    created=SCNetworkServiceEstablishDefaultConfiguration(service)&&SCNetworkServiceSetEnabled(service,true)&&
        SCNetworkSetAddService(current,service);
    if(created)identifier=[(__bridge NSString *)SCNetworkServiceGetServiceID(service)copy];
    CFRelease(service);
   }
   break;
  }
  if(interfaces)CFRelease(interfaces);
 }
 CFArrayRef order=current?SCNetworkSetGetServiceOrder(current):NULL;
 BOOL ready=identifier&&order&&CFArrayContainsValue(order,CFRangeMake(0,CFArrayGetCount(order)),(__bridge CFStringRef)identifier);
 if(ready&&CFArrayGetCount(order)&&(created||!CFEqual(CFArrayGetValueAtIndex(order,0),(__bridge CFStringRef)identifier))){
  NSMutableArray *updated=[(__bridge NSArray *)order mutableCopy];[updated removeObject:identifier];[updated insertObject:identifier atIndex:0];
  ready=SCNetworkSetSetServiceOrder(current,(__bridge CFArrayRef)updated)&&SCPreferencesCommitChanges(preferences)&&SCPreferencesApplyChanges(preferences);
 }
 if(services)CFRelease(services);if(current)CFRelease(current);
 SCPreferencesUnlock(preferences);CFRelease(preferences);if(!ready)return NO;
 NSDictionary *record=@{@"Schema":@1,@"PriorityPrepared":@YES,@"BSDName":bsd,@"ServiceID":identifier,@"ExistingIPSettingsPreserved":@YES};
 NSData *data=[NSPropertyListSerialization dataWithPropertyList:record format:NSPropertyListXMLFormat_v1_0 options:0 error:NULL];
 return data&&[data writeToFile:receipt options:NSDataWritingAtomic error:NULL]&&!chmod(receipt.fileSystemRepresentation,0600);
}
