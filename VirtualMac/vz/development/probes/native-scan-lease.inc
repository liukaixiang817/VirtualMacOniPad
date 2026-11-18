// One scheduled native scan owns one generation. Late/duplicate callbacks
// cannot replace another scan's cache. Completed scans are not cancelled.
static uint64_t BrokerScanGeneration,BrokerScanActiveGeneration;
static BOOL BrokerScanSuccess;
#ifdef VM27_WIFI_RETAIN_RECENT_NATIVE_BSS
#include <math.h>
#include "native-scan-cache.inc"
#endif
#ifndef VM27_OWNED_SCAN_TIMEOUT_SECONDS
#define VM27_OWNED_SCAN_TIMEOUT_SECONDS 15
#endif
static void brokerScanned(CFTypeRef device,CFArrayRef rows,void *error,void *context){
 uint64_t generation=(uint64_t)(uintptr_t)context;
 if(device!=PrimaryDevice||!generation||generation!=BrokerScanActiveGeneration||BrokerScanDone){
  Report[@"brokerNativeScanIgnoredCallbacks"]=@([Report[@"brokerNativeScanIgnoredCallbacks"]unsignedIntValue]+1);return;
 }
 BrokerScanSuccess=!error&&rows&&CFGetTypeID(rows)==CFArrayGetTypeID();
 if(BrokerScanSuccess){
  NSMutableArray *result=[NSMutableArray array];
  CFStringRef (*getSSID)(CFTypeRef)=(void *)dlsym(RTLD_DEFAULT,"WiFiNetworkGetSSID");
  if(!getSSID)BrokerScanSuccess=NO;
  else for(CFIndex i=0;i<CFArrayGetCount(rows)&&i<256;i++){
   CFTypeRef network=CFArrayGetValueAtIndex(rows,i);CFStringRef ssid=getSSID(network);if(!ssid)continue;
   NSData *bytes=[(__bridge NSString *)ssid dataUsingEncoding:NSUTF8StringEncoding];if(!bytes.length||bytes.length>32)continue;
   NSMutableDictionary *row=[@{@"ssidBase64":[bytes base64EncodedStringWithOptions:0]}mutableCopy];
   for(NSString *key in @[@"BSSID",@"CHANNEL",@"CHANNEL_FLAGS",@"CHANNEL_WIDTH",@"RSSI",@"CAPABILITIES",@"IE"])
    row[key]=brokerProperty(NetworkProperty(network,(__bridge CFStringRef)key));
   [result addObject:row];
  }
#ifdef VM27_WIFI_RETAIN_RECENT_NATIVE_BSS
  if(BrokerScanSuccess){
   double now=NSProcessInfo.processInfo.systemUptime;
   BrokerScanRows=brokerMergeObservedScanRows(result,now);
   BrokerScanCompletedTime=now;
  }
#else
  if(BrokerScanSuccess){BrokerScanRows=result;BrokerScanCompletedTime=NSProcessInfo.processInfo.systemUptime;}
#endif
 }
 BrokerScanDone=YES;
 Report[@"brokerNativeScanCompletedCallbacks"]=@([Report[@"brokerNativeScanCompletedCallbacks"]unsignedIntValue]+1);
 Report[@"brokerNativeScanCallbackSucceeded"]=@(BrokerScanSuccess);
}
static BOOL scanStationRows(void){
 void *lib=dlopen("/System/Library/PrivateFrameworks/MobileWiFi.framework/MobileWiFi",RTLD_NOW|RTLD_GLOBAL);
 void (*schedule)(CFTypeRef,CFRunLoopRef,CFStringRef)=(void *)dlsym(lib,"WiFiManagerClientScheduleWithRunLoop");
 void (*unschedule)(CFTypeRef,CFRunLoopRef,CFStringRef)=(void *)dlsym(lib,"WiFiManagerClientUnscheduleFromRunLoop");
 int (*scan)(CFTypeRef,CFDictionaryRef,void(*)(CFTypeRef,CFArrayRef,void *,void *),void *)=(void *)dlsym(lib,"WiFiDeviceClientScanAsync");
 void (*cancel)(CFTypeRef)=(void *)dlsym(lib,"WiFiDeviceClientScanCancel");
 if(!schedule||!unschedule||!scan||!cancel||BrokerScanGeneration==UINT64_MAX)return NO;
 uint64_t generation=++BrokerScanGeneration;
 BrokerScanActiveGeneration=generation;BrokerScanDone=BrokerScanSuccess=NO;
 if(!Report[@"brokerNativeScanCancellationCalls"])Report[@"brokerNativeScanCancellationCalls"]=@0;
 schedule(WiFiManager,CFRunLoopGetMain(),kCFRunLoopDefaultMode);
 int status=scan(PrimaryDevice,(__bridge CFDictionaryRef)@{@"SCAN_MAXAGE":@2},brokerScanned,(void *)(uintptr_t)generation);
 double deadline=NSProcessInfo.processInfo.systemUptime+VM27_OWNED_SCAN_TIMEOUT_SECONDS;
 while(!status&&!BrokerScanDone&&!Stop&&NSProcessInfo.processInfo.systemUptime<deadline)
  CFRunLoopRunInMode(kCFRunLoopDefaultMode,.05,false);
 BOOL completed=!status&&BrokerScanDone&&BrokerScanSuccess&&!Stop;
 // Clear ownership BEFORE cancellation or unscheduling can deliver a late
 // callback. Never cancel after the completion callback already arrived.
 BrokerScanActiveGeneration=0;
 if(!status&&!BrokerScanDone){cancel(PrimaryDevice);
  Report[@"brokerNativeScanCancellationCalls"]=@([Report[@"brokerNativeScanCancellationCalls"]unsignedIntValue]+1);}
 unschedule(WiFiManager,CFRunLoopGetMain(),kCFRunLoopDefaultMode);
 Report[@"brokerNativeScanStatus"]=@(status);Report[@"brokerNativeScanNetworkCount"]=@(BrokerScanRows.count);
 return completed;
}
