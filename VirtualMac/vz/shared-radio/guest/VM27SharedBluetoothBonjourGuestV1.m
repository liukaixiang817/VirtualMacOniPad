#import "VM27SharedBluetoothBonjourGuestV1.h"
#include <dns_sd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <unistd.h>

static void addressRegistered(DNSServiceRef service, DNSRecordRef record,
    DNSServiceFlags flags, DNSServiceErrorType error, void *context) {
    (void)service;(void)record;(void)flags;(void)context;
    fprintf(stderr,"Native Bluetooth Bonjour address registration status=%d\n",error);
}
static void serviceRegistered(DNSServiceRef service, DNSServiceFlags flags,
    DNSServiceErrorType error, const char *name, const char *type,
    const char *domain, void *context) {
    (void)service;(void)flags;(void)name;(void)type;(void)domain;(void)context;
    fprintf(stderr,"Native Bluetooth Bonjour service registration status=%d\n",error);
}
@implementation VM27SharedBluetoothBonjourGuestV1 {
    DNSServiceRef _address, _service;
    DNSRecordRef _record;
    dispatch_queue_t _queue;
}
- (BOOL)startWithEndpoint:(NSDictionary *)endpoint {
    if(geteuid()||_address||_service||![endpoint[@"ok"]boolValue]||[endpoint[@"protocol"]unsignedIntValue]!=1||
        ![endpoint[@"guestAddress"]isEqual:@"10.0.2.4"]||[endpoint[@"guestPort"]unsignedIntValue]!=39028)return NO;
    NSString *identifier=endpoint[@"serverUUID"];
    if(![identifier isKindOfClass:NSString.class]||![[NSUUID alloc]initWithUUIDString:identifier])return NO;
    uint32_t interface=if_nametoindex("en0");if(!interface)return NO;
    NSString *label=[@"vm27bt-" stringByAppendingString:[[identifier stringByReplacingOccurrencesOfString:@"-" withString:@""]lowercaseString]];
    NSString *host=[label stringByAppendingString:@".local."];
    struct in_addr address;if(inet_pton(AF_INET,"10.0.2.4",&address)!=1)return NO;
    _queue=dispatch_queue_create("com.virtualmac.shared-bluetooth-bonjour-v1",DISPATCH_QUEUE_SERIAL);
    DNSServiceErrorType error=DNSServiceCreateConnection(&_address);
    if(!error)error=DNSServiceSetDispatchQueue(_address,_queue);
    if(!error)error=DNSServiceRegisterRecord(_address,&_record,kDNSServiceFlagsUnique,interface,
        host.UTF8String,kDNSServiceType_A,kDNSServiceClass_IN,sizeof(address),&address,60,addressRegistered,NULL);
    if(!error)error=DNSServiceRegister(&_service,0,interface,label.UTF8String,"_btvc._tcp","local.",
        host.UTF8String,htons(39028),0,NULL,serviceRegistered,NULL);
    if(!error)error=DNSServiceSetDispatchQueue(_service,_queue);
    if(error){fprintf(stderr,"Native Bluetooth Bonjour setup failed status=%d\n",error);[self invalidate];return NO;}
    fprintf(stderr,"Native Bluetooth Bonjour discovery endpoint registered on guest en0\n");return YES;
}
- (void)invalidate {
    if(_service){DNSServiceRef service=_service;_service=NULL;DNSServiceRefDeallocate(service);}
    if(_address){DNSServiceRef service=_address;_address=NULL;DNSServiceRefDeallocate(service);}
    _record=NULL;_queue=nil;
}
- (void)dealloc {[self invalidate];}
@end
