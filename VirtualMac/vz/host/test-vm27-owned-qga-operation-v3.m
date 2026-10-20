/* HOST source fixture only: Foundation identities and real socketpairs exercise
 * actual private callback/epoch/FD behavior. These are not VZ SDK objects. */
#import "VZGuestTools_owned_active_ssh_v3.m"
#include <poll.h>
#include <time.h>
static uint64_t fixtureNow=1000;
bool VM27QGAFixtureTimeV3(uint64_t *out) {*out=__atomic_load_n(&fixtureNow,__ATOMIC_ACQUIRE);return true;}
static unsigned checks;
static void check(BOOL condition) {if(!condition){fprintf(stderr,"failed event check %u\n",checks+1);abort();}++checks;}
@interface VM27HostSocketIdentityFixtureV3 : NSObject {@public int _fd;}
- (int)fileDescriptor;
@end
@implementation VM27HostSocketIdentityFixtureV3
- (int)fileDescriptor{return _fd;}
- (void)dealloc{if(_fd>=0)close(_fd);[super dealloc];}
@end
static VM27HostSocketIdentityFixtureV3 *connectFixture(int *peer) {
    int f[2];check(socketpair(AF_UNIX,SOCK_STREAM,0,f)==0);
    VM27HostSocketIdentityFixtureV3 *c=[VM27HostSocketIdentityFixtureV3 new];c->_fd=f[0];*peer=f[1];
    VZGuestToolsAcceptConnection(c);QGASyncV3(^{gGuestProvisioningStarted=YES;});return c;
}
static NSDictionary *packet(int peer) {
    NSMutableData *data=[NSMutableData data];uint8_t bytes[4096];
    while(1){struct pollfd fd={peer,POLLIN,0};check(poll(&fd,1,1500)>0);ssize_t amount=recv(peer,bytes,sizeof(bytes),0);check(amount>0);[data appendBytes:bytes length:(NSUInteger)amount];if(bytes[amount-1]=='\n')break;}
    id decoded=[NSJSONSerialization JSONObjectWithData:data options:0 error:NULL];check([decoded isKindOfClass:NSDictionary.class]);return decoded;
}
static void response(int peer,NSDictionary *value) {
    NSMutableData *data=[[[NSJSONSerialization dataWithJSONObject:value options:0 error:NULL] mutableCopy] autorelease];[data appendBytes:"\n" length:1];
    check(send(peer,data.bytes,data.length,0)==(ssize_t)data.length);
}
static void waitDone(dispatch_semaphore_t sem) {check(dispatch_semaphore_wait(sem,dispatch_time(DISPATCH_TIME_NOW,2*NSEC_PER_SEC))==0);}
static void noPacket(int peer) {struct pollfd fd={peer,POLLIN,0};check(poll(&fd,1,350)==0);}
static void oldOff(int peer) {struct pollfd fd={peer,POLLIN,0};check(poll(&fd,1,1000)>0);char c;check(recv(peer,&c,1,0)==0);}
int main(void) {@autoreleasepool {
    alarm(15);int a;VM27HostSocketIdentityFixtureV3 *ca=connectFixture(&a);
    dispatch_semaphore_t done=dispatch_semaphore_create(0);__block unsigned completions=0;
    VZGuestToolsRun(@"/bin/true",@[],^(BOOL success,NSData *output){check(success && [output isEqualToData:[@"ok" dataUsingEncoding:NSUTF8StringEncoding]]);++completions;dispatch_semaphore_signal(done);});
    NSDictionary *request=packet(a);check([request[@"execute"] isEqual:@"guest-exec"]);
    response(a,@{@"id":request[@"id"],@"return":@{@"pid":@701}});request=packet(a);check([request[@"execute"] isEqual:@"guest-exec-status"]);
    response(a,@{@"id":request[@"id"],@"return":@{@"exited":@YES,@"exitcode":@0,@"out-data":@"b2s="}});waitDone(done);check(completions==1);
    check(!(fcntl(ca->_fd,F_GETFL)&O_NONBLOCK));
    fprintf(stderr,"stage success done checks=%u\n",checks);
    // The delayed old PID poll must never be sent on a replacement stream.
    VZGuestToolsRun(@"/bin/true",@[],^(BOOL success,NSData *output){(void)output;check(!success);++completions;dispatch_semaphore_signal(done);});
    request=packet(a);response(a,@{@"id":request[@"id"],@"return":@{@"pid":@702}});request=packet(a);
    response(a,@{@"id":request[@"id"],@"return":@{@"exited":@NO}});
    int b;VM27HostSocketIdentityFixtureV3 *cb=connectFixture(&b);waitDone(done);check(completions==2);oldOff(a);noPacket(b);
    fprintf(stderr,"stage PID replace done checks=%u\n",checks);
    // A real old guest-file handle/write callback cannot continue after replace.
    NSData *upload=[NSMutableData dataWithLength:52448];
    VZGuestToolsWriteFile(@"/fixed/test/path",upload,^(BOOL success){check(!success);++completions;dispatch_semaphore_signal(done);});
    request=packet(b);check([request[@"execute"] isEqual:@"guest-file-open"]);response(b,@{@"id":request[@"id"],@"return":@81});
    request=packet(b);check([request[@"execute"] isEqual:@"guest-file-write"] && [request[@"arguments"][@"handle"] isEqual:@81]);
    int c;VM27HostSocketIdentityFixtureV3 *cc=connectFixture(&c);waitDone(done);check(completions==3);oldOff(b);noPacket(c);
    fprintf(stderr,"stage upload replace done checks=%u\n",checks);
    // Monotonic expiry removes its owned callbacks, shuts only this old stream,
    // and retains the normal listener and VM lifetime rather than stopping VM.
    NSObject *listener=[NSObject new];
    VZGuestSocketListenerDelegate *delegate=[VZGuestSocketListenerDelegate new];
    VZGuestSocketListenerDelegate *oldDelegate=[VZGuestSocketListenerDelegate new];
    QGASyncV3(^{gGuestSocketListener=[listener retain];gGuestSocketDelegate=[delegate retain];});
    check(![oldDelegate listener:listener shouldAcceptNewConnection:cc fromSocketDevice:nil]);
    [oldDelegate release];
    VZGuestToolsRun(@"/bin/true",@[],^(BOOL success,NSData *output){check(!success && output.length>0);++completions;dispatch_semaphore_signal(done);});
    request=packet(c);__atomic_store_n(&fixtureNow,UINT64_C(45000001000),__ATOMIC_RELEASE);
    response(c,@{@"id":request[@"id"],@"return":@{@"pid":@703}});waitDone(done);check(completions==4);oldOff(c);
    fprintf(stderr,"stage deadline closed checks=%u\n",checks);
    QGASyncV3(^{check(gGuestSocketListener==listener && gGuestCallbacks.count==0 && gGuestOwnedOperationV3==nil);});
    __atomic_store_n(&fixtureNow,1000,__ATOMIC_RELEASE);int d;VM27HostSocketIdentityFixtureV3 *cd=connectFixture(&d);
    noPacket(d);check(send(d,"{}\n",3,0)==3); // unrelated replacement remains open
    VZGuestToolsRun(@"/bin/true",@[],^(BOOL success,NSData *output){(void)output;check(!success);++completions;dispatch_semaphore_signal(done);});
    packet(d);VZGuestToolsReset();waitDone(done);check(completions==5);oldOff(d);
    QGASyncV3(^{check(gGuestSocketListener==listener && gGuestSocketDelegate==delegate);
        [gGuestSocketListener release];gGuestSocketListener=nil;[gGuestSocketDelegate release];gGuestSocketDelegate=nil;});
    [ca release];[cb release];[cc release];[cd release];[listener release];[delegate release];close(a);close(b);close(c);close(d);dispatch_release(done);
    printf("QGA operation v3: %u finite real-socket event checks passed; SDK and guest not executed\n",checks);return 0;
}}
