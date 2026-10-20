/* Finite HOST source delta only: these Foundation identities are not VZ SDK
 * objects. Real sockets test actual native FD retention and counter refusal. */
#import "VZGuestTools_owned_active_ssh_v5.m"
static uint64_t nowNS=1000;
bool VM27QGAFixtureTimeV3(uint64_t *out){*out=nowNS;return true;}
static unsigned checks;
static void check(BOOL ok){if(!ok){fprintf(stderr,"failed admission check %u\n",checks+1);abort();}++checks;}
@interface VM27AdmissionSocketIdentityV4 : NSObject {@public int fd;}
- (int)fileDescriptor;
@end
@implementation VM27AdmissionSocketIdentityV4
- (int)fileDescriptor{return fd;}
- (void)dealloc{if(fd>=0)close(fd);[super dealloc];}
@end
static VM27AdmissionSocketIdentityV4 *pair(int *peer){int f[2];check(socketpair(AF_UNIX,SOCK_STREAM,0,f)==0);VM27AdmissionSocketIdentityV4 *o=[VM27AdmissionSocketIdentityV4 new];o->fd=f[0];*peer=f[1];return o;}
int main(void){@autoreleasepool{
 alarm(10);int a,b;VM27AdmissionSocketIdentityV4 *first=pair(&a),*next=pair(&b);
 VZGuestSocketListenerDelegate *delegate=[VZGuestSocketListenerDelegate new];NSObject *listener=[NSObject new];
 __block unsigned failed=0;
 QGASyncV3(^{
  gGuestSocketDelegate=[delegate retain];gGuestSocketListener=[listener retain];
  gGuestConnectionEpochV3=UINT64_MAX-2;gGuestProvisioningGeneration=UINT64_MAX-2;
  check(VZGuestToolsAcceptConnection(first));gGuestProvisioningStarted=YES;
  check(gGuestConnectionEpochV3==UINT64_MAX-1 && gGuestProvisioningGeneration==UINT64_MAX-1);
  VM27OwnedQGAOperationV5 *owner=BeginQGAOperationV3(^(BOOL success,NSData *output){check(!success && output.length>0);++failed;});check(owner!=nil);
  check(![delegate listener:listener shouldAcceptNewConnection:next fromSocketDevice:nil]);
  check(gGuestConnectionEpochV3==UINT64_MAX && gGuestProvisioningGeneration==UINT64_MAX);
  check(failed==1 && gGuestOwnedOperationV3==nil && gGuestSocketConnection==first);
  check(gGuestSocketListener==listener && gGuestSocketDelegate==delegate);
 });
 __block char byte;check(recv(a,&byte,1,0)==0);check(send(next->fd,"x",1,0)==1 && recv(b,&byte,1,0)==1);
 VM27AdmissionSocketIdentityV4 *invalid=[VM27AdmissionSocketIdentityV4 new];invalid->fd=-1;
 check(![delegate listener:listener shouldAcceptNewConnection:invalid fromSocketDevice:nil]);[invalid release];
 VZGuestToolsReset();
 // Native ownership uncertainty retains the actual old SDK identity. A new
 // unrelated socket must remain open and must not be reported admitted.
 int c,d,e;VM27AdmissionSocketIdentityV4 *old=pair(&c),*replacement=pair(&d),*unrelated=pair(&e);
 QGASyncV3(^{
  gGuestConnectionEpochV3=10;gGuestProvisioningGeneration=20;
  check(VZGuestToolsAcceptConnection(old));gGuestProvisioningStarted=YES;
  VM27OwnedQGAOperationV5 *owner=BeginQGAOperationV3(^(BOOL success,NSData *output){check(!success && output.length>0);++failed;});check(owner!=nil);
  int held=owner->_lease.ownedFD;check(close(held)==0);check(dup2(unrelated->fd,held)==held);
  check(!VZGuestToolsAcceptConnection(replacement));
  check(failed==2 && gGuestSocketConnection==old && gGuestReadDescriptor==-1);
  check(gGuestCleanupUnresolvedV5);
  uint64_t actualEpoch=gGuestConnectionEpochV3,actualGeneration=gGuestProvisioningGeneration;
  check(!VZGuestToolsAcceptConnection(replacement));
  check(gGuestConnectionEpochV3==actualEpoch && gGuestProvisioningGeneration==actualGeneration);
  VZGuestToolsReset();
  check(gGuestCleanupUnresolvedV5 && ![delegate listener:listener shouldAcceptNewConnection:replacement fromSocketDevice:nil]);
  check(BeginQGAOperationV3(nil)==nil);
  check(gGuestSocketListener==listener && gGuestSocketDelegate==delegate);
  check(send(held,"y",1,0)==1 && recv(e,&byte,1,0)==1);check(close(held)==0);
  check(send(replacement->fd,"z",1,0)==1 && recv(d,&byte,1,0)==1);
  // Fixture owns all these descriptors and closes them explicitly. Production
  // retains unresolved owners for the normal VM owner; it never fakes cleanup.
  close(old->fd);old->fd=-1;
 });
 VZGuestToolsReset();QGASyncV3(^{[gGuestSocketListener release];gGuestSocketListener=nil;[gGuestSocketDelegate release];gGuestSocketDelegate=nil;});
 [first release];[next release];[old release];[replacement release];[unrelated release];[delegate release];[listener release];close(a);close(b);close(c);close(d);close(e);
 printf("QGA admission v5: %u finite real-socket delta checks passed; SDK and guest not executed\n",checks);return 0;
}}
