/* HOST-only finite new service delta; these objects are not genuine VZ VMs.
 * Real socketpair/stat identity is used; no QGA request, guest job, or SDK call. */
#import "VZGuestTools_owned_active_ssh_v6.m"
static unsigned checks;
static void check(BOOL ok){if(!ok){fprintf(stderr,"service check failed %u\n",checks+1);abort();}++checks;}
static VM27OwnedSSHServiceV2 *service(id vm,VM27SSHServiceStateV2 state) {
    VM27OwnedSSHServiceV2 *o=[VM27OwnedSSHServiceV2 new];o->_vm=[vm retain];o->_state=state;o->_hostPID=getpid();return o;
}
int main(void){@autoreleasepool{
 alarm(10);NSObject *vm=[NSObject new],*other=[NSObject new];
 check(VM27OwnedSSHServiceAttachGateV2(vm));
 QGASyncV3(^{
  check(VM27SSHAttachedV2(vm));check(!VM27SSHAttachedV2(other));
  VM27OwnedSSHServiceV2 *o=service(vm,VM27SSHServiceWaitingV2);gGuestOwnedSSHServiceV2=o;
  VM27OwnedSSHServiceConnectionChangedV2();check(o->_state==VM27SSHServiceWaitingV2 && gGuestOwnedSSHServiceV2==o);
  check(!VM27OwnedSSHServiceAttachGateV2(other));check(VM27SSHAttachedV2(vm));
  VM27OwnedSSHServiceResetNoticeV2();check(gGuestOwnedSSHServiceV2==nil);
  o=service(vm,VM27SSHServiceRunningV2);gGuestOwnedSSHServiceV2=o;
  VM27OwnedSSHServiceConnectionChangedV2();check(o->_state==VM27SSHServiceUnresolvedV2 && o->_vm==vm);
  VM27OwnedSSHServiceResetNoticeV2();check(gGuestOwnedSSHServiceV2==o && o->_vm==vm);
  check(VM27OwnedSSHServiceActiveV2());gGuestOwnedSSHServiceV2=nil;[o release];
  o=service(vm,VM27SSHServiceWaitingV2);gGuestOwnedSSHServiceV2=o;o->_readyDeadline=0;
  VM27SSHReadyTryV2(o);check(gGuestOwnedSSHServiceV2==nil);
  o=service(vm,VM27SSHServiceInstallingV2);
  NSString *valid=@"VM27_OWNED_SSH_SERVICE_CAPTURE pid=42 uid=502 ppid=1 startSHA256=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef label=com.mac.virtual.independent27.owned-ssh-v2 guestSSHAuthenticated=0\n";
  check(VM27SSHCaptureV2(o,VM27SSHMessageV2(valid)));check(o->_guestPID==42 && o->_guestUID==502);
  [o->_guestStart release];o->_guestStart=nil;
  check(!VM27SSHCaptureV2(o,VM27SSHMessageV2([valid stringByAppendingString:valid])));
  check(!VM27SSHCaptureV2(o,VM27SSHMessageV2([valid stringByReplacingOccurrencesOfString:@"pid=42" withString:@"pid=-1"])));
  check(!VM27SSHCaptureV2(o,VM27SSHMessageV2([valid stringByReplacingOccurrencesOfString:@"uid=502" withString:@"uid=0"])));
  check(!VM27SSHCaptureV2(o,VM27SSHMessageV2([valid stringByReplacingOccurrencesOfString:@"ppid=1" withString:@"ppid=2"])));
  check(!VM27SSHCaptureV2(o,VM27SSHMessageV2([valid stringByReplacingOccurrencesOfString:@"owned-ssh-v2" withString:@"foreign-ssh-v2"])));
  check(!VM27SSHCaptureV2(o,VM27SSHMessageV2([valid stringByReplacingOccurrencesOfString:@"guestSSHAuthenticated=0" withString:@"guestSSHAuthenticated=0 extra=1"])));
  int sockets[2],unrelated[2];check(socketpair(AF_UNIX,SOCK_STREAM,0,sockets)==0);check(socketpair(AF_UNIX,SOCK_STREAM,0,unrelated)==0);
  NSObject *connection=[NSObject new];struct stat st;check(fstat(sockets[0],&st)==0);
  gGuestSocketConnection=[connection retain];gGuestReadDescriptor=gGuestWriteDescriptor=sockets[0];
  gGuestConnectionEpochV3=17;gGuestProvisioningGeneration=23;o->_connection=[connection retain];
  o->_epoch=17;o->_generation=23;o->_originalFD=sockets[0];o->_socketDevice=st.st_dev;o->_socketInode=st.st_ino;
  check(VM27SSHCurrentConnectionV2(o));++gGuestConnectionEpochV3;check(!VM27SSHCurrentConnectionV2(o));--gGuestConnectionEpochV3;
  ++gGuestProvisioningGeneration;check(!VM27SSHCurrentConnectionV2(o));--gGuestProvisioningGeneration;
  check(dup2(unrelated[0],sockets[0])==sockets[0]);check(!VM27SSHCurrentConnectionV2(o));
  close(sockets[0]);close(sockets[1]);close(unrelated[0]);close(unrelated[1]);
  [gGuestSocketConnection release];gGuestSocketConnection=nil;gGuestReadDescriptor=gGuestWriteDescriptor=-1;
  [connection release];[o release];[gGuestAttachedVMsV2 release];gGuestAttachedVMsV2=nil;
 });
 [vm release];[other release];printf("Owned SSH service V2: %u finite HOST delta checks passed; QGA/SDK/guest not executed\n",checks);return 0;
}}
