// Keep the authenticated App socket alive while native hardware ownership
// lives in a separate process. A detach retires that process completely.
// A new process is admitted only after a separate, short-lived read proves
// native retirement. No controller-reset or firmware-delete API is used.
typedef struct {int fd;pid_t pid;uint64_t sequence,generation;} VM27OwnedNativeChildV1;
static int proxyTransferV1(int fd,void *data,size_t length,BOOL sending,unsigned seconds){
 uint8_t *bytes=data;size_t done=0;double end=NSProcessInfo.processInfo.systemUptime+seconds;
 while(done<length&&!Stop){
  if(NSProcessInfo.processInfo.systemUptime>=end)return ETIMEDOUT;
  struct pollfd item={fd,sending?POLLOUT:POLLIN,0};int ready=poll(&item,1,100);
  if(ready<0){if(errno==EINTR)continue;return errno;}if(!ready)continue;
  ssize_t count=sending?send(fd,bytes+done,length-done,0):recv(fd,bytes+done,length-done,0);
  if(count>0){done+=(size_t)count;continue;}
  if(count<0&&(errno==EINTR||errno==EAGAIN))continue;
  return count?errno:EPIPE;
 }return done==length?0:ECANCELED;
}
static int proxySendV1(int fd,struct vm27_radio_frame_v1 frame,NSData *payload,unsigned seconds){
 if(!payload||payload.length>VM27_RADIO_WIRE_MAX_PAYLOAD)return EINVAL;
 frame.payload_bytes=(uint32_t)payload.length;uint8_t header[32];
 int status=vm27_radio_header_encode_v1(header,&frame);
 if(!status)status=proxyTransferV1(fd,header,32,YES,seconds);
 if(!status)status=proxyTransferV1(fd,(void *)payload.bytes,payload.length,YES,seconds);
 return status;
}
static int proxyReadV1(int fd,struct vm27_radio_frame_v1 *frame,NSMutableData **payload,unsigned seconds){
 uint8_t header[32];int status=proxyTransferV1(fd,header,32,NO,seconds);
 if(!status)status=vm27_radio_header_decode_v1(header,32,frame);if(status)return status;
 NSMutableData *bytes=[NSMutableData dataWithLength:frame->payload_bytes];
 status=proxyTransferV1(fd,bytes.mutableBytes,bytes.length,NO,seconds);
 if(status){wipe(bytes.mutableBytes,bytes.length);return status;}*payload=bytes;return 0;
}
static int proxyRetireChildV1(VM27OwnedNativeChildV1 *child){
 if(child->fd>=0){close(child->fd);child->fd=-1;}
 if(child->pid<=0)return 0;
 pid_t pid=child->pid;child->pid=0;child->sequence=child->generation=0;
 kill(pid,SIGTERM);double end=NSProcessInfo.processInfo.systemUptime+6;int status=0;
 while(NSProcessInfo.processInfo.systemUptime<end){
  pid_t result=waitpid(pid,&status,WNOHANG);
  if(result==pid)return WIFEXITED(status)&&WEXITSTATUS(status)==0?0:EIO;
  if(result<0){if(errno==EINTR)continue;return errno;}
  usleep(50000);
 }
 kill(pid,SIGKILL);while(waitpid(pid,&status,0)<0&&errno==EINTR){}
 return ETIMEDOUT;
}
static int proxyNativeRetirementProbeV1(double remaining){
 const char *argv[]={OwnedExecutable,"--read-owned-native-retirement",NULL};pid_t pid=0;int status=0;
 int error=posix_spawn(&pid,OwnedExecutable,NULL,NULL,(char *const *)argv,environ);if(error)return error;
 double end=NSProcessInfo.processInfo.systemUptime+MIN(3,remaining);
 while(!Stop&&NSProcessInfo.processInfo.systemUptime<end){
  pid_t result=waitpid(pid,&status,WNOHANG);
  if(result==pid)return WIFEXITED(status)?WEXITSTATUS(status):EIO;
  if(result<0){if(errno==EINTR)continue;return errno;}usleep(50000);
 }
 // This child has no radio setters and holds no association.
 kill(pid,SIGKILL);while(waitpid(pid,&status,0)<0&&errno==EINTR){}
 return Stop?ECANCELED:ETIMEDOUT;
}
static int proxyWaitForNativeRetirementV1(void){
 double end=NSProcessInfo.processInfo.systemUptime+8;unsigned attempts=0;
 while(!Stop&&NSProcessInfo.processInfo.systemUptime<end){
  int result=proxyNativeRetirementProbeV1(end-NSProcessInfo.processInfo.systemUptime);attempts++;
  if(!result){fprintf(stderr,"[OwnedWiFi] native-process retirement verified probes=%u noRadioSetters=1\n",attempts);return 0;}
  if(result!=75&&result!=ETIMEDOUT)return result;
  usleep(200000);
 }return Stop?ECANCELED:ETIMEDOUT;
}
static int proxyOpenNativeChildV1(VM27OwnedNativeChildV1 *child){
 int error=proxyWaitForNativeRetirementV1();if(error)return error;
 int ends[2];if(socketpair(AF_UNIX,SOCK_STREAM,0,ends))return errno;
 int one=1;for(unsigned i=0;i<2;i++){
  if(fcntl(ends[i],F_SETFD,FD_CLOEXEC)||setsockopt(ends[i],SOL_SOCKET,SO_NOSIGPIPE,&one,sizeof(one))){
   error=errno;close(ends[0]);close(ends[1]);return error;
  }
 }
 posix_spawn_file_actions_t actions;posix_spawn_file_actions_init(&actions);
 posix_spawn_file_actions_adddup2(&actions,ends[1],3);
 if(ends[0]!=3)posix_spawn_file_actions_addclose(&actions,ends[0]);
 if(ends[1]!=3)posix_spawn_file_actions_addclose(&actions,ends[1]);
 const char *argv[]={OwnedExecutable,"--serve-owned-native-station-fd","3",NULL};pid_t pid=0;
 error=posix_spawn(&pid,OwnedExecutable,&actions,NULL,(char *const *)argv,environ);
 posix_spawn_file_actions_destroy(&actions);close(ends[1]);
 if(error){close(ends[0]);return error;}
 child->fd=ends[0];child->pid=pid;child->sequence=1;child->generation=0;
 NSData *hello=[NSJSONSerialization dataWithJSONObject:@{@"protocol":@1}options:0 error:NULL];
 struct vm27_radio_frame_v1 frame={VM27_RADIO_HELLO,0,child->sequence,0};
 error=proxySendV1(child->fd,frame,hello,8);NSMutableData *reply=nil;
 if(!error)error=proxyReadV1(child->fd,&frame,&reply,8);
 if(!error&&(frame.type!=VM27_RADIO_HELLO_REPLY||frame.request_id!=1||!frame.generation))error=EPROTO;
 NSDictionary *object=!error?[NSJSONSerialization JSONObjectWithData:reply options:0 error:NULL]:nil;
 if(!error&&(![object isKindOfClass:NSDictionary.class]||![object[@"ok"]isEqual:@YES]))error=EPROTO;
 if(reply)wipe(reply.mutableBytes,reply.length);
 if(error){proxyRetireChildV1(child);return error;}
 child->generation=frame.generation;return 0;
}
static int VM27OwnedWiFiSessionProxyV1(int fd,uid_t owner){@autoreleasepool{
 if(geteuid()!=owner)return 77;
 signal(SIGTERM,stopSignal);signal(SIGINT,stopSignal);signal(SIGPIPE,SIG_IGN);
 VM27OwnedNativeChildV1 child={.fd=-1};uint64_t generation=0,lastSequence=0;
 arc4random_buf(&generation,sizeof(generation));if(!generation)generation=1;
 BOOL authenticated=NO;int result=0;double acceptedAt=NSProcessInfo.processInfo.systemUptime;
 while(!Stop){@autoreleasepool{
  if(!authenticated&&NSProcessInfo.processInfo.systemUptime-acceptedAt>20){result=ETIMEDOUT;break;}
  struct pollfd item={fd,POLLIN,0};int ready=poll(&item,1,100);
  if(ready<0){if(errno==EINTR)continue;result=errno;break;}if(!ready)continue;
  struct vm27_radio_frame_v1 incoming;NSMutableData *payload=nil;
  result=proxyReadV1(fd,&incoming,&payload,4);if(result){if(result==EPIPE)result=0;break;}
  NSDictionary *request=[NSJSONSerialization JSONObjectWithData:payload options:0 error:NULL];
  if(![request isKindOfClass:NSDictionary.class]||incoming.request_id<=lastSequence){wipe(payload.mutableBytes,payload.length);result=EPROTO;break;}
  lastSequence=incoming.request_id;NSMutableData *output=nil;
  uint32_t responseType=VM27_RADIO_REPLY;
  if(!authenticated&&incoming.type==VM27_RADIO_HELLO&&incoming.generation==0&&[request[@"protocol"]isEqual:@1]){
   authenticated=YES;responseType=VM27_RADIO_HELLO_REPLY;
   output=[[NSJSONSerialization dataWithJSONObject:@{@"ok":@YES,@"protocol":@1}options:0 error:NULL]mutableCopy];
  }else if(authenticated&&incoming.type==VM27_RADIO_REQUEST&&incoming.generation==generation){
   NSString *method=[request[@"method"]isKindOfClass:NSString.class]?request[@"method"]:nil;
   if(![method hasPrefix:@"wifi."]){wipe(payload.mutableBytes,payload.length);result=EPROTO;break;}
   int error=0;
   if(child.fd<0&&([method isEqual:@"wifi.state"]||[method isEqual:@"wifi.detachShared"])){
    output=[[NSJSONSerialization dataWithJSONObject:@{@"ok":@YES,@"wifi":@{@"hostPowered":@YES,@"hostAssociated":@NO,@"guestAttached":@NO,@"dataPathConfigured":@NO,@"mode":@"independent-native-managed-station"}}options:0 error:NULL]mutableCopy];
   }else if(child.fd<0&&![method isEqual:@"wifi.scan"]&&![method isEqual:@"wifi.associate"]){
    output=[[NSJSONSerialization dataWithJSONObject:@{@"ok":@NO,@"error":@{@"code":@(ENOTCONN)}}options:0 error:NULL]mutableCopy];
   }else{
    if(child.fd<0)error=proxyOpenNativeChildV1(&child);
    if(!error&&child.sequence==UINT64_MAX)error=EOVERFLOW;
    struct vm27_radio_frame_v1 nativeFrame={VM27_RADIO_REQUEST,0,error?0:++child.sequence,child.generation};
    if(!error)error=proxySendV1(child.fd,nativeFrame,payload,4);
    if(!error)error=proxyReadV1(child.fd,&nativeFrame,&output,30);
    if(!error&&(nativeFrame.type!=VM27_RADIO_REPLY||nativeFrame.request_id!=child.sequence||nativeFrame.generation!=child.generation))error=EPROTO;
    NSDictionary *nativeReply=!error?[NSJSONSerialization JSONObjectWithData:output options:0 error:NULL]:nil;
    if(!error&&![nativeReply isKindOfClass:NSDictionary.class])error=EPROTO;
    NSDictionary *wifi=[nativeReply[@"wifi"]isKindOfClass:NSDictionary.class]?nativeReply[@"wifi"]:nil;
    BOOL active=[wifi[@"guestAttached"]boolValue]&&[wifi[@"dataPathConfigured"]boolValue]&&[wifi[@"hostAssociated"]boolValue];
    // A rejected, ineligible candidate must not retire a still-valid link.
    BOOL retire=!error&&([method isEqual:@"wifi.detachShared"]||([method isEqual:@"wifi.associate"]&&![nativeReply[@"ok"]boolValue]&&!active));
    if(error||retire){
     int stopped=proxyRetireChildV1(&child);
     if(stopped&&!error)error=stopped;
     fprintf(stderr,"[OwnedWiFi] native-process session retired result=%d detach=%d associationFailed=%d\n",stopped,[method isEqual:@"wifi.detachShared"],[method isEqual:@"wifi.associate"]);
    }
    if(error){
     if(output)wipe(output.mutableBytes,output.length);
     output=[[NSJSONSerialization dataWithJSONObject:@{@"ok":@NO,@"error":@{@"code":@(error)}}options:0 error:NULL]mutableCopy];
    }
   }
  }else{wipe(payload.mutableBytes,payload.length);result=EPROTO;break;}
  wipe(payload.mutableBytes,payload.length);
  struct vm27_radio_frame_v1 response={responseType,0,incoming.request_id,generation};
  result=proxySendV1(fd,response,output,4);if(output)wipe(output.mutableBytes,output.length);if(result)break;
 }}
 close(fd);int stopped=proxyRetireChildV1(&child);return result?result:stopped;
}}
