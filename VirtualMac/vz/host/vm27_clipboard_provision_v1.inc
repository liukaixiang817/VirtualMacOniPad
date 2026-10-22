#include "vm27_clipboard_provision_v1.h"
#include "vm27_clipboard_guest_artifact_v1.h"
/* Included after the original owned QGA/SSH definitions. One actual 45 second
 * lease spans preflight, signed helper upload, install and GUI launch. */
void VM27ProvisionClipboardGuestV1(id vm,void (^completion)(BOOL)) {
 NSCAssert(pthread_main_np(),@"Provision admission requires actual main VM.queue");
 IMP state=NULL;
 if(!VM27SSHOriginalIMPOnMainV2(vm,"state",&state) ||
    ((NSInteger(*)(id,SEL))state)(vm,sel_registerName("state"))!=1) {completion(NO);return;}
 NSData *artifact=[NSData dataWithContentsOfFile:[NSBundle.mainBundle.bundlePath stringByAppendingPathComponent:@"GuestTools/vm27-clipboard-guest-signed-v1"]];
 uint8_t digest[CC_SHA256_DIGEST_LENGTH];
 if(artifact.length!=VM27_CLIPBOARD_GUEST_BYTES){completion(NO);return;}
 CC_SHA256(artifact.bytes,(CC_LONG)artifact.length,digest);
 NSMutableString *actual=[NSMutableString string];
 for(unsigned i=0;i<CC_SHA256_DIGEST_LENGTH;++i)[actual appendFormat:@"%02x",digest[i]];
 if(![actual isEqualToString:VM27_CLIPBOARD_GUEST_SHA256]){completion(NO);return;}
 NSString *suffix=NSUUID.UUID.UUIDString;
 NSString *stage=[@"/var/root/.VM27ClipboardInstall-" stringByAppendingString:suffix];
 NSString *pre=[@"set -eu\n[ \"$(id -u)\" = 0 ]\nuid=$(/usr/bin/stat -f %u /dev/console)\ncase \"$uid\" in ''|*[!0-9]*) exit 77;; esac\n[ \"$uid\" -ge 500 ]\n/bin/launchctl print \"gui/$uid\" >/dev/null\nif [ ! -L '/Library/VirtualMac/ClipboardSync/VM27ClipboardGuest' ] && [ -f '/Library/VirtualMac/ClipboardSync/VM27ClipboardGuest' ] && [ ! -L '/Library/LaunchAgents/com.mac.virtual.clipboard-sync.plist' ] && [ -f '/Library/LaunchAgents/com.mac.virtual.clipboard-sync.plist' ] &&\n [ \"$(/usr/bin/shasum -a 256 '/Library/VirtualMac/ClipboardSync/VM27ClipboardGuest' | /usr/bin/cut -d ' ' -f1)\" = 'd3d4f11d0fa54b8e7b7c22210fdf8b2f2c596474695d4dee81a70df8de4cb9d7' ] &&\n [ \"$(/usr/bin/shasum -a 256 '/Library/LaunchAgents/com.mac.virtual.clipboard-sync.plist' | /usr/bin/cut -d ' ' -f1)\" = '0acf78e586c1979f981d2b982cce580d69d9dc2c61cf83c0d1a148c30ab08c72' ] &&\n [ \"$(/usr/bin/stat -f '%u:%g:%Lp:%l' '/Library/VirtualMac/ClipboardSync/VM27ClipboardGuest')\" = 0:0:755:1 ] &&\n [ \"$(/usr/bin/stat -f '%u:%g:%Lp:%l' '/Library/LaunchAgents/com.mac.virtual.clipboard-sync.plist')\" = 0:0:644:1 ];then\n if ! /bin/launchctl print \"gui/$uid/com.mac.virtual.clipboard-sync\" >/dev/null 2>&1;then /bin/launchctl bootstrap \"gui/$uid\" '/Library/LaunchAgents/com.mac.virtual.clipboard-sync.plist';fi\n printf 'VM27_CLIPBOARD_CURRENT\\n';exit 0\nfi\numask 077\nstage='/var/root/.VM27ClipboardInstall-__STAGE__'\n[ ! -e \"$stage\" ] && [ ! -L \"$stage\" ]\n/bin/mkdir -m 700 \"$stage\"\nprintf 'VM27_CLIPBOARD_STAGE_READY\\n'\n" stringByReplacingOccurrencesOfString:@"__STAGE__" withString:suffix];
 NSString *install=[@"set -eu\n[ \"$(id -u)\" = 0 ]\nuid=$(/usr/bin/stat -f %u /dev/console)\ncase \"$uid\" in ''|*[!0-9]*) exit 77;; esac\n[ \"$uid\" -ge 500 ]\n/bin/launchctl print \"gui/$uid\" >/dev/null\nstage='/var/root/.VM27ClipboardInstall-__STAGE__'\n[ ! -L \"$stage\" ] && [ \"$(/usr/bin/stat -f '%u:%g:%Lp' \"$stage\")\" = 0:0:700 ]\n[ ! -L \"$stage/agent\" ] && [ ! -L \"$stage/job.plist\" ]\n[ \"$(/usr/bin/shasum -a 256 \"$stage/agent\" | /usr/bin/cut -d ' ' -f1)\" = 'd3d4f11d0fa54b8e7b7c22210fdf8b2f2c596474695d4dee81a70df8de4cb9d7' ]\n[ \"$(/usr/bin/shasum -a 256 \"$stage/job.plist\" | /usr/bin/cut -d ' ' -f1)\" = '0acf78e586c1979f981d2b982cce580d69d9dc2c61cf83c0d1a148c30ab08c72' ]\n/usr/bin/codesign --verify --strict \"$stage/agent\"\n/usr/bin/codesign -dv \"$stage/agent\" 2>&1 | /usr/bin/grep -Fx 'Identifier=com.mac.virtual.clipboard-agent'\n/usr/bin/plutil -lint \"$stage/job.plist\"\nfor directory in /Library/VirtualMac /Library/VirtualMac/ClipboardSync /Library/LaunchAgents;do\n [ ! -L \"$directory\" ]\n if [ ! -e \"$directory\" ];then /bin/mkdir -m 755 \"$directory\";fi\n [ -d \"$directory\" ] && [ \"$(/usr/bin/stat -f %u \"$directory\")\" = 0 ]\ndone\n[ ! -L '/Library/VirtualMac/ClipboardSync/VM27ClipboardGuest' ] && [ ! -L '/Library/LaunchAgents/com.mac.virtual.clipboard-sync.plist' ]\nif [ -e '/Library/VirtualMac/ClipboardSync/VM27ClipboardGuest' ];then /bin/cp -p '/Library/VirtualMac/ClipboardSync/VM27ClipboardGuest' \"$stage/previous-agent\";fi\nif [ -e '/Library/LaunchAgents/com.mac.virtual.clipboard-sync.plist' ];then /bin/cp -p '/Library/LaunchAgents/com.mac.virtual.clipboard-sync.plist' \"$stage/previous-job.plist\";fi\n/bin/chmod 755 \"$stage/agent\"\n/bin/chmod 644 \"$stage/job.plist\"\n/bin/cp \"$stage/agent\" '/Library/VirtualMac/ClipboardSync/VM27ClipboardGuest.new'\n/bin/cp \"$stage/job.plist\" '/Library/LaunchAgents/com.mac.virtual.clipboard-sync.plist.new'\n/usr/sbin/chown 0:0 '/Library/VirtualMac/ClipboardSync/VM27ClipboardGuest.new' '/Library/LaunchAgents/com.mac.virtual.clipboard-sync.plist.new'\n/bin/chmod 755 '/Library/VirtualMac/ClipboardSync/VM27ClipboardGuest.new'\n/bin/chmod 644 '/Library/LaunchAgents/com.mac.virtual.clipboard-sync.plist.new'\n/bin/mv -f '/Library/VirtualMac/ClipboardSync/VM27ClipboardGuest.new' '/Library/VirtualMac/ClipboardSync/VM27ClipboardGuest'\n/bin/mv -f '/Library/LaunchAgents/com.mac.virtual.clipboard-sync.plist.new' '/Library/LaunchAgents/com.mac.virtual.clipboard-sync.plist'\nif /bin/launchctl print \"gui/$uid/com.mac.virtual.clipboard-sync\" >/dev/null 2>&1;then /bin/launchctl bootout \"gui/$uid/com.mac.virtual.clipboard-sync\";fi\n/bin/launchctl bootstrap \"gui/$uid\" '/Library/LaunchAgents/com.mac.virtual.clipboard-sync.plist'\n/bin/launchctl print \"gui/$uid/com.mac.virtual.clipboard-sync\" >/dev/null\n/bin/rm \"$stage/agent\" \"$stage/job.plist\"\nprintf 'VM27_CLIPBOARD_GUI_AGENT_INSTALLED\\n'\n" stringByReplacingOccurrencesOfString:@"__STAGE__" withString:suffix];
 NSData *job=[@"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\">\n<dict>\n\t<key>KeepAlive</key>\n\t<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>\n\t</dict>\n\t<key>Label</key>\n\t<string>com.mac.virtual.clipboard-sync</string>\n\t<key>LimitLoadToSessionType</key>\n\t<string>Aqua</string>\n\t<key>ProgramArguments</key>\n\t<array>\n\t\t<string>/Library/VirtualMac/ClipboardSync/VM27ClipboardGuest</string>\n\t</array>\n\t<key>RunAtLoad</key>\n\t<true/>\n\t<key>ThrottleInterval</key>\n\t<integer>10</integer>\n</dict>\n</plist>\n" dataUsingEncoding:NSUTF8StringEncoding];
 dispatch_async(QGAQueueV3(),^{
  if(!VM27SSHRoleV2() || !VM27SSHAttachedV2(vm) || gGuestCleanupUnresolvedV5 || gGuestOwnedOperationV3 || gGuestWriteDescriptor<0) {
   dispatch_async(dispatch_get_main_queue(),^{completion(NO);});return;
  }
  VM27OwnedQGAOperationV5 *owner=BeginQGAOperationV3(^(BOOL success,NSData *output){
   NSString *text=[[[NSString alloc]initWithData:output encoding:NSUTF8StringEncoding]autorelease];
   BOOL verified=success && ([text containsString:@"VM27_CLIPBOARD_CURRENT"] || [text containsString:@"VM27_CLIPBOARD_GUI_AGENT_INSTALLED"]);
   dispatch_async(dispatch_get_main_queue(),^{completion(verified);});
  });
  if(!owner)return;
  OwnedQGARunV3(owner,@"/bin/sh",@[@"-c",pre],^(BOOL ok,NSData *output){
   if(![owner isLive])return;
   NSString *text=[[[NSString alloc]initWithData:output encoding:NSUTF8StringEncoding]autorelease];
   if(!ok || [text containsString:@"VM27_CLIPBOARD_CURRENT"]){[owner finish:ok output:output];return;}
   if(![text containsString:@"VM27_CLIPBOARD_STAGE_READY"]){[owner finish:NO output:[NSData data]];return;}
   OwnedQGAWriteFileV3(owner,[stage stringByAppendingPathComponent:@"agent"],artifact,^(BOOL uploaded){
    if(![owner isLive])return;if(!uploaded){[owner finish:NO output:[NSData data]];return;}
    OwnedQGAWriteFileV3(owner,[stage stringByAppendingPathComponent:@"job.plist"],job,^(BOOL wrote){
     if(![owner isLive])return;if(!wrote){[owner finish:NO output:[NSData data]];return;}
     OwnedQGARunV3(owner,@"/bin/sh",@[@"-c",install],^(BOOL installed,NSData *result){if([owner isLive])[owner finish:installed output:result];});
    });
   });
  });
 });
}
