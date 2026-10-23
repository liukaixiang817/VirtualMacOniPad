#include <notify.h>
#include "vm27_lock_pause_policy_v1.h"
static VM27LockPausePolicyV1 VM27LockPolicyV1;
static id VM27LockOwnerV1;
static BOOL VM27LockSubmittingV1,VM27LockInstalledV1;
static int VM27LockNotifyTokenV1=-1;
static unsigned VM27LockObserveLogsV1;
static uint64_t VM27LockRetryGenerationV1,VM27LockForegroundEpochV4;
static UIBackgroundTaskIdentifier VM27LockBackgroundTaskV1;
static BOOL VM27LockTaskReadyV1;
static UIView *VM27PausedCardV1;
static void VM27LockMaybeResumeV1(void);
static void VM27LockEndBackgroundV1(void) {
 if(VM27LockTaskReadyV1 && VM27LockBackgroundTaskV1!=UIBackgroundTaskInvalid) {
  UIBackgroundTaskIdentifier task=VM27LockBackgroundTaskV1;VM27LockBackgroundTaskV1=UIBackgroundTaskInvalid;
  [UIApplication.sharedApplication endBackgroundTask:task];
 }
}
static void VM27LockClearOwnerV1(void) {
 VM27LockEndBackgroundV1();VM27LockManualV1(&VM27LockPolicyV1);[VM27LockOwnerV1 release];VM27LockOwnerV1=nil;
}
static void VM27LockManualRequestV1(void) {
 if(!VM27LockSubmittingV1)VM27LockClearOwnerV1();
}
@interface VM27PauseCardV1 : UIVisualEffectView
@property(nonatomic,retain) UILabel *statusLabel;
@property(nonatomic,retain) UIButton *resumeButton;
- (void)refreshStatus;
@end
@implementation VM27PauseCardV1
- (void)resume:(id)sender {
 (void)sender;
 if(!VM27HibernateOperationPendingV4() && !gIndependent27VMStateTransitionPendingV44)
  VZIndependent27RequestVMStateV44(YES);
 [self refreshStatus];
}
- (void)refreshStatus {
 BOOL saving=VM27HibernateOperationPendingV4();
 BOOL busy=saving || gIndependent27VMStateTransitionPendingV44;
 self.statusLabel.text=VZL(saving?@"Saving virtual machine state…":
  busy?@"Resuming virtual machine…":@"The virtual machine is paused. Resume when you are ready.");
 self.resumeButton.enabled=!busy;
}
- (void)dealloc {[_statusLabel release];[_resumeButton release];[super dealloc];}
@end
static void VM27LockShowPausedV1(BOOL paused) {
 if(!pthread_main_np())return;
 id root=UIApplication.sharedApplication.keyWindow.rootViewController;
 VZViewController *controller=[root isKindOfClass:VZViewController.class]?root:nil;
 if(!paused || !controller.isVMDisplayActive) {
  if(VM27PausedCardV1)fprintf(stderr,"[VM27PauseOverlayV2] visible=0\n");
  [VM27PausedCardV1 removeFromSuperview];[VM27PausedCardV1 release];VM27PausedCardV1=nil;return;
 }
 if(VM27PausedCardV1){[(VM27PauseCardV1 *)VM27PausedCardV1 refreshStatus];return;}
 // The effect exists only while the real VM is paused. Running frames never
 // pay for a full-screen backdrop render, and the overlay consumes all taps.
 VM27PauseCardV1 *card=[[VM27PauseCardV1 alloc] initWithEffect:
  [UIBlurEffect effectWithStyle:UIBlurEffectStyleSystemMaterialDark]];
 VM27PausedCardV1=card;card.accessibilityViewIsModal=YES;
 card.accessibilityIdentifier=@"VM27FullScreenPauseOverlay";
 card.translatesAutoresizingMaskIntoConstraints=NO;
 card.contentView.backgroundColor=[UIColor colorWithWhite:0 alpha:0.15];
 UIImageView *icon=[[[UIImageView alloc]initWithImage:[UIImage systemImageNamed:@"pause.circle.fill"]]autorelease];
 icon.contentMode=UIViewContentModeScaleAspectFit;icon.tintColor=UIColor.whiteColor;
 [icon.heightAnchor constraintEqualToConstant:60].active=YES;
 UILabel *title=[[[UILabel alloc]init]autorelease];title.text=VZL(@"Virtual Mac Paused");
 title.textColor=UIColor.whiteColor;title.textAlignment=NSTextAlignmentCenter;title.numberOfLines=0;
 title.font=[UIFont preferredFontForTextStyle:UIFontTextStyleTitle1];title.adjustsFontForContentSizeCategory=YES;
 UILabel *status=[[[UILabel alloc]init]autorelease];status.textColor=[UIColor.whiteColor colorWithAlphaComponent:.85];
 status.textAlignment=NSTextAlignmentCenter;status.numberOfLines=0;
 status.font=[UIFont preferredFontForTextStyle:UIFontTextStyleBody];status.adjustsFontForContentSizeCategory=YES;card.statusLabel=status;
 UIButton *resume=[UIButton buttonWithType:UIButtonTypeSystem];[resume setTitle:VZL(@"Resume") forState:UIControlStateNormal];
 resume.tintColor=UIColor.whiteColor;resume.backgroundColor=[UIColor colorWithWhite:1 alpha:.2];resume.layer.cornerRadius=14;
 resume.titleLabel.font=[UIFont preferredFontForTextStyle:UIFontTextStyleHeadline];
 resume.contentEdgeInsets=UIEdgeInsetsMake(14,28,14,28);card.resumeButton=resume;
 [resume addTarget:card action:@selector(resume:) forControlEvents:UIControlEventTouchUpInside];
 UIStackView *stack=[[[UIStackView alloc]initWithArrangedSubviews:@[icon,title,status,resume]]autorelease];
 stack.axis=UILayoutConstraintAxisVertical;stack.spacing=20;stack.translatesAutoresizingMaskIntoConstraints=NO;
 [card.contentView addSubview:stack];[controller.view addSubview:card];
 [NSLayoutConstraint activateConstraints:@[
  [card.leadingAnchor constraintEqualToAnchor:controller.view.leadingAnchor],
  [card.trailingAnchor constraintEqualToAnchor:controller.view.trailingAnchor],
  [card.topAnchor constraintEqualToAnchor:controller.view.topAnchor],
  [card.bottomAnchor constraintEqualToAnchor:controller.view.bottomAnchor],
  [stack.centerXAnchor constraintEqualToAnchor:card.contentView.centerXAnchor],
  [stack.centerYAnchor constraintEqualToAnchor:card.contentView.centerYAnchor],
  [stack.widthAnchor constraintLessThanOrEqualToConstant:440],
  [stack.leadingAnchor constraintGreaterThanOrEqualToAnchor:card.contentView.safeAreaLayoutGuide.leadingAnchor constant:24],
  [stack.trailingAnchor constraintLessThanOrEqualToAnchor:card.contentView.safeAreaLayoutGuide.trailingAnchor constant:-24]]];
 // Keep explicit VM controls accessible above the touch-blocking overlay.
 if(gHUDView.superview==controller.view)[controller.view bringSubviewToFront:gHUDView];
 [card refreshStatus];UIAccessibilityPostNotification(UIAccessibilityScreenChangedNotification,title);
 fprintf(stderr,"[VM27PauseOverlayV2] visible=1 fullScreenBlur=1 actualNativeState=2\n");
}
static void VM27LockRefreshPausedOverlayV2(void) {
 if(!pthread_main_np())return;
 BOOL paused=gVirtualMachine && ((NSInteger(*)(id,SEL))objc_msgSend)(gVirtualMachine,S("state"))==2;
 VM27LockShowPausedV1(paused);
}
static void VM27LockTransitionFinishedV1(id vm,uint64_t ticket,BOOL resume,NSInteger actual,BOOL verified) {
 VM27LockShowPausedV1(actual==2);
 if(VM27LockPolicyV1.owned && VM27LockOwnerV1==vm && VM27LockPolicyV1.ticket==ticket) {
  if(!verified || (resume && actual==1))VM27LockClearOwnerV1();
  if(!resume){VM27LockEndBackgroundV1();if(verified && actual==2)VM27LockMaybeResumeV1();}
 }
}
static void VM27LockMaybeResumeV1(void) {
 if(!gVirtualMachine)return;
 NSInteger state=((NSInteger(*)(id,SEL))objc_msgSend)(gVirtualMachine,S("state"));
 BOOL active=UIApplication.sharedApplication.applicationState==UIApplicationStateActive;
 if(VM27LockShouldResumeV1(&VM27LockPolicyV1,(uintptr_t)gVirtualMachine,active,state==2,
   gIndependent27VMStateTransitionPendingV44 || gIndependent27InputClosePending)) {
  VM27LockPolicyV1.ticket=gIndependent27VMStateEpochV44+1;VM27LockSubmittingV1=YES;
  BOOL accepted=VZIndependent27RequestVMStateV44(YES);VM27LockSubmittingV1=NO;
  fprintf(stderr,"[Independent27LockPauseV1] automaticResumeRequested=%u sameLockOwner=1\n",accepted);
 }
}
static void VM27LockTryPauseV1(uint64_t generation,unsigned retry) {
 if(generation!=VM27LockRetryGenerationV1 || !VM27LockPolicyV1.locked || !VM27LockPolicyV1.eligible ||
  !gVirtualMachine || gIndependent27OwnerClosePending)return;
 NSInteger state=((NSInteger(*)(id,SEL))objc_msgSend)(gVirtualMachine,S("state"));
 BOOL pending=gIndependent27VMStateTransitionPendingV44 || gIndependent27InputClosePending;
 if(VM27LockShouldPauseV1(&VM27LockPolicyV1,state==1,pending)) {
  [VM27LockOwnerV1 release];VM27LockOwnerV1=[gVirtualMachine retain];
  VM27LockPolicyV1.owned=true;VM27LockPolicyV1.owner=(uintptr_t)gVirtualMachine;
  VM27LockPolicyV1.ticket=gIndependent27VMStateEpochV44+1;VM27LockSubmittingV1=YES;
  BOOL accepted=VZIndependent27RequestVMStateV44(NO);VM27LockSubmittingV1=NO;
  if(!accepted)VM27LockClearOwnerV1();
  fprintf(stderr,"[Independent27LockPauseV1] lockPauseRequested=%u retry=%u autoResume=%u\n",accepted,retry,VM27LockPolicyV1.autoResume);
  if(accepted)return;
 }
 if(state==1 && retry<40)dispatch_after(dispatch_time(DISPATCH_TIME_NOW,50*NSEC_PER_MSEC),dispatch_get_main_queue(),^{VM27LockTryPauseV1(generation,retry+1);});
 else VM27LockEndBackgroundV1();
}
static void VM27LockObserveV1(void) {
 if(!pthread_main_np() || VM27LockNotifyTokenV1<0)return;
 uint64_t value=UINT64_MAX;if(notify_get_state(VM27LockNotifyTokenV1,&value)!=NOTIFY_STATUS_OK || value>1)return;
 BOOL wasLocked=VM27LockPolicyV1.locked;VM27LockPolicyV1.locked=value!=0;
 if(VM27LockObserveLogsV1++<64)fprintf(stderr,"[Independent27LockPauseV1] deviceLocked=%u eligible=%u active=%u nativeNotifyState=%llu\n",VM27LockPolicyV1.locked,VM27LockPolicyV1.eligible,UIApplication.sharedApplication.applicationState==UIApplicationStateActive,(unsigned long long)value);
 if(VM27LockPolicyV1.locked) {
  if(UIApplication.sharedApplication.applicationState==UIApplicationStateActive && gVirtualMachine)VM27LockPolicyV1.eligible=true;
  if(!wasLocked && VM27LockPolicyV1.eligible) {
   if(VM27LockBackgroundTaskV1==UIBackgroundTaskInvalid)VM27LockBackgroundTaskV1=[UIApplication.sharedApplication beginBackgroundTaskWithName:@"Pause Virtual Mac on lock" expirationHandler:^{VM27LockEndBackgroundV1();}];
   VM27LockTryPauseV1(++VM27LockRetryGenerationV1,0);
  }
 } else {++VM27LockRetryGenerationV1;VM27LockMaybeResumeV1();}
}
static void VM27LockWillResignV1(BOOL visible) {
 ++VM27LockForegroundEpochV4;
 if(!VM27LockPolicyV1.locked)VM27LockPolicyV1.eligible=visible;
 // Keep the process awake across the UIKit -> SpringBoard lock-notification gap.
 if(visible && gVirtualMachine && ((NSInteger(*)(id,SEL))objc_msgSend)(gVirtualMachine,S("state"))==1 && VM27LockBackgroundTaskV1==UIBackgroundTaskInvalid)
  VM27LockBackgroundTaskV1=[UIApplication.sharedApplication beginBackgroundTaskWithName:@"Observe Virtual Mac lock transition" expirationHandler:^{VM27LockEndBackgroundV1();}];
 VM27LockObserveV1();
}
static void VM27LockDidBackgroundV1(void) {
 VM27LockObserveV1();
 uint64_t epoch=++VM27LockForegroundEpochV4;
 // The actual lockstate can arrive after didEnterBackground. Retain only this
 // brief foreground-transition latch; an ordinary backgrounded VM stays running.
 dispatch_after(dispatch_time(DISPATCH_TIME_NOW,750*NSEC_PER_MSEC),dispatch_get_main_queue(),^{
  if(epoch==VM27LockForegroundEpochV4 && !VM27LockPolicyV1.locked && UIApplication.sharedApplication.applicationState==UIApplicationStateBackground) {
   VM27LockPolicyV1.eligible=false;VM27LockEndBackgroundV1();
  }
 });
}
static void VM27LockBecameActiveV1(void) {
 ++VM27LockForegroundEpochV4;VM27LockObserveV1();
 if(!VM27LockPolicyV1.locked && !gIndependent27VMStateTransitionPendingV44)VM27LockEndBackgroundV1();
 if(gVirtualMachine) {
  NSInteger state=((NSInteger(*)(id,SEL))objc_msgSend)(gVirtualMachine,S("state"));
  VM27LockShowPausedV1(state==2);VM27LockMaybeResumeV1();
 }
}
static void VM27LockResetV1(void) {
 ++VM27LockForegroundEpochV4;++VM27LockRetryGenerationV1;VM27LockPolicyV1.eligible=false;VM27LockClearOwnerV1();
 VM27LockEndBackgroundV1();VM27LockShowPausedV1(NO);
}
static void VM27LockInstallV1(void) {
 if(VM27LockInstalledV1)return;VM27LockInstalledV1=YES;
 VM27LockBackgroundTaskV1=UIBackgroundTaskInvalid;VM27LockTaskReadyV1=YES;
 int status=notify_register_dispatch("com.apple.springboard.lockstate",&VM27LockNotifyTokenV1,dispatch_get_main_queue(),^(int token){if(token==VM27LockNotifyTokenV1)VM27LockObserveV1();});
 fprintf(stderr,"[Independent27LockPauseV1] notificationRegistered=%u defaultAutoResume=0\n",status==NOTIFY_STATUS_OK);
 if(status==NOTIFY_STATUS_OK)VM27LockObserveV1();else VM27LockNotifyTokenV1=-1;
}
