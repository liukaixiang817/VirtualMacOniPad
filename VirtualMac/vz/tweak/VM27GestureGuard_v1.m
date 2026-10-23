// The independent package owns this companion. It never intercepts keyboards
// or another App, and it restores native behavior on lock/background/exit.
#import <Foundation/Foundation.h>
#import <objc/message.h>
#import <objc/runtime.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static NSDictionary *settings;
static BOOL ready;
static IMP systemPublic, systemPrivate, fluidBegin, fluidTouch;
static const char *marker = "/tmp/virtual-mac-independent27-vm-active";
static void record(NSString *message) {
    NSLog(@"[VM27GestureGuardV1] %@", message);
    FILE *f=fopen("/tmp/vm27-gesture-guard.log","a");
    if(f){fprintf(f,"%s\n",message.UTF8String);fclose(f);}
}
static void reloadSettings(void) {
    NSDictionary *value=[NSDictionary dictionaryWithContentsOfFile:@"/var/mobile/Media/VirtualMac/Settings.plist"];
    [settings release];settings=[[value isKindOfClass:NSDictionary.class]?value:@{} copy];
}
static void settingsChanged(CFNotificationCenterRef c,void *o,CFStringRef n,const void *v,CFDictionaryRef u) {
    (void)c;(void)o;(void)n;(void)v;(void)u;
    dispatch_async(dispatch_get_main_queue(),^{reloadSettings();});
}
static BOOL optedIn(NSString *key) {
    id value=settings[key];
    return ([value isKindOfClass:NSNumber.class] || [value isKindOfClass:NSString.class]) && [value boolValue];
}
static BOOL liveMarker(void) {
    int fd=open(marker,O_RDONLY|O_NOFOLLOW|O_NONBLOCK);
    if(fd<0)return NO;
    struct stat st;char value[24]={0};
    BOOL valid=fstat(fd,&st)==0 && S_ISREG(st.st_mode) && st.st_uid==501 && st.st_size>1 && st.st_size<sizeof(value);
    ssize_t count=valid?read(fd,value,sizeof(value)-1):-1;close(fd);
    if(!valid || count!=st.st_size)return NO;
    char *end=NULL;long pid=strtol(value,&end,10);
    return pid>1 && pid<=INT_MAX && end && *end=='\n' && end[1]==0 && kill((pid_t)pid,0)==0;
}
static BOOL ownsGestures(void) {
    // Do not construct SpringBoard's switcher tree during launch. Unknown
    // private APIs or a missing state marker always leave system input alone.
    if(!ready || !NSThread.isMainThread || !liveMarker())return NO;
    @try {
        Class lock=objc_getClass("SBLockScreenManager");SEL shared=sel_registerName("sharedInstance");
        if(![lock respondsToSelector:shared])return NO;
        id manager=((id(*)(id,SEL))objc_msgSend)(lock,shared);
        SEL locked=sel_registerName("isUILocked");
        if(![manager respondsToSelector:locked] || ((BOOL(*)(id,SEL))objc_msgSend)(manager,locked))return NO;
        Class cls=objc_getClass("UIApplication");SEL appSelector=sel_registerName("sharedApplication");
        if(![cls respondsToSelector:appSelector])return NO;
        id app=((id(*)(id,SEL))objc_msgSend)(cls,appSelector);
        SEL front=sel_registerName("_accessibilityFrontMostApplication");
        if(![app respondsToSelector:front])return NO;
        id application=((id(*)(id,SEL))objc_msgSend)(app,front);
        SEL identity=sel_registerName("bundleIdentifier");
        if(![application respondsToSelector:identity])return NO;
        return [((id(*)(id,SEL))objc_msgSend)(application,identity) isEqualToString:@"com.mac.virtual.independent27"];
    } @catch(NSException *e) {return NO;}
}
static BOOL suppress(NSString *key) {
    BOOL value=optedIn(key) && ownsGestures();
    static unsigned receipts;
    if(value && receipts++<16)record([@"suppressed=" stringByAppendingString:key]);
    return value;
}
static BOOL systemGesture(id self,SEL cmd,unsigned long long type) {
    if(suppress(@"SystemGestureSuppression"))return NO;
    IMP prior=cmd==sel_registerName("_shouldEnableSystemGestureWithType:")?systemPrivate:systemPublic;
    return ((BOOL(*)(id,SEL,unsigned long long))prior)(self,cmd,type);
}
static BOOL beginGesture(id self,SEL cmd,id gesture) {
    if(suppress(@"MultitaskingGestureSuppression"))return NO;
    return ((BOOL(*)(id,SEL,id))fluidBegin)(self,cmd,gesture);
}
static BOOL touchGesture(id self,SEL cmd,id gesture,id touch) {
    if(suppress(@"MultitaskingGestureSuppression"))return NO;
    return ((BOOL(*)(id,SEL,id,id))fluidTouch)(self,cmd,gesture,touch);
}
static BOOL install(const char *name,const char *selector,IMP replacement,IMP *original,const char *arguments) {
    Class cls=objc_getClass(name);SEL sel=sel_registerName(selector);Method m=class_getInstanceMethod(cls,sel);
    if(!m)return NO;
    NSMethodSignature *sig=[NSMethodSignature signatureWithObjCTypes:method_getTypeEncoding(m)];
    if(sig.numberOfArguments!=strlen(arguments)+2 ||
       (strcmp(sig.methodReturnType,"B") && strcmp(sig.methodReturnType,"c")))return NO;
    for(NSUInteger i=0;i<strlen(arguments);++i)
        if(*[sig getArgumentTypeAtIndex:i+2]!=arguments[i])return NO;
    *original=method_getImplementation(m);
    // If inherited, add an override only to this class; do not mutate UIKit.
    if(!class_addMethod(cls,sel,replacement,method_getTypeEncoding(m)))
        *original=method_setImplementation(class_getInstanceMethod(cls,sel),replacement);
    return YES;
}
__attribute__((constructor)) static void start(void) {
    if(![NSBundle.mainBundle.bundleIdentifier isEqualToString:@"com.apple.springboard"])return;
    reloadSettings();
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),NULL,settingsChanged,
        CFSTR("com.mac.virtual.settings-changed"),NULL,CFNotificationSuspensionBehaviorDeliverImmediately);
    NSString **name=dlsym(RTLD_DEFAULT,"UIApplicationDidFinishLaunchingNotification");
    if(name && *name){static id observer;observer=[[NSNotificationCenter.defaultCenter addObserverForName:*name
        object:nil queue:NSOperationQueue.mainQueue usingBlock:^(NSNotification *note){
            ready=YES;record(@"launch-ready=1 foreground-and-unlocked-only=1");
        }]retain];}
    BOOL a=install("SBSystemGestureManager","shouldEnableSystemGestureWithType:",(IMP)systemGesture,&systemPublic,"Q");
    BOOL b=install("SBSystemGestureManager","_shouldEnableSystemGestureWithType:",(IMP)systemGesture,&systemPrivate,"Q");
    BOOL c=install("SBFluidSwitcherGestureManager","gestureRecognizerShouldBegin:",(IMP)beginGesture,&fluidBegin,"@");
    BOOL d=install("SBFluidSwitcherGestureManager","gestureRecognizer:shouldReceiveTouch:",(IMP)touchGesture,&fluidTouch,"@@");
    record([NSString stringWithFormat:@"installed public=%u private=%u multitasking=%u touch=%u",a,b,c,d]);
}
