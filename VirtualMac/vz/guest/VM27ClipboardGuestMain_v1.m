#import <AppKit/AppKit.h>
#import "VM27ClipboardGuest_v1.h"
int main(void) {
    @autoreleasepool {
        if(getuid()==0)return 77; /* Never enter the root pasteboard namespace. */
        NSApplication *app=NSApplication.sharedApplication;
        [app setActivationPolicy:NSApplicationActivationPolicyProhibited];
        VM27ClipboardGuestStart();[app run];VM27ClipboardGuestStop();
    }
    return 0;
}
