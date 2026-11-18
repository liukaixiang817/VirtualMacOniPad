#import <Foundation/Foundation.h>

// /dev/console can already name the new owner while Setup User still owns
// the visible session. A password alert in the owner's background session
// cannot be seen. Use the actual SystemConfiguration session readback.
static inline BOOL VM27RadioConsoleSessionReadyV1(NSDictionary *console, uid_t uid, BOOL visible) {
    id rows=console[@"SessionInfo"];
    if(![rows isKindOfClass:NSArray.class]||[rows count]>32||uid<500)return NO;
    for(id row in rows) {
        if(![row isKindOfClass:NSDictionary.class]||
           ![row[@"kCGSSessionUserIDKey"] isEqual:@(uid)]||
           ![row[@"kCGSessionLoginDoneKey"] isEqual:@YES])continue;
        if(!visible||[row[@"kCGSSessionOnConsoleKey"] isEqual:@YES])return YES;
    }
    return NO;
}
static inline BOOL VM27RadioSetupHandoffPendingV1(NSDictionary *console, uid_t uid) {
    if(!VM27RadioConsoleSessionReadyV1(console,uid,NO)||VM27RadioConsoleSessionReadyV1(console,uid,YES))return NO;
    for(id row in console[@"SessionInfo"])
        if([row isKindOfClass:NSDictionary.class]&&
           [row[@"kCGSSessionUserNameKey"] isEqual:@"_mbsetupuser"]&&
           [row[@"kCGSSessionOnConsoleKey"] isEqual:@YES])return YES;
    return NO;
}

// Observed on a fresh 26A5416b restore: setup has exited, the completed owner
// is in the background, and an unfinished root/loginwindow session remains
// visible. This is eligible only when the coordinator saw Setup Assistant in
// this same boot and has never seen the owner visible. An ordinary lock or
// fast user switch must not become an automatic restart.
static inline BOOL VM27RadioInitialRootHandoffPendingV2(NSDictionary *console, uid_t uid,
                                                       BOOL setupSeenThisBoot,
                                                       BOOL ownerSeenVisibleThisBoot) {
    if(!setupSeenThisBoot || ownerSeenVisibleThisBoot ||
       ![console[@"UID"] isEqual:@0] || ![console[@"Name"] isEqual:@"loginwindow"] ||
       !VM27RadioConsoleSessionReadyV1(console,uid,NO) ||
       VM27RadioConsoleSessionReadyV1(console,uid,YES))return NO;
    NSUInteger visible=0;BOOL unfinishedRoot=NO;
    for(id row in console[@"SessionInfo"]) {
        if(![row isKindOfClass:NSDictionary.class])return NO;
        if(![row[@"kCGSSessionOnConsoleKey"] isEqual:@YES])continue;
        visible++;
        unfinishedRoot=[row[@"kCGSSessionUserIDKey"] isEqual:@0] &&
            [row[@"kCGSSessionUserNameKey"] isEqual:@"root"] &&
            [row[@"kCGSessionLoginDoneKey"] isEqual:@NO];
    }
    return visible==1 && unfinishedRoot;
}
