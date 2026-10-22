#import <Foundation/Foundation.h>
/* Main VM queue only; independent macOS27 runtime. No external TCP port. */
@interface VM27ClipboardBridge : NSObject
+ (instancetype)attachToVM:(id)vm expectedImage:(NSString *)path error:(NSError **)error;
- (void)setSuspended:(BOOL)suspended;
- (void)close;
@end
