#import <Foundation/Foundation.h>
#define VM27_CLIPBOARD_PORT 505051u
#define VM27_CLIPBOARD_MAX_BYTES (4u*1024u*1024u)
/* All methods and callbacks execute on the main queue. Owns its duplicate FD.
 * The only accepted encoding is a bounded binary property list, never an
 * object archive. Nothing from the pasteboard is written to disk or logs. */
@interface VM27ClipboardChannel : NSObject
@property(nonatomic,copy) void (^received)(NSDictionary *message);
@property(nonatomic,copy) void (^disconnected)(void);
- (instancetype)initWithOwnedDescriptor:(int)descriptor;
- (BOOL)send:(NSDictionary *)message;
- (void)close;
@end
NSArray<NSString *> *VM27ClipboardTypes(void);
BOOL VM27ClipboardValidateItems(id items);
