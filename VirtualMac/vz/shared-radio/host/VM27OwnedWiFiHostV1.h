#import <Foundation/Foundation.h>
@interface VM27OwnedWiFiHostV1 : NSObject
+ (BOOL)endpointPresent;
- (void)request:(NSDictionary *)request completion:(void (^)(NSDictionary *))completion;
- (void)invalidate;
@end
