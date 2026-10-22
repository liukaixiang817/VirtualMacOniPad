#import <Foundation/Foundation.h>
#define VM27TrackpadThreeFingerGesturesKey @"TrackpadThreeFingerGesturesEnabled"
#define VM27TrackpadFourFingerGesturesKey @"TrackpadFourFingerGesturesEnabled"
NS_INLINE BOOL VM27TrackpadGestureOptionV1(NSDictionary *options, NSString *key) {
    id value=options[key];
    return value==nil || ([value isKindOfClass:NSNumber.class] && [value boolValue]);
}
@protocol VM27TrackpadGestureConfigurationV1 <NSObject>
/* Main thread, before a new session starts. Options belong to this VM only. */
- (BOOL)vm27_configureThreeFingerV1:(BOOL)three fourFinger:(BOOL)four;
@end
