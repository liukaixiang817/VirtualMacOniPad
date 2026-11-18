#import <Foundation/Foundation.h>
#import "VM27CameraFrame.h"

NS_ASSUME_NONNULL_BEGIN

@interface VM27HostCamera : NSObject
- (instancetype)initWithVirtualMachine:(id)virtualMachine profile:(VM27CameraProfile)profile;
@property(nonatomic, readonly) BOOL sharingRequested;
@property(nonatomic) VM27CameraProfile profile;
@property(nonatomic, getter=isFrontCamera) BOOL frontCamera;
@property(nonatomic) BOOL mirrored;
- (void)requestSharing:(BOOL)enabled completion:(void (^)(BOOL))completion;
// Main-queue lifecycle. Turning eligibility off stops media immediately.
- (void)setEligible:(BOOL)eligible;
- (void)invalidate;
@end

NS_ASSUME_NONNULL_END
