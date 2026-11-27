#import <Foundation/Foundation.h>

// Local notification from this VM's existing root-agent connection. This is
// not a cross-process service, and exposes no arbitrary guest command.
extern NSString *const VM27RadioColdRestartNotificationV1;
void VM27RadioColdShutdownV1(NSString *bundle, NSString *request,
                            void (^completion)(BOOL success));
void VM27RadioRequestColdRestartV1(NSString *bundle, void (^completion)(BOOL success));
