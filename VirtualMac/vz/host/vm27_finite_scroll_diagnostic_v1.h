#import <Foundation/Foundation.h>
/* Include after the caller's existing versioned surface declaration. */
/* Development-only, finite own packet injection. This does not construct
 * UIKit hardware events and does not establish physical trackpad acceptance. */
@interface VM27UIKitInputSurfaceV2 (VM27FiniteScrollDiagnosticV1)
- (BOOL)vm27_beginFiniteScrollDiagnosticV1:(BOOL)legacyUncoalesced;
- (void)vm27_cancelFiniteScrollDiagnosticV1;
@end
