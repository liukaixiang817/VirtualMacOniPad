#import <Foundation/Foundation.h>
/* Fixed own GUI LaunchAgent install using the existing exclusive QGA lease.
 * Completion on main. Pasteboard content never travels over QGA. */
void VM27ProvisionClipboardGuestV1(id vm, void (^completion)(BOOL));
