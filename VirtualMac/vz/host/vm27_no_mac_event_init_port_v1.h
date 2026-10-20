#ifndef VM27_NO_MAC_EVENT_INIT_PORT_V1_H
#define VM27_NO_MAC_EVENT_INIT_PORT_V1_H
#import <Foundation/Foundation.h>
/* Exact ObjC initializer register ABI: consumed +1 self, selector, borrowed
 * event. This explicit independent-UIKit profile port releases the allocated
 * self before raising Unsupported. The actual six-argument VZ scroll
 * initializer and sender remain the owned UIKit receiver's genuine path. */
_Noreturn void VM27NoMacEventV1(__attribute__((ns_consumed)) id ownedSelf,
    SEL command, __unsafe_unretained id borrowedEvent);
#endif
