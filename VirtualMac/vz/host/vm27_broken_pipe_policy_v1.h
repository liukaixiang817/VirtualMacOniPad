#ifndef VM27_BROKEN_PIPE_POLICY_V1_H
#define VM27_BROKEN_PIPE_POLICY_V1_H

#include <signal.h>

/* A disconnected optional byte stream must return EPIPE to its existing
 * owner, rather than terminate UIKit and every device owned by the VM.
 * SO_NOSIGPIPE on our sockets does not cover pipes or framework-owned FDs.
 * Install before UIKit starts threads; leave all other signals untouched. */
static inline int vm27_install_broken_pipe_policy_v1(void)
{
    struct sigaction action = {0};
    action.sa_handler = SIG_IGN;
    if (sigemptyset(&action.sa_mask) != 0)
        return -1;
    return sigaction(SIGPIPE, &action, NULL);
}

#endif
