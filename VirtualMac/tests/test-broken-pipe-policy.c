#include "../vz/host/vm27_broken_pipe_policy_v2.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static void disconnected_writer(int socket_stream, int protected)
{
    alarm(2);
    struct sigaction original_term, current_term;
    assert(sigaction(SIGTERM, NULL, &original_term) == 0);
    assert(signal(SIGPIPE, SIG_DFL) != SIG_ERR);
    if (protected)
        assert(vm27_install_broken_pipe_policy_v2() == 0);
    int descriptors[2];
    if (socket_stream)
        assert(socketpair(AF_UNIX, SOCK_STREAM, 0, descriptors) == 0);
    else
        assert(pipe(descriptors) == 0);
    close(descriptors[0]);
    errno = 0;
    ssize_t result = write(descriptors[1], "x", 1);
    assert(protected && result == -1 && errno == EPIPE);
    assert(sigaction(SIGTERM, NULL, &current_term) == 0);
    assert(original_term.sa_handler == current_term.sa_handler);
    close(descriptors[1]);
    _exit(0);
}

int main(void)
{
    for (int socket_stream = 0; socket_stream < 2; socket_stream++) {
        for (int protected = 0; protected < 2; protected++) {
            pid_t child = fork();
            assert(child >= 0);
            if (child == 0)
                disconnected_writer(socket_stream, protected);
            int status;
            assert(waitpid(child, &status, 0) == child);
            if (protected)
                assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
            else
                assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGPIPE);
        }
    }
    puts("Closed pipe and socket return EPIPE; default controls die with SIGPIPE; SIGTERM unchanged.");
    return 0;
}
