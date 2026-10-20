/* Ordinary process-start control: only libSystem, no VM or private providers. */
#include <signal.h>
#include <sys/resource.h>
#include <unistd.h>

int main(void) {
    static const char started[] = "ORDINARY_STARTUP_MAIN\n";
    static const char passed[] = "ORDINARY_STARTUP_LIMITS_OK\n";
    struct rlimit cpu_limit, core_limit;
    if (write(STDOUT_FILENO, started, sizeof(started) - 1) != sizeof(started) - 1)
        return 71;
    alarm(15);
    if (getrlimit(RLIMIT_CPU, &cpu_limit) != 0 || cpu_limit.rlim_cur != 5)
        return 72;
    if (getrlimit(RLIMIT_CORE, &core_limit) != 0 || core_limit.rlim_cur != 0)
        return 73;
    if (write(STDOUT_FILENO, passed, sizeof(passed) - 1) != sizeof(passed) - 1)
        return 74;
    return 0;
}
