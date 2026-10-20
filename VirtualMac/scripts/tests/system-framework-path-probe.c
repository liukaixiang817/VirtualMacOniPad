/* Read cache membership and file metadata without loading any target image. */
#include <errno.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

static void json_string(const char *s) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) {
        if (*p == '"' || *p == '\\') putchar('\\');
        if (*p < 32) printf("\\u%04x", *p); else putchar(*p);
    }
    putchar('"');
}
int main(int argc, char **argv) {
    struct rlimit cpu = {3, 3}, core = {0, 0};
    if (setrlimit(RLIMIT_CPU, &cpu) || setrlimit(RLIMIT_CORE, &core)) return 78;
    alarm(8);
    if (argc < 2 || argc > 129) return 64;
    setbuf(stdout, NULL);
    printf("{\"record\":\"start\",\"PID\":%d,\"UID\":%u,\"dlopenCalls\":0,\"VMCalls\":0,\"GPUCalls\":0}\n", getpid(), getuid());
    for (int i = 1; i < argc; ++i) {
        const char *path = argv[i];
        if (strlen(path) > 4096 || path[0] != '/' || strstr(path, "/../")) return 64;
        struct stat st = {0}; errno = 0; int rc = stat(path, &st), saved = errno;
        int cache = _dyld_shared_cache_contains_path(path);
        printf("{\"record\":\"path\",\"path\":"); json_string(path);
        printf(",\"cacheContains\":%s,\"statReturn\":%d,\"statErrno\":%d,\"regularFile\":%s}\n",
               cache ? "true" : "false", rc, saved, rc == 0 && S_ISREG(st.st_mode) ? "true" : "false");
    }
    printf("{\"record\":\"summary\",\"paths\":%d,\"dlopenCalls\":0}\n", argc - 1);
    alarm(0);
    return 0;
}
