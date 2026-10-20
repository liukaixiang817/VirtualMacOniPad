/* HOST fixtures only: execute the exact production core with explicit native
 * and eligibility callbacks; no iPad native query or deployment is performed. */
#include "vm27_owned_vz_cache_confstr_v1.c"
#include <assert.h>

static unsigned checks, nativeCalls, eligibilityCalls, directoryCalls;
static int expectedName, nativeError, directoryError;
static size_t nativeResult;
static bool eligibility, directoryValid;
static size_t FixtureNative(int name, char *buffer, size_t capacity) {
    ++nativeCalls; assert(name == expectedName);
    if (nativeResult && buffer && capacity) buffer[0] = 'N';
    errno = nativeError; return nativeResult;
}
static bool FixtureEligibility(void *caller) {
    ++eligibilityCalls; assert(caller == (void *)(uintptr_t)7);
    errno = EBADF; return eligibility;
}
static bool FixtureDirectory(void) {
    ++directoryCalls; errno = directoryError; return directoryValid;
}
static void ResetFixture(int name) {
    expectedName = name; nativeCalls = eligibilityCalls = directoryCalls = 0;
    nativeResult = 0; nativeError = EIO; eligibility = directoryValid = true;
    directoryError = 0; errno = EDOM;
}
static size_t RunFixture(int name, char *buffer, size_t capacity) {
    return CacheCoreV1(name, buffer, capacity, FixtureNative,
        FixtureEligibility, (void *)(uintptr_t)7, FixtureDirectory);
}
#define CHECK(expression) do { assert(expression); ++checks; } while (0)

int main(void) {
    const size_t required = sizeof(VM27_CACHE_PATH);
    ResetFixture(_CS_DARWIN_USER_CACHE_DIR);
    CHECK(RunFixture(expectedName, NULL, 0) == required);
    CHECK(errno == EDOM && nativeCalls == 1 && eligibilityCalls == 1 && directoryCalls == 1);
    ResetFixture(_CS_DARWIN_USER_CACHE_DIR);
    CHECK(RunFixture(expectedName, NULL, 4096) == required && errno == EDOM);
    char buffer[4096]; memset(buffer, 'Q', sizeof(buffer));
    ResetFixture(_CS_DARWIN_USER_CACHE_DIR);
    CHECK(RunFixture(expectedName, buffer, 0) == required && buffer[0] == 'Q');
    CHECK(errno == EDOM);
    ResetFixture(_CS_DARWIN_USER_CACHE_DIR);
    CHECK(RunFixture(expectedName, buffer, 1) == required && buffer[0] == '\0' && buffer[1] == 'Q');
    ResetFixture(_CS_DARWIN_USER_CACHE_DIR); memset(buffer, 'Q', sizeof(buffer));
    CHECK(RunFixture(expectedName, buffer, 2) == required && buffer[0] == '/' && buffer[1] == '\0' && buffer[2] == 'Q');
    ResetFixture(_CS_DARWIN_USER_CACHE_DIR); memset(buffer, 'Q', sizeof(buffer));
    CHECK(RunFixture(expectedName, buffer, required-1) == required);
    CHECK(!memcmp(buffer, VM27_CACHE_PATH, required-2) && buffer[required-2] == '\0' && buffer[required-1] == 'Q');
    ResetFixture(_CS_DARWIN_USER_CACHE_DIR); memset(buffer, 'Q', sizeof(buffer));
    CHECK(RunFixture(expectedName, buffer, required) == required && !strcmp(buffer, VM27_CACHE_PATH));
    CHECK(buffer[required] == 'Q' && errno == EDOM);
    ResetFixture(_CS_DARWIN_USER_CACHE_DIR); memset(buffer, 'Q', sizeof(buffer));
    CHECK(RunFixture(expectedName, buffer, SIZE_MAX) == required && !strcmp(buffer, VM27_CACHE_PATH));
    CHECK(buffer[required] == 'Q' && errno == EDOM);
    ResetFixture(_CS_DARWIN_USER_CACHE_DIR); nativeResult = 71; nativeError = ENOTTY;
    CHECK(RunFixture(expectedName, buffer, sizeof(buffer)) == 71 && buffer[0] == 'N');
    CHECK(errno == ENOTTY && nativeCalls == 1 && !eligibilityCalls && !directoryCalls);
    ResetFixture(_CS_DARWIN_USER_TEMP_DIR);
    CHECK(RunFixture(expectedName, buffer, sizeof(buffer)) == 0 && errno == EIO);
    CHECK(!eligibilityCalls && !directoryCalls);
    ResetFixture(_CS_PATH); nativeResult = 8; nativeError = ENOTTY;
    CHECK(RunFixture(expectedName, buffer, sizeof(buffer)) == 8 && errno == ENOTTY && buffer[0] == 'N');
    CHECK(!eligibilityCalls && !directoryCalls);
    ResetFixture(_CS_DARWIN_USER_CACHE_DIR); eligibility = false;
    CHECK(RunFixture(expectedName, buffer, sizeof(buffer)) == 0 && errno == EIO);
    CHECK(eligibilityCalls == 1 && !directoryCalls);
    ResetFixture(_CS_DARWIN_USER_CACHE_DIR); directoryValid = false; directoryError = ENOENT;
    CHECK(RunFixture(expectedName, buffer, sizeof(buffer)) == 0 && errno == ENOENT);
    ResetFixture(_CS_DARWIN_USER_CACHE_DIR); directoryValid = false; directoryError = 0;
    CHECK(RunFixture(expectedName, buffer, sizeof(buffer)) == 0 && errno == EACCES);

    /* These are genuine HOST filesystem checks of the production no-follow
     * helper; the HOST group differs from iPad501 and is never forged. */
    char temporary[] = "/private/tmp/vm27-cache-fixture-XXXXXX";
    CHECK(mkdtemp(temporary) != NULL && chmod(temporary, 0700) == 0);
    int fd = open(temporary, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    CHECK(fd >= 0 && CacheDirectoryStatV1(fd, getuid(), false));
    CHECK(!CacheDirectoryStatV1(fd, getuid()+1, false) && errno == EACCES);
    CHECK(fchmod(fd, 0777) == 0 && !CacheDirectoryStatV1(fd, getuid(), false) && errno == EACCES);
    CHECK(fchmod(fd, 0700) == 0);
    CHECK(symlinkat(temporary, fd, "link") == 0);
    int owned = dup(fd);
    CHECK(owned >= 0 && !CacheOpenCheckedComponentV1(&owned, "link", getuid(), false));
    CHECK(owned == -1 && (errno == ELOOP || errno == ENOTDIR));
    CHECK(unlinkat(fd, "link", 0) == 0 && close(fd) == 0 && rmdir(temporary) == 0);
    printf("{\"actualHostFixtureChecks\":%u,\"deviceOperations\":0,\"nativeConfstrQueriesMockedExplicitly\":true,\"actualProductionCacheDirectoryVerified\":false}\n", checks);
    return 0;
}
