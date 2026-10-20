#ifndef VM27_SCOPED_SOFTLINKING_H
#define VM27_SCOPED_SOFTLINKING_H
/* Observed two-pointer register ABI. paths must be a valid non-null,
 * NULL-terminated array. This application-private candidate is certified only
 * for absolute paths, not loader/caller-relative names or allocation failure.
 * Success leaves *errorString unchanged; failure transfers a malloc string.
 */
void *_sl_dlopen(const char *const paths[], char **errorString);
#endif
