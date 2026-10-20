#ifndef VM27_ARRAY_FIXTURE_IDENTITY_H
#define VM27_ARRAY_FIXTURE_IDENTITY_H
#ifdef __cplusplus
extern "C" {
#endif
// Read-only identity gate; no Swift entry is invoked here. Returns eight only
// when every exact private export belongs to the pinned loaded provider.
int VM27ArrayProviderIdentity(void);
#ifdef __cplusplus
}
#endif
#endif
