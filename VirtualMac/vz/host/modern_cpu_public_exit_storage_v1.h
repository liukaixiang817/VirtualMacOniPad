#ifndef VM27_PUBLIC_EXIT_STORAGE_V1_H
#define VM27_PUBLIC_EXIT_STORAGE_V1_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

// Portable own mock contract. IDs/epochs are own identities, not Apple IDs,
// kernel returned slots or a claim about native guest exits. All raw bytes are
// opaque; this component has no guest Run, native syscall or framework import.
enum { VM27_EXIT_STORAGE_BYTES_V1 = 32 };
typedef struct vm27_exit_owner_v1 vm27_exit_owner_v1;
typedef struct vm27_exit_borrow_v1 vm27_exit_borrow_v1;
typedef enum {
    VM27_EXIT_OK_V1 = 0,
    VM27_EXIT_BAD_ARGUMENT_V1,
    VM27_EXIT_WRONG_THREAD_V1,
    VM27_EXIT_BUSY_V1,
    VM27_EXIT_NOT_LIVE_V1,
    VM27_EXIT_OUT_OF_MEMORY_V1,
    VM27_EXIT_MOCK_FAILURE_V1,
    VM27_EXIT_ID_EXHAUSTED_V1
} vm27_exit_status_v1;
typedef int (*vm27_exit_mock_callback_v1)(void *context);
typedef struct {
    uint32_t schema_version; // Exactly 1; callback is exclusively a mock model.
    vm27_exit_mock_callback_v1 complete_mock_create;
    vm27_exit_mock_callback_v1 complete_mock_destroy;
    void *context;
} vm27_exit_mock_ops_v1;
typedef struct {
    uint64_t owner_epoch;
    uint64_t owner_generation;
    size_t published;
    size_t retained_borrows;
    size_t persistent_storage;
    size_t destroyed_tombstones;
} vm27_exit_stats_v1;

// One live own owner per actual pthread/private TLS. Nonzero own epoch is
// immutable; an independent process-monotonic generation also seals it.
// All output arguments remain byte-for-byte unchanged on any refusal.
// Callbacks must return normally and owner must close before its pthread exits;
// cancellation/longjmp and abandoned-owner adoption are outside this contract.
vm27_exit_status_v1 vm27_exit_owner_create_v1(uint64_t epoch,
    const vm27_exit_mock_ops_v1 *, vm27_exit_owner_v1 **out_owner);
// Refuses published entries or any retained borrow. Successful close removes
// TLS/registry membership and frees dead entries. Closed pointers are invalid C.
vm27_exit_status_v1 vm27_exit_owner_close_v1(vm27_exit_owner_v1 *, uint64_t epoch);

// Allocates persistent zeroed32B storage before the callback. No publication
// or caller output occurs until mock create returns0. Failed attempts consume
// an own ID reservation but free storage and leave outputs unchanged. The
// successful pointer is stable until successful destroy; only owner may use
// it. Raw-pointer use must finish before destroy and never cross threads.
vm27_exit_status_v1 vm27_exit_create_v1(vm27_exit_owner_v1 *, uint64_t epoch,
    uint64_t *out_identity, const unsigned char **out_storage);

// Registry lookup precedes dereferencing caller handles. Acquisition may occur
// on any pthread and retains allocation. A borrow belongs to its acquiring
// actual pthread. View additionally requires actual owner/TLS/epoch/generation.
// Borrow is a lifetime reference only, not a native operation/Run lease.
// Released handles remain refusing tombstones until owner close; handles become
// invalid C pointers after owner close and must never be used thereafter.
vm27_exit_status_v1 vm27_exit_borrow_v1_acquire(vm27_exit_owner_v1 *, uint64_t epoch,
    uint64_t identity, vm27_exit_borrow_v1 **out_borrow);
vm27_exit_status_v1 vm27_exit_borrow_v1_view(vm27_exit_borrow_v1 *,
    const unsigned char **out_storage);
vm27_exit_status_v1 vm27_exit_borrow_v1_release(vm27_exit_borrow_v1 *);

// Only a live owner's admitted mock-success status0 may copy exactly32 external
// opaque bytes. Failure status, unknown/stale ID, foreign/TLS mismatch, epoch
// mismatch, size31/33 and private-memory aliases refuse without reading input
// bytes or mutating storage. This is not native exit layout translation.
vm27_exit_status_v1 vm27_exit_update_mock_success_v1(vm27_exit_owner_v1 *,
    uint64_t epoch, uint64_t identity, int mock_status,
    const void *raw_bytes, size_t byte_count);

// Any outstanding borrow returnsBUSY before callback and leaves published.
// Callback runs outside the registry lock with owner admission held. Mock
// failure preserves lookup/storage; success unpublishes, drains (zero borrows),
// then frees storage. Dead ID tombstone prevents stale lookup/republication.
// This transaction differs from native-bearing lifecycle v5 early-unpublish.
vm27_exit_status_v1 vm27_exit_destroy_v1(vm27_exit_owner_v1 *, uint64_t epoch,
    uint64_t identity);
vm27_exit_status_v1 vm27_exit_owner_stats_v1(vm27_exit_owner_v1 *, uint64_t epoch,
    vm27_exit_stats_v1 *out_stats);
#ifdef __cplusplus
}
#endif
#endif
