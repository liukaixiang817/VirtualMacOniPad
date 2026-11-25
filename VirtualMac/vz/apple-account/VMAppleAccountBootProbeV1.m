// Development-only observation of the genuine native VMApple mappings.
// This compilation retains the accepted bootstrap and does not alter guests.
// Appended to the frozen bootstrap30 unit by the probe builder, after its one
// public map definition has been renamed with hidden visibility. Freezing
// avoids overriding the nested map aliases in bootstrap25 through bootstrap28.

static unsigned AppleAccountMapCountV1;
static unsigned AppleAccountRunCountV1;
typedef struct {
    void *host;
    uint64_t ipa;
    size_t bytes;
} AppleAccountObservedMapV1;
static AppleAccountObservedMapV1 AppleAccountMapsV1[64];

hv_return_t hv_vm_map(void *host, hv_ipa_t ipa, size_t bytes, hv_memory_flags_t flags) {
    hv_return_t status = VMAppleAccountInheritedMapV1(host, ipa, bytes, flags);
    unsigned count = __atomic_fetch_add(&AppleAccountMapCountV1, 1, __ATOMIC_RELAXED);
    if (count < 64) {
        dprintf(2, "[AppleAccountBootProbeV1] map ordinal=%u GPA=0x%llx bytes=0x%zx flags=0x%llx status=0x%08x\n",
                count + 1, (unsigned long long)ipa, bytes, (unsigned long long)flags, (unsigned)status);
        if (!status) {
            Lock();
            AppleAccountMapsV1[count] = (AppleAccountObservedMapV1){host, ipa, bytes};
            Unlock();
        }
    }
    return status;
}

__attribute__((visibility("hidden"))) void VMAppleAccountBeforeRunProbeV1(void) {
    unsigned count = __atomic_load_n(&AppleAccountRunCountV1, __ATOMIC_RELAXED);
    if (count >= 8) return;
    count = __atomic_fetch_add(&AppleAccountRunCountV1, 1, __ATOMIC_RELAXED);
    if (count >= 8) return;
    Lock();
    for (unsigned i = 0; i < 64; ++i) {
        AppleAccountObservedMapV1 m = AppleAccountMapsV1[i];
        if (!m.host || m.bytes < 0x600 || m.ipa >= 0x80000000) continue;
        // Only structure headers are observed; never emit serials, credentials,
        // guest RAM, device keys, or account-service response bytes.
        uint32_t fields[4] = {0};
        memcpy(fields, m.host, sizeof(fields));
        dprintf(2, "[AppleAccountBootProbeV1] pre-run=%u GPA=0x%llx header=%08x,%08x,%08x,%08x\n",
                count + 1, (unsigned long long)m.ipa, fields[0], fields[1], fields[2], fields[3]);
    }
    Unlock();
}
