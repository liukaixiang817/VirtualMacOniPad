/* macOS26B123 probes ID_AA64ISAR3_EL1 during early CPU discovery.
 * The existing virtual CPU profile exposes none of its newer extensions.
 * Architectural encoding: S3_0_C0_C6_3 (Arm Trusted Firmware arch.h).
 * Only a genuine AArch64 EL1 MRS is handled; MSR and other ELs retain their
 * existing exception path. The caller still owns all register/PC commits.
 */
static _Bool VM27IDAA64ISAR3MRSV1(uint32_t esr) {
    uint16_t identifier = (uint16_t)((((esr >> 20) & 3) << 14) |
        (((esr >> 14) & 7) << 11) | (((esr >> 10) & 15) << 7) |
        (((esr >> 1) & 15) << 3) | ((esr >> 17) & 7));
    return (esr >> 26) == 0x18 && (esr & (1u << 25)) && (esr & 1) && identifier == 0xc033;
}
static _Bool VM27IDAA64ISAR3PrepareV1(uint32_t esr, uint32_t pstate,
    VM27GICTrapResultV1 *out) {
    uint32_t mode = pstate & 31;
    if (!out || !VM27IDAA64ISAR3MRSV1(esr) || (mode != 4 && mode != 5)) return 0;
    *out = (VM27GICTrapResultV1){.handled = 1, .is64Bit = 1,
        .registerIndex = (esr >> 5) & 31, .bytes = 8, .readValue = 0};
    return 1;
}
