// Mach-O absolute ABI export, not a pointer to a data allocation.
// Exact original Swift nlist: N_ABS|N_EXT, value 0x80000004ffffffff.
// InlineRefCountBits::immortalBits(): (2 << 33) | 0xffffffff | (1 << 63).
// Discovery must use the symbol value; never dereference it as an address.
.globl __swiftImmortalRefCount
.set __swiftImmortalRefCount, 0x80000004ffffffff
