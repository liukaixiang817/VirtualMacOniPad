The original iPadOS-compatible Hypervisor wrappers at RVA `4b5c..4c94`
encode five consecutive 64-bit words: host address, guest IPA, size, flags,
and space word. Native operations 3/4/5 are map/unmap/protect. Unmap zeroes
the host address and flags; protect zeroes the host address. Public wrappers
use space zero. The private space wrappers carry the caller's actual word.

This module encodes only default-space, 16KiB-aligned ranges within the
previously validated 36-bit profile. It neither loads the old framework nor
executes a native operation. It checks overflow and preserves output after
invalid input. Native users must separately establish their own VM and host
memory ownership, keep memory alive while mapped, and observe real cleanup.

The initial isolated native fixture maps one owned anonymous 16KiB host
page at guest IPA `0x40000000` with READ|WRITE, changes guest permission to
READ, restores READ|WRITE, then unmaps and destroys the owned VM. It creates
no CPU and executes no guest instructions. Success does not prove guest
loads/stores, executable mappings, private spaces, full RAM or original VMM
integration. It does not modify the production lifecycle's native1 admission.
