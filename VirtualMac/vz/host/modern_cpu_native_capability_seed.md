# Pure native capability seed conversion

This application-private module reproduces the successful initialized seed
branch of the pinned old Hypervisor510c..5288. It transforms exactly328 bytes
of explicit input and three explicit SDK predicate results into224 bytes of
typed feature/cache values. It does not acquire capabilities, call nativeop0
or dyld, construct an Apple object, install a CPU cache, or enable run.

Original op0 uses x0=0 and x1=global buffer1c060, and stores its status at1c058.
The352-byte global region establishes capacity, not the kernel's actual write
length. The packed tail is separate: GIC flag+148, unaligned64-bit getters
at+149 and+151. A padded KDK structure is not an exact ABI for this image.
This converter only reads+68..147 and never consumes or guesses that tail.

The original seed writes0xe0 continuous bytes at old per-CPU table+8..e7:
12 feature u64 values,64 instruction CCSIDR bytes and64 data/unified CCSIDR
bytes. Config-feature selectors10/11 swap the final two seed words; CCSIDR
selector0 reads the data/unified group and1 reads the instruction group.
The closed nine encoded SYS feature selectors are mapped to their exact seed
word indices. Unknown selectors preserve output. Original cache pointer+0,
pending-interrupt shadow+e8 (known low bits6/7) and exit/control fields+f0..117
are not produced here; their other bits and padding are separate contracts.

All three original SDK calls use token0x07e60901ffffffff. Their booleans are
explicit inputs in the original call order, including mixed permutations;
the module neither fabricates a program SDK version nor claims to have
observed those predicates. A future real acquisition path must provide the
actual successful kernel bytes and SDK results with its own receipt.

Diagnostics`native-capability-seed-contract-v1/audit.py` pins the original
image and interprets its integer, SIMD, stack and memory instructions in a
bounded pure model. It emits6688 golden records from836 prefixes and all8
SDK result combinations. Portable C tests compare every transformed byte and
all typed selectors against that independent original instruction model.
These are static/model results, not native acquisition or execution proof.
