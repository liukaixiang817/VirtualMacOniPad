#!/usr/bin/env python3
"""Prepare one inert VMM restore block using the genuine public SYS stub.

No signing, loading, native hypervisor call or device operation is performed.
The remaining modern context accesses need their own port before execution.
"""
from pathlib import Path
import hashlib
import json
import runpy
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
D = N / 'original27-mdccint-restore-source-port-data-v1'
BEGIN, END, STUB, FATAL = 0x28b1ac, 0x28b1e4, 0x412e64, 0x28cb8c


def require(ok, message):
    if not ok:
        raise ValueError(message)


def pin(path):
    path = Path(path).resolve()
    require(path.is_file() and not path.is_symlink(), 'regular input')
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def signed(value, bits):
    return value - (1 << bits) if value & (1 << (bits - 1)) else value


def target(word, at):
    if word & 0x7c000000 == 0x14000000:
        return at + 4 * signed(word & 0x3ffffff, 26)
    if word & 0xff000010 == 0x54000000 or word & 0x7e000000 == 0x34000000:
        return at + 4 * signed((word >> 5) & 0x7ffff, 19)
    if word & 0x7e000000 == 0x36000000:
        return at + 4 * signed((word >> 5) & 0x3fff, 14)
    return None


def direct_interior_entries(image):
    external, internal = [], []
    for section in image.sections:
        if not section['flags'] & 0x80000400:
            continue
        require(section['bytes'] % 4 == 0, 'complete instruction section')
        for offset in range(0, section['bytes'], 4):
            at = section['va'] - image.base + offset
            word = struct.unpack('<I', image.raw(at, 4))[0]
            to = target(word, at)
            if to is not None and BEGIN < to < END:
                row = dict(sourceRVA=at, targetRVA=to, word=word)
                (internal if BEGIN <= at < END else external).append(row)
    require(not external, 'external direct entry into skipped block')
    require(internal == [dict(sourceRVA=0x28b1c0, targetRVA=0x28b1d4, word=0x370800a8)],
        'sole original block internal conditional')
    return dict(external=external, internal=internal)


def rebase_interior_entries(image):
    offset, size = image.fix
    chain = image.b[offset:offset + size]
    starts = struct.unpack_from('<I', chain, 4)[0]
    count = struct.unpack_from('<I', chain, starts)[0]
    require(count == len(image.segments), 'all chained segments')
    interior, rebases, binds, words = [], 0, 0, 0
    for index, segment in enumerate(image.segments):
        relative = struct.unpack_from('<I', chain, starts + 4 + index * 4)[0]
        if not relative:
            continue
        start = starts + relative
        length, page, fmt, segoff, maximum, pages = struct.unpack_from('<IHHQIH', chain, start)
        require(fmt == 12 and maximum == 0 and length == 22 + pages * 2 and page == 16384,
            'actual USERLAND24 runtime-offset format')
        require(segoff == segment['va'] - image.base, 'segment join')
        for page_index in range(pages):
            first = struct.unpack_from('<H', chain, start + 22 + page_index * 2)[0]
            if first == 0xffff:
                continue
            require(first < page, 'single actual page start')
            at, seen = segoff + page_index * page + first, set()
            while True:
                require(at not in seen and segoff + page_index * page <= at and
                    at + 8 <= segoff + (page_index + 1) * page, 'bounded complete chain')
                seen.add(at)
                word = struct.unpack('<Q', image.raw(at, 8))[0]
                words += 1
                auth, bind, following = bool(word >> 63), bool(word & (1 << 62)), (word >> 51) & 0x7ff
                if bind:
                    binds += 1
                    require(at in image.binds, 'parser bind word join')
                else:
                    rebases += 1
                    low = word & (0xffffffff if auth else (1 << 43) - 1)
                    # Format12 stores VM offsets for both authenticated and
                    # unauthenticated targets. Strip a top-byte tag for range comparison.
                    destination = image.base + low
                    if image.base + BEGIN < destination < image.base + END:
                        interior.append(dict(slotRVA=at, targetVA=destination, word=word, authenticated=auth))
                if not following:
                    break
                at += following * 8
    require(binds == len(image.binds) and not interior, 'all binds and no chained interior rebase')
    return dict(words=words, binds=binds, rebases=rebases, interior=interior,
        formats=[12], genericIndirectInteriorEntrypointExhaustivelyProven=False)


def object_text(data):
    require(struct.unpack_from('<I', data)[0] == 0xfeedfacf, 'assembler MachO')
    at, found = 32, []
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        command, size = struct.unpack_from('<II', data, at)
        if command == 0x19:
            for index in range(struct.unpack_from('<I', data, at + 64)[0]):
                section = at + 72 + 80 * index
                if data[section:section + 16].split(b'\0')[0] == b'__text':
                    length, offset = struct.unpack_from('<QI', data, section + 40)
                    found.append(data[offset:offset + length])
        at += size
    require(len(found) == 1, 'one compiled block')
    return found[0]


def semantic_checks(code):
    words = struct.unpack('<5I', code)
    require(words[:2] == (0xaa1603e2, 0x52900201), 'actual argument movement')
    require(target(words[2], BEGIN + 8) == STUB and words[2] & 0xfc000000 == 0x94000000,
        'public SYS call')
    require(words[3] & 0xff00001f == 0x35000000 and target(words[3], BEGIN + 12) == FATAL,
        'original fatal branch on actual 32bit result')
    require(words[4] & 0xfc000000 == 0x14000000 and target(words[4], BEGIN + 16) == END,
        'original resume')
    cases = []
    for cpu in (1, 0x123456789abcdef0, (1 << 64) - 1):
        for value in (0, 2, 0x1122334455667788, (1 << 64) - 1):
            for rc in (0, 1, 0xfae94001, 0xffffffff):
                registers = {0: cpu, 22: value, 19: 0x1900, 20: 0x2000, 26: 0x2600}
                registers[2] = registers[22]  # decoded MOV X2,X22
                registers[1] = (words[1] >> 5) & 0xffff  # decoded MOVZ W1
                require((registers[0], registers[1], registers[2]) == (cpu, 0x8010, value), 'actual public three arguments')
                registers[0] = rc
                to = target(words[3], BEGIN + 12) if rc & 0xffffffff else target(words[4], BEGIN + 16)
                require(to == (FATAL if rc else END), 'finite success/failure control')
                require(tuple(registers[i] for i in (19, 20, 22, 26)) == (0x1900, 0x2000, value, 0x2600),
                    'callee saved input registers')
                cases.append(dict(cpu=cpu, value=value, actualReturn=rc, destination=to))
    return cases


def main():
    require(not D.exists(), 'fresh inert candidate directory')
    parser_path = N / 'vmm-public-adapter-gap-design-v1/audit.py'
    require(pin(parser_path)['sha256'] == '8f91d0c632d9711a982e1e8b6a2ba1f312bde0c6a42e9a91f3b4b77297742351', 'pinned genuine parser')
    parser = runpy.run_path(str(parser_path))
    primary = parser['VM']
    require(pin(primary)['sha256'] == 'c81d16f0ec5364bf71d915ac3ee9388610dc940446b2ad1abf3849ba57d46422', 'actual modern VMM')
    before = primary.read_bytes()
    image = parser['MachO'](before)
    require(image.uuid == '4a6a588d1afd30f5a64d6304eb79be0b' and image.bounds(BEGIN) == (0x28a508, 0x28cc24), 'full original restore extent')
    require(hashlib.sha256(image.raw(0x28a508, 10012)).hexdigest() == '2bdd7f1d1ab04cd8eedfb0edc42da89b9ed6673e10580f71998410e686515d31', 'whole original body')
    decoder = json.loads((N / 'modern27-native-physical-decoder-readonly-v1/audit.json').read_bytes())
    require(decoder['modernMDCCINT'] == dict(identifier=0x8010, valid=True, offset=0x688, mask=2), 'genuine modern field contract')
    field_source = R / 'VirtualMac/vz/host/modern_cpu_kernel_system_fields.inc'
    require('{0x8010, VZ_KERNEL_SYS_PHYSICAL, 0x650, 8, UINT64_C(0x0000000000000002), 0}' in field_source.read_text(), 'actual own old field route')
    slot, binding = parser['authenticated_stub'](image, image.raw(STUB, 16), STUB)
    record = binding['importRecord']
    require(record['name'] == '_hv_vcpu_set_sys_reg' and record['ordinal'] == 21 and not record['weak'] and record['addend'] == 0,
        'genuine positive strong public SYS import')
    require(image.raw(BEGIN - 8, 8) == bytes.fromhex('76f242f9400340f9'), 'frame5e0 then public CPU ID retained')
    require(image.raw(END, 16) == bytes.fromhex('76fe42f9400340f9f21c0694f50300aa'), 'nextfield reloads ID and context')
    entries = direct_interior_entries(image)
    rebases = rebase_interior_entries(image)
    D.mkdir(mode=0o700)
    assembler = D / 'block.s'
    assembler.write_text('.text\n.globl _vm27_mdccint_restore_block\n_vm27_mdccint_restore_block:\n'
        'mov x2, x22\nmov w1, #0x8010\n' +
        f'bl . + {STUB - (BEGIN + 8)}\ncbnz w0, . + {FATAL - (BEGIN + 12)}\nb . + {END - (BEGIN + 16)}\n')
    obj = D / 'block.o'
    commands = []
    def run(label, argv):
        result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=60)
        (D / (label + '.stdout')).write_bytes(result.stdout)
        (D / (label + '.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label, argv=list(map(str, argv)), exit=result.returncode))
        require(result.returncode == 0, label + ': ' + result.stderr.decode())
        return result
    run('assemble', ['xcrun', 'clang', '-target', 'arm64e-apple-macos27', '-c', assembler, '-o', obj])
    code = object_text(obj.read_bytes())
    require(len(code) == 20, 'only five compiled instructions')
    cases = semantic_checks(code)
    segment = next(s for s in image.segments if s['va'] <= image.base + BEGIN and image.base + END <= s['va'] + s['bytes'])
    offset = segment['offset'] + image.base + BEGIN - segment['va']
    after = bytearray(before)
    after[offset:offset + 20] = code
    candidate = D / 'VirtualMachine27.mdccint-only.mac.inert.macho-data'
    with candidate.open('xb') as stream:
        stream.write(after)
    candidate.chmod(0o600)
    require(before[:offset] == after[:offset] and before[offset + 20:] == after[offset + 20:], 'whole byte preservation outside five instructions')
    revised = parser['MachO'](after)
    require(revised.imports == image.imports and revised.binds == image.binds and revised.sections == image.sections and
        revised.segments == image.segments and revised.starts == image.starts and revised.uuid == image.uuid, 'original metadata and PAC bindings retained')
    run('compiled-block-disassembly', ['xcrun', 'llvm-objdump', '--disassemble', obj])
    run('candidate-block-disassembly', ['xcrun', 'llvm-objdump', '--disassemble', '--arch-name=aarch64',
        f'--start-address={image.base + BEGIN:#x}', f'--stop-address={image.base + END:#x}', candidate])
    run('validate', ['xcrun', 'dyld_info', '-validate_only', candidate])
    report = dict(schema='Original27 MDCCINT restore public SYS block inert port v1', primaryImage=pin(primary), originalUUID=image.uuid,
        candidate=pin(candidate), parser=pin(parser_path), originalRestoreContract=pin(N / 'modern27-cpu-restore-readonly-v1/contract.json'),
        modernPhysicalDecoder=pin(N / 'modern27-native-physical-decoder-readonly-v1/audit.json'), oldPhysicalSource=pin(field_source),
        source=pin(Path(__file__)), selectedBlock=[BEGIN, END], changedInstructionRange=[BEGIN, BEGIN + 20],
        originalBlockHex=image.raw(BEGIN, END - BEGIN).hex(), compiledBlockHex=code.hex(), publicSYSStub=STUB,
        actualAuthenticatedSlot=slot, originalPositiveStrongBinding=binding, frameValueOffset=0x5e0,
        originalCPUIdOffset=0xd8, logicalSYS=0x8010, modernField=0x688, ownOldField=0x650, readyDirtyMask=2,
        originalFatalHandler=FATAL, originalResume=END, unchangedBytesOutsideFiveInstructions=True,
        directInteriorEntries=entries, chainedInteriorEntries=rebases, compiledIntegerArgumentAndControlCases=cases,
        linkedPublicSYSAdapterInstalled=False, sourcePortsCompletedInThisRestoreFunction=1,
        remainingModernGetContextCallsInRestore=58, originalSYSCalls=133, routedSYSCallsOnNewSelectedPath=134,
        selectedPathNoLongerAccessesModern4110A08688=True, selectedPathNoLongerCallsOriginalNative8=True,
        remainingModernContextLayoutCompatible=False, architectureResetComplete=False,
        publicCallerActuallyExecuted=False, nativeCalls=0, deviceOperations=0, signingCalls=0, guestInstructions=0,
        originalVMMExecuted=False, full27Backend=False, processes=commands)
    with (D / 'candidate.json').open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    paths = [Path(__file__), parser_path, primary, field_source,
        N / 'modern27-cpu-restore-readonly-v1/contract.json', N / 'modern27-cpu-restore-readonly-v1/freeze.json',
        N / 'modern27-native-physical-decoder-readonly-v1/audit.json', N / 'modern27-native-physical-decoder-readonly-v1/audit-optimized.json']
    paths += [p for p in D.iterdir() if p.is_file()]
    with (D / 'freeze.json').open('x') as stream:
        json.dump(dict(files=[pin(p) for p in paths], nativeCalls=0, deviceOperations=0), stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(candidate=pin(D / 'candidate.json'), freeze=pin(D / 'freeze.json'), portedBlocks=1, publicCallerExecuted=False)))


if __name__ == '__main__':
    main()
