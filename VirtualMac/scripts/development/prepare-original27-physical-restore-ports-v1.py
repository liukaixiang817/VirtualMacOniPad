#!/usr/bin/env python3
"""Port only source-proven ordinary physical restore blocks, inert output."""
from pathlib import Path
import hashlib
import json
import re
import runpy
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
D = N / 'original27-physical-restore-source-ports-data-v1'


def require(ok, message):
    if not ok:
        raise ValueError(message)


def pin(path):
    path = Path(path).resolve()
    require(path.is_file() and not path.is_symlink(), 'regular input')
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def register_use(text, register):
    """Conservative textual def/use for this original bounded A64 body."""
    mnemonic, arguments = text.split(None, 1) if re.search(r'\s', text) else (text, '')
    arguments = arguments.split(';')[0].split('<')[0].strip()
    aliases = (register, 'w' + register[1:])
    occurrences = list(re.finditer(r'\b(?:' + '|'.join(aliases) + r')\b', arguments))
    if not occurrences:
        return 'none'
    operands = [q.strip() for q in arguments.split(',')]
    writes = ('mov', 'movz', 'movn', 'adr', 'adrp', 'add', 'sub', 'and', 'orr', 'eor', 'bic', 'ubfx',
        'sbfx', 'bfxil', 'ubfiz', 'sbfiz', 'lsl', 'lsr', 'asr', 'csel', 'csinc', 'cset', 'csetm',
        'ldrb', 'ldrh', 'ldr', 'ldur', 'ldrsw', 'ldar', 'ldapr', 'ldarb', 'ldp')
    if mnemonic in writes and operands and operands[0] in aliases:
        # A read of the destination in a source or address is still a use.
        return 'read' if len(occurrences) > 1 else 'kill'
    if mnemonic == 'ldp' and len(operands) > 1 and operands[1] in aliases:
        return 'read' if len(occurrences) > 1 else 'kill'
    return 'read'


def prove_dead_old_context(rows, begin, function_end, edges):
    """Every original successful/local successor overwrites old x21 first."""
    todo, seen, kills = [begin], set(), []
    while todo:
        at = todo.pop()
        if at in seen:
            continue
        seen.add(at)
        require(at in rows and at < function_end, 'bounded old context lifetime')
        text = rows[at]['instruction']
        effect = register_use(text, 'x21')
        require(effect != 'read', 'old context still live at ' + hex(at) + ': ' + text)
        if effect == 'kill':
            kills.append(dict(rva=at, instruction=text))
            continue
        successors = edges(rows[at]['word'], at)
        require(successors, 'old x21 must be overwritten before return')
        require(all(begin <= to < function_end or to in rows for to in successors), 'local context successor')
        todo.extend(successors)
    return dict(startRVA=begin, instructionsChecked=len(seen), firstOverwrites=kills,
        interproceduralCalleeSavedX21AAPCSAssumed=True)


def main():
    require(not D.exists(), 'fresh inert bulk candidate')
    helper_path = R / 'VirtualMac/scripts/development/prepare-original27-mdccint-restore-port-v1.py'
    single_freeze = json.loads((N / 'original27-mdccint-restore-source-port-data-v1/freeze.json').read_bytes())
    frozen_helper = next(q for q in single_freeze['files'] if q['path'] == str(helper_path))
    require(pin(helper_path) == frozen_helper, 'single block helper pinned')
    helper = runpy.run_path(str(helper_path))
    parser_path = N / 'vmm-public-adapter-gap-design-v1/audit.py'
    require(pin(parser_path)['sha256'] == '8f91d0c632d9711a982e1e8b6a2ba1f312bde0c6a42e9a91f3b4b77297742351', 'actual parser')
    parser = runpy.run_path(str(parser_path))
    primary = parser['VM']
    require(pin(primary)['sha256'] == 'c81d16f0ec5364bf71d915ac3ee9388610dc940446b2ad1abf3849ba57d46422', 'actual primary VMM')
    before = primary.read_bytes()
    image = parser['MachO'](before)
    contract_path = N / 'modern27-cpu-restore-readonly-v1/contract.json'
    contract = json.loads(contract_path.read_bytes())
    require(pin(contract_path)['sha256'] == '182be5ed22594cc1e68aef2e74b715a960ebcf7f7c74613008c62b0fea52d3d2', 'genuine restore contract')
    rows = {}
    for line in (N / 'modern27-cpu-restore-readonly-v1/original-function.asm').read_text().splitlines():
        match = re.match(r'^([0-9a-f]+): ([0-9a-f]{8})\s+(.+)$', line)
        if match:
            rows[int(match[1], 16) - image.base] = dict(word=int(match[2], 16), instruction=match[3])
    require(b''.join(struct.pack('<I', row['word']) for row in rows.values()) == image.raw(0x28a508, 10012), 'whole genuine disassembly')
    control = runpy.run_path(str(R / 'VirtualMac/scripts/development/audit-original27-cpu-restore-v1.py'))
    decoder_path = N / 'modern27-native-physical-decoder-readonly-v1/accepted-descriptors.json'
    decoder = json.loads(decoder_path.read_bytes())
    physical = {q['offset']: q for q in decoder}
    require(len(physical) == len(decoder) == 137, 'unique physical modern routes')
    fields_path = R / 'VirtualMac/vz/host/modern_cpu_kernel_system_fields.inc'
    old_routes = {int(m[1], 16): dict(nativeOffset=int(m[2], 16), mask=int(m[3], 16)) for m in
        re.finditer(r'\{0x([0-9a-f]+), VZ_KERNEL_SYS_PHYSICAL, 0x([0-9a-f]+), 8, UINT64_C\(0x([0-9a-f]+)\), 0\}', fields_path.read_text())}
    calls = [q for q in contract['staticCalls'] if q['symbol'] == '__hv_vcpu_get_context']
    incoming = {}
    for section in image.sections:
        if not section['flags'] & 0x80000400:
            continue
        require(section['bytes'] % 4 == 0, 'complete actual executable section')
        section_bytes = image.raw(section['va'] - image.base, section['bytes'])
        for delta in range(0, section['bytes'], 4):
            pc = section['va'] - image.base + delta
            word = struct.unpack_from('<I', section_bytes, delta)[0]
            to = helper['target'](word, pc)
            if to is not None:
                incoming.setdefault(to, []).append(pc)
    selected, remaining = [], []
    for call in calls:
        at = call['rva']
        block = [rows[at + i * 4]['instruction'] for i in range(14)]
        if not block[1].startswith('mov\tx21, x0'):
            remaining.append(dict(callRVA=at, reason='short direct-context block; needs separately allocated port code'))
            continue
        match = re.fullmatch(r'str\s+x(22|23), \[x21, #0x([0-9a-f]+)\]', block[13])
        require(match is not None, 'ordinary inline block final field store')
        source_register, modern_offset = int(match[1]), int(match[2], 16)
        descriptor = physical.get(modern_offset)
        if not descriptor or descriptor['identifier'] not in old_routes:
            remaining.append(dict(callRVA=at, modernOffset=modern_offset,
                logical=descriptor['identifier'] if descriptor else None, reason='genuine physical logical route unavailable'))
            continue
        ready = re.fullmatch(r'mov\s+w8, #0x([0-9a-f]+)\s*;.*', block[2])
        bit = re.fullmatch(r'tbnz\s+w8, #0x([0-9a-f]+), 0x([0-9a-f]+).*', block[5])
        dirty = re.fullmatch(r'orr\s+x8, x8, #0x([0-9a-f]+)', block[11])
        require(ready and bit and dirty, 'original readiness/dirty mask instruction')
        byte, number, dirty_mask = int(ready[1], 16), int(bit[1], 16), int(dirty[1], 16)
        require(0x4110 <= byte <= 0x4117 and number < 8 and
            1 << ((byte - 0x4110) * 8 + number) == dirty_mask == descriptor['mask'], 'actual decoder and inline mask match')
        require(int(bit[2], 16) - image.base == at + 40, 'original ready skip')
        expected_fixed = {1: 0xaa0003f5, 3: 0x8b080008, 4: 0x39400108, 6: 0x52800100,
            7: 0xd2800001, 10: 0xf94506a8, 12: 0xf90506a8}
        require(all(rows[at + i * 4]['word'] == word for i, word in expected_fixed.items()), 'actual complete common block')
        require(helper['target'](rows[at + 8 * 4]['word'], at + 8 * 4) == 0x3a59a4 and
            rows[at + 9 * 4]['word'] & 0xff00001f == 0x35000000 and
            helper['target'](rows[at + 9 * 4]['word'], at + 9 * 4) == 0x28cb8c, 'original native8 and fatal handler')
        require(rows[at - 4]['word'] == 0xf9400340, 'actual public CPU ID from x26')
        load = re.fullmatch(r'ldr\s+x' + str(source_register) + r', \[x19, #0x([0-9a-f]+)\]', rows[at - 8]['instruction'])
        require(load, 'genuine incoming frame value source')
        helper['BEGIN'], helper['END'] = at, at + 56
        # runpy returns a namespace copy; update globals used by the functions.
        helper['direct_interior_entries'].__globals__.update(BEGIN=at, END=at + 56)
        entry_external, entry_internal = [], []
        for to in range(at + 4, at + 56, 4):
            for pc in incoming.get(to, []):
                (entry_internal if at <= pc < at + 56 else entry_external).append(dict(source=pc, target=to))
        require(not entry_external and entry_internal == [dict(source=at + 20, target=at + 40)], 'all direct interior branches')
        rebase_proof = helper['rebase_interior_entries'](image)
        lifetime = prove_dead_old_context(rows, at + 56, 0x28cc24, control['edges'])
        selected.append(dict(callRVA=at, resumeRVA=at + 56, sourceRegister=source_register,
            frameOffset=int(load[1], 16), modernDescriptor=descriptor, ownOldDescriptor=old_routes[descriptor['identifier']],
            exactOriginalBlockHex=image.raw(at, 56).hex(), directInteriorBranches=entry_internal,
            noExternalDirectInteriorBranch=True, allRebaseWordsWalked=rebase_proof['words'],
            noChainedInteriorRebase=True, oldContextLifetime=lifetime))
    require(len(selected) >= 40 and len(selected) + len(remaining) == 59, 'finite supported block enumeration')
    D.mkdir(mode=0o700)
    assembly = D / 'blocks.s'
    text = '.text\n'
    for row in selected:
        at = row['callRVA']
        text += f'.globl _vm27_restore_{at:x}\n_vm27_restore_{at:x}:\nmov x2, x{row["sourceRegister"]}\n'
        text += f'mov w1, #{row["modernDescriptor"]["identifier"]}\nbl . + {0x412e64 - at - 8}\n'
        text += f'cbnz w0, . + {0x28cb8c - at - 12}\nb . + 40\n'
    assembly.write_text(text)
    obj = D / 'blocks.o'
    processes = []
    def run(label, argv):
        result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=60)
        (D / (label + '.stdout')).write_bytes(result.stdout)
        (D / (label + '.stderr')).write_bytes(result.stderr)
        processes.append(dict(label=label, argv=list(map(str, argv)), exit=result.returncode))
        require(result.returncode == 0, label + ': ' + result.stderr.decode())
    run('assemble', ['xcrun', 'clang', '-target', 'arm64e-apple-macos27', '-c', assembly, '-o', obj])
    machine = helper['object_text'](obj.read_bytes())
    require(len(machine) == 20 * len(selected), 'all five-instruction blocks')
    after = bytearray(before)
    cases = 0
    changed_offsets = set()
    for index, row in enumerate(selected):
        at, logical, source = row['callRVA'], row['modernDescriptor']['identifier'], row['sourceRegister']
        code = machine[index * 20:(index + 1) * 20]
        words = struct.unpack('<5I', code)
        require(words[0] == 0xaa0003e2 | source << 16 and words[1] == 0x52800001 | logical << 5,
            'actual compiled three-argument A64 public ABI')
        require(helper['target'](words[2], at + 8) == 0x412e64 and words[2] & 0xfc000000 == 0x94000000 and
            words[3] & 0xff00001f == 0x35000000 and helper['target'](words[3], at + 12) == 0x28cb8c and
            words[4] & 0xfc000000 == 0x14000000 and helper['target'](words[4], at + 16) == at + 56, 'compiled original success/fatal branches')
        for cpu in (1, 0x123456789abcdef0, (1 << 64) - 1):
            for value in (0, 2, 0x1122334455667788, (1 << 64) - 1):
                for rc in (0, 1, 0xfae94001, 0xffffffff):
                    registers = {0: cpu, source: value}
                    registers[2] = registers[(words[0] >> 16) & 31]
                    registers[1] = (words[1] >> 5) & 0xffff
                    require((registers[0], registers[1], registers[2]) == (cpu, logical, value), 'compiled exact logical setter arguments')
                    destination = helper['target'](words[3], at + 12) if rc & 0xffffffff else helper['target'](words[4], at + 16)
                    require(destination == (0x28cb8c if rc else at + 56), 'exact actual32bit return branch')
                    cases += 1
        segment = next(s for s in image.segments if s['va'] <= image.base + at < s['va'] + s['bytes'])
        offset = segment['offset'] + image.base + at - segment['va']
        require(not changed_offsets.intersection(range(offset, offset + 20)), 'disjoint port blocks')
        changed_offsets.update(range(offset, offset + 20))
        after[offset:offset + 20] = code
        row.update(compiledBlockHex=code.hex(), fileOffset=offset)
    require(all(a == b or i in changed_offsets for i, (a, b) in enumerate(zip(before, after))), 'whole image byte preservation')
    revised = parser['MachO'](after)
    require(revised.imports == image.imports and revised.binds == image.binds and revised.sections == image.sections and
        revised.segments == image.segments and revised.starts == image.starts and revised.uuid == image.uuid, 'all original imports/PAC/layout metadata unchanged')
    candidate = D / 'VirtualMachine27.physical-restore-only.mac.inert.macho-data'
    with candidate.open('xb') as stream:
        stream.write(after)
    candidate.chmod(0o600)
    run('compiled-blocks-disassembly', ['xcrun', 'llvm-objdump', '--disassemble', obj])
    run('validate', ['xcrun', 'dyld_info', '-validate_only', candidate])
    report = dict(schema='Genuine original27 supported physical restore block inert ports v1',
        primaryImage=pin(primary), candidate=pin(candidate), source=pin(Path(__file__)), originalWholeRestoreContract=pin(contract_path),
        modernPhysicalDescriptors=pin(decoder_path), ownOldPhysicalSource=pin(fields_path),
        supportedPorts=selected, remainingOriginalGetContextCalls=remaining, portedBlocks=len(selected),
        compiledArgumentAndControlCases=cases, changedInstructionBytes=20 * len(selected),
        allWholeImageBytesOutsideFiveInstructionsPerPortPreserved=True, originalImportMetadataPACAndLayoutPreserved=True,
        genericIndirectInteriorEntrypointExhaustivelyProven=False, originalFeatureBranchesAndIncomingValuesPreserved=True,
        actualModernPublicSYSStub=0x412e64, originalFatalHandler=0x28cb8c,
        selectedPathsNoLongerUseModernContextOrOriginalNative8=True, actualPublicAdapterInstalled=False,
        originalRestoreExecuted=False, fullArchitectureResetComplete=False, modernContextLayoutFullyPorted=False,
        nativeCalls=0, deviceOperations=0, signingCalls=0, guestInstructions=0, full27Backend=False, processes=processes)
    with (D / 'candidate.json').open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    paths = [Path(__file__), helper_path, parser_path, primary, contract_path, fields_path, decoder_path,
        N / 'modern27-native-physical-decoder-readonly-v1/freeze.json',
        R / 'VirtualMac/scripts/development/audit-original27-cpu-restore-v1.py',
        Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX27.0.sdk/usr/include/mach-o/fixup-chains.h')]
    paths += [p for p in D.iterdir() if p.is_file()]
    with (D / 'freeze.json').open('x') as stream:
        json.dump(dict(files=[pin(p) for p in paths], nativeCalls=0, deviceOperations=0), stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(candidate=pin(D / 'candidate.json'), freeze=pin(D / 'freeze.json'),
        portedBlocks=len(selected), remainingContextCalls=len(remaining), nativeCalls=0)))


if __name__ == '__main__':
    main()
