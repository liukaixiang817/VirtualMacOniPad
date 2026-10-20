#!/usr/bin/env python3
"""Use four proven skipped instruction tails for short public SYS ports.

This is an inert candidate. Unknown context fields and feature paths remain.
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
D = N / 'original27-short-physical-restore-source-ports-data-v1'
SELECTED = ((0x28ca00, 0x28ca04, 0xe7e0, 0xc70, 0x1d70),
            (0x28ca10, 0x28ca14, 0xf795, 0x398, 0x1d78),
            (0x28ca60, 0x28ca64, 0xf7c3, 0xa28, 0x1d88),
            (0x28cb00, 0x28cb04, 0xe78a, 0xaf0, 0x1da8))


def require(ok, message):
    if not ok:
        raise ValueError(message)


def pin(path):
    path = Path(path).resolve()
    require(path.is_file() and not path.is_symlink(), 'regular source')
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def main():
    require(not D.exists(), 'fresh inert short port')
    previous_path = N / 'original27-physical-restore-source-ports-data-v1/candidate.json'
    require(pin(previous_path)['sha256'] == '9d634d98a66dfc77080951154f1da78997955ff809e600cc59d72352bf5cdc0e', '49 existing source ports')
    previous = json.loads(previous_path.read_bytes())
    source = Path(previous['candidate']['path'])
    require(pin(source) == previous['candidate'], 'existing inert whole image')
    before = source.read_bytes()
    parser_path = N / 'vmm-public-adapter-gap-design-v1/audit.py'
    require(pin(parser_path)['sha256'] == '8f91d0c632d9711a982e1e8b6a2ba1f312bde0c6a42e9a91f3b4b77297742351', 'actual parser')
    parser = runpy.run_path(str(parser_path))
    image = parser['MachO'](before)
    helper_path = R / 'VirtualMac/scripts/development/prepare-original27-mdccint-restore-port-v1.py'
    helper = runpy.run_path(str(helper_path))
    fields_path = R / 'VirtualMac/vz/host/modern_cpu_kernel_system_fields.inc'
    decoder_path = N / 'modern27-native-physical-decoder-readonly-v1/accepted-descriptors.json'
    physical = {q['identifier']: q for q in json.loads(decoder_path.read_bytes())}
    caves = [q['callRVA'] + 20 for q in previous['supportedPorts'][:4]]
    require(len(set(caves)) == 4, 'four disjoint proven skipped tails')
    ports = []
    for selected, cave in zip(SELECTED, caves):
        call, store, logical, field, frame = selected
        require(physical[logical]['offset'] == field and '{0x%04x, VZ_KERNEL_SYS_PHYSICAL,' % logical in fields_path.read_text(),
            'genuine modern physical ID has verified old physical route')
        require(image.raw(call - 8, 8) == struct.pack('<II', 0xf9400000 | (frame // 8) << 10 | 19 << 5 | 21, 0xf9400340),
            'original incoming frame X21 and real CPU ID')
        require(helper['target'](struct.unpack('<I', image.raw(call, 4))[0], call) == 0x4125b4 and
            image.raw(store, 4) == struct.pack('<I', 0xf9000000 | (field // 8) << 10 | 21), 'original context call and exact8B store')
        parent = next(q for q in previous['supportedPorts'] if q['callRVA'] + 20 == cave)
        require(image.raw(cave - 4, 4) == struct.pack('<I', 0x14000000 | 10) and parent['resumeRVA'] == cave + 36,
            'previous port always skips whole tail')
        helper['rebase_interior_entries'].__globals__.update(BEGIN=cave - 4, END=cave + 20)
        rebase = helper['rebase_interior_entries'](image)
        incoming = []
        for section in image.sections:
            if not section['flags'] & 0x80000400:
                continue
            raw = image.raw(section['va'] - image.base, section['bytes'])
            for delta in range(0, len(raw), 4):
                at = section['va'] - image.base + delta
                to = helper['target'](struct.unpack_from('<I', raw, delta)[0], at)
                if to is not None and cave <= to < cave + 20:
                    incoming.append(dict(source=at, target=to))
        require(not incoming, 'no branch into reused skipped tail')
        ports.append(dict(callRVA=call, removedStoreRVA=store, caveRVA=cave, logicalSYS=logical,
            modernField=field, frameOffset=frame, sourceRegister=21, resumeRVA=call + 4,
            originalCallHex=image.raw(call, 4).hex(), originalStoreHex=image.raw(store, 4).hex(),
            originalSkippedTailHex=image.raw(cave, 20).hex(), previousAlwaysSkipBranchRVA=cave - 4,
            noPriorDirectEntryIntoCave=True, noChainedRebaseIntoCave=True, chainedWordsWalked=rebase['words'],
            genericIndirectEntryAbsenceExhaustivelyProven=False))
    D.mkdir(mode=0o700)
    assembly = D / 'short-blocks.s'
    text = '.text\n'
    for row in ports:
        call, cave, logical = row['callRVA'], row['caveRVA'], row['logicalSYS']
        text += f'.globl _vm27_short_{call:x}\n_vm27_short_{call:x}:\nmov x2, x21\nmov w1, #{logical}\n'
        text += f'bl . + {0x412e64 - cave - 8}\ncbnz w0, . + {0x28cb8c - cave - 12}\nb . + {call + 4 - cave - 16}\n'
    assembly.write_text(text)
    obj, processes = D / 'short-blocks.o', []
    def run(label, argv):
        result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=60)
        (D / (label + '.stdout')).write_bytes(result.stdout)
        (D / (label + '.stderr')).write_bytes(result.stderr)
        processes.append(dict(label=label, argv=list(map(str, argv)), exit=result.returncode))
        require(result.returncode == 0, label + ': ' + result.stderr.decode())
    run('assemble', ['xcrun', 'clang', '-target', 'arm64e-apple-macos27', '-c', assembly, '-o', obj])
    compiled = helper['object_text'](obj.read_bytes())
    require(len(compiled) == len(ports) * 20, 'four real compiled blocks')
    after, allowed, checks = bytearray(before), set(), 0
    def replace(at, data):
        segment = next(s for s in image.segments if s['va'] <= image.base + at and image.base + at + len(data) <= s['va'] + s['bytes'])
        offset = segment['offset'] + image.base + at - segment['va']
        require(not allowed.intersection(range(offset, offset + len(data))), 'disjoint actual modifications')
        allowed.update(range(offset, offset + len(data)))
        after[offset:offset + len(data)] = data
    for index, row in enumerate(ports):
        code = compiled[index * 20:(index + 1) * 20]
        words = struct.unpack('<5I', code)
        at, call, logical = row['caveRVA'], row['callRVA'], row['logicalSYS']
        require(words[:2] == (0xaa1503e2, 0x52800001 | logical << 5), 'actual 64bit value and uint16 SYS arguments')
        require(words[2] & 0xfc000000 == 0x94000000 and helper['target'](words[2], at + 8) == 0x412e64 and
            words[3] & 0xff00001f == 0x35000000 and helper['target'](words[3], at + 12) == 0x28cb8c and
            words[4] & 0xfc000000 == 0x14000000 and helper['target'](words[4], at + 16) == call + 4,
            'actual public setter/fatal/original continuation branches')
        for cpu in (1, 0x123456789abcdef0, (1 << 64) - 1):
            for value in (0, 2, 0x1122334455667788, (1 << 64) - 1):
                for result in (0, 1, 0xfae94001, 0xffffffff):
                    registers = {0: cpu, 21: value}
                    registers[2] = registers[(words[0] >> 16) & 31]
                    registers[1] = (words[1] >> 5) & 0xffff
                    require((registers[0], registers[1], registers[2]) == (cpu, logical, value), 'genuine argument triple')
                    to = helper['target'](words[3], at + 12) if result & 0xffffffff else helper['target'](words[4], at + 16)
                    require(to == (0x28cb8c if result else call + 4), 'true failure branch')
                    checks += 1
        delta = at - call
        require(delta % 4 == 0 and -(1 << 27) <= delta < (1 << 27), 'local nonlink branch range')
        replace(call, struct.pack('<I', 0x14000000 | ((delta // 4) & 0x3ffffff)))
        replace(row['removedStoreRVA'], struct.pack('<I', 0xd503201f))
        replace(at, code)
        row['compiledBlockHex'] = code.hex()
    require(all(a == b or i in allowed for i, (a, b) in enumerate(zip(before, after))), 'whole preservation outside four direct ports and tails')
    revised = parser['MachO'](after)
    require(revised.imports == image.imports and revised.binds == image.binds and revised.sections == image.sections and
        revised.starts == image.starts and revised.uuid == image.uuid and revised.segments == image.segments,
        'whole metadata/PAC/layout retained')
    candidate = D / 'VirtualMachine27.physical53-restore-only.mac.inert.macho-data'
    with candidate.open('xb') as stream:
        stream.write(after)
    candidate.chmod(0o600)
    run('compiled-blocks-disassembly', ['xcrun', 'llvm-objdump', '--disassemble', obj])
    run('validate', ['xcrun', 'dyld_info', '-validate_only', candidate])
    report = dict(schema='Original27 four short physical restore inert ports v1', priorCandidate=pin(previous_path),
        sourceImage=pin(source), candidate=pin(candidate), source=pin(Path(__file__)), ports=ports,
        newCompiledArgumentControlCases=checks, newModifiedBytes=112, previous49PortsPreserved=True,
        totalRestorePhysicalPorts=53, originalGetContextCallsRemaining=6,
        remainingFields=[0x6a0, 0x410, 0xca8, 0xbc0, 0x390, 0xaf8],
        unchangedAllInstructionsOutsideDeclaredRanges=True, allMetadataAndPACAndLinkLayoutUnchanged=True,
        usedOnlyPreviouslyProvenUnreachableInstructionTails=True, newCallUsesLocalNonlinkBranch=True,
        originalPublicSYSStrongAuthenticatedStubRetained=True, actualPublicAdapterInstalled=False,
        genericIndirectEntryAbsenceExhaustivelyProven=False, wholeExceptionTableRouteSafetyExecuted=False,
        originalRestoreExecuted=False, architecturalResetComplete=False, modernContextFullyPorted=False,
        signingCalls=0, deviceOperations=0, nativeCalls=0, guestInstructions=0, full27Backend=False, processes=processes)
    with (D / 'candidate.json').open('x') as stream:
        json.dump(report, stream, indent=2)
        stream.write('\n')
    paths = [Path(__file__), previous_path, source, parser_path, helper_path, fields_path, decoder_path]
    paths += [p for p in D.iterdir() if p.is_file()]
    with (D / 'freeze.json').open('x') as stream:
        json.dump(dict(files=[pin(p) for p in paths], deviceOperations=0, nativeCalls=0), stream, indent=2)
        stream.write('\n')
    print(json.dumps(dict(candidate=pin(D / 'candidate.json'), freeze=pin(D / 'freeze.json'), newPorts=4, remainingContextCalls=6)))


if __name__ == '__main__':
    main()
