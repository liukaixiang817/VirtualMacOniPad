#!/usr/bin/env python3
"""Compose genuine SAVE/RESTORE SYS callers with the current routed VMM.

Writes a fresh, inert Mach-O data candidate only. Never signs or runs VMM.
"""
from pathlib import Path
import argparse
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


def require(value, message):
    if not value:
        raise ValueError(message)


def pin(path):
    path = Path(path).resolve()
    require(path.is_file() and not path.is_symlink(), 'regular input')
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def save_context_lifetime(rows, begin, end, register_use, edges):
    todo, seen, kills, fatal = [begin], set(), [], []
    while todo:
        at = todo.pop()
        if at in seen:
            continue
        seen.add(at)
        require(at in rows and at < end, 'bounded SAVE old context lifetime')
        effect = register_use(rows[at]['instruction'], 'x21')
        require(effect != 'read', 'old SAVE context live at ' + hex(at))
        if effect == 'kill':
            kills.append(dict(rva=at, instruction=rows[at]['instruction']))
            continue
        successors = edges(rows[at]['word'], at)
        if not successors:
            require(rows[at]['word'] & 0xffe0001f == 0xd4200000, 'normal return must restore x21')
            fatal.append(dict(rva=at, instruction=rows[at]['instruction']))
        todo.extend(successors)
    return dict(startRVA=begin, instructionsChecked=len(seen), firstOverwrites=kills,
        originalFatalBRKTerminals=fatal, interproceduralCalleeSavedX21AAPCSAssumed=True)


def main():
    arguments = argparse.ArgumentParser()
    arguments.add_argument('--out', type=Path, required=True)
    output = arguments.parse_args().out.resolve()
    require(output.parent == N.resolve() and not output.exists(), 'fresh diagnostic output')
    parser_path = N / 'vmm-public-adapter-gap-design-v1/audit.py'
    require(pin(parser_path)['sha256'] == '8f91d0c632d9711a982e1e8b6a2ba1f312bde0c6a42e9a91f3b4b77297742351', 'actual Mach-O parser')
    parser = runpy.run_path(str(parser_path))
    helper_path = R / 'VirtualMac/scripts/development/prepare-original27-mdccint-restore-port-v1.py'
    require(pin(helper_path)['sha256'] == 'a5a9a134cdd6266999dcb17d581b42e8711e9d86713e9d5d386ba8bf3b01ebd3', 'actual bounded instruction helper')
    helper = runpy.run_path(str(helper_path))
    lifetime_path = R / 'VirtualMac/scripts/development/prepare-original27-physical-restore-ports-v1.py'
    require(pin(lifetime_path)['sha256'] == 'b5b3d69ff07f35904070893ce68b4fe4fe40d02c64411761d9a6082d468c30fc', 'actual context lifetime helper')
    lifetimes = runpy.run_path(str(lifetime_path))
    control_path = R / 'VirtualMac/scripts/development/audit-original27-cpu-restore-v1.py'
    control = runpy.run_path(str(control_path))
    route_receipt = N / 'owned-vmm-three-xpc-v9-route-v2/candidate.json'
    route = json.loads(route_receipt.read_bytes())
    source = N / 'owned-vmm-three-xpc-v9-route-v2/VMM27.owned-xpc-v9-route.inert.macho-data'
    require(pin(source)['sha256'] == '9c80a9c3dde357bcf0bb5f15568f27de0afcb539787014cdd253b53981320c7e', 'latest exact routed VMM')
    original = Path(parser['VM'])
    require(pin(original)['sha256'] == 'c81d16f0ec5364bf71d915ac3ee9388610dc940446b2ad1abf3849ba57d46422', 'genuine original VMM')
    before, original_bytes = source.read_bytes(), original.read_bytes()
    image = parser['MachO'](before)
    genuine = parser['MachO'](original_bytes)
    save_begin, save_end = genuine.bounds(0x28835c)
    require((save_begin, save_end) == (0x2875a8, 0x28a258), 'genuine LC26 save function')
    require(image.raw(save_begin, 0x28cc24 - save_begin) == genuine.raw(save_begin, 0x28cc24 - save_begin), 'routed original save/restore bytes')
    asm_path = N / 'cpu-physical-timer-boot-basis-v1/vmm-full-save-complete.asm'
    rows = {}
    for line in asm_path.read_text().splitlines():
        match = re.match(r'^([0-9a-f]+): ([0-9a-f]{8})\s+(.+)$', line)
        if match:
            rows[int(match[1], 16) - image.base] = dict(word=int(match[2], 16), instruction=match[3])
    require(list(rows) == list(range(save_begin, save_end, 4)), 'whole bounded save disassembly')
    require(b''.join(struct.pack('<I', row['word']) for row in rows.values()) == genuine.raw(save_begin, save_end - save_begin), 'whole save instruction words')
    fields_path = R / 'VirtualMac/vz/host/modern_vmm_physical_save53_fields_v1.inc'
    fields = [dict(callRVA=int(m[1], 16), logicalSYS=int(m[2], 16), modernField=int(m[3], 16),
        oldNativeField=int(m[4], 16), frameOffset=int(m[5], 16), bankMask=int(m[6], 16)) for m in
        re.finditer(r'\{0x([0-9a-f]+),0x([0-9a-f]+),0x([0-9a-f]+),0x([0-9a-f]+),0x([0-9a-f]+),UINT64_C\(0x([0-9a-f]+)\)\}', fields_path.read_text())]
    require(len(fields) == len({q['callRVA'] for q in fields}) == 53, 'genuine 53 source descriptors')
    old_fields_path = R / 'VirtualMac/vz/host/modern_cpu_kernel_system_fields.inc'
    old_routes = {int(m[1], 16): (int(m[2], 16), int(m[3], 16)) for m in
        re.finditer(r'\{0x([0-9a-f]+), VZ_KERNEL_SYS_PHYSICAL, 0x([0-9a-f]+), 8, UINT64_C\(0x([0-9a-f]+)\), 0\}', old_fields_path.read_text())}
    modern_fields_path = N / 'modern27-native-physical-decoder-readonly-v1/accepted-descriptors.json'
    modern_routes = {q['identifier']: q for q in json.loads(modern_fields_path.read_bytes())}
    incoming = {}
    for section in image.sections:
        if not section['flags'] & 0x80000400:
            continue
        raw = image.raw(section['va'] - image.base, section['bytes'])
        require(len(raw) % 4 == 0, 'whole executable sections')
        for delta in range(0, len(raw), 4):
            at = section['va'] - image.base + delta
            destination = helper['target'](struct.unpack_from('<I', raw, delta)[0], at)
            if destination is not None:
                incoming.setdefault(destination, []).append(at)
    longs, shorts = [], []
    for field in fields:
        at = field['callRVA']
        require(old_routes[field['logicalSYS']] == (field['oldNativeField'], field['bankMask']), 'real old physical route')
        modern = modern_routes[field['logicalSYS']]
        require(modern['offset'] == field['modernField'], 'genuine modern physical selector route')
        require(rows[at - 4]['word'] == 0xf9400300 and helper['target'](rows[at]['word'], at) == 0x4125b4, 'actual CPU ID from x24 and GetContext call')
        long = rows[at + 4]['word'] == 0xaa0003f5
        size = 48 if long else 12
        load_at = at + (40 if long else 4)
        require(rows[load_at]['word'] == (0xf9400000 | (field['modernField'] // 8) << 10 | (21 if long else 0) << 5 | 8), 'true original context field load')
        require(rows[load_at + 4]['word'] == (0xf9000000 | (field['frameOffset'] // 8) << 10 | 19 << 5 | 8), 'true original frame 64-bit store')
        external = [dict(source=pc, target=to) for to in range(at + 4, at + size, 4)
            for pc in incoming.get(to, []) if not at <= pc < at + size]
        require(not external, 'no external branch into replaced block')
        helper['rebase_interior_entries'].__globals__.update(BEGIN=at, END=at + size)
        rebase = helper['rebase_interior_entries'](image)
        field.update(blockBytes=size, originalBlockHex=image.raw(at, size).hex(),
            resumeRVA=at + size, noExternalDirectInteriorEntry=True, chainedWordsWalked=rebase['words'])
        if long:
            fixed = {3:0x8b080008, 4:0x39400108, 6:0x52800100, 7:0xd2800001}
            require(all(rows[at + 4 * i]['word'] == word for i, word in fixed.items()), 'whole original native8 readiness block')
            require(helper['target'](rows[at + 32]['word'], at + 32) == 0x3a59a4 and
                helper['target'](rows[at + 20]['word'], at + 20) == at + 40 and
                rows[at + 36]['word'] & 0xff00001f == 0x35000000, 'original native8 readiness and status branches')
            ready_word = rows[at + 8]['word']
            require(ready_word & 0xffe0001f == 0x52800008, 'actual ready-byte immediate')
            byte = (ready_word >> 5) & 0xffff
            bit = (rows[at + 20]['word'] >> 19) & 31
            require(0x4110 <= byte <= 0x4117 and 1 << ((byte - 0x4110) * 8 + bit) == modern['mask'],
                'genuine modern decoder matches original SAVE readiness at ' + hex(at))
            field['originalModernReadinessMask'] = modern['mask']
            field['fatalRVA'] = helper['target'](rows[at + 36]['word'], at + 36)
            field['oldContextLifetime'] = save_context_lifetime(rows, at + 48, save_end, lifetimes['register_use'], control['edges'])
            field['compiledBytes'] = 20 if field['frameOffset'] < 0x1000 else 24
            longs.append(field)
        else:
            # Every original public SYS failure island has this same exact
            # status-consuming call then branch to the shared exception body.
            require(rows[0x289e88]['word'] == 0x940617f0 and
                helper['target'](rows[0x289e8c]['word'], 0x289e8c) == 0x288e64, 'genuine public SYS exception island')
            field.update(fatalRVA=0x289e88, compiledBytes=24)
            shorts.append(field)
    require(len(longs) == 49 and len(shorts) == 4, '49 long and four short source SAVE blocks')
    for short, parent in zip(shorts, longs[:4]):
        cave = parent['callRVA'] + parent['compiledBytes']
        require(cave + short['compiledBytes'] <= parent['resumeRVA'], 'bounded skipped tail')
        short.update(caveRVA=cave, parentCallRVA=parent['callRVA'])
    output.mkdir(mode=0o700)
    assembly = output / 'save-blocks.s'
    text = '.text\n'
    for field in longs + shorts:
        at = field.get('caveRVA', field['callRVA'])
        frame, logical = field['frameOffset'], field['logicalSYS']
        text += f'.globl _vm27_save_{field["callRVA"]:x}\n_vm27_save_{field["callRVA"]:x}:\nmov w1, #{logical}\n'
        if frame < 0x1000:
            text += f'add x2, x19, #{frame}\n'
            count = 2
        else:
            text += f'add x2, x19, #{frame >> 12}, lsl #12\nadd x2, x2, #{frame & 0xfff}\n'
            count = 3
        text += f'bl . + {0x412dd4 - at - count * 4}\n'
        text += f'cbnz w0, . + {field["fatalRVA"] - at - (count + 1) * 4}\n'
        text += f'b . + {field["resumeRVA"] - at - (count + 2) * 4}\n'
    assembly.write_text(text)
    commands = []
    def run(label, argv):
        result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=60)
        (output / (label + '.stdout')).write_bytes(result.stdout)
        (output / (label + '.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label, argv=list(map(str, argv)), exit=result.returncode))
        require(result.returncode == 0, label + ': ' + result.stderr.decode())
    obj = output / 'save-blocks.o'
    run('assemble', ['xcrun', 'clang', '-target', 'arm64e-apple-macos27', '-c', assembly, '-o', obj])
    compiled = helper['object_text'](obj.read_bytes())
    require(len(compiled) == sum(q['compiledBytes'] for q in longs + shorts), 'actual compiled port lengths')
    after, allowed, offset = bytearray(before), set(), 0
    def replace(at, data):
        segment = next(s for s in image.segments if s['va'] <= image.base + at and image.base + at + len(data) <= s['va'] + s['bytes'])
        file_at = segment['offset'] + image.base + at - segment['va']
        require(not allowed.intersection(range(file_at, file_at + len(data))), 'disjoint replacements')
        allowed.update(range(file_at, file_at + len(data)))
        after[file_at:file_at + len(data)] = data
    cases = 0
    for field in longs + shorts:
        at = field.get('caveRVA', field['callRVA'])
        code = compiled[offset:offset + field['compiledBytes']]
        offset += len(code)
        words = struct.unpack('<' + 'I' * (len(code) // 4), code)
        count = len(words) - 3
        require(words[0] == 0x52800001 | field['logicalSYS'] << 5, 'actual uint16 SYS selector ABI')
        require(words[count] & 0xfc000000 == 0x94000000 and helper['target'](words[count], at + count * 4) == 0x412dd4 and
            words[count + 1] & 0xff00001f == 0x35000000 and helper['target'](words[count + 1], at + (count + 1) * 4) == field['fatalRVA'] and
            helper['target'](words[count + 2], at + (count + 2) * 4) == field['resumeRVA'], 'compiled genuine getter/status/continuation')
        for cpu in (0, 0x123456789abcdef0, (1 << 64) - 1):
            for frame in (0x100000, 0x1234000000):
                registers = {0:cpu, 19:frame}
                for word in words[:count]:
                    if word & 0xffe00000 == 0x52800000:
                        registers[word & 31] = (word >> 5) & 0xffff
                    else:
                        require(word & 0xff000000 == 0x91000000, 'compiled ADD argument')
                        registers[word & 31] = registers[(word >> 5) & 31] + (((word >> 10) & 0xfff) << (12 if word & (1 << 22) else 0))
                require((registers[0], registers[1], registers[2]) == (cpu, field['logicalSYS'], frame + field['frameOffset']), 'actual passed identity and exact genuine output frame')
                for status in (0, 1, 0xfae94001, 0xffffffff):
                    destination = helper['target'](words[count + (1 if status else 2)], at + (count + (1 if status else 2)) * 4)
                    require(destination == (field['fatalRVA'] if status else field['resumeRVA']), '32-bit result dispatch')
                    cases += 1
        replace(at, code)
        if 'caveRVA' in field:
            delta = at - field['callRVA']
            require(delta % 4 == 0 and -(1 << 27) <= delta < (1 << 27), 'nonlink cave branch')
            replace(field['callRVA'], struct.pack('<I', 0x14000000 | (delta // 4 & 0x3ffffff)))
            replace(field['callRVA'] + 4, struct.pack('<II', 0xd503201f, 0xd503201f))
        field['compiledBlockHex'] = code.hex()
    restore_receipt = N / 'original27-short-physical-restore-source-ports-data-v1/candidate.json'
    restore = json.loads(restore_receipt.read_bytes())
    restore_source = Path(restore['candidate']['path'])
    require(pin(restore_source)['sha256'] == 'fd1a042749d17e497757742a6d97b8fb972b5783b57cdaab4a1df4b212b5aa6c', 'frozen actual 53 RESTORE image')
    restore_bytes = restore_source.read_bytes()
    require(len(restore_bytes) == len(original_bytes) == len(before), 'same whole original image size')
    restore_changed = [i for i, (a, b) in enumerate(zip(original_bytes, restore_bytes)) if a != b]
    require(restore_changed and all(0x28a508 <= i < 0x28cc24 for i in restore_changed), 'restore-only exact deltas')
    for i in restore_changed:
        require(i not in allowed and before[i] == original_bytes[i], 'no routed/restore collision')
        allowed.add(i)
        after[i] = restore_bytes[i]
    require(all(a == b or i in allowed for i, (a, b) in enumerate(zip(before, after))), 'all bytes outside exact ports preserved')
    revised = parser['MachO'](after)
    require(revised.imports == image.imports and revised.binds == image.binds and revised.libs == image.libs and
        revised.sections == image.sections and revised.segments == image.segments and revised.starts == image.starts and revised.uuid == image.uuid,
        'latest routing/imports/PAC/layout exactly preserved')
    target = output / 'VMM27.routed-save53-restore53.inert.macho-data'
    with target.open('xb') as stream:
        stream.write(after)
    target.chmod(0o600)
    run('disassemble', ['xcrun', 'llvm-objdump', '--disassemble', obj])
    run('validate', ['xcrun', 'dyld_info', '-validate_only', target])
    report = dict(schema='Genuine current routed original27 physical SAVE53 RESTORE53 inert callers v1',
        source=pin(Path(__file__)), original=pin(original), routedSource=pin(source), routedReceipt=pin(route_receipt),
        inheritedRestore=pin(restore_receipt), candidate=pin(target), savePorts=longs + shorts,
        savePortsCount=53, restorePortsCount=53, compiledArgumentAndBranchCases=cases,
        originalFeatureBranchesPreserved=True, actualCPUIdentityLoadedFromOriginalX24=True,
        noGeneratedCPUIdentity=True, noModernGetContextView=True, noUnconditional59FieldLoop=True,
        remainingContextFields=[0x6a0,0x410,0xca8,0xbc0,0x390,0xaf8], remainingSaveContextCalls=6,
        remainingRestoreContextCalls=6, mandatoryPrivateCallerAdapterNotYetRouted=True,
        allBytesOutsideExactDeclaredPortsPreserved=True, latestImportsAndAuthenticatedChainsAndMetadataPreserved=True,
        genericIndirectEntrypointAbsenceExhaustivelyProven=False, exceptionUnwindRoutesExecuted=False,
        candidateSigned=False, candidateLoaded=False, originalSaveRestoreExecuted=False,
        nativeCalls=0, deviceOperations=0, guestInstructions=0, fullIndependent27GuestBoot=False, commands=commands)
    (output / 'candidate.json').write_text(json.dumps(report, indent=2) + '\n')
    inputs = [Path(__file__), parser_path, helper_path, lifetime_path, control_path, original, source, route_receipt,
        restore_receipt, restore_source, asm_path, fields_path, old_fields_path, modern_fields_path]
    files = inputs + [p for p in output.iterdir() if p.is_file()]
    (output / 'freeze.json').write_text(json.dumps(dict(files=[pin(p) for p in files], deviceOperations=0, nativeCalls=0), indent=2) + '\n')
    print(json.dumps(dict(candidate=pin(output / 'candidate.json'), freeze=pin(output / 'freeze.json'), savePorts=53, restorePorts=53)))


if __name__ == '__main__':
    main()
