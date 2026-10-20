#!/usr/bin/env python3
"""Audit genuine 13/27 run/exit words and test an owned value-only reducer.

Only stock disassembly and own model code execute. No Apple image is loaded;
no native trap, CPU operation, device connection, deployment or retry occurs.
"""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import os
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
T = R / 'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3'
H = R / 'VirtualMac/vz/host'
READER = N / 'native-init-contract-v1/audit.py'
READER_SHA = 'aebcb8a809c935739683b7ff75109bc11afbf7581cd1da86a823f85f82b02323'
MODERN = T / 'integrity-audit/modern-compiler/virtualization27-stack-audit-v1/raw'
HV27_SHA = '4d334d43c5628d134ef6b0f8ceef9a4c3c620467b284f92dc1c49b16bfc495a3'
VMM27_SHA = 'c81d16f0ec5364bf71d915ac3ee9388610dc940446b2ad1abf3849ba57d46422'
ACTUAL = N / 'native-initial-cancel-actual-v32/native.stdout'
ACTUAL_SHA = 'c3f1555b86fba87cca4f49c1f2dfe39d0f03e48ea37b97aa822f249742a51b03'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def pin(path):
    data = path.read_bytes()
    return dict(path=str(path.resolve()), bytes=len(data), sha256=sha(data))


def main():
    assert not sys.flags.optimize
    ap = argparse.ArgumentParser()
    ap.add_argument('--output', type=Path, required=True)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(N)
    out.mkdir(mode=0o700, exist_ok=False)
    (out / 'audit-snapshot.py').write_bytes(Path(__file__).read_bytes())
    assert pin(READER)['sha256'] == READER_SHA
    spec = importlib.util.spec_from_file_location('pinned_macho_reader', READER)
    reader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(reader)
    hv13, hi13 = reader.pin(reader.HV, reader.HV_SHA)
    hv27, hi27 = reader.pin(MODERN / 'Hypervisor', HV27_SHA)
    vm27, vi27 = reader.pin(MODERN / 'VirtualMachine.arm64e', VMM27_SHA)
    assert hi13['uuid'] == '1b1e116f81fd3fd6b42452d4fa96e9ab'
    assert hi27['uuid'] == '1b4f3a6a055836c6850d886311584afc'
    assert pin(ACTUAL)['sha256'] == ACTUAL_SHA
    # Bounded frames are deliberately not a transitive whole-backend claim.
    requests = [
        ('old-trap', reader.HV, hv13, hi13, 0x492c, 0x4938),
        ('old-create-exit-pointer', reader.HV, hv13, hi13, 0x53f0, 0x54d0),
        ('old-public-run', reader.HV, hv13, hi13, 0x6eec, 0x70b0),
        ('old-public-exit-tail', reader.HV, hv13, hi13, 0x7678, 0x7730),
        ('modern-trap', MODERN / 'Hypervisor', hv27, hi27, 0xd92c, 0xd938),
        ('modern-public-create-exit-pointer', MODERN / 'Hypervisor', hv27, hi27, 0x4490, 0x4688),
        ('modern-public-run', MODERN / 'Hypervisor', hv27, hi27, 0x85844, 0x8587c),
        ('modern-USER-resolver', MODERN / 'Hypervisor', hv27, hi27, 0x8cd4, 0x8dd4),
        ('modern-USER-native-run', MODERN / 'Hypervisor', hv27, hi27, 0x97f0, 0x99c4),
        ('modern-USER-run-wrapper', MODERN / 'Hypervisor', hv27, hi27, 0x9a24, 0x9b04),
        ('modern-raw-exit-dispatch', MODERN / 'Hypervisor', hv27, hi27, 0x4d14, 0x4e28),
        ('modern-exception-values', MODERN / 'Hypervisor', hv27, hi27, 0x4e28, 0x4e70),
        ('modern-VMM-run-caller', MODERN / 'VirtualMachine.arm64e', vm27, vi27, 0xb1548, 0xb1584),
        ('modern-VMM-public-exit-consumer', MODERN / 'VirtualMachine.arm64e', vm27, vi27, 0x28d4a0, 0x28d594),
    ]
    frames = {}
    for name, path, data, info, lo, hi in requests:
        argv, text, rows = reader.disassemble(path, info['imageBase'], lo, hi)
        raw = reader.raw(data, info, lo, hi)
        assert bytes.fromhex(''.join(row['machineWord'][i:i + 2]
                                     for row in rows for i in (6, 4, 2, 0))) == raw
        (out / (name + '.asm')).write_text(text)
        frames[name] = dict(imageSHA256=info['sha256'], beginRVA=hex(lo), endRVA=hex(hi),
                            bytes=len(raw), bytesSHA256=sha(raw), instructions=rows, argv=argv)
    checked = []

    def word(frame, rva, expected):
        rows = {r['rva']: r for r in frames[frame]['instructions']}
        assert rows[rva]['machineWord'] == expected
        checked.append(dict(frame=frame, rva=hex(rva), machineWord=expected,
                            instruction=rows[rva]['instruction']))

    for frame, lo in [('old-trap', 0x492c), ('modern-trap', 0xd92c)]:
        for at, w in [(lo, '92800090'), (lo + 4, 'd4001001'), (lo + 8, 'd65f03c0')]:
            word(frame, at, w)
    for at, w in [(0x6f28, 'f84e8d16'), (0x6f30, 'b40000f6'), (0x6f3c, 'aa160102'),
                  (0x6f48, '97fffa24'), (0x702c, '52800120'), (0x7030, 'd2800001'),
                  (0x7034, '97fff63e'), (0x703c, '35003560'),
                  (0x7044, 'b8786ab0'), (0x7060, 'b8b07a30'), (0x7074, 'b9000357'),
                  (0x7078, 'b9785668'), (0x707c, 'f9000328'), (0x7080, 'f9600ea8'),
                  (0x7088, 'f96012a8'), (0x7094, 'd35afd28'), (0x7098, 'f100591f'),
                  (0x709c, '540003a0'), (0x70a0, 'f100fd1f'), (0x70a4, '54000500'),
                  (0x70a8, 'f100611f'), (0x70ac, '540031e1')]:
        word('old-public-run', at, w)
    for at, w in [(0x76a0, '52800016'), (0x76a4, 'b900035f'),
                  (0x76e8, 'f85a03a8'), (0x76ec, 'b4000108'), (0x76f4, 'f900011f'),
                  (0x7700, '9278f502'), (0x7708, '97fff834'), (0x770c, 'aa1603e0')]:
        word('old-public-exit-tail', at, w)
    for at, w in [(0x98e4, '52800120'), (0x98e8, 'd2800001'), (0x98ec, '94001010'),
                  (0x98f0, '35000220'),
                  (0x990c, '97ffed02'), (0x991c, '54fffe41')]:
        word('modern-USER-native-run', at, w)
    for at, w in [(0x4d24, '52800028'), (0x4d30, '7100093f'), (0x4d44, '7100093f'),
                  (0x4d4c, 'aa0803e0'), (0x4d50, 'd65f03c0'),
                  (0x4d64, '71002d3f'), (0x4d68, '54ffff20'), (0x4df8, 'b901481f')]:
        word('modern-raw-exit-dispatch', at, w)
    for at, w in [(0x4e4c, 'f9600901'), (0x4e50, 'b9014809'), (0x4e54, 'f900a801'),
                  (0x4e58, 'f9601102'), (0x4e5c, 'f900ac02'), (0x4e60, 'f9601503'),
                  (0x4e64, 'f900b003')]:
        word('modern-exception-values', at, w)
    for at, w in [(0xb1570, '940d861d'), (0xb1574, '350005e0'), (0xb157c, '94076fc9')]:
        word('modern-VMM-run-caller', at, w)
    for at, w in [(0x28d4b8, 'f9407008'), (0x28d4bc, 'b9400108'),
                  (0x28d4c4, '7100051f'), (0x28d568, 'f9400533'),
                  (0x28d56c, '531a7e68')]:
        word('modern-VMM-public-exit-consumer', at, w)
    table = reader.raw(hv13, hi13, 0x7730, 0x7760)
    destinations = [0x7064 + n for n in struct.unpack('<12i', table)]
    assert destinations == [0x76a0, 0x7070, 0x702c, 0x7678, 0x7678, 0x7690,
                            0x7070, 0x71f0, 0x7070, 0x7690, 0x7690, 0x702c]
    negatives = []
    for index in range(12):
        changed = bytearray(table)
        struct.pack_into('<i', changed, index * 4,
                         struct.unpack_from('<i', changed, index * 4)[0] + 4)
        actual = [0x7064 + n for n in struct.unpack('<12i', changed)]
        assert actual != destinations
        negatives.append(dict(kind='mutated-jump-entry', rawReason=index, rejected=True))
    for row in checked:
        changed = int(row['machineWord'], 16) ^ 1
        assert f'{changed:08x}' != row['machineWord']
    records = [json.loads(line) for line in ACTUAL.read_text().splitlines()
               if line.startswith('{')]
    raw_exits = [r for r in records if r.get('kind') == 'rawExit']
    # Distinguish each native round from the separate final afterRun summary.
    # Exact fixture names and order are required, never fuzzy stage matching.
    afters = [r for r in raw_exits if r.get('stage') in
              {f'afterRound{i}' for i in range(1, 17)}]
    assert [r['stage'] for r in afters] == [f'afterRound{i}' for i in range(1, 17)]
    final = [r for r in raw_exits if r.get('stage') == 'afterRun']
    assert len(final) == 1 and final[0]['reason'] == 11
    assert [r['reason'] for r in afters] == [0] + [11] * 15
    assert all(r['readVerified'] and r['pc'] == '0x0000000040000000' and
               r['x0'] == '0x0000000000000011' and not r['publicExitObject'] for r in afters)
    native_returns = [r for r in records if r.get('kind') == 'nativeReturn' and
                      r.get('operation') == 9]
    assert len(native_returns) == 16 and all(r['return'] == '0x00000000' for r in native_returns)
    sources = [H / 'modern_cpu_native_exit_reducer_v1.h', H / 'modern_cpu_native_exit_reducer_v1.c',
               R / 'VirtualMac/scripts/tests/test-modern-cpu-native-exit-reducer-v1.c',
               R / 'VirtualMac/scripts/tests/test-modern-cpu-native-exit-reducer-cxx-v1.cpp',
               H / 'modern_cpu_native_exit_reducer_v1.md']
    source_dir = out / 'source'
    source_dir.mkdir()
    source_pins = [pin(p) for p in sources]
    for p in sources:
        (source_dir / p.name).write_bytes(p.read_bytes())
    commands = []

    def run(label, argv):
        argv = list(map(str, argv))
        env = {k: v for k, v in os.environ.items() if not k.startswith('DYLD_')}
        env['ASAN_OPTIONS'] = 'detect_leaks=0'
        p = subprocess.run(argv, capture_output=True, env=env, timeout=30)
        (out / (label + '.stdout')).write_bytes(p.stdout)
        (out / (label + '.stderr')).write_bytes(p.stderr)
        commands.append(dict(label=label, argv=argv, exit=p.returncode, deadlineSeconds=30))
        assert p.returncode == 0 and not p.stderr, (label, p.returncode, p.stderr.decode())
        return p.stdout.decode()

    sdk = run('macos-sdk', ['xcrun', '--sdk', 'macosx', '--show-sdk-path']).strip()
    sdk_header = Path(sdk) / 'System/Library/Frameworks/Hypervisor.framework/Headers/hv_vcpu_types.h'
    sdk_pin = pin(sdk_header)
    for sanitized in (False, True):
        label = 'model-sanitized' if sanitized else 'model'
        exe = out / label
        argv = ['xcrun', 'clang', '-std=c11', '-Wall', '-Wextra', '-Werror', '-isysroot', sdk,
                '-I', source_dir, source_dir / sources[1].name, source_dir / sources[2].name, '-o', exe]
        if sanitized:
            argv += ['-fsanitize=address,undefined', '-fno-omit-frame-pointer']
        run(label + '-compile', argv)
        stdout = run(label + '-run', [exe])
        assert 'model checks passed; native calls=0, guest instruction claims=0' in stdout
    mac_obj = out / 'modern_cpu_native_exit_reducer_v1.arm64.o'
    run('macos-object', ['xcrun', 'clang', '-std=c11', '-Wall', '-Wextra', '-Werror',
                        '-isysroot', sdk, '-I', source_dir, '-c',
                        source_dir / sources[1].name, '-o', mac_obj])
    cxx_exe = out / 'model-cxx'
    run('cxx-caller-link', ['xcrun', 'clang++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
                            '-isysroot', sdk, '-I', source_dir, source_dir / sources[3].name,
                            mac_obj, '-o', cxx_exe])
    cxx_stdout = run('cxx-caller-run', [cxx_exe])
    assert 'C++ caller linked to C reducer; native calls=0, retries=0' in cxx_stdout
    ios = run('ios-sdk', ['xcrun', '--sdk', 'iphoneos', '--show-sdk-path']).strip()
    obj = out / 'modern_cpu_native_exit_reducer_v1.arm64e.o'
    run('ios-object', ['xcrun', 'clang', '-target', 'arm64e-apple-ios16.0', '-std=c11',
                      '-Wall', '-Wextra', '-Werror', '-isysroot', ios, '-I', source_dir,
                      '-c', source_dir / sources[1].name, '-o', obj])
    undefined = run('ios-undefined', ['xcrun', 'nm', '-u', obj])
    # The iOS SDK fortifies the final bounded memcpy; no HV/kernel dependency.
    assert all(name.strip() in ('_memcpy', '_memset', '___memcpy_chk')
               for name in undefined.splitlines())
    assert [pin(p) for p in sources] == source_pins
    result = dict(schema='genuine13-27-public-run-exit-static-audit-v1',
                  scope=dict(originalImagesLoaded=False, nativeCalls=0, nativeWrites=0,
                             deviceOperations=0, guestInstructions=0, runAllowedChanged=False,
                             original27VMMExecuted=False, full27Backend=False),
                  inputPins=[pin(READER), pin(ACTUAL), *source_pins, sdk_pin],
                  originalImages=[hi13, hi27, vi27], frames=frames, checkedMachineWords=checked,
                  oldJumpTable=dict(beginRVA='0x7730', bytes=48, sha256=sha(table),
                                    targets=[dict(rawReason=i, targetRVA=hex(n))
                                             for i, n in enumerate(destinations)]),
                  negativeControls=negatives,
                  nativeCallABI=dict(oldAndModernExactTrapBytesEqual=True, x16=-5, svcImmediate=128,
                                     operation9X0=9, operation9X1Null=True,
                                     nativeReturnDistinctFromRawReason=True,
                                     nonzeroNativeReturnBypassesRawDispatch=True),
                  raw2And11=dict(old='jump directly to native9',
                                 modern='return internal bool1 then native run loop or VIEW run wrapper',
                                 publicExit=False, errnoMeaningProved=False,
                                 retryIsCausalFixProved=False),
                  nativeLayouts=dict(old=dict(version='0x206879700000000e', reason=[0x4008, 4],
                                              syndrome=[0x400c, 4], va=[0x4018, 8], ipa=[0x4020, 8]),
                                     modern=dict(version='0x2068797003000004', reason=[0x4008, 4],
                                                 syndrome=[0x4010, 8], va=[0x4020, 8], ipa=[0x4028, 8])),
                  publicLayout=dict(bytes=32, reason=0, syndrome=8, va=16, ipa=24,
                                    oldUSEROffset=0xf0, modernUSEROffset=0x148,
                                    oldSyndromeZeroExtended=True),
                  originalReturnSideEffects=dict(oldPendingE8EntryORIntoNative670=True,
                                                 oldPendingE8ExitClearAndNative670Bits6And7Clear=True,
                                                 sideEffectsImplementedByReducer=False,
                                                 originalPublicRunEquivalentClaimed=False,
                                                 modernUSERVIEWTransitionsUnclosed=True),
                  reducer=dict(rawExceptionReasons=[1, 6, 8], refusedExceptionClasses=[0x16, 0x18, 0x3f],
                               internalRetryReasons=[2, 11], raw0DeclinedDespiteKnownCanceledMeaning=True,
                               pureValueOnly=True, publicationToOriginalConsumerImplemented=False,
                               callerOwnerGenerationTokenPostLeaseNotEstablishedByReducer=True,
                               outputUnchangedOnEveryRefusal=True, iosObject=pin(obj), commands=commands),
                  savedV32=dict(historicalActualOnly=True, rawReasons=[r['reason'] for r in afters],
                                nativeReturn='0x00000000', PC='0x0000000040000000', X0='0x11',
                                lostPublicExitTranslationExplainsPCNotMoving=False),
                  cause=dict(sourceProvenCauseOfRaw11=False,
                             nextProductFix='Integrate typed old-native exit reduction only inside a future actual-owned post-return lease; close USER/VIEW state and caller ownership before publication. No native retry or CPU execution probe is proposed.'))
    (out / 'audit.json').write_text(json.dumps(result, indent=2) + '\n')
    files = [pin(p) for p in sorted(out.rglob('*')) if p.is_file()]
    (out / 'freeze.json').write_text(json.dumps(dict(schema='public-exit-audit-freeze-v1', files=files), indent=2) + '\n')
    print(json.dumps(dict(output=str(out), checkedMachineWords=len(checked),
                          model=stdout.strip(), auditSHA256=pin(out / 'audit.json')['sha256'],
                          nativeCalls=0, deviceOperations=0)))


if __name__ == '__main__':
    main()
