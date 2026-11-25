#!/usr/bin/env python3
"""Build the native Apple Account provider from the pinned CPU99 owner boundaries.

Preserves the native Hypervisor ABI and genuine VZ identity. Only a validated
per-VM handoff enables the scoped guest compatibility policy.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import runpy
import shlex
import subprocess

R = Path(__file__).resolve().parents[3]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', required=True, type=Path)
O = parser.parse_args().output.resolve()
O.mkdir(parents=True, exist_ok=False)
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
baseline = N / 'cpu-cross-wake-v99-attempt3'
old = json.loads((baseline / 'candidate.json').read_text())
objects = old['changedCPUObjects'] + old['inheritedCPUObjects']
commands = []


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def pin(path):
    p = Path(path).resolve()
    return dict(path=str(p), bytes=p.stat().st_size, sha256=sha(p))


def run(label, argv):
    argv = list(map(str, argv))
    p = subprocess.run(argv, capture_output=True, timeout=120)
    (O / (label + '.log')).write_bytes(p.stdout + p.stderr)
    commands.append(dict(label=label, argv=argv, exit=p.returncode))
    (O / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
    if p.returncode:
        raise RuntimeError(label + ': ' + p.stderr.decode(errors='replace')[-3500:])


def recipe(obj):
    parent = Path(obj['path']).parent
    rows = json.loads((parent / 'commands.json').read_text())
    return next(c['argv'][:] for c in rows if '-c' in c['argv'] and
                c['argv'][c['argv'].index('-o') + 1] == obj['path'])


for obj in objects:
    assert pin(obj['path']) == obj, obj['path']
bootstrap = next(o for o in objects if o['path'].endswith('/bootstrap30.o'))
factory = next(o for o in objects if o['path'].endswith('/factory-state.o'))
products = []
for oldobj, label in [(bootstrap, 'bootstrap'), (factory, 'factory')]:
    args = recipe(oldobj)
    preprocess = args.copy()
    if '-MMD' in preprocess: preprocess.remove('-MMD')
    if '-MF' in preprocess:
        at = preprocess.index('-MF'); del preprocess[at:at + 2]
    preprocess[preprocess.index('-c')] = '-E'
    preprocessed = O / (label + '-baseline' + ('.m' if label == 'bootstrap' else '.c'))
    preprocess[preprocess.index('-o') + 1] = preprocessed
    run('freeze-' + label, preprocess)
    text = preprocessed.read_text()
    if label == 'bootstrap':
        marker = 'hv_return_t hv_vm_map(void *host,hv_ipa_t ipa,size_t bytes,hv_memory_flags_t flags) {'
        assert text.count(marker) == 1
        text = text.replace(marker, '__attribute__((visibility("hidden"))) hv_return_t VMAppleAccountInheritedMapV1(void *host,hv_ipa_t ipa,size_t bytes,hv_memory_flags_t flags) {')
        probe = (R / 'VirtualMac/vz/apple-account/VMAppleAccountBootProbeV1.m').read_text()
        probe = probe.replace('hv_return_t status = VMAppleAccountInheritedMapV1(host, ipa, bytes, flags);', 'hv_return_t status = VMAppleAccountInheritedMapV1(host, ipa, bytes, flags);\n    if (!status) VMAppleAccountRecordMapV1(host, ipa, bytes, flags);')
        text += '\n__attribute__((visibility("hidden"))) void VMAppleAccountRecordMapV1(void *, uint64_t, size_t, uint64_t);\n' + probe
        for public, arguments, values, notify in [
            ('hv_vm_unmap', 'hv_ipa_t ipa,size_t bytes', 'ipa, bytes', 'VMAppleAccountRecordUnmapV1(ipa, bytes)'),
            ('hv_vm_protect', 'hv_ipa_t ipa,size_t bytes,hv_memory_flags_t flags', 'ipa, bytes, flags', 'VMAppleAccountRecordProtectV1(ipa, bytes, flags)')]:
            marker = 'hv_return_t ' + public + '(' + arguments + ') {'
            assert text.count(marker) == 1
            inherited = 'VMAppleAccountInherited' + public + 'V1'
            text = text.replace(marker, '__attribute__((visibility("hidden"))) hv_return_t ' + inherited + '(' + arguments + ') {')
            text += '\nextern __attribute__((visibility("hidden"))) void ' + notify.split('(')[0] + '(' + ('uint64_t, size_t' if public.endswith('unmap') else 'uint64_t, size_t, uint64_t') + ');\n'
            text += 'hv_return_t ' + public + '(' + arguments + ') { hv_return_t status = ' + inherited + '(' + values + '); if (!status) ' + notify + '; return status; }\n'
        source = O / 'bootstrap-probe.m'
        source.write_text(text)
    else:
        marker = 'hv_return_t hv_vcpu_run(hv_vcpu_t id) {'
        assert text.count(marker) == 1
        text = text.replace(marker, '__attribute__((visibility("hidden"))) hv_return_t VMAppleAccountInheritedRunV1(hv_vcpu_t id) {')
        mmio = '\ntypedef struct { _Bool valid; hv_vcpu_t cpu; uint64_t pa; uint32_t esr; } VMAppleAccountMMIOV1;\nstatic _Thread_local VMAppleAccountMMIOV1 VMAppleAccountPendingMMIOV1;\nextern __attribute__((visibility("hidden"))) _Bool VMAppleAccountBeforeRunV1(void);\nextern __attribute__((visibility("hidden"))) void VMAppleAccountRecordFirstCPUV1(uint64_t);\nextern __attribute__((visibility("hidden"))) void VMAppleAccountCPUResetV1(uint64_t, uint64_t);\nextern __attribute__((visibility("hidden"))) _Bool VMAppleAccountOverrideConfigReadV1(uint64_t, uint32_t, uint64_t, uint64_t *);\n'
        marker = '__attribute__((visibility("hidden"))) hv_return_t VMAppleAccountInheritedRunV1(hv_vcpu_t id) {'
        assert text.count(marker) == 1
        text = text.replace(marker, mmio + marker + '\n VMAppleAccountPendingMMIOV1.valid = 0; VMAppleAccountRecordFirstCPUV1(id); (void)VMAppleAccountBeforeRunV1();')
        marker = ' PublicEndV6();\n if(!status && producerInvoked && !canceled && r.publicExitProduced &&'
        assert text.count(marker) == 1
        observe = '\n if (!status && r.publicExitProduced && r.publicExit.reason == 1 &&\n     (r.publicExit.syndrome >> 26) == 0x24 && (r.publicExit.syndrome & (1U << 24)) &&\n     !(r.publicExit.syndrome & (1U << 6)) && r.publicExit.physicalAddress >= 0x400000 &&\n     r.publicExit.physicalAddress < 0x401000 && ((r.publicExit.syndrome >> 16) & 31) != 31)\n   VMAppleAccountPendingMMIOV1 = (VMAppleAccountMMIOV1){1, id, r.publicExit.physicalAddress, (uint32_t)r.publicExit.syndrome};\n'
        text = text.replace(marker, observe + marker)
        marker = 'hv_return_t hv_vcpu_set_reg(hv_vcpu_t cpu,hv_reg_t reg,uint64_t value) {'
        assert text.count(marker) == 1
        text = text.replace(marker, '__attribute__((visibility("hidden"))) hv_return_t VMAppleAccountInheritedSetRegV1(hv_vcpu_t cpu,hv_reg_t reg,uint64_t value) {')
        text += '\nhv_return_t hv_vcpu_set_reg(hv_vcpu_t cpu, hv_reg_t reg, uint64_t value) {\n  VMAppleAccountMMIOV1 *pending = &VMAppleAccountPendingMMIOV1;\n  if (pending->valid && pending->cpu == cpu && reg == ((pending->esr >> 16) & 31)) {\n    uint64_t replacement = value;\n    if (VMAppleAccountOverrideConfigReadV1(pending->pa, pending->esr, value, &replacement)) value = replacement;\n    pending->valid = 0;\n  }\n  hv_return_t status = VMAppleAccountInheritedSetRegV1(cpu, reg, value);\n  if (!status && reg == 31) VMAppleAccountCPUResetV1(cpu, value);\n  return status;\n}\n'
        text += '\n__attribute__((visibility("hidden"))) void VMAppleAccountBeforeRunProbeV1(void);\n'
        text += 'hv_return_t hv_vcpu_run(hv_vcpu_t id) { VMAppleAccountBeforeRunProbeV1(); return VMAppleAccountInheritedRunV1(id); }\n'
        source = O / 'factory-probe.c'
        source.write_text(text)
    output = O / (label + '.o')
    args[args.index('-c') + 1] = source
    args[args.index('-o') + 1] = output
    if '-MF' in args: args[args.index('-MF') + 1] = O / (label + '.d')
    run('compile-' + label, args)
    products.append(pin(output))

link = next(c['argv'][:] for c in json.loads((baseline / 'commands.json').read_text()) if c['label'] == 'link-cpu')
for original, replacement in zip([bootstrap, factory], products):
    assert link.count(original['path']) == 1
    link[link.index(original['path'])] = replacement['path']
lifecycle = next(o for o in objects if o['path'].endswith('/lifecycle-cross-wake.o'))
args = recipe(lifecycle)
source = Path(args[args.index('-c') + 1])
text = source.read_text()
text = runpy.run_path(str(R / 'VirtualMac/scripts/development/apple-account-cpu-source-v1.py'))['apply_native_features'](R, text)
marker = '     step->postReturnIdentityValidated=1;\n     VM27RunWakePostSnapshotV34(&access,&q,step);'
assert text.count(marker) == 1
hook = '\n     extern __attribute__((visibility("hidden"))) _Bool VMAppleAccountKernelPendingV1(void);\n     extern __attribute__((visibility("hidden"))) int VMAppleAccountEarlyKernelV1(uint64_t, const uint64_t[31], uint64_t, uint64_t);\n     if (VMAppleAccountKernelPendingV1()) {\n       uint64_t identityPC = 0;\n       if (GICPostFieldV20(&access, 0x108, 0, &identityPC) && (identityPC >> 40) == 0xfffffe) {\n         uint64_t identityRegisters[31] = {0};\n         _Bool identityRead = 1;\n         for (unsigned identityIndex = 0; identityIndex < 31 && identityRead; ++identityIndex)\n           identityRead = GICPostFieldV20(&access, 8 + 8 * identityIndex, 0, &identityRegisters[identityIndex]);\n         VZKernelLifecycleResult identityLifecycle = *access.init.lifecycle;\n         RunPostAccessV7 identityPost = *access.post; identityPost.lifecycle = &identityLifecycle;\n         PendingRunAccessV14 identityAccess = access;\n         identityAccess.init.lifecycle = &identityLifecycle; identityAccess.post = &identityPost;\n         VM27RunDiagnosticSYSV36 identitySYS = {.access=&identityAccess, .syncStatus=VZ_KERNEL_OK};\n         VZKernelInitAccess identityPort = {&identitySYS, VM27RunDiagnosticSYSReadV36, VM27RunDiagnosticSYSWriteV36};\n         VZKernelSysFeatureCache identityCache = {0};\n         const uint32_t identityIDs[2] = {0xc102, 0xc101};\n         uint64_t identitySystem[2] = {0};\n         for (unsigned identityIndex = 0; identityIndex < 2 && identityRead; ++identityIndex) {\n           VZKernelSysRequest identityRequest = {1, q.validatedKernelProfile, q.expectedOwnerThread,\n             q.expectedCPUGeneration, q.expectedReturnedSlotWord, q.nativeHVISA,\n             VZ_KERNEL_SYS_READ, identityIDs[identityIndex], 0};\n           VZKernelSysReceipt identityReceipt = {0};\n           identityRead = PendingRequestOwnedV14(identityAccess.init.cpu, &q) == VZ_KERNEL_OK &&\n             PendingBoundaryV14(&identityAccess) &&\n             VZKernelSysApplyVerifiedRouteV3(&identityRequest, &identityPort, &identityCache,\n               &identitySystem[identityIndex], &identityReceipt, VM27RunDiagnosticSYSSyncV36) == VZ_KERNEL_OK &&\n             PendingBoundaryV14(&identityAccess);\n         }\n         if (!identityRead || VMAppleAccountEarlyKernelV1(identityPC, identityRegisters, identitySystem[0], identitySystem[1]) < 0) {\n           GICPoisonV20(cpu);\n           status = VZ_KERNEL_CONTEXT_UNREADABLE;\n         }\n       }\n     }\n'
text = text.replace(marker, marker + hook)
source = O / 'lifecycle-early-identity.c'
source.write_text(text)
obj = O / 'lifecycle.o'
args[args.index('-c') + 1] = source
args[args.index('-o') + 1] = obj
args[args.index('-MF') + 1] = O / 'lifecycle.d'
run('compile-lifecycle', args)
assert link.count(lifecycle['path']) == 1
link[link.index(lifecycle['path'])] = obj
products.append(pin(obj))
for name in ['VMAppleAccountRuntimeV1.c', 'reference/legacy_vmm_policy.c', 'reference/legacy_dtree.c']:
    source = R / 'VirtualMac/vz/apple-account' / name
    obj = O / (source.stem + '.o')
    run('compile-' + source.stem, ['xcrun', '--sdk', 'iphoneos', 'clang', '-target', 'arm64e-apple-ios16.1',
        '-O2', '-Wall', '-Wextra', '-Werror', '-fvisibility=hidden', '-DVM_APPLE_ACCOUNT_OBSERVE_ONLY=0',
        '-c', source, '-o', obj])
    link.append(obj)
    products.append(pin(obj))
cpu = O / 'VM27HVVMProduction.dylib'
link[link.index('-o') + 1] = cpu
run('link-cpu', link)
run('validate-cpu', ['xcrun', 'dyld_info', '-validate_only', cpu])
(O / 'candidate.json').write_text(json.dumps(dict(cpu=pin(cpu), baseline=pin(baseline / 'candidate.json'),
    changedObjects=products, unchangedObjects=[o for o in objects if o not in [bootstrap, factory, lifecycle]],
    guestWrites=True, probeOnly=False), indent=2) + '\n')
print(cpu)
