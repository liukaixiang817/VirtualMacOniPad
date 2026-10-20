#!/usr/bin/env python3
"""Finite independent DTR source and four-body review; read-only inputs."""
import argparse
import difflib
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import sys

sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
S = R / 'VirtualMac/vz/host'
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'


def pin(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def expand(path):
    return re.sub(r'^#include "(modern_cpu_kernel_lifecycle_v\d+\.c)"\s*$',
                  lambda match: expand(path.parent / match.group(1)).rstrip(),
                  path.read_text(), flags=re.M)


def normalized(text):
    text = re.sub(r'//[^\n]*', '', text)
    text = re.sub(r'^#include "modern_cpu_kernel_lifecycle_v\d+\.h"\s*$', '', text, flags=re.M)
    return '\n'.join(line.strip() for line in text.splitlines() if line.strip())


def signed(value, width):
    return value - (1 << width) if value & (1 << (width - 1)) else value


def branch(word, pc):
    if word & 0x7c000000 == 0x14000000:
        return pc + signed(word & 0x3ffffff, 26) * 4
    if word & 0xff000010 == 0x54000000 or word & 0x7e000000 == 0x34000000:
        return pc + signed((word >> 5) & 0x7ffff, 19) * 4
    if word & 0x7e000000 == 0x36000000:
        return pc + signed((word >> 5) & 0x3fff, 14) * 4
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    out = parser.parse_args().output.resolve()
    assert out.is_relative_to(N) and not out.exists()
    out.mkdir()
    source = N / 'cpu-dtr-factory-local-v21-attempt2/candidate.json'
    port = N / 'original27-dtr-methods-source-port-data-v1-attempt1/candidate.json'
    assert pin(source)['sha256'] == 'dfa21ad3c60329f70ebf758c489cbc0290120c220923e3446d96b27497b06091'
    assert pin(port)['sha256'] == '79fb62984d92de302abca18fb6d31f6d66bc127dea55c148f3edc6937f6e243d'
    sj, pj = json.loads(source.read_bytes()), json.loads(port.read_bytes())
    checked = {}

    def freeze(path):
        path = path.resolve()
        if str(path) in checked:
            return
        data = json.loads(path.read_bytes())
        rows = []
        def collect(value):
            if isinstance(value, dict):
                if {'path', 'bytes', 'sha256'} <= value.keys():
                    rows.append({key: value[key] for key in ('path', 'bytes', 'sha256')})
                else:
                    for child in value.values():
                        collect(child)
            elif isinstance(value, list):
                for child in value:
                    collect(child)
        collect(data)
        assert rows
        checked[str(path)] = dict(pin=pin(path), actualFiles=len(rows))
        for row in rows:
            actual = pin(row['path'])
            assert actual['bytes'] == row['bytes'] and actual['sha256'] == row['sha256'], row['path']
            assert actual['path'] == str(Path(row['path']).resolve())
        for row in rows:
            child = Path(row['path'])
            if child.name == 'freeze.json':
                freeze(child)

    freeze(source.parent / 'freeze.json')
    freeze(port.parent / 'freeze.json')
    old = expand(S / 'modern_cpu_kernel_lifecycle_v22.c')
    new = (S / 'modern_cpu_kernel_lifecycle_v23.c').read_text()
    stripped = new.replace('    uint64_t dtrRXV23, dtrTXV23;\n', '')
    stripped = stripped.replace('        cpu->dtrRXV23=cpu->dtrTXV23=0;\n', '')
    stripped = stripped.replace('#include "modern_cpu_kernel_dtr_v23.inc"\n', '')
    assert normalized(old) == normalized(stripped), 'unrelated lower lifecycle delta'
    (out / 'expanded-life22-to23.diff').write_text(''.join(difflib.unified_diff(
        old.splitlines(True), new.splitlines(True), fromfile='actual-expanded-Life22', tofile='actual-Life23')))
    lower = (S / 'modern_cpu_kernel_dtr_v23.inc').read_text()
    factory = (S / 'modern_cpu_native_public_factory_dtr_v21.inc').read_text()
    pending = (S / 'modern_cpu_kernel_pending_run_v14.inc').read_text()
    public = (S / 'modern_cpu_native_public_factory_v8.c').read_text()
    optional = (S / 'modern_cpu_optional_abi_v1.c').read_text()
    checks = {
        'exclusiveLowerCPUOperationBeforeCallback': lower.index('BeginCPUOperation(cpu)') < lower.index('DTRBoundaryV23(cpu,&q.identity'),
        'realRegistryOwnerEpochGenerationAndSlot': all(x in pending for x in ('CPUOwnedV5(cpu)', 'expectedVMEpoch', 'expectedCPUGeneration', 'expectedReturnedSlotWord', 'expectedPublicIdentity', 'mutationPoisoned')),
        'realMappedContextAndFullVersionBeforeBank': 'VM27CPUSelfMappedRangeV1' in lower and 'Version(cpu,r)' in lower,
        'secondOwnedVersionBoundaryBeforeSecondTXWrite': 's=DTRBoundaryV23(cpu,&q.identity,&lifecycle);\n    if(s==VZ_KERNEL_OK){cpu->dtrTXV23=q.value>>32;' in lower,
        'partialSoftwareWritePoison': 'if(s!=VZ_KERNEL_OK && receipt.actualSoftwareWrites)cpu->mutationPoisoned=true;' in lower,
        'factoryWithdrawsBothRealRegistriesOnPartialFailure': 'entry->published=false;entry->draining=true;' in factory and 'VZKernelCPUUnpublishIdentityV5(cpu)' in factory,
        'failedBorrowReleaseRetainsActualObjectInTLS': 'PublicDeferredBorrowV6=borrow' in public and 'PublicReleaseV6(borrow,status)' in factory,
        'publicReadPublishesOnlyAfterReleaseAndFreshOutputValidation': factory.index('PublicReleaseV6(borrow,status)') < factory.index('VM27CPUSelfWriteV1(NULL,out'),
        'RXNeverAssignedByDTRWrite': 'cpu->dtrRXV23=' not in lower,
        'actualCallocResetAndOnlySuccessfulDestroyClears': 'VZKernelCPU *cpu = calloc(1, sizeof(*cpu));' in new and 'if (!r->nativeReturn) {\n        Lock(&vm->mutex); cpu->live = false; cpu->nativeContext = 0;\n        cpu->dtrRXV23=cpu->dtrTXV23=0;' in new,
        'noNativeDTRTrapOrNativeContextProjection': 'nativeTrap(' not in lower and 'writeMemory' not in lower,
        'GetContextValidCPUHasExplicitNoreturnUnsupported': 'if(status==BadV1())return NULL;' in optional and '__builtin_trap();' in optional[optional.index('void *_hv_vcpu_get_context'):],
    }
    assert all(checks.values()), checks
    reader = N / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    spec = importlib.util.spec_from_file_location('dtr_peer_macho', reader)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    provider = module.MachO(Path(sj['provider']['path']).read_bytes())
    inherited = json.loads(Path(sj['inheritedCandidate']['path']).read_bytes())
    prior = module.MachO(Path(inherited['provider']['path']).read_bytes())
    assert provider.imports == prior.imports and len(provider.imports) == 71
    assert set(provider.exports) == set(prior.exports) | {
        '_VM27CPUFactoryAccessDTRV21', '_VM27VMMReadDTRV1', '_VM27VMMWriteDTRV1'}
    before_bytes = Path(pj['sourceImage']['path']).read_bytes()
    after_bytes = Path(pj['candidate']['path']).read_bytes()
    before, after = module.MachO(before_bytes), module.MachO(after_bytes)
    assert len(before_bytes) == len(after_bytes)
    assert before.uuid == after.uuid == '4a6a588d1afd30f5a64d6304eb79be0b'
    assert before.commands == after.commands and before.binds == after.binds
    assert before.imports == after.imports and before.sections == after.sections
    assert before.exports == after.exports and before.segments == after.segments
    recipe = json.loads(Path(pj['patchRecipe']['path']).read_bytes())
    assert recipe['importChanges'] == [] and recipe['newRequiredLoads'] == []
    allowed = set()
    methods = []
    for patch in recipe['codePatches']:
        start, end = patch['startRVA'], patch['endRVA']
        at = before.file(before.base + start)
        assert at == patch['originalFileOffset'] and before_bytes[at:at + end - start].hex() == patch['beforeHex']
        assert after_bytes[at:at + end - start].hex() == patch['afterHex']
        allowed.update(range(at, at + end - start))
        words = struct.unpack_from('<' + 'I' * ((end - start) // 4), after_bytes, at)
        is_write = patch['functionSignature'].startswith('void')
        lead = 1 if is_write else 0
        if is_write:
            assert words[0] == 0xaa0103e2  # Preserve full setter value in x2.
        assert words[lead] == 0xf9406c00  # Genuine this+0xd8 identity.
        assert (words[lead + 1] >> 5) & 0xffff == patch['semanticSelector']
        target = branch(words[lead + 2], start + 4 * (lead + 2))
        assert target == (0x296538 if is_write else 0x2964ac)
        methods.append(dict(startRVA=start, endRVA=end, identityOffset=0xd8,
                            selector=patch['semanticSelector'], commonResolverRVA=target))
    assert all(a == b or i in allowed for i, (a, b) in enumerate(zip(before_bytes, after_bytes)))
    direct_interior = []
    for section in before.sections:
        if not section['flags'] & 0x80000400:
            continue
        for offset in range(0, section['size'], 4):
            pc = section['va'] - before.base + offset
            word = struct.unpack_from('<I', before_bytes, section['fileoff'] + offset)[0]
            target = branch(word, pc)
            for method in methods:
                if target is not None and method['startRVA'] < target < method['endRVA'] and not method['startRVA'] <= pc < method['endRVA']:
                    direct_interior.append(dict(pc=pc, target=target))
    assert not direct_interior
    for pc, scale, offset, mask in [(0x2964e0, 4, 0x690, 0xb9400000),
                                    (0x296614, 8, 0x690, 0xf9400000),
                                    (0x296580, 8, 0x698, 0xf9000000),
                                    (0x2965c0, 8, 0x698, 0xf9000000),
                                    (0x296674, 8, 0x698, 0xf9000000)]:
        word = struct.unpack_from('<I', before_bytes, before.file(before.base + pc))[0]
        assert word & 0xffc00000 == mask and ((word >> 10) & 0xfff) * scale == offset
    model_records = {mode: json.loads((source.parent / f'{mode}-run.stdout').read_bytes())
                     for mode in ('normal', 'san')}
    assert all(result == sj['models'][mode] and result['checks'] == 689
               for mode, result in model_records.items())
    review = dict(schema='Finite DTR source and four original VMM methods independent review v1',
                  sourceCandidate=pin(source), sourceFreeze=pin(source.parent / 'freeze.json'),
                  portCandidate=pin(port), portFreeze=pin(port.parent / 'freeze.json'),
                  patchRecipe=pj['patchRecipe'], actualProvider=sj['provider'],
                  verifiedParentFreezes=list(checked.values()), sourceChecks=checks,
                  lowerFlatteningOnlyAddsOwnBankResetAndDTRInclude=True,
                  actualProviderExports=153, actualUnchangedNativeImports=71,
                  actualOriginalFourMethodEntryChecks=methods,
                  originalRXLow32Full64AndBothTXStoresIndependentlyDecoded=True,
                  actualAllBytesOutsideFourBodiesUnchanged=True,
                  directExternalInteriorBranchEntries=direct_interior,
                  actualUUIDHeaderSectionPACFixupImportsExportsUnchanged=True,
                  existingDlsymImportIndex=326, sourceProviderReplacesOneProductionRegistry=True,
                  existingParentNormalSANResultsReadAndHashVerified=model_records,
                  hostModelsRerun=False, deviceOperations=0, nativeOperations=0,
                  finiteLocalScopePassed=True, findings=[],
                  boundary='Only own software DTR bank and finite four-method source port. '
                           'No hardware RX producer, actual original execution, generic context layout, '
                           'asynchronous unwind validation or exhaustive indirect interior-entry proof. '
                           'Root must replace the one same-registry production provider and make its '
                           'actual two C exports visible before original DTR calls; final graph/signature/device validation remains required.')
    save(out / 'review.json', review)
    files = [pin(__file__), pin(out / 'review.json'), pin(out / 'expanded-life22-to23.diff'),
             pin(source), pin(source.parent / 'freeze.json'), pin(port), pin(port.parent / 'freeze.json'),
             pin(reader)]
    save(out / 'freeze.json', dict(schema='Finite DTR independent review freeze v1', files=files))
    print(json.dumps(dict(review=pin(out / 'review.json'), freeze=pin(out / 'freeze.json'),
                          sourceChecks=len(checks), findings=[])))


if __name__ == '__main__':
    main()
