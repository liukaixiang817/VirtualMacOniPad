#!/usr/bin/env python3
"""Finite HOST-only peer of the genuine factory/RuntimeV5 ownership delta."""
import hashlib
import json
import pathlib

R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S = R / 'VirtualMac/vz/host'

def pin(path):
    path = pathlib.Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

def exact(row):
    assert pin(row['path']) == {key: row[key] for key in ('path', 'bytes', 'sha256')}, row['path']
    return pathlib.Path(row['path'])

def main():
    candidate = N / 'independent27-runtime-v5-factory-attestation-source-v1-attempt1/candidate.json'
    data = json.loads(candidate.read_bytes())
    freeze = candidate.parent / 'freeze.json'
    for row in json.loads(freeze.read_bytes())['files']:
        exact(row)
    runtime = exact(data['runtimeSource']).read_text()
    old_runtime = (S / 'vm27_independent_app_runtime_v4.m').read_text()
    assert runtime == old_runtime.replace('#include "vm27_independent_app_runtime_v2.m"',
        '#include "vm27_independent_app_runtime_v5_owner.inc"')
    owner = exact(data['runtimeOwnerSource']).read_text()
    old_owner = (S / 'vm27_independent_app_runtime_v2.m').read_text()
    anchor_start = ' NSDictionary *image=nil;NSString *fileID=nil;'
    anchor_end = ' if(failure || definition!=(__bridge void *)cls)return RefuseV1(error,@"The registered VM class differs from the actual strong export.");\n'
    def anchored(text):
        start = text.index(anchor_start)
        return text[start:text.index(anchor_end, start) + len(anchor_end)]
    assert anchored(owner) == anchored(old_owner)
    bind_start = 'BOOL VM27IndependentAppRuntimeBindGuestV1(id vm,dispatch_queue_t queue,NSError **error)'
    assert owner[owner.index(bind_start):] == old_owner[old_owner.index(bind_start):]
    assert 'if(!cls || !vm)' in owner
    assert 'object_getClass(vm)!=cls' not in owner
    assert owner.index(anchor_end) < owner.index('return VM27UIKitActualVirtualMachineAttestedV2(vm,cls,error);')
    assert 'actual-vm-class object=' in owner and 'actual-vm-strong-class original=' in owner

    factory = exact(data['factorySource']).read_text()
    old_factory = (S / 'vm27_uikit_guest_display_v1.mm').read_text()
    suffix = '@interface VM27UIKitMetalDisplayV1 : UIView'
    assert factory[factory.index(suffix):] == old_factory[old_factory.index(suffix):]
    assert 'static __weak id ActualFactoryVMV2;' in factory
    assert 'NSKVONotifying_' not in factory and 'object_setClass(' not in factory
    create = factory[factory.index('id VM27UIKitCreateActualVirtualMachineV1('):factory.index(suffix)]
    query = factory[factory.index('BOOL VM27UIKitActualVirtualMachineAttestedV2('):factory.index('id VM27UIKitCreateActualVirtualMachineV1(')]
    for token in ('!NSThread.isMainThread', 'ActualFactoryPIDV2!=getpid()', 'id prior=ActualFactoryVMV2;',
                  'object_getClass(allocated)!=cls', '(__bridge const void *)vm!=allocatedIdentity',
                  'class_getInstanceSize(actual)!=384', 'FactoryClassChainV2(actual,cls)',
                  'method_getImplementation(initializer)!=originalInitializer',
                  'VM27GenuineDisplayClassProfileAvailableV1(error)', 'VM27GenuineDisplayProfileAvailableV1(vm,error)'):
        assert token in create, token
    assert create.index('VM27GenuineDisplayProfileAvailableV1(vm,error)') < create.index('ActualFactoryVMV2=vm;')
    assert create.index('id allocated=[cls alloc];') < create.index('id vm=[allocated initWithConfiguration:configuration queue:dispatch_get_main_queue()];')
    for token in ('ActualFactoryPIDV2!=getpid()', 'id owner=ActualFactoryVMV2;', 'owner!=vm',
                  'ActualFactoryOriginalClassV2!=original', 'actual!=ActualFactoryReturnedISAV2',
                  'class_getInstanceSize(actual)!=384', 'class_getInstanceSize(original)!=384',
                  'method_getImplementation(initializer)!=ActualFactoryInitializerV2',
                  'VM27GenuineDisplayProfileAvailableV1(vm,error)'):
        assert token in query, token
    assert 'actual && depth<8' in factory
    assert 'Class next=class_getSuperclass(actual);if(next==actual)return NO;' in factory
    header = exact(data['typedHeader']).read_text()
    assert 'extern "C" {' in header and 'visibility("hidden")' in header
    assert 'id vm, Class originalClass, NSError * _Nullable * _Nullable error' in header
    assert 'Query only:' in header
    tools = data['actualIOSTools']
    assert len(tools) == 2
    for tool in tools:
        assert tool['exit'] == 0 and '-Werror' in tool['argv'] and '-fobjc-arc' in tool['argv']
        assert tool['argv'][tool['argv'].index('-target') + 1] == 'arm64e-apple-ios16.1'
        exact(tool['object']); exact(tool['stdout']); exact(tool['stderr']); exact(tool['nm']); exact(tool['undefined'])
        assert exact(tool['stderr']).stat().st_size == 0
    symbol = '_VM27UIKitActualVirtualMachineAttestedV2'
    assert symbol in exact(tools[0]['undefined']).read_text()
    definition_line = next(line for line in exact(tools[1]['nm']).read_text().splitlines() if line.endswith(' ' + symbol))
    assert 'private external' in definition_line and 'undefined' not in definition_line
    assert data['actualAppLinked'] is False and data['codeSigned'] is False
    assert data['attestationContract']['freshAppSingleVMLimit'] is True
    assert data['attestationContract']['repeatStartWithinSameAppImplemented'] is False
    old_log_receipt = json.loads(exact(data['actualObservedBindingFailureReadonly']).read_bytes())
    assert old_log_receipt['transportExit'] == 0
    actual(old_log_receipt['stdout'])
    out = N / 'independent27-runtime5-factory-attestation-independent-peer-v1-attempt1'
    out.mkdir(mode=0o700)
    report = dict(schema='Finite independent genuine factory exact-object RuntimeV5 source peer v1',
        sourceCandidate=pin(candidate), sourceFreeze=pin(freeze), sources=[data[key] for key in
            ('runtimeSource', 'runtimeOwnerSource', 'factorySource', 'typedHeader')],
        actualBindingFailureReadonly=data['actualObservedBindingFailureReadonly'],
        runtime4BootstrapAndAllExistingSignatureManifestLoadAndParentChecksWholePreserved=True,
        runtime2OriginalStrongClassExportCanonicalImageAndUUIDChecksWholePreserved=True,
        originalRuntimeBindMutexMainQueueAndBoundVMChecksWholePreserved=True,
        noGuessedKVOClassOrArbitrarySubclassAdmission=True,
        realOriginalAllocationAndSameObjectNativeInitializerBeforeWeakOwnerPublication=True,
        exactLiveWeakObjectReturnedISAOriginalClassPIDMainAndInitializerRequired=True,
        originalAndReturnedISAInstanceSizeRequired=384, actualAncestryMaximum=8,
        realProfileRecheckedAtQuery=True, weakOwnerCannotKeepStoppedVMAliveOrAdmitReusedAddress=True,
        unchangedMetalDisplayAndObserverLifecycleWholeBytes=True,
        actualBothIOSARCWerrorCompilesAndHiddenUnmangledCJoinVerified=True,
        freshAppSingleVMLimit=True, repeatStartWithinSameAppImplemented=False,
        modelsOrNativeCapturesRepeated=False, actualOriginalVZExecutedByThisPeer=False,
        actualDynamicClassNameObserved=False, actualGuestStarted=False, actualVisibleGuest=False,
        codeSigningOperations=0, deviceOperations=0, findings=[], finiteLocalScopePassed=True,
        readyForActualAppLinkAndFiniteProductReview=True)
    (out / 'review.json').write_text(json.dumps(report, indent=2) + '\n')
    rows = [pin(__file__), pin(candidate), pin(freeze)] + report['sources'] + [
        pin(S / 'vm27_independent_app_runtime_v4.m'), pin(S / 'vm27_independent_app_runtime_v2.m'),
        pin(S / 'vm27_uikit_guest_display_v1.mm'), data['actualObservedBindingFailureReadonly'],
        old_log_receipt['stdout']] + [tool[key] for tool in tools for key in
            ('object', 'stdout', 'stderr', 'nm', 'undefined')] + [pin(out / 'review.json')]
    (out / 'freeze.json').write_text(json.dumps(dict(files=rows, deviceOperations=0), indent=2) + '\n')
    print(json.dumps(dict(review=pin(out / 'review.json'), freeze=pin(out / 'freeze.json'), findings=[])))

# Alias keeps the review's actual pin reader explicit at the receipt boundary.
actual = exact

if __name__ == '__main__':
    main()
