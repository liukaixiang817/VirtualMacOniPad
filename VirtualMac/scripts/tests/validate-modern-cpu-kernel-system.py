"""Validate a real bounded native receipt; never starts a VM or a probe."""
import json
from pathlib import Path


def native_transcript(path, direct_pid, wait, *, native_isa=1):
    assert native_isa in (1, 2)
    assert direct_pid > 1 and wait == 0
    rows = [json.loads(line) for line in Path(path).read_text().splitlines()]
    def one(kind, **fields):
        found = [r for r in rows if r['kind'] == kind and all(r.get(k) == v for k, v in fields.items())]
        assert len(found) == 1, kind
        return found[0]
    scope = one('scope')
    assert scope['uid'] == scope['euid'] == 0 and scope['nativeContextWritesPlanned']
    assert scope['nativeGuestRunCalls'] == scope['mapCalls'] == 0
    assert not any(scope[k] for k in ('appleUSEROrVIEWConstructed', 'oldHypervisorFrameworkLoaded', 'publicExitABIImplemented'))
    assert one('kernelProfile')['matchesPinnedIPadOS1611']
    image = one('mainImage')
    assert image['headerValid'] and image['commandsValid'] and image['UUIDMatchesExactBuild'] and image['dyldMainIndex'] >= 0
    assert image['ownUUID'] == image['embeddedExpectedUUID'] == {1: '478acad398fd3c7fac62880b4dd44da4', 2: '66450ad8ec173fe7b6f1ac89cfb46743'}[native_isa]
    trap = one('trapBytes')
    assert trap['readValid'] and trap['exactWordsMatch'] and trap['sameActualMainImage']
    assert trap['actualWords'] == ['0x92800090', '0xd4001001', '0xd65f03c0']
    gate = one('imageGate')
    assert gate['trapInOwnExecutableAndExactBytes'] and gate['hypervisorOrVirtualizationImagesLoaded'] == gate['dlopenCalls'] == 0
    begins = [r for r in rows if r['kind'] == 'nativeBegin']
    returns = [r for r in rows if r['kind'] == 'nativeReturn']
    assert [r['operation'] for r in begins] == [r['operation'] for r in returns] == [1, 6, 7, 2]
    assert all(r['return'] == '0x00000000' for r in returns)
    assert begins[0]['thread'] == begins[3]['thread'] != begins[1]['thread'] == begins[2]['thread']
    assert [r['argumentsNull'] for r in begins] == [False, False, True, True]
    for stage in ('vmCreate', 'cpuCreate', 'cpuDestroy', 'vmDestroy'):
        event = one('lifecycle', stage=stage)
        assert event['status'] == 0 and event['nativeInvoked'] and event['nativeReturn'] == '0x00000000'
    create = one('lifecycle', stage='cpuCreate')
    destroy = one('lifecycle', stage='cpuDestroy')
    assert create['ownerThread'] == destroy['ownerThread'] == begins[1]['thread']
    assert create['generation'] == destroy['generation'] > 0
    assert create['returnedSlotWord'] == destroy['returnedSlotWord']
    assert create['contextVersionRead'] and create['contextVersion'] == '0x206879700000000e'
    assert not destroy['cpuLive'] and not one('lifecycle', stage='vmDestroy')['vmLive']
    receipts = [r for r in rows if r['kind'] == 'initReceipt']
    assert len(receipts) == 2 and all(not r['runAllowed'] and not r['architecturalResetComplete'] and not r['mutationPoisoned'] for r in receipts)
    policy = one('initReceipt', stage='defaultCreationPolicy')
    expected_writes = 7 if policy['policyBit4'] else 6
    assert policy['status'] == 0 and policy['policyBit4Read'] and policy['creationPolicySliceComplete']
    assert policy['completedWrites'] == policy['attemptedWrites'] == expected_writes
    rejected = one('initReceipt', stage='unimplementedRunExplicitlyRejected')
    assert rejected['status'] != 0 and rejected['attemptedWrites'] == rejected['completedWrites'] == 0
    observed = one('nativePolicyByteObserved')
    assert observed['nativeOffset'] == 0x4030 and observed['bytes'] == 1 and observed['readOnly'] is True
    assert isinstance(observed['fullByte'], int) and 0 <= observed['fullByte'] <= 255
    assert bool(observed['fullByte'] & 16) == policy['policyBit4']
    assert one('systemUnknownRejected') == {'kind': 'systemUnknownRejected', 'passed': True, 'readOutputUnchanged': True, 'nativeOp8Calls': 0}
    expected = [(0x8012, 1, 0x350, '0x0000000000000000', 1), (0xc080, 1, 0x400, '0x0000000000000001', 2), (0xc000, 3, 0x698, '0x0000000000000000', 4)]
    assert len([r for r in rows if r['kind'] == 'systemNativeWrite']) == 3
    assert len([r for r in rows if r['kind'] == 'systemNativeReadback']) == 3
    for selector, domain, offset, mask, count in expected:
        write = one('systemNativeWrite', selector=selector)
        assert write == {'kind': 'systemNativeWrite', 'selector': selector, 'domain': domain, 'nativeOffset': offset, 'mask': mask, 'status': 0, 'attemptedWrites': count, 'completedWrites': count, 'sameValue': True, 'passed': True, 'nativeOp8Invoked': False, 'completeModernSYSContract': False, 'runAllowed': False}
        assert one('systemNativeReadback', selector=selector) == {'kind': 'systemNativeReadback', 'selector': selector, 'status': 0, 'exact': True, 'passed': True}
    if native_isa == 1:
        assert one('requestedFeatureCache') == {'kind': 'requestedFeatureCache', 'freshEntriesRejected': 9, 'explicitEntriesSetAndRead': 9, 'nativeWrites': 0, 'hostCapabilitiesFabricated': False, 'old118ByteTableConstructed': False}
    else:
        assert policy['policyBit4'] is True and observed['fullByte'] == 19 and expected_writes == 7
        assert not any(r['kind'] == 'requestedFeatureCache' for r in rows)
    parity = one('policyParity')
    assert parity['passed'] and not any(parity[k] for k in ('policy4030Written', 'versionWritten', 'productionDirtyMaskCopied'))
    snapshots = [r for r in rows if r['kind'] == 'nativeSnapshot']
    assert len(snapshots) == 3 and all(r['fields'] == 78 and r['markersStable'] and r['passed'] for r in snapshots)
    writes = [r for r in rows if r['kind'] == 'ownCPUWrite']
    assert len(writes) == expected_writes+7 <= 14 and [r['ordinal'] for r in writes] == list(range(1, len(writes)+1))
    assert all(r['bytes'] == 8 and r['machWriteReturn'] == '0x00000000' and r['readBackExact'] and not r['contextAddressExposed'] for r in writes)
    final = one('systemParity')
    assert final['passed'] and final['78KnownFieldsExact'] and final['runRequestRejected']
    assert final['sameValueSystemSetters'] == 3 and final['systemStoreAttempts'] == 7 and final['writeAttempts'] == final['writeReadbackVerified'] == len(writes)
    assert final['nativeOp8Calls'] == final['nativeMapCalls'] == final['guestInstructions'] == 0 and not final['appleUSEROrVIEWConstructed']
    worker = one('worker')
    assert worker['pthreadCreateReturn'] == worker['pthreadJoinReturn'] == 0 and worker['defaultAttributes'] and not worker['appleVMMTLSModified']
    assert one('cpuHandleFree')['status'] == 0
    summary = one('summary')
    assert summary['kernelOnlySYSPASS' if native_isa == 1 else 'nativeISA2SystemPASS'] and summary['realCPUCreated'] and summary['realCPUDestroyed'] and summary['vmDestroyed']
    assert summary['vmHandleFreeStatus'] == summary['old13ImagesLoaded'] == summary['guestInstructionsExecuted'] == 0
    assert all(summary[k] == 1 for k in ('vmCreateCalls', 'vmDestroyCalls', 'cpuCreateCalls', 'cpuDestroyCalls'))
    assert not summary['original27VMMExecuted'] and not summary['complete27CPU']
    parent = one('parent')
    assert parent['childPID'] > 1 and parent['childPID'] != direct_pid and parent['childReaped'] and parent['strictPASS']
    assert parent['exitStatus'] == parent['signal'] == 0 and not parent['wallTimeout'] and not parent['cleanupClaimedOnTimeout']
    return {'passed': True, 'directParentPID': direct_pid, 'observedWaitExit': wait,
            'CPUChildPID': parent['childPID'], 'parent': parent, 'summary': summary,
            'system': final, 'nativeHVISA': native_isa, 'fullPolicy4030Byte': observed['fullByte'], 'policy': policy, 'nativeOperations': [1, 6, 7, 2],
            'complete27CPU': False, 'original27VMMExecuted': False}
