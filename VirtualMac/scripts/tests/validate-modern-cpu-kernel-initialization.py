"""Validate a real bounded native receipt; never starts a VM or a probe."""
import json
from pathlib import Path


def native_transcript(path, direct_pid, wait):
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
    assert image['ownUUID'] == image['embeddedExpectedUUID'] == '6bf6f2812fcb3f809f83aa551713c2ba'
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
    assert len(receipts) == 7 and all(not r['runAllowed'] and not r['architecturalResetComplete'] and not r['mutationPoisoned'] for r in receipts)
    policy = one('initReceipt', stage='defaultCreationPolicy')
    expected_writes = 7 if policy['policyBit4'] else 6
    assert policy['status'] == 0 and policy['policyBit4Read'] and policy['creationPolicySliceComplete']
    assert policy['completedWrites'] == policy['attemptedWrites'] == expected_writes
    setters = [r for r in receipts if r['stage'] == 'typedOwnScalarOrSIMD']
    assert len(setters) == 5 and all(r['status'] == 0 and r['attemptedReads'] == 0 and r['attemptedWrites'] == r['completedWrites'] == 1 for r in setters)
    rejected = one('initReceipt', stage='unimplementedRunExplicitlyRejected')
    assert rejected['status'] != 0 and rejected['attemptedWrites'] == rejected['completedWrites'] == 0
    parity = one('policyParity')
    assert parity['passed'] and not any(parity[k] for k in ('policy4030Written', 'versionWritten', 'productionDirtyMaskCopied'))
    snapshots = [r for r in rows if r['kind'] == 'nativeSnapshot']
    assert len(snapshots) == 3 and all(r['fields'] == 78 and r['markersStable'] and r['passed'] for r in snapshots)
    writes = [r for r in rows if r['kind'] == 'ownCPUWrite']
    assert len(writes) == expected_writes+5 <= 12 and [r['ordinal'] for r in writes] == list(range(1, len(writes)+1))
    assert all(r['bytes'] in (4, 8, 16) and r['machWriteReturn'] == '0x00000000' and r['readBackExact'] and not r['contextAddressExposed'] for r in writes)
    final = one('initializationParity')
    assert final['passed'] and final['78KnownFieldsExact'] and final['runRequestRejected']
    assert final['scalarWrites'] == 3 and final['simdWrites'] == 2 and final['writeAttempts'] == final['writeReadbackVerified'] == len(writes)
    assert final['nativeOp8Calls'] == final['nativeMapCalls'] == final['guestInstructions'] == 0 and not final['appleUSEROrVIEWConstructed']
    worker = one('worker')
    assert worker['pthreadCreateReturn'] == worker['pthreadJoinReturn'] == 0 and worker['defaultAttributes'] and not worker['appleVMMTLSModified']
    assert one('cpuHandleFree')['status'] == 0
    summary = one('summary')
    assert summary['kernelOnlyInitializationPASS'] and summary['realCPUCreated'] and summary['realCPUDestroyed'] and summary['vmDestroyed']
    assert summary['vmHandleFreeStatus'] == summary['old13ImagesLoaded'] == summary['guestInstructionsExecuted'] == 0
    assert all(summary[k] == 1 for k in ('vmCreateCalls', 'vmDestroyCalls', 'cpuCreateCalls', 'cpuDestroyCalls'))
    assert not summary['original27VMMExecuted'] and not summary['complete27CPU']
    parent = one('parent')
    assert parent['childPID'] > 1 and parent['childPID'] != direct_pid and parent['childReaped'] and parent['strictPASS']
    assert parent['exitStatus'] == parent['signal'] == 0 and not parent['wallTimeout'] and not parent['cleanupClaimedOnTimeout']
    return {'passed': True, 'directParentPID': direct_pid, 'observedWaitExit': wait,
            'CPUChildPID': parent['childPID'], 'parent': parent, 'summary': summary,
            'initialization': final, 'policy': policy, 'nativeOperations': [1, 6, 7, 2],
            'complete27CPU': False, 'original27VMMExecuted': False}
