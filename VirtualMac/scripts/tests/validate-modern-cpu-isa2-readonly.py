"""Validate bounded native ISA 2 observations without admitting CPU execution."""
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
    assert scope['uid'] == scope['euid'] == 0 and scope['nativeContextWritesPlanned'] is False
    assert scope['nativeGuestRunCalls'] == scope['mapCalls'] == 0
    assert not any(scope[k] for k in ('appleUSEROrVIEWConstructed', 'oldHypervisorFrameworkLoaded', 'publicExitABIImplemented'))
    assert one('kernelProfile')['matchesPinnedIPadOS1611']
    image = one('mainImage')
    assert image['headerValid'] and image['commandsValid'] and image['UUIDMatchesExactBuild'] and image['dyldMainIndex'] >= 0
    assert image['ownUUID'] == image['embeddedExpectedUUID'] == '8019547a37933c3db1ed55d58fe2bda0'
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
    snapshots = [r for r in rows if r['kind'] == 'nativeSnapshot']
    assert [r['stage'] for r in snapshots] == ['beforeReadOnlyProfile', 'afterReadOnlyProfile']
    assert all(r['fields'] == 78 and r['markersStable'] and r['passed'] for r in snapshots)
    raw = [r for r in rows if r['kind'] == 'rawKernelMetadata']
    assert [r['nativeOffset'] for r in raw] == [0x4028, 0x4030, 0x4038, 0x4100, 0x670, 0x678, 0x748]
    for event in raw:
        assert event['nativeHVISA'] == 2 and event['bytes'] == event['copied'] == 8
        assert event['machReadReturn'] == '0x00000000' and event['valid'] and event['readOnly']
        assert event['semanticEnumNamesKnown'] is event['contextPointerExposed'] is False
        assert isinstance(event['value'], str) and len(event['value']) == 18 and event['value'].startswith('0x')
        assert 0 <= int(event['value'], 16) < 2**64
    profile = one('readOnlyProfile')
    assert profile['nativeHVISA'] == 2 and profile['passed'] and profile['ownerVerified']
    assert profile['generation'] == create['generation'] and profile['returnedSlotWord'] == create['returnedSlotWord']
    assert profile['versionStable'] and profile['version'] == '0x206879700000000e' and profile['78KnownFieldsExact']
    assert type(profile['fullPolicy4030Byte']) is int and 0 <= profile['fullPolicy4030Byte'] <= 255
    assert profile['fullPolicy4030Byte'] == int(raw[1]['value'], 16) & 255
    assert profile['policyBit4'] is bool(profile['fullPolicy4030Byte'] & 16)
    assert all(profile[k] == 0 for k in ('nativeContextWrites', 'nativeOp8Calls', 'nativeMapCalls', 'nativeRunCalls'))
    assert profile['SYSOrInitializationInvoked'] is profile['AArch64ISAEnumMeaningProved'] is False
    assert not any(r['kind'] in ('ownCPUWrite', 'initReceipt', 'systemNativeWrite', 'systemNativeReadback') for r in rows)
    worker = one('worker')
    assert worker['pthreadCreateReturn'] == worker['pthreadJoinReturn'] == 0 and worker['defaultAttributes'] and not worker['appleVMMTLSModified']
    assert one('cpuHandleFree')['status'] == 0
    summary = one('summary')
    assert summary['nativeISA2ReadOnlyPASS'] and summary['realCPUCreated'] and summary['realCPUDestroyed'] and summary['vmDestroyed']
    assert summary['vmHandleFreeStatus'] == summary['old13ImagesLoaded'] == summary['guestInstructionsExecuted'] == 0
    assert all(summary[k] == 1 for k in ('vmCreateCalls', 'vmDestroyCalls', 'cpuCreateCalls', 'cpuDestroyCalls'))
    assert not summary['original27VMMExecuted'] and not summary['complete27CPU']
    parent = one('parent')
    assert parent['childPID'] > 1 and parent['childPID'] != direct_pid and parent['childReaped'] and parent['strictPASS']
    assert parent['exitStatus'] == parent['signal'] == 0 and not parent['wallTimeout'] and not parent['cleanupClaimedOnTimeout']
    return {'passed': True, 'directParentPID': direct_pid, 'observedWaitExit': wait,
            'CPUChildPID': parent['childPID'], 'parent': parent, 'summary': summary,
            'readOnlyProfile': profile, 'rawKernelMetadata': raw, 'nativeOperations': [1, 6, 7, 2],
            'complete27CPU': False, 'original27VMMExecuted': False}
