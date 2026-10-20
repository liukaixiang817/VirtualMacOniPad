#!/usr/bin/env python3
"""Audit the real 252-byte Metal callback capture without loading any image."""
import argparse
import importlib.util
import json
from pathlib import Path
import struct
import sys
import warnings
sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
spec = importlib.util.spec_from_file_location('metal_nil_plan', HERE/'plan-modern-metal-native-nil-downstream-v1.py')
t = importlib.util.module_from_spec(spec); spec.loader.exec_module(t)
with warnings.catch_warnings():
    warnings.simplefilter('ignore', UserWarning)
    from capstone import Cs, CS_ARCH_ARM64, CS_MODE_ARM
p, d, N = t.p, t.d, t.N


def words(raw): return list(struct.unpack('<'+'I'*(len(raw)//4), raw))


def branch_target(raw, base, offset, mask=0x94000000):
    word = struct.unpack_from('<I', raw, offset)[0]
    assert word & 0xfc000000 == mask
    immediate = word & 0x3ffffff
    if immediate & 0x2000000: immediate -= 1 << 26
    return base+offset+immediate*4


def complete_callback(raw):
    assert len(raw) == 144
    actual = words(raw)
    # All control/data-flow words used in the finite nil and index-zero result
    # proof are checked. Callee names are deliberately not invented.
    # Indices below are literal instruction indices, rather than byte offsets.
    fixed = {0:0xd503237f,4:0xaa0003f3,6:0xf9460680,7:0x9406130e,
             8:0xb4000180,10:0x9406130b,11:0xf100041f,12:0x54000161,
             14:0xd2800002,16:0x95468499,17:0xf9401268,18:0xf9400508,19:0xf9001500,
             22:0xd65f0fff,35:0x140355c9}
    assert all(actual[index] == word for index, word in fixed.items())
    base = 0x181b1caec
    assert branch_target(raw, base, 28) == branch_target(raw, base, 40) == 0x181ca1740
    assert branch_target(raw, base, 60) == 0x181ca8d80
    assert branch_target(raw, base, 64) == 0x186cbdd90
    assert branch_target(raw, base, 140, 0x14000000) == 0x181bf229c
    cbz = actual[8]
    immediate = (cbz >> 5) & 0x7ffff
    if immediate & (1 << 18): immediate -= 1 << 19
    assert base+32+immediate*4 == base+80
    conditional = actual[12]
    immediate = (conditional >> 5) & 0x7ffff
    if immediate & (1 << 18): immediate -= 1 << 19
    assert base+48+immediate*4 == base+92
    return dict(getterIsland=0x181ca1740, indexZeroIsland=0x181ca8d80,
        getterNameAndTypeValidated=False, indexGetterNameAndTypeValidated=False,
        zeroGetterReturnSkipsByrefResultWrite=True, resultInitiallyNil=True,
        getterExactlyOnePassesLiteralIndexZero=True,
        getterOtherNonzeroTakesOriginalAssertion=True, originalAssertionTail=0x181bf229c,
        indexZeroResultCallsUnidentifiedCallee=0x186cbdd90,
        indexZeroResultThenStoredThroughForwardingAtByrefOffset=40,
        unidentifiedCalleeProvenRetain=False, actualDeviceListOrIOServiceQueryProven=False)


def auth_stub(raw, base):
    assert len(raw) == 16
    address = t.literal_pair(raw, base, 0, 17)
    assert words(raw)[2:] == [0xf9400230,0xd71f0a11]
    return dict(address=base, GOTSlot=address, branchInstruction='BRAA x16,x17',
                authenticatedKey='IA', addressModifierRegister=17,
                actualGOTWordRead=False, actualTargetOrNamedBindingValidated=False)


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('--output', type=Path, required=True)
    out = ap.parse_args().output.resolve(); assert out.is_relative_to(N) and not out.exists(); out.mkdir()
    plan = N/'ipad-current-metal-native-nil-downstream-plan-v1'
    capture = N/'ipad-current-metal-native-nil-downstream-readonly-v1'
    pins = d.original_freeze(plan/'freeze.json')
    declaration = d.strict_json(plan/'derivation.json')
    hp = Path(declaration['headers']['path']); assert p.pin(hp) == declaration['headers']
    receipt = d.f.s.checked_capture(capture, plan/'request.json', hp)
    assert receipt['requestedBytes'] == 252 and receipt['requestedRanges'] == 8
    assert receipt['readerSHA256'] == p.pin(capture/'reader-source.py')['sha256'] == declaration['reader']['sha256']
    heads = d.strict_json(hp); involved = {'main'} | {x['cache'] for x in receipt['ranges']}
    assert involved == {'main','01','27-data'}
    script = (capture/'script.sh').read_text()
    assert all(script.count(x['sha256']) == 2 for x in heads['headers'] if x['name'] in involved)
    material, decoded = {}, []
    md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
    for declared, actual in zip(declaration['actualExactRequestDerivations'], receipt['ranges']):
        assert all(actual[k] == declared['request'][k] for k in ('name','cache','offset','length'))
        assert t.mapping(heads, declared['VA'], actual['length']) == {k:actual[k] for k in ('cache','offset','length')}
        path = Path(actual['path']); raw = path.read_bytes(); material[actual['name']] = raw
        pins.append(p.pin(path))
        rows = []
        if declared['kind'] in ('function','stub'):
            for at in range(0,len(raw),4):
                instructions = list(md.disasm(raw[at:at+4], declared['VA']+at))
                if instructions:
                    ins = instructions[0]; rows.append(dict(VA=ins.address, word=raw[at:at+4].hex(), mnemonic=ins.mnemonic, operands=ins.op_str))
                else:
                    rows.append(dict(VA=declared['VA']+at, word=raw[at:at+4].hex(), decoderUnsupported=True))
        decoded.append(dict(name=actual['name'], VA=declared['VA'], input=p.pin(path),
                            completeDeclaredExtent=declared['extent'], rawHex=raw.hex(), instructions=rows))
    callback = material['metal-native-default-result-block-complete']
    proof = complete_callback(callback)
    native_body = Path(declaration['originalCurrentNativeBody']['path']).read_bytes()
    assert words(native_body)[23] == 0xa9057ff0  # stp x16,xzr: zero byref result +0x28
    copy = material['metal-native-default-byref-copy-complete']
    destroy = material['metal-native-default-byref-destroy-complete']
    assert words(copy) == [0x9100a000,0xf9401421,0x52801062,0x15443eb8]
    assert words(destroy) == [0xf9401400,0x52801061,0x15443eb9]
    copy_target = branch_target(copy,0x181bad774,12,0x14000000)
    destroy_target = branch_target(destroy,0x181bad784,8,0x14000000)
    assert (copy_target,destroy_target) == (0x186cbd260,0x186cbd270)
    stubs = [auth_stub(material[name], va) for name, va in (
        ('metal-native-default-call1-auth-stub',0x181c14c30),('metal-native-default-once-auth-stub',0x181c14b30))]
    assert [x['GOTSlot'] for x in stubs] == [0x1e22d9c18,0x1e22d9ab8]
    block = material['metal-native-default-once-global-block']
    isa, flags, reserved, invoke, descriptor = struct.unpack('<QIIQQ',block)
    assert reserved == 0 and flags == 0x50000000 and invoke == 0x8009000001b19b30
    assert material['metal-native-default-block-word-2c'] == struct.pack('<2I',0x52000000,48)
    assert material['metal-native-default-block-word-84'] == struct.pack('<2I',0xc0000000,0)
    negatives = []
    for label, index in [('getter branch',8),('one-element comparison',11),('assert branch',12),
                          ('literal index',14),('result store',19),('result forwarding',18),('PAC return',22)]:
        damaged = bytearray(callback); struct.pack_into('<I',damaged,index*4,words(callback)[index]^1)
        try: complete_callback(bytes(damaged))
        except AssertionError: negatives.append(dict(name=label,rejected=True))
        else: raise AssertionError('accepted damaged nil callback '+label)
    for row, stub in zip(stubs, ['metal-native-default-call1-auth-stub','metal-native-default-once-auth-stub']):
        damaged = bytearray(material[stub]); damaged[15] ^= 1
        try: auth_stub(bytes(damaged),row['address'])
        except AssertionError: negatives.append(dict(name='auth branch '+stub,rejected=True))
        else: raise AssertionError('accepted changed authentication branch')
    report = dict(schema='Actual native Metal finite nil callback and lifetime byte audit v1',
        actualReceipt=p.pin(capture/'receipt.json'), actualCurrentHeaders=p.pin(hp),
        actualBeforeAfterGuardedMembers=sorted(involved), fullPossibleFourteenMemberListWasRead=False,
        exact252BytesAllCurrentReceiptsAndMappingsVerified=True, originalPlan=p.pin(plan/'request.json'),
        actualCompleteByteExtents=decoded, finiteResultCallback=proof,
        byrefLifetime=dict(copyBodyBytes=16,destroyBodyBytes=12,ownResultOffset=40,actualLiteralFlags=131,
                          copyDirectTail=copy_target,destroyDirectTail=destroy_target,
                          namedBlockLifetimeCalleesValidated=False),
        actualAuthStubs=stubs, actualGlobalBlockPrefix=dict(ISA=hex(isa),flags=flags,
            invokeWord=hex(invoke),descriptorWord=hex(descriptor),actualMappingSlideHeaderRead=False,
            slideChainMembershipProven=False,initializationInvokeTargetDecoded=False),
        negativeControls=negatives, deviceGPUAbsenceProven=False, selectorAbsenceProven=False,
        specificPermissionFailureProven=False, currentNativeServiceQueryContractProven=False,
        originalVZCallerExecuted=False, candidateReadyForNativeLoading=False,
        nativeCPUCalls=0, nativeVMCalls=0, deviceOperations=0, full27Backend=False)
    p.save(out/'audit.json',report)
    pins += [p.pin(x) for x in (Path(__file__), plan/'derivation.json', plan/'request.json', hp,
        capture/'receipt.json', capture/'manifest.json', capture/'reader-source.py', capture/'script.sh',
        capture/'stdout',capture/'stderr', out/'audit.json')]
    dedup = {x['path']:x for x in pins}; assert all(dedup[x['path']] == x for x in pins)
    p.save(out/'freeze.json',dict(files=list(dedup.values()),deviceOperations=0))
    print(json.dumps(dict(audit=p.pin(out/'audit.json'),freeze=p.pin(out/'freeze.json'),negativeControls=len(negatives))))


if __name__ == '__main__': main()
