"""Audit existing native sandbox bytes and freeze a finite adapter contract; no device I/O."""
import hashlib
import json
from pathlib import Path
import re
import struct
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
NODE = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OUT = NODE / 'ipad-native-sandbox-apply-abi-host-audit-v1-attempt1'
CAPTURE = NODE / 'ipad-current-native-sandbox-code-readonly-v1'
AUDIT = NODE / 'ipad-current-native-sandbox-code-host-audit-v1-attempt2'
SDK = Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX27.0.sdk/usr/include')


def pin(path):
    b = path.read_bytes()
    return dict(path=str(path.resolve()), bytes=len(b), sha256=hashlib.sha256(b).hexdigest())


def dump(path, x):
    path.write_text(json.dumps(x, indent=2) + '\n')


def main():
    receipt = json.loads((CAPTURE / 'receipt.json').read_bytes())
    assert receipt['transportExit'] == 0 and receipt['deviceWrites'] == 0
    assert receipt['allHeaderPinsMatchBeforeAndAfter'] is True
    data_path = CAPTURE / 'sandbox-compiler-text.bin'
    data = data_path.read_bytes()
    assert len(data) == 12288 and pin(data_path)['sha256'] == 'cb07d03ed245f3fa283b5285a7dabc8ca677d0ce64ee5e2483440d4e8a32e9dc'
    actual = next(r for r in receipt['ranges'] if Path(r['path']) == data_path)
    assert actual['sha256'] == pin(data_path)['sha256']
    text_path = AUDIT / 'sandbox-compiler-text-disassembly.txt'
    lines = text_path.read_text().splitlines()
    instructions = {}
    for line in lines:
        m = re.match(r'^([0-9a-f]+):\s+([0-9a-f]{8})\s+(.*)$', line)
        if m:
            instructions[int(m[1], 16)] = (int(m[2], 16), m[3])
    base = 0x1d4f4d000
    decoded = []
    for va in range(base + 0x24fc, base + 0x2598, 4):
        word = struct.unpack_from('<I', data, va - base)[0]
        assert instructions[va][0] == word
        decoded.append(dict(VA=hex(va), word=f'{word:08x}', llvmDecode=instructions[va][1]))
    expected = {0x250c:0xf9400008, 0x2510:0xb40000e8, 0x2514:0xa90007e8,
                0x252c:0xa940a408, 0x2530:0xa90027e8, 0x2534:0xf9000be1,
                0x2568:0xd2800008, 0x256c:0xf9000fe8, 0x2578:0x910003e2,
                0x257c:0x52800001, 0x2580:0x94215a0c,
                0x2590:0xd2800001, 0x2594:0x17ffffda}
    for off, word in expected.items():
        assert struct.unpack_from('<I', data, off)[0] == word
    def signed(x,bits):
        return x-(1<<bits) if x&(1<<(bits-1)) else x
    assert base+0x2594 + signed(0x17ffffda & 0x3ffffff,26)*4 == base+0x24fc
    assert base+0x2580 + signed(0x94215a0c & 0x3ffffff,26)*4 == 0x1d57a5db0
    assert data[0x2e86:0x2e8e] == b'Sandbox\0'
    assert data[0x2eea:].split(b'\0', 1)[0] == b'profile compilation not supported on this platform'
    flags = json.loads((AUDIT / 'report.json').read_bytes())
    assert pin(AUDIT / 'report.json')['sha256'] == '248972ced46a11209380bdd420c34fc87f684356a914f4a6a0913865ada04eb0'
    assert flags['nativeFlagDispatch']['cases'][3]['targetVA'] == '0x1d335d438'
    assert 'sandbox_apply lookup and call occur only after nonNULL compiler output; flags3 never reaches them on this native implementation.' in flags['flags3ExactFlow']
    kernel_sdk = (SDK / 'sys/syscall.h').read_text()
    sandbox_sdk = (SDK / 'sandbox.h').read_text()
    assert '#define\tSYS___mac_syscall  381' in kernel_sdk
    assert 'already in a sandbox' in sandbox_sdk and 'current process' in sandbox_sdk
    inputs = [Path(__file__), CAPTURE / 'receipt.json', data_path, text_path, AUDIT / 'report.json',
              AUDIT / 'freeze.json', SDK / 'sandbox.h', SDK / 'sys/syscall.h',
              NODE / 'current-native-header-export-index-v3/index.json',
              NODE / 'ipad-native-sandbox-apply-edge-readonly-plan-v1-attempt1/candidate.json']
    OUT.mkdir(exist_ok=False)
    dump(OUT / 'actual-decoded-apply.json', dict(schema='Actual iPad apply consumed instructions v1', imageUUID='41a96a45b5c23f928f64816ba6daa693', imageBaseVA=hex(base), instructions=decoded, sourceBytes=pin(data_path)))
    primary = [
        dict(URL='https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/bsd/kern/syscalls.master', lines=[546,558], verifiedWithWebTool=True,
             supports='Policy syscall 381 has policy string, integer operation and user argument pointer. Generic signature only; does not prove this private sandbox blob format.'),
        dict(URL='https://raw.githubusercontent.com/apple-oss-distributions/xnu/main/security/mac_policy.h', lines=[1851,1881], verifiedWithWebTool=True,
             supports='mpo_policy_syscall receives the calling process, operation and argument address; policy must perform copyin and security checks itself. Does not prove current proprietary Sandbox handler.'),
        dict(localHeader=pin(SDK / 'sandbox.h'), lines=[24,49],
             supports='Public sandbox_init constrains its current process; reinitializing an already sandboxed process returns an error. Current SDK wording is context, not a definition of private flags3/apply ABI.')]
    dump(OUT / 'primary-sources.json', dict(schema='Primary sources browser verified references v1', sources=primary,
        noThirdPartyABIUsed=True, noRemoteWholeSourceCaptureClaim=True))
    contract = dict(schema='Finite genuine compiler to native apply adapter boundary v1',
        implementationWritten=False, deviceExecuted=False, nativeApplyExecuted=False,
        intendedEntryABI='int ownEntry(const char *originalProfilePath, uint64_t flags, const char *const *parameters, char **errorbuf)',
        admission=[
            'Only exact authenticated owned original child image and its original Main import; never call in the parent App.',
            'flags must remain exactly 3 and parameters NULL, as this actual original Main passes them.',
            'Original genuine profile path/content must match the signed manifest and stable descriptor; do not replace or weaken the profile.',
            'Compiler is the genuine Mac27 image with exact UUID/closed dependency graph and verified actual export; native apply is the genuine iPad image UUID41a96... RVA2590.',
            'Resolve each with its exact handle plus actual Dl_info/image UUID/RVA and source-code identity; never RTLD_DEFAULT or guessed syscall address.'
        ],
        compiledObject=[
            'Use the exact object returned by one genuine sandbox_compile_file call; this report proves native consumption of the first24 bytes only.',
            'Required byte-profile lane: actual field0=NULL, field8 nonNULL, field16 uint64 length>0 within a declared finite bound supported by actual compiler output.',
            'Keep compiler object, byte buffer and compiler image alive until actual native apply returns; free exactly once with the genuine producing compiler release API.',
            'Do not fabricate a 24-byte object, translate pointer offsets, mutate serialization, infer blob version, or use native free_profile on a foreign compiler allocation.'
        ],
        nativeApply=[
            'Call genuine typed sandbox_apply once on the compiling child itself, only after native external-target binding is proven.',
            'Keep actual return and immediate errno. Failure is a real failure, with no fallback or success flags.',
            'A nonzero result leaves original Main on its real failure path. Return0 may be reported only from actual native apply returning0.',
            'No direct syscall, target PID argument, sandbox removal, flags change, alternate built-in permissive profile or parent apply is authorized by this contract.'
        ],
        actualUnknowns=[
            'Actual optimized shared stub1d57a5db0 binding and native syscall wrapper words pending two-phase readonly capture.',
            'Mac27 compiler object compatibility and serialized profile version accepted by current iPad kernel.',
            'Current child sandbox state / native apply permission and genuine resulting allow/deny behavior.',
            'iPad supported operations/extensions required by this unchanged macOS27 profile.'
        ],
        subsequentBoundedProbeOnlyAfterClosure=[
            'Root must prepare a separate exact owned-child scope after genuine compiled object/blob evidence and target binding.',
            'Exactly one self apply, immediate result/errno and explicit owner cleanup; no apply in this report or readonly capture.',
            'Verify expected profile deny and required allow operations without touching system daemons/settings before claiming sandbox behavior preserved.'
        ])
    dump(OUT / 'adapter-contract.json', contract)
    report = dict(schema='Independent actual iPad native apply ABI HOST audit v1', finiteLocalScopePassed=True, findings=[],
        deviceOperations=0, nativeSandboxCalls=0, newTrustCacheEntries=0, originalMainChanged=False,
        existingActualCapture=pin(CAPTURE / 'receipt.json'), actualImageUUID='41a96a45b5c23f928f64816ba6daa693',
        currentMainCacheUUID='1995ea169d0a33a0b78962cf99891168',
        actualEntry=dict(symbol='_sandbox_apply', RVA='0x2590', parameters='x0 exact compiler object pointer; x1 explicitly NULL internally'),
        actualConsumedObjectFields=[dict(offset=0,bytes=8,kind='pointer discriminant; nonNULL selects named-profile native operation1'),
                                    dict(offset=8,bytes=8,kind='serialized-byte pointer, read if field0 is NULL'),
                                    dict(offset=16,bytes=8,kind='unsigned64 length, read if field0 is NULL')],
        consumedSpanBytes=24, completeObjectAllocationSizeProven=False,
        byteProfileNativeCall=dict(policy='Sandbox', operation=0, argumentsAtSP=['field8 byte pointer','field16 uint64 length','NULL container pointer','0 container length'], externalStubVA='0x1d57a5db0', externalStubBindingProven=False),
        namedProfileNativeCall=dict(policy='Sandbox', operation=1, argumentsAtSP=['field0 pointer','NULL container pointer','0 container length']),
        actualPACPreserved=True, nativeTargetProcessExactKernelHandlerProven=False,
        primaryCallingProcessContract=True,
        nativeFlags3CompilationFailsBeforeApply=True, needDispatchRuntime7ToRediscoverNativeCompilerFailure=False,
        runtime7ResourcePackagingCorrectnessIsSeparate=True, runtime7InitializationExecuted=False,
        decodedInstructions=pin(OUT / 'actual-decoded-apply.json'), primarySources=pin(OUT / 'primary-sources.json'),
        adapterContract=pin(OUT / 'adapter-contract.json'),
        readonlyCapturePlan=pin(NODE / 'ipad-native-sandbox-apply-edge-readonly-plan-v1-attempt1/candidate.json'),
        noClaimOfMac27CompiledBlobKernelCompatibility=True, noClaimOfGuestExecution=True, inputs=[pin(p) for p in inputs])
    dump(OUT / 'report.json', report)
    files = [pin(p) for p in inputs] + [pin(OUT / n) for n in ['actual-decoded-apply.json','primary-sources.json','adapter-contract.json','report.json']]
    dump(OUT / 'freeze.json', dict(schema='Native apply ABI HOST audit freeze v1', files=files))
    print(json.dumps(dict(report=pin(OUT / 'report.json'), freeze=pin(OUT / 'freeze.json'))))


if __name__ == '__main__':
    main()
