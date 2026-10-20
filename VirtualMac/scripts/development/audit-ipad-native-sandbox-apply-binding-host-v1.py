"""Close native apply -> actual shared stub -> syscall381 using captured bytes only."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
NODE = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OUT = NODE / 'ipad-native-sandbox-apply-binding-host-audit-v1-attempt1'

def pin(p):
    b=p.read_bytes(); return dict(path=str(p.resolve()),bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def dump(p,x): p.write_text(json.dumps(x,indent=2)+'\n')
def signed(x,b): return x-(1<<b) if x&(1<<(b-1)) else x

def main():
    first=NODE/'ipad-native-sandbox-apply-edge-readonly-v1/receipt.json'
    second=NODE/'ipad-native-sandbox-apply-stub-readonly-v1/receipt.json'
    assert pin(first)['sha256']=='c46be6a41be93c6c952f8e50b1118b903ae697ac1fac4bf3d83dcdc4ad5bba11'
    assert pin(second)['sha256']=='02f1ff3c6a399a432d769a372e81b2e43f905557ce88e496bb9405465e6d07b1'
    a=json.loads(first.read_bytes()); b=json.loads(second.read_bytes())
    assert a['transportExit']==b['transportExit']==a['deviceWrites']==b['deviceWrites']==a['nativeSandboxCalls']==b['nativeSandboxCalls']==0
    assert a['allExisting18HeaderPinsMatchBeforeAndAfter'] and b['all19HeaderPinsMatchBeforeAndAfter']
    for row in a['captured']: assert pin(Path(row['path']))==row
    assert pin(Path(b['captured']['path']))==b['captured']
    stub=Path(b['captured']['path']); words=struct.unpack('<8I',stub.read_bytes())
    assert words[:4]==(0x90f6c5d0,0x91331210,0xd61f0200,0xd4200020)
    pc=0x1d57a5db0
    assert words[0]&0x9f00001f==0x90000010  # ADRP x16
    page=(pc&~0xfff)+(signed((((words[0]>>5)&0x7ffff)<<2)|((words[0]>>29)&3),21)<<12)
    assert words[1]&0xffc003ff==0x91000210  # ADD x16,x16,uimm12, no shifted immediate
    target=page+((words[1]>>10)&0xfff)
    assert target==0x1c305dcc4
    k=NODE/'ipad-native-sandbox-apply-edge-readonly-v1/native-mac-syscall-export-code.bin'
    kw=struct.unpack('<8I',k.read_bytes())
    assert kw[:2]==(0xd2802fb0,0xd4001001)
    assert kw[0]&0xffe0001f==0xd2800010 and ((kw[0]>>5)&0xffff)==381
    assert kw[1]==0xd4000001|(0x80<<5)
    index=NODE/'current-native-header-export-index-v3/index.json'
    x=json.loads(index.read_bytes()); native=x['images']['/usr/lib/system/libsystem_kernel.dylib']
    assert native['UUID']=='ff27fc8f90ba3332ab7ac5bc2d9ca7b1'
    assert native['base']+native['definitions']['___mac_syscall']['offset']==target
    assert native['definitions']['___mac_syscall']['flags']==0
    abi=ROOT/'VirtualMac/vz/host/vm27_native_sandbox_apply_abi_v1.h'
    fixture='#include "'+str(abi)+'"\nint main(void) { return 0; }\n'
    normal=subprocess.run(['/usr/bin/clang','-std=c11','-Wall','-Wextra','-Werror','-x','c','-fsyntax-only','-'],input=fixture.encode(),capture_output=True)
    assert normal.returncode==0,normal.stderr.decode()
    ios_sdk=subprocess.run(['/usr/bin/xcrun','--sdk','iphoneos','--show-sdk-path'],capture_output=True,check=True).stdout.decode().strip()
    ios=subprocess.run(['/usr/bin/clang','-target','arm64e-apple-ios16.1','-isysroot',ios_sdk,'-std=c11','-Wall','-Wextra','-Werror','-x','c','-fsyntax-only','-'],input=fixture.encode(),capture_output=True)
    assert ios.returncode==0,ios.stderr.decode()
    OUT.mkdir(exist_ok=False)
    dump(OUT/'header-compile-checks.json',dict(schema='Consumed prefix C ABI syntax checks v1',macExit=normal.returncode,iosArm64e161Exit=ios.returncode,executableCreated=False,deviceExecuted=False))
    probe=dict(schema='Inactive single self native apply compatibility probe contract v1',deviceExecuted=False,nativeApplyCalls=0,productionAdapterWritten=False,
        intendedActualNativeApplyCalls=1,ownProcessOnly=True,wallSeconds=20,rootControllerOwnCleanupRequired=True,
        admission=[
            'A new separately pinned Root-owned helper child, exact executable+PID+UID+PPID+start identity, no VM/CPU/Guest operations and no unrelated process targets.',
            'Use exact genuine native libsandbox.1 UUID41a96a45... exportRVA2590 with Dl_info/imageUUID/actual entry-code identity; no RTLD_DEFAULT or hand-written syscall.',
            'Use only genuine original27 profile compiled by genuine fixed Mac27 compiler. Preserve signed profile and imported policy source hashes, original input flags3 semantics and true producer allocation ownership.',
            'Require actual compiler object prefix field0NULL/+8nonNULL/length13696 plus approved actual complete blob SHA2b7ad4d1be09203d49af1dafa560dfdb9b3ddcd5953c7ee061713a5fb34e898b, or reject before native apply. The future product must pin the actual compiler result receipt; this contract is not that receipt.',
            'Capture pre-apply readable /dev/null positive baseline and readable/writable Root-owned test file outside allowed paths; verify no sandbox extension was issued for that file.',
            'Keep output/identity/diagnostic descriptors prepared before self apply, and preserve parent independent wall timeout and exact own-child cleanup.'
        ],
        onceSequence=[
            'Resolve and verify genuine compile/free/nativeApply identities; compile once and hash/inspect actual immutable producer object/data.',
            'Record PID/UID/PPID, full profile/blob pins and pre-apply witness results without claiming a sandbox is active.',
            'Call genuine native sandbox_apply once with the actual producer object; immediately save int return and errno before all diagnostics.',
            'If return is nonzero, report actual failure/errno and stop. Do not retry, switch flags, install permissive policy, or continue a guest.',
            'If return0, open/read /dev/null as inherited system.sb explicit allow and attempt non-mutating fresh open of preexisting own test file as deny witness. Record actual result/errno for both. Do not write denied file or any system settings.',
            'Exit that owned probe process; parent records real wait/timeout/corpse status. Native0 success alone is not policy equivalence or guest-ready admission.'
        ],
        semanticLimits=[
            'Native API and syscall number are now actual-byte closed. Kernel proprietary Sandbox operation0 parser/version checks are not included in these userland captures.',
            'An Apple-produced13,696B blob is a finite conventional native API input, not an arbitrary malformed-input/syscall test. Reject/accept behavior must be reported from the actual single owned-process run.',
            'The format does not prove Mac27 operation count204 names/semantics match iPad16. Header+0 featuresflags6002 and +2 instructions228 must not be mislabeled as a version.',
            'Passing two allow/deny witnesses is only local evidence; required VMM Mach/I/O/hypervisor permissions and all204 operations remain separate actual boot evidence.',
            'No claim that every newer-format blob is safely rejected: exact proprietary kernel validation remains unverified; never fuzz lengths/flags/blob data or apply to parent/system processes.'
        ],readyForDeviceDispatch=False,requiresFutureRootExactHelperProductAndController=True)
    dump(OUT/'inactive-probe-contract.json',probe)
    inputs=[Path(__file__),first,second,stub,k,index,abi,
            NODE/'ipad-native-sandbox-apply-abi-host-audit-v1-attempt1/report.json',
            NODE/'ipad-native-sandbox-apply-abi-host-audit-v1-attempt1/freeze.json']
    report=dict(schema='Actual native apply external target HOST binding audit v1',finiteLocalScopePassed=True,findings=[],
        deviceOperations=0,nativeSandboxCalls=0,actualCapturesPerformedByRoot=True,
        actualStubCode=[dict(VA=hex(pc+i*4),word=f'{w:08x}') for i,w in enumerate(words[:4])],
        stubKind='ADRP x16 / ADD x16 / BR x16; exact direct cache target, no GOT or PAC stripping',targetVA=hex(target),
        currentKernelUserLibrary=dict(path='/usr/lib/system/libsystem_kernel.dylib',UUID=native['UUID'],export='___mac_syscall',RVA='0x2cc4'),
        actualWrapperWords=[dict(VA=hex(target+i*4),word=f'{w:08x}') for i,w in enumerate(kw)],
        actualSyscallNumber=381,actualSVCImmediate=128,typedArguments=['const char* policy','int call','user argument pointer'],
        actualNativeApplyPolicy='Sandbox',actualNativeApplyByteOperation=0,actual24BPrefixConsumptionInherited=True,
        nativeTargetBindingClosed=True,additionalGOTReadRequired=False,unknownSyscallNotIntroduced=True,
        callerProcessScopeSupportedByPrimaryMACContract=True,proprietaryKernelBlobCompatibilityNotEstablished=True,
        actualApplyResultUnknown=True,header=pin(abi),headerSyntaxChecks=pin(OUT/'header-compile-checks.json'),
        inactiveProbeContract=pin(OUT/'inactive-probe-contract.json'),inputs=[pin(p) for p in inputs])
    dump(OUT/'report.json',report)
    dump(OUT/'freeze.json',dict(schema='Actual native apply external target HOST binding freeze v1',files=[pin(p) for p in inputs]+[pin(OUT/n) for n in ['header-compile-checks.json','inactive-probe-contract.json','report.json']]))
    print(json.dumps(dict(report=pin(OUT/'report.json'),freeze=pin(OUT/'freeze.json'))))
if __name__=='__main__': main()
