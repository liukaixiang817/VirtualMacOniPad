"""Build pure VMM SCXT section and pin actual call/remaining-frame contracts.

Only local mock getters/setters run. Never imports a project builder or audit.
"""
from pathlib import Path
import hashlib, json, os, re, struct, subprocess

R = Path(__file__).resolve().parents[3]
S = Path(__file__).resolve().parent
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
D = N / 'vmm-scxt-state-guard-integration-local-v1'
RAW = R / 'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler/virtualization27-stack-audit-v1/raw'
SDK = Path('/Applications/Xcode.app/Contents/Developer/Platforms/MacOSX.platform/Developer/SDKs/MacOSX27.0.sdk/System/Library/Frameworks/Hypervisor.framework/Headers')

def need(ok, message):
    if not ok:
        raise ValueError(message)

def pin(p):
    p = Path(p).resolve()
    need(p.is_file() and not p.is_symlink(), 'regular input')
    b = p.read_bytes()
    return dict(path=str(p), bytes=len(b), sha256=hashlib.sha256(b).hexdigest())

class Image:
    def __init__(self, p):
        self.b = p.read_bytes(); self.segs = []; self.sections = []
        need(struct.unpack_from('<I', self.b)[0] == 0xfeedfacf, 'actual arm64 Mach-O')
        ncmds, nbytes = struct.unpack_from('<II', self.b, 16); at = 32
        for _ in range(ncmds):
            cmd, size = struct.unpack_from('<II', self.b, at)
            need(size >= 8 and at + size <= 32 + nbytes, 'bounded load command')
            if cmd == 0x19:
                name = self.b[at+8:at+24].split(b'\0')[0].decode()
                va, vs, off, sz = struct.unpack_from('<4Q', self.b, at+24)
                self.segs.append((name, va, off, sz))
                ns = struct.unpack_from('<I', self.b, at+64)[0]
                need(size == 72 + ns * 80 and off + sz <= len(self.b), 'bounded segment')
                for i in range(ns):
                    a = at + 72 + i * 80
                    sec = self.b[a:a+16].split(b'\0')[0].decode()
                    sva, sn, so = struct.unpack_from('<QQI', self.b, a+32)
                    self.sections.append((name, sec, sva, sn, so))
            elif cmd == 0x1b:
                self.uuid = self.b[at+8:at+24].hex()
            at += size
        need(at == 32 + nbytes, 'whole load command table')
        self.base = next(s[1] for s in self.segs if s[0] == '__TEXT')
    def raw(self, rva, size):
        s = next(s for s in self.segs if s[1] <= self.base+rva and self.base+rva+size <= s[1]+s[3])
        at = s[2]+self.base+rva-s[1]
        return self.b[at:at+size]
    def word(self, rva): return struct.unpack('<I', self.raw(rva, 4))[0]

def target(word, rva):
    if word & 0xfc000000 not in (0x14000000, 0x94000000): return None
    imm = word & 0x3ffffff
    if imm & (1 << 25): imm -= 1 << 26
    return rva + imm * 4

def main():
    need(not D.exists(), 'fresh guard build directory')
    # All input files stay read-only. Output creation is explicit and local.
    units = ['modern_vmm_scxt_state_guard_v1.h', 'modern_vmm_scxt_state_guard_v1.c',
        'test-modern-vmm-scxt-state-guard-v1.c', 'vmm_scxt_guard_sdk_abi_v1.c',
        'modern_vmm_scxt_state_guard_v1.md']
    inputs = [Path(__file__), *[S/p for p in units], RAW/'VirtualMachine.arm64e', RAW/'Hypervisor',
        SDK/'hv_vcpu_types.h', SDK/'hv_vcpu.h',
        N/'modern27-cpu-restore-readonly-v1/contract.json',
        N/'original27-physical-restore-source-ports-data-v1/candidate.json',
        N/'original27-short-physical-restore-source-ports-data-v1/candidate.json',
        N/'cpu-hv-vtimer-source-byte-basis-v1/basis.json',
        N/'native-pending-control-return-contract-v1/contract.json',
        S/'modern_cpu_kernel_system_fields.inc',
        S/'modern_cpu_kernel_lifecycle_v9.c', S/'modern_cpu_native_exit_reducer_v1.c',
        S/'modern_cpu_kernel_vtimer_v12.inc']
    initial = [pin(p) for p in inputs]
    need(pin(RAW/'VirtualMachine.arm64e')['sha256'] == 'c81d16f0ec5364bf71d915ac3ee9388610dc940446b2ad1abf3849ba57d46422', 'genuine VMM input')
    need(pin(RAW/'Hypervisor')['sha256'] == '4d334d43c5628d134ef6b0f8ceef9a4c3c620467b284f92dc1c49b16bfc495a3', 'genuine modern HV input')
    vm = Image(RAW/'VirtualMachine.arm64e')
    need(vm.uuid == '4a6a588d1afd30f5a64d6304eb79be0b', 'genuine UUID')
    D.mkdir(mode=0o700)
    steps = []
    def run(label, argv):
        env = {k:v for k,v in os.environ.items() if not k.startswith('DYLD_')}
        env['ASAN_OPTIONS'] = 'halt_on_error=1:detect_leaks=0'
        p = subprocess.run(list(map(str, argv)), capture_output=True, env=env, timeout=45)
        (D/(label+'.stdout')).write_bytes(p.stdout)
        (D/(label+'.stderr')).write_bytes(p.stderr)
        steps.append(dict(label=label, argv=list(map(str, argv)), exit=p.returncode,
            stdout=pin(D/(label+'.stdout')), stderr=pin(D/(label+'.stderr'))))
        need(p.returncode == 0, label+' failed; exact outputs retained')
        return p.stdout
    results = []
    for label, flags in [('normal',[]),('sanitized',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
        run(label+'-compile', ['xcrun','--sdk','macosx','clang','-std=c11','-Wall','-Wextra','-Werror',
            *flags,S/units[1],S/units[2],'-o',D/label])
        results.append(json.loads(run(label+'-run', [D/label]).splitlines()[-1]))
    need(results[0] == results[1] and results[0]['nativeCalls'] == 0, 'matching mock-only fixtures')
    run('mac-sdk-abi', ['xcrun','--sdk','macosx','clang','-arch','arm64e','-std=c11','-Wall','-Wextra','-Werror',
        '-O0','-S','-emit-llvm',S/units[3],'-o',D/'mac-sdk-abi.ll'])
    run('ios-guard-object', ['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1',
        '-std=c11','-Wall','-Wextra','-Werror','-c',S/units[1],'-o',D/'ios-guard.o'])
    run('ios-guard-ir', ['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1',
        '-std=c11','-Wall','-Wextra','-Werror','-O0','-S','-emit-llvm',S/units[1],'-o',D/'ios-guard.ll'])
    cpp = D/'header-cxx.cpp'
    cpp.write_text('#include "modern_vmm_scxt_state_guard_v1.h"\nVM27VMMGetSYSV1 getFromC = nullptr;\n')
    run('ios-cxx-header', ['xcrun','--sdk','iphoneos','clang++','-arch','arm64e','-miphoneos-version-min=16.1',
        '-std=c++17','-Wall','-Wextra','-Werror','-I',S,'-c',cpp,'-o',D/'header-cxx.o'])
    ir = (D/'mac-sdk-abi.ll').read_text()
    need(re.search(r'declare i32 @hv_vcpu_get_sys_reg\(i64[^,]*, i16[^,]*, ptr',ir), 'real getter ABI i64/i16/pointer')
    need(re.search(r'declare i32 @hv_vcpu_set_sys_reg\(i64[^,]*, i16[^,]*, i64',ir), 'real setter ABI i64/i16/i64')
    callrows = []
    for kind, ident, call, literal, slot, slotat, word in [
        ('save',0xde87,0x288940,0x28893c,0x760,0x28894c,0xf903b268),
        ('save',0xc687,0x288960,0x28895c,0x768,0x28896c,0xf903b668),
        ('restore',0xde87,0x28b58c,0x28b588,0x760,0x28b580,0xf943b262),
        ('restore',0xc687,0x28b5a0,0x28b59c,0x768,0x28b594,0xf943b662)]:
        need(vm.word(literal) == 0x52800001 | ident << 5, 'true literal SYS selector')
        need(vm.word(slotat) == word, 'true frame slot load/store')
        stub = 0x412dd4 if kind == 'save' else 0x412e64
        need(target(vm.word(call), call) == stub, 'true public SYS call target')
        callrows.append(dict(kind=kind, identifier=hex(ident), callRVA=hex(call), literalRVA=hex(literal),
            slot=hex(slot), slotInstructionRVA=hex(slotat), slotWord=hex(word), actualPublicStubRVA=hex(stub)))
    for label, begin, end in [('original-save',0x2875a8,0x28a258),('original-restore',0x28a508,0x28cc24)]:
        (D/(label+'.bin')).write_bytes(vm.raw(begin,end-begin))
        run(label+'-disassembly', ['xcrun','llvm-objdump','--disassemble',
            '--start-address='+hex(vm.base+begin),'--stop-address='+hex(vm.base+end),RAW/'VirtualMachine.arm64e'])
    savecalls = [r for r in range(0x2875a8,0x28a258,4) if target(vm.word(r),r) == 0x4125b4]
    restorecalls = [r for r in range(0x28a508,0x28cc24,4) if target(vm.word(r),r) == 0x4125b4]
    long = json.loads((N/'original27-physical-restore-source-ports-data-v1/candidate.json').read_bytes())
    short = json.loads((N/'original27-short-physical-restore-source-ports-data-v1/candidate.json').read_bytes())
    done = {r['callRVA'] for r in long['supportedPorts']} | {r['callRVA'] for r in short['ports']}
    remaining = [r for r in restorecalls if r not in done]
    need(len(savecalls) == len(restorecalls) == 59 and len(done) == 53 and len(remaining) == 6, 'actual 59/53 extent')
    contract = json.loads((N/'modern27-cpu-restore-readonly-v1/contract.json').read_bytes())
    mandatory = [r['rva'] for r in contract['staticCalls'] if r['rva'] in remaining and r['structurallyRequiredOnEveryOrdinarySuccessPath']]
    need(mandatory == [0x28b16c,0x28b1ec], 'two remaining structurally mandatory context routes')
    for ident, call, literal in [(0xdf11,0x28abb0,0x28abac),(0xdf12,0x28abc4,0x28abc0)]:
        need(vm.word(literal) == 0x52800001 | ident << 5 and target(vm.word(call),call) == 0x412e64, 'true mandatory CNTP call')
    need([pin(p) for p in inputs] == initial, 'all inputs unchanged')
    report = dict(schema='Application VMM SCXT feature guard and honest timer closure contract v1',
        finiteGuardSourceFixturePassed=True, findings=[], results=results[0], steps=steps,
        realSDKAssignmentWithoutCastPassed=True, genuineSDKIdentifierBits=16,
        iosArm64eCompilePassed=True, cxxHeaderPassed=True, actualOriginalSCXTCalls=callrows,
        suppliedGuestPFRsRequired=True, unknownFeatureEncodingRejected=True,
        absenceResultIsHVSuccess=False, absentFrameValidMask=0,
        typedFailureIsPreserved=True, publicSCXTUnsupportedChanged=False,
        existingPhysicalRestorePortCount=53, originalSaveContextCalls=59, originalRestoreContextCalls=59,
        remainingRestoreContextCalls=[hex(r) for r in remaining],
        remainingMandatoryRestoreContextCalls=[hex(r) for r in mandatory],
        originalSaveAndRestoreCompleteFrameComposable=False, originalGuardInstalled=False,
        sidecarFrameIsAppleOriginalFrame=False, ownsOrValidatesNativeCPULeaseItself=False,
        CNTPImplemented=False, actualPendingIRQRunConsumerClosed=False, actualGICTimerPPIConsumerClosed=False,
        architecturalPrimaryReferences=dict(verifiedBy='Root in this turn; this child stays offline',
            armPDF='https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Security%20Update%2008%20March%202022/Spectre-BHB%20White%20Paper%20v1.6.pdf',
            armPDFZeroBasedPages=[4,7], linuxSysreg='https://raw.githubusercontent.com/torvalds/linux/master/arch/arm64/tools/sysreg',
            linuxLineRanges=[[1128,1138],[1233,1237]], fractionCombinationRefusalsAreConservativeScope=True),
        inputs=initial, nativeCPUCalls=0, nativeVMCalls=0, deviceOperations=0,
        originalAppleCodeExecuted=False, originalImageModified=False, probeSigned=False,
        full27Backend=False, guestBootVerified=False)
    (D/'candidate.json').write_text(json.dumps(report,indent=2)+'\n')
    rows = {r['path']:r for r in initial}
    for p in D.iterdir():
        if p.is_file(): rows[str(p.resolve())] = pin(p)
    (D/'freeze.json').write_text(json.dumps(dict(schema='Finite SCXT guard source build v1 pins',
        files=sorted(rows.values(),key=lambda r:r['path']),deviceOperations=0,nativeCalls=0),indent=2)+'\n')
    print(json.dumps(dict(candidate=pin(D/'candidate.json'),freeze=pin(D/'freeze.json'),guardFixturePassed=True)))

if __name__ == '__main__':
    main()
