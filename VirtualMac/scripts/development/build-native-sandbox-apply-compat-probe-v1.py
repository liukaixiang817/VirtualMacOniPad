"""HOST-only unsigned self probe build; never loads/applies a sandbox here."""
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / 'VirtualMac/vz/host'
NODE = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
OUT = NODE / 'native-sandbox-apply-compat-probe-unsigned-local-v1-attempt2'

def pin(path):
    path = Path(path).resolve()
    data = path.read_bytes()
    return dict(path=str(path), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

def save(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')

def main():
    OUT.mkdir(exist_ok=False)
    steps = []
    inputs = []
    def run(label, arguments, timeout=45):
        env = {k:v for k,v in os.environ.items() if not k.startswith('DYLD_')}
        process = subprocess.run(list(map(str,arguments)), capture_output=True, timeout=timeout, env=env)
        (OUT/(label+'.stdout')).write_bytes(process.stdout)
        (OUT/(label+'.stderr')).write_bytes(process.stderr)
        steps.append(dict(label=label,arguments=list(map(str,arguments)),exit=process.returncode,
                          stdout=pin(OUT/(label+'.stdout')),stderr=pin(OUT/(label+'.stderr'))))
        (OUT/'steps-in-progress.json').write_text(json.dumps(steps,indent=2)+'\n')
        if process.returncode:
            raise ValueError(label+' failed')
        return process.stdout
    try:
        blob = NODE/'mac27-vmm-sandbox-compile-only-host-v1-attempt1/compiled-profile.bin'
        assert pin(blob)['bytes']==13696 and pin(blob)['sha256']=='2b7ad4d1be09203d49af1dafa560dfdb9b3ddcd5953c7ee061713a5fb34e898b'
        compiler_freeze = NODE/'mac27-genuine-sandbox-compiler-host-audit-v1-attempt1/freeze.json'
        assert pin(compiler_freeze)['sha256']=='50a45e8b7343b360d26b77cb7132c7af30c695876279e2e5b4a3d20a5c861373'
        for row in json.loads(compiler_freeze.read_bytes())['files']:
            assert pin(row['path'])==row, ('changed compiler evidence',row['path'])
        native_index=NODE/'current-native-header-export-index-v3/index.json'
        current=json.loads(native_index.read_bytes())['images']
        for name,uuid,symbol,offset in [('/usr/lib/libsandbox.1.dylib','41a96a45b5c23f928f64816ba6daa693','_sandbox_apply',0x2590),
                                      ('/usr/lib/system/libsystem_sandbox.dylib','140cc26b91e932f4ad75096c4e104eb0','_sandbox_check',0x19b4)]:
            assert current[name]['UUID']==uuid
            assert current[name]['definitions'][symbol]==dict(flags=0,offset=offset)
        compiler_code=NODE/'ipad-current-native-sandbox-code-readonly-v1/sandbox-compiler-text.bin'
        check_code=NODE/'ipad-current-native-sandbox-code-readonly-v1/system-sandbox-text.bin'
        apply_bytes=compiler_code.read_bytes()[0x24fc:0x2598]
        check_bytes=check_code.read_bytes()[0x19b4:0x1a24]
        assert hashlib.sha256(apply_bytes).hexdigest()=='ffa55cebf510dc908c8cf12d27deb8e891e15d7216d061a57a6b152eb1c67cd2'
        assert hashlib.sha256(check_bytes).hexdigest()=='1cecf5e729b300f2cbf283a37a452c4de7c82590748ccac7df157cb768281340'
        probe=SOURCE/'vm27_native_sandbox_apply_compat_probe_v1.c'
        host_tests=SOURCE/'vm27_native_sandbox_apply_compat_host_tests_v1.c'
        flags=['xcrun','--sdk','iphoneos','clang','-arch','arm64e','-miphoneos-version-min=16.1',
               '-std=c11','-Wall','-Wextra','-Werror','-fvisibility=hidden','-I',SOURCE]
        dependencies=run('ios-dependencies',flags+['-MM',probe]).decode().split(':',1)[1].replace('\\\n',' ')
        closure={Path(__file__).resolve(),probe,host_tests}
        for token in shlex.split(dependencies):
            path=Path(token).resolve()
            if not path.is_relative_to(SOURCE) and path.name!='SDKSettings.json':
                raise ValueError('unexpected local include '+str(path))
            closure.add(path)
        inputs=[pin(path) for path in sorted(closure)]+[pin(path) for path in [blob,compiler_freeze,
                NODE/'mac27-genuine-sandbox-compiler-host-audit-v1-attempt1/report.json',native_index,compiler_code,check_code,
                NODE/'ipad-native-sandbox-apply-binding-host-audit-v1-attempt1/report.json',
                NODE/'ipad-native-sandbox-apply-binding-host-audit-v1-attempt1/freeze.json']]
        run('ios-compile',flags+['-O1','-c',probe,'-o',OUT/'probe.o'])
        binary=OUT/'sandbox-apply-compat-probe-v1'
        run('ios-link',flags+[OUT/'probe.o','-Wl,-undefined,error','-Wl,-no_adhoc_codesign','-o',binary])
        run('ios-validate',['xcrun','dyld_info','-validate_only',binary])
        imports=run('ios-imports',['xcrun','dyld_info','-dependents','-imports',binary])
        run('ios-disassembly',['xcrun','llvm-objdump','--macho','--disassemble',binary])
        if re.search(rb'Hypervisor|Virtualization|VirtualMachineMonitor|\s_hv_|\s_sandbox_apply\s|\s_sandbox_check\s',imports):
            raise ValueError('unexpected static VM/native sandbox import')
        data=binary.read_bytes(); offset=32
        assert struct.unpack_from('<I',data)[0]==0xfeedfacf
        for _ in range(struct.unpack_from('<I',data,16)[0]):
            command,size=struct.unpack_from('<II',data,offset)
            assert command!=0x1d, 'probe must remain unsigned'
            offset+=size
        host_results=[]
        for label,extra in [('normal',[]),('sanitizers',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
            host=OUT/('host-'+label)
            run('host-'+label+'-compile',['clang','-std=c11','-Wall','-Wextra','-Werror','-O1',*extra,host_tests,'-o',host])
            stdout=run('host-'+label+'-tests',[host],timeout=20)
            assert b'nativeApplyCalls=0 nativeSandboxCheckCalls=0 deviceOperations=0' in stdout
            host_results.append(dict(mode=label,actualOutput=pin(OUT/('host-'+label+'-tests.stdout')),
                                     actualHostValidationOnly=True,nativeApplyCalls=0,nativeSandboxCheckCalls=0))
        witness=OUT/'deny-witness.txt'; witness.write_bytes(b'VM27 sandbox deny witness v1\n')
        own_blob=OUT/'compiled-profile.bin'; own_blob.write_bytes(blob.read_bytes())
        save(OUT/'host-results.json',dict(schema='Native sandbox probe prevalidation/oracle HOST tests v1',
                                         runs=host_results,deviceOperations=0,nativeApplyCalls=0,nativeSandboxCheckCalls=0))
        save(OUT/'primary-sources.json',dict(schema='Native sandbox private typed API primary provenance v1',
            sources=[dict(url='https://raw.githubusercontent.com/WebKit/WebKit/main/Source/WTF/wtf/spi/darwin/SandboxSPI.h',
                          lines='40-48,54-58,77,89',supports='PATH=1; PID/op/filter varargs; 24B LP64 profile fields; typed apply'),
                     dict(url='https://raw.githubusercontent.com/apple-oss-distributions/clang/main/src/projects/compiler-rt/lib/sanitizer_common/sanitizer_mac_spi.cc',
                          lines='20-37,40-48',supports='typed sandbox_check; positive result denies; probe treats negative as error')],
            localOriginalProfile=pin(Path('/System/Library/Frameworks/Virtualization.framework/Versions/A/XPCServices/com.apple.Virtualization.VirtualMachine.xpc/Contents/Resources/com.apple.Virtualization.VirtualMachine.sb')),
            localImportedSystemProfile=pin(Path('/System/Library/Sandbox/Profiles/system.sb')),
            exactWitnessPolicy=dict(allowedMetadata='/usr original profile line265',allowedRead='/dev/null imported system.sb line113',
                                    denyWitness='default-deny outside exact allows; no sandbox extension issued by probe; actual checks and opens required')))
        for row in inputs:
            assert pin(row['path'])==row, ('input changed',row['path'])
        candidate=dict(schema='Unsigned single self native sandbox apply compatibility probe candidate v1',
            binary=pin(binary),inputs=inputs,actualIOSArm64e161CompileLinkValidatePassed=True,
            hostResults=pin(OUT/'host-results.json'),primarySources=pin(OUT/'primary-sources.json'),
            genuineCompiledBlob=pin(own_blob),genuineCompiledBlobOriginal=pin(blob),denyWitness=pin(witness),
            exactArgument='--self-apply-once-compiled27-v1',
            requiredDirectory='/private/var/mobile/Library/VirtualMacIndependent27SandboxProbe-v1',
            requiredFiles={'sandbox-apply-compat-probe-v1':dict(uid=501,mode='0700',nlink=1),
                           'compiled-profile.bin':dict(uid=501,mode='0600',nlink=1),
                           'deny-witness.txt':dict(uid=501,mode='0600',nlink=1)},
            requiredDirectoryUID=501,requiredDirectoryMode='0700',requiredUID=501,requiredEUID=501,
            requiredCPUSoftHardSeconds=5,requiredCoreSoftHardBytes=0,requiresRootExternalWallSeconds=20,
            actualNativeApplyCalls=0,intendedNativeApplyMaximum=1,deviceOperations=0,providerSigned=False,trustCacheAdded=False,
            usesExactNativeImageUUIDRVAAndCurrentCodeSHA=True,noRTLDDefault=True,noManualSyscall=True,
            diagnostic24BWrapperOnly=True,producerNativeFreeNotCalled=True,productionUsesCompilerOpaqueObjectStillRequired=True,
            nonMutatingFreshOpenWitnesses=True,baselineMustReallyPass=True,
            nativeReturnAndErrnoReported=True,nativeRejectionIsValidEvidence=True,
            ordinaryNativeAPICompatibilityUnknown=True,all204OperationSemanticsUnknown=True,
            originalMainExecuted=False,flags3ProductionPathProved=False,guestBooted=False,fullVM=False,
            requiresIndependentSourceProductAndRootControllerReviewBeforeDevice=True,
            finiteLocalScopePassed=True,findings=[])
        save(OUT/'candidate.json',candidate)
        files=[pin(p) for p in sorted(OUT.iterdir()) if p.is_file()]
        save(OUT/'freeze.json',dict(schema='Native apply compatibility probe HOST source/unsigned product freeze v1',
                                   files=inputs+files,deviceOperations=0,nativeApplyCalls=0))
        print(json.dumps(dict(candidate=pin(OUT/'candidate.json'),freeze=pin(OUT/'freeze.json'),binary=pin(binary))))
    except Exception as error:
        save(OUT/'failure.json',dict(error=str(error),steps=steps,inputs=inputs,deviceOperations=0,nativeApplyCalls=0))
        raise

if __name__=='__main__':
    main()
