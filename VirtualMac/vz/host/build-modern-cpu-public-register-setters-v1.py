"""Real owned factory integration on Mac; compiler-only genuine SDK ABI calls."""
import hashlib,json,os,re,subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
SOURCE=Path(__file__).resolve().parent
OUTPUT=ROOT/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/cpu-public-register-setters-integration-local-v1'
def pin(path):
    path=Path(path).resolve(); data=path.read_bytes()
    return {'path':str(path),'bytes':len(data),'sha256':hashlib.sha256(data).hexdigest()}
def require(value,message):
    if not value: raise ValueError(message)
steps=[]
def run(label,arguments):
    env={k:v for k,v in os.environ.items() if not k.startswith('DYLD_')}
    env['ASAN_OPTIONS']='halt_on_error=1:detect_leaks=0'
    result=subprocess.run(list(map(str,arguments)),capture_output=True,env=env,timeout=30)
    (OUTPUT/(label+'.stdout')).write_bytes(result.stdout)
    (OUTPUT/(label+'.stderr')).write_bytes(result.stderr)
    steps.append({'label':label,'arguments':list(map(str,arguments)),'exit':result.returncode,
        'stdout':pin(OUTPUT/(label+'.stdout')),'stderr':pin(OUTPUT/(label+'.stderr'))})
    require(result.returncode==0,label+' failed; exact outputs preserved')
    return result.stdout
def main():
    OUTPUT.mkdir(exist_ok=False)
    units=['modern_cpu_public_register_setters_v1.c','modern_cpu_native_public_factory_v2.c',
        'modern_cpu_kernel_lifecycle_v6.c','modern_cpu_kernel_initialization_v3.c',
        'modern_cpu_native_fields.c','modern_cpu_pending_interrupt_values_v1.c',
        'modern_cpu_kernel_system_v2.c','modern_cpu_config_os_object_v3.m']
    test=SOURCE/'test-modern-cpu-public-register-setters-v1.m'
    common=['xcrun','--sdk','macosx','clang','-std=c11','-fno-objc-arc','-Wall',
        '-Wextra','-Werror','-I',SOURCE,'-DVM27_CPU_CONFIG_TESTING=1']
    results=[]
    for label,flags in [('normal',[]),('sanitized',['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
        run(label+'-compile',common+flags+[SOURCE/x for x in units]+[test,
            '-framework','CoreFoundation','-lobjc','-o',OUTPUT/label])
        stdout=run(label+'-run',[OUTPUT/label]); result=json.loads(stdout.splitlines()[-1])
        require(result['actualCFObjectsCreated']==result['actualCFObjectsDestroyed']==1,
            'actual CF object lifetime')
        require(result['mockOnlyNativeCallbacks'] is True and result['nativeRunCalls']==0,
            'native execution outside fixture scope')
        results.append(result)
    require(results[0]==results[1],'normal and sanitized actual result disagreement')
    macIR=OUTPUT/'genuine-sdk-caller-arm64e.ll'
    run('genuine-sdk-caller-ir',['xcrun','--sdk','macosx','clang','-arch','arm64e',
        '-std=c11','-Wall','-Wextra','-Werror','-I',SOURCE,'-O0','-S','-emit-llvm',
        SOURCE/'cpu_register_setters_sdk_caller_v1.c','-o',macIR])
    iosIR=OUTPUT/'own-setters-ios-arm64e.ll'
    run('own-ios-ir',['xcrun','--sdk','iphoneos','clang','-arch','arm64e',
        '-miphoneos-version-min=16.1','-std=c11','-Wall','-Wextra','-Werror',
        '-I',SOURCE,'-O0','-S','-emit-llvm',SOURCE/units[0],'-o',iosIR])
    run('own-ios-object',['xcrun','--sdk','iphoneos','clang','-arch','arm64e',
        '-miphoneos-version-min=16.1','-std=c11','-Wall','-Wextra','-Werror',
        '-I',SOURCE,'-c',SOURCE/units[0],'-o',OUTPUT/'own-setters-ios-arm64e.o'])
    genuine=re.search(r'declare i32 @hv_vcpu_set_simd_fp_reg\(([^\n]+)\)',macIR.read_text())
    own=re.search(r'define[^\n]* i32 @VM27CPUSetSIMDRegisterV1\(([^\n]+)\)',iosIR.read_text())
    require(genuine and own,'real compiler declarations missing')
    # The first three argument types are the SDK prefix. Extra own parameters
    # intentionally remain, so the wrapper cannot be called as an hv_* symbol.
    for declaration in [genuine.group(1),own.group(1)]:
        arguments=declaration.split(',')
        require(len(arguments)>=3 and all(arguments[i].lstrip().startswith(t)
            for i,t in enumerate(['i64 ','i32 ','<16 x i8> '])),
            'genuine caller and own callee vector/ID/register ABI differ')
    inputs=[Path(__file__),test,SOURCE/'cpu_register_setters_sdk_caller_v1.c',
        *[SOURCE/x for x in units],SOURCE/'modern_cpu_public_register_setters_v1.h']
    inputs.extend(SOURCE.glob('modern_cpu_kernel*.h'))
    inputs.extend([SOURCE/'modern_cpu_config_os_object_v3.h',SOURCE/'modern_cpu_config_os_object_v3_private.h',
        SOURCE/'modern_cpu_native_public_factory_v2.h',SOURCE/'modern_cpu_kernel_system_fields.inc',
        SOURCE/'modern_cpu_pending_interrupt_values_v1.h',SOURCE/'modern_cpu_native_fields.h'])
    report={'schema':'Owned public scalar SIMD control setter integration v1',
        'finiteOwnSetterSourceIntegrationPassed':True,'findings':[],
        'actualResult':results[0],'genuineSDKCompilerDeclaration':genuine.group(0),
        'ownIOSCompilerDefinition':own.group(0),'steps':steps,
        'inputs':[pin(p) for p in sorted(set(inputs))],
        'SDKPrefixABICompatible':True,'directHVInterposer':False,
        'unexpectedReleaseFailureReferenceRetainedByTLS':True,
        'actualReleaseFailureInjected':False,'nativeCPUCallsExecuted':0,
        'providerLinkedWithSetters':False,'deviceOperations':0,'full27Backend':False}
    (OUTPUT/'candidate.json').write_text(json.dumps(report,indent=2)+'\n')
    pins={r['path']:r for r in report['inputs']}
    for path in OUTPUT.iterdir():
        if path.is_file(): pins[str(path.resolve())]=pin(path)
    (OUTPUT/'freeze.json').write_text(json.dumps({'schema':'Finite setter source integration pins v1',
        'files':list(pins.values())},indent=2)+'\n')
    print(json.dumps({'candidate':pin(OUTPUT/'candidate.json'),'freeze':pin(OUTPUT/'freeze.json'),
        'checks':results[0]['checks']}))
if __name__=='__main__': main()
