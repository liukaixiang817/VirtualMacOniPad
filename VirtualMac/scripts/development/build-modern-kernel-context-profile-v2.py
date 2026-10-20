"""Build the versioned, application-private typed CPU context provider.

This performs local compilation/signing only. It never loads the provider,
contacts an iPad, grants trust, or starts a guest.
"""
from pathlib import Path
import hashlib, json, plistlib, shutil, subprocess, sys

R = Path(__file__).resolve().parents[3]
P = R/'VirtualMac/vz/host'
D = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/kernel-context-profiles-product-v2'
H = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
def pin(p):
    return dict(path=str(p.relative_to(R)),bytes=p.stat().st_size,sha256=H(p))

assert sys.argv[1:] == []
models = json.loads((D/'model-result.json').read_bytes())
assert models['passed'] is True and len(models['results']) == 12
assert models['nativeOperations'] == models['deviceOperations'] == models['guestInstructions'] == 0
for command in models['commands']:
    assert command['exit'] == 0
    if not command['label'].endswith('-compile') and not command['label'].startswith('ios-object-'):
        assert (D/'tests'/(command['label']+'.stderr')).read_bytes() == b''
for row in models['sources']+models['oldModelSources']+models['sourceFreeze']:
    p = R/row['path']
    assert p.is_file() and not p.is_symlink() and pin(p) == row
out = D/'provider-build-v2'
assert not out.exists()
out.mkdir()
source = out/'source'
source.mkdir()
for p in sorted((D/'source-freeze').iterdir()):
    if p.name.startswith('modern_cpu_'):
        shutil.copyfile(p,source/p.name)
commands = []
def run(label,argv):
    argv = list(map(str,argv))
    r = subprocess.run(argv,capture_output=True)
    (out/(label+'.stdout')).write_bytes(r.stdout)
    (out/(label+'.stderr')).write_bytes(r.stderr)
    commands.append(dict(label=label,argv=argv,exit=r.returncode))
    assert r.returncode == 0, (label,r.stderr.decode())
    return r
candidate = out/'VM27KernelContextProfilesV2.dylib'
implementation = [source/n for n in ('modern_cpu_kernel_lifecycle_v2.c',
    'modern_cpu_native_fields.c','modern_cpu_kernel_initialization_v2.c',
    'modern_cpu_kernel_system_v2.c')]
run('ios-link',['xcrun','--sdk','iphoneos','clang','-arch','arm64e',
    '-miphoneos-version-min=16.1','-std=c11','-Wall','-Wextra','-Werror','-pthread',
    '-I',source,'-dynamiclib',*implementation,'-Wl,-undefined,error',
    '-Wl,-install_name,@rpath/VM27KernelContextProfilesV2.dylib',
    '-Wl,-current_version,2.0','-Wl,-compatibility_version,2.0','-o',candidate])
run('adhoc-sign',['codesign','--force','--sign','-',candidate])
run('strict-signature',['codesign','--verify','--strict',candidate])
identity = run('signature-identity',['codesign','-d','--verbose=4',candidate]).stderr.decode()
ent = run('entitlements',['codesign','-d','--entitlements',':-',candidate]).stdout
assert not ent or plistlib.loads(ent) == {}
run('metadata',['xcrun','dyld_info','-validate_only',candidate])
deps = run('dependencies',['otool','-L',candidate]).stdout.decode()
assert all(s not in deps for s in ('Hypervisor.framework','Virtualization.framework','VirtualMac2','13.2.1'))
exports = run('exports',['xcrun','nm','-gU',candidate]).stdout.decode()
for symbol in ('VZKernelVMCreate','VZKernelCPUDestroy','VZKernelCPUApplyInitialization',
    'VZKernelCPUAccessSystemRegister'):
    assert (' _'+symbol+'\n') in exports
assert ' _VZCPU27KernelTrapRaw\n' not in exports
commands_path = out/'commands.json'
commands_path.write_text(json.dumps(commands,indent=2)+'\n')
result = dict(schema='application-private-kernel-context-profile-v2-provider',
    candidate=pin(candidate),source=[pin(p) for p in sorted(source.iterdir())],
    modelReceipt=pin(D/'model-result.json'),signingIdentity=identity,
    entitlements={},nativeISA=[1,2],knownKernelProfile='iPadOS16.1.1-version0e',
    requiresActualOwnerAndGeneration=True,typedContextSlicesOnly=True,
    validatedTrapSuppliedByCaller=True,nativeTrapEntryLinked=False,
    supportsISA3=False,completeArchitecturalReset=False,guestRunImplemented=False,
    originalVMMExecuted=False,originalVZLoaded=False,deviceOperations=0,full27Backend=False)
(out/'candidate.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(dict(candidate=pin(candidate),nativeISA=[1,2],deviceOperations=0,
    guestRunImplemented=False,full27Backend=False),indent=2))
