"""Build the device-independent cache adapter without changing frozen inputs."""
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess

R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S = R / 'VirtualMac/vz/host'
O = N / 'portable-vz-cache-helper-v2-attempt1'

def pin(p):
    p = Path(p).resolve()
    data = p.read_bytes()
    return dict(path=str(p), bytes=len(data), sha256=hashlib.sha256(data).hexdigest())

def main():
    O.mkdir(mode=0o700)
    commands = []
    def run(label, argv):
        argv = list(map(str, argv))
        result = subprocess.run(argv, capture_output=True, timeout=90)
        (O / (label+'.stdout')).write_bytes(result.stdout)
        (O / (label+'.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label, argv=argv, exit=result.returncode))
        (O/'commands.json').write_text(json.dumps(commands, indent=2)+'\n')
        if result.returncode:
            raise RuntimeError(label+': '+result.stderr.decode())
    source = S/'vm27_owned_vz_cache_confstr_v2_portable.c'
    test = S/'test_vm27_owned_vz_cache_confstr_v2_portable.c'
    obj = O/'cache.o'
    flags = ['-target','arm64e-apple-ios15.0','-O2','-fvisibility=hidden',
             '-Wall','-Wextra','-Werror','-I',S]
    run('compile-cache', ['xcrun','--sdk','iphoneos','clang',*flags,'-std=c11','-c',source,'-o',obj])
    local = S/'vm27_owned_vz_localization_v2_trace.m'
    localobj = O/'localization.o'
    run('compile-localization', ['xcrun','--sdk','iphoneos','clang',*flags,'-fobjc-arc','-fblocks','-c',local,'-o',localobj])
    dll = O/'VM27OwnedVZStartCompat.dylib'
    run('link-helper', ['xcrun','--sdk','iphoneos','clang',*flags,'-dynamiclib',
        '-Wl,-no_adhoc_codesign','-Wl,-install_name,@loader_path/'+dll.name,
        '-Wl,-exported_symbol,_VM27OwnedVZCacheConfstrV1',
        '-Wl,-exported_symbol,_VM27OwnedVZLocalizedStringOrEnglishKeyV1',
        obj,localobj,'-framework','Foundation','-lobjc','-o',dll])
    run('validate-helper',['xcrun','dyld_info','-validate_only',dll])
    for label, extra in [('normal', []), ('san', ['-fsanitize=address,undefined','-fno-omit-frame-pointer'])]:
        exe = O/('test-'+label)
        run('compile-'+label,['xcrun','--sdk','macosx','clang','-std=c11',
            '-Wall','-Wextra','-Werror',*extra,test,'-o',exe])
        run('run-'+label,[exe])
    readerpath=N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
    spec=importlib.util.spec_from_file_location('cache_image', readerpath)
    reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
    image=reader.MachO(dll.read_bytes())
    assert set(image.exports)=={'_VM27OwnedVZCacheConfstrV1','_VM27OwnedVZLocalizedStringOrEnglishKeyV1'}
    assert b'dopamine-FUG16w' not in dll.read_bytes() and b'/private/preboot/' not in dll.read_bytes()
    result=dict(schema='Portable owned cache adapter; stable rootless alias and native libc export identity',
        provider=pin(dll),sources=[pin(source),pin(test),pin(local)],builder=pin(__file__),
        exports=image.exports,imports=image.imports,loads=image.loads,
        hostTestsPassed=True,deviceOperations=0,newDeviceGuestBootVerified=False,
        cacheFallbackSemanticsUnchanged=True,appOwnerAndInodeVerified=True,
        nativeConfstrResolution='exact export of already loaded native libsystem_c, not a fixed build UUID/RVA')
    (O/'candidate.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(pin(O/'candidate.json')))

if __name__=='__main__':main()
