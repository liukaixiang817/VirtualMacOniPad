#!/usr/bin/env python3
"""Build an actual immutable CFString export and ordinary native Mac comparison."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('request_key_current_s', HERE / 'audit-modern-current-stock-extra-exports-v2.py')
s = importlib.util.module_from_spec(spec); spec.loader.exec_module(s)
p = s.p
HOST = p.ROOT / 'VirtualMac/vz/host'
ORIGINAL = p.NODE / 'iokit-three-original-abi-readonly-v3/audit.json'


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output', required=True, type=Path)
    out = ap.parse_args().output.resolve()
    assert out.is_relative_to(p.NODE) and not out.exists()
    out.mkdir()
    inputs = [Path(__file__), ORIGINAL, HOST/'modern_iokit_request_terminate_key.c',
              HOST/'modern_iokit_request_terminate_key_fixture.c']
    original = json.loads(ORIGINAL.read_bytes())
    for pin in json.loads((ORIGINAL.parent/'freeze.json').read_bytes())['files']:
        assert p.pin(Path(pin['path'])) == pin
    assert original['requestTerminateConstant']['actualObjectKind'] == 'CFConstantString'
    assert original['requestTerminateConstant']['value'] == 'RequestTerminate'
    pins = list(map(p.pin, inputs))
    images = s.primary.captured_images()
    current_pins = s.join_capture(images, 'stock-extra', p.NODE/'ipad-current-cache-stock-extra-headers-v1/headers.json')
    assert s.primary.resolve(images, '/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation',
                             '___CFConstantStringClassReference')['status'] == 'actualDirectExport'
    commands, roles = [], []
    def run(label, argv):
        result = subprocess.run(list(map(str,argv)),capture_output=True,timeout=60)
        (out/(label+'.stdout')).write_bytes(result.stdout)
        (out/(label+'.stderr')).write_bytes(result.stderr)
        commands.append(dict(label=label,argv=list(map(str,argv)),exit=result.returncode,
            stdoutSHA256=hashlib.sha256(result.stdout).hexdigest(),stderrSHA256=hashlib.sha256(result.stderr).hexdigest()))
        p.save(out/'commands.json',commands)
        assert result.returncode == 0,(label,result.stderr.decode())
        return result
    try:
        for label in ('mac','mac-sanitized'):
            sdk = run(label+'-sdk',['xcrun','--sdk','macosx','--show-sdk-path']).stdout.decode().strip()
            exe = out/(label+'-native-constant-fixture')
            flags = ['xcrun','--sdk','macosx','clang','-target','arm64e-apple-macos13.0',
                     '-isysroot',sdk,'-O2','-Wall','-Wextra','-Werror']
            if label == 'mac-sanitized': flags += ['-fsanitize=address,undefined']
            run(label+'-build',flags+['-DVM27_REQUEST_TERMINATE_SYMBOL=VM27RequestTerminateFixtureKey',
                inputs[2],inputs[3],'-framework','CoreFoundation','-framework','IOKit','-o',exe])
            tested = run(label+'-native-compare',[exe])
            actual = json.loads(tested.stdout)
            assert not tested.stderr and actual['nativeIOKitConstantCompared'] and actual['checks'] >= 520
            assert actual['retainReleasePairs'] == 256 and not actual['nativeHIDEventConstructorsExecuted']
            roles.append(dict(role=label,fixture=p.pin(exe),actualOrdinaryNativeIOKitComparison=actual,
                              addressAndUndefinedSanitized=label=='mac-sanitized'))
        sdk = run('ios-sdk',['xcrun','--sdk','iphoneos','--show-sdk-path']).stdout.decode().strip()
        exports = out/'exports.list'; exports.write_text('_kIOHIDServiceRequestTerminateKey\n')
        provider = out/'IK.unsigned.inert.macho-data'
        flags = ['xcrun','--sdk','iphoneos','clang','-target','arm64e-apple-ios16.1',
                 '-isysroot',sdk,'-O2','-fvisibility=hidden','-Wall','-Wextra','-Werror']
        run('ios-build',flags+['-dynamiclib',inputs[2],'-framework','CoreFoundation',
            '-Wl,-install_name,@rpath/VM27IOKitRequestTerminate.dylib','-Wl,-exported_symbols_list,'+str(exports),
            '-Wl,-no_adhoc_codesign','-o',provider])
        run('ios-dyld-validate',['xcrun','dyld_info','-validate_only',provider])
        raw = provider.read_bytes()
        assert not any(cmd==0x1d for cmd,at,size in p.commands(raw))
        off,length = next(struct.unpack_from('<II',raw,at+8) for cmd,at,size in p.commands(raw)if cmd==0x80000033)
        defs = s.primary.trie(raw[off:off+length])
        assert len(defs)==1 and defs['_kIOHIDServiceRequestTerminateKey']['flags']==0
        imports = p.imports(raw)['imports']; deps={x['ordinal']:x['path']for x in p.dependencies(raw)}
        assert len(imports)==1 and imports[0]['name']=='___CFConstantStringClassReference'
        proof = s.primary.resolve(images,deps[imports[0]['ordinal']],imports[0]['name'])
        assert proof['status']=='actualDirectExport' and imports[0]['ordinal']>0 and not imports[0]['weak']
        ir = out/'ios-key.ll'; run('ios-IR',flags+['-S','-emit-llvm',inputs[2],'-o',ir])
        llvm = ir.read_text()
        assert re.search(r'^@kIOHIDServiceRequestTerminateKey = (?:local_unnamed_addr )?constant ptr @_unnamed_cfstring_, align 8$', llvm, re.M)
        assert 'c"RequestTerminate\\00"' in llvm and 'i32 1992' in llvm and 'i64 16' in llvm
        assert 'i32 2, i64 ptrtoint (ptr @_unnamed_cfstring_ to i64), i64 27361' in llvm
        assert pins == list(map(p.pin,inputs))
        report=dict(schema='Genuine RequestTerminate immutable CFString provider data v1',inputs=pins,
            originalABI=p.pin(ORIGINAL),ordinaryMacRoles=roles,iosProvider=p.pin(provider),iosIR=p.pin(ir),
            exactExports=defs,actualCurrentNativeImport=dict(imports[0],dependency=deps[imports[0]['ordinal']],proof=proof),
            originalCFStringTypeValueLifetimePreserved=True,constantSourceNotCString=True,
            originalTwoUHValueBridgeCallersCaptured=True,originalTwoUHValueBridgeCallersExecuted=False,
            missingEventConstructorsImplemented=False,currentFullIOKitGraphProven=False,
            codeSigned=False,nativeIOSExecuted=False,deviceOperations=0,originalHIDLoaded=False,
            originalVZLoaded=False,candidateReadyForNativeLoading=False,full27Backend=False)
        p.save(out/'candidate.json',report)
        files=[x for x in out.rglob('*')if x.is_file()]
        p.save(out/'freeze.json',dict(files=pins+current_pins+list(map(p.pin,files)),deviceOperations=0))
        print(json.dumps(dict(candidate=p.pin(out/'candidate.json'),provider=p.pin(provider),roles=roles)))
    except Exception as error:
        failed=out/'failed-sources';failed.mkdir(exist_ok=True)
        for source in inputs:(failed/source.name).write_bytes(source.read_bytes())
        p.save(out/'failure.json',dict(error=repr(error),inputs=pins,nativeIOSExecuted=False,deviceOperations=0))
        raise


if __name__=='__main__':main()
