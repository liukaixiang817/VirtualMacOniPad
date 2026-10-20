#!/usr/bin/env python3
"""Strictly compile the owned relative mouse adapter; no link/sign/load/device."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess


def pin(path):
    data = path.read_bytes()
    return dict(path=str(path.resolve()),bytes=len(data),sha256=hashlib.sha256(data).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out',type=Path,required=True)
    args = parser.parse_args()
    output = args.out.resolve()
    assert not output.exists()
    root = Path(__file__).resolve().parents[2]
    source = root/'vz/host/vm27_scoped_pointer_input_v2.m'
    header = source.with_suffix('.h')
    lifecycle = source.with_name('vm27_scoped_pointer_lifecycle_v1.h')
    pins = [pin(path) for path in [source,header,lifecycle,Path(__file__)]]
    output.mkdir(parents=True)
    records = []

    def run(label, argv, expected):
        result = subprocess.run(list(map(str,argv)),capture_output=True,timeout=30)
        (output/(label+'.stdout')).write_bytes(result.stdout)
        (output/(label+'.stderr')).write_bytes(result.stderr)
        records.append(dict(label=label,argv=list(map(str,argv)),exit=result.returncode))
        assert (result.returncode == 0) is expected, result.stderr.decode(errors='replace')
        return result
    sdk = run('sdk',['xcrun','--sdk','iphoneos','--show-sdk-path'],True).stdout.decode().strip()
    obj = output/'vm27_scoped_pointer_input_v2.o'
    base = ['xcrun','clang','-target','arm64e-apple-ios16.1','-isysroot',sdk,
        '-fobjc-arc','-fblocks','-fno-autolink','-Wall','-Wextra','-Werror','-Wunguarded-availability-new']
    run('strict',base+['-c',source,'-o',obj],True)
    no_arc = run('no-arc',[x if x!='-fobjc-arc' else '-fno-objc-arc' for x in base]+['-fsyntax-only',source],False)
    assert b'VM27 scoped pointer input v2 requires ARC.' in no_arc.stderr
    client = output/'deployment-floor-negative.m'
    client.write_text('#import "vm27_scoped_pointer_input_v2.h"\n'
        'void only_compile(VM27ScopedPointerControllerV1 *controller) {\n'
        ' (void)[[VM27ScopedPointerInputV2 alloc] initWithController:controller owner:1 generation:1];\n}\n')
    old = [x if x!='arm64e-apple-ios16.1' else 'arm64e-apple-ios16.0' for x in base]
    negative = run('ios16.0',old+['-I',source.parent,'-fsyntax-only',client],False)
    assert b'only available on iOS 16.1 or newer' in negative.stderr
    defined = run('defined',['xcrun','nm','-gU',obj],True).stdout.decode()
    imports = run('undefined',['xcrun','nm','-u',obj],True).stdout.decode()
    assert '_OBJC_CLASS_$_VM27ScopedPointerInputV2' in defined
    assert not any(name in defined+imports for name in ['_SL','_hv_','Hypervisor','Virtualization'])
    data = obj.read_bytes()
    assert struct.unpack_from('<I',data)[0] == 0xfeedfacf and struct.unpack_from('<I',data,12)[0] == 1
    commands, at = [], 32
    for _ in range(struct.unpack_from('<I',data,16)[0]):
        command, length = struct.unpack_from('<II',data,at)
        assert length>=8 and length%8==0
        commands.append(command)
        at += length
    assert commands == [0x19,0x32,0x2,0xb]
    assert at == 32+struct.unpack_from('<I',data,20)[0]
    for record in pins:
        assert pin(Path(record['path'])) == record
    result = dict(schema='Owned relative pointer input v2 strict compile only',sources=pins,
        object=pin(obj),commands=records,negativeCompileControls=2,
        SDKPath=sdk,target='arm64e-apple-ios16.1',machFileType='MH_OBJECT',
        SLExports=False,frontendIntegrated=False,pointerEffectActuallyTested=False,
        actualMouseMotionDelivered=False,nativeExecuted=False,deviceOperations=0,
        originalVZLoaded=False,originalVMMExecuted=False,guestInstructions=0,full27Backend=False)
    (output/'candidate.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(object=result['object'],negativeControls=2,nativeExecuted=False)))


if __name__ == '__main__':
    main()
