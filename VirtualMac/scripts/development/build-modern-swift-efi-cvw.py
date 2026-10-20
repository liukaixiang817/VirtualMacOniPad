#!/usr/bin/env python3
"""Build a private, UUID-gated EFI ownership provider; never deploy or execute."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True,exist_ok=False)
    project = Path(__file__).resolve().parents[2]
    source = project/'vz/host/modern_swift_efi_cvw_compat.cpp'
    inputs = [source,source.with_suffix('.h'),project/'vendor/swift-bytecode-enum-tag/LICENSE.txt']
    exports = ['VM27EFICVWQuery','VM27EFICVWGetEnumTag','VM27EFICVWDestroy',
        'VM27EFICVWInitWithCopy','VM27EFICVWAssignWithCopy','VM27EFICVWAssignWithTake','VM27EFICVWBufferCopy']
    commands,files = [],[]
    for sdkname,target,role in [('iphoneos','arm64e-apple-ios16.1','ios'),('macosx','arm64e-apple-macos27.0','mac')]:
        sdk = subprocess.check_output(['xcrun','--sdk',sdkname,'--show-sdk-path'],text=True).strip()
        library = output/('VM27EFICVW-'+role+'.dylib')
        compile = ['xcrun','clang++','-target',target,'-isysroot',sdk,'-O2','-std=c++17',
            '-fno-exceptions','-fno-rtti','-nostdlib++','-fno-typed-cxx-new-delete','-fno-typed-memory-operations',
            '-Wall','-Wextra','-Werror','-dynamiclib',str(source),'-L'+sdk+'/usr/lib/swift','-lswiftCore',
            '-lobjc','-Wl,-install_name,@rpath/VM27EFICVW.dylib','-o',str(library)]
        compile += ['-Wl,-exported_symbol,_'+x for x in exports]
        for label,argv in [('compile',compile),('sign',['codesign','--force','--sign','-','--timestamp=none',str(library)]),
                ('strict',['codesign','--verify','--strict',str(library)]),
                ('dyld',['xcrun','dyld_info','-validate_only','-imports','-linked_dylibs',str(library)]),
                ('exports',['xcrun','nm','-gU',str(library)]),('signature',['codesign','-d','--verbose=4',str(library)])]:
            result = subprocess.run(argv,capture_output=True,text=True,timeout=30)
            commands.append(dict(role=role,label=label,argv=argv,exit=result.returncode,stdout=result.stdout,stderr=result.stderr))
            (output/'commands.json').write_text(json.dumps(commands,indent=2)+'\n')
            if result.returncode:raise SystemExit(result.stderr)
        actual = sorted(x.split()[-1][1:] for x in commands[-2]['stdout'].splitlines())
        if actual != sorted(exports):raise SystemExit('unexpected exports: '+repr(actual))
        files.append(dict(name=library.name,bytes=library.stat().st_size,
            sha256=hashlib.sha256(library.read_bytes()).hexdigest(),
            cdhash=re.search(r'CDHash=([0-9a-f]{40})',commands[-1]['stderr'])[1]))
    manifest = dict(inputs=[dict(path=str(p),sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in inputs],
        files=files,exports=exports,genuineType='VZ27 VZEFISignature only',originalVZUUID='418efc4809d93606918eb6f95baeffdc',
        globalSwiftOverride=False,completeCVWInterpreter=False,overrideRegistry=False,deviceOperations=False,nativeExecution=False)
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(manifest,indent=2))


if __name__ == '__main__':main()
