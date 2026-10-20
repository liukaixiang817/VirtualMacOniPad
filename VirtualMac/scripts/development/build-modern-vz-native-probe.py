#!/usr/bin/env python3
"""Build independent VZ27 configuration probes; no device operations or execution."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    project = Path(__file__).resolve().parents[2]
    source = project / 'vz/host/modern_vz_native_configuration_probe.mm'
    required_header = source.with_name('modern_vz_required_imports.h')
    records, binaries = [], []
    rights = output / 'Probe.entitlements'
    rights.write_bytes(plistlib.dumps({'platform-application': True}))
    for sdkname, target, role in [('iphoneos','arm64e-apple-ios16.1','ios'),
                                  ('macosx','arm64e-apple-macos27.0','mac')]:
        sdk = subprocess.check_output(['xcrun','--sdk',sdkname,'--show-sdk-path'],text=True).strip()
        binary = output / ('vz27-native-config-' + role)
        commands = [('compile',['xcrun','clang++','-target',target,'-isysroot',sdk,
            '-O2','-std=c++17','-fobjc-arc','-fno-exceptions','-fno-rtti',
            '-fno-typed-cxx-new-delete','-fno-typed-memory-operations','-Wall','-Wextra','-Werror',
            str(source),'-framework','Foundation','-o',str(binary)]),
            ('sign',['codesign','--force','--sign','-','--timestamp=none',str(binary)] +
                (['--entitlements',str(rights)] if role == 'ios' else [])),
            ('strict',['codesign','--verify','--strict',str(binary)]),
            ('dyld',['xcrun','dyld_info','-validate_only','-imports','-linked_dylibs',str(binary)]),
            ('signature',['codesign','-d','--verbose=4',str(binary)])]
        for label, argv in commands:
            result = subprocess.run(argv,capture_output=True,text=True,timeout=60)
            records.append(dict(role=role,label=label,argv=argv,exit=result.returncode,
                                stdout=result.stdout,stderr=result.stderr))
            (output/'commands.json').write_text(json.dumps(records,indent=2)+'\n')
            if result.returncode: raise SystemExit(result.stderr)
        if 'Virtualization.framework' in records[-2]['stdout'] or 'Hypervisor.framework' in records[-2]['stdout']:
            raise SystemExit('Probe must not link any VZ/HV provider')
        binaries.append(dict(name=binary.name,bytes=binary.stat().st_size,
            sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
            cdhash=re.search(r'CDHash=([0-9a-f]{40})',records[-1]['stderr'])[1]))
    manifest = dict(source=str(source),sourceSHA256=hashlib.sha256(source.read_bytes()).hexdigest(),
        requiredImportsHeaderSHA256=hashlib.sha256(required_header.read_bytes()).hexdigest(),
        originalNonweakNlistRequired=844,originalFixupClosureRecovered=False,
        originalVZUUID='418efc4809d93606918eb6f95baeffdc',binaries=binaries,
        scope='exact image + two real Swift metadata accessors + CPU/memory configuration lifecycle',
        VMCreated=False,VMMStarted=False,GPUWork=False,deviceExecuted=False,nativeExecuted=False,
        entitlementsIOS={'platform-application':True},entitlementsMac={})
    (output/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps(manifest,indent=2))


if __name__ == '__main__': main()
