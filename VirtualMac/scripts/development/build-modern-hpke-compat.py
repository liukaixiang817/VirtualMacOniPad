#!/usr/bin/env python3
"""Build a private Apple-source HPKE module using existing native key objects.

No device operation, original CryptoKit UUID, hand-built Swift metadata or
global Swift runtime hook. Original nominal context names are not preserved.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[3]
SOURCE = ROOT / 'VirtualMac/vz/host/modern_hpke_compat'
SHA = lambda data: hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir()
    provenance = json.loads((SOURCE / 'upstream-manifest.json').read_bytes())
    aliases = json.loads((SOURCE / 'abi-aliases.json').read_bytes())
    assert provenance['commit'] == '629f0b679d0fd0a6ae823d7f750b9ab032c00b80'
    assert provenance['originalCryptoKitBinaryClaimed'] is False
    assert len(provenance['sources']) == 17 and len(aliases['aliases']) == 16
    for row in provenance['sources']:
        assert SHA((SOURCE / row['generatedPath']).read_bytes()) == row['generatedSHA256']
    authored = provenance['authoredNativeConformances']
    assert SHA((SOURCE / authored['file']).read_bytes()) == authored['sha256']
    destination = out / 'source'
    shutil.copytree(SOURCE, destination)
    sources = sorted(destination.glob('*.swift'))
    assert len(sources) == 18
    (out / 'provenance.json').write_bytes((SOURCE / 'upstream-manifest.json').read_bytes())
    (out / 'aliases.json').write_bytes((SOURCE / 'abi-aliases.json').read_bytes())
    processes = []

    def run(label, argv):
        child = subprocess.Popen([str(item) for item in argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            stdout, stderr = child.communicate(timeout=60)
        except subprocess.TimeoutExpired:
            child.kill()
            stdout, stderr = child.communicate()
            raise
        (out / (label + '.stdout')).write_bytes(stdout)
        (out / (label + '.stderr')).write_bytes(stderr)
        processes.append(dict(label=label, argv=[str(item) for item in argv], PID=child.pid,
                              wait=child.returncode, reaped=True))
        (out / 'processes.json').write_text(json.dumps(processes, indent=2) + '\n')
        assert child.returncode == 0, label + ': ' + stderr.decode(errors='replace')[-5000:]
        return stdout

    for role, sdk, target in [('mac', 'macosx', 'arm64e-apple-macos13.0'),
                              ('ios', 'iphoneos', 'arm64e-apple-ios16.1')]:
        directory = out / role
        directory.mkdir()
        sdkpath = run(role + '-sdk', ['xcrun', '--sdk', sdk, '--show-sdk-path']).decode().strip()
        common = ['xcrun', 'swiftc', '-parse-as-library', '-target', target, '-sdk', sdkpath,
                  '-module-name', 'VM27HPKE', '-module-cache-path', out / (role + '-cache'),
                  '-enable-library-evolution', '-Xfrontend', '-disable-layout-string-value-witnesses',
                  '-Xfrontend', '-disable-layout-string-value-witnesses-instantiation',
                  '-Xfrontend', '-disable-availability-checking', '-whole-module-optimization', '-O']
        run(role + '-module', common + sources + ['-emit-module', '-emit-module-path', directory / 'VM27HPKE.swiftmodule'])
        run(role + '-ir', common + sources + ['-emit-ir', '-o', out / (role + '.ll')])
        arguments = []
        for row in aliases['aliases']:
            assert row['newPrivateSemantics'] is True and row['originalTypeContextNameRetained'] is False
            original = subprocess.check_output(['xcrun', 'swift-demangle', '--compact', row['originalSymbol']], text=True).strip()
            natural = subprocess.check_output(['xcrun', 'swift-demangle', '--compact', row['naturalSymbol']], text=True).strip()
            assert original.replace('CryptoKit.HPKE', 'VM27HPKE.HPKE').replace('in CryptoKit', 'in VM27HPKE') == natural
            arguments += ['-Xlinker', '-alias', '-Xlinker', row['naturalSymbol'], '-Xlinker', row['originalSymbol']]
        library = directory / 'VM27HPKECompat.dylib'
        run(role + '-library', common + sources + arguments + ['-Xlinker', '-reexport_framework', '-Xlinker', 'CryptoKit',
            '-emit-library', '-Xlinker', '-install_name', '-Xlinker', '@rpath/VM27HPKECompat.dylib', '-o', library])
        run(role + '-exports', ['xcrun', 'dyld_info', '-exports', library])
        run(role + '-imports', ['xcrun', 'dyld_info', '-imports', '-linked_dylibs', library])
    print(json.dumps(dict(sourceFiles=18, privateNaturalModule='VM27HPKE', aliases=16,
                          originalCryptoKitBinaryClaimed=False, functionalValidationPending=True)))


if __name__ == '__main__':
    main()
