#!/usr/bin/env python3
"""Bundle corresponding network sources and the tested App's relink inputs."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import tarfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--app-candidate', required=True, type=Path)
    parser.add_argument('--release', required=True, type=Path)
    parser.add_argument('--network-upstream', required=True, type=Path)
    args = parser.parse_args()
    app = json.loads(args.app_candidate.read_bytes())
    root = args.release / 'network-source-and-relink-v2'
    root.mkdir()
    for name in ('objects', 'libraries', 'sources', 'AppResources', 'upstream'):
        (root / name).mkdir()
    mapping = {}
    for index, row in enumerate(app['objects']):
        source = Path(row['path'])
        assert hashlib.sha256(source.read_bytes()).hexdigest() == row['sha256']
        target = Path('objects') / (str(index) + '.o')
        shutil.copyfile(source, root / target)
        mapping[str(source)] = str(target)
    for row in app['sourceFiles'] + app['actualIncludeClosure']:
        source = Path(row['path'])
        if source.suffix not in ('.h', '.inc', '.m', '.mm', '.c', '.S'):
            continue
        assert hashlib.sha256(source.read_bytes()).hexdigest() == row['sha256']
        target = root / 'sources' / source.name
        if target.exists() and target.read_bytes() != source.read_bytes():
            # Candidate history also pins old generated anchors. Keep those
            # separate instead of replacing a current translation unit.
            target = root / 'sources/historical' / row['sha256'] / source.name
            target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            shutil.copyfile(source, target)
    app_path = args.release / 'stage/var/jb/Applications/VirtualMacIndependent27.app'
    shutil.copytree(app_path, root / 'AppResources/VirtualMacIndependent27.app')
    (root / 'AppResources/VirtualMacIndependent27.app/VirtualMacIndependent27').unlink()
    shutil.rmtree(root / 'AppResources/VirtualMacIndependent27.app/_CodeSignature')
    upstream = args.network_upstream.resolve()
    library_paths = [upstream / 'ios-build-v1/libslirp.a',
                     upstream / 'ios-build-v1/subprojects/glib/glib/libglib-2.0.a',
                     upstream / 'ios-build-v1/subprojects/proxy-libintl-0.5/libintl.a']
    for source in library_paths:
        target = Path('libraries') / source.name
        shutil.copyfile(source, root / target)
        mapping[str(source)] = str(target)
    argv = next(c['argv'] for c in app['commands'] if c['label'] == 'link-app')
    portable = []
    skip = False
    for index, value in enumerate(argv):
        if skip:
            skip = False
            continue
        if value == '-I':
            skip = True
            continue
        if index and argv[index - 1] == '-isysroot':
            portable.append('@SDK@')
        elif index and argv[index - 1] == '-o':
            portable.append('@APP@/VirtualMacIndependent27')
        elif value.startswith('-Wl,-load_hidden,'):
            portable.append('-Wl,-load_hidden,@ROOT@/' + mapping[value.split(',', 2)[2]])
        elif value in mapping:
            portable.append('@ROOT@/' + mapping[value])
        else:
            portable.append(value)
    (root / 'link-argv.json').write_text(json.dumps(portable, indent=2) + '\n')
    for name in ('libslirp-v4.9.5.tar.gz', 'glib-2.88.3.tar.xz',
                 'source-downloads.json', 'darwin-static-recipe-v1.diff',
                 'ios16-native-config-override-v1.json'):
        shutil.copyfile(upstream / name, root / 'upstream' / name)
    shutil.copytree(upstream / 'libslirp-v4.9.5/subprojects/packagecache', root / 'upstream/packagecache')
    # SPDX/license text remains in the original corresponding source archives.
    shutil.copytree(args.release / 'stage/var/jb/usr/share/virtualmac-independent27/licenses', root / 'licenses')
    (root / 'relink.py').write_text('''#!/usr/bin/env python3
import json,pathlib,shutil,subprocess,tempfile
r=pathlib.Path(__file__).resolve().parent
destination=r/'Relinked/VirtualMacIndependent27.app'
assert not destination.exists(), 'Use a fresh Relinked directory'
work=tempfile.TemporaryDirectory(prefix='vm27-relink-',dir='/private/tmp')
a=pathlib.Path(work.name)/'VirtualMacIndependent27.app'
shutil.copytree(r/'AppResources/VirtualMacIndependent27.app',a)
subprocess.run(['xattr','-cr',str(a)],check=True)
sdk=subprocess.check_output(['xcrun','--sdk','iphoneos','--show-sdk-path'],text=True).strip()
argv=[s.replace('@SDK@',sdk).replace('@ROOT@',str(r)).replace('@APP@',str(a))for s in json.loads((r/'link-argv.json').read_text())]
subprocess.run(argv,check=True)
subprocess.run(['codesign','--force','--sign','-','--timestamp=none','--digest-algorithm=sha256','--identifier','com.mac.virtual.independent27','--entitlements',str(r/'sources/VirtualMac.entitlements'),'--generate-entitlement-der',str(a)],check=True)
subprocess.run(['codesign','--verify','--strict',str(a)],check=True)
destination.parent.mkdir(exist_ok=True)
shutil.copytree(a,destination,copy_function=shutil.copyfile)
for source in a.rglob('*'):
 target=destination/source.relative_to(a)
 target.chmod(source.stat().st_mode&0o7777)
work.cleanup()
print(destination)
''')
    source = Path(__file__).resolve().parents[2] / 'vz/host/VirtualMac.entitlements'
    shutil.copyfile(source, root / 'sources/VirtualMac.entitlements')
    (root / 'README.txt').write_text('''VirtualMac 2.0.0beta2 network library sources and App relink inputs

Requires Xcode with the iPhoneOS SDK on an Apple Silicon Mac and Python 3.
Run: python3 relink.py
This links the actual App objects against libraries/libslirp.a, libglib-2.0.a
and libintl.a, then ad-hoc signs a copy with the supplied entitlements.
You may replace these static libraries with your modified compatible versions.
The separate independent runtime and guest disks are not changed by this tool.
Installing the modified App requires trusting its new CDHash on your own device.
Removal of an injected trust entry may require rebooting that device.

Corresponding upstream sources are in upstream/. No upstream C source was changed.
Build used Meson 1.12.1, Ninja 1.13.2, arm64e-apple-ios16.1 and iPhoneOS27.1 SDK.
libslirp's Darwin static recipe omits the unsupported compiler -static flag.
GLib's generated config.h undefines HAVE_PIPE2 for the actual iOS16 target,
selecting the upstream pipe/fcntl implementation. See the supplied patch/record.
Build GLib and libslirp as static with -Dstatic=true --default-library=static,
GLib tests/NLS/docs/introspection disabled. Build proxy-libintl's static libintl.a
as well. Keep the same target/sysroot when recompiling.

The App object files allow relinking against modified LGPL libraries. The
repository sources contain the compatibility implementation; these files
also include the exact App translation units and their project header closure.
''')
    hashes = [(hashlib.sha256(p.read_bytes()).hexdigest(), str(p.relative_to(root)))
              for p in sorted(root.rglob('*')) if p.is_file()]
    (root / 'SHA256SUMS').write_text(''.join(h + '  ' + name + '\n' for h, name in hashes))
    target = args.release / 'VirtualMac_2.0.0beta2_network-source-and-relink.tar.xz'
    with tarfile.open(target, 'w:xz') as archive:
        archive.add(root, arcname=root.name)
    print(json.dumps(dict(asset=str(target), bytes=target.stat().st_size,
                          sha256=hashlib.sha256(target.read_bytes()).hexdigest())))


if __name__ == '__main__':
    main()
