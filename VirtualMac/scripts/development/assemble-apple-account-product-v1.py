#!/usr/bin/env python3
"""Assemble the complete native Apple Account runtime and UIKit App.

Reuses the verified release signing, manifest and dependency proof contracts;
contains no VM disks, account credentials or cloud authentication data.
"""
from pathlib import Path
import argparse
import copy
import hashlib
import importlib.util
import json
import plistlib
import shutil
import subprocess
import tempfile

R = Path(__file__).resolve().parents[3]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--cpu', type=Path, required=True)
parser.add_argument('--installer', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--release', action='store_true',
    help='Build Beta 8 from the verified Beta 7 production App')
args = parser.parse_args()
O = args.output.resolve()
O.mkdir(parents=True, exist_ok=False)
helper = R / 'VirtualMac/scripts/development/build-independent27-signed-runtime-product-v10.py'
spec = importlib.util.spec_from_file_location('runtime_primitives', helper)
base = importlib.util.module_from_spec(spec); spec.loader.exec_module(base)
pin = base.pin
baseline = R / 'DeviceDiagnostics/2026-11-12-upstream-1.2.4/beta6-r2-candidate-v8/stage/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1'
runtime = O / 'runtime'
manifest_name = 'VM27IndependentRuntimeManifestV1.plist'
manifest = plistlib.loads((baseline / manifest_name).read_bytes())
rows = {r['id']: r for r in manifest['files']}
previous = copy.deepcopy(rows)
probe = args.cpu.resolve(strict=True)
commands = []


def run(label, argv):
    argv = list(map(str, argv))
    result = subprocess.run(argv, capture_output=True, timeout=180)
    (O / (label + '.log')).write_bytes(result.stdout + result.stderr)
    commands.append(dict(label=label, argv=argv, exit=result.returncode))
    (O / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
    if result.returncode:
        raise RuntimeError(label + ': ' + result.stderr.decode(errors='replace')[-2000:])
    return result.stdout


for row in rows.values():
    source = baseline / row['path']
    actual = pin(source)
    assert (actual['bytes'], actual['sha256']) == (row['bytes'], row['sha256']), row['path']
    target = runtime / row['path']
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, target)

changes = ['parent:VM27HVVMProduction.dylib', 'child:VM27HVVMProduction.dylib']
oldcpu = base.image_profile((baseline / rows[changes[0]]['path']).read_bytes(), 'baseline')
newcpu = base.image_profile(probe.read_bytes(), 'probe')
assert set(oldcpu.exports) == set(newcpu.exports)
semantics = lambda im: [(r['ordinal'], r['weak'], r['name'], r['addend']) for r in im.imports]
assert set(semantics(oldcpu)).issubset(set(semantics(newcpu)))
added_imports = [r for r in newcpu.imports if r['name'] not in {i['name'] for i in oldcpu.imports}]
for row in added_imports:
    assert newcpu.loads[row['ordinal'] - 1]['path'] == '/usr/lib/libSystem.B.dylib', row
assert [(r['path'], r['cmd']) for r in oldcpu.loads] == [(r['path'], r['cmd']) for r in newcpu.loads]
for identity in changes:
    target = runtime / rows[identity]['path']
    shutil.copyfile(probe, target)
    run('sign-' + identity.replace(':', '-'), ['codesign', '--force', '--sign', '-', '--timestamp=none',
        '--digest-algorithm=sha256', '--identifier', 'org.lkx.VirtualMacAppleAccount.' + identity.replace(':', '.'), target])

childid = manifest['childEntryContract']['childID']
child = runtime / rows[childid]['path']
original_child = base.image_profile(child.read_bytes(), 'child')
entitlements = base.signature(child.read_bytes(), original_child.uuid,
    {int(k): (runtime / rows[v]['path']).read_bytes() for k, v in rows[childid].get('signatureSlots', {}).items()})['embeddedEntitlements']
ent = O / 'child.entitlements.plist'
ent.write_bytes(plistlib.dumps(entitlements))
xpc = child.parent.parent.parent
with tempfile.TemporaryDirectory(prefix='vm-apple-account-sign-', dir='/private/tmp') as work:
    bundle = Path(work) / xpc.name
    shutil.copytree(xpc, bundle)
    run('clear-child-xattrs', ['xattr', '-cr', bundle])
    run('sign-child', ['codesign', '--force', '--sign', '-', '--timestamp=none', '--digest-algorithm=sha256',
        '--identifier', 'com.apple.Virtualization.VirtualMachine', '--entitlements', ent,
        '--generate-entitlement-der', bundle])
    run('verify-child', ['codesign', '--verify', '--strict', bundle])
    for identity in [childid, 'child-coderesources']:
        target = runtime / rows[identity]['path']
        shutil.copyfile(bundle / target.relative_to(xpc), target)
changes += [childid, 'child-coderesources']
newchild = base.image_profile(child.read_bytes(), 'child')
for section in original_child.sections:
    at, size = section['fileoff'], section['size']
    if at and size and section['flags'] & 255 not in (1, 12, 18):
        assert original_child.data[at:at + size] == newchild.data[at:at + size]

images = {}
for identity in changes:
    row = rows[identity]
    path = runtime / row['path']
    actual = pin(path)
    row.update(bytes=actual['bytes'], sha256=actual['sha256'])
    if row['kind'] == 'mach-o':
        image = base.image_profile(path.read_bytes(), identity)
        images[identity] = image
        proof = base.signature(path.read_bytes(), image.uuid,
            {int(k): (runtime / rows[v]['path']).read_bytes() for k, v in row.get('signatureSlots', {}).items()})
        row.update(uuid=proof['uuid'], cdhash=proof['cdhash'])

for entry in manifest['entries']:
    if entry['fileID'] in images:
        entry['rva'] = images[entry['fileID']].exports['_' + entry['symbol']]['address']
contract = manifest['childEntryContract']
contract['providerEntryRVA'] = images[contract['providerID']].exports['_' + contract['symbol']]['address']
graphid = manifest['dependencyProofID']
graph = json.loads((runtime / rows[graphid]['path']).read_text())
assert graph['finalStrongDefinitionGraphClosed'] and not graph['unresolvedStrongImportRows']
graph['appleAccountBootProbeV1'] = dict(component=pin(probe), exportsUnchanged=True, importsAddedOnlyFromNativeLibSystem=added_imports,
                                      guestWrites=True, originalVMMInstructionsUnchanged=True)
(runtime / rows[graphid]['path']).write_text(json.dumps(graph, indent=2) + '\n')
actual = pin(runtime / rows[graphid]['path'])
rows[graphid].update(bytes=actual['bytes'], sha256=actual['sha256'])
changes.append(graphid)
for identity in rows:
    if identity not in changes: assert rows[identity] == previous[identity]
manifest_data = plistlib.dumps(manifest, fmt=plistlib.FMT_BINARY, sort_keys=True)
(runtime / manifest_name).write_bytes(manifest_data)
anchor = O / 'runtime-anchor.c'
anchor.write_text('#include "vm27_independent_app_runtime_anchor_v1.h"\n'
    'const uint8_t VM27IndependentRuntimeManifestSHA256V1[32]={' +
    ','.join(map(str, hashlib.sha256(manifest_data).digest())) + '};\n'
    'const size_t VM27IndependentRuntimeManifestBytesV1=' + str(len(manifest_data)) + ';\n')
anchorobj = O / 'runtime-anchor.o'
run('compile-anchor', ['xcrun', '--sdk', 'iphoneos', 'clang', '-target', 'arm64e-apple-ios16.1',
    '-I', R / 'VirtualMac/vz/host', '-c', anchor, '-o', anchorobj])

appbaseline = R / ('DeviceDiagnostics/2026-11-15-macos26-firstboot-v1/' +
    ('app-new26-v109-beta7' if args.release else 'app-new26-v108-camera-audio'))
app = O / 'VirtualMacIndependent27.app'
baseline_app_hash = pin(appbaseline / app.name / 'VirtualMacIndependent27')['sha256']
assert baseline_app_hash == ('9eef959cd8a2d94b6e67e9b5ef3fb9fc29da76201631b05be759d5d059c6b6e3' if args.release
    else '06821aac23738f66ec1636ad3cde2a46f737e8504be102aba464891f0819375d')
shutil.copytree(appbaseline / app.name, app, dirs_exist_ok=True)
link = next(c['argv'][:] for c in json.loads((appbaseline / 'commands.json').read_text()) if c['label'] == 'link-app')
oldanchor = next(a for a in link if a.endswith('/anchor-34.o'))
assert link.count(oldanchor) == 1
link[link.index(oldanchor)] = anchorobj
link[link.index('-o') + 1] = app / 'VirtualMacIndependent27'
spec = importlib.util.spec_from_file_location('account_app_source', R / 'VirtualMac/scripts/development/apple-account-app-source-v1.py')
account = importlib.util.module_from_spec(spec); spec.loader.exec_module(account)
main = O / 'VirtualMacApp_apple_account_v1.m'
text = (appbaseline / 'VirtualMacApp_shared_radio_v1.m').read_text()
main.write_text(account.apply(text))
compile = next(c['argv'][:] for c in json.loads((appbaseline / 'commands.json').read_text()) if c['label'] == 'compile-main')
oldmain = compile[compile.index('-o') + 1]
compile[compile.index('-c') + 1] = main
compile[compile.index('-o') + 1] = O / 'main.o'
compile[compile.index('-MF') + 1] = O / 'main.d'
compile += ['-I', R / 'VirtualMac/vz/apple-account']
run('compile-account-main', compile)
assert link.count(oldmain) == 1
link[link.index(oldmain)] = O / 'main.o'
link += account.compile_objects(R, O, args.installer.resolve(strict=True), run)
account.replace_library(R, O, link, run)
run('link-app', link)
if args.release:
    info_path = app / 'Info.plist'
    info = plistlib.loads(info_path.read_bytes())
    info.update(CFBundleShortVersionString='2.0.0beta8', CFBundleVersion='1008',
        CFBundleDisplayName='VirtualMac 2 beta8', VirtualMacPackageRevision='1008')
    info.pop('VM27SharedRadioDevelopmentRevision', None)
    info_path.write_bytes(plistlib.dumps(info, sort_keys=False))
for lang, translation in [('en', 'This Mac keeps a fixed network address for Apple Account.'), ('zh_CN', '此虚拟 Mac 使用固定网络地址，以保持 Apple 账户身份一致。')]:
    with (app / (lang + '.lproj/Localizable.strings')).open('a') as localized:
        localized.write('\n"This Mac keeps a fixed network address for Apple Account." = ' + json.dumps(translation, ensure_ascii=False) + ';\n')
with tempfile.TemporaryDirectory(prefix='vm-apple-account-app-', dir='/private/tmp') as work:
    clean = Path(work) / app.name
    shutil.copytree(app, clean)
    run('clear-app-xattrs', ['xattr', '-cr', clean])
    run('sign-app', ['codesign', '--force', '--sign', '-', '--timestamp=none', '--digest-algorithm=sha256',
        '--identifier', 'com.mac.virtual.independent27', '--entitlements', appbaseline / 'app.entitlements.plist',
        '--generate-entitlement-der', clean])
    run('verify-app', ['codesign', '--verify', '--strict', '--deep', clean])
    for name in ['VirtualMacIndependent27', '_CodeSignature/CodeResources']:
        shutil.copyfile(clean / name, app / name)

appimage = base.image_profile((app / 'VirtualMacIndependent27').read_bytes(), 'app')
appproof = base.signature(appimage.data, appimage.uuid,
    {1: (app / 'Info.plist').read_bytes(), 3: (app / '_CodeSignature/CodeResources').read_bytes()})
files = []
for identity in changes:
    row = rows[identity]
    files.append(dict(relativePath='runtime/' + row['path'], old=pin(baseline / row['path']),
                      new=pin(runtime / row['path']), cdhash=row.get('cdhash')))
files.append(dict(relativePath='runtime/' + manifest_name, old=pin(baseline / manifest_name), new=pin(runtime / manifest_name)))
app_files = ['VirtualMacIndependent27', '_CodeSignature/CodeResources', 'en.lproj/Localizable.strings', 'zh_CN.lproj/Localizable.strings']
if args.release:
    app_files.append('Info.plist')
    for action in ('radio-guest-unlock', 'radio-guest-click', 'radio-review-install',
        'radio-review-keys', 'radio-guest-screen', 'radio-crash-disk-readonly',
        'radio-acceptance-mouse-gatt-probe', 'diagnostic-ssh-enable',
        'guest-gui-diagnostic', 'frame-timing', 'display-native-iosurface'):
        assert action.encode() + b'\0' not in appimage.data, action
for name in app_files:
    files.append(dict(relativePath='app/' + name, old=pin(appbaseline / app.name / name),
                      new=pin(app / name), cdhash=appproof['cdhash'] if name == 'VirtualMacIndependent27' else None))
(O / 'candidate.json').write_text(json.dumps(dict(files=files, runtimeRoot=str(runtime),
    app=str(app), appCDHash=appproof['cdhash'], guestWrites=True, deviceAcceptancePending=True,
    release=args.release, newGuestAppleAccountEnabledByDefault=True,
    appleAccountAvailableDuringSetupAssistant=True,
    auditedGuestBuilds=['24G90', '25G83', '26A5416b', '26B123'],
    expectedBaselineAppSHA256=baseline_app_hash), indent=2) + '\n')
print(O / 'candidate.json')
