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
    help='Build Beta 9 RC2 from the verified Beta 7 production App')
parser.add_argument('--radio-package', type=Path,
    help='Add the audited combined 26B131 radio package without replacing existing packages')
parser.add_argument('--display-version', default='2.0.0beta9rc2')
parser.add_argument('--package-version', default='1009-2')
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
spec = importlib.util.spec_from_file_location('native_touchscreen_app_source',
    R / 'VirtualMac/scripts/development/native-touchscreen-app-source-v1.py')
touchscreen = importlib.util.module_from_spec(spec); spec.loader.exec_module(touchscreen)
text = touchscreen.apply(account.apply(text))
if args.radio_package:
    spec = importlib.util.spec_from_file_location('radio_cold_restart',
        R / 'VirtualMac/scripts/development/radio-cold-restart-source-v1.py')
    cold = importlib.util.module_from_spec(spec);spec.loader.exec_module(cold)
    text = cold.apply(text, R / 'VirtualMac/vz/shared-radio')
main.write_text(text)
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
spec = importlib.util.spec_from_file_location('install_version_selection',
    R / 'VirtualMac/scripts/development/install-version-selection-source-v1.py')
selection = importlib.util.module_from_spec(spec); spec.loader.exec_module(selection)
selection_resources = selection.rebuild(R, O, app, link, run)
touchscreen.rebuild(R, O, app, link, run)
radio_resources = []
if args.radio_package:
    package = args.radio_package.resolve(strict=True)
    catalog = plistlib.loads((package / 'Catalog.plist').read_bytes())
    assert catalog['Schema'] == 1 and set(catalog['Packages']) == {'26B131'}
    entry = catalog['Packages']['26B131']
    assert entry['CombinedInstallation'] is True
    assert pin(package / 'Package/Package.plist')['sha256'] == entry['ManifestSHA256']
    assert pin(package / 'RadioPackage.tar')['sha256'] == entry['ArchiveSHA256']
    assert pin(package / 'shared-radio-package-v1')['sha256'] == entry['InstallerSHA256']
    destination = app / 'SharedRadio'
    merged = plistlib.loads((destination / 'Catalog.plist').read_bytes())
    assert merged['Schema'] == 1
    for category, folder in [('Packages', '26B131'), ('AutomaticPackages', 'Automatic26B131')]:
        assert '26B131' not in merged[category]
        (destination / folder).mkdir()
        for name in ['RadioPackage.tar', 'shared-radio-package-v1']:
            shutil.copyfile(package / name, destination / folder / name)
            radio_resources.append('SharedRadio/' + folder + '/' + name)
        merged[category]['26B131'] = dict(entry, ResourceDirectory=folder)
    (destination / 'Catalog.plist').write_bytes(plistlib.dumps(merged))
    radio_resources.append('SharedRadio/Catalog.plist')
    # The boot-ROM profile is compiled separately from the App's main source.
    boot_compile = next(c['argv'][:] for c in json.loads((appbaseline / 'commands.json').read_text())
        if c['label'] == 'compile-radio-5')
    assert Path(boot_compile[boot_compile.index('-c') + 1]).name == 'VM27RadioAutomaticBoot26V1.m'
    boot_object = boot_compile[boot_compile.index('-o') + 1]
    boot_compile[boot_compile.index('-o') + 1] = O / 'VM27RadioAutomaticBoot26V1.o'
    run('compile-current-radio-boot', boot_compile)
    assert link.count(boot_object) == 1
    link[link.index(boot_object)] = O / 'VM27RadioAutomaticBoot26V1.o'
    provisioning_compile = next(c['argv'][:] for c in json.loads((appbaseline / 'commands.json').read_text())
        if c['label'] == 'compile-radio-provisioning')
    provisioning_object = provisioning_compile[provisioning_compile.index('-o') + 1]
    provisioning_compile[provisioning_compile.index('-o') + 1] = O / 'guest-tools-radio.o'
    provisioning_compile[provisioning_compile.index('-MF') + 1] = O / 'guest-tools-radio.d'
    run('compile-current-radio-provisioning', provisioning_compile)
    assert link.count(provisioning_object) == 1
    link[link.index(provisioning_object)] = O / 'guest-tools-radio.o'
    wifi_compile = next(c['argv'][:] for c in json.loads((appbaseline / 'commands.json').read_text())
        if c['label'] != 'link-app' and any(a.endswith('/VM27OwnedWiFiHostV1.m') for a in c['argv']))
    wifi_object = wifi_compile[wifi_compile.index('-o') + 1]
    wifi_compile[wifi_compile.index('-o') + 1] = O / 'VM27OwnedWiFiHostV1.o'
    run('compile-current-owned-wifi', wifi_compile)
    assert link.count(wifi_object) == 1
    link[link.index(wifi_object)] = O / 'VM27OwnedWiFiHostV1.o'
run('link-app', link)
if args.release:
    info_path = app / 'Info.plist'
    info = plistlib.loads(info_path.read_bytes())
    info.update(CFBundleShortVersionString=args.display_version, CFBundleVersion=args.package_version.replace('-', '.'),
        CFBundleDisplayName='VirtualMac 2 beta9', VirtualMacPackageRevision=args.package_version)
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
app_files += selection_resources
app_files += radio_resources
if args.release:
    app_files.append('Info.plist')
    for action in ('radio-guest-unlock', 'radio-guest-click', 'radio-review-install',
        'radio-review-keys', 'radio-guest-screen', 'radio-crash-disk-readonly',
        'radio-acceptance-mouse-gatt-probe', 'diagnostic-ssh-enable',
        'guest-gui-diagnostic', 'frame-timing', 'display-native-iosurface'):
        assert action.encode() + b'\0' not in appimage.data, action
for name in app_files:
    original = appbaseline / app.name / name
    files.append(dict(relativePath='app/' + name, old=pin(original) if original.exists() else None,
                      new=pin(app / name), cdhash=appproof['cdhash'] if name == 'VirtualMacIndependent27' else None))
(O / 'candidate.json').write_text(json.dumps(dict(files=files, runtimeRoot=str(runtime),
    app=str(app), appCDHash=appproof['cdhash'], guestWrites=True, deviceAcceptancePending=True,
    release=args.release, newGuestAppleAccountEnabledByDefault=True,
    addedRadioBuilds=['26B131'] if args.radio_package else [],
    appleAccountAvailableDuringSetupAssistant=True,
    auditedGuestBuilds=['24G90', '25G83', '26A5416b', '26B123', '26B131'],
    installVersionRecommendations=['24G90', '25G83', '26B123'],
    allVersionsAndLocalIPSWChoices=True,
    nativeTouchScreenForCompatible27Guests=True,
    softwareKeyboardManualDismissalRespected=True,
    newGuestIdentityGeneratedForAllRestoreBuilds=True,
    liveAppleRestoreCatalog=True,
    futureVersionsNotHiddenByMajorVersion=True,
    expectedBaselineAppSHA256=baseline_app_hash), indent=2) + '\n')
print(O / 'candidate.json')
