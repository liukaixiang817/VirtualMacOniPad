#!/usr/bin/env python3
"""Sign a copied actual App with the genuine Runtime3 manifest anchor."""
import argparse
import hashlib
import importlib.util
import json
import pathlib
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S = R/'VirtualMac/vz/host'
REVIEW = pathlib.Path(__file__).with_name('review-independent27-signed-runtime-product-v1.py')
spec = importlib.util.spec_from_file_location('independent_actual_app_signatures', REVIEW)
review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(review)
need = review.require
pin = review.pin


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--app-candidate', required=True, type=pathlib.Path)
    parser.add_argument('--runtime-candidate', required=True, type=pathlib.Path)
    parser.add_argument('--output', required=True, type=pathlib.Path)
    args = parser.parse_args()
    output = args.output.resolve()
    need(output.parent == N and not output.exists(), 'new diagnostics output')
    app_input = json.loads(args.app_candidate.read_bytes())
    runtime = json.loads(args.runtime_candidate.read_bytes())
    for row in [app_input['binary'], *app_input['appFiles'], *app_input['sourceFiles'], *app_input['actualIncludeClosure']]:
        need(pin(row['path']) == row, 'actual strong linked App input: '+row['path'])
    need(app_input['applicationBinaryLinked'] and app_input['applicationPackaged'] and not app_input['codeSigned'],
         'actual unsigned strong linked App package')
    need(app_input['runtimeRoot'] == runtime['canonicalDeviceRoot'], 'same actual configured runtime root')
    anchor = runtime['anchorSource']
    need(anchor in app_input['sourceFiles'] and pin(anchor['path']) == anchor, 'actual product anchor compiled into main')
    need(any(row['path'] == str((S/'vm27_independent_app_runtime_v4.m').resolve()) for row in app_input['sourceFiles']),
         'actual Runtime4 compiled into main')
    source = pathlib.Path(app_input['binary']['path']).parent
    need(source.name == 'VirtualMacIndependent27.app', 'actual independent package basename')
    output.mkdir(mode=0o700)
    commands = []

    def run(label, argv):
        result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=60)
        (output/(label+'.stdout')).write_bytes(result.stdout)
        (output/(label+'.stderr')).write_bytes(result.stderr)
        commands.append({'label': label, 'argv': list(map(str, argv)), 'exit': result.returncode})
        (output/'commands.json').write_text(json.dumps(commands, indent=2)+'\n')
        need(result.returncode == 0, label+': '+result.stderr.decode(errors='replace'))
        return result

    with tempfile.TemporaryDirectory(prefix='vm27-actual-signed-app-', dir='/private/tmp') as work:
        app = pathlib.Path(work)/source.name
        shutil.copytree(source, app)
        need(not any(path.is_symlink() for path in app.rglob('*')), 'regular copied App resources')
        info_path = app/'Info.plist'
        info = plistlib.loads(info_path.read_bytes())
        need(info['CFBundleIdentifier'] == 'com.mac.virtual.independent27' and
             info['CFBundleExecutable'] == 'VirtualMacIndependent27', 'own actual App identity')
        info.update(CFBundleDisplayName='VirtualMac 27', CFBundleShortVersionString='27.0.1', CFBundleVersion='1',
                    CFBundleURLTypes=[{'CFBundleURLName': 'VirtualMac Independent27',
                                       'CFBundleURLSchemes': ['virtualmac27']}])
        info_path.write_bytes(plistlib.dumps(info, sort_keys=False))
        for path in app.rglob('*'):
            path.chmod(0o755 if path.is_dir() or path.name == info['CFBundleExecutable'] else 0o644)
        app.chmod(0o755)
        binary = app/info['CFBundleExecutable']
        before = binary.read_bytes()
        run('sign-app', ['codesign', '--force', '--sign', '-', '--timestamp=none', '--digest-algorithm=sha256',
                         '--identifier', info['CFBundleIdentifier'], '--entitlements', S/'VirtualMac.entitlements',
                         '--generate-entitlement-der', app])
        run('strict-app', ['codesign', '--verify', '--strict', app])
        description = run('signature-app', ['codesign', '-d', '--verbose=4', app]).stderr.decode()
        matches = re.findall(r'^CDHash=([0-9a-f]{40})$', description, re.M)
        need(len(matches) == 1, 'actual primary signed App hash')
        uuid_text = run('uuid-app', ['xcrun', 'dyld_info', '-uuid', binary]).stdout.decode()
        uuids = re.findall(r'\b[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\b', uuid_text)
        need(len(uuids) == 1, 'actual signed main UUID')
        row = {'uuid': uuids[0].replace('-', '').lower(), 'cdhash': matches[0]}
        signature = review.signed_image(binary, row, {1: info_path.read_bytes(),
                                        3: (app/'_CodeSignature/CodeResources').read_bytes()})
        need(signature['embeddedEntitlements'] == plistlib.loads((S/'VirtualMac.entitlements').read_bytes()),
             'actual App embedded entitlement set')
        need(binary.stat().st_size <= 2*1024*1024, 'actual signed main within true Runtime3 self-inspector bound')
        # Check unchanged signed main sections, exports and real imports with
        # the independently frozen Mach-O reader already used in stage review.
        reader = N/'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'
        sp = importlib.util.spec_from_file_location('actual_app_section_reader', reader)
        image_reader = importlib.util.module_from_spec(sp)
        sp.loader.exec_module(image_reader)
        original = image_reader.MachO(before)
        signed = image_reader.MachO(binary.read_bytes())
        need(original.uuid == signed.uuid and original.sections == signed.sections and original.imports == signed.imports and
             original.exports == signed.exports and original.binds == signed.binds, 'signing preserves actual App code identity')
        for section in original.sections:
            at, size = section['fileoff'], section['size']
            if at and size and section['flags'] & 255 not in (1, 12, 18):
                need(before[at:at+size] == signed.data[at:at+size], 'actual compiled App section unchanged')
        need(not any('VZHostCompat' in row['path'] or 'ModernCPURuntimeCompat' in row['path'] for row in signed.loads),
             'no old backend direct App loads')
        run('validate-app', ['xcrun', 'dyld_info', '-validate_only', binary])
        target = output/source.name
        shutil.copytree(app, target)
    signature = review.signed_image(target/info['CFBundleExecutable'], row,
                                    {1: (target/'Info.plist').read_bytes(),
                                     3: (target/'_CodeSignature/CodeResources').read_bytes()})
    actual_files = [pin(path) for path in sorted(target.rglob('*')) if path.is_file()]
    record = {'schema': 'Actual strong linked and signed independent27 App main identity product v2',
              'app': str(target), 'binary': pin(target/info['CFBundleExecutable']), 'actualSignature': signature,
              'appFiles': actual_files, 'actualBundleID': info['CFBundleIdentifier'], 'actualURLScheme': 'virtualmac27',
              'runtimeRoot': runtime['canonicalDeviceRoot'], 'runtimeCandidate': pin(args.runtime_candidate),
              'sourceCandidate': pin(args.app_candidate), 'realCompiledManifestAnchor': anchor,
              'actualPrimaryPagesAndExternalSlotsVerified': True, 'actualSelfInspectorMainSizePassed': True,
              'signedMainBytes': (target/info['CFBundleExecutable']).stat().st_size, 'oldBackendDirectImports': False,
              'actualApplicationLinked': True, 'actualApplicationPackaged': True, 'actualCodeSigned': True,
              'localSigningOnly': True, 'deviceOperations': 0, 'trustCacheOperations': 0,
              'actualAppLaunched': False, 'actualGuestBoot': False, 'actualNetworkAvailable': False}
    (output/'candidate.json').write_text(json.dumps(record, indent=2)+'\n')
    frozen = [pin(path) for path in sorted(output.rglob('*')) if path.is_file()]
    frozen.extend([pin(__file__), pin(REVIEW), pin(args.app_candidate), pin(args.runtime_candidate), pin(reader),
                   pin(S/'VirtualMac.entitlements'), *app_input['sourceFiles'], *app_input['actualIncludeClosure']])
    (output/'freeze.json').write_text(json.dumps({'files': list({row['path']: row for row in frozen}.values()),
                                                 'deviceOperations': 0, 'trustCacheOperations': 0}, indent=2)+'\n')
    print(json.dumps({'candidate': pin(output/'candidate.json'), 'freeze': pin(output/'freeze.json'),
                      'actualAppCDHash': signature['cdhash'], 'signedMainBytes': record['signedMainBytes']}))


if __name__ == '__main__':
    main()
