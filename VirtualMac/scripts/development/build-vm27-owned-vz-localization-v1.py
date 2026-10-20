#!/usr/bin/env python3
"""Build a named localization leaf and its exact parent-only call-site recipe.

This HOST tool creates no patched VZ image and performs no signing or device
operation. The single shared start-compat composer must apply the recipe.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import struct
import subprocess
import sys

sys.dont_write_bytecode = True
R = Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
S = R / 'VirtualMac/vz/host'
VZ = N / 'independent27-signed-runtime-uikit-filter-product-v10-attempt1/runtime/parent-flat/VZ27.dylib'
TRACE = N / 'actual-vz-start-error-localization-nil-secondary-host-v1-attempt1/review.json'
PARSER = N / 'modern27-remaining-context-fields-independent-readonly-v1/independent_macho.py'

def require(value, message):
    if not value:
        raise ValueError(message)

def pin(path):
    path = Path(path).resolve()
    value = path.read_bytes()
    return {'path': str(path), 'bytes': len(value), 'sha256': hashlib.sha256(value).hexdigest()}

def save(path, value):
    Path(path).write_text(json.dumps(value, indent=2) + '\n')

def section(data, name):
    n, size = struct.unpack_from('<II', data, 16)
    at = 32
    for _ in range(n):
        command, length = struct.unpack_from('<II', data, at)
        if command == 0x19:
            count = struct.unpack_from('<I', data, at+64)[0]
            for i in range(count):
                p = at+72+80*i
                if data[p:p+16].split(b'\0')[0].decode() == name:
                    amount, offset = struct.unpack_from('<QI', data, p+40)
                    return data[offset:offset+amount]
        at += length
    raise ValueError('missing actual section ' + name)

def main():
    arguments = argparse.ArgumentParser()
    arguments.add_argument('--output', required=True)
    args = arguments.parse_args()
    out = Path(args.output).resolve()
    require(not out.exists(), 'fresh output required')
    out.mkdir(parents=True)
    steps = []
    def run(label, command, env=None):
        actual = subprocess.run(command, capture_output=True, env=env)
        stdout = out / (label + '.stdout')
        stderr = out / (label + '.stderr')
        stdout.write_bytes(actual.stdout)
        stderr.write_bytes(actual.stderr)
        row = {'label': label, 'command': command, 'exitCode': actual.returncode,
               'stdout': pin(stdout), 'stderr': pin(stderr)}
        steps.append(row)
        require(actual.returncode == 0, label + ' failed: ' + actual.stderr.decode(errors='replace'))
        return actual.stdout
    try:
        loader = importlib.util.spec_from_file_location('bounded_macho', PARSER)
        module = importlib.util.module_from_spec(loader)
        loader.loader.exec_module(module)
        raw = VZ.read_bytes()
        image = module.MachO(raw)
        require(image.uuid == '418efc4809d93606918eb6f95baeffdc', 'actual VZ UUID')
        require(len(image.loads) == 63 and len(image.imports) == 1057, 'exact baseline route')
        require(pin(VZ)['sha256'] == 'bb6240889b8be5a1948471822c36a9e9ac6da51e04eb53a91589b9fef3e95fd3', 'actual signed baseline pin')
        def at(rva, length):
            p = image.file(image.base+rva)
            return raw[p:p+length]
        require(at(0x39c4, 4) == bytes.fromhex('e20313aa'), 'exact argument move')
        require(at(0x39d0, 4) == bytes.fromhex('e0730b94'), 'exact original localizer BL')
        require(at(0x2e4e30, 16) == bytes(16) and at(0x3197d0, 8) == bytes(8), 'reserved zero ranges')
        require(all(not (s['va'] <= image.base+0x2e4e30 < s['va']+s['size']) for s in image.sections), 'stub must be unclaimed by any backed section')
        require(all(not (s['va'] <= image.base+0x3197d0 < s['va']+s['size']) for s in image.sections), 'slot must be unclaimed by any backed section')
        require(not any(b['va'] == image.base+0x3197d0 for b in image.binds), 'slot already bound')
        sdk = run('actual-ios-sdk', ['xcrun', '--sdk', 'iphoneos', '--show-sdk-path']).decode().strip()
        source = S / 'vm27_owned_vz_localization_v1.m'
        header = S / 'vm27_owned_vz_localization_v1.h'
        fixture = S / 'test-vm27-owned-vz-localization-v1.m'
        ios = out / 'vm27_owned_vz_localization_v1.ios.o'
        flags = ['-O2', '-fobjc-arc', '-fblocks', '-fvisibility=hidden', '-Wall', '-Wextra', '-Werror', '-I', str(S)]
        run('strict-ios-compile', ['xcrun', 'clang', '-target', 'arm64e-apple-ios16.1', '-isysroot', sdk, *flags, '-c', str(source), '-o', str(ios)])
        undefined = run('actual-ios-undefined', ['xcrun', 'nm', '-u', str(ios)]).decode()
        defined = run('actual-ios-defined', ['xcrun', 'nm', '-gU', str(ios)]).decode()
        require('_VM27OwnedVZLocalizedStringOrEnglishKeyV1' in defined, 'actual unmangled API definition')
        typed = out / 'typed-header.mm'
        typed.write_text('#import "vm27_owned_vz_localization_v1.h"\n'
            'using Expected = NSString* (*)(NSBundle*,NSString*);\n'
            'Expected Actual = &VM27OwnedVZLocalizedStringOrEnglishKeyV1;\n')
        run('strict-ios-cxx-header', ['xcrun', 'clang++', '-target', 'arm64e-apple-ios16.1', '-isysroot', sdk, *flags, '-c', str(typed), '-o', str(out/'typed-header.ios.o')])
        typed_undefined = run('actual-cxx-undefined', ['xcrun', 'nm', '-u', str(out/'typed-header.ios.o')]).decode()
        require('_VM27OwnedVZLocalizedStringOrEnglishKeyV1' in typed_undefined and '__Z' not in typed_undefined, 'actual CXX API must be unmangled')
        bundle = out / 'ActualLocalizationFixture.bundle'
        (bundle / 'Contents/Resources/en.lproj').mkdir(parents=True)
        (bundle / 'Contents/Info.plist').write_text('<?xml version="1.0"?><plist version="1.0"><dict><key>CFBundleIdentifier</key><string>owned.vm27.localization.fixture</string><key>CFBundleDevelopmentRegion</key><string>en</string><key>CFBundlePackageType</key><string>BNDL</string></dict></plist>\n')
        (bundle / 'Contents/Resources/en.lproj/Localizable.strings').write_text('"Internal Virtualization error." = "Verified real resource translation";\n')
        for label, extra in [('normal', []), ('san', ['-fsanitize=address,undefined', '-fno-omit-frame-pointer'])]:
            executable = out / ('actual-foundation-' + label)
            run(label+'-compile', ['xcrun', 'clang', *flags, *extra, str(source), str(fixture), '-framework', 'Foundation', '-o', str(executable)])
            env = dict(os.environ)
            if extra: env['ASAN_OPTIONS'] = 'detect_leaks=0'
            stdout = run(label+'-execute', [str(executable), str(bundle)], env)
            require(b'actualFoundationChecks=10 nativeBundleResource=1 originalErrorCode=1' in stdout, 'ten actual Foundation checks')
        asm = out / 'actual-auth-thunk.s'
        asm.write_text('.text\n.globl _VM27RecipeThunk\n_VM27RecipeThunk:\n'
            'adrp x16, #0x35000\nadd x16, x16, #0x7d0\nldr x17, [x16]\nbraa x17, x16\n'
            '.section __TEXT,__branchproof,regular,pure_instructions\n'
            'bl #0x2e1460\n')
        asm_object = out / 'actual-auth-thunk.ios.o'
        run('actual-auth-assembler', ['xcrun', 'clang', '-target', 'arm64e-apple-ios16.1', '-isysroot', sdk, '-c', str(asm), '-o', str(asm_object)])
        assembled = asm_object.read_bytes()
        thunk = section(assembled, '__text')
        branch = section(assembled, '__branchproof')
        require(thunk == bytes.fromhex('b00100b010421f91110240f9300a1fd7'), 'actual auth thunk machine words')
        require(branch == bytes.fromhex('18850b94'), 'actual BL displacement')
        words = [{'rva': 0x39c4, 'before': 'e20313aa', 'after': 'e10313aa', 'meaning': 'actual retained original key x19 to C argument x1'},
                 {'rva': 0x39d0, 'before': 'e0730b94', 'after': branch.hex(), 'meaning': 'BL auth thunk; original return PC39d4 remains'}]
        recipe = {'schema': 'Exact parent-only owned localization caller recipe v1',
            'originalParentVZ': pin(VZ), 'originalUUID': image.uuid,
            'selectedOriginalFunctionRVA': 0x395c, 'codeWords': words,
            'newImport': {'index': len(image.imports), 'name': '_VM27OwnedVZLocalizedStringOrEnglishKeyV1', 'ordinal': 64, 'weak': False, 'addend': 0},
            'newRequiredLoad': {'ordinal': 64, 'providerKey': 'VM27OwnedVZStartCompat.dylib', 'sharedWithCacheImport504': True},
            'authenticatedThunk': {'rva': 0x2e4e30, 'fileOffset': image.file(image.base+0x2e4e30), 'before': bytes(16).hex(), 'after': thunk.hex(), 'instructionWords': [f'0x{v:08x}' for v in struct.unpack('<4I', thunk)], 'actualAssembler': pin(asm_object)},
            'authenticatedSlot': {'rva': 0x3197d0, 'fileOffset': image.file(image.base+0x3197d0), 'before': bytes(8).hex(), 'afterWord': f'0x{(1<<63)|(1<<62)|(1<<48)|len(image.imports):016x}', 'pointerFormat': 9, 'key': 'IA', 'addressDiversity': True, 'diversity': 0, 'next': 0, 'importIndex': len(image.imports)},
            'chainStart': {'segment': '__DATA_CONST', 'segmentOffset': 0x2e8000, 'pageSize': 16384, 'pageIndex': 12, 'existingStart': 0, 'addedStart': 0x17d0, 'method': 'new MULTI overflow seeds; preserve every old chain word'},
            'preservedOriginalLocalizer': {'prologueAndPAC': True, 'cachedActualNSBundleOnce': True, 'keyRetainRelease': True, 'returnRetainAutorelease': True, 'unwindAndLSDA': True, 'originalErrorCode1': True},
            'boundaries': {'parentOnly': True, 'globalFoundationInterposition': False, 'processGOTMutation': False, 'newPatchedVZProducedByThisBuilder': False, 'signed': False, 'deviceExecuted': False}}
        recipe_path = out/'recipe.json'; save(recipe_path, recipe)
        contract = {'symbol': '_VM27OwnedVZLocalizedStringOrEnglishKeyV1', 'abi': 'C two ObjC pointer arguments x0 actual NSBundle or nil, x1 original NSString; NSString+0 in x0', 'sourcePin': pin(source), 'headerPin': pin(header), 'iosObject': pin(ios), 'recipe': pin(recipe_path), 'actualBundleTranslationPreserved': True, 'missingTranslationReturnsOriginalEnglishKey': True, 'nativeErrorCodeAndReasonUnchanged': True, 'noNSBundleFabrication': True, 'actualNativeBundlePointerOnDeviceObserved': False, 'deviceExecution': False, 'guestBootAccepted': False}
        candidate = {'schema': 'Owned parent VZ error presentation localization source v1', 'source': pin(source), 'header': pin(header), 'actualIOSObject': pin(ios), 'fixture': pin(fixture), 'recipe': pin(recipe_path), 'ownLocalizationContract': contract, 'steps': steps, 'actualIOSUndefinedSymbols': undefined.splitlines(), 'actualFoundationChecksNormal': 10, 'actualFoundationChecksSAN': 10, 'boundary': 'HOST source/assembler and real Foundation resource only; no patched image, signing, native iOS runtime execution or guest acceptance'}
        candidate_path = out/'candidate.json'; save(candidate_path, candidate)
        inputs = [Path(__file__), source, header, fixture, VZ, TRACE, PARSER]
        produced = [p for p in out.rglob('*') if p.is_file()]
        rows = {p['path']: p for p in [pin(p) for p in inputs+produced]}
        save(out/'freeze.json', {'schema': 'Owned localization source freeze v1', 'candidate': pin(candidate_path), 'files': list(rows.values()), 'deviceExecuted': False, 'signed': False})
        print(json.dumps({'candidate': pin(candidate_path), 'freeze': pin(out/'freeze.json'), 'recipe': pin(recipe_path), 'iosObject': pin(ios)}))
    except Exception as error:
        save(out/'failure.json', {'error': str(error), 'steps': steps})
        raise

if __name__ == '__main__':
    main()
