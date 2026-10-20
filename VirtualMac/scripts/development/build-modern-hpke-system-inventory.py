"""Build a four-permission symbol-only probe for real native HPKE primitives."""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import re
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
N = ROOT / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
READER = ROOT / 'DeviceDiagnostics/2026-10-02-virtualmac-2.0/Tahoe3/integrity-audit/modern-compiler'
sys.path.insert(0, str(READER))
from compiler_image import commands, imports, cstring
SHA = lambda b: hashlib.sha256(b).hexdigest()
RIGHTS = {'platform-application': True, 'com.apple.private.security.no-container': True,
          'com.apple.private.security.no-sandbox': True, 'com.apple.private.amfi.can-execute-cdhash': True}
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(); out = args.output.resolve(); out.mkdir(parents=True, exist_ok=False)
    source = out / 'source'; source.mkdir()
    provider = N / 'hpke-compat-build-v4/ios/VM27HPKECompat.dylib'
    data = provider.read_bytes()
    deps = [cstring(data, at + struct.unpack_from('<I', data, at + 8)[0])
            for c, at, _ in commands(data) if c in (12, 0x80000018, 0x8000001f, 0x80000023)]
    rows = imports(data)['imports']; assert len(rows) == 187 and all(not r['weak'] and r['ordinal'] > 0 for r in rows)
    contracts = N / 'cryptokit27-original-contract-v1/contract.json'
    original = json.loads(contracts.read_text())['DI2RequiredExports']; assert len(original) == 21
    selected = {(deps[r['ordinal'] - 1], r['name']): dict(provider=True, DI2=False) for r in rows}
    for row in original:
        key = ('/System/Library/Frameworks/CryptoKit.framework/CryptoKit', row['plan']['symbol'])
        selected.setdefault(key, dict(provider=False, DI2=False))['DI2'] = True
    images = sorted({key[0] for key in selected})
    selected = [dict(owner=path, name=name, **flags) for (path, name), flags in sorted(selected.items())]
    for row in selected:
        # Exact source import categories. These are data declarations in Swift
        # ABI, not accessor/thunk entry points (Ma/Tj remain functions).
        row['data'] = row['name'] == '___stack_chk_guard' or row['name'] == '__swiftEmptyArrayStorage' or (
            row['name'].startswith('_$s') and row['name'].endswith(('N', 'Mn', 'Mp', 'Mc', 'WP', 'WV', 'TL', 'Tl', 'Tn', 'Tq', 'Tb')))
    header = '#define HPKE_IMAGE_COUNT ' + str(len(images)) + '\n#define HPKE_SYMBOL_COUNT ' + str(len(selected)) + '\n'
    header += 'static const char *SystemImages[HPKE_IMAGE_COUNT]={' + ','.join(json.dumps(s) for s in images) + '};\n'
    header += 'struct Symbol { const char *name; unsigned owner; int data, provider, DI2; };\n'
    header += 'static const struct Symbol RequiredSymbols[HPKE_SYMBOL_COUNT]={\n'
    for row in selected:
        header += '{' + json.dumps(row['name']) + ',' + str(images.index(row['owner'])) + ',' + ','.join(str(int(row[x])) for x in ('data', 'provider', 'DI2')) + '},\n'
    header += '};\n'; (source / 'hpke-system-inventory-pins.h').write_text(header)
    host = ROOT / 'VirtualMac/vz/host/modern_hpke_system_inventory_probe.c'
    for path in (Path(__file__), host, contracts): (source / path.name).write_bytes(path.read_bytes())
    logs = []
    def run(label, argv):
        child = subprocess.Popen([str(a) for a in argv], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try: stdout, stderr = child.communicate(timeout=40)
        except subprocess.TimeoutExpired: child.kill(); child.communicate(); raise
        (out / (label + '.stdout')).write_bytes(stdout); (out / (label + '.stderr')).write_bytes(stderr)
        logs.append(dict(label=label, argv=[str(a) for a in argv], PID=child.pid, wait=child.returncode, reaped=True))
        assert child.returncode == 0, stderr.decode(errors='replace')[-4000:]
        return stdout, stderr
    sdk = run('sdk', ['xcrun', '--sdk', 'iphoneos', '--show-sdk-path'])[0].decode().strip()
    probe = out / 'hpke-system-inventory-probe'
    run('build', ['xcrun', 'clang', '-target', 'arm64e-apple-ios16.1', '-isysroot', sdk, '-fptrauth-abi-version=0',
                  '-fno-typed-memory-operations-experimental', '-Wall', '-Wextra', '-Werror', '-I', source, host, '-o', probe])
    ent = out / 'Probe.entitlements'; ent.write_bytes(plistlib.dumps(RIGHTS))
    run('sign', ['codesign', '--force', '--sign', '-', '--timestamp=none', '--entitlements', ent, probe])
    run('strict', ['codesign', '--verify', '--strict', probe]); run('dyld', ['xcrun', 'dyld_info', '-validate_only', probe])
    _, signature = run('signature', ['codesign', '-d', '--verbose=4', probe])
    rights, _ = run('rights', ['codesign', '-d', '--entitlements', ':-', probe]); assert plistlib.loads(rights) == RIGHTS
    b = probe.read_bytes(); uuid = next(b[at + 8:at + 24].hex() for c, at, _ in commands(b) if c == 0x1b)
    inputs = [provider, contracts, host, Path(__file__), READER / 'compiler_image.py']
    plan = dict(version=1, mode='inventory', executable=probe.name, arguments=['--inventory'],
                systemImages=images, symbols=selected, providerImports=187, DI2OriginalSymbols=21,
                files=[dict(name=probe.name, path=str(probe), bytes=len(b), sha256=SHA(b), UUID=uuid,
                            CDHash=re.search(rb'CDHash=([0-9a-f]{40})', signature)[1].decode(), entitlements=RIGHTS)],
                inputs=[dict(path=str(p), bytes=len(p.read_bytes()), sha256=SHA(p.read_bytes())) for p in inputs],
                cryptoAPICalls=0, metadataAccessorCalls=0, privateProviderLoaded=False, deviceOperations=False,
                symbolsArePresenceOnly=True, missingSymbolsAreDiscovery=True)
    planpath = out / 'consumer-plan.json'; planpath.write_text(json.dumps(plan, indent=2) + '\n')
    (out / 'processes.json').write_text(json.dumps(logs, indent=2) + '\n')
    pins = [probe, ent, planpath, out / 'processes.json'] + list(source.iterdir()) + inputs
    pins = sorted(set(pins)); freeze = dict(files=[dict(path=str(p), bytes=len(p.read_bytes()), sha256=SHA(p.read_bytes())) for p in pins], deviceOperations=False)
    (out / 'freeze.json').write_text(json.dumps(freeze, indent=2) + '\n')
    print(json.dumps(dict(plan=str(planpath), planSHA256=SHA(planpath.read_bytes()), freezeSHA256=SHA((out / 'freeze.json').read_bytes()), symbols=len(selected), file=plan['files'][0]), indent=2))
if __name__ == '__main__': main()
