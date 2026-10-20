#!/usr/bin/env python3
"""Build eight private CFString data symbols. Does not load or deploy a library."""
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
    root = Path(__file__).resolve().parents[3]
    source = root / 'VirtualMac/vz/host/modern_diskimages2_constants.c'
    proof = root / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/di2-macos-constant-contract-v1'
    transcript = proof / 'native.stdout'
    receipt = json.loads((proof / 'result.json').read_bytes())
    assert receipt['reaped'] and receipt['observedWaitExit'] == 0
    assert receipt['stdoutSHA256'] == hashlib.sha256(transcript.read_bytes()).hexdigest()
    rows = [json.loads(line) for line in transcript.read_text().splitlines()]
    assert rows[0]['PID'] == receipt['directChildPID'] and rows[-1]['constants'] == 8 and rows[-1]['passed']
    constants = {row['name']: row['value'] for row in rows if row['record'] == 'constant'}
    parsed = {symbol: value for _, symbol, value in re.findall(
        r'VM27_STRING\((\w+), "([\w]+)", "([^"]+)"\);', source.read_text())}
    assert len(constants) == 8 and constants == parsed
    assert all(row['type'] == 'CFStringRef' and row['ownerUUID'] == (
        'f78b7942c45b352092c8dd66e11c46fe' if row['name'].startswith('kCFNetwork') else
        '7b094bb2dd4d3a818c295879451255f5') for row in rows if row['record'] == 'constant')
    output = args.output.resolve(); output.mkdir(parents=True, exist_ok=False)
    commands = []

    def run(label, command):
        result = subprocess.run(command, capture_output=True)
        (output / (label + '.stdout')).write_bytes(result.stdout)
        (output / (label + '.stderr')).write_bytes(result.stderr)
        commands.append({'argv': command, 'exit': result.returncode})
        if result.returncode:
            raise RuntimeError(result.stderr.decode(errors='replace'))
        return result

    sdk = run('sdk', ['xcrun', '--sdk', 'iphoneos', '--show-sdk-path']).stdout.decode().strip()
    library = output / 'VM27DiskImageConstants.dylib'
    run('compile', ['xcrun', 'clang', '-target', 'arm64e-apple-ios16.1', '-isysroot', sdk,
        '-O2', '-std=c11', '-fvisibility=hidden', '-fno-typed-memory-operations-experimental',
        '-Wall', '-Wextra', '-Werror', '-dynamiclib', '-framework', 'CoreFoundation',
        '-Wl,-platform_version,ios,16.1,16.1',
        '-Wl,-install_name,@rpath/VM27DiskImageConstants.dylib', str(source), '-o', str(library)])
    run('sign', ['codesign', '--force', '--sign', '-', '--timestamp=none', str(library)])
    run('strict', ['codesign', '--verify', '--strict', str(library)])
    signature = run('signature', ['codesign', '-d', '--verbose=4', str(library)]).stderr
    run('validate', ['xcrun', 'dyld_info', '-validate_only', '-imports', '-exports', '-linked_dylibs', str(library)])
    exports = run('exports', ['xcrun', 'nm', '-gU', str(library)]).stdout.decode().splitlines()
    assert {line.split()[-1] for line in exports} == {'_' + key for key in constants}
    records = []
    for path in (source, Path(__file__).resolve(), transcript, proof / 'result.json'):
        frozen = output / 'source' / path.relative_to(root)
        frozen.parent.mkdir(parents=True, exist_ok=True); frozen.write_bytes(path.read_bytes())
        records.append({'path': str(frozen), 'sha256': hashlib.sha256(frozen.read_bytes()).hexdigest()})
    data = library.read_bytes()
    manifest = dict(library=dict(path=str(library), bytes=len(data), sha256=hashlib.sha256(data).hexdigest(),
        cdhash=re.search(rb'CDHash=([0-9a-f]{40})', signature)[1].decode(), entitlements={}),
        constants=constants, genuineMacReadOnlyPID=receipt['directChildPID'], sourceFreeze=records,
        dataOnly=True, authorizationServicesImplemented=False, keychainServicesImplemented=False,
        proxyServicesImplemented=False, iOSExecuted=False, genuine27DI2Loaded=False,
        original27ConsumerBindingsChanged=False, productionModified=False, full27Backend=False)
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    (output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
    print(json.dumps(manifest['library'], indent=2))


if __name__ == '__main__':
    main()
