#!/usr/bin/env python3
"""Build private POSIX disk transport and bounded own-file probes; no device operations."""
import argparse
import hashlib
import json
import pathlib
import subprocess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=pathlib.Path, required=True)
    parser.add_argument('--can-execute-cdhash', action='store_true', help='Additional right only for this diagnostic process')
    parser.add_argument('--get-task-allow', action='store_true', help='Known-working diagnostic mapping control, not a production permission')
    args = parser.parse_args()
    output = args.output.resolve()
    if output.exists():
        parser.error('output must not already exist')
    output.mkdir(parents=True)
    project = pathlib.Path(__file__).resolve().parents[2]
    source = project / 'vz/host/modern_disk_io_compat.c'
    header = source.with_suffix('.h')
    probe_source = project / 'scripts/tests/test-modern-disk-io.c'
    exports = ['VM27DiskIOCreate', 'VM27DiskIOSubmit', 'VM27DiskIOGetCompletion',
               'VM27DiskIOSuspend', 'VM27DiskIOResume', 'VM27DiskIOCancel',
               'VM27DiskIOClose', 'VM27DiskIODestroy', 'VM27DiskIOGetStats']
    commands = []

    def run(label, argv):
        result = subprocess.run(argv, capture_output=True, text=True)
        commands.append(dict(label=label, argv=argv, exitCode=result.returncode,
                             stdout=result.stdout, stderr=result.stderr))
        (output / 'commands.json').write_text(json.dumps(commands, indent=2) + '\n')
        if result.returncode:
            raise SystemExit('failed ' + label + ': ' + result.stderr)
        return result

    rights = output / 'Probe.entitlements'
    rights.write_text('''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>platform-application</key><true/>
<key>com.apple.private.security.no-container</key><true/>
<key>com.apple.private.security.no-sandbox</key><true/>
''' + ('<key>com.apple.private.amfi.can-execute-cdhash</key><true/>\n' if args.can_execute_cdhash else '') +
        ('<key>get-task-allow</key><true/>\n' if args.get_task_allow else '') + '</dict></plist>\n')
    for sdk_name, target, role in [('macosx', 'arm64e-apple-macos13.0', 'mac'),
                                   ('iphoneos', 'arm64e-apple-ios16.1', 'ios')]:
        sdk = subprocess.check_output(['xcrun', '--sdk', sdk_name, '--show-sdk-path'], text=True).strip()
        common = ['xcrun', 'clang', '-target', target, '-isysroot', sdk, '-std=c11', '-O2',
                  '-Wall', '-Wextra', '-Werror', '-fno-typed-memory-operations', '-I' + str(source.parent)]
        library = output / ('VM27DiskIO-' + role + '.dylib')
        run(role + '-library', common + ['-dynamiclib', str(source),
            '-Wl,-install_name,@rpath/' + library.name, '-o', str(library)] +
            ['-Wl,-exported_symbol,_' + name for name in exports])
        run(role + '-library-sign', ['codesign', '--force', '--sign', '-', '--timestamp=none', str(library)])
        probe = output / ('vm27-disk-io-' + role)
        run(role + '-probe', common + [str(probe_source), str(library),
            '-Wl,-rpath,@loader_path', '-o', str(probe)])
        signing = ['codesign', '--force', '--sign', '-', '--timestamp=none', '--identifier',
                   'com.virtualmac.diagnostics.disk-io-v1']
        if role == 'ios':
            signing += ['--entitlements', str(rights)]
        run(role + '-probe-sign', signing + [str(probe)])
        for item in [library, probe]:
            run(item.name + '-strict', ['codesign', '--verify', '--strict', str(item)])
            run(item.name + '-dyld', ['xcrun', 'dyld_info', '-validate_only', str(item)])
            run(item.name + '-imports', ['xcrun', 'dyld_info', '-imports', str(item)])
            run(item.name + '-signature', ['codesign', '-d', '--verbose=4', str(item)])
    manifest = dict(schemaVersion=1, exports=exports, appleIORingsABI=False, nativeExecution=False,
        diagnosticCanExecuteCDHash=args.can_execute_cdhash, diagnosticGetTaskAllow=args.get_task_allow,
        usesOnlyPrivateOwnFileDuringProbe=True, maximumRequests=256, maximumProbeFileBytes=131072,
        deviceOperations=False, guestDiskAccessed=False, systemModified=False,
        sources=[dict(path=str(path.relative_to(project)), sha256=hashlib.sha256(path.read_bytes()).hexdigest())
                 for path in [source, header, probe_source]],
        files=[dict(name=path.name, bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
               for path in sorted(output.iterdir()) if path.suffix == '.dylib' or path.name.startswith('vm27-disk-io-')])
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(manifest, indent=2))


if __name__ == '__main__':
    main()
