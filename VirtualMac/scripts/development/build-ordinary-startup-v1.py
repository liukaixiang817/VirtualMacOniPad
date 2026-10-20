"""Build an empty-entitlement process-start control; never dispatch to iPad."""
from pathlib import Path
import hashlib, json, re, resource, struct, subprocess, sys

R = Path(__file__).resolve().parents[3]
SOURCE = R / 'VirtualMac/scripts/tests/test-ordinary-startup-v1.c'
OUT = Path(sys.argv[1]).resolve()
OUT.mkdir(mode=0o700, exist_ok=False)
def pin(p):
    return dict(path=str(p.resolve()), bytes=p.stat().st_size,
                sha256=hashlib.sha256(p.read_bytes()).hexdigest())
def command(label, argv, **kwargs):
    (OUT / (label + '.command.json')).write_text(json.dumps(list(map(str, argv)), indent=2) + '\n')
    result = subprocess.run(list(map(str, argv)), capture_output=True, timeout=20, **kwargs)
    (OUT / (label + '.stdout')).write_bytes(result.stdout)
    (OUT / (label + '.stderr')).write_bytes(result.stderr)
    assert result.returncode == 0, (label, result.stderr.decode(errors='replace'))
    return result
def commands(data):
    assert struct.unpack_from('<I', data)[0] == 0xfeedfacf
    offset = 32
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        code, size = struct.unpack_from('<II', data, offset)
        assert size >= 8 and size % 8 == 0
        yield code, offset, size
        offset += size
    assert offset == 32 + struct.unpack_from('<I', data, 20)[0]
products = []
for platform, sdk, target in [('ios', 'iphoneos', 'arm64e-apple-ios16.1'),
                               ('macos', 'macosx', 'arm64e-apple-macos13.0')]:
    directory = OUT / platform
    directory.mkdir()
    binary = directory / 'ordinary-startup-v1'
    flags = ['-std=c11', '-O2', '-Wall', '-Wextra', '-Werror', '-fptrauth-abi-version=0',
             '-Wl,-no_adhoc_codesign']
    if platform == 'macos':
        flags += ['-Wl,-no_mac_public_arm64e']
    command(platform + '-compile', ['xcrun', '--sdk', sdk, 'clang', '-target', target,
                                    *flags, SOURCE, '-o', binary])
    if platform == 'ios':
        data = bytearray(binary.read_bytes())
        builds = [offset for code, offset, size in commands(data) if code == 0x32]
        assert len(builds) == 1 and struct.unpack_from('<I', data, builds[0] + 8)[0] == 2
        struct.pack_into('<3I', data, builds[0] + 8, 2, 0x100100, 0x100100)
        binary.write_bytes(data)
    command(platform + '-sign', ['codesign', '--force', '--sign', '-', '--timestamp=none',
                                 '--identifier', 'local.VirtualMac.ordinary-startup.' + platform, binary])
    command(platform + '-strict', ['codesign', '--verify', '--strict', binary])
    signature = command(platform + '-signature', ['codesign', '-dvvv', binary]).stderr
    entitlements = command(platform + '-entitlements', ['codesign', '-d', '--entitlements', ':-', binary])
    assert not entitlements.stdout
    command(platform + '-dyld-validate', ['xcrun', 'dyld_info', '-validate_only', binary])
    imports = command(platform + '-imports', ['xcrun', 'dyld_info', '-imports', '-dependents', binary]).stdout.decode()
    assert all(name in imports for name in ['_alarm', '_getrlimit', '_write'])
    assert not any(name in imports for name in ['libc++', 'CPURuntime', 'Hypervisor', 'Virtualization', 'VirtualMachine', 'ParavirtualizedGraphics', 'IOKit'])
    data = binary.read_bytes()
    uuids = [data[offset+8:offset+24].hex() for code, offset, size in commands(data) if code == 0x1b]
    assert len(uuids) == 1 and struct.unpack_from('<I', data, 8)[0] == 0x80000002
    products.append(dict(**pin(binary), role=platform, UUID=uuids[0],
                         CDHash=re.search(rb'CDHash=([0-9a-f]{40})', signature)[1].decode(),
                         emptyEntitlements=True, arm64ePACABI=0))
    if platform == 'macos':
        def bounded_child():
            resource.setrlimit(resource.RLIMIT_CPU, (5, 5))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        result = command('macos-execute', [binary], preexec_fn=bounded_child)
        assert result.stdout == b'ORDINARY_STARTUP_MAIN\nORDINARY_STARTUP_LIMITS_OK\n'
manifest = dict(schema='Minimal ordinary process-start control v1', products=products,
                nativeCPUCalls=0, privateProvidersLoaded=False, iPadExecuted=False,
                deviceWrites=0, macControlPassed=True, killCauseProven=False,
                full27Backend=False)
(OUT / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
files = [Path(__file__), SOURCE] + [p for p in sorted(OUT.rglob('*')) if p.is_file()]
(OUT / 'freeze.json').write_text(json.dumps(dict(files=[pin(p) for p in files]), indent=2) + '\n')
print(json.dumps(dict(manifest=pin(OUT / 'manifest.json'), freeze=pin(OUT / 'freeze.json')), indent=2))
