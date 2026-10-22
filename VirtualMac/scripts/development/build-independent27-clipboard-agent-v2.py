#!/usr/bin/env python3
"""Build the login-user clipboard agent; never installs or accesses a pasteboard."""
import argparse
import hashlib
import json
import pathlib
import plistlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[2]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', required=True, type=pathlib.Path)
args = parser.parse_args()
output = args.output.resolve()
output.mkdir(mode=0o700, parents=True, exist_ok=False)
sources = [ROOT / 'vz/guest/VM27ClipboardGuestMain_v1.m',
           ROOT / 'vz/guest/VM27ClipboardGuest_v6_handshake.m',
           ROOT / 'vz/shared/VM27ClipboardChannel_v1.m']
binary = output / 'VM27ClipboardGuest'
commands = [
    ['xcrun', 'clang', '-target', 'arm64-apple-macos13', '-fobjc-arc',
     '-fblocks', '-O2', '-Wall', '-Wextra', '-Werror', '-framework', 'AppKit',
     *map(str, sources), '-o', str(binary)],
    ['codesign', '--force', '--sign', '-', '--identifier',
     'com.mac.virtual.clipboard-agent', '--timestamp=none', str(binary)],
    ['codesign', '--verify', '--strict', str(binary)],
]
for index, command in enumerate(commands):
    result = subprocess.run(command, capture_output=True, timeout=60)
    (output / f'{index}.stderr').write_bytes(result.stderr)
    if result.returncode:
        raise SystemExit(result.stderr.decode(errors='replace'))
raw = binary.read_bytes()
sha = hashlib.sha256(raw).hexdigest()
(output / 'vm27_clipboard_guest_artifact_v6.h').write_text(
    f'#define VM27_CLIPBOARD_GUEST_BYTES {len(raw)}u\n'
    f'#define VM27_CLIPBOARD_GUEST_SHA256 @"{sha}"\n')
agent = dict(Label='com.mac.virtual.clipboard-sync',
             ProgramArguments=['/Library/VirtualMac/ClipboardSync/VM27ClipboardGuest'],
             LimitLoadToSessionType='Aqua', RunAtLoad=True,
             KeepAlive=dict(SuccessfulExit=False), ThrottleInterval=10)
(output / 'agent.plist').write_bytes(plistlib.dumps(agent, sort_keys=True))
manifest = dict(artifact=dict(path=str(binary), bytes=len(raw), sha256=sha),
                sources=[dict(path=str(p), sha256=hashlib.sha256(p.read_bytes()).hexdigest())
                         for p in sources], commands=commands, deviceOperations=0)
(output / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
print(json.dumps(manifest['artifact']))
