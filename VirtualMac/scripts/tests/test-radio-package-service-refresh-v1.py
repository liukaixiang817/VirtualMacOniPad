#!/usr/bin/env python3
"""Run the real package guard with identical, changed and unexpected services."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[3]
spec = importlib.util.spec_from_file_location('package_account', ROOT /
    'VirtualMac/scripts/development/package-independent27-apple-account-v1.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)


def main():
    with tempfile.TemporaryDirectory(prefix='vm27-radio-refresh-') as folder:
        folder = Path(folder)
        launcher = folder / 'launchctl'
        launcher.write_text('''#!/usr/bin/env python3
import json,os,sys
from pathlib import Path
root=Path(os.environ['VM27_TEST_RADIO_ROOT'])
jobs=json.loads((root/'jobs.json').read_text())
action,label=sys.argv[1:3]
if label not in jobs:sys.exit(113)
if action=='print':print('program = '+jobs[label])
elif action=='bootout':
 with (root/'stopped.txt').open('a') as f:f.write(label+'\\n')
 del jobs[label]
 (root/'jobs.json').write_text(json.dumps(jobs))
else:sys.exit(114)
''')
        launcher.chmod(0o755)
        # Run the shipping shell function; only its launchctl executable is
        # replaced. File existence, symlink, SHA and program guards stay real.
        guard = package.prior.RADIO_GUARD.replace(
            'vm27_launchctl=/var/jb/bin/launchctl',
            'vm27_launchctl=' + shlex.quote(str(launcher)))
        prepare = package.refresh_radio_preinst(package.prior.PREPARE)
        a, b = folder / 'wifi', folder / 'bluetooth'
        a.write_bytes(b'owned-wifi')
        b.write_bytes(b'owned-bluetooth')
        digest = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
        labels = ['system/com.virtualmac.owned-wifi-v1',
                  'system/com.virtualmac.exclusive-bluetooth-v1']
        tail = '\nfor label in $vm27_radio_reload; do "$vm27_launchctl" bootout "system/$label"; done\n'
        env = dict(os.environ, VM27_TEST_RADIO_ROOT=str(folder))
        for case in ['identical', 'changed', 'absent', 'wrong-program', 'symlink']:
            jobs = dict(zip(labels, map(str, [a, b])))
            expected = [digest(a), digest(b)]
            if case == 'changed': expected = ['0' * 64, '1' * 64]
            if case == 'absent': jobs = {}
            if case == 'wrong-program': jobs[labels[1]] = '/unrelated/service'
            if case == 'symlink':
                b.unlink()
                b.symlink_to(a)
            (folder / 'jobs.json').write_text(json.dumps(jobs))
            stopped = folder / 'stopped.txt'
            stopped.unlink(missing_ok=True)
            calls = ''.join('vm27_radio_prepare ' + shlex.quote(label.removeprefix('system/')) +
                ' ' + shlex.quote(str(binary)) + ' ' + sha + '\n'
                for label, binary, sha in zip(labels, [a, b], expected))
            result = subprocess.run(['/bin/sh', '-c', 'set -eu\n' + guard + prepare + calls + tail],
                env=env, capture_output=True, text=True, timeout=5)
            actual = stopped.read_text().splitlines() if stopped.exists() else []
            if case in ['identical', 'changed']:
                assert result.returncode == 0, result.stderr
                assert actual == labels, (case, actual)
            elif case == 'absent':
                assert result.returncode == 0 and actual == [], result.stderr
            else:
                assert result.returncode != 0 and actual == [], (case, actual)
        b.unlink()
        b.write_bytes(b'owned-bluetooth')
        receipt = folder / 'receipt.json'
        recovery = folder / 'recover'
        recovery.write_text('''#!/bin/sh
test "$1" = --recover-owned-auxiliary-station || exit 95
printf 'recovered\\n' >> "$VM27_TEST_RADIO_ROOT/recovered.txt"
exit "${VM27_TEST_RECOVERY_EXIT:-0}"
''')
        recovery.chmod(0o755)
        script = package.RADIO_RECOVERY.replace(
            '/var/run/com.virtualmac.wifi-auxiliary-station-lease-v1/identity.json', str(receipt))
        script = script.replace('/var/jb/usr/local/libexec/virtualmac-owned-wifi-v1', str(recovery))
        script = script.replace(package.OWNED_WIFI_SHA, digest(recovery))
        for case in ['absent', 'owned', 'active-service', 'symlink', 'changed-binary', 'helper-refused']:
            receipt.unlink(missing_ok=True)
            recovered = folder / 'recovered.txt'
            recovered.unlink(missing_ok=True)
            (folder / 'jobs.json').write_text(json.dumps(
                {labels[0]: str(a)} if case == 'active-service' else {}))
            if case == 'symlink': receipt.symlink_to(a)
            elif case != 'absent': receipt.write_text('{}')
            candidate = script.replace(digest(recovery), '0' * 64) if case == 'changed-binary' else script
            result = subprocess.run(['/bin/sh', '-c', 'set -eu\n' + guard + candidate +
                '\nprintf registered'], env=dict(env, VM27_TEST_RECOVERY_EXIT='75' if case == 'helper-refused' else '0'),
                capture_output=True, text=True, timeout=5)
            if case in ['absent', 'owned']:
                assert result.returncode == 0 and result.stdout == 'registered', (case, result.stderr)
                assert recovered.exists() == (case == 'owned')
            else:
                assert result.returncode != 0 and 'registered' not in result.stdout, (case, result)
                assert recovered.exists() == (case == 'helper-refused')
    print('same-content refresh, program guards and owned recovery before registration passed')


if __name__ == '__main__':
    main()
