#!/usr/bin/env python3
"""Exercise the real configure script with isolated files and fake jbctl only."""
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

source = Path(__file__).resolve().parents[1] / 'development/configure-complete-dual-beta4-r1-v2.sh'
with tempfile.TemporaryDirectory(prefix='vm27-configure-test-', dir='/private/tmp') as temporary:
    root = Path(temporary)
    bins = root / 'bin'
    bins.mkdir()
    paths = {
        '/var/jb/Applications/VirtualMacIndependent27.app': root / 'app',
        '/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1': root / 'runtime',
        '/private/var/mobile/Library/VirtualMacFull13Runtime-v1': root / 'full13',
        '/var/jb/usr/share/virtualmac-independent27': root / 'metadata',
    }
    body = source.read_text()
    for original, replacement in paths.items():
        replacement.mkdir()
        body = body.replace(original, str(replacement))
    script = root / 'configure.sh'
    script.write_text('set -eu\n' + body)
    metadata = root / 'metadata'
    binary = root / 'app/owned-image'
    binary.write_bytes(b'reviewed signed-image fixture')
    digest = hashlib.sha256(binary.read_bytes()).hexdigest()
    cdhash = 'a' * 40
    (metadata / 'files.sha256').write_text(f'{digest}  {binary}\n')
    (metadata / 'symlinks.tsv').write_text('')
    (metadata / 'trustcache-v2.txt').write_text(f'{cdhash} {digest} {binary}\n')
    shim = '''import hashlib,os,pathlib,sys
r=pathlib.Path(os.environ['VM27_TEST_ROOT']); name=pathlib.Path(sys.argv[0]).name
if name=='id': print('0')
elif name=='chown': pass
elif name=='uicache': (r/'registered').write_text('yes')
elif name=='ldid': (r/'unexpected-ldid').write_text('called'); sys.exit(99)
elif name=='sha256sum':
 if '-c' in sys.argv:
  for row in pathlib.Path(sys.argv[-1]).read_text().splitlines():
   h,p=row.split('  ',1)
   if hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()!=h: sys.exit(1)
 else: print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest()+'  '+sys.argv[1])
elif name=='jbctl':
 state=r/'trusted'
 if sys.argv[2]=='info':
  print('Jailbreak Trustcache 0 <UUID: test>')
  if state.exists(): print('| 1: '+state.read_text())
 elif sys.argv[2]=='add':
  (r/'add-called').write_text(sys.argv[3])
  if os.environ.get('VM27_TEST_DROP_ADD')!='1': state.write_text(sys.argv[3])
 else: sys.exit(91)
else: sys.exit(92)
'''
    for name in ['id', 'chown', 'uicache', 'ldid', 'sha256sum', 'jbctl']:
        path = bins / name
        path.write_text('#!' + sys.executable + '\n' + shim)
        path.chmod(0o755)
    environment = dict(os.environ, PATH=str(bins) + ':/usr/bin:/bin:/usr/sbin:/sbin', VM27_TEST_ROOT=str(root))

    def run():
        return subprocess.run(['/bin/sh', str(script), 'configure'], env=environment,
                              capture_output=True, timeout=20)

    result = run()
    assert result.returncode == 0, result.stderr.decode()
    assert (root / 'registered').exists() and (root / 'trusted').read_text() == cdhash
    assert not (root / 'unexpected-ldid').exists()
    (root / 'add-called').unlink()
    assert run().returncode == 0 and not (root / 'add-called').exists()
    binary.write_bytes(b'tampered')
    assert run().returncode != 0 and not (root / 'add-called').exists()
    binary.write_bytes(b'reviewed signed-image fixture')
    (metadata / 'trustcache-v2.txt').write_text(f'{cdhash} {"b" * 64} {binary}\n')
    assert run().returncode != 0 and not (root / 'add-called').exists()
    (metadata / 'trustcache-v2.txt').write_text(f'{cdhash} {digest} {binary}\n')
    (root / 'trusted').unlink()
    (root / 'registered').unlink()
    environment['VM27_TEST_DROP_ADD'] = '1'
    assert run().returncode != 0 and not (root / 'registered').exists()
    assert 'phase=verify-trust-cache exit=1' in (metadata / 'configure.log').read_text()
    print('PASS: configure without ldid, idempotent retry, tamper and hash-binding rejection, false-success trust rejection')
