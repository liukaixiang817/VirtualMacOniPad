#!/usr/bin/env python3
"""Root-only bounded copy of the existing iPad diagnostic executable, never execute it."""
import datetime, getpass, hashlib, importlib.util, json, pathlib, shlex, subprocess, sys
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
C = N / 'independent27-raw-disk-app-only-device-v39-attempt2/control.py'
O = N / 'independent27-native-spindump-tool-readonly-v1-attempt1'
def pin(p):
    p = pathlib.Path(p).resolve(); b = p.read_bytes()
    return dict(path=str(p), bytes=len(b), sha256=hashlib.sha256(b).hexdigest())
def save(p, d): p.write_text(json.dumps(d, indent=2) + '\n')
def main():
    assert pin(C)['sha256'] == '15c71047eaeb3304a982058060fd93735d00fcf48d62f79e29fd226d80368c7b'
    sp = importlib.util.spec_from_file_location('current_dev39_read_transport', C)
    c = importlib.util.module_from_spec(sp); sp.loader.exec_module(c)
    body = c.prefix(0) + c.off_check() + '''
tool=/usr/sbin/spindump
[ -f "$tool" ] && [ ! -L "$tool" ]
[ "$(realpath "$tool")" = "$tool" ]
[ "$(stat -c %u:%g:%h "$tool")" = 0:0:1 ]
size=$(stat -c %s "$tool")
case "$size" in ''|*[!0-9]*) exit 8;; esac
[ "$size" -gt 0 ] && [ "$size" -le 8388608 ]
printf 'EXISTING_TOOL_METADATA %s\\nTOOL_BINARY_BEGIN\\n' "$(stat -c %d:%i:%u:%g:%a:%h:%s "$tool")"
cat "$tool"
'''
    script = 'set -eu\n/var/jb/usr/bin/timeout --signal=TERM --kill-after=3 20 /var/jb/bin/sh -c ' + shlex.quote(body) + '\n'
    assert subprocess.run(['/bin/sh', '-n'], input=script.encode(), capture_output=True).returncode == 0
    assert not O.exists(); O.mkdir(mode=0o700); (O / 'read-root.sh').write_text(script)
    save(O / 'request.json', dict(source=pin(__file__), controller=pin(C), script=pin(O/'read-root.sh'),
        deviceWrites=0, processSignals=0, trustCacheOperations=0, toolExecuted=False))
    password = getpass.getpass('iPad password: ')
    try: rc, out, err, error = c.run_remote(script, b'', True, password)
    finally: password = None
    (O/'stdout').write_bytes(out); (O/'stderr').write_bytes(err)
    row = dict(transportExit=rc, transportError=error, finishedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        request=pin(O/'request.json'), stdout=pin(O/'stdout'), stderr=pin(O/'stderr'), deviceWrites=0,
        processSignals=0, trustCacheOperations=0, toolExecuted=False)
    if rc == 0:
        header, binary = out.split(b'TOOL_BINARY_BEGIN\n', 1)
        assert 0 < len(binary) <= 8388608
        (O/'metadata.txt').write_bytes(header); (O/'spindump.ipad-readonly').write_bytes(binary)
        row['actualTool'] = pin(O/'spindump.ipad-readonly')
    save(O/'receipt.json', row); print(json.dumps(row)); raise SystemExit(rc)
if __name__ == '__main__': main()
