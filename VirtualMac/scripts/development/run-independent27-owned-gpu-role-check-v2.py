#!/usr/bin/env python3
"""Root-only bounded load check of the exact installed native GPU executable.

The fixed server-v1 role is supplied without an owner control endpoint.
This isolates main-image admission from VMM spawning; no GPU or guest is requested.
"""
import argparse, datetime, getpass, hashlib, importlib.util, json, pathlib, shlex, sys
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
REL = 'runtime/gpu-task-flat/GPUTask.bundle/Contents/XPCServices/com.apple.gpusw.ParavirtualizedGraphicsGPUTask.xpc/Contents/MacOS/'

def pin(p):
    p = pathlib.Path(p).resolve(); b = p.read_bytes()
    return dict(path=str(p), bytes=len(b), sha256=hashlib.sha256(b).hexdigest())

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--device-packet', type=pathlib.Path, required=True)
    ap.add_argument('--output', type=pathlib.Path, required=True)
    a = ap.parse_args(); packet = a.device_packet.resolve(); out = a.output.resolve()
    assert packet.parent == out.parent == N and not out.exists()
    candidate = json.loads((packet/'candidate.json').read_bytes())
    assert candidate['scope'] == pin(packet/'scope.json')
    assert json.loads((packet/'device-receipts/post/receipt.json').read_bytes())['transportExit'] == 0
    scope = json.loads((packet/'scope.json').read_bytes())
    rows = {r['archivePath']:r for r in scope['files']}
    task = rows[REL+'com.apple.gpusw.ParavirtualizedGraphicsGPUTask']
    compat = rows[REL+'VM27OwnedGPUTaskCompatV1.dylib']
    assert task['devicePath'].startswith('/private/var/mobile/Library/VirtualMacIndependent27Runtime-v1/gpu-task-flat/')
    assert task['mode'] == compat['mode'] == 0o700
    assert candidate['controller'] == pin(packet/'control.py')
    spec = importlib.util.spec_from_file_location('exact_owned_gpu_load_transport', packet/'control.py')
    c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)
    body = c.prefix(501) + c.off_check()
    body += 'OWN_GPU=' + shlex.quote(task['devicePath']) + '\n'
    off = '''ps -axo pid=,ppid=,uid=,comm= | awk -v g="$OWN_GPU" 'NF<4 {bad=1;next} {n++;if($4==g){print "UNEXPECTED_OWN_GPU",$0;bad=1}} END {exit bad || !n}'
'''
    body += off
    for row in (task, compat):
        q = shlex.quote(row['devicePath'])
        body += f'[ -f {q} ] && [ ! -L {q} ]\n'
        body += f'[ "$(realpath {q})" = {q} ]\n'
        body += f'[ "$(stat -c %u:%g:%a:%h:%s {q})" = 501:501:700:1:{row["local"]["bytes"]} ]\n'
        body += f'[ "$(sha256sum {q} | cut -d " " -f1)" = {row["local"]["sha256"]} ]\n'
    body += '''ulimit -c 0
printf 'OWN_GPU_DIRECT_LOAD_BEGIN uid=%s fixedRoleWithoutControlEndpoint=1 wallSeconds=20\\n' "$(id -u)"
set +e
VM27_OWNED_GPU_TASK_ROLE=server-v1 /var/jb/usr/bin/timeout -s TERM -k 2 20 "$OWN_GPU"
own_gpu_exit=$?
set -e
printf 'OWN_GPU_DIRECT_LOAD_EXIT %s\\n' "$own_gpu_exit"
'''
    body += off + c.off_check()
    body += "printf 'OWN_GPU_DIRECT_LOAD_EXACT_PROCESS_OFF\\n'\n"
    out.mkdir(mode=0o700); (out/'remote.sh').write_text(body)
    request = dict(schema='Exact installed native GPU main-image admission check with fixed role but no owner control endpoint',
        startedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        deviceCandidate=pin(packet/'candidate.json'), scope=pin(packet/'scope.json'),
        task=task, compat=compat, script=pin(out/'remote.sh'), source=pin(__file__),
        externalWallSeconds=20, guestRequested=False, newTrustEntries=0)
    (out/'request.json').write_text(json.dumps(request, indent=2)+'\n')
    password = getpass.getpass('iPad password: ')
    try:
        status, stdout, stderr, error = c.run_remote(body, b'', False, password, transport_timeout=55)
    finally:
        password = None
    (out/'stdout').write_bytes(stdout); (out/'stderr').write_bytes(stderr)
    entered = b'owned-server failure boundary=' in stdout+stderr
    main_passed = b'owned-server failure boundary=inherited-owner-configuration status=57' in stdout+stderr
    receipt = dict(schema='Actual exact native GPU role admission check result',
        finishedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        request=pin(out/'request.json'), transportExit=status, transportError=error,
        stdout=pin(out/'stdout'), stderr=pin(out/'stderr'),
        ownedMainFailureReported=entered,
        actualMainImageAdmissionPassedAndNoOwnerRefused=main_passed,
        guestBoot=False, nativeGPUHandshakePassed=False, deviceProductChanges=0,
        trustCacheOperations=0, cleanupVerified=b'OWN_GPU_DIRECT_LOAD_EXACT_PROCESS_OFF' in stdout)
    (out/'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps(receipt, indent=2)); print(stdout.decode(errors='replace')); print(stderr.decode(errors='replace'))
    assert status == 0 and receipt['cleanupVerified'], 'bounded own process cleanup must be resolved'

if __name__ == '__main__':
    main()
