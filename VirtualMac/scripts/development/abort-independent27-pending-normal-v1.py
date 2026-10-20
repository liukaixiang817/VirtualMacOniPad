#!/usr/bin/env python3
"""Root-owned abort of an active start using its exact frozen own-process stop script."""
import argparse, datetime, getpass, hashlib, importlib.util, json, pathlib, sys
sys.dont_write_bytecode = True
R = pathlib.Path(__file__).resolve().parents[3]
N = R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
def pin(p):
    p = pathlib.Path(p).resolve(); b = p.read_bytes()
    return dict(path=str(p), bytes=len(b), sha256=hashlib.sha256(b).hexdigest())
def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--normal-packet', required=True, type=pathlib.Path)
    ap.add_argument('--output', required=True, type=pathlib.Path)
    a = ap.parse_args(); packet = a.normal_packet.resolve(); out = a.output.resolve()
    assert packet.parent == out.parent == N and not out.exists()
    candidate = json.loads((packet/'candidate.json').read_bytes())
    active = packet/'device-receipts/start/request.json'
    assert active.is_file() and not (active.parent/'receipt.json').exists()
    assert json.loads(active.read_bytes())['packetCandidate'] == pin(packet/'candidate.json')
    assert json.loads((packet/'device-receipts/preflight/receipt.json').read_bytes())['transportExit'] == 0
    script_path = packet/'stop.sh'
    assert candidate['scripts']['stop'] == pin(script_path)
    controller_pin = candidate['inheritedController']
    assert pin(controller_pin['path']) == controller_pin
    spec = importlib.util.spec_from_file_location('exact_owned_abort_transport', controller_pin['path'])
    c = importlib.util.module_from_spec(spec); spec.loader.exec_module(c)
    script = script_path.read_text()
    assert 'start_hash' in script and 'scan_own' in script and 'cleanup_own' in script
    assert 'timeout --signal=TERM --kill-after=3 20 ' in script
    out.mkdir(mode=0o700)
    request = dict(source=pin(__file__), packet=pin(packet/'candidate.json'), activeStart=pin(active),
        frozenStopScript=pin(script_path), controller=controller_pin, owningRootTask='/root',
        reason='Actual native GPU NSXPC memory-map decoder repeatedly rejects mismatched lengths; stop this failed boot before the necessary fix.',
        exactOwnProcessStopOnly=True, productWrites=0, trustCacheOperations=0,
        startedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat())
    (out/'request.json').write_text(json.dumps(request, indent=2)+'\n')
    password = getpass.getpass('iPad password: ')
    try: rc, stdout, stderr, error = c.run_remote(script, b'', False, password)
    finally: password = None
    (out/'stdout').write_bytes(stdout); (out/'stderr').write_bytes(stderr)
    receipt = dict(transportExit=rc, transportError=error, request=pin(out/'request.json'),
        stdout=pin(out/'stdout'), stderr=pin(out/'stderr'),
        finishedUTC=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        exactOwnProcessesOff=b'INDEPENDENT27_OWN_APP_AND_CHILD_OFF' in stdout,
        originalStartControllerStillResponsibleForTerminalCleanupAndPost=True)
    (out/'receipt.json').write_text(json.dumps(receipt, indent=2)+'\n')
    print(json.dumps(receipt)); assert rc == 0 and receipt['exactOwnProcessesOff']
if __name__ == '__main__': main()
