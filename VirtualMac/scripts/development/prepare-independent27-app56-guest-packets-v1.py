#!/usr/bin/env python3
"""HOST-only Read40/Normal48 preparation from future actual Device40 receipts.

This wrapper only calls the unchanged Read7 and Normal12 preparers. It never
dispatches a device action, writes an execution receipt, or changes ownership.
"""
import argparse, hashlib, json, pathlib, subprocess, sys
sys.dont_write_bytecode = True
B = pathlib.Path(__file__).resolve().parent
R = B.parents[2]
N = R / 'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm'
DEVICE = N / 'independent27-wfx-wait-device-v40-attempt1'
READ = N / 'independent27-app56-guest-readonly-v40-attempt1'
ACTUAL_READ = N / 'independent27-app56-newboot-guest-current-readonly-v1-attempt1'
NORMAL = N / 'independent27-app56-normal-guest-lifecycle-v48-attempt1'
OLD_NORMAL = N / 'independent27-app55-normal-guest-lifecycle-v47-attempt1/candidate.json'
PAIR = B / 'dispatch-independent27-normal-guest-serial-pair-v43.py'

def pin(p):
    p = pathlib.Path(p).resolve(); raw = p.read_bytes()
    return dict(path=str(p), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--phase', choices=('readonly','normal'), required=True)
    args = ap.parse_args()
    assert pin(DEVICE/'candidate.json')['sha256'] == 'a1e2c0fd0181fb86806d85b89828c8eceb772d22bf79421005af3ef3e415e6d6'
    launch = DEVICE/'device-receipts/launch/receipt.json'
    post = DEVICE/'device-receipts/post/receipt.json'
    # These files must be original actual results. The inherited preparers
    # validate their requests, transport status, exact product and log state.
    assert launch.is_file() and post.is_file(), 'Wait for actual Device40 launch and post receipts.'
    for p in (launch, post):
        assert json.loads(p.read_bytes())['transportExit'] == 0, 'Actual initialization must succeed.'
    argv = [sys.executable, str(B / ('prepare-independent27-guest-bundle-readonly-v7.py'
        if args.phase == 'readonly' else 'prepare-independent27-normal-guest-lifecycle-v12.py')),
        '--initializer-candidate', str(DEVICE/'candidate.json'),
        '--initializer-launch', str(launch), '--initializer-post', str(post)]
    if args.phase == 'readonly':
        argv += ['--output', str(READ)]
    else:
        prior = json.loads(OLD_NORMAL.read_bytes())['priorNormalPreflightFailure']
        assert pin(prior['path']) == prior
        argv += ['--guest-readonly', str(ACTUAL_READ/'receipt.json'),
            '--guest-configuration', str(ACTUAL_READ/'configuration.json'),
            '--prior-normal-preflight-failure', prior['path'],
            '--no-before-screenshot-input-free-boot', '--output', str(NORMAL)]
    subprocess.run(argv, check=True)
    if args.phase == 'normal':
        source = (B/'dispatch-independent27-normal-guest-serial-pair-v42.py').read_text()
        assert "PACKET=R/'DeviceDiagnostics/2026-10-08-full-macos27-cpu-vmm/independent27-app55-normal-guest-lifecycle-v47-attempt1'" in source
        old_sha = '6d2f1f2400572b0dae0ce4a6c8db0ff421b71f2497c7c6198d1c967fb059f29b'
        assert source.count(old_sha) == 1 and not PAIR.exists()
        source = source.replace('independent27-app55-normal-guest-lifecycle-v47-attempt1', NORMAL.name)
        source = source.replace(old_sha, pin(NORMAL/'candidate.json')['sha256'])
        compile(source, str(PAIR), 'exec')
        PAIR.write_text(source)
        print(json.dumps(dict(serialPair=pin(PAIR), sameRootReadyAndOwnershipLogic=True,
            deviceOperations=0, executionReceiptsSynthesized=False)))

if __name__ == '__main__': main()
